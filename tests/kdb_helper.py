"""Writer for synthetic KeePass 1 (.kdb) files, for tests only (the production code
only reads). Follows the published KeePass 1.x format."""
import hashlib
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import twofish


def _field(t, data):
    return struct.pack("<HI", t, len(data)) + data


def _s(text):
    return text.encode("utf-8") + b"\x00"


def build_content(groups, entries):
    """groups: [(id, name)]; entries: [dict(gid,title,url,username,password,notes)]"""
    out = b""
    for gid, name in groups:
        out += (_field(1, struct.pack("<I", gid)) + _field(2, _s(name))
                + _field(7, struct.pack("<I", 1)) + _field(8, struct.pack("<H", 0))
                + _field(0xFFFF, b""))
    for e in entries:
        out += (_field(1, os.urandom(16)) + _field(2, struct.pack("<I", e["gid"]))
                + _field(3, struct.pack("<I", 1)) + _field(4, _s(e.get("title", "")))
                + _field(5, _s(e.get("url", ""))) + _field(6, _s(e.get("username", "")))
                + _field(7, _s(e.get("password", ""))) + _field(8, _s(e.get("notes", "")))
                + _field(0xFFFF, b""))
    return out


def make_kdb(password, groups, entries, cipher="aes", rounds=1000, pw_encoding="utf-8",
             keyfile_key=None, flags=None, version=0x00030002, count_groups=None,
             count_entries=None, raw_content=None):
    content = raw_content if raw_content is not None else build_content(groups, entries)
    seed, iv, tseed = os.urandom(16), os.urandom(16), os.urandom(32)
    pk = hashlib.sha256(password.encode(pw_encoding)).digest() if password is not None else None
    if keyfile_key is None:
        master = pk
    elif pk is None:
        master = keyfile_key
    else:
        master = hashlib.sha256(pk + keyfile_key).digest()
    enc = Cipher(algorithms.AES(tseed), modes.ECB()).encryptor()
    k = master
    for _ in range(rounds):
        k = enc.update(k)
    key = hashlib.sha256(seed + hashlib.sha256(k).digest()).digest()
    pad = 16 - len(content) % 16
    padded = content + bytes([pad]) * pad
    if cipher == "aes":
        c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        body = c.update(padded) + c.finalize()
        fl = 1 | 2
    else:
        body = twofish.cbc_encrypt(key, iv, padded)
        fl = 1 | 8
    if flags is not None:
        fl = flags
    header = struct.pack("<IIII16s16sII32s32sI", 0x9AA2D903, 0xB54BFB65, fl, version, seed, iv,
                         len(groups) if count_groups is None else count_groups,
                         len(entries) if count_entries is None else count_entries,
                         hashlib.sha256(content).digest(), tseed, rounds)
    return header + body
