"""Read-only importer for KeePass 1.x (.kdb) databases (KeePass 1.x, KeePassX 0.x).

The .kdb file is an INTERCHANGE format here: the data is decrypted in memory,
turned into plain entries and handed to the vault; nothing is written to disk and
the file is never modified. Pure Python + the already-required `cryptography`
package (AES); Twofish databases use the bundled pure-Python twofish.py.

Format (all integers little-endian), 124-byte header then the encrypted body:
   0 signature 0x9AA2D903, 4 signature 0xB54BFB65, 8 flags (1 SHA2, 2 Rijndael,
   4 ARCFOUR, 8 Twofish), 12 version (0x0003xxxx), 16 master seed (16 bytes),
  32 IV (16), 48 group count, 52 entry count, 56 SHA-256 of the plaintext (32),
  88 transform seed (32), 120 transform rounds.
Key: K0 = SHA-256(password)  (or SHA-256(K0 || keyfile key) / keyfile key alone)
     K1 = AES-256-ECB(seed=transform seed) applied `rounds` times to K0
     key = SHA-256(master seed || SHA-256(K1));  body = CBC(key, IV), PKCS-style pad
Body: `groups` TLV records then `entries` TLV records; TLV = u16 type, u32 size,
data, record ends with type 0xFFFF.
Not handled: ARCFOUR databases, attachments, group hierarchy (group names are not
imported), KeePassX meta entries and the KeePass "Backup" group (skipped + counted).
"""
import hashlib
import os
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import twofish

SIG1, SIG2 = 0x9AA2D903, 0xB54BFB65
FLAG_RIJNDAEL, FLAG_TWOFISH, FLAG_ARCFOUR = 2, 8, 4
HEADER_LEN = 124
KDB_MAX_BYTES = 32 * 1024 * 1024          # real databases are well under 1 MiB
KDB_MAX_ROUNDS = 50_000_000               # KeePass default is 50 000; 6 000 000 takes ~10 s
KDB_MAX_RECORDS = 50000


class KdbError(Exception):
    """Problem with the file itself (not a .kdb, unsupported, damaged, too big)."""


class KdbWrongPassword(KdbError):
    """Password (or key file) did not open the database."""


def _keyfile_key(keyfile_bytes):
    n = len(keyfile_bytes)
    if n == 32:
        return keyfile_bytes
    if n == 64:
        try:
            return bytes.fromhex(keyfile_bytes.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass
    return hashlib.sha256(keyfile_bytes).digest()


def _password_candidates(password):
    """Byte encodings to try. KeePassX hashes UTF-8; KeePass 1.x on Windows used the
    ANSI code page, which only differs for non-ASCII passwords."""
    out = []
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            b = password.encode(enc)
        except UnicodeEncodeError:
            continue
        if b not in out:
            out.append(b)
    return out


def _transform(raw_key, seed, rounds):
    enc = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()
    update = enc.update
    k = raw_key
    for _ in range(rounds):
        k = update(k)
    return hashlib.sha256(k).digest()


def _decrypt_body(flags, key, iv, body):
    if flags & FLAG_RIJNDAEL:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        plain = dec.update(body) + dec.finalize()
    else:
        plain = twofish.cbc_decrypt(key, iv, body)
    pad = plain[-1] if plain else 0
    if not 1 <= pad <= 16 or pad > len(plain):
        raise KdbWrongPassword("padding")
    return plain[:len(plain) - pad]


def _text(b):
    if b.endswith(b"\x00"):
        b = b[:-1]
    return b.decode("utf-8", errors="replace")


def _tlv(data, pos):
    if pos + 6 > len(data):
        raise KdbError("The KeePass database content is damaged (truncated).")
    ftype, fsize = struct.unpack_from("<HI", data, pos)
    pos += 6
    if fsize > len(data) - pos:
        raise KdbError("The KeePass database content is damaged (bad field size).")
    return ftype, data[pos:pos + fsize], pos + fsize


def parse_content(data, n_groups, n_entries):
    """Return (rows, info) from decrypted content. rows: dicts with the 5 fields."""
    pos = 0
    groups = {}
    for _ in range(n_groups):
        gid, name = None, ""
        while True:
            ftype, val, pos = _tlv(data, pos)
            if ftype == 0xFFFF:
                break
            if ftype == 1 and len(val) >= 4:
                gid = struct.unpack_from("<I", val)[0]
            elif ftype == 2:
                name = _text(val)
        if gid is not None:
            groups[gid] = name
    rows, meta, backup = [], 0, 0
    for _ in range(n_entries):
        f = {"gid": None, "title": "", "url": "", "username": "", "password": "", "notes": ""}
        while True:
            ftype, val, pos = _tlv(data, pos)
            if ftype == 0xFFFF:
                break
            if ftype == 2 and len(val) >= 4:
                f["gid"] = struct.unpack_from("<I", val)[0]
            elif ftype in (4, 5, 6, 7, 8):
                f[("title", "url", "username", "password", "notes")[ftype - 4]] = _text(val)
        if f["title"] == "Meta-Info" and f["username"] == "SYSTEM":
            meta += 1                      # KeePassX/KeePass UI-state record, not a password
            continue
        if groups.get(f["gid"]) == "Backup":
            backup += 1                    # KeePass 1 keeps old/deleted copies here
            continue
        rows.append({k: f[k] for k in ("title", "username", "password", "url", "notes")})
    return rows, {"groups": len(groups), "meta": meta, "backup": backup}


def read_kdb(path, password="", keyfile=None):
    """Open and decrypt a .kdb file in memory; return (rows, info). Never raises
    anything but KdbError / KdbWrongPassword."""
    try:
        size = os.path.getsize(path)
        if size > KDB_MAX_BYTES:
            raise KdbError("This file is too large to be a KeePass 1 database (limit %d MiB)."
                           % (KDB_MAX_BYTES >> 20))
        with open(path, "rb") as f:
            raw = f.read(KDB_MAX_BYTES + 1)
    except OSError as exc:
        raise KdbError("Could not read file: %s" % exc.strerror) from exc
    if len(raw) > KDB_MAX_BYTES:
        raise KdbError("This file is too large to be a KeePass 1 database.")
    return read_kdb_bytes(raw, password, keyfile)


def read_kdb_bytes(raw, password="", keyfile=None):
    if len(raw) < HEADER_LEN + 16:
        raise KdbError("This is not a KeePass 1 (.kdb) database (file too small).")
    (sig1, sig2, flags, version, seed, iv, n_groups, n_entries, chash, tseed,
     rounds) = struct.unpack_from("<IIII16s16sII32s32sI", raw, 0)
    if sig1 != SIG1 or sig2 != SIG2:
        if raw[:4] == bytes.fromhex("03d9a29a") and raw[4:8] == bytes.fromhex("67fb4bb5"):
            raise KdbError("This is a KeePass 2 (.kdbx) database. Export it from KeePass 2 as XML "
                           "and use File > Import from XML instead.")
        raise KdbError("This is not a KeePass 1 (.kdb) database.")
    if version & 0xFFFFFF00 != 0x00030000:
        raise KdbError("Unsupported KeePass 1 file version (0x%08x)." % version)
    if flags & FLAG_RIJNDAEL:
        pass
    elif flags & FLAG_TWOFISH:
        pass
    elif flags & FLAG_ARCFOUR:
        raise KdbError("This database uses ARCFOUR encryption, which is not supported. "
                       "Re-save it in KeePass with Rijndael (AES) or Twofish first.")
    else:
        raise KdbError("Unknown encryption type in this KeePass 1 database.")
    if not 1 <= rounds <= KDB_MAX_ROUNDS:
        raise KdbError("Refused: the key-transformation rounds in this file (%d) are out of range."
                       % rounds)
    if n_groups > KDB_MAX_RECORDS or n_entries > KDB_MAX_RECORDS:
        raise KdbError("Refused: too many groups/entries (limit %d)." % KDB_MAX_RECORDS)
    body = raw[HEADER_LEN:]
    if not body or len(body) % 16:
        raise KdbError("The KeePass database is damaged (bad length).")
    fk = None
    if keyfile is not None:
        try:
            with open(keyfile, "rb") as f:
                kb = f.read(16 * 1024 * 1024 + 1)
        except OSError as exc:
            raise KdbError("Could not read the key file: %s" % exc.strerror) from exc
        if len(kb) > 16 * 1024 * 1024:
            raise KdbError("The key file is too large.")
        fk = _keyfile_key(kb)
    if not password and fk is None:
        raise KdbWrongPassword("empty")
    if password:
        masters = []
        for pb in _password_candidates(password):
            pk = hashlib.sha256(pb).digest()
            masters.append(pk if fk is None else hashlib.sha256(pk + fk).digest())
    else:
        masters = [fk]
    flags_eff = flags
    for master in masters:
        key = hashlib.sha256(seed + _transform(master, tseed, rounds)).digest()
        try:
            plain = _decrypt_body(flags_eff, key, iv, body)
        except KdbWrongPassword:
            continue
        if hashlib.sha256(plain).digest() == chash:
            break
    else:
        raise KdbWrongPassword("hash")
    rows, info = parse_content(plain, n_groups, n_entries)
    info["cipher"] = "AES" if flags & FLAG_RIJNDAEL else "Twofish"
    info["rounds"] = rounds
    return rows, info
