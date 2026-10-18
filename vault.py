"""OttoVault - vault logic (crypto + storage). No GUI code in this file.

File format (JSON text, version 1):
  {"format": "OttoVault", "version": 1,
   "kdf": {"name": "scrypt", "n": 32768, "r": 8, "p": 1, "salt": "<b64 16 bytes>"},
   "cipher": "AES-256-GCM", "nonce": "<b64 12 bytes>", "ciphertext": "<b64>"}
The key comes from the master password via Scrypt. The whole vault (a JSON
document) is encrypted with AES-256-GCM using a fresh random nonce on every
save. The header (everything except nonce/ciphertext) is authenticated as
GCM "associated data", so changing any header field makes decryption fail.
Nothing secret is ever written to disk in plain text and nothing is logged.
"""
import base64
import copy
import csv
import json
import os
import secrets
import shutil
import string
import tempfile
import time
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

__version__ = "1.1.0"

FORMAT_NAME = "OttoVault"
FORMAT_VERSION = 1
KDF_N = 2 ** 15          # CPU/memory cost (32768) -> ~32 MB, ~0.1-0.3 s
KDF_R = 8
KDF_P = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32             # AES-256
MIN_PASSWORD_LEN = 8
MAX_KDF_N = 2 ** 20      # refuse absurd values from a hostile file
MAX_FILE_BYTES = 64 * 1024 * 1024

FIELDS = ("title", "username", "password", "url", "notes")


class VaultError(Exception):
    """Base class for all vault problems (messages are safe to show)."""


class WrongPasswordError(VaultError):
    """Wrong master password, or the file was modified/damaged."""


class CorruptVaultError(VaultError):
    """The file is not a valid OttoVault file."""


class WeakPasswordError(VaultError):
    """Master password does not meet the minimum rules."""


# ----------------------------------------------------------------- helpers
def default_vault_path():
    base = os.environ.get("APPDATA")
    if base:
        d = os.path.join(base, "OttoVault")
    else:  # non-Windows (only used for testing)
        d = os.path.join(os.path.expanduser("~"), ".ottovault")
    return os.path.join(d, "vault.dat")


def _b64e(b):
    return base64.b64encode(b).decode("ascii")


def _b64d(s):
    try:
        raw = base64.b64decode(s.encode("ascii"), validate=True)
        if base64.b64encode(raw).decode("ascii") != s:   # reject non-canonical padding bits
            raise ValueError("non-canonical base64")
        return raw
    except Exception as exc:
        raise CorruptVaultError("Vault file is damaged (bad encoding).") from exc


def check_master_password(pw):
    if not isinstance(pw, str) or len(pw) < MIN_PASSWORD_LEN:
        raise WeakPasswordError(
            "Master password must be at least %d characters." % MIN_PASSWORD_LEN)


def _derive_key(password, salt, n, r, p):
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _aad(kdf):
    """Header bytes that are authenticated (not secret)."""
    hdr = {"format": FORMAT_NAME, "version": FORMAT_VERSION,
           "kdf": kdf, "cipher": "AES-256-GCM"}
    return json.dumps(hdr, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _atomic_write(path, data, keep_backup=True):
    """Write bytes to path via temp file + replace. Keeps one .bak of the
    previous file."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".ottovault-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if keep_backup and os.path.exists(path):
            shutil.copy2(path, path + ".bak")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _parse_file(raw):
    """Return (kdf_dict, salt, nonce, ciphertext) or raise CorruptVaultError."""
    try:
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict) or doc.get("format") != FORMAT_NAME:
            raise ValueError
        if doc.get("version") != FORMAT_VERSION:
            raise CorruptVaultError(
                "This vault file has an unsupported version (%r)." % doc.get("version"))
        kdf = doc["kdf"]
        if doc.get("cipher") != "AES-256-GCM" or kdf.get("name") != "scrypt":
            raise ValueError
        n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
        if not (KDF_N <= n <= MAX_KDF_N) or n & (n - 1) or not (1 <= r <= 16) or not (1 <= p <= 4):
            raise CorruptVaultError("Vault file has unsafe or invalid KDF settings.")
        salt = _b64d(kdf["salt"])
        nonce = _b64d(doc["nonce"])
        ct = _b64d(doc["ciphertext"])
        if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN or len(ct) < 16:
            raise ValueError
    except CorruptVaultError:
        raise
    except Exception as exc:
        raise CorruptVaultError("This is not a valid OttoVault file.") from exc
    kdf_clean = {"name": "scrypt", "n": n, "r": r, "p": p, "salt": kdf["salt"]}
    return kdf_clean, salt, nonce, ct


def _decrypt_file(path, password):
    try:
        size = os.path.getsize(path)
        if size > MAX_FILE_BYTES:
            raise CorruptVaultError("File is too large to be an OttoVault file.")
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as exc:
        raise VaultError("Could not read file: %s" % exc.strerror) from exc
    kdf, salt, nonce, ct = _parse_file(raw)
    key = _derive_key(password, salt, kdf["n"], kdf["r"], kdf["p"])
    try:
        plain = AESGCM(key).decrypt(nonce, ct, _aad(kdf))
    except InvalidTag as exc:
        raise WrongPasswordError(
            "Wrong master password (or the file has been damaged).") from exc
    try:
        data = json.loads(plain.decode("utf-8"))
        if not isinstance(data.get("entries"), list):
            raise ValueError
    except Exception as exc:
        raise CorruptVaultError("Vault contents are damaged.") from exc
    return data, key, kdf


def _encrypt(data, key, kdf):
    nonce = secrets.token_bytes(NONCE_LEN)  # fresh nonce every save
    plain = json.dumps(data, separators=(",", ":")).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plain, _aad(kdf))
    doc = {"format": FORMAT_NAME, "version": FORMAT_VERSION, "kdf": kdf,
           "cipher": "AES-256-GCM", "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}
    return json.dumps(doc, indent=1).encode("utf-8")


# ------------------------------------------------------------------ inbox
# "Inbox": lets another program (Otto) hand you a NEW entry without knowing
# your master password. The vault holds an X25519 key pair; the PUBLIC key is
# written to inbox_public.key (not secret). Anyone can encrypt an entry to it
# (ephemeral X25519 + HKDF-SHA256 + AES-256-GCM) and drop the file into the
# inbox folder, but only the unlocked vault holds the private key, so only
# OttoVault can read it - on your next unlock it is imported and deleted.
INBOX_EXT = ".ottoentry"
INBOX_MAX_BYTES = 64 * 1024
INBOX_FORMAT = "OttoVault-inbox"
_INBOX_INFO = b"OttoVault inbox v1"
PUBLIC_KEY_FILENAME = "inbox_public.key"
INBOX_DIRNAME = "inbox"


def inbox_dir_for(vault_path):
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), INBOX_DIRNAME)


def public_key_path_for(vault_path):
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), PUBLIC_KEY_FILENAME)


def _inbox_key(shared, eph_pub, recipient_pub):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub,
                info=_INBOX_INFO).derive(shared)


def _inbox_aad(eph_pub_b64):
    return ("%s|1|%s" % (INBOX_FORMAT, eph_pub_b64)).encode("ascii")


def read_public_key_file(path):
    """Return the 32-byte public key from inbox_public.key, or raise VaultError."""
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read(4096).decode("utf-8"))
        if doc.get("format") != "OttoVault-inbox-key" or doc.get("version") != 1:
            raise ValueError
        pub = base64.b64decode(doc["public_key"], validate=True)
        if len(pub) != 32:
            raise ValueError
        return pub
    except FileNotFoundError as exc:
        raise VaultError("Public key file not found: open OttoVault and unlock it once.") from exc
    except Exception as exc:
        raise VaultError("Public key file is not valid.") from exc


def public_key_file_bytes(pub):
    doc = {"format": "OttoVault-inbox-key", "version": 1, "public_key": _b64e(pub)}
    return (json.dumps(doc, indent=1) + "\n").encode("utf-8")


def inbox_seal(public_key, entry):
    """Encrypt an entry dict (title, username, password, url, notes) to the
    vault's public key. Returns the bytes to store in an .ottoentry file."""
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_key))
    key = _inbox_key(shared, eph_pub, public_key)
    payload = {f: str(entry.get(f, "") or "") for f in FIELDS}
    payload["msg_id"] = uuid.uuid4().hex
    nonce = secrets.token_bytes(NONCE_LEN)
    eph_b64 = _b64e(eph_pub)
    ct = AESGCM(key).encrypt(nonce, json.dumps(payload).encode("utf-8"), _inbox_aad(eph_b64))
    doc = {"format": INBOX_FORMAT, "version": 1, "eph": eph_b64,
           "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}
    return json.dumps(doc).encode("utf-8")


def inbox_open(private_key, blob):
    """Decrypt an inbox message with the vault's private key; returns dict."""
    try:
        doc = json.loads(blob.decode("utf-8"))
        if doc.get("format") != INBOX_FORMAT or doc.get("version") != 1:
            raise ValueError
        eph_pub = _b64d(doc["eph"])
        nonce = _b64d(doc["nonce"])
        ct = _b64d(doc["ciphertext"])
        priv = X25519PrivateKey.from_private_bytes(private_key)
        pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        key = _inbox_key(shared, eph_pub, pub)
        payload = json.loads(AESGCM(key).decrypt(nonce, ct, _inbox_aad(doc["eph"])).decode("utf-8"))
        if not isinstance(payload, dict) or not str(payload.get("title", "")).strip():
            raise ValueError
        return payload
    except Exception as exc:
        raise VaultError("Inbox message could not be read.") from exc


# --------------------------------------------------------------- generator
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


def generate_password(length=20, symbols=True):
    """Random password using the `secrets` module. Guarantees at least one
    lowercase, uppercase, digit (and symbol if enabled)."""
    length = int(length)
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    if length < len(pools):
        raise ValueError("length too short")
    chars = [secrets.choice(p) for p in pools]
    alphabet = "".join(pools)
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# -------------------------------------------------------------------- CSV
_ALIASES = {
    "title": ("title", "name", "account", "site", "website name", "entry"),
    "username": ("username", "user name", "user", "login", "login name", "login username", "email"),
    "password": ("password", "pass", "login password", "pwd"),
    "url": ("url", "web site", "website", "login uri", "uri", "address", "link"),
    "notes": ("notes", "note", "comment", "comments", "extra", "description"),
}


def _map_header(row):
    """Return {field: column index} if row looks like a header, else None."""
    idx = {}
    for i, cell in enumerate(row):
        c = cell.strip().lower()
        for field, names in _ALIASES.items():
            if c in names and field not in idx:
                idx[field] = i
    return idx if "password" in idx and len(idx) >= 2 else None


def parse_csv(path):
    """Read a CSV file and return a list of entry dicts (no saving)."""
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.reader(f))
    except UnicodeDecodeError:
        with open(path, "r", encoding="latin-1", newline="") as f:
            rows = list(csv.reader(f))
    except OSError as exc:
        raise VaultError("Could not read file: %s" % exc.strerror) from exc
    rows = [r for r in rows if any(c.strip() for c in r)]
    if not rows:
        return []
    mapping = _map_header(rows[0])
    if mapping:
        body = rows[1:]
    else:  # no header: assume title,username,password,url,notes
        mapping = {"title": 0, "username": 1, "password": 2, "url": 3, "notes": 4}
        body = rows
    out = []
    for r in body:
        e = {}
        for field in FIELDS:
            i = mapping.get(field)
            val = r[i] if i is not None and i < len(r) else ""
            e[field] = val if field == "password" else val.strip()
        if not e["title"]:
            e["title"] = e["url"] or e["username"] or "(untitled)"
        out.append(e)
    return out


# ------------------------------------------------------------------ Vault
class Vault:
    """An unlocked vault held in memory. Create with Vault.create / Vault.open."""

    def __init__(self, path, data, key, kdf):
        self.path = path
        self._data = data
        self._key = key
        self._kdf = kdf

    # --- creation / opening
    @staticmethod
    def exists(path):
        return os.path.isfile(path)

    @classmethod
    def create(cls, path, password, kdf_n=KDF_N):
        check_master_password(password)
        if os.path.exists(path):
            raise VaultError("A vault already exists at this location.")
        salt = secrets.token_bytes(SALT_LEN)
        kdf = {"name": "scrypt", "n": kdf_n, "r": KDF_R, "p": KDF_P, "salt": _b64e(salt)}
        key = _derive_key(password, salt, kdf_n, KDF_R, KDF_P)
        v = cls(path, {"version": 1, "entries": []}, key, kdf)
        v.save()
        return v

    @classmethod
    def open(cls, path, password):
        data, key, kdf = _decrypt_file(path, password)
        return cls(path, data, key, kdf)

    # --- persistence
    def save(self):
        _atomic_write(self.path, _encrypt(self._data, self._key, self._kdf))

    def lock(self):
        """Forget the key and data (best effort - Python can't truly wipe)."""
        self._key = b""
        self._data = {"entries": []}

    @property
    def locked(self):
        return not self._key

    # --- entries
    def list_entries(self):
        return sorted(copy.deepcopy(self._data["entries"]),
                      key=lambda e: e["title"].lower())

    def get_entry(self, entry_id):
        for e in self._data["entries"]:
            if e["id"] == entry_id:
                return copy.deepcopy(e)
        raise KeyError(entry_id)

    def _new_entry(self, title, username, password, url, notes):
        title = (title or "").strip()
        if not title:
            raise VaultError("Title is required.")
        now = int(time.time())
        return {"id": uuid.uuid4().hex, "title": title, "username": username or "",
                "password": password or "", "url": (url or "").strip(),
                "notes": notes or "", "created": now, "modified": now}

    def add_entry(self, title, username="", password="", url="", notes="", save=True):
        e = self._new_entry(title, username, password, url, notes)
        self._data["entries"].append(e)
        if save:
            self.save()
        return e["id"]

    def update_entry(self, entry_id, **fields):
        for e in self._data["entries"]:
            if e["id"] == entry_id:
                new = dict(e)
                for k, val in fields.items():
                    if k not in FIELDS:
                        raise VaultError("Unknown field: %s" % k)
                    new[k] = val if val is not None else ""
                new["title"] = new["title"].strip()
                if not new["title"]:
                    raise VaultError("Title is required.")
                new["modified"] = int(time.time())
                e.update(new)
                self.save()
                return
        raise KeyError(entry_id)

    def delete_entry(self, entry_id):
        n = len(self._data["entries"])
        self._data["entries"] = [e for e in self._data["entries"] if e["id"] != entry_id]
        if len(self._data["entries"]) == n:
            raise KeyError(entry_id)
        self.save()

    def search(self, text):
        """Case-insensitive match on title, username, url, notes (not password)."""
        t = (text or "").strip().lower()
        if not t:
            return self.list_entries()
        return [e for e in self.list_entries()
                if any(t in e[f].lower() for f in ("title", "username", "url", "notes"))]

    # --- master password
    def change_master_password(self, old_password, new_password):
        check_master_password(new_password)
        # verify the old one by re-deriving from the current salt
        salt = _b64d(self._kdf["salt"])
        old_key = _derive_key(old_password, salt, self._kdf["n"], self._kdf["r"], self._kdf["p"])
        if not secrets.compare_digest(old_key, self._key):
            raise WrongPasswordError("Current master password is wrong.")
        new_salt = secrets.token_bytes(SALT_LEN)
        kdf = {"name": "scrypt", "n": max(KDF_N, self._kdf["n"]), "r": KDF_R, "p": KDF_P,
               "salt": _b64e(new_salt)}
        self._key = _derive_key(new_password, new_salt, kdf["n"], kdf["r"], kdf["p"])
        self._kdf = kdf
        self.save()

    # --- inbox (see section above)
    def ensure_inbox_keypair(self):
        """Make sure the vault has an inbox key pair (migrates older vaults).
        Returns the 32-byte public key."""
        box = self._data.get("inbox")
        try:
            priv = base64.b64decode(box["private_key"], validate=True)
            pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)
            return pub
        except Exception:
            pass
        priv_key = X25519PrivateKey.generate()
        priv = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._data["inbox"] = {"private_key": _b64e(priv), "public_key": _b64e(pub)}
        self._data["version"] = 2
        self.save()
        return pub

    def write_public_key_file(self):
        """Write inbox_public.key next to the vault if missing or different.
        Returns True if a file was written. Contains no secret."""
        pub = self.ensure_inbox_keypair()
        path = public_key_path_for(self.path)
        data = public_key_file_bytes(pub)
        try:
            with open(path, "rb") as f:
                if f.read(4096) == data:
                    return False
        except OSError:
            pass
        _atomic_write(path, data, keep_backup=False)
        return True

    def import_inbox(self, inbox_dir=None):
        """Import and delete waiting inbox files. Unreadable files are renamed
        to <name>.bad. Returns (added, bad)."""
        inbox_dir = inbox_dir or inbox_dir_for(self.path)
        if not os.path.isdir(inbox_dir):
            return 0, 0
        self.ensure_inbox_keypair()
        priv = base64.b64decode(self._data["inbox"]["private_key"])
        seen = self._data.setdefault("inbox_seen", [])
        added = bad = 0
        done = []          # files to delete after the vault is saved
        for name in sorted(os.listdir(inbox_dir)):
            if not name.endswith(INBOX_EXT):
                continue
            fp = os.path.join(inbox_dir, name)
            try:
                if os.path.getsize(fp) > INBOX_MAX_BYTES:
                    raise VaultError("too large")
                with open(fp, "rb") as f:
                    payload = inbox_open(priv, f.read())
            except (VaultError, OSError):
                bad += 1
                try:
                    os.replace(fp, fp + ".bad")
                except OSError:
                    pass
                continue
            mid = str(payload.get("msg_id", ""))
            if mid and mid in seen:        # already imported earlier
                done.append(fp)
                continue
            self._data["entries"].append(self._new_entry(
                *(str(payload.get(f, "") or "") for f in FIELDS)))
            if mid:
                seen.append(mid)
            added += 1
            done.append(fp)
        del seen[:-1000]
        if added:
            self.save()
        for fp in done:
            try:
                os.remove(fp)
            except OSError:
                pass
        return added, bad

    # --- CSV import
    def import_csv(self, csv_path):
        """Import entries; skips exact duplicates. Returns (added, skipped)."""
        rows = parse_csv(csv_path)
        have = {tuple(e[f] for f in FIELDS) for e in self._data["entries"]}
        added = skipped = 0
        for r in rows:
            key = tuple(r[f] for f in FIELDS)
            if key in have:
                skipped += 1
                continue
            have.add(key)
            self._data["entries"].append(self._new_entry(**{f: r[f] for f in FIELDS}))
            added += 1
        if added:
            self.save()
        return added, skipped

    # --- export / restore (encrypted with the current master password)
    def export_backup(self, dest_path):
        _atomic_write(dest_path, _encrypt(self._data, self._key, self._kdf), keep_backup=False)

    @staticmethod
    def restore_backup(backup_path, vault_path, backup_password):
        """Check backup_path opens with backup_password, then make it the vault
        at vault_path (the current vault, if any, is kept as .bak)."""
        _decrypt_file(backup_path, backup_password)  # raises if wrong/damaged
        with open(backup_path, "rb") as f:
            raw = f.read()
        _atomic_write(vault_path, raw)
