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
import collections
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import string
import tempfile
import time
import unicodedata
import uuid
import xml.etree.ElementTree as ET

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat)
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:   # Argon2id needs the "cryptography" package 44.0 or newer
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:   # pragma: no cover - depends on the installed version
    Argon2id = None

__version__ = "1.3.1"

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

# Argon2id (RFC 9106 "second recommended option": 64 MiB, 3 passes, 4 lanes).
# Stored in the file header (authenticated), so parameters can be raised later
# and old vaults keep opening with whatever they were created with.
ARGON2_VERSION = 0x13
ARGON2_PARAMS = {"m": 65536, "t": 3, "p": 4}      # m in KiB; new vaults / upgrades
ARGON2_MIN = {"m": 19456, "t": 2, "p": 1}         # OWASP floor: refuse weaker files
ARGON2_MAX = {"m": 1048576, "t": 10, "p": 16}     # refuse absurd values (1 GiB)

FIELDS = ("title", "username", "password", "url", "notes")
FLAG_FIELDS = ("otto_approved",)     # booleans stored with each entry
DAY = 86400
AI_EXPIRY_CHOICES = (0, 7, 30)       # days; 0 = never expires
DEFAULT_AI_EXPIRY_DAYS = 30


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


def argon2_available():
    return Argon2id is not None


def _derive_with(kdf, password):
    """Derive the vault key for a (validated) kdf header dict."""
    salt = _b64d(kdf["salt"])
    if kdf["name"] == "argon2id":
        if Argon2id is None:
            raise VaultError(
                "This vault uses Argon2id, which needs a newer 'cryptography' package. "
                "Run:  py -m pip install --upgrade cryptography")
        return Argon2id(salt=salt, length=KEY_LEN, iterations=kdf["t"], lanes=kdf["p"],
                        memory_cost=kdf["m"]).derive(password.encode("utf-8"))
    return _derive_key(password, salt, kdf["n"], kdf["r"], kdf["p"])


def _new_kdf(name=None, kdf_n=KDF_N):
    """Fresh header (random salt). name None = best available."""
    if name is None:
        name = "argon2id" if Argon2id is not None else "scrypt"
    salt = _b64e(secrets.token_bytes(SALT_LEN))
    if name == "argon2id":
        if Argon2id is None:
            raise VaultError("Argon2id is not available (needs cryptography 44 or newer).")
        return {"name": "argon2id", "m": ARGON2_PARAMS["m"], "t": ARGON2_PARAMS["t"],
                "p": ARGON2_PARAMS["p"], "v": ARGON2_VERSION, "salt": salt}
    return {"name": "scrypt", "n": kdf_n, "r": KDF_R, "p": KDF_P, "salt": salt}


def _kdf_outdated(kdf):
    """True if this header is weaker than what new vaults get (and we can upgrade)."""
    if Argon2id is None:
        return False
    if kdf["name"] != "argon2id":
        return True
    return any(kdf[k] < ARGON2_PARAMS[k] for k in ("m", "t", "p"))


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
        if doc.get("cipher") != "AES-256-GCM" or kdf.get("name") not in ("scrypt", "argon2id"):
            raise ValueError
        if kdf["name"] == "argon2id":
            m, t, p = kdf["m"], kdf["t"], kdf["p"]
            if (any(type(x) is not int for x in (m, t, p)) or kdf.get("v") != ARGON2_VERSION
                    or not (ARGON2_MIN["m"] <= m <= ARGON2_MAX["m"])
                    or not (ARGON2_MIN["t"] <= t <= ARGON2_MAX["t"])
                    or not (ARGON2_MIN["p"] <= p <= ARGON2_MAX["p"])):
                raise CorruptVaultError("Vault file has unsafe or invalid KDF settings.")
            kdf_clean = {"name": "argon2id", "m": m, "t": t, "p": p, "v": ARGON2_VERSION,
                         "salt": kdf["salt"]}
        else:
            n, r, p = int(kdf["n"]), int(kdf["r"]), int(kdf["p"])
            if (not (KDF_N <= n <= MAX_KDF_N) or n & (n - 1) or not (1 <= r <= 16)
                    or not (1 <= p <= 4)):
                raise CorruptVaultError("Vault file has unsafe or invalid KDF settings.")
            kdf_clean = {"name": "scrypt", "n": n, "r": r, "p": p, "salt": kdf["salt"]}
        salt = _b64d(kdf["salt"])
        nonce = _b64d(doc["nonce"])
        ct = _b64d(doc["ciphertext"])
        if len(salt) != SALT_LEN or len(nonce) != NONCE_LEN or len(ct) < 16:
            raise ValueError
    except CorruptVaultError:
        raise
    except Exception as exc:
        raise CorruptVaultError("This is not a valid OttoVault file.") from exc
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
    key = _derive_with(kdf, password)
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


# ------------------------------------------------------------ validation
# Length / character-set hardening for everything that is stored (GUI save,
# inbox files, CSV import, otto_add.py). The vault never builds SQL or shell
# commands from these values, so this is not "injection prevention": it keeps
# garbage, huge values and look-alike/invisible characters out of the vault and
# makes service-name matching predictable. Passwords stay free-form.
MAX_LEN = {"title": 200, "username": 256, "password": 1024, "url": 2048, "notes": 20000}


def _collapse_ws(s):
    """Any run of Unicode whitespace (tabs, newlines, NBSP, ...) -> one space."""
    return " ".join(s.split())


def _check_chars(name, s, forbidden):
    for ch in s:
        if unicodedata.category(ch) in forbidden:
            raise VaultError("%s contains a character that is not allowed (U+%04X)."
                             % (name.capitalize(), ord(ch)))


def _checked_len(name, s):
    if len(s) > MAX_LEN[name]:
        raise VaultError("%s is too long (maximum %d characters)." % (name.capitalize(), MAX_LEN[name]))


def clean_title(s, name="title"):
    """Titles/usernames: NFC, whitespace collapsed, no control, invisible or
    bidi-override characters."""
    if not isinstance(s, str):
        raise VaultError("%s must be text." % name.capitalize())
    s = unicodedata.normalize("NFC", _collapse_ws(s))
    _check_chars(name, s, ("Cc", "Cf", "Cs"))
    _checked_len(name, s)
    return s


def clean_url(s):
    if not isinstance(s, str):
        raise VaultError("URL must be text.")
    s = s.strip()
    _check_chars("url", s, ("Cc", "Cf", "Cs"))
    _checked_len("url", s)
    return s


def clean_password(s):
    """Free-form (symbols, spaces, emoji are fine) - only length and control
    characters (NUL, newline, tab, ...) are refused."""
    if not isinstance(s, str):
        raise VaultError("Password must be text.")
    _check_chars("password", s, ("Cc", "Cs"))
    _checked_len("password", s)
    return s


def clean_notes(s):
    if not isinstance(s, str):
        raise VaultError("Notes must be text.")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    for ch in s:
        if (unicodedata.category(ch) in ("Cc", "Cs") and ch not in "\n\t"):
            raise VaultError("Notes contain a character that is not allowed (U+%04X)." % ord(ch))
    _checked_len("notes", s)
    return s


def clean_entry_fields(title="", username="", password="", url="", notes=""):
    """Validate + normalise one entry's text fields. Raises VaultError."""
    t = clean_title(title or "", "title")
    if not t:
        raise VaultError("Title is required.")
    return {"title": t, "username": clean_title(username or "", "username"),
            "password": clean_password(password or ""), "url": clean_url(url or ""),
            "notes": clean_notes(notes or "")}


_CLEANERS = {"title": lambda v: clean_title(v, "title"),
             "username": lambda v: clean_title(v, "username"),
             "password": clean_password, "url": clean_url, "notes": clean_notes}


def match_key(s):
    """What service-name matching compares: NFKC, case-folded, spaces collapsed."""
    return unicodedata.normalize("NFKC", _collapse_ws(str(s))).casefold()


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


# ------------------------------------------------- Otto standing approvals
# Request/response mailbox that lets Otto read the password of an entry the
# owner has explicitly approved (checkbox on the entry, GUI only). It works
# ONLY while the vault is unlocked: the app answers requests from memory, so
# the master password is never stored anywhere.
#
#   requests\<id>.ottoreq   written by otto_get.py (service name, an ephemeral
#                           X25519 public key, a timestamp). Contains no secret.
#   responses\<id>.ottoresp written by the unlocked app. EVERY response (also a
#                           denial) is encrypted to the request's ephemeral key
#                           and authenticated with the vault's own key pair
#                           (two Diffie-Hellman results mixed by HKDF), so a
#                           third program can neither read nor forge one.
REQUESTS_DIRNAME = "requests"
RESPONSES_DIRNAME = "responses"
REQUEST_EXT = ".ottoreq"
RESPONSE_EXT = ".ottoresp"
REQUEST_FORMAT = "OttoVault-request"
RESPONSE_FORMAT = "OttoVault-response"
_RESPONSE_INFO = b"OttoVault response v1"
REQUEST_MAX_BYTES = 4096
RESPONSE_MAX_BYTES = 64 * 1024
REQUEST_MAX_AGE = 120            # seconds; older requests are ignored
REQUEST_MAX_FUTURE = 60          # clock-skew allowance
RESPONSE_MAX_AGE = 300           # leftover response files are swept after this
MAX_NAME_LEN = 200
MAX_RELEASES_PER_MIN = 30        # successful password releases
MAX_REQUESTS_PER_MIN = 60        # all requests (flood guard)
MAX_REQUESTS_PER_POLL = 25
OTTO_LOG_MAX = 500
_REQ_ID_RE = re.compile(r"^[0-9a-f]{32}$")

# result words used in responses and in the audit log
R_RELEASED = "released"
R_DENIED = "denied"
R_NOT_FOUND = "not found"
R_AMBIGUOUS = "ambiguous"
R_RATE = "rate limited"


def request_dir_for(vault_path):
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), REQUESTS_DIRNAME)


def response_dir_for(vault_path):
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), RESPONSES_DIRNAME)


def _clean_text(s, limit=100):
    """Printable, single-line, length-limited copy of untrusted text."""
    s = "".join(ch if ch.isprintable() else " " for ch in str(s))
    return s.strip()[:limit]


def _raw_pub(priv):
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def make_request(service, username="", now=None):
    """Build a request. Returns {"id", "blob", "eph_private"}; keep eph_private
    in memory only - it is the only key that can open the answer."""
    service = clean_title(service or "", "title")
    username = clean_title(username or "", "username")
    if not service or len(service) > MAX_NAME_LEN or len(username) > MAX_NAME_LEN:
        raise VaultError("Service/username must be 1-%d characters." % MAX_NAME_LEN)
    eph = X25519PrivateKey.generate()
    rid = secrets.token_hex(16)
    doc = {"format": REQUEST_FORMAT, "version": 1, "id": rid, "service": service,
           "username": username, "eph": _b64e(_raw_pub(eph)),
           "ts": int(time.time() if now is None else now)}
    return {"id": rid, "blob": json.dumps(doc).encode("utf-8"),
            "eph_private": eph.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())}


def parse_request(blob, now=None):
    """Validate a request file. Returns the dict, or raises VaultError (bad)
    or StaleRequest (well-formed but too old/new)."""
    now = time.time() if now is None else now
    try:
        if len(blob) > REQUEST_MAX_BYTES:
            raise ValueError
        doc = json.loads(blob.decode("utf-8"))
        if doc.get("format") != REQUEST_FORMAT or doc.get("version") != 1:
            raise ValueError
        rid, svc, usr = doc["id"], doc["service"], doc.get("username", "")
        if not isinstance(rid, str) or not _REQ_ID_RE.match(rid):
            raise ValueError
        if not isinstance(svc, str) or not isinstance(usr, str):
            raise ValueError
        svc, usr = clean_title(svc, "title"), clean_title(usr, "username")
        if not svc or len(svc) > MAX_NAME_LEN or len(usr) > MAX_NAME_LEN:
            raise ValueError
        ts = doc["ts"]
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            raise ValueError
        eph = _b64d(doc["eph"])
        if len(eph) != 32:
            raise ValueError
        X25519PublicKey.from_public_bytes(eph)
    except Exception as exc:
        raise VaultError("Request is not valid.") from exc
    if now - ts > REQUEST_MAX_AGE or ts - now > REQUEST_MAX_FUTURE:
        raise StaleRequest("Request is too old.")
    return {"id": rid, "service": svc, "username": usr, "eph": eph, "ts": ts}


class StaleRequest(VaultError):
    pass


def _response_key(shared1, shared2, req_eph, resp_eph, vault_pub):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=req_eph + resp_eph + vault_pub,
                info=_RESPONSE_INFO).derive(shared1 + shared2)


def _response_aad(rid, resp_eph_b64):
    return ("%s|1|%s|%s" % (RESPONSE_FORMAT, rid, resp_eph_b64)).encode("ascii")


def response_seal(vault_private, req_eph_pub, rid, payload):
    """Encrypt a response dict to the requester's ephemeral public key and
    authenticate it with the vault's static key (vault_private, 32 bytes)."""
    static = X25519PrivateKey.from_private_bytes(vault_private)
    peer = X25519PublicKey.from_public_bytes(req_eph_pub)
    r = X25519PrivateKey.generate()
    r_pub = _raw_pub(r)
    key = _response_key(r.exchange(peer), static.exchange(peer), req_eph_pub, r_pub,
                        _raw_pub(static))
    nonce = secrets.token_bytes(NONCE_LEN)
    r_b64 = _b64e(r_pub)
    body = dict(payload)
    body["id"] = rid
    ct = AESGCM(key).encrypt(nonce, json.dumps(body).encode("utf-8"),
                             _response_aad(rid, r_b64))
    doc = {"format": RESPONSE_FORMAT, "version": 1, "id": rid, "eph": r_b64,
           "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}
    return json.dumps(doc).encode("utf-8")


def response_open(req_eph_private, vault_public, blob, rid):
    """Decrypt + verify a response with the request's ephemeral private key and
    the vault's public key (inbox_public.key). Raises VaultError on any
    problem (wrong key, forged, tampered, wrong request id)."""
    try:
        if len(blob) > RESPONSE_MAX_BYTES:
            raise ValueError
        doc = json.loads(blob.decode("utf-8"))
        if (doc.get("format") != RESPONSE_FORMAT or doc.get("version") != 1
                or doc.get("id") != rid):
            raise ValueError
        r_pub = _b64d(doc["eph"])
        nonce = _b64d(doc["nonce"])
        ct = _b64d(doc["ciphertext"])
        mine = X25519PrivateKey.from_private_bytes(req_eph_private)
        my_pub = _raw_pub(mine)
        key = _response_key(mine.exchange(X25519PublicKey.from_public_bytes(r_pub)),
                            mine.exchange(X25519PublicKey.from_public_bytes(vault_public)),
                            my_pub, r_pub, vault_public)
        body = json.loads(AESGCM(key).decrypt(nonce, ct, _response_aad(rid, doc["eph"]))
                          .decode("utf-8"))
        if not isinstance(body, dict) or body.get("id") != rid or "status" not in body:
            raise ValueError
        return body
    except Exception as exc:
        raise VaultError("Response could not be verified or decrypted.") from exc


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


# -------------------------------------------------------------------- XML
# XML is an INTERCHANGE format only (like CSV): the live vault stays the
# encrypted custom file. An exported XML file is plain text with every password
# in it. Parsing uses the standard library's ElementTree after refusing any
# document that declares a DOCTYPE or entities (no entity expansion, no
# external entities, so no "billion laughs" and no XXE), with a size cap.
#
# OttoVault schema (version 1):
#   <ottovault version="1">
#     <entry ai_access="true" ai_access_until="2026-11-17">   <!-- optional, informational -->
#       <title/> <username/> <password/> <url/> <notes/>
#     </entry>
#   </ottovault>
# ai_access / ai_access_until are written for information only; import ignores
# them - importing NEVER grants AI access.
#
# Also read: KeePass 2.x "XML" export (KeePassFile/Root/Group/Entry with
# <String><Key>Title|UserName|Password|URL|Notes</Key><Value>...</Value></String>).
# Groups (names/hierarchy), history, attachments, custom fields, icons, tags and
# expiry are ignored; the "Recycle Bin" group is skipped; entries whose password
# value is marked Protected="True" (KeePass's internal encrypted form, not what
# its XML export writes) are skipped instead of importing ciphertext.
XML_MAX_BYTES = 10 * 1024 * 1024
XML_MAX_ENTRIES = 50000
XML_ROOT = "ottovault"
XML_VERSION = "1"
_XML_BAD_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _xml_text(s):
    return s if isinstance(s, str) else ""


def read_xml_root(path):
    """Read + safely parse an XML file. Raises VaultError (never anything else)."""
    try:
        size = os.path.getsize(path)
        if size > XML_MAX_BYTES:
            raise VaultError("This XML file is too large (limit %d MiB)." % (XML_MAX_BYTES >> 20))
        with open(path, "rb") as f:
            raw = f.read(XML_MAX_BYTES + 1)
    except OSError as exc:
        raise VaultError("Could not read file: %s" % exc.strerror) from exc
    if len(raw) > XML_MAX_BYTES:
        raise VaultError("This XML file is too large (limit %d MiB)." % (XML_MAX_BYTES >> 20))
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = raw.decode("utf-16")
        else:
            text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise VaultError("The XML file must be saved as UTF-8 (or UTF-16).") from exc
    low = text.lower()
    if "<!doctype" in low or "<!entity" in low:
        raise VaultError("Refused: the XML file contains a DOCTYPE/entity declaration "
                         "(not used by OttoVault or KeePass exports, and unsafe).")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise VaultError("This is not a valid XML file (%s)." % exc) from exc
    except (ValueError, RecursionError) as exc:
        raise VaultError("This is not a valid XML file.") from exc


def _ottovault_xml_entries(root):
    ver = root.get("version")
    if ver is not None and ver != XML_VERSION:
        raise VaultError("Unsupported OttoVault XML version (%r)." % ver)
    out = []
    for el in root.findall("entry"):
        out.append({f: _xml_text(el.findtext(f, default="")) for f in FIELDS})
    return out


def _keepass_entries(root):
    """(entries, unsupported_count) from a KeePass 2.x XML export."""
    out, unsupported = [], 0

    def walk(group):
        nonlocal unsupported
        name = (group.findtext("Name") or "").strip()
        if name == "Recycle Bin":
            return
        for el in group.findall("Entry"):          # direct children only: History is skipped
            vals, protected = {}, False
            for st in el.findall("String"):
                key = st.findtext("Key")
                v = st.find("Value")
                if key in ("Title", "UserName", "Password", "URL", "Notes") and v is not None:
                    if key == "Password" and (v.get("Protected") or "").lower() == "true":
                        protected = True
                    vals[key] = _xml_text(v.text)
            if protected:
                unsupported += 1
                continue
            out.append({"title": vals.get("Title", ""), "username": vals.get("UserName", ""),
                        "password": vals.get("Password", ""), "url": vals.get("URL", ""),
                        "notes": vals.get("Notes", "")})
        for sub in group.findall("Group"):
            walk(sub)

    top = root.find("Root")
    if top is None:
        raise VaultError("This KeePass XML file has no <Root> section.")
    for g in top.findall("Group"):
        walk(g)
    return out, unsupported


def parse_xml_entries(path):
    """Return (rows, format_name, unsupported_count) without touching any vault."""
    root = read_xml_root(path)
    if root.tag == XML_ROOT:
        rows, fmt, uns = _ottovault_xml_entries(root), "OttoVault XML", 0
    elif root.tag == "KeePassFile":
        (rows, uns), fmt = _keepass_entries(root), "KeePass 2.x XML"
    else:
        raise VaultError("Not an OttoVault or KeePass 2.x XML file (root element <%s>)."
                         % _clean_text(root.tag, 40))
    if len(rows) > XML_MAX_ENTRIES:
        raise VaultError("Too many entries in one XML file (limit %d)." % XML_MAX_ENTRIES)
    for r in rows:
        if not r["title"].strip():
            r["title"] = r["url"].strip() or r["username"].strip() or "(untitled)"
    return rows, fmt, uns


# ------------------------------------------------------------------ Vault
ANCHOR_FILENAME = "audit_anchor.json"
_AUDIT_INFO = b"OttoVault audit chain v1"


def anchor_path_for(vault_path):
    d, name = os.path.split(os.path.abspath(vault_path))
    return os.path.join(d, ANCHOR_FILENAME if name == "vault.dat"
                        else name + "." + ANCHOR_FILENAME)


class Vault:
    """An unlocked vault held in memory. Create with Vault.create / Vault.open."""

    def __init__(self, path, data, key, kdf, expiry_days=DEFAULT_AI_EXPIRY_DAYS):
        self.path = path
        self._data = data
        self._key = key
        self._kdf = kdf
        self.expiry_days = expiry_days if expiry_days in AI_EXPIRY_CHOICES else DEFAULT_AI_EXPIRY_DAYS
        self._release_times = collections.deque()   # AI-access rate limiting (memory only)
        self._request_times = collections.deque()
        self._req_seen = collections.OrderedDict()
        self._audit_key_cache = None
        self._anchor_state = None
        self._dirty = False                # migration/integrity changes not yet saved
        self.integrity_warnings = []       # shown loudly by the GUI after unlock
        self.kdf_upgraded = False          # True once if open() re-wrapped the key
        self.last_xml_report = None        # details of the latest import_xml()
        self._migrate()
        self._verify_log()

    # --- migration of older vaults (all in memory; saved by open())
    def _migrate(self):
        """Older vaults/entries lack the AI-access fields. Approval defaults to
        False; only the literal value True counts. Approvals that exist without a
        start/expiry (1.2.x) get a fresh expiry from today, and a log line."""
        now = int(time.time())
        d = self._data
        for e in d.get("entries", []):
            e["otto_approved"] = e.get("otto_approved") is True
            if not e["otto_approved"]:
                e["otto_approved_at"] = None
                e["otto_expires"] = None
                continue
            if not isinstance(e.get("otto_approved_at"), int):
                e["otto_approved_at"] = now
                e["otto_expires"] = now + self.expiry_days * DAY if self.expiry_days else None
                self._dirty = True
                d.setdefault("_pending_logs", []).append((e.get("title", ""), "approval period set"))
            elif not (e.get("otto_expires") is None or isinstance(e.get("otto_expires"), int)):
                e["otto_expires"] = None
        if not isinstance(d.get("otto_log"), list):
            d["otto_log"] = []
        if not isinstance(d.get("otto_log_total"), int):
            d["otto_log_total"] = len(d["otto_log"])
        if not isinstance(d.get("otto_log_base"), str):
            d["otto_log_base"] = ""

    # --- audit log chain (tamper evidence; see README "Access log integrity")
    def _audit_key(self):
        if self._audit_key_cache is None:
            self._audit_key_cache = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                                         info=_AUDIT_INFO).derive(self._key)
        return self._audit_key_cache

    def _mac(self, prev, rec):
        msg = json.dumps([prev, rec.get("t"), rec.get("title"), rec.get("result")],
                         ensure_ascii=True, separators=(",", ":")).encode("ascii")
        return hmac.new(self._audit_key(), msg, hashlib.sha256).hexdigest()

    def _log_head(self):
        log = self._data.get("otto_log") or []
        return log[-1].get("mac", "") if log else self._data.get("otto_log_base", "")

    def _reseal_log(self):
        """Recompute every MAC from the stored base (after a migration, a
        master-password change, or once a break has been reported)."""
        prev = self._data["otto_log_base"]
        for rec in self._data["otto_log"]:
            rec["mac"] = self._mac(prev, rec)
            prev = rec["mac"]

    def _verify_log(self):
        """Check the chain and the outside anchor. Fills self.integrity_warnings,
        records ONE 'log integrity warning' event per problem set, re-seals."""
        d = self._data
        log = d["otto_log"]
        problems = []
        legacy = [r for r in log if not isinstance(r, dict) or "mac" not in r]
        if legacy and len(legacy) == len(log):      # 1.2.x log: start the chain now
            for r in log:
                r.setdefault("t", 0); r.setdefault("title", ""); r.setdefault("result", "")
            self._reseal_log()
            self._dirty = True
            d.setdefault("_pending_logs", []).append(
                ("(%d earlier entries)" % len(log), "log chain enabled"))
        else:
            prev = d["otto_log_base"]
            for n, rec in enumerate(log):
                ok = (isinstance(rec, dict) and isinstance(rec.get("mac"), str)
                      and isinstance(rec.get("t"), int) and isinstance(rec.get("title"), str)
                      and isinstance(rec.get("result"), str)
                      and hmac.compare_digest(rec["mac"], self._mac(prev, rec)))
                if not ok:
                    problems.append("entry %d of %d in the AI access log was altered, "
                                    "removed or reordered" % (n + 1, len(log)))
                    break
                prev = rec["mac"]
            if len(log) > 0 and d["otto_log_total"] < len(log):
                problems.append("the AI access log counter is inconsistent")
        problems += self._check_anchor()
        if problems:
            self.integrity_warnings = problems
            if any(not isinstance(r, dict) for r in log):
                d["otto_log"] = [r for r in log if isinstance(r, dict)]
            for r in d["otto_log"]:
                r.setdefault("t", 0); r.setdefault("title", ""); r.setdefault("result", "")
                for k, dflt in (("t", 0), ("title", ""), ("result", "")):
                    if not isinstance(r[k], type(dflt)):
                        r[k] = dflt
            self._reseal_log()
            d.setdefault("_pending_logs", []).append((_clean_text(problems[0], 90),
                                                      "log integrity warning"))
            self._dirty = True
        self._flush_pending_logs()

    def _flush_pending_logs(self):
        pend = self._data.pop("_pending_logs", [])
        for title, result in pend:
            self._log_otto(title, result)

    def _anchor_tag(self, total, head):
        return hmac.new(self._audit_key(), ("anchor|%d|%s" % (total, head)).encode("ascii"),
                        hashlib.sha256).hexdigest()

    def _check_anchor(self):
        """Compare with the small outside file written at every save. It is
        MAC'd with the vault-derived key, so it cannot be forged without the
        master password; it exposes a rolled-back or truncated vault copy."""
        try:
            with open(anchor_path_for(self.path), "rb") as f:
                a = json.loads(f.read(4096).decode("utf-8"))
            total, head, tag = a["total"], a["head"], a["tag"]
            if type(total) is not int or not isinstance(head, str) or not isinstance(tag, str):
                raise ValueError
        except FileNotFoundError:
            return []
        except Exception:
            return ["the audit anchor file next to the vault is unreadable"]
        if not hmac.compare_digest(tag, self._anchor_tag(total, head)):
            return ["the audit anchor does not belong to this vault (the vault was replaced, "
                    "restored from another backup, or the anchor file was edited)"]
        mine = self._data["otto_log_total"]
        if total > mine:
            return ["the AI access log is older than the last one seen "
                    "(vault restored from an older copy, or log entries were removed)"]
        if total == mine and head != self._log_head():
            return ["the AI access log differs from the last one seen"]
        return []

    def _write_anchor(self):
        total, head = self._data.get("otto_log_total", 0), self._log_head()
        if self._anchor_state == (total, head):
            return
        doc = {"format": "OttoVault-audit-anchor", "version": 1, "total": total,
               "head": head, "tag": self._anchor_tag(total, head)}
        try:
            _atomic_write(anchor_path_for(self.path), json.dumps(doc).encode("utf-8"),
                          keep_backup=False)
            self._anchor_state = (total, head)
        except OSError:
            pass

    # --- creation / opening
    @staticmethod
    def exists(path):
        return os.path.isfile(path)

    @classmethod
    def create(cls, path, password, kdf_n=KDF_N, kdf=None,
               expiry_days=DEFAULT_AI_EXPIRY_DAYS):
        """kdf: None = Argon2id when available else Scrypt; or "argon2id"/"scrypt"."""
        check_master_password(password)
        if os.path.exists(path):
            raise VaultError("A vault already exists at this location.")
        header = _new_kdf(kdf, kdf_n)
        key = _derive_with(header, password)
        v = cls(path, {"version": 1, "entries": []}, key, header, expiry_days)
        v.save()
        return v

    @classmethod
    def open(cls, path, password, expiry_days=DEFAULT_AI_EXPIRY_DAYS, upgrade_kdf=True):
        data, key, kdf = _decrypt_file(path, password)
        v = cls(path, data, key, kdf, expiry_days)
        if upgrade_kdf and _kdf_outdated(kdf):
            v._upgrade_kdf(password)
        if v._dirty:
            v._dirty = False
            v.save()
        else:
            v._write_anchor()
        return v

    def _upgrade_kdf(self, password):
        """Transparent one-time re-wrap with the current best KDF, done right
        after a successful unlock (the only moment the password is at hand).
        The previous file is kept as <vault>.pre-upgrade.bak. On any failure the
        old key/header stay in use and nothing is lost."""
        try:
            new_kdf = _new_kdf(None)
            new_key = _derive_with(new_kdf, password)
            keep = self.path + ".pre-upgrade.bak"
            if not os.path.exists(keep):
                shutil.copy2(self.path, keep)
            old = (self._key, self._kdf, self._audit_key_cache)
            self._key, self._kdf, self._audit_key_cache = new_key, new_kdf, None
            try:
                self._reseal_log()
                self.save()
            except Exception:
                self._key, self._kdf, self._audit_key_cache = old
                raise
            self._anchor_state = None
            self._write_anchor()
            self.kdf_upgraded = True
            self._dirty = False
        except Exception:
            self.kdf_upgraded = False

    @property
    def kdf_name(self):
        return self._kdf["name"]

    # --- persistence
    def save(self):
        self._flush_pending_logs()
        _atomic_write(self.path, _encrypt(self._data, self._key, self._kdf))
        self._write_anchor()

    def lock(self):
        """Forget the key and data (best effort - Python can't truly wipe)."""
        self._key = b""
        self._audit_key_cache = None
        self._data = {"entries": [], "otto_log": [], "otto_log_total": 0, "otto_log_base": ""}
        self._release_times.clear()
        self._request_times.clear()
        self._req_seen.clear()

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
        c = clean_entry_fields(title, username, password, url, notes)
        now = int(time.time())
        return {"id": uuid.uuid4().hex, "title": c["title"], "username": c["username"],
                "password": c["password"], "url": c["url"],
                "notes": c["notes"], "otto_approved": False,
                "otto_approved_at": None, "otto_expires": None,
                "created": now, "modified": now}

    def _grant(self, e, now=None):
        now = int(time.time() if now is None else now)
        e["otto_approved"] = True
        e["otto_approved_at"] = now
        e["otto_expires"] = now + self.expiry_days * DAY if self.expiry_days else None
        return ("approved (expires %s)" % time.strftime("%Y-%m-%d", time.localtime(e["otto_expires"]))
                if e["otto_expires"] else "approved (no expiry)")

    @staticmethod
    def _unapprove(e):
        e["otto_approved"] = False
        e["otto_approved_at"] = None
        e["otto_expires"] = None

    def add_entry(self, title, username="", password="", url="", notes="",
                  otto_approved=False, save=True):
        e = self._new_entry(title, username, password, url, notes)
        self._data["entries"].append(e)
        if otto_approved is True:
            self._log_otto(e["title"], self._grant(e))
        if save:
            self.save()
        return e["id"]

    def update_entry(self, entry_id, **fields):
        for e in self._data["entries"]:
            if e["id"] == entry_id:
                new = dict(e)
                want_flag = None
                for k, val in fields.items():
                    if k in FLAG_FIELDS:
                        want_flag = val is True
                    elif k in FIELDS:
                        val = val if val is not None else ""
                        if not isinstance(val, str):
                            raise VaultError("%s must be text." % k.capitalize())
                        # only re-validate what changed (old entries may predate the limits)
                        new[k] = val if val == e.get(k) else _CLEANERS[k](val)
                    else:
                        raise VaultError("Unknown field: %s" % k)
                if not new["title"]:
                    raise VaultError("Title is required.")
                new["modified"] = int(time.time())
                was = e.get("otto_approved") is True
                e.update(new)
                if want_flag is True and not was:
                    self._log_otto(e["title"], self._grant(e))
                elif want_flag is False and was:
                    self._unapprove(e)
                    self._log_otto(e["title"], "revoked")
                self.save()
                return
        raise KeyError(entry_id)

    def delete_entry(self, entry_id):
        gone = [e for e in self._data["entries"] if e["id"] == entry_id]
        if not gone:
            raise KeyError(entry_id)
        self._data["entries"] = [e for e in self._data["entries"] if e["id"] != entry_id]
        if gone[0].get("otto_approved") is True:
            self._log_otto(gone[0]["title"], "revoked (entry deleted)")
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
        # verify the old one by re-deriving from the current header
        old_key = _derive_with(self._kdf, old_password)
        if not secrets.compare_digest(old_key, self._key):
            raise WrongPasswordError("Current master password is wrong.")
        kdf = _new_kdf(None, max(KDF_N, self._kdf.get("n", KDF_N)))
        new_key = _derive_with(kdf, new_password)
        self._key, self._kdf, self._audit_key_cache = new_key, kdf, None
        self._reseal_log()                  # the audit MAC key follows the vault key
        self._anchor_state = None
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
            try:
                new = self._new_entry(*(str(payload.get(f, "") or "") for f in FIELDS))
            except VaultError:             # too long / forbidden characters
                bad += 1
                try:
                    os.replace(fp, fp + ".bad")
                except OSError:
                    pass
                continue
            self._data["entries"].append(new)
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

    # --- Otto standing approvals (see section above)
    def approved_count(self):
        return sum(1 for e in self._data["entries"] if e.get("otto_approved") is True)

    def revoke_all_otto(self):
        """Remove every AI-access approval. Each one is logged. Returns the count."""
        n = 0
        for e in self._data["entries"]:
            if e.get("otto_approved") is True:
                self._unapprove(e)
                self._log_otto(e["title"], "revoked")
                n += 1
        self._log_otto("(all entries)", "revoked all (%d)" % n)
        self.save()
        return n

    def expire_approvals(self, now=None):
        """Turn off approvals whose expiry has passed (re-tick needed). Logged.
        Returns the titles. Runs at unlock and on every request poll."""
        if self.locked:
            return []
        now = time.time() if now is None else now
        out = []
        for e in self._data["entries"]:
            exp = e.get("otto_expires")
            if e.get("otto_approved") is True and exp is not None and exp <= now:
                self._unapprove(e)
                self._log_otto(e["title"], "expired", now)
                out.append(e["title"])
        if out:
            self.save()
        return out

    def otto_log(self):
        """Newest first: [{'t': epoch, 'title': str, 'result': str}] - never a password."""
        return [{"t": r["t"], "title": r["title"], "result": r["result"]}
                for r in reversed(self._data["otto_log"])]

    def _log_otto(self, title, result, now=None):
        d = self._data
        log = d["otto_log"]
        rec = {"t": int(time.time() if now is None else now),
               "title": _clean_text(title), "result": result}
        rec["mac"] = self._mac(self._log_head(), rec)
        log.append(rec)
        d["otto_log_total"] += 1
        while len(log) > OTTO_LOG_MAX:
            d["otto_log_base"] = log.pop(0)["mac"]

    def process_requests(self, requests_dir=None, responses_dir=None, now=None):
        """Answer waiting *.ottoreq files. Only works while unlocked (a locked
        vault does nothing, so requests simply time out). Returns a list of
        (service title, result) for the status bar. Never writes a plaintext
        password anywhere: released passwords are only in the encrypted
        response file."""
        if self.locked:
            return []
        now = time.time() if now is None else now
        results = [(_clean_text(t, 60), "expired") for t in self.expire_approvals(now)]
        rdir = requests_dir or request_dir_for(self.path)
        odir = responses_dir or response_dir_for(self.path)
        if not os.path.isdir(rdir):
            return results
        try:
            names = sorted(n for n in os.listdir(rdir) if n.endswith(REQUEST_EXT))
        except OSError:
            return results
        self._sweep_responses(odir, now)
        if not names:
            return results
        self.ensure_inbox_keypair()
        priv = base64.b64decode(self._data["inbox"]["private_key"])
        logged = False
        for name in names[:MAX_REQUESTS_PER_POLL]:
            fp = os.path.join(rdir, name)
            try:
                if os.path.getsize(fp) > REQUEST_MAX_BYTES:
                    raise VaultError("too large")
                with open(fp, "rb") as f:
                    req = parse_request(f.read(REQUEST_MAX_BYTES + 1), now)
            except VaultError:                # bad, oversized or stale: just drop it
                self._remove(fp)
                continue
            except OSError:
                continue
            if req["id"] in self._req_seen:   # replay / failed deletion earlier
                self._remove(fp)
                continue
            while self._request_times and now - self._request_times[0] > 60:
                self._request_times.popleft()
            if len(self._request_times) >= MAX_REQUESTS_PER_MIN:
                self._remove(fp)              # flood: no answer, no log spam
                results.append(("", "flood"))
                continue
            self._request_times.append(now)
            status, entry = self._decide(req, now)
            payload = {"status": status}
            title = entry["title"] if entry else req["service"]
            if status == R_RELEASED:
                payload.update(password=entry["password"], username=entry["username"],
                               title=entry["title"])
            try:
                os.makedirs(odir, exist_ok=True)
                blob = response_seal(priv, req["eph"], req["id"], payload)
                _atomic_write(os.path.join(odir, req["id"] + RESPONSE_EXT), blob,
                              keep_backup=False)
            except (OSError, ValueError):
                if status == R_RELEASED:      # nothing was handed out
                    self._release_times.pop()
                continue
            finally:
                payload.clear()
            self._req_seen[req["id"]] = True
            while len(self._req_seen) > 1000:
                self._req_seen.popitem(last=False)
            self._log_otto(title, status, now)
            logged = True
            results.append((_clean_text(title, 60), status))
            self._remove(fp)
        if logged:
            try:
                self.save()
            except OSError:
                pass
        return results

    def _decide(self, req, now):
        svc = match_key(req["service"])
        usr = match_key(req["username"])
        hits = [e for e in self._data["entries"]
                if match_key(e["title"]) == svc
                and (not usr or match_key(e["username"]) == usr)]
        if not hits:
            return R_NOT_FOUND, None
        if len(hits) > 1:
            return R_AMBIGUOUS, None
        e = hits[0]
        exp = e.get("otto_expires")
        if e.get("otto_approved") is not True or (exp is not None and exp <= now):
            return R_DENIED, e
        while self._release_times and now - self._release_times[0] > 60:
            self._release_times.popleft()
        if len(self._release_times) >= MAX_RELEASES_PER_MIN:
            return R_RATE, e
        self._release_times.append(now)
        return R_RELEASED, e

    @staticmethod
    def _remove(fp):
        try:
            os.remove(fp)
        except OSError:
            pass

    @staticmethod
    def _sweep_responses(odir, now):
        """Delete response files nobody picked up (they are encrypted anyway)."""
        try:
            for n in os.listdir(odir):
                if n.endswith(RESPONSE_EXT):
                    fp = os.path.join(odir, n)
                    if now - os.path.getmtime(fp) > RESPONSE_MAX_AGE:
                        os.remove(fp)
        except OSError:
            pass

    # --- CSV import
    def import_csv(self, csv_path):
        """Import entries; skips exact duplicates. Returns (added, skipped)."""
        rows = parse_csv(csv_path)
        have = {tuple(e[f] for f in FIELDS) for e in self._data["entries"]}
        added = skipped = 0
        for r in rows:
            try:      # compare/store the NORMALISED form (e.g. Windows CRLF in notes -> LF)
                c = clean_entry_fields(**{f: r[f] for f in FIELDS})
            except VaultError:             # invalid rows are skipped, never half-imported
                skipped += 1
                continue
            key = tuple(c[f] for f in FIELDS)
            if key in have:
                skipped += 1
                continue
            have.add(key)
            self._data["entries"].append(self._new_entry(**c))
            added += 1
        if added:
            self.save()
        return added, skipped

    # --- XML import / export (interchange only; see the XML section above)
    def verify_master_password(self, password):
        """True if password opens this vault (used to re-confirm risky actions)."""
        try:
            return secrets.compare_digest(_derive_with(self._kdf, password), self._key)
        except VaultError:
            return False

    def export_xml(self, dest_path, include_ai_info=True):
        """Write ALL entries as UNENCRYPTED XML (plain-text passwords!).
        Returns (written, skipped); skipped = entries holding characters XML
        cannot carry (only possible for entries older than the input rules)."""
        root = ET.Element(XML_ROOT, {"version": XML_VERSION})
        root.append(ET.Comment(" UNENCRYPTED export from OttoVault: contains passwords in "
                               "plain text. Delete it after use. "))
        written = skipped = 0
        for e in self.list_entries():
            if any(_XML_BAD_CHARS.search(str(e.get(f, ""))) for f in FIELDS):
                skipped += 1
                continue
            attrs = {}
            if include_ai_info and e.get("otto_approved") is True:
                attrs["ai_access"] = "true"
                if e.get("otto_expires"):
                    attrs["ai_access_until"] = time.strftime(
                        "%Y-%m-%d", time.localtime(e["otto_expires"]))
            el = ET.SubElement(root, "entry", attrs)
            for f in FIELDS:
                ET.SubElement(el, f).text = e.get(f, "")
            written += 1
        ET.indent(root, space="  ")
        data = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                + ET.tostring(root, encoding="unicode") + "\n").encode("utf-8")
        _atomic_write(dest_path, data, keep_backup=False)
        try:
            os.chmod(dest_path, 0o600)       # best effort (no effect on Windows)
        except OSError:
            pass
        return written, skipped

    def import_xml(self, xml_path):
        """Import entries from an OttoVault or KeePass 2.x XML file with the same
        validation and duplicate policy as CSV. Never grants AI access. Returns
        (added, skipped); details in self.last_xml_report."""
        rows, fmt, unsupported = parse_xml_entries(xml_path)
        have = {tuple(e[f] for f in FIELDS) for e in self._data["entries"]}
        added = invalid = dup = 0
        for r in rows:
            try:
                c = clean_entry_fields(**{f: r[f] for f in FIELDS})
            except VaultError:
                invalid += 1
                continue
            key = tuple(c[f] for f in FIELDS)
            if key in have:
                dup += 1
                continue
            have.add(key)
            self._data["entries"].append(self._new_entry(**c))
            added += 1
        if added:
            self.save()
        self.last_xml_report = {"format": fmt, "added": added, "duplicates": dup,
                                "invalid": invalid, "unsupported": unsupported}
        return added, dup + invalid + unsupported

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
