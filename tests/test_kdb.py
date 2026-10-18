"""KeePass 1 (.kdb) import. Only synthetic throwaway databases in temp dirs: ones
written by tests/kdb_helper.py, and ones made by the independent `kppy` library
(tests/kdb_fixtures.py)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
import kdb  # noqa: E402
import twofish  # noqa: E402
import vault as V  # noqa: E402
import kdb_fixtures as FX  # noqa: E402
from kdb_helper import make_kdb  # noqa: E402

PW = "test-master-pw-123"
KPW = "throwaway-kdb-pw"
G = [(1, "General"), (2, "Backup")]


@pytest.fixture
def v(tmp_path):
    return V.Vault.create(str(tmp_path / "v" / "vault.dat"), PW)


def put(tmp_path, data, name="db.kdb"):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def ent(title, pw="pw", gid=1, **kw):
    d = {"gid": gid, "title": title, "password": pw}
    d.update(kw)
    return d


# ------------------------------------------------------------ Twofish itself
@pytest.mark.parametrize("key,ct", [
    ("00" * 16, "9F589F5CF6122C32B6BFEC2F2AE8C35A"),
    ("0123456789ABCDEFFEDCBA98765432100011223344556677", "CFD1D2E5A9BE9CDF501F13B892BD2248"),
    ("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
     "37527BE0052334B89F0CFCCAE87CFA20")])
def test_twofish_official_vectors(key, ct):
    t = twofish.Twofish(bytes.fromhex(key))
    assert t.encrypt(bytes(16)).hex().upper() == ct
    assert t.decrypt(bytes.fromhex(ct)) == bytes(16)


def test_twofish_cbc_roundtrip():
    key, iv, data = os.urandom(32), os.urandom(16), os.urandom(160)
    assert twofish.cbc_decrypt(key, iv, twofish.cbc_encrypt(key, iv, data)) == data
    with pytest.raises(ValueError):
        twofish.Twofish(b"short")


# ------------------------------------------- independent (kppy-made) databases
def test_kppy_database_password_only(v, tmp_path):
    p = put(tmp_path, FX.KDB_PASSWORD_ONLY)
    assert v.import_kdb(p, FX.KDB_PW) == (2, 1)            # 1 skipped = Backup group entry
    got = {e["title"]: e for e in v.list_entries()}
    assert set(got) == {"Site One", "Ünï Tïtle ✓"}
    s = got["Site One"]
    assert (s["username"], s["password"], s["url"], s["notes"]) == (
        "alice", "p@ss\"w0rd;<>&'", "https://one.example", "note line1\nline2")
    assert got["Ünï Tïtle ✓"]["password"] == "pässwörd✓"
    assert v.last_kdb_report["backup_group"] == 1 and v.last_kdb_report["cipher"] == "AES"


def test_kppy_with_keyfile_and_keyfile_only(v, tmp_path):
    kf = put(tmp_path, FX.KDB_KEYFILE, "key.bin")
    both = put(tmp_path, FX.KDB_BOTH, "both.kdb")
    only = put(tmp_path, FX.KDB_KEYONLY, "only.kdb")
    with pytest.raises(kdb.KdbWrongPassword):               # needs the key file too
        v.import_kdb(both, FX.KDB_PW)
    assert v.import_kdb(both, FX.KDB_PW, kf)[0] == 2
    w = V.Vault.create(str(tmp_path / "w" / "vault.dat"), PW)
    assert w.import_kdb(only, "", kf)[0] == 2
    with pytest.raises(kdb.KdbWrongPassword):
        w.import_kdb(only, "", None)


# ------------------------------------------------------------------ wrong password
def test_wrong_password_changes_nothing(v, tmp_path):
    p = put(tmp_path, make_kdb(KPW, G, [ent("a")]))
    before = open(v.path, "rb").read()
    for bad in ("nope", "", KPW + " ", KPW.upper()):
        with pytest.raises(kdb.KdbWrongPassword):
            v.import_kdb(p, bad)
    assert v.list_entries() == [] and open(v.path, "rb").read() == before
    assert not os.path.exists(os.path.join(os.path.dirname(v.path), "lockout.json"))


# --------------------------------------------------------------- content handling
def test_empty_database(v, tmp_path):
    p = put(tmp_path, make_kdb(KPW, [], []))
    assert v.import_kdb(p, KPW) == (0, 0)
    assert v.last_kdb_report["found"] == 0 and v.list_entries() == []
    p2 = put(tmp_path, make_kdb(KPW, G, []), "g.kdb")
    assert v.import_kdb(p2, KPW) == (0, 0)


def test_special_characters_and_multiline_notes(v, tmp_path):
    odd = "p\"'`$%^&*()<>;|\\/ €😀ñ"
    e = [ent("Sp €cial 😀", odd, username="üser@x", url="http://a/?q=1&r=2",
             notes="l1\r\nl2\nl3 'q' \"dq\"")]
    p = put(tmp_path, make_kdb(KPW, G, e))
    assert v.import_kdb(p, KPW) == (1, 0)
    got = v.list_entries()[0]
    assert got["password"] == odd and got["username"] == "üser@x"
    assert got["notes"] == "l1\nl2\nl3 'q' \"dq\""         # CRLF normalised like CSV/XML


def test_non_ascii_password_utf8_and_cp1252(v, tmp_path):
    pw = "pässwörd-é"
    for enc, name in (("utf-8", "u.kdb"), ("cp1252", "c.kdb")):
        w = V.Vault.create(str(tmp_path / enc / "vault.dat"), PW)
        p = put(tmp_path, make_kdb(pw, G, [ent("x")], pw_encoding=enc), name)
        assert w.import_kdb(p, pw) == (1, 0)


def test_duplicates_skipped(v, tmp_path):
    p = put(tmp_path, make_kdb(KPW, G, [ent("a", "1"), ent("a", "1"), ent("b", "2")]))
    assert v.import_kdb(p, KPW) == (2, 1)
    assert v.import_kdb(p, KPW) == (0, 3)                  # second run: all duplicates
    assert v.last_kdb_report["duplicates"] == 3
    v.add_entry("c", "u", "pw3")
    p2 = put(tmp_path, make_kdb(KPW, G, [ent("c", "pw3", username="u")]), "d2.kdb")
    assert v.import_kdb(p2, KPW) == (0, 1)                 # duplicate of an existing entry
    assert len(v.list_entries()) == 3


def test_never_grants_ai_access(v, tmp_path):
    p = put(tmp_path, make_kdb(KPW, G, [ent("a"), ent("b", notes="ai_access=true otto_approved")]))
    v.import_kdb(p, KPW)
    assert v.list_entries() and all(e["otto_approved"] is False for e in v.list_entries())
    assert v.approved_count() == 0
    assert not any("grant" in str(l).lower() for l in v.otto_log())


def test_validation_rules_apply(v, tmp_path):
    e = [ent("x" * 500), ent("ctrl\x07title"), ent("ok", "p" * 5000), ent("fine"),
         ent("  Spaced   Title  ", "q"), ent("", "np", url="https://untitled.example")]
    p = put(tmp_path, make_kdb(KPW, G, e))
    added, skipped = v.import_kdb(p, KPW)
    titles = sorted(x["title"] for x in v.list_entries())
    assert added == 3 and skipped == 3 == v.last_kdb_report["invalid"]
    assert titles == ["Spaced Title", "fine", "https://untitled.example"]


def test_meta_info_and_backup_group_skipped(v, tmp_path):
    e = [ent("Meta-Info", "x", username="SYSTEM", url="$", notes="KPX_GROUP_TREE_STATE"),
         ent("keep", "k"), ent("old", "o", gid=2)]
    p = put(tmp_path, make_kdb(KPW, G, e))
    assert v.import_kdb(p, KPW) == (1, 1)
    r = v.last_kdb_report
    assert r["meta"] == 1 and r["backup_group"] == 1 and [x["title"] for x in v.list_entries()] == ["keep"]


def test_twofish_database(v, tmp_path):
    p = put(tmp_path, make_kdb(KPW, G, [ent("tf", "twopw", username="u")], cipher="twofish"))
    assert v.import_kdb(p, KPW) == (1, 0)
    assert v.last_kdb_report["cipher"] == "Twofish"
    assert v.list_entries()[0]["password"] == "twopw"
    with pytest.raises(kdb.KdbWrongPassword):
        v.import_kdb(p, "wrong")


def test_keyfile_helper_database(v, tmp_path):
    key = os.urandom(32)
    kf = put(tmp_path, key, "k32.key")
    p = put(tmp_path, make_kdb(KPW, G, [ent("kf")], keyfile_key=key))
    assert v.import_kdb(p, KPW, kf)[0] == 1
    hexkf = put(tmp_path, key.hex().encode(), "k64.key")            # 64 hex chars form
    w = V.Vault.create(str(tmp_path / "w" / "vault.dat"), PW)
    assert w.import_kdb(p, KPW, hexkf)[0] == 1


# --------------------------------------------------------------- hostile files
def test_not_a_kdb_and_kdbx_message(v, tmp_path):
    for data, msg in ((b"hello" * 100, "not a KeePass 1"), (b"x" * 10, "too small"),
                      (bytes.fromhex("03d9a29a67fb4bb5") + b"\0" * 300, "KeePass 2")):
        with pytest.raises(V.VaultError, match=msg):
            v.import_kdb(put(tmp_path, data), KPW)
    with pytest.raises(V.VaultError, match="Could not read"):
        v.import_kdb(str(tmp_path / "missing.kdb"), KPW)


def test_huge_file_refused(v, tmp_path, monkeypatch):
    p = put(tmp_path, make_kdb(KPW, G, [ent("a")]))
    monkeypatch.setattr(kdb, "KDB_MAX_BYTES", 100)
    with pytest.raises(V.VaultError, match="too large"):
        v.import_kdb(p, KPW)


def test_bad_rounds_arcfour_version_counts(v, tmp_path):
    with pytest.raises(V.VaultError, match="rounds"):
        v.import_kdb(put(tmp_path, make_kdb(KPW, G, [ent("a")], rounds=1000)[:120]
                         + b"\xff\xff\xff\xff" + make_kdb(KPW, G, [])[124:], "r.kdb"), KPW)
    with pytest.raises(V.VaultError, match="ARCFOUR"):
        v.import_kdb(put(tmp_path, make_kdb(KPW, G, [ent("a")], flags=1 | 4), "a.kdb"), KPW)
    with pytest.raises(V.VaultError, match="version"):
        v.import_kdb(put(tmp_path, make_kdb(KPW, G, [ent("a")], version=0x00040000), "v.kdb"), KPW)
    with pytest.raises(V.VaultError, match="too many"):
        v.import_kdb(put(tmp_path, make_kdb(KPW, G, [ent("a")], count_entries=10**6), "c.kdb"), KPW)


def test_damaged_content_is_clean_error(v, tmp_path):
    good = make_kdb(KPW, G, [ent("a")])
    # lie about the entry count: records run out before the header says
    p = put(tmp_path, make_kdb(KPW, G, [ent("a")], count_entries=5))
    with pytest.raises(V.VaultError, match="damaged"):
        v.import_kdb(p, KPW)
    # flipped ciphertext bit => hash mismatch, reported as wrong password/damaged
    b = bytearray(good)
    b[-20] ^= 1
    with pytest.raises(kdb.KdbWrongPassword):
        v.import_kdb(put(tmp_path, bytes(b), "f.kdb"), KPW)
    # truncated body (not block aligned)
    with pytest.raises(V.VaultError, match="damaged"):
        v.import_kdb(put(tmp_path, good[:-5], "t.kdb"), KPW)
    # a field claiming a huge size
    bad = make_kdb(KPW, [], [], raw_content=b"\x01\x00\xff\xff\xff\x7f", count_groups=1)
    with pytest.raises(V.VaultError, match="damaged"):
        v.import_kdb(put(tmp_path, bad, "s.kdb"), KPW)
    assert v.list_entries() == []


def test_passwords_never_in_reports_or_files(v, tmp_path, capsys):
    p = put(tmp_path, make_kdb(KPW, G, [ent("a", "secret-entry-pw-xyz")]))
    v.import_kdb(p, KPW)
    v.lock()
    out = capsys.readouterr()
    assert KPW not in out.out + out.err and "secret-entry-pw-xyz" not in out.out + out.err
    assert KPW not in str(v.last_kdb_report) and "secret-entry-pw-xyz" not in str(v.last_kdb_report)
    d = os.path.dirname(v.path)
    for f in os.listdir(d):
        raw = open(os.path.join(d, f), "rb").read()
        assert KPW.encode() not in raw and b"secret-entry-pw-xyz" not in raw
