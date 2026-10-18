import base64
import json
import os
import string
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vault as V  # noqa: E402

PW = "test-master-pw-123"   # throwaway test value only


@pytest.fixture
def vpath(tmp_path):
    return str(tmp_path / "sub" / "vault.dat")


def test_create_and_file_is_encrypted(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("Bank", "me", "SECRET-PASSWORD-XYZ", "https://bank.example", "my notes")
    raw = open(vpath, "rb").read()
    for needle in (b"SECRET-PASSWORD-XYZ", b"Bank", b"bank.example", b"my notes"):
        assert needle not in raw
    doc = json.loads(raw)
    assert doc["version"] == 1 and doc["cipher"] == "AES-256-GCM"
    assert doc["kdf"]["name"] == "scrypt" and doc["kdf"]["n"] >= 2 ** 15 and doc["kdf"]["r"] == 8
    assert len(base64.b64decode(doc["kdf"]["salt"])) == 16
    assert len(base64.b64decode(doc["nonce"])) == 12


def test_add_edit_delete(vpath):
    v = V.Vault.create(vpath, PW)
    a = v.add_entry("A", "ua", "pa", "http://a", "na")
    b = v.add_entry("b", "ub", "pb")
    assert [e["title"] for e in v.list_entries()] == ["A", "b"]
    v.update_entry(a, title="A2", password="newpass")
    e = v.get_entry(a)
    assert e["title"] == "A2" and e["password"] == "newpass" and e["username"] == "ua"
    v.delete_entry(b)
    assert len(v.list_entries()) == 1
    with pytest.raises(KeyError):
        v.delete_entry(b)
    with pytest.raises(V.VaultError):
        v.add_entry("   ")
    with pytest.raises(V.VaultError):
        v.update_entry(a, title="")


def test_save_reopen(vpath):
    v = V.Vault.create(vpath, PW)
    i = v.add_entry("Mail", "u", "p@ss ünï", "http://m", "line1\nline2")
    v2 = V.Vault.open(vpath, PW)
    assert v2.get_entry(i)["password"] == "p@ss ünï"
    assert v2.get_entry(i)["notes"] == "line1\nline2"


def test_wrong_password_rejected(vpath):
    V.Vault.create(vpath, PW)
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, PW + "x")
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, "")


def test_master_password_min_length(vpath):
    with pytest.raises(V.WeakPasswordError):
        V.Vault.create(vpath, "short7!")
    assert not os.path.exists(vpath)


def test_tampered_ciphertext_rejected(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("x", "y", "z")
    doc = json.load(open(vpath))
    ct = bytearray(base64.b64decode(doc["ciphertext"]))
    ct[len(ct) // 2] ^= 0x01
    doc["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    json.dump(doc, open(vpath, "w"))
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, PW)


def test_tampered_nonce_tag_and_header_rejected(vpath):
    V.Vault.create(vpath, PW)
    orig = json.load(open(vpath))

    def write(d):
        json.dump(d, open(vpath, "w"))

    d = json.loads(json.dumps(orig))
    n = bytearray(base64.b64decode(d["nonce"])); n[0] ^= 1
    d["nonce"] = base64.b64encode(bytes(n)).decode(); write(d)
    with pytest.raises(V.VaultError):
        V.Vault.open(vpath, PW)

    d = json.loads(json.dumps(orig))
    c = bytearray(base64.b64decode(d["ciphertext"])); c[-1] ^= 1  # auth tag
    d["ciphertext"] = base64.b64encode(bytes(c)).decode(); write(d)
    with pytest.raises(V.VaultError):
        V.Vault.open(vpath, PW)

    d = json.loads(json.dumps(orig)); d["kdf"]["p"] = 2; write(d)
    with pytest.raises(V.VaultError):
        V.Vault.open(vpath, PW)


def test_any_single_raw_byte_flip_rejected(vpath):
    V.Vault.create(vpath, PW).add_entry("x", "y", "z")
    raw = open(vpath, "rb").read()
    # flip one byte at several positions in the raw file
    for pos in range(0, len(raw), max(1, len(raw) // 25)):
        b = bytearray(raw); b[pos] ^= 0x01
        open(vpath, "wb").write(bytes(b))
        try:
            V.Vault.open(vpath, PW)
        except V.VaultError:
            continue
        # only acceptable if the flip hit insignificant JSON whitespace
        assert raw[pos:pos + 1].isspace(), "flip at %d accepted" % pos


def test_garbage_and_huge_kdf_rejected(vpath):
    os.makedirs(os.path.dirname(vpath))
    open(vpath, "wb").write(b"not a vault at all")
    with pytest.raises(V.CorruptVaultError):
        V.Vault.open(vpath, PW)
    open(vpath, "wb").write(b"")
    with pytest.raises(V.CorruptVaultError):
        V.Vault.open(vpath, PW)
    V.Vault.create(vpath + "2", PW)
    d = json.load(open(vpath + "2")); d["kdf"]["n"] = 2 ** 30
    json.dump(d, open(vpath + "2", "w"))
    with pytest.raises(V.CorruptVaultError):
        V.Vault.open(vpath + "2", PW)


def test_fresh_nonce_each_save(vpath):
    v = V.Vault.create(vpath, PW)
    nonces = set()
    for _ in range(5):
        v.save()
        nonces.add(json.load(open(vpath))["nonce"])
    assert len(nonces) == 5


def test_atomic_write_and_backup(vpath):
    v = V.Vault.create(vpath, PW)
    assert not os.path.exists(vpath + ".bak")
    v.add_entry("one", "", "p1")
    first = open(vpath, "rb").read()
    v.add_entry("two", "", "p2")
    assert os.path.exists(vpath + ".bak")
    assert open(vpath + ".bak", "rb").read() == first       # previous version
    assert len(V.Vault.open(vpath + ".bak", PW).list_entries()) == 1
    assert len(V.Vault.open(vpath, PW).list_entries()) == 2
    leftovers = [f for f in os.listdir(os.path.dirname(vpath)) if f.endswith(".tmp")]
    assert leftovers == []


def test_failed_write_keeps_old_vault(vpath, monkeypatch):
    v = V.Vault.create(vpath, PW)
    v.add_entry("keep", "", "p")
    before = open(vpath, "rb").read()

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(V.os, "replace", boom)
    with pytest.raises(OSError):
        v.add_entry("lost", "", "p")
    monkeypatch.undo()
    assert open(vpath, "rb").read() == before
    assert [f for f in os.listdir(os.path.dirname(vpath)) if f.endswith(".tmp")] == []


def test_search(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("Gmail", "alice", "pw-needle", "https://mail.google.com", "personal")
    v.add_entry("Bank", "bob", "x", "https://bank.example", "savings")
    assert [e["title"] for e in v.search("gm")] == ["Gmail"]
    assert [e["title"] for e in v.search("BOB")] == ["Bank"]
    assert [e["title"] for e in v.search("example")] == ["Bank"]
    assert [e["title"] for e in v.search("savings")] == ["Bank"]
    assert v.search("pw-needle") == []        # passwords are not searchable
    assert len(v.search("")) == 2


def test_change_master_password(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("x", "y", "z")
    salt_before = json.load(open(vpath))["kdf"]["salt"]
    with pytest.raises(V.WrongPasswordError):
        v.change_master_password("wrong-old-pw", "new-master-456")
    with pytest.raises(V.WeakPasswordError):
        v.change_master_password(PW, "short")
    v.change_master_password(PW, "new-master-456")
    assert json.load(open(vpath))["kdf"]["salt"] != salt_before
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, PW)
    assert len(V.Vault.open(vpath, "new-master-456").list_entries()) == 1


def test_csv_import_keepassx_chrome_and_headerless(vpath, tmp_path):
    v = V.Vault.create(vpath, PW)
    kp = tmp_path / "kp.csv"
    kp.write_text('"Group","Title","Username","Password","URL","Comment"\n'
                  '"Internet","Site, One","u1","p,1","http://one","multi\nline"\n'
                  '"Internet","Two","u2","p2","http://two",""\n', encoding="utf-8")
    assert v.import_csv(str(kp)) == (2, 0)
    e = [x for x in v.list_entries() if x["title"] == "Site, One"][0]
    assert (e["username"], e["password"], e["url"], e["notes"].replace("\r\n", "\n")) == ("u1", "p,1", "http://one", "multi\nline")  # Windows write_text turns \n into \r\n
    assert v.import_csv(str(kp)) == (0, 2)       # duplicates skipped

    ch = tmp_path / "chrome.csv"
    ch.write_text("name,url,username,password,note\nChromeSite,https://c.example,cu,cp,cn\n",
                  encoding="utf-8-sig")
    assert v.import_csv(str(ch)) == (1, 0)
    c = [x for x in v.list_entries() if x["title"] == "ChromeSite"][0]
    assert (c["url"], c["username"], c["password"], c["notes"]) == ("https://c.example", "cu", "cp", "cn")

    nh = tmp_path / "nohdr.csv"
    nh.write_text("T3,u3,p3,http://three,n3\n", encoding="utf-8")
    assert v.import_csv(str(nh)) == (1, 0)
    t = [x for x in v.list_entries() if x["title"] == "T3"][0]
    assert (t["username"], t["password"], t["url"], t["notes"]) == ("u3", "p3", "http://three", "n3")

    # persisted
    assert len(V.Vault.open(vpath, PW).list_entries()) == 4
    empty = tmp_path / "e.csv"; empty.write_text("")
    assert v.import_csv(str(empty)) == (0, 0)


def test_export_restore_roundtrip(vpath, tmp_path):
    v = V.Vault.create(vpath, PW)
    v.add_entry("E1-Alpha", "u", "p1")
    v.add_entry("E2-Beta", "u", "p2")
    dest = str(tmp_path / "backup" / "my-backup.ottovault")
    v.export_backup(dest)
    assert b"Alpha" not in open(dest, "rb").read()
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(dest, "nope-nope-nope")
    # wreck the live vault, then restore
    v.delete_entry(v.list_entries()[0]["id"])
    new_path = str(tmp_path / "restored" / "vault.dat")
    V.Vault.restore_backup(dest, new_path, PW)
    r = V.Vault.open(new_path, PW)
    assert [e["title"] for e in r.list_entries()] == ["E1-Alpha", "E2-Beta"]
    with pytest.raises(V.WrongPasswordError):
        V.Vault.restore_backup(dest, str(tmp_path / "x.dat"), "bad-password-1")
    assert not os.path.exists(str(tmp_path / "x.dat"))
    # restore over existing vault keeps previous as .bak
    V.Vault.restore_backup(dest, vpath, PW)
    assert os.path.exists(vpath + ".bak")
    assert len(V.Vault.open(vpath, PW).list_entries()) == 2


def test_lock_forgets_key(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("a", "b", "c")
    v.lock()
    assert v.locked and v.list_entries() == []


def test_default_path_uses_appdata(monkeypatch):
    monkeypatch.setenv("APPDATA", os.path.join("C:", "Users", "x", "AppData", "Roaming"))
    p = V.default_vault_path()
    assert p.endswith(os.path.join("OttoVault", "vault.dat")) and "AppData" in p


def test_generator_properties():
    for length in (8, 12, 20, 64, 128):
        for sym in (True, False):
            p = V.generate_password(length, sym)
            assert len(p) == length
            assert any(c in string.ascii_lowercase for c in p)
            assert any(c in string.ascii_uppercase for c in p)
            assert any(c in string.digits for c in p)
            has_sym = any(c in V.SYMBOLS for c in p)
            assert has_sym == sym
            allowed = string.ascii_letters + string.digits + (V.SYMBOLS if sym else "")
            assert set(p) <= set(allowed)
    assert len({V.generate_password(20) for _ in range(200)}) == 200
    with pytest.raises(ValueError):
        V.generate_password(2, True)


def test_generator_uses_secrets():
    import inspect
    src = inspect.getsource(V.generate_password)
    assert "secrets." in src and "random." not in src.replace("SystemRandom", "")
