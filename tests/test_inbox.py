import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import vault as V  # noqa: E402
import otto_add  # noqa: E402

PW = "test-master-pw-123"


@pytest.fixture
def v(tmp_path):
    return V.Vault.create(str(tmp_path / "vault.dat"), PW)


def test_version_string():
    assert V.__version__.count(".") == 2


def test_old_vault_migrates_and_writes_public_key(tmp_path):
    p = str(tmp_path / "vault.dat")
    v = V.Vault.create(p, PW)
    v.add_entry("keep", "u", "p")
    assert "inbox" not in v._data                       # like a pre-keypair vault
    v2 = V.Vault.open(p, PW)
    assert v2.write_public_key_file() is True
    assert os.path.exists(V.public_key_path_for(p))
    pub = V.read_public_key_file(V.public_key_path_for(p))
    assert len(pub) == 32
    assert v2.write_public_key_file() is False          # unchanged -> not rewritten
    v3 = V.Vault.open(p, PW)                            # key pair persisted in vault
    assert v3.ensure_inbox_keypair() == pub
    assert [e["title"] for e in v3.list_entries()] == ["keep"]
    assert b"private" not in open(p, "rb").read()
    # public key file holds no secret
    assert json.load(open(V.public_key_path_for(p)))["format"] == "OttoVault-inbox-key"


def test_seal_open_roundtrip_and_wrong_key(v):
    pub = v.ensure_inbox_keypair()
    blob = V.inbox_seal(pub, {"title": "T", "username": "u", "password": "pä$$", "url": "x", "notes": "n"})
    assert b"p\xc3\xa4$$" not in blob and b'"T"' not in blob
    import base64
    priv = base64.b64decode(v._data["inbox"]["private_key"])
    e = V.inbox_open(priv, blob)
    assert (e["title"], e["username"], e["password"]) == ("T", "u", "pä$$")
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
    other = X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    with pytest.raises(V.VaultError):
        V.inbox_open(other, blob)


def test_import_inbox_adds_deletes_and_dedupes(v, tmp_path):
    v.write_public_key_file()
    pub = v.ensure_inbox_keypair()
    inbox = V.inbox_dir_for(v.path)
    os.makedirs(inbox)
    blob = V.inbox_seal(pub, {"title": "Svc", "username": "usr", "password": "pw1", "notes": "hi"})
    open(os.path.join(inbox, "a" + V.INBOX_EXT), "wb").write(blob)
    open(os.path.join(inbox, "b" + V.INBOX_EXT), "wb").write(blob)       # same message replayed
    open(os.path.join(inbox, "c" + V.INBOX_EXT), "wb").write(b"garbage")
    open(os.path.join(inbox, "readme.txt"), "w").write("ignored")
    assert v.import_inbox() == (1, 1)
    assert sorted(os.listdir(inbox)) == ["c.ottoentry.bad", "readme.txt"]
    assert [e["title"] for e in V.Vault.open(v.path, PW).list_entries()] == ["Svc"]
    assert v.import_inbox() == (0, 0)


def test_replay_after_crash_is_not_duplicated(v):
    pub = v.ensure_inbox_keypair()
    inbox = V.inbox_dir_for(v.path); os.makedirs(inbox)
    blob = V.inbox_seal(pub, {"title": "Once", "password": "p"})
    fp = os.path.join(inbox, "x" + V.INBOX_EXT)
    open(fp, "wb").write(blob)
    assert v.import_inbox()[0] == 1
    open(fp, "wb").write(blob)      # file reappears (e.g. delete failed)
    assert v.import_inbox() == (0, 0)
    assert len(V.Vault.open(v.path, PW).list_entries()) == 1


def test_missing_inbox_folder_is_fine(v):
    assert v.import_inbox() == (0, 0)


def test_message_for_other_vault_goes_bad(v, tmp_path):
    other = V.Vault.create(str(tmp_path / "o" / "vault.dat"), PW)
    blob = V.inbox_seal(other.ensure_inbox_keypair(), {"title": "X", "password": "p"})
    inbox = V.inbox_dir_for(v.path); os.makedirs(inbox)
    open(os.path.join(inbox, "z" + V.INBOX_EXT), "wb").write(blob)
    assert v.import_inbox() == (0, 1)
    assert v.list_entries() == []


def test_otto_add_cli_end_to_end(v, tmp_path, capsys):
    v.write_public_key_file()
    base = os.path.dirname(v.path)
    rc = otto_add.main(["--service", "TestService Example", "--generate-username",
                        "--generate-password", "--dir", base])
    out = capsys.readouterr().out
    assert rc == 0 and "TestService Example" in out and "username: user-" in out
    files = os.listdir(os.path.join(base, "inbox"))
    assert len(files) == 1 and files[0].endswith(V.INBOX_EXT)
    # the password must not be on disk in plain text or printed
    assert v.import_inbox() == (1, 0)
    e = v.list_entries()[0]
    assert e["title"] == "TestService Example" and e["username"].startswith("user-")
    assert len(e["password"]) == 24 and e["password"] not in out
    assert os.listdir(os.path.join(base, "inbox")) == []


def test_otto_add_without_key_fails_cleanly(tmp_path, capsys):
    rc = otto_add.main(["--service", "S", "--generate-password", "--dir", str(tmp_path)])
    assert rc == 2 and not os.path.exists(tmp_path / "inbox")
    assert "unlock" in capsys.readouterr().err.lower()
