"""Standing per-service approval: request/response flow, audit log, limits.
Only throwaway vaults in temp dirs with throwaway passwords."""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
import vault as V  # noqa: E402
import otto_get  # noqa: E402

PW = "test-master-pw-123"
SECRET = "S3cret!throwaway-pw-XYZ"


@pytest.fixture
def v(tmp_path):
    vv = V.Vault.create(str(tmp_path / "vault.dat"), PW)
    vv.write_public_key_file()
    return vv


@pytest.fixture
def base(v):
    return os.path.dirname(v.path)


def file_request(v, service, username="", now=None):
    req = V.make_request(service, username, now=now)
    d = V.request_dir_for(v.path)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, req["id"] + V.REQUEST_EXT), "wb") as f:
        f.write(req["blob"])
    return req


def answer(v, req):
    """Read + open the response the vault wrote for req (None if none)."""
    p = os.path.join(V.response_dir_for(v.path), req["id"] + V.RESPONSE_EXT)
    if not os.path.exists(p):
        return None
    pub = V.read_public_key_file(V.public_key_path_for(v.path))
    return V.response_open(req["eph_private"], pub, open(p, "rb").read(), req["id"])


def ask(v, service, username="", now=None):
    req = file_request(v, service, username, now)
    res = v.process_requests(now=now)
    return req, res, answer(v, req)


# ------------------------------------------------------------- migration
def test_new_entries_default_not_approved(v):
    eid = v.add_entry("A", "u", "p")
    assert v.get_entry(eid)["otto_approved"] is False
    assert v.approved_count() == 0


def test_old_vault_migrates_cleanly(tmp_path):
    p = str(tmp_path / "vault.dat")
    old = V.Vault.create(p, PW)
    old.add_entry("Old", "u", "p")
    for e in old._data["entries"]:          # make it look like a 1.1 vault
        e.pop("otto_approved", None)
    old._data.pop("otto_log", None)
    old.save()
    new = V.Vault.open(p, PW)
    e = new.list_entries()[0]
    assert e["otto_approved"] is False and e["title"] == "Old"
    assert new.otto_log() == []
    new.update_entry(e["id"], otto_approved=True)
    assert V.Vault.open(p, PW).get_entry(e["id"])["otto_approved"] is True


def test_only_literal_true_counts_as_approved(tmp_path):
    p = str(tmp_path / "vault.dat")
    x = V.Vault.create(p, PW)
    eid = x.add_entry("A", "u", "p")
    x._data["entries"][0]["otto_approved"] = "yes"
    x.save()
    y = V.Vault.open(p, PW)
    assert y.get_entry(eid)["otto_approved"] is False
    y.update_entry(eid, otto_approved="true")       # not a real bool -> not approved
    assert y.get_entry(eid)["otto_approved"] is False


def test_csv_import_and_inbox_never_approve(v, tmp_path):
    csvp = tmp_path / "x.csv"
    csvp.write_text("title,username,password,otto_approved\nCsvSite,u,pw,True\n")
    assert v.import_csv(str(csvp)) == (1, 0)
    assert v.list_entries()[0]["otto_approved"] is False
    pub = V.read_public_key_file(V.public_key_path_for(v.path))
    inbox = V.inbox_dir_for(v.path)
    os.makedirs(inbox)
    blob = V.inbox_seal(pub, {"title": "FromOtto", "password": "x", "otto_approved": True})
    open(os.path.join(inbox, "a" + V.INBOX_EXT), "wb").write(blob)
    assert v.import_inbox() == (1, 0)
    got = [e for e in v.list_entries() if e["title"] == "FromOtto"][0]
    assert got["otto_approved"] is False


def test_update_entry_unknown_field_still_rejected(v):
    eid = v.add_entry("A")
    with pytest.raises(V.VaultError):
        v.update_entry(eid, bogus="x")


# --------------------------------------------------------------- release
def test_release_for_approved_entry(v):
    v.add_entry("Example Service", "alice", SECRET, otto_approved=True)
    req, res, body = ask(v, "example SERVICE")          # case-insensitive
    assert res == [("Example Service", V.R_RELEASED)]
    assert body["status"] == V.R_RELEASED
    assert body["password"] == SECRET and body["username"] == "alice"
    assert os.listdir(V.request_dir_for(v.path)) == []       # request consumed


def test_response_file_never_contains_plaintext(v):
    v.add_entry("Svc", "alice", SECRET, otto_approved=True)
    ask(v, "Svc")
    d = V.response_dir_for(v.path)
    for n in os.listdir(d):
        raw = open(os.path.join(d, n), "rb").read()
        assert SECRET.encode() not in raw and b"alice" not in raw


def test_denied_for_unapproved(v):
    v.add_entry("Svc", "u", SECRET)
    req, res, body = ask(v, "Svc")
    assert res == [("Svc", V.R_DENIED)]
    assert body == {"status": V.R_DENIED, "id": req["id"]}
    assert SECRET not in json.dumps(body)


def test_unknown_service(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    req, res, body = ask(v, "Other")
    assert res == [("Other", V.R_NOT_FOUND)] and body["status"] == V.R_NOT_FOUND
    assert "password" not in body


def test_partial_title_does_not_match(v):
    v.add_entry("Svc Main", "u", SECRET, otto_approved=True)
    assert ask(v, "Svc")[2]["status"] == V.R_NOT_FOUND


def test_ambiguous_denies_and_lists_nothing(v):
    v.add_entry("Dup", "a", "pw-a", otto_approved=True)
    v.add_entry("dup", "b", "pw-b", otto_approved=True)
    req, res, body = ask(v, "DUP")
    assert body == {"status": V.R_AMBIGUOUS, "id": req["id"]}
    # --username disambiguates
    req, res, body = ask(v, "Dup", "B")
    assert body["status"] == V.R_RELEASED and body["password"] == "pw-b"


def test_ambiguity_counts_unapproved_duplicates(v):
    v.add_entry("Dup", "a", "pw-a", otto_approved=True)
    v.add_entry("Dup", "b", "pw-b")
    assert ask(v, "Dup")[2]["status"] == V.R_AMBIGUOUS
    assert ask(v, "Dup", "b")[2]["status"] == V.R_DENIED


def test_stale_request_ignored(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    old = file_request(v, "Svc", now=1000)
    res = v.process_requests(now=1000 + V.REQUEST_MAX_AGE + 5)
    assert res == [] and answer(v, old) is None
    assert os.listdir(V.request_dir_for(v.path)) == []       # dropped
    assert [r["result"] for r in v.otto_log()] == ["approved"]   # nothing released/denied
    future = file_request(v, "Svc", now=5000 + 600)
    assert v.process_requests(now=5000) == [] and answer(v, future) is None


def test_malformed_and_oversized_requests_dropped(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    d = V.request_dir_for(v.path)
    os.makedirs(d)
    open(os.path.join(d, "a.ottoreq"), "wb").write(b"not json")
    open(os.path.join(d, "b.ottoreq"), "wb").write(b"x" * (V.REQUEST_MAX_BYTES + 10))
    bad = json.loads(V.make_request("Svc")["blob"])
    bad["id"] = "../../evil"                                  # path traversal attempt
    open(os.path.join(d, "c.ottoreq"), "wb").write(json.dumps(bad).encode())
    bad2 = json.loads(V.make_request("Svc")["blob"])
    bad2["eph"] = "AAAA"
    open(os.path.join(d, "d.ottoreq"), "wb").write(json.dumps(bad2).encode())
    assert v.process_requests() == []
    assert os.listdir(d) == []
    assert not os.path.exists(V.response_dir_for(v.path)) or \
        os.listdir(V.response_dir_for(v.path)) == []


def test_replayed_request_answered_once(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    req = file_request(v, "Svc")
    blob = open(os.path.join(V.request_dir_for(v.path), req["id"] + V.REQUEST_EXT), "rb").read()
    assert len(v.process_requests()) == 1
    os.remove(os.path.join(V.response_dir_for(v.path), req["id"] + V.RESPONSE_EXT))
    open(os.path.join(V.request_dir_for(v.path), "again.ottoreq"), "wb").write(blob)
    assert v.process_requests() == []
    assert answer(v, req) is None


def test_rate_limit_on_releases(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    t = 10_000.0
    results = []
    for i in range(V.MAX_RELEASES_PER_MIN + 5):
        results.append(ask(v, "Svc", now=t + i * 0.1)[2]["status"])
    assert results.count(V.R_RELEASED) == V.MAX_RELEASES_PER_MIN
    assert results[-1] == V.R_RATE
    # a minute later it works again
    assert ask(v, "Svc", now=t + 100)[2]["status"] == V.R_RELEASED


def test_request_flood_guard_drops_without_answer(v):
    t = 10_000.0
    for i in range(V.MAX_REQUESTS_PER_MIN):
        ask(v, "Nope", now=t)
    req, res, body = ask(v, "Nope", now=t)
    assert body is None and res == [("", "flood")]


def test_per_poll_cap(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    for _ in range(V.MAX_REQUESTS_PER_POLL + 5):
        file_request(v, "Nope")
    assert len(v.process_requests()) == V.MAX_REQUESTS_PER_POLL


# ------------------------------------------------------------ audit log
def test_audit_log_has_no_password_and_persists(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    v.add_entry("Closed", "u", SECRET + "2")
    ask(v, "Svc")
    ask(v, "Closed")
    ask(v, "Missing")
    log = v.otto_log()
    assert [(r["title"], r["result"]) for r in log[:3]] == [
        ("Missing", "not found"), ("Closed", "denied"), ("Svc", "released")]
    assert all(set(r) == {"t", "title", "result"} for r in log)
    assert SECRET not in json.dumps(log)
    again = V.Vault.open(v.path, PW)                        # stored in the vault
    assert [r["result"] for r in again.otto_log()[:3]] == ["not found", "denied", "released"]
    raw = open(v.path, "rb").read()
    assert b"released" not in raw and SECRET.encode() not in raw   # encrypted at rest


def test_audit_log_capped_and_title_sanitised(v):
    for i in range(V.OTTO_LOG_MAX + 40):
        v._log_otto("t%d" % i, "denied")
    assert len(v.otto_log()) == V.OTTO_LOG_MAX
    assert v.otto_log()[0]["title"] == "t%d" % (V.OTTO_LOG_MAX + 39)
    v._log_otto("a\nb\x00" + "x" * 500, "denied")
    t = v.otto_log()[0]["title"]
    assert "\n" not in t and "\x00" not in t and len(t) <= 100


def test_approval_changes_are_logged(v):
    eid = v.add_entry("Svc", "u", "p")
    v.update_entry(eid, otto_approved=True)
    v.update_entry(eid, notes="n")            # no change -> no extra log line
    v.update_entry(eid, otto_approved=False)
    assert [(r["title"], r["result"]) for r in v.otto_log()] == [
        ("Svc", "revoked"), ("Svc", "approved")]


# --------------------------------------------------------------- locked
def test_locked_vault_gives_no_response(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    req = file_request(v, "Svc")
    v.lock()
    assert v.process_requests() == []
    assert answer(v, req) is None
    assert os.listdir(V.request_dir_for(v.path)) != []      # untouched, will go stale


def test_locked_vault_forgets_everything(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    v.lock()
    assert v.locked and v.list_entries() == [] and v.otto_log() == []


# --------------------------------------------------------------- revoke
def test_unticking_revokes_immediately(v):
    eid = v.add_entry("Svc", "u", SECRET, otto_approved=True)
    assert ask(v, "Svc")[2]["status"] == V.R_RELEASED
    v.update_entry(eid, otto_approved=False)
    assert ask(v, "Svc")[2]["status"] == V.R_DENIED


def test_revoke_all(v):
    for n in ("A", "B", "C"):
        v.add_entry(n, "u", SECRET, otto_approved=True)
    v.add_entry("D", "u", SECRET)
    assert v.approved_count() == 3
    assert v.revoke_all_otto() == 3
    assert v.approved_count() == 0
    for n in ("A", "B", "C"):
        assert ask(v, n)[2]["status"] == V.R_DENIED
    assert V.Vault.open(v.path, PW).approved_count() == 0   # persisted
    assert any(r["result"].startswith("revoked all") for r in v.otto_log())


# --------------------------------------------------------------- crypto
def test_wrong_key_cannot_decrypt_response(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    req, _, _ = ask(v, "Svc")
    p = os.path.join(V.response_dir_for(v.path), req["id"] + V.RESPONSE_EXT)
    blob = open(p, "rb").read()
    pub = V.read_public_key_file(V.public_key_path_for(v.path))
    other = V.make_request("Svc")                            # someone else's ephemeral key
    with pytest.raises(V.VaultError):
        V.response_open(other["eph_private"], pub, blob, req["id"])
    with pytest.raises(V.VaultError):                        # right key, wrong request id
        V.response_open(req["eph_private"], pub, blob, "0" * 32)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    fake_pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    with pytest.raises(V.VaultError):                        # not the vault's real public key
        V.response_open(req["eph_private"], fake_pub, blob, req["id"])
    tampered = bytearray(blob)
    tampered[-10] ^= 1
    with pytest.raises(V.VaultError):
        V.response_open(req["eph_private"], pub, bytes(tampered), req["id"])
    assert V.response_open(req["eph_private"], pub, blob, req["id"])["password"] == SECRET


def test_forged_response_is_rejected(v):
    """A program that only knows the request (public) can encrypt to the
    ephemeral key but cannot authenticate as the vault."""
    req = V.make_request("Svc")
    pub = V.read_public_key_file(V.public_key_path_for(v.path))
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    attacker = X25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    parsed = V.parse_request(req["blob"])
    forged = V.response_seal(attacker, parsed["eph"], req["id"],
                             {"status": "released", "password": "evil"})
    with pytest.raises(V.VaultError):
        V.response_open(req["eph_private"], pub, forged, req["id"])


def test_stale_response_files_swept(v):
    v.add_entry("Svc", "u", SECRET, otto_approved=True)
    req, _, _ = ask(v, "Svc")
    p = os.path.join(V.response_dir_for(v.path), req["id"] + V.RESPONSE_EXT)
    old = os.path.getmtime(p) - V.RESPONSE_MAX_AGE - 10
    os.utime(p, (old, old))
    file_request(v, "Nope")
    v.process_requests()
    assert not os.path.exists(p)


# ------------------------------------------------------- otto_get.py CLI
def test_cli_without_public_key_file_is_an_error(tmp_path, capsys):
    assert otto_get.main(["--dir", str(tmp_path), "--service", "Svc", "--timeout", "1"]) == 6
    assert "Public key file not found" in capsys.readouterr().err


def test_cli_locked_times_out_and_cleans_request(v, base, capsys):
    rc = otto_get.main(["--dir", base, "--service", "Svc", "--timeout", "1"])
    assert rc == 4
    assert "vault locked or not running" in capsys.readouterr().out
    assert os.listdir(V.request_dir_for(v.path)) == []


def _run_cli_with_app(v, base, args, capsys):
    """Run otto_get.main in a thread while this thread plays the app."""
    import threading
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("rc", otto_get.main(
        ["--dir", base, "--timeout", "10"] + args)))
    t.start()
    import time
    end = time.time() + 10
    while t.is_alive() and time.time() < end:
        v.process_requests()
        time.sleep(0.05)
    t.join(2)
    return box["rc"], capsys.readouterr()


def test_cli_default_prints_status_only(v, base, capsys):
    v.add_entry("Svc", "alice", SECRET, otto_approved=True)
    rc, cap = _run_cli_with_app(v, base, ["--service", "svc"], capsys)
    assert rc == 0 and "approved" in cap.out and "NOT printed" in cap.out
    assert SECRET not in cap.out + cap.err


def test_cli_print_flag_prints_password_only_on_stdout(v, base, capsys):
    v.add_entry("Svc", "alice", SECRET, otto_approved=True)
    rc, cap = _run_cli_with_app(v, base, ["--service", "Svc", "--print"], capsys)
    assert rc == 0 and cap.out == SECRET + "\n" and SECRET not in cap.err
    assert os.listdir(V.response_dir_for(v.path)) == []     # response file cleaned up
    assert os.listdir(V.request_dir_for(v.path)) == []


def test_cli_denied_unknown_ambiguous_exit_codes(v, base, capsys):
    v.add_entry("Closed", "u", SECRET)
    v.add_entry("Dup", "a", "x", otto_approved=True)
    v.add_entry("Dup", "b", "y", otto_approved=True)
    for svc, code in (("Closed", 1), ("Nothing", 2), ("Dup", 3)):
        rc, cap = _run_cli_with_app(v, base, ["--service", svc, "--print"], capsys)
        assert rc == code and cap.out == "" and SECRET not in cap.err


def test_cli_rejects_forged_answer(v, base, capsys):
    """A same-user program races a fake 'released' answer: it is ignored."""
    import threading, time
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    attacker = X25519PrivateKey.generate().private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("rc", otto_get.main(
        ["--dir", base, "--timeout", "10", "--service", "Svc", "--print"])))
    t.start()
    d = V.request_dir_for(v.path)
    end = time.time() + 5
    while time.time() < end and not (os.path.isdir(d) and os.listdir(d)):
        time.sleep(0.02)
    name = os.listdir(d)[0]
    parsed = V.parse_request(open(os.path.join(d, name), "rb").read())
    forged = V.response_seal(attacker, parsed["eph"], parsed["id"],
                             {"status": "released", "password": "evil"})
    open(os.path.join(V.response_dir_for(v.path), parsed["id"] + V.RESPONSE_EXT), "wb").write(forged)
    t.join(10)
    cap = capsys.readouterr()
    assert box["rc"] == 6 and "evil" not in cap.out
