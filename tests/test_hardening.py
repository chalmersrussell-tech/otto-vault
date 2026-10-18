"""1.3.0 hardening: Argon2id + KDF upgrade, input validation, AI-access expiry,
unlock lockout, tamper-evident access log, no secrets on disk.
Only throwaway vaults in temp dirs with throwaway passwords."""
import base64
import json
import logging
import os
import sys
import time

import pytest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
import vault as V  # noqa: E402
import lockout as L  # noqa: E402
import settings as S  # noqa: E402
import otto_add  # noqa: E402

PW = "test-master-pw-123"
needs_argon2 = pytest.mark.skipif(not V.argon2_available(),
                                  reason="needs cryptography >= 44 (Argon2id)")


@pytest.fixture
def vpath(tmp_path):
    return str(tmp_path / "vault.dat")


@pytest.fixture
def v(vpath):
    vv = V.Vault.create(vpath, PW)
    vv.write_public_key_file()
    return vv


def header(path):
    return json.load(open(path))["kdf"]


# ================================================================== KDF
@needs_argon2
def test_default_argon2_parameters():
    p = V.REAL_ARGON2_PARAMS
    assert p["m"] >= 65536 and p["t"] >= 3 and p["p"] >= 4          # RFC 9106 option 2


@needs_argon2
def test_new_vault_uses_argon2id_and_opens(vpath):
    V.Vault.create(vpath, PW).add_entry("a", "u", "p")
    h = header(vpath)
    assert h["name"] == "argon2id" and h["m"] >= V.ARGON2_MIN["m"] and h["v"] == 0x13
    assert len(base64.b64decode(h["salt"])) == 16
    assert len(V.Vault.open(vpath, PW).list_entries()) == 1
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, PW + "x")


@needs_argon2
def test_real_default_params_roundtrip(vpath, monkeypatch):
    monkeypatch.setattr(V, "ARGON2_PARAMS", dict(V.REAL_ARGON2_PARAMS))
    V.Vault.create(vpath, PW)
    assert header(vpath)["m"] == 65536
    assert V.Vault.open(vpath, PW).kdf_upgraded is False


@needs_argon2
def test_scrypt_vault_opens_and_is_upgraded_once(vpath):
    v = V.Vault.create(vpath, PW, kdf="scrypt")
    v.add_entry("keep", "u", "secret-1")
    assert header(vpath)["name"] == "scrypt"
    old_bytes = open(vpath, "rb").read()
    v2 = V.Vault.open(vpath, PW)
    assert v2.kdf_upgraded is True and header(vpath)["name"] == "argon2id"
    assert [e["password"] for e in v2.list_entries()] == ["secret-1"]
    keep = vpath + ".pre-upgrade.bak"
    assert open(keep, "rb").read() == old_bytes                       # safety copy of the old file
    assert V.Vault.open(keep, PW, upgrade_kdf=False).kdf_name == "scrypt"
    v3 = V.Vault.open(vpath, PW)                                      # second open: nothing to do
    assert v3.kdf_upgraded is False and open(keep, "rb").read() == old_bytes
    assert [e["password"] for e in v3.list_entries()] == ["secret-1"]


@needs_argon2
def test_wrong_password_never_upgrades_or_changes_file(vpath):
    V.Vault.create(vpath, PW, kdf="scrypt")
    before = open(vpath, "rb").read()
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, "wrong-wrong-1")
    assert open(vpath, "rb").read() == before and not os.path.exists(vpath + ".pre-upgrade.bak")


def test_upgrade_can_be_disabled(vpath):
    V.Vault.create(vpath, PW, kdf="scrypt")
    v = V.Vault.open(vpath, PW, upgrade_kdf=False)
    assert v.kdf_name == "scrypt" and header(vpath)["name"] == "scrypt"


@needs_argon2
def test_weak_or_absurd_argon2_headers_rejected(vpath):
    V.Vault.create(vpath, PW)
    orig = json.load(open(vpath))
    for k, val in (("m", 8), ("m", 2 ** 31), ("t", 1), ("t", 99), ("p", 0), ("p", 99),
                   ("m", "65536"), ("v", 0x10)):
        d = json.loads(json.dumps(orig))
        d["kdf"][k] = val
        json.dump(d, open(vpath, "w"))
        with pytest.raises(V.CorruptVaultError):
            V.Vault.open(vpath, PW)


@needs_argon2
def test_argon2_header_is_authenticated(vpath):
    V.Vault.create(vpath, PW)
    d = json.load(open(vpath))
    d["kdf"]["t"] += 1                    # still in the allowed range
    json.dump(d, open(vpath, "w"))
    with pytest.raises(V.WrongPasswordError):
        V.Vault.open(vpath, PW)


@needs_argon2
def test_change_master_password_keeps_argon2_and_log_chain(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("A", "u", "p", otto_approved=True)
    v.change_master_password(PW, "brand-new-pw-456")
    assert header(vpath)["name"] == "argon2id"
    v2 = V.Vault.open(vpath, "brand-new-pw-456")
    assert v2.integrity_warnings == [] and len(v2.otto_log()) == 1


def test_without_argon2_support_falls_back_and_explains(vpath, monkeypatch):
    if not V.argon2_available():
        pytest.skip("already running without Argon2id")
    V.Vault.create(vpath, PW)                                          # argon2 vault on disk
    monkeypatch.setattr(V, "Argon2id", None)
    with pytest.raises(V.VaultError, match="cryptography"):
        V.Vault.open(vpath, PW)
    other = vpath + "2"
    v = V.Vault.create(other, PW)                                      # new vault -> scrypt
    assert v.kdf_name == "scrypt"
    assert V.Vault.open(other, PW).kdf_upgraded is False


# ============================================ master password never stored
def test_master_password_never_stored_or_logged(vpath, tmp_path, capsys, caplog):
    secret = "Ultra-Secret-Master-4711"
    caplog.set_level(logging.DEBUG)
    v = V.Vault.create(vpath, secret)
    v.write_public_key_file()
    v.add_entry("Svc", "alice", "entry-pw-1", otto_approved=True)
    S.save_settings(S.settings_path_for(vpath), {"idle_minutes": 30})
    lk = L.Lockout(L.lockout_path_for(vpath))
    for _ in range(6):
        lk.record_failure()
    for _ in range(2):
        with pytest.raises(V.WrongPasswordError):
            V.Vault.open(vpath, secret + "x")
    v.process_requests()
    v.change_master_password(secret, secret + "-2")
    v.export_backup(str(tmp_path / "b.ottovault"))
    V.Vault.open(vpath, secret + "-2")
    blobs = [secret.encode(), (secret + "-2").encode(), base64.b64encode(secret.encode()),
             base64.b64encode((secret + "-2").encode())]
    for root, _d, files in os.walk(tmp_path):
        for f in files:
            raw = open(os.path.join(root, f), "rb").read()
            for b in blobs:
                assert b not in raw, f
    out = capsys.readouterr()
    assert secret not in out.out + out.err + caplog.text
    assert not [val for val in vars(v).values() if val in (secret, secret + "-2")]


# ============================================================ validation
def test_length_caps_per_field(v):
    ok = {"title": "t" * 200, "username": "u" * 256, "password": "p" * 1024,
          "url": "h" * 2048, "notes": "n" * 20000}
    eid = v.add_entry(**ok)
    assert v.get_entry(eid)["notes"] == "n" * 20000
    for field, n in (("title", 201), ("username", 257), ("password", 1025),
                     ("url", 2049), ("notes", 20001)):
        bad = dict(ok); bad[field] = "x" * n
        with pytest.raises(V.VaultError, match="too long"):
            v.add_entry(**bad)
        with pytest.raises(V.VaultError, match="too long"):
            v.update_entry(eid, **{field: "x" * n})
    assert len(v.list_entries()) == 1


@pytest.mark.parametrize("field", ["title", "username", "url", "password", "notes"])
def test_nul_and_control_characters_rejected(v, field):
    for bad in ("a\x00b", "a\x07b", "a\x1bb", "a\x7fb"):
        with pytest.raises(V.VaultError, match="not allowed"):
            v.add_entry(**{"title": "T", field: bad} if field != "title" else {"title": bad})
    assert v.list_entries() == []


def test_notes_allow_newlines_and_tabs_but_normalise_them(v):
    eid = v.add_entry("T", notes="line1\r\nline2\rline3\tx")
    assert v.get_entry(eid)["notes"] == "line1\nline2\nline3\tx"


def test_passwords_stay_free_form(v):
    pw = "  p@$$ w0rd!\"'`;|&<>\\/{}[]%$#~\u00e9\u4e2d\U0001F600  "
    eid = v.add_entry("T", password=pw)
    assert v.get_entry(eid)["password"] == pw                  # not stripped, not altered
    assert V.Vault.open(v.path, PW).get_entry(eid)["password"] == pw
    with pytest.raises(V.VaultError):                          # but no newline/tab/NUL
        v.add_entry("T2", password="a\nb")
    with pytest.raises(V.VaultError):
        v.add_entry("T3", password="a\tb")


def test_title_whitespace_is_collapsed_and_invisible_chars_refused(v):
    eid = v.add_entry("  My \t\n  Bank\u00a0\u00a0Site  ", username=" bob   smith ")
    e = v.get_entry(eid)
    assert e["title"] == "My Bank Site" and e["username"] == "bob smith"
    for bad in ("Ba\u200bnk", "Bank\u202eFDP", "Bank\ufeff"):  # zero-width, RTL override, BOM
        with pytest.raises(V.VaultError, match="not allowed"):
            v.add_entry(bad)
    with pytest.raises(V.VaultError, match="required"):
        v.add_entry("   \t ")


def test_title_is_nfc_and_matching_ignores_spacing_case_and_compat_forms(v):
    v.add_entry("Caf\u00e9  Main", "u", "pw-x", otto_approved=True)       # composed e-acute
    assert v.list_entries()[0]["title"] == "Caf\u00e9 Main"
    import test_otto_access as T                                          # reuse helpers
    for q in ("cafe\u0301 main", "  CAF\u00c9   MAIN ", "\uff23af\u00e9 Main"):  # decomposed / fullwidth C
        req, res, body = T.ask(v, q)
        assert body["status"] == V.R_RELEASED, q


def test_update_only_revalidates_changed_fields(v):
    eid = v.add_entry("T", notes="x")
    v._data["entries"][0]["notes"] = "n" * 30000                # legacy over-long entry
    v.update_entry(eid, title="Renamed", notes="n" * 30000)     # unchanged field is not rejected
    assert v.get_entry(eid)["title"] == "Renamed"
    with pytest.raises(V.VaultError):
        v.update_entry(eid, notes="m" * 30000)


def test_non_string_values_rejected(v):
    with pytest.raises(V.VaultError):
        v.add_entry("T", username=123)
    eid = v.add_entry("T")
    with pytest.raises(V.VaultError):
        v.update_entry(eid, url=["x"])


def test_inbox_payload_validated(v, tmp_path):
    pub = V.read_public_key_file(V.public_key_path_for(v.path))
    inbox = V.inbox_dir_for(v.path)
    os.makedirs(inbox)
    cases = {"nul": {"title": "Bad\x00Title", "password": "x"},
             "long": {"title": "T", "password": "x", "notes": "n" * 25000},
             "bidi": {"title": "Evil\u202e", "password": "x"},
             "good": {"title": "Good\n  Site", "password": "pw", "username": "u"}}
    for name, entry in cases.items():
        open(os.path.join(inbox, name + V.INBOX_EXT), "wb").write(V.inbox_seal(pub, entry))
    assert v.import_inbox() == (1, 3)
    assert [e["title"] for e in v.list_entries()] == ["Good Site"]
    assert sorted(f for f in os.listdir(inbox)) == ["bidi.ottoentry.bad", "long.ottoentry.bad",
                                                    "nul.ottoentry.bad"]


def test_csv_import_skips_invalid_rows(v, tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("title,username,password\nGood,u,pw\nBad\x00,u,pw\nLong,u," + "p" * 2000 + "\n",
                 encoding="utf-8")
    assert v.import_csv(str(p)) == (1, 2)
    assert [e["title"] for e in v.list_entries()] == ["Good"]


def test_otto_add_validates_before_queueing(v, capsys, monkeypatch):
    base = os.path.dirname(v.path)
    inbox = V.inbox_dir_for(v.path)
    assert otto_add.main(["--dir", base, "--service", "Bad\x00Name", "--generate-password"]) == 2
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO("p" * 2000 + "\n"))
    assert otto_add.main(["--dir", base, "--service", "Svc", "--password-stdin"]) == 2
    assert otto_add.main(["--dir", base, "--service", "Svc", "--username", "a\x07b",
                          "--generate-password"]) == 2
    assert not os.path.isdir(inbox) or os.listdir(inbox) == []
    assert otto_add.main(["--dir", base, "--service", "  Fine \n Svc ", "--username", "bob",
                          "--generate-password"]) == 0
    assert "Fine Svc" in capsys.readouterr().out
    assert len(os.listdir(inbox)) == 1


def test_requests_with_control_characters_refused():
    with pytest.raises(V.VaultError):
        V.make_request("Svc\x00")
    req = V.make_request("Svc")
    doc = json.loads(req["blob"])
    doc["service"] = "Svc\x1b[31m"
    with pytest.raises(V.VaultError):
        V.parse_request(json.dumps(doc).encode())


# ============================================================ AI expiry
def test_new_approval_gets_default_30_day_expiry(v):
    assert v.expiry_days == 30
    t0 = int(time.time())
    eid = v.add_entry("A", "u", "p", otto_approved=True)
    e = v.get_entry(eid)
    assert e["otto_approved"] and abs(e["otto_approved_at"] - t0) < 5
    assert e["otto_expires"] - e["otto_approved_at"] == 30 * 86400
    eid2 = v.add_entry("B", "u", "p")
    assert v.get_entry(eid2)["otto_expires"] is None
    v.update_entry(eid2, otto_approved=True)
    assert v.get_entry(eid2)["otto_expires"] - v.get_entry(eid2)["otto_approved_at"] == 30 * 86400


def test_expiry_choices_7_30_never(vpath):
    for days, expect in ((7, 7 * 86400), (30, 30 * 86400), (0, None)):
        d = vpath + str(days)
        v = V.Vault.create(d, PW, expiry_days=days)
        eid = v.add_entry("A", otto_approved=True)
        e = v.get_entry(eid)
        assert (e["otto_expires"] - e["otto_approved_at"] if expect else e["otto_expires"]) == expect
    assert S.normalize_expiry(7) == 7 and S.normalize_expiry(0) == 0
    for junk in (5, "30", True, None, -1, 3.5):
        assert S.normalize_expiry(junk) == 30
    p = S.settings_path_for(vpath)
    S.save_settings(p, {"idle_minutes": 15, "ai_expiry_days": 7})
    assert S.load_settings(p)["ai_expiry_days"] == 7
    assert S.load_settings(str(os.path.join(os.path.dirname(vpath), "none.json")))["ai_expiry_days"] == 30


def test_expiry_cannot_be_set_through_update_entry(v):
    eid = v.add_entry("A")
    with pytest.raises(V.VaultError):
        v.update_entry(eid, otto_expires=None)
    with pytest.raises(V.VaultError):
        v.update_entry(eid, otto_approved_at=1)


def test_expired_approval_is_turned_off_logged_and_denied(v):
    import test_otto_access as T
    eid = v.add_entry("Svc", "u", "pw-secret", otto_approved=True)
    assert T.ask(v, "Svc")[2]["status"] == V.R_RELEASED
    later = time.time() + 31 * 86400
    req = T.file_request(v, "Svc", now=later)
    res = v.process_requests(now=later)
    assert ("Svc", "expired") in res and ("Svc", V.R_DENIED) in res
    assert T.answer(v, req)["status"] == V.R_DENIED
    e = v.get_entry(eid)
    assert e["otto_approved"] is False and e["otto_expires"] is None   # must be re-ticked
    assert any(r["result"] == "expired" for r in v.otto_log())
    assert V.Vault.open(v.path, PW).get_entry(eid)["otto_approved"] is False   # persisted
    v.update_entry(eid, otto_approved=True)                             # re-tick = new grant
    assert T.ask(v, "Svc")[2]["status"] == V.R_RELEASED


def test_expired_flag_is_not_honoured_even_if_sweep_is_skipped(v):
    eid = v.add_entry("Svc", "u", "pw", otto_approved=True)
    v._data["entries"][0]["otto_expires"] = int(time.time()) - 5
    req = {"service": "Svc", "username": ""}
    assert v._decide(req, time.time())[0] == V.R_DENIED


def test_legacy_approvals_get_an_expiry_on_migration(vpath):
    v = V.Vault.create(vpath, PW)
    v.add_entry("Old", "u", "p")
    ent = v._data["entries"][0]
    ent["otto_approved"] = True                       # what a 1.2.x vault looks like
    ent.pop("otto_approved_at"); ent.pop("otto_expires")
    v.save()
    v2 = V.Vault.open(vpath, PW)
    e = v2.list_entries()[0]
    assert e["otto_approved"] is True
    assert e["otto_expires"] - e["otto_approved_at"] == 30 * 86400
    assert any(r["result"] == "approval period set" for r in v2.otto_log())
    assert V.Vault.open(vpath, PW).list_entries()[0]["otto_expires"] == e["otto_expires"]


def test_every_grant_and_revoke_is_logged(v):
    a = v.add_entry("A", otto_approved=True)                      # grant at creation
    b = v.add_entry("B")
    v.update_entry(b, otto_approved=True)                          # grant
    v.update_entry(b, notes="n")                                   # no change -> no line
    v.update_entry(b, otto_approved=False)                         # revoke
    v.update_entry(b, otto_approved=False)                         # already off -> no line
    c = v.add_entry("C", otto_approved=True)
    v.delete_entry(c)                                              # revoke by deletion
    d = v.add_entry("D", otto_approved=True)
    v.revoke_all_otto()                                            # per-entry + summary
    got = [(r["title"], r["result"].split(" (")[0]) for r in reversed(v.otto_log())]
    assert got == [("A", "approved"), ("B", "approved"), ("B", "revoked"), ("C", "approved"),
                   ("C", "revoked"), ("D", "approved"), ("A", "revoked"), ("D", "revoked"),
                   ("(all entries)", "revoked all")]


# ================================================================ lockout
def test_delay_schedule():
    assert [L.delay_for(n) for n in (0, 1, 4)] == [0, 0, 0]
    assert [L.delay_for(n) for n in (5, 6, 7, 8)] == [30, 60, 120, 240]
    assert L.delay_for(10) == 900 and L.delay_for(500) == 900     # capped at 15 minutes


def test_lockout_after_five_failures_increases_and_resets(tmp_path):
    clock = [1_000_000.0]
    p = str(tmp_path / "lockout.json")
    lk = L.Lockout(p, clock=lambda: clock[0])
    for _ in range(4):
        assert lk.record_failure() == 0 and lk.remaining() == 0
    assert lk.tries_left() == 1
    assert lk.record_failure() == 30 and lk.remaining() == 30
    clock[0] += 10
    assert lk.remaining() == 20
    clock[0] += 25
    assert lk.remaining() == 0
    assert lk.record_failure() == 60 and lk.remaining() == 60
    clock[0] += 61
    assert lk.record_failure() == 120
    # a fresh instance (app restarted) sees the same state
    lk2 = L.Lockout(p, clock=lambda: clock[0])
    assert lk2.failures == 7 and lk2.remaining() == 120
    lk2.record_success()
    assert lk2.failures == 0 and lk2.remaining() == 0 and not os.path.exists(p)
    assert L.Lockout(p, clock=lambda: clock[0]).failures == 0


def test_lockout_cap_and_clock_rollback(tmp_path):
    clock = [1_000_000.0]
    lk = L.Lockout(str(tmp_path / "l.json"), clock=lambda: clock[0])
    for _ in range(30):
        lk.record_failure()
    assert lk.remaining() == 900
    clock[0] -= 10 ** 6                       # clock set far back must not lock for days
    assert lk.remaining() <= 900


def test_lockout_file_has_no_password_and_detects_edits(tmp_path):
    p = str(tmp_path / "l.json")
    lk = L.Lockout(p)
    for _ in range(6):
        lk.record_failure()
    doc = json.load(open(p))
    assert set(doc) == {"version", "salt", "failures", "until", "check"}
    doc["failures"] = 0                       # casual hand-edit to reset the counter
    json.dump(doc, open(p, "w"))
    lk2 = L.Lockout(p)
    assert lk2.failures == L.FREE_ATTEMPTS and lk2.remaining() > 0
    open(p, "w").write("garbage")
    assert L.Lockout(p).failures == L.FREE_ATTEMPTS


def test_lockout_is_independent_of_vault_and_does_not_block_open(vpath):
    """The counter is enforced by the unlock UI; the vault API stays pure."""
    V.Vault.create(vpath, PW)
    lk = L.Lockout(L.lockout_path_for(vpath))
    for _ in range(6):
        lk.record_failure()
    assert V.Vault.open(vpath, PW).list_entries() == []


# =========================================================== audit MAC
def reopen(path):
    return V.Vault.open(path, PW)


def make_log(v, n=5):
    for i in range(n):
        v._log_otto("Svc%d" % i, "denied")
    v.save()


def tamper(path, fn):
    """Edit the decrypted vault the way a hostile tool would (valid encryption,
    no MAC recomputation)."""
    w = V.Vault.open(path, PW)
    fn(w._data)
    V._atomic_write(path, V._encrypt(w._data, w._key, w._kdf))   # raw write: anchor not updated


def test_clean_log_verifies_and_survives_reopen(v):
    make_log(v)
    w = reopen(v.path)
    assert w.integrity_warnings == []
    assert [r["title"] for r in w.otto_log()] == ["Svc4", "Svc3", "Svc2", "Svc1", "Svc0"]


def test_flipped_entry_is_detected_reported_and_recorded(v):
    make_log(v)
    tamper(v.path, lambda d: d["otto_log"][2].__setitem__("result", "released"))
    w = reopen(v.path)
    assert w.integrity_warnings and "entry 3" in w.integrity_warnings[0]
    assert w.otto_log()[0]["result"] == "log integrity warning"
    assert w.otto_log()[0]["title"].startswith("entry 3")
    again = reopen(v.path)                                    # reported once, event persists
    assert again.integrity_warnings == []
    assert any(r["result"] == "log integrity warning" for r in again.otto_log())


@pytest.mark.parametrize("edit", [
    lambda d: d["otto_log"].pop(1),                                   # deleted from the middle
    lambda d: d["otto_log"].pop(0),                                   # deleted from the start
    lambda d: d["otto_log"].reverse(),                                # reordered
    lambda d: d["otto_log"][1].__setitem__("title", "Other"),         # renamed
    lambda d: d["otto_log"][1].__setitem__("t", 5),                   # re-dated
    lambda d: d["otto_log"][1].pop("mac"),                            # MAC stripped
    lambda d: d["otto_log"][1].__setitem__("mac", "0" * 64),          # MAC forged
    lambda d: d["otto_log"].insert(2, {"t": 1, "title": "x", "result": "denied", "mac": "1" * 64}),
])
def test_various_edits_are_detected(v, edit):
    make_log(v)
    tamper(v.path, lambda d: edit(d))
    assert reopen(v.path).integrity_warnings


def test_deleting_the_last_entries_is_caught_by_the_anchor(v):
    make_log(v)
    tamper(v.path, lambda d: (d["otto_log"].__delitem__(slice(3, None)),
                              d.__setitem__("otto_log_total", 3)))
    w = reopen(v.path)
    assert w.integrity_warnings and "older" in w.integrity_warnings[0]


def test_rolled_back_vault_copy_is_caught(v):
    for i in range(3):
        v._log_otto("a%d" % i, "denied")
    v.save()
    snapshot = open(v.path, "rb").read()
    for i in range(2):
        v._log_otto("b%d" % i, "denied")
    v.save()
    open(v.path, "wb").write(snapshot)                         # restore the older file
    assert reopen(v.path).integrity_warnings


def test_forged_anchor_and_missing_anchor(v):
    make_log(v)
    ap = V.anchor_path_for(v.path)
    doc = json.load(open(ap))
    doc["total"] = 999                                         # edit without the key -> bad tag
    json.dump(doc, open(ap, "w"))
    assert reopen(v.path).integrity_warnings
    os.remove(ap)                                              # no anchor = nothing to compare
    w = reopen(v.path)
    assert w.integrity_warnings == [] and os.path.exists(ap)   # (limit: documented in README)


def test_legacy_unchained_log_is_adopted_without_false_alarm(v):
    v._data["otto_log"] = [{"t": 1, "title": "Old%d" % i, "result": "released"} for i in range(4)]
    v._data.pop("otto_log_total", None)
    v._data.pop("otto_log_base", None)
    v.save()
    os.remove(V.anchor_path_for(v.path))
    w = reopen(v.path)
    assert w.integrity_warnings == []
    log = w.otto_log()
    assert len(log) == 5 and log[0]["result"] == "log chain enabled"
    assert reopen(v.path).integrity_warnings == []


def test_trimmed_log_still_verifies(v):
    for i in range(V.OTTO_LOG_MAX + 25):
        v._log_otto("t%d" % i, "denied")
    v.save()
    w = reopen(v.path)
    assert w.integrity_warnings == [] and len(w.otto_log()) == V.OTTO_LOG_MAX
    assert w._data["otto_log_total"] == V.OTTO_LOG_MAX + 25 and w._data["otto_log_base"] != ""
    tamper(v.path, lambda d: d["otto_log"][10].__setitem__("result", "released"))
    assert reopen(v.path).integrity_warnings


def test_log_never_contains_password_even_with_mac_fields(v):
    import test_otto_access as T
    v.add_entry("Svc", "u", "Zz-top-secret-77", otto_approved=True)
    T.ask(v, "Svc")
    assert "Zz-top-secret-77" not in json.dumps(v._data["otto_log"])
    assert set(v._data["otto_log"][-1]) == {"t", "title", "result", "mac"}


def test_csv_dedupe_compares_normalised_form_crlf(v, tmp_path):
    """Windows CSV files carry CRLF inside quoted notes; notes are stored with LF,
    so a second import of the same file must still be recognised as duplicates."""
    p = tmp_path / "w.csv"
    p.write_bytes(b'title,username,password,notes\r\n"A","u","p","multi\r\nline"\r\n')
    assert v.import_csv(str(p)) == (1, 0)
    assert v.list_entries()[0]["notes"] == "multi\nline"
    assert v.import_csv(str(p)) == (0, 1)
