import ctypes
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import autotype as AT  # noqa: E402
import settings as S  # noqa: E402


# ------------------------------------------------------------- settings
def test_defaults_when_missing(tmp_path):
    s = S.load_settings(str(tmp_path / "nope.json"))
    assert s["idle_minutes"] == 15


def test_save_and_load_roundtrip(tmp_path):
    p = str(tmp_path / "d" / "settings.json")
    for val in (5, 15, 30, 60, "never"):
        S.save_settings(p, {"idle_minutes": val})
        assert S.load_settings(p)["idle_minutes"] == val
    assert [f for f in os.listdir(os.path.dirname(p)) if f.endswith(".tmp")] == []
    doc = json.load(open(p))
    assert set(doc) == {"version", "idle_minutes"}      # only non-secret prefs


@pytest.mark.parametrize("raw", [b"", b"{not json", b"[1,2]", b'{"idle_minutes": 7}',
                                 b'{"idle_minutes": "soon"}', b'{"idle_minutes": true}',
                                 b'{"idle_minutes": null}', b"\xff\xfe\x00"])
def test_corrupt_or_invalid_settings_fall_back_to_default(tmp_path, raw):
    p = tmp_path / "settings.json"
    p.write_bytes(raw)
    assert S.load_settings(str(p))["idle_minutes"] == 15


def test_save_invalid_value_normalised(tmp_path):
    p = str(tmp_path / "s.json")
    assert S.save_settings(p, {"idle_minutes": 999})["idle_minutes"] == 15


def test_settings_path_next_to_vault(tmp_path):
    assert S.settings_path_for(str(tmp_path / "vault.dat")) == str(tmp_path / "settings.json")


# ------------------------------------------------------------- idle logic
class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_idle_expires_at_timeout():
    c = FakeClock()
    t = S.IdleTracker(15, clock=c)
    c.t += 15 * 60 - 1
    assert not t.expired()
    c.t += 1
    assert t.expired()


def test_activity_resets_timer():
    c = FakeClock()
    t = S.IdleTracker(5, clock=c)
    for _ in range(10):          # 10 x 4 min with activity each time -> never expires
        c.t += 4 * 60
        assert not t.expired()
        t.touch()
    c.t += 5 * 60
    assert t.expired()


@pytest.mark.parametrize("m", [5, 15, 30, 60])
def test_each_timeout_option(m):
    c = FakeClock()
    t = S.IdleTracker(m, clock=c)
    c.t += m * 60 - 0.5
    assert not t.expired() and 0 < t.remaining() <= 0.5
    c.t += 1
    assert t.expired() and t.remaining() == 0


def test_never_mode_never_expires():
    c = FakeClock()
    t = S.IdleTracker("never", clock=c)
    c.t += 10 * 365 * 24 * 3600
    assert not t.expired() and t.remaining() is None


def test_changing_setting_applies_and_resets():
    c = FakeClock()
    t = S.IdleTracker(5, clock=c)
    c.t += 200
    t.set_minutes(60)
    c.t += 30 * 60
    assert not t.expired()
    t.set_minutes("never")
    c.t += 99999
    assert not t.expired()
    t.set_minutes(5)
    c.t += 301
    assert t.expired()


def test_default_tracker_is_15_minutes():
    assert S.IdleTracker().minutes == 15


# ------------------------------------------------------------- auto-type
def chars_of(events):
    """Decode the key-down events back to a readable list for assertions."""
    out = []
    for vk, scan, flags in events:
        if flags & AT.KEYEVENTF_KEYUP:
            continue
        if flags & AT.KEYEVENTF_UNICODE:
            out.append(chr(scan))
        elif vk == AT.VK_TAB:
            out.append("<TAB>")
        elif vk == AT.VK_RETURN:
            out.append("<ENTER>")
    return out


def test_sequence_both():
    t = AT.build_sequence("alice", "s3cret", "both")
    assert t == [("text", "alice"), ("key", "tab"), ("text", "s3cret"), ("key", "enter")]


def test_sequence_variants():
    assert AT.build_sequence("alice", "pw", "password") == [("text", "pw"), ("key", "enter")]
    assert AT.build_sequence("alice", "pw", "username") == [("text", "alice"), ("key", "enter")]
    assert AT.build_sequence("", "pw", "both") == [("text", "pw"), ("key", "enter")]
    assert AT.build_sequence("alice", "", "both") == [("text", "alice"), ("key", "tab"), ("key", "enter")]
    assert AT.build_sequence("", "", "both") == []
    assert AT.build_sequence("", "pw", "username") == []
    with pytest.raises(ValueError):
        AT.build_sequence("a", "b", "bogus")


def test_event_order_chars_tab_enter():
    ev = AT.build_events(AT.build_sequence("ab", "cd", "both"))
    assert chars_of(ev) == ["a", "b", "<TAB>", "c", "d", "<ENTER>"]
    # every key is a down immediately followed by an up of the same key
    assert len(ev) % 2 == 0
    for down, up in zip(ev[0::2], ev[1::2]):
        assert down[:2] == up[:2]
        assert not down[2] & AT.KEYEVENTF_KEYUP and up[2] & AT.KEYEVENTF_KEYUP


def test_unicode_flag_and_special_characters():
    pw = "P@ss!\"'\\{}[]<>|~`^%&*()_+=;:,./?äöüß€Ω漢"
    ev = AT.text_events(pw)
    assert chars_of(ev) == list(pw)
    for vk, scan, flags in ev:
        assert vk == 0 and flags & AT.KEYEVENTF_UNICODE


def test_non_bmp_uses_surrogate_pairs():
    ev = AT.text_events("😀")                      # U+1F600 -> D83D DE00
    downs = [e[1] for e in ev if not e[2] & AT.KEYEVENTF_KEYUP]
    assert downs == [0xD83D, 0xDE00]


def test_newline_and_tab_in_text_become_keys():
    assert chars_of(AT.text_events("a\tb\r\nc")) == ["a", "<TAB>", "b", "<ENTER>", "c"]


def test_type_tokens_with_mock_sendinput_and_no_real_sleep():
    sent, naps = [], []
    AT.type_tokens(AT.build_sequence("üser", "pä$$", "both"),
                   sender=lambda evs: sent.append(list(evs)),
                   sleep=naps.append, delay=0.004)
    flat = [e for batch in sent for e in batch]
    assert chars_of(flat) == ["ü", "s", "e", "r", "<TAB>", "p", "ä", "$", "$", "<ENTER>"]
    assert all(len(b) == 2 for b in sent)          # one key (down+up) per call
    assert len(naps) == len(sent) and all(n == 0.004 for n in naps)


def test_sender_error_propagates():
    def boom(_):
        raise AT.AutoTypeError("blocked")
    with pytest.raises(AT.AutoTypeError):
        AT.type_tokens([("text", "x")], sender=boom, sleep=lambda s: None)


def test_win_sender_refuses_off_windows(monkeypatch):
    monkeypatch.setattr(AT.sys, "platform", "linux")
    with pytest.raises(AT.AutoTypeError):
        AT._win_sender([(0, 65, AT.KEYEVENTF_UNICODE)])
    assert AT.foreground_is_own_process() is False


def test_input_struct_layout_matches_windows():
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(AT.INPUT) == 40       # what 64-bit Windows expects
    else:
        assert ctypes.sizeof(AT.INPUT) == 28
    i = AT.INPUT(); i.type = AT.INPUT_KEYBOARD
    i.u.ki = AT._KEYBDINPUT(0, 0x20AC, AT.KEYEVENTF_UNICODE, 0, 0)
    assert i.u.ki.wScan == 0x20AC


def test_module_does_not_touch_clipboard():
    src = open(AT.__file__, encoding="utf-8").read()
    assert "clipboard_append" not in src and "pyperclip" not in src and "OpenClipboard" not in src
