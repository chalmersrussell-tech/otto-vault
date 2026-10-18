"""Headless GUI smoke test (run under xvfb-run on Linux). Uses a temp folder and
a throwaway test password only. Real SendInput is never called (mocked)."""
import os, sys, tempfile, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app as A
import autotype as AT
import settings as S
import vault as V

def pump(secs):
    end = time.time() + secs
    while time.time() < end:
        a.update(); time.sleep(0.05)

tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "vault.dat")
shown = []
A.messagebox.askyesno = lambda *x, **k: True
A.messagebox.showinfo = lambda *x, **k: shown.append(x[1])
A.messagebox.showerror = lambda *x, **k: shown.append(x[1])
A.messagebox.showwarning = lambda *x, **k: shown.append(x[1])

a = A.App(vault_path=path)
a.update()
assert not V.Vault.exists(path)
a.pw1.set("throwaway-test-pw"); a.pw2.set("throwaway-test-pw")
a.do_create(); a.update()
assert a.vault and V.Vault.exists(path)
assert os.path.exists(V.public_key_path_for(path)), "public key file not written"
assert a.idle.minutes == 15                                  # default
a.f["title"].set("Test"); a.f["username"].set("u\u00e4"); a.f["password"].set("p4ss!")
a.notes.insert("1.0", "n"); a.save_entry(); a.update()
assert len(a.tree.get_children()) == 1
a.search_var.set("zzz"); a.update(); assert len(a.tree.get_children()) == 0
a.search_var.set("te"); a.update(); assert len(a.tree.get_children()) == 1
a.tree.selection_set(a.tree.get_children()[0]); a.update()
assert a.f["password"].get() == "p4ss!" and a.pw_entry.cget("show") != ""
a.show_var.set(True); a.toggle_show(); assert a.pw_entry.cget("show") == ""
a.copy_password(); assert a.clipboard_get() == "p4ss!"
a._clear_clipboard_now(); a.update(); assert a.clipboard_get() == ""

# settings menu choice persists
a.idle_choice.set("30"); a.on_idle_choice()
assert a.idle.minutes == 30 and S.load_settings(S.settings_path_for(path))["idle_minutes"] == 30

# idle auto-lock with the configured timeout (fake the clock by rewinding)
a.idle._last -= 29 * 60; pump(1.5); assert a.vault is not None, "locked too early"
a.idle._last -= 2 * 60; pump(1.5); assert a.vault is None, "auto-lock did not fire"
# re-open: setting survived; never mode never locks
a.pw1.set("wrong-wrong-1"); a.do_unlock(); assert a.vault is None
a.pw1.set("throwaway-test-pw"); a.do_unlock(); a.update()
assert a.vault and a.idle.minutes == 30
a.idle_choice.set("never"); a.on_idle_choice(); assert a.idle.minutes == "never"
a.idle._last -= 10 ** 7; pump(1.5); assert a.vault is not None, "never mode locked"
# sleep/pause detection locks
a._last_tick -= 1000; pump(1.5); assert a.vault is None, "pause did not lock"

# inbox: Otto drops an entry while the vault is locked; import happens on unlock
pub = V.read_public_key_file(V.public_key_path_for(path))
inbox = V.inbox_dir_for(path); os.makedirs(inbox, exist_ok=True)
open(os.path.join(inbox, "t" + V.INBOX_EXT), "wb").write(
    V.inbox_seal(pub, {"title": "FromOtto", "username": "ou", "password": "op"}))
shown.clear()
a.pw1.set("throwaway-test-pw"); a.do_unlock(); a.update()
assert any("Imported 1 entry from Otto" in m for m in shown), shown
assert os.listdir(inbox) == []
a.search_var.set("fromotto"); a.update(); assert len(a.tree.get_children()) == 1

# auto-type flow with mocked SendInput + short countdown
A.AUTOTYPE_COUNTDOWN = 1
a.search_var.set("")
a.update()
sel = [i for i in a.tree.get_children() if a.vault.get_entry(i)["title"] == "Test"][0]
a.tree.selection_set(sel); a.update()
sent = []
AT.is_supported = lambda: True
AT.foreground_is_own_process = lambda: False
orig_send = AT._win_sender
AT._win_sender = lambda evs: sent.extend(evs)
AT.time.sleep = lambda s: None   # no real pauses
a.do_autotype("both")
pump(2.8)
text = []
for vk, scan, fl in sent:
    if fl & AT.KEYEVENTF_KEYUP: continue
    text.append(chr(scan) if fl & AT.KEYEVENTF_UNICODE else {9: "<T>", 13: "<E>"}[vk])
assert "".join(text) == "u\u00e4<T>p4ss!<E>", text
assert a._countdown_win is None and a.state() == "normal"
# own-window safety: nothing typed if OttoVault itself has focus
sent.clear(); AT.foreground_is_own_process = lambda: True
a.do_autotype("password"); pump(2.8)
assert sent == [], "typed into own window!"
a.destroy()
print("GUI SMOKE OK")
