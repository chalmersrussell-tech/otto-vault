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

# ---- failed-unlock lockout: 5 wrong passwords -> Unlock disabled, even the right one refused
for i in range(5):
    a.pw1.set("wrong-wrong-%d" % i); a.do_unlock()
assert a.vault is None and a.lockout.remaining() > 0
a.update()
assert "disabled" in a.unlock_btn.state(), a.unlock_btn.state()
assert "Too many wrong passwords" in a.lock_msg.get(), a.lock_msg.get()
assert os.path.exists(os.path.join(os.path.dirname(path), "lockout.json"))
assert b"throwaway-test-pw" not in open(os.path.join(os.path.dirname(path), "lockout.json"), "rb").read()
a.pw1.set("throwaway-test-pw"); a.do_unlock()
assert a.vault is None, "unlocked during lockout!"
a.lockout.until = int(time.time()) - 1; pump(1.5)          # the delay has passed
assert "disabled" not in a.unlock_btn.state()
a.pw1.set("throwaway-test-pw"); a.do_unlock(); a.update()
assert a.vault is not None and a.lockout.failures == 0
assert not os.path.exists(os.path.join(os.path.dirname(path), "lockout.json"))
a.lock(); a.update()

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

# ---- AI access approval (checkbox, request answering, revoke, log)
def otto_ask(service):
    req = V.make_request(service)
    d = V.request_dir_for(path); os.makedirs(d, exist_ok=True)
    open(os.path.join(d, req["id"] + V.REQUEST_EXT), "wb").write(req["blob"])
    pump(A.REQUEST_CHECK_SECS + 2.5)
    rp = os.path.join(V.response_dir_for(path), req["id"] + V.RESPONSE_EXT)
    if not os.path.exists(rp):
        return None
    return V.response_open(req["eph_private"], V.read_public_key_file(V.public_key_path_for(path)),
                           open(rp, "rb").read(), req["id"])

# user-facing wording of the AI-access feature
def widget_texts(w):
    out = []
    for c in w.winfo_children():
        try: out.append(c.cget("text"))
        except Exception: pass
        out += widget_texts(c)
    return out
assert "Allow AI access to this password" in widget_texts(a)
assert a.tree.heading("ai", "text") == "AI"
def menu_labels(m):
    out = []
    for i in range(m.index("end") + 1):
        if m.type(i) == "cascade":
            out += menu_labels(m.nametowidget(m.entrycget(i, "menu")))
        elif m.type(i) not in ("separator", "tearoff"):
            out.append(m.entrycget(i, "label"))
    return out
labels = menu_labels(a.nametowidget(a.cget("menu")))
assert "AI access log..." in labels and "Revoke all AI access approvals..." in labels, labels
assert not any("Otto" in l for l in labels), labels
a.search_var.set(""); a.update()
tid = [i for i in a.tree.get_children() if a.vault.get_entry(i)["title"] == "Test"][0]
a.tree.selection_set(tid); a.update()
assert a.otto_var.get() is False and a.tree.set(tid, "ai") == ""
assert otto_ask("Test")["status"] == "denied"
assert "An AI assistant asked for 'Test' - not approved" in a.status.get(), a.status.get()
a.otto_var.set(True); a.save_entry(); a.update()
assert a.vault.get_entry(tid)["otto_approved"] is True and a.tree.set(tid, "ai") == "\u2713"
assert "AI assistants may use this password" in a.status.get()
body = otto_ask("test")
assert body["status"] == "released" and body["password"] == "p4ss!", body
a.tree.selection_set(()); a.update(); a.tree.selection_set(tid); a.update()
assert a.otto_var.get() is True                      # checkbox reloads from the vault
a.show_otto_log(); a.update()
assert a._log_win is not None and len(a._log_win.tree.get_children()) >= 3
a._log_win._close(); a.update()
a.otto_var.set(False); a.save_entry(); a.update()    # untick = immediate revoke
assert otto_ask("Test")["status"] == "denied"
a.otto_var.set(True); a.save_entry(); a.update()
assert otto_ask("Test")["status"] == "released"
a.do_revoke_all(); a.update()
assert a.vault.approved_count() == 0 and a.otto_var.get() is False
assert otto_ask("Test")["status"] == "denied"
assert otto_ask("No such service")["status"] == "not found"
# a locked app never answers
a.otto_var.set(True); a.save_entry(); a.update()
a.lock(); a.update()
assert otto_ask("Test") is None, "answered while locked!"
a.pw1.set("throwaway-test-pw"); a.do_unlock(); a.update()
print("otto approval GUI OK")

# ---- AI access expiry (settings menu, form label, sweep) and log-integrity warning
assert "AI access approval lasts (for new approvals):" in menu_labels(a.nametowidget(a.cget("menu")))
a.expiry_choice.set("7"); a.on_expiry_choice()
assert S.load_settings(S.settings_path_for(path))["ai_expiry_days"] == 7 and a.vault.expiry_days == 7
a.tree.selection_set(tid); a.update()
a.otto_var.set(False); a.save_entry(); a.update()
a.otto_var.set(True); a.save_entry(); a.update()           # a fresh grant uses the new setting
e = a.vault.get_entry(tid)
assert e["otto_expires"] - e["otto_approved_at"] == 7 * 86400
assert a.expiry_text.get().startswith("AI access ends "), a.expiry_text.get()
a.expiry_choice.set("30"); a.on_expiry_choice()
a.vault._data["entries"][[x["id"] for x in a.vault._data["entries"]].index(tid)]["otto_expires"] = int(time.time()) - 5
a._last_request_check = 0; pump(A.REQUEST_CHECK_SECS + 1.5)
assert a.vault.get_entry(tid)["otto_approved"] is False
assert a.otto_var.get() is False, "form still ticked after expiry"
assert "expired" in a.status.get(), a.status.get()
assert a.tree.set(tid, "ai") == ""
# tamper with the in-vault log (raw write) -> loud warning on next unlock
a.lock(); a.update()
w = V.Vault.open(path, "throwaway-test-pw")
w._data["otto_log"][1]["result"] = "released"
V._atomic_write(path, V._encrypt(w._data, w._key, w._kdf))
shown.clear()
a.pw1.set("throwaway-test-pw"); a.do_unlock(); a.update()
assert any("tampered" in m for m in shown), shown
assert "WARNING" in a.status.get()
assert a.vault.otto_log()[0]["result"] == "log integrity warning"
print("hardening GUI OK")

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
