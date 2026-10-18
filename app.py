"""OttoVault - desktop GUI (tkinter). All crypto/storage lives in vault.py."""
import os
import sys
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import autotype as AT
import lockout as L
import settings as S
import vault as V

APP_NAME = "OttoVault"
CLIPBOARD_CLEAR_SECS = 20
SLEEP_GAP_SECS = 90          # a gap this long between timer ticks = PC was asleep
AUTOTYPE_COUNTDOWN = 3
INBOX_CHECK_SECS = 15
REQUEST_CHECK_SECS = 2         # AI password requests are answered quickly
EXPIRY_CHOICES = ((30, "30 days (default)"), (7, "7 days"), (0, "Never expires"))
IDLE_CHOICES = ((5, "5 minutes"), (15, "15 minutes"), (30, "30 minutes"),
                (60, "60 minutes"), ("never", "Until I lock it or close the app"))
NO_RECOVERY_WARNING = (
    "IMPORTANT: Your master password can NOT be recovered.\n"
    "If you forget it, your passwords are gone for good - nobody can reset it.\n"
    "Write it down and keep it somewhere safe.")


class PasswordPrompt(tk.Toplevel):
    """Small modal dialog asking for one or more hidden fields."""

    def __init__(self, parent, title, labels, message=None):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)
        self.result = None
        frm = ttk.Frame(self, padding=14)
        frm.pack()
        r = 0
        if message:
            ttk.Label(frm, text=message, wraplength=360, justify="left").grid(
                row=r, column=0, columnspan=2, pady=(0, 10), sticky="w")
            r += 1
        self.vars = []
        self.entries = []
        for lab in labels:
            ttk.Label(frm, text=lab).grid(row=r, column=0, sticky="e", padx=(0, 8), pady=3)
            var = tk.StringVar()
            e = ttk.Entry(frm, textvariable=var, show="•", width=32)
            e.grid(row=r, column=1, pady=3)
            self.vars.append(var)
            self.entries.append(e)
            r += 1
        btns = ttk.Frame(frm)
        btns.grid(row=r, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right")
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="right", padx=6)
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        self.entries[0].focus_set()
        self.grab_set()
        self.wait_window()

    def _ok(self):
        self.result = [v.get() for v in self.vars]
        self.destroy()


class GeneratorDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Password generator")
        self.transient(parent)
        self.resizable(False, False)
        self.result = None
        frm = ttk.Frame(self, padding=14)
        frm.pack()
        self.length = tk.IntVar(value=20)
        self.symbols = tk.BooleanVar(value=True)
        self.out = tk.StringVar()
        ttk.Label(frm, text="Length:").grid(row=0, column=0, sticky="w")
        self.len_lbl = ttk.Label(frm, text="20", width=3)
        self.len_lbl.grid(row=0, column=2)
        ttk.Scale(frm, from_=8, to=64, orient="horizontal", length=240,
                  command=self._on_len).grid(row=0, column=1, padx=6)
        ttk.Checkbutton(frm, text="Include symbols (!@#$...)", variable=self.symbols,
                        command=self.regen).grid(row=1, column=0, columnspan=3, sticky="w", pady=6)
        ttk.Entry(frm, textvariable=self.out, width=44, font=("Consolas", 11)).grid(
            row=2, column=0, columnspan=3, pady=4)
        b = ttk.Frame(frm)
        b.grid(row=3, column=0, columnspan=3, pady=(8, 0), sticky="e")
        ttk.Button(b, text="Use this password", command=self._use).pack(side="right")
        ttk.Button(b, text="New one", command=self.regen).pack(side="right", padx=6)
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="right")
        self.regen()
        self.grab_set()
        self.wait_window()

    def _on_len(self, val):
        self.length.set(int(float(val)))
        self.len_lbl.config(text=str(self.length.get()))
        self.regen()

    def regen(self):
        self.out.set(V.generate_password(self.length.get(), self.symbols.get()))

    def _use(self):
        self.result = self.out.get()
        self.destroy()


class OttoLogWindow(tk.Toplevel):
    """Read-only view of the audit log kept inside the encrypted vault."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("AI access log")
        self.geometry("560x380")
        self.transient(app)
        ttk.Label(self, text="Every time an AI assistant asked for a password (newest first). "
                             "Passwords are never recorded.", padding=8).pack(anchor="w")
        self.tree = ttk.Treeview(self, columns=("time", "service", "result"),
                                 show="headings")
        for c, w in (("time", 140), ("service", 260), ("result", 130)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, padx=8)
        bar = ttk.Frame(self, padding=8)
        bar.pack(fill="x")
        ttk.Button(bar, text="Close", command=self._close).pack(side="right")
        ttk.Button(bar, text="Refresh", command=self.reload).pack(side="right", padx=6)
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.reload()

    def _close(self):
        self.app._log_win = None
        self.destroy()

    def reload(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        if self.app.vault is None or self.app.vault.locked:
            return
        for r in self.app.vault.otto_log():
            self.tree.insert("", "end", values=(
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["t"])),
                r["title"], r["result"]))


class App(tk.Tk):
    def __init__(self, vault_path=None):
        super().__init__()
        self.title("%s %s" % (APP_NAME, V.__version__))
        self.geometry("900x560")
        self.minsize(760, 480)
        self.vault_path = vault_path or V.default_vault_path()
        self.vault = None
        self.settings_path = S.settings_path_for(self.vault_path)
        self.settings = S.load_settings(self.settings_path)
        self.idle = S.IdleTracker(self.settings["idle_minutes"])
        self.lockout = L.Lockout(L.lockout_path_for(self.vault_path))
        self._lock_after = None
        self._last_tick = time.time()
        self._last_inbox_check = 0.0
        self._last_request_check = 0.0
        self._log_win = None
        self._countdown_win = None
        self._clip_token = None
        self._selected_id = None
        self._loading_form = False
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        for ev in ("<Key>", "<Motion>", "<Button>", "<MouseWheel>"):
            self.bind_all(ev, self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self.on_quit)
        self.after(1000, self._tick)
        self.show_unlock()

    # ---------------------------------------------------------- housekeeping
    def _touch(self, _e=None):
        self.idle.touch()

    def _tick(self):
        now = time.time()
        gap = now - self._last_tick
        self._last_tick = now
        if self.vault and not self.vault.locked:
            if gap > SLEEP_GAP_SECS:
                self.lock("Locked because the computer was asleep or paused.")
            elif self.idle.expired():
                self.lock("Locked automatically after %s minutes of no activity."
                          % self.idle.minutes)
            else:
                if now - self._last_request_check >= REQUEST_CHECK_SECS:
                    self._last_request_check = now
                    self._process_otto_requests()
                if now - self._last_inbox_check > INBOX_CHECK_SECS:
                    self._last_inbox_check = now
                    self._import_inbox(quiet=True)
        self.after(1000, self._tick)

    def _import_inbox(self, quiet=False):
        """Pull in entries Otto dropped in the inbox folder (no password needed:
        the private key is inside the unlocked vault)."""
        try:
            added, bad = self.vault.import_inbox()
        except Exception:
            return
        if added or bad:
            if hasattr(self, "tree"):
                self.refresh_list(select_id=self._selected_id)
            msg = ""
            if added:
                msg = "Imported %d %s from Otto." % (added, "entry" if added == 1 else "entries")
            if bad:
                msg += " %d inbox file(s) could not be read (renamed .bad)." % bad
            if hasattr(self, "status"):
                self.status.set(msg.strip())
            if added and not quiet:
                messagebox.showinfo(APP_NAME, msg.strip())

    def _process_otto_requests(self):
        """Answer AI assistants' password requests (only approved entries are released;
        everything is logged inside the vault). Runs only while unlocked."""
        if self.vault is None or self.vault.locked:
            return
        try:
            results = self.vault.process_requests()
        except Exception:
            return
        if not results:
            return
        if any(res == "expired" for _t, res in results) and hasattr(self, "tree"):
            self.refresh_list(select_id=self._selected_id)
            if self._selected_id:             # keep the open form in step (box becomes unticked)
                try:
                    e = self.vault.get_entry(self._selected_id)
                    self.otto_var.set(e["otto_approved"])
                    self.expiry_text.set(self._expiry_text(e))
                except KeyError:
                    pass
        msgs = []
        for title, res in results:
            if res == V.R_RELEASED:
                msgs.append("An AI assistant used the password for '%s'." % title)
            elif res == V.R_DENIED:
                msgs.append("An AI assistant asked for '%s' - not approved." % title)
            elif res == V.R_NOT_FOUND:
                msgs.append("An AI assistant asked for '%s' - not found." % title)
            elif res == V.R_AMBIGUOUS:
                msgs.append("An AI assistant asked for '%s' - several entries match, refused." % title)
            elif res == "expired":
                msgs.append("AI access for '%s' expired - tick the box again to renew it." % title)
            elif res == V.R_RATE:
                msgs.append("An AI assistant asked for '%s' - too many requests, refused." % title)
            else:
                msgs.append("Too many requests from an AI assistant - some were ignored.")
        if hasattr(self, "status"):
            self.status.set(" ".join(msgs[-3:]))
        if self._log_win is not None:
            try:
                self._log_win.reload()
            except Exception:
                pass

    def _after_unlock(self):
        """Run right after a successful create/unlock."""
        self.idle.touch()
        self._last_tick = time.time()
        try:
            self.vault.write_public_key_file()   # also migrates old vaults
        except Exception as exc:
            messagebox.showwarning(APP_NAME, "Could not set up the Otto inbox key:\n%s" % exc)
        self.show_main()
        self._import_inbox()
        self._process_otto_requests()
        if self.vault.kdf_upgraded:
            self.status.set("Your vault's key protection was upgraded to Argon2id. "
                            "(A copy of the old file was kept as vault.dat.pre-upgrade.bak.)")
        warns = self.vault.integrity_warnings
        if warns:
            self.status.set("WARNING: AI access log integrity problem - see File > AI access log.")
            messagebox.showwarning(
                APP_NAME, "WARNING: the AI access log may have been tampered with.\n\n- "
                          + "\n- ".join(warns) + "\n\nThe problem was recorded in the log as "
                          "'log integrity warning'. If you did not restore an older backup "
                          "or edit the vault yourself, treat this seriously: change your master "
                          "password and review which entries have AI access.")

    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    def on_quit(self):
        self._clear_clipboard_now()
        if self.vault:
            self.vault.lock()
        self.destroy()

    # ---------------------------------------------------------------- unlock
    def show_unlock(self, note=None):
        self._clear()
        self.config(menu=tk.Menu(self))
        exists = V.Vault.exists(self.vault_path)
        outer = ttk.Frame(self.container, padding=30)
        outer.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(outer, text="OttoVault", font=("Segoe UI", 22, "bold")).pack()
        ttk.Label(outer, text="Free, local, encrypted password manager  (v%s)" % V.__version__).pack(pady=(0, 14))
        if note:
            ttk.Label(outer, text=note, foreground="#a15c00", wraplength=380).pack(pady=(0, 8))
        self.pw1 = tk.StringVar()
        self.pw2 = tk.StringVar()
        if exists:
            ttk.Label(outer, text="Master password:").pack(anchor="w")
            e1 = ttk.Entry(outer, textvariable=self.pw1, show="•", width=36)
            e1.pack(pady=4)
            self.lock_msg = tk.StringVar()
            ttk.Label(outer, textvariable=self.lock_msg, foreground="#b00020",
                      wraplength=380, justify="left").pack()
            self.unlock_btn = ttk.Button(outer, text="Unlock", command=self.do_unlock)
            self.unlock_btn.pack(pady=8)
            ttk.Button(outer, text="Restore from a backup file...",
                       command=self.do_restore).pack()
            e1.bind("<Return>", lambda e: self.do_unlock())
            e1.focus_set()
        else:
            ttk.Label(outer, text="Welcome! Create your master password.",
                      font=("Segoe UI", 11, "bold")).pack(pady=(0, 6))
            ttk.Label(outer, text=NO_RECOVERY_WARNING, foreground="#b00020",
                      wraplength=380, justify="left").pack(pady=(0, 10))
            ttk.Label(outer, text="Master password (at least 8 characters):").pack(anchor="w")
            e1 = ttk.Entry(outer, textvariable=self.pw1, show="•", width=36)
            e1.pack(pady=4)
            ttk.Label(outer, text="Type it again:").pack(anchor="w")
            e2 = ttk.Entry(outer, textvariable=self.pw2, show="•", width=36)
            e2.pack(pady=4)
            ttk.Button(outer, text="Create my vault", command=self.do_create).pack(pady=8)
            ttk.Button(outer, text="Restore from a backup file...",
                       command=self.do_restore).pack()
            e2.bind("<Return>", lambda e: self.do_create())
            e1.focus_set()
        ttk.Label(outer, text="Vault file: " + self.vault_path, foreground="#666",
                  wraplength=420).pack(pady=(16, 0))
        if exists:
            self._refresh_lockout()

    def _refresh_lockout(self):
        """Disable Unlock and show a countdown while the failed-attempt delay runs."""
        if self._lock_after is not None:
            try:
                self.after_cancel(self._lock_after)
            except Exception:
                pass
            self._lock_after = None
        if not hasattr(self, "unlock_btn"):
            return
        try:
            left = self.lockout.remaining()
            if left > 0:
                self.unlock_btn.state(["disabled"])
                self.lock_msg.set("Too many wrong passwords. You can try again in %d:%02d."
                                  % (left // 60, left % 60))
                self._lock_after = self.after(1000, self._refresh_lockout)
            else:
                self.unlock_btn.state(["!disabled"])
                if self.lock_msg.get().startswith("Too many"):
                    self.lock_msg.set("")
        except tk.TclError:
            pass

    def do_create(self):
        a, b = self.pw1.get(), self.pw2.get()
        if a != b:
            messagebox.showerror(APP_NAME, "The two passwords do not match.")
            return
        try:
            V.check_master_password(a)
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        if not messagebox.askyesno(
                APP_NAME, NO_RECOVERY_WARNING + "\n\nCreate the vault with this password?"):
            return
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            self.vault = V.Vault.create(self.vault_path, a,
                                        expiry_days=self.settings["ai_expiry_days"])
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Could not create the vault:\n%s" % exc)
            return
        finally:
            self.config(cursor="")
            self.pw1.set("")
            self.pw2.set("")
        self._after_unlock()

    def _wrong_password(self, what="Wrong master password."):
        """Count a failed attempt and tell the user how it stands."""
        delay = self.lockout.record_failure()
        self.pw1.set("")
        if delay:
            self._refresh_lockout()
            messagebox.showerror(APP_NAME, "%s\n\nToo many wrong passwords in a row: unlocking "
                                 "is paused for %d seconds (it gets longer if you keep failing)."
                                 % (what, delay))
        else:
            left = self.lockout.tries_left()
            messagebox.showerror(APP_NAME, "%s Please try again.\n(%d more wrong %s before a "
                                 "waiting time starts.)" % (what, left, "try" if left == 1 else "tries"))

    def do_unlock(self):
        if self.lockout.remaining() > 0:
            self._refresh_lockout()
            return
        pw = self.pw1.get()
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            self.vault = V.Vault.open(self.vault_path, pw,
                                      expiry_days=self.settings["ai_expiry_days"])
        except V.WrongPasswordError:
            self.config(cursor="")
            self._wrong_password()
            return
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        finally:
            self.config(cursor="")
        self.lockout.record_success()
        self.pw1.set("")
        self._after_unlock()

    def do_restore(self):
        if self.lockout.remaining() > 0:      # restore must not become a password oracle
            self._refresh_lockout()
            return
        src = filedialog.askopenfilename(title="Choose a backup file")
        if not src:
            return
        d = PasswordPrompt(self, "Restore backup", ["Backup's master password:"],
                           "Enter the master password that the backup was made with.")
        if not d.result:
            return
        if V.Vault.exists(self.vault_path) and not messagebox.askyesno(
                APP_NAME, "This will replace the current vault with the backup "
                          "(the current one is kept as vault.dat.bak). Continue?"):
            return
        try:
            V.Vault.restore_backup(src, self.vault_path, d.result[0])
        except V.WrongPasswordError:
            self._wrong_password("Wrong backup password.")
            return
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        messagebox.showinfo(APP_NAME, "Backup restored. Now unlock it with its master password.")
        self.show_unlock()

    # ------------------------------------------------------------------ main
    def show_main(self):
        self._clear()
        self._selected_id = None
        self._touch()
        m = tk.Menu(self)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Import from CSV...", command=self.do_import)
        fm.add_command(label="Import from XML...", command=self.do_import_xml)
        fm.add_command(label="Export to XML (not encrypted)...", command=self.do_export_xml)
        fm.add_command(label="Export encrypted backup...", command=self.do_export)
        fm.add_command(label="AI access log...", command=self.show_otto_log)
        fm.add_separator()
        fm.add_command(label="Change master password...", command=self.do_change_pw)
        fm.add_command(label="Lock now", command=lambda: self.lock())
        fm.add_separator()
        fm.add_command(label="Quit", command=self.on_quit)
        m.add_cascade(label="File", menu=fm)
        sm = tk.Menu(m, tearoff=0)
        sm.add_command(label="Stay unlocked for (idle time):", state="disabled")
        self.idle_choice = tk.StringVar(value=str(self.settings["idle_minutes"]))
        for val, label in IDLE_CHOICES:
            sm.add_radiobutton(label=label, value=str(val), variable=self.idle_choice,
                               command=self.on_idle_choice)
        sm.add_separator()
        sm.add_command(label="AI access approval lasts (for new approvals):", state="disabled")
        self.expiry_choice = tk.StringVar(value=str(self.settings["ai_expiry_days"]))
        for val, label in EXPIRY_CHOICES:
            sm.add_radiobutton(label=label, value=str(val), variable=self.expiry_choice,
                               command=self.on_expiry_choice)
        sm.add_separator()
        sm.add_command(label="Revoke all AI access approvals...", command=self.do_revoke_all)
        m.add_cascade(label="Settings", menu=sm)
        self.config(menu=m)

        paned = ttk.Frame(self.container, padding=8)
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(paned, padding=(12, 0, 0, 0))
        right.pack(side="right", fill="y")

        top = ttk.Frame(left)
        top.pack(fill="x")
        ttk.Label(top, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self.refresh_list())
        se = ttk.Entry(top, textvariable=self.search_var)
        se.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Clear", command=lambda: self.search_var.set("")).pack(side="left")
        ttk.Button(top, text="+ New entry", command=self.new_entry).pack(side="left", padx=(8, 0))

        cols = ("title", "username", "url", "ai")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for c, w in (("title", 200), ("username", 150), ("url", 200), ("ai", 50)):
            self.tree.heading(c, text="AI" if c == "ai" else c.capitalize())
            self.tree.column(c, width=w, anchor="center" if c == "ai" else "w",
                             stretch=c != "ai")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", pady=(8, 0))
        self.tree.pack(fill="both", expand=True, pady=(8, 0))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.status = tk.StringVar(value="")
        ttk.Label(left, textvariable=self.status, foreground="#2e7d32").pack(fill="x", side="bottom")

        # --- detail form
        self.f = {k: tk.StringVar() for k in ("title", "username", "password", "url")}
        r = 0
        for key, label in (("title", "Title"), ("username", "Username"),
                           ("password", "Password"), ("url", "URL")):
            ttk.Label(right, text=label).grid(row=r, column=0, sticky="w", pady=(6, 0))
            r += 1
            if key == "password":
                self.pw_entry = ttk.Entry(right, textvariable=self.f[key], show="•", width=34)
                self.pw_entry.grid(row=r, column=0, columnspan=3, sticky="we")
                r += 1
                bar = ttk.Frame(right)
                bar.grid(row=r, column=0, columnspan=3, sticky="w", pady=3)
                self.show_var = tk.BooleanVar(value=False)
                ttk.Checkbutton(bar, text="Show", variable=self.show_var,
                                command=self.toggle_show).pack(side="left")
                ttk.Button(bar, text="Generate...", command=self.do_generate).pack(side="left", padx=4)
                ttk.Button(bar, text="Copy password", command=self.copy_password).pack(side="left")
                r += 1
            else:
                ttk.Entry(right, textvariable=self.f[key], width=34).grid(
                    row=r, column=0, columnspan=3, sticky="we")
                r += 1
        ttk.Label(right, text="Notes").grid(row=r, column=0, sticky="w", pady=(6, 0))
        r += 1
        self.notes = tk.Text(right, width=34, height=7, wrap="word")
        self.notes.grid(row=r, column=0, columnspan=3, sticky="we")
        r += 1
        self.otto_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Allow AI access to this password",
                        variable=self.otto_var).grid(
            row=r, column=0, columnspan=3, sticky="w", pady=(8, 0))
        r += 1
        self.expiry_text = tk.StringVar(value="")
        ttk.Label(right, textvariable=self.expiry_text, foreground="#666").grid(
            row=r, column=0, columnspan=3, sticky="w")
        r += 1
        bb = ttk.Frame(right)
        bb.grid(row=r, column=0, columnspan=3, pady=10, sticky="w")
        ttk.Button(bb, text="Save", command=self.save_entry).pack(side="left")
        ttk.Button(bb, text="Copy username", command=self.copy_username).pack(side="left", padx=4)
        ttk.Button(bb, text="Delete", command=self.delete_entry).pack(side="left")
        at = ttk.Menubutton(right, text="Auto-type login  \u25be")
        atm = tk.Menu(at, tearoff=0)
        atm.add_command(label="Username + Tab + password + Enter",
                        command=lambda: self.do_autotype("both"))
        atm.add_command(label="Password only (then Enter)",
                        command=lambda: self.do_autotype("password"))
        atm.add_command(label="Username only (then Enter)",
                        command=lambda: self.do_autotype("username"))
        at["menu"] = atm
        at.grid(row=r + 1, column=0, columnspan=3, sticky="w")
        ttk.Label(right, text="Click Auto-type, then click the login box of\nthe site/app within 3 seconds.",
                  foreground="#666").grid(row=r + 2, column=0, columnspan=3, sticky="w", pady=(4, 0))
        self.refresh_list()
        self.clear_form()
        se.focus_set()

    def refresh_list(self, select_id=None):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for e in self.vault.search(self.search_var.get()):
            self.tree.insert("", "end", iid=e["id"], values=(
                e["title"], e["username"], e["url"], "\u2713" if e["otto_approved"] else ""))
        if select_id and self.tree.exists(select_id):
            self.tree.selection_set(select_id)
        n = self.vault.approved_count()
        self.status.set("%d entries" % len(self.tree.get_children())
                        + ("  -  %d with AI access" % n if n else ""))

    def clear_form(self):
        self._selected_id = None
        for v in self.f.values():
            v.set("")
        self.notes.delete("1.0", "end")
        self.otto_var.set(False)
        self.expiry_text.set("")
        self.show_var.set(False)
        self.toggle_show()

    def toggle_show(self):
        self.pw_entry.config(show="" if self.show_var.get() else "•")

    def on_select(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        e = self.vault.get_entry(sel[0])
        self._selected_id = e["id"]
        for k in self.f:
            self.f[k].set(e[k])
        self.notes.delete("1.0", "end")
        self.notes.insert("1.0", e["notes"])
        self.otto_var.set(e["otto_approved"])
        self.expiry_text.set(self._expiry_text(e))
        self.show_var.set(False)
        self.toggle_show()

    def new_entry(self):
        self.tree.selection_set(())
        self.clear_form()

    def _form(self):
        d = {k: v.get() for k, v in self.f.items()}
        d["notes"] = self.notes.get("1.0", "end-1c")
        d["otto_approved"] = bool(self.otto_var.get())
        return d

    def save_entry(self):
        d = self._form()
        try:
            if self._selected_id:
                self.vault.update_entry(self._selected_id, **d)
                eid = self._selected_id
            else:
                eid = self.vault.add_entry(**d)
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Could not save: %s" % exc)
            return
        self._selected_id = eid
        self.refresh_list(select_id=eid)
        self.expiry_text.set(self._expiry_text(self.vault.get_entry(eid)))
        self.status.set("Saved. AI assistants may use this password without asking."
                        if d["otto_approved"] else "Saved.")

    def delete_entry(self):
        if not self._selected_id:
            return
        title = self.f["title"].get()
        if not messagebox.askyesno(APP_NAME, "Delete '%s'? This cannot be undone." % title):
            return
        try:
            self.vault.delete_entry(self._selected_id)
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.clear_form()
        self.refresh_list()
        self.status.set("Deleted.")

    def do_generate(self):
        d = GeneratorDialog(self)
        if d.result:
            self.f["password"].set(d.result)
            self.show_var.set(True)
            self.toggle_show()
            self.status.set("Generated password placed in the form - click Save.")

    # ------------------------------------------------------------- settings
    def on_idle_choice(self):
        raw = self.idle_choice.get()
        val = S.NEVER if raw == S.NEVER else int(raw)
        if val == S.NEVER and not messagebox.askyesno(
                APP_NAME, "OttoVault will stay unlocked until you lock it or close it.\n"
                          "Anyone using this PC while it is unlocked could see your passwords.\n\n"
                          "Use this setting?"):
            self.idle_choice.set(str(self.settings["idle_minutes"]))
            return
        self.settings["idle_minutes"] = val
        self.idle.set_minutes(val)
        try:
            S.save_settings(self.settings_path, self.settings)
            self.status.set("Saved: stay unlocked = %s" % dict((str(k), l) for k, l in IDLE_CHOICES)[str(val)])
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Could not save the setting: %s" % exc)

    # -------------------------------------------------------------- AI access
    def do_revoke_all(self):
        n = self.vault.approved_count()
        if not n:
            messagebox.showinfo(APP_NAME, "No entries have AI access.")
            return
        if not messagebox.askyesno(
                APP_NAME, "Remove AI access from all %d approved entr%s?\n\n"
                          "AI assistants will be refused until you tick the box again."
                          % (n, "y" if n == 1 else "ies")):
            return
        try:
            self.vault.revoke_all_otto()
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Could not save: %s" % exc)
            return
        self.refresh_list(select_id=self._selected_id)
        if self._selected_id:
            self.otto_var.set(False)
            self.expiry_text.set("")
        self.status.set("All AI access approvals were revoked.")

    def show_otto_log(self):
        if self._log_win is not None:
            try:
                self._log_win.lift()
                self._log_win.reload()
                return
            except tk.TclError:
                self._log_win = None
        self._log_win = OttoLogWindow(self)

    def on_expiry_choice(self):
        val = S.normalize_expiry(int(self.expiry_choice.get()))
        self.settings["ai_expiry_days"] = val
        if self.vault is not None:
            self.vault.expiry_days = val
        try:
            S.save_settings(self.settings_path, self.settings)
        except OSError as exc:
            messagebox.showerror(APP_NAME, "Could not save the setting: %s" % exc)
            return
        self.status.set("New AI access approvals will last: %s (existing ones keep their date)."
                        % dict((str(k), l) for k, l in EXPIRY_CHOICES)[str(val)].replace(" (default)", ""))

    def _expiry_text(self, e=None):
        if e is None or not e.get("otto_approved"):
            return ""
        exp = e.get("otto_expires")
        return ("AI access ends " + time.strftime("%Y-%m-%d", time.localtime(exp))
                if exp else "AI access has no end date")

    # --------------------------------------------------------------- auto-type
    def do_autotype(self, mode="both"):
        if not self._selected_id:
            self.status.set("Click an entry first, then Auto-type.")
            return
        if not AT.is_supported():
            messagebox.showinfo(APP_NAME, "Auto-type only works on Windows.")
            return
        try:
            e = self.vault.get_entry(self._selected_id)
        except KeyError:
            return
        tokens = AT.build_sequence(e["username"], e["password"], mode)
        if not tokens:
            self.status.set("This entry has nothing to type for that option.")
            return
        self.iconify()
        w = tk.Toplevel(self)
        self._countdown_win = w
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        lbl = tk.Label(w, text="", bg="#fff3b0", fg="#000", font=("Segoe UI", 11, "bold"),
                       padx=14, pady=8, relief="solid", bd=1)
        lbl.pack()
        w.geometry("+%d+%d" % (self.winfo_screenwidth() - 430, 40))
        self._countdown(AUTOTYPE_COUNTDOWN, lbl, tokens)

    def _countdown(self, n, lbl, tokens):
        if n > 0:
            lbl.config(text="OttoVault will type in %d...  click the login box now" % n)
            self.after(1000, lambda: self._countdown(n - 1, lbl, tokens))
            return
        if self._countdown_win:
            self._countdown_win.destroy()
            self._countdown_win = None
        self.after(200, lambda: self._finish_autotype(tokens))

    def _finish_autotype(self, tokens):
        msg = ""
        try:
            if self.vault is None or self.vault.locked:
                msg = "Not typed: OttoVault locked."
            elif AT.foreground_is_own_process():
                msg = "Not typed: no other window was selected."
            else:
                AT.type_tokens(tokens)
                msg = "Typed."
        except AT.AutoTypeError as exc:
            msg = "Not typed: %s" % exc
        finally:
            tokens.clear()
            self.deiconify()
            self.lift()
        if hasattr(self, "status") and self.vault is not None:
            self.status.set(msg)

    # ------------------------------------------------------------- clipboard
    def _copy(self, text, what):
        if not text:
            self.status.set("Nothing to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update()
        token = object()
        self._clip_token = (token, text)
        self.after(CLIPBOARD_CLEAR_SECS * 1000, lambda: self._clear_clipboard(token))
        self.status.set("%s copied. Clipboard clears in %d seconds." % (what, CLIPBOARD_CLEAR_SECS))

    def copy_password(self):
        self._copy(self.f["password"].get(), "Password")

    def copy_username(self):
        self._copy(self.f["username"].get(), "Username")

    def _clear_clipboard(self, token):
        if self._clip_token and self._clip_token[0] is token:
            self._clear_clipboard_now()

    def _clear_clipboard_now(self):
        if not self._clip_token:
            return
        text = self._clip_token[1]
        self._clip_token = None
        try:
            if self.clipboard_get() == text:   # only wipe if it's still ours
                self.clipboard_clear()
                self.clipboard_append("")
                self.update()
        except tk.TclError:
            pass
        try:
            self.status.set("Clipboard cleared.")
        except Exception:
            pass

    # ------------------------------------------------------- menu operations
    def do_import(self):
        p = filedialog.askopenfilename(title="Choose a CSV file",
                                       filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not p:
            return
        try:
            added, skipped = self.vault.import_csv(p)
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.refresh_list()
        messagebox.showinfo(
            APP_NAME,
            "Imported %d entries (%d duplicates skipped).\n\n"
            "The CSV file you imported contains your passwords in PLAIN TEXT. "
            "Delete it now (and empty the Recycle Bin)." % (added, skipped))

    def do_import_xml(self):
        p = filedialog.askopenfilename(
            title="Choose an XML file (OttoVault or KeePass 2.x export)",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if not p:
            return
        try:
            added, skipped = self.vault.import_xml(p)
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.refresh_list()
        r = self.vault.last_xml_report
        extra = ""
        if r["invalid"]:
            extra += "\n%d entries were skipped because a field was too long or had forbidden characters." % r["invalid"]
        if r["unsupported"]:
            extra += "\n%d KeePass entries were skipped (password stored in KeePass's protected form)." % r["unsupported"]
        messagebox.showinfo(
            APP_NAME,
            "Imported %d entries from %s (%d skipped, %d of them duplicates).%s\n\n"
            "Imported entries have NO AI access - tick it yourself where wanted.\n\n"
            "The XML file you imported contains your passwords in PLAIN TEXT. "
            "Delete it now (and empty the Recycle Bin)."
            % (added, r["format"], skipped, r["duplicates"], extra))

    def do_export_xml(self):
        if self.lockout.remaining() > 0:
            self.status.set("Export is paused after too many wrong passwords - wait for the timer.")
            return
        if not messagebox.askyesno(
                APP_NAME, "WARNING: an XML export is NOT encrypted.\n\n"
                          "It will contain EVERY password in plain text, readable by anyone "
                          "(or any program) who can open the file, and it may be copied by "
                          "backup or cloud-sync software.\n\n"
                          "Only continue if you need it for moving to another program, and "
                          "delete the file afterwards.\n\nContinue?",
                icon="warning", default="no"):
            return
        d = PasswordPrompt(self, "Confirm export", ["Master password:"],
                           "Re-enter your master password to export your passwords as plain text.")
        if not d.result:
            return
        if not self.vault.verify_master_password(d.result[0]):
            self._wrong_password()
            return
        self.lockout.record_success()
        p = filedialog.asksaveasfilename(
            title="Save UNENCRYPTED XML export as", defaultextension=".xml",
            initialfile="OttoVault-export-%s.xml" % time.strftime("%Y-%m-%d"),
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if not p:
            return
        try:
            written, skipped = self.vault.export_xml(p)
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Could not write the export:\n%s" % exc)
            return
        messagebox.showwarning(
            APP_NAME, "Exported %d entries to:\n%s\n\nThis file is NOT encrypted and contains "
                      "your passwords in plain text. Delete it as soon as you have used it "
                      "(and empty the Recycle Bin).%s"
                      % (written, p, "\n\n%d entries could not be written (unsupported "
                                      "characters)." % skipped if skipped else ""))

    def do_export(self):
        p = filedialog.asksaveasfilename(
            title="Save encrypted backup as", defaultextension=".ottovault",
            initialfile="OttoVault-backup-%s.ottovault" % time.strftime("%Y-%m-%d"),
            filetypes=[("OttoVault backup", "*.ottovault"), ("All files", "*.*")])
        if not p:
            return
        try:
            self.vault.export_backup(p)
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Could not write backup:\n%s" % exc)
            return
        messagebox.showinfo(APP_NAME, "Encrypted backup saved to:\n%s\n\n"
                            "It opens with your current master password." % p)

    def do_change_pw(self):
        d = PasswordPrompt(
            self, "Change master password",
            ["Current password:", "New password:", "New password again:"],
            "New password must be at least 8 characters.\n" + NO_RECOVERY_WARNING)
        if not d.result:
            return
        old, new, new2 = d.result
        if new != new2:
            messagebox.showerror(APP_NAME, "The new passwords do not match.")
            return
        try:
            self.vault.change_master_password(old, new)
        except V.VaultError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        messagebox.showinfo(APP_NAME, "Master password changed.\n"
                            "Old backups still need the OLD password.")

    def lock(self, note=None):
        if self._log_win is not None:
            try:
                self._log_win.destroy()
            except tk.TclError:
                pass
            self._log_win = None
        if self._countdown_win:
            self._countdown_win.destroy()
            self._countdown_win = None
        self._clear_clipboard_now()
        if self.vault:
            self.vault.lock()
            self.vault = None
        self.show_unlock(note)


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
