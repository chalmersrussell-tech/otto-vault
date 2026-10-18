> **Please read first.** OttoVault is a **homemade hobby project. It has not been independently security-audited and comes with no warranty** (see `LICENSE`). **Do not make it your only copy of your passwords.** Keep an established password manager or your existing vault until you have tested this thoroughly, keep encrypted backups, and remember that a forgotten master password **cannot be recovered**.

# Free Password Manager

An idea for a **free, open password manager that anyone can use or self-host**, with encrypted storage on the person's own device.

## Why
Good password managers are usually subscriptions, and many people skip them and reuse weak passwords. This project is about making a simple, free option for everyday people, with no account, no subscription and no cloud required.

## Principles
- **Your device, your data.** The vault is one encrypted file stored locally. Sync is optional and up to the user.
- **One master password** unlocks it. It cannot be recovered if forgotten, and the app says so clearly.
- **Well-known cryptography only.** A standard password-based key derivation (Scrypt or Argon2) plus AES-256-GCM, using vetted libraries. No homemade ciphers.
- **Open and self-hostable.** Readable source, no telemetry, no network calls by default.
- **Simple first.** Add, edit, delete and search entries, copy a password with auto-clearing clipboard, a password generator, auto-lock, encrypted backup, and import from CSV.

## Honest notes
- A new, unaudited app should not be anyone's only copy of their passwords. Keep an existing manager until you trust it, and keep backups.
- Established free options already exist (for example KeePass-family apps and Bitwarden's free tier). This project is a learning build and a simple option, not a claim to be safer than them.

## Status (version 1.3.0)
A working Windows version is included here: Python and tkinter, local only, no network code.

- Encrypted vault (Argon2id or Scrypt key derivation + AES-256-GCM, fresh nonce on every save, atomic saves with a `.bak`), master password, add/edit/delete/search, copy with auto-clearing clipboard, password generator, encrypted backup/restore, CSV import.
- **Stay unlocked** (1Password-style): enter the master password once; choose 5/15/30/60 minutes idle or "until I lock it" in the Settings menu (default 15). Locks on sleep. Only that preference is saved (`settings.json`); the master password is never stored and the key lives only in memory. Changing the master password still asks for the current one.
- **Auto-type login**: types username, Tab, password, Enter into the window you click (Windows `SendInput`, Unicode-safe, clipboard not used). Variants: password only, username only.
- **Otto inbox**: the vault holds an X25519 key pair; the public key is written to `inbox_public.key`. `otto_add.py` can encrypt a new entry to it and drop it in the `inbox` folder without ever knowing the master password; the app imports it on the next unlock.
- **Per-service AI access (optional, off by default)**: tick "Allow AI access to this password" on an entry and an AI assistant using `otto_get.py` can fetch that one password from the *running, unlocked* app through an encrypted request/response mailbox, without asking again. Locked vault = no answer. The master password is never stored; approvals and an audit log live inside the encrypted vault; every release is logged; you can untick one entry or revoke all. See the security tradeoff in `OTTO_USAGE.md`.

Tests: 151 pytest unit tests (`py -m pytest tests`) plus a headless GUI smoke test (`tests/gui_smoke.py`, run under xvfb on Linux). Real auto-typing into a Windows application and the tkinter GUI on Windows have not been automatically tested, and the app has not been independently audited.

To run it on Windows, read `README.txt`; for the helper scripts (inbox and approved retrieval) see `OTTO_USAGE.md` (install Python once, then double-click `Run OttoVault.bat`).

## Security notes (please read)

**Threat model.** OttoVault protects the vault *file* against someone who gets a copy of it (stolen laptop, cloud-synced folder, backup drive): without the master password it is AES-256-GCM ciphertext, and the key is stretched with a memory-hard KDF. It does **not** protect you from malware or another person already running as your Windows user while the vault is unlocked: such a program can read the unlocked app's memory, log keystrokes, read the clipboard while a password is copied, or (if you enabled AI access) file requests for approved entries. No password manager can fully defend against that. Lock the vault when you are away (File > Lock now, or a short "stay unlocked" time), keep Windows and your antivirus up to date, and do not make this your only copy of your passwords.

**Key derivation.** New vaults use **Argon2id** (64 MiB memory, 3 passes, 4 lanes, random 16-byte salt; RFC 9106 second recommended profile) through the `cryptography` package (44 or newer). Scrypt (n=32768, r=8, p=1, which was already strong) is still supported: an older vault opens normally and is **transparently re-wrapped with Argon2id once**, right after you unlock it successfully (the only moment the password is available). The previous file is kept next to it as `vault.dat.pre-upgrade.bak` (an older OttoVault cannot open the upgraded file, so keep that copy until you are happy). If your Python has an older `cryptography`, new vaults fall back to Scrypt and an Argon2id vault explains what to upgrade. KDF parameters live in the authenticated file header, so they can be raised later without breaking old vaults; hostile or too-weak headers are refused. The master password is never stored, never logged and never written to any file (tests scan the vault folder, backups, settings, lockout and audit files for it).

**Unlock lockout.** After 5 wrong master passwords in a row the unlock screen refuses further tries for 30 s, then 60 s, 120 s ... up to 15 minutes; a correct password resets it. The counter and the "locked until" time are kept in `lockout.json` next to the vault together with a salted hash of both (so accidental damage or hand-editing is noticed; a damaged file starts the first delay). The failed *backup restore* password prompt counts too, so it cannot be used to guess around the lockout. Be clear about what this is: a speed bump against someone typing guesses into the app. It does **not** slow an offline attack on a copied `vault.dat` (the Argon2id/Scrypt cost does that) and a program running as you could delete the file.

**Input limits.** Entries are limited to: title 200, username 256, password 1024, URL 2048, notes 20000 characters. NUL and other control characters are refused everywhere (notes may contain newlines and tabs); titles and usernames also refuse invisible/bidirectional-override characters, are NFC-normalised and have whitespace runs collapsed, which makes the exact-title matching used by AI access predictable (matching ignores case, spacing and look-alike compatibility forms). Passwords stay free-form (symbols, spaces, emoji are fine). The same rules apply on save in the app, on inbox import (bad files become `*.bad`), CSV import (bad rows are skipped) and in `otto_add.py`. This is length/character-set hardening: nothing in OttoVault builds SQL or shell commands from entry text, so it is not "injection prevention".

**AI access (optional, off by default).** Tick "Allow AI access to this password" on an entry and an AI assistant using `otto_get.py` can fetch *that* password from the running, unlocked app without asking each time. Details and the honest tradeoff are in `OTTO_USAGE.md`. Safeguards:
- approvals live inside the encrypted vault; the master password is never stored; a locked or closed app answers nothing;
- **approvals expire**: each new approval lasts 30 days by default (Settings: 7 days / 30 days / never); after that the box is switched off automatically and must be re-ticked. Approvals from version 1.2 get a period (your current setting, 30 days by default) starting the first time 1.3 opens the vault;
- untick one entry and Save to revoke it at once, or Settings > "Revoke all AI access approvals..." (both were already present in 1.2);
- every grant, revoke, expiry, release, denial and refusal is written to the in-vault **AI access log** (File > AI access log...; last 500 events; never a password);
- rate limits (30 releases per minute, flood guard) and request size/age limits.

**Access log integrity.** True immutability is impossible on a PC you control (you can always delete `vault.dat`). Instead the log is *tamper-evident*: each log entry carries an HMAC-SHA256 chained to the previous entry, keyed from the vault key; a tiny `audit_anchor.json` next to the vault (also MAC'd, no secrets) remembers the newest entry. On every unlock the chain and the anchor are checked; an edited, deleted, re-ordered or forged entry, or a vault restored from an older copy, produces a loud warning dialog and a permanent "log integrity warning" event. Limits: this detects silent edits by anything that does not know the master password (or that edits without recomputing the chain); someone who knows your master password *and* rewrites the whole vault with the code can still forge a consistent log; deleting both `vault.dat` and its anchor destroys the evidence; restoring an old backup legitimately triggers the warning once.

**Launcher / `.exe`.** `Run OttoVault.bat` starts the app with your Python. `build_exe.ps1` builds a real `OttoVault.exe` (PyInstaller, no console window, per-user install). Neither is a security boundary: both run the same open Python code, an unsigned exe may trigger SmartScreen/antivirus warnings or be **blocked outright** by Windows application-control policies (Smart App Control / WDAC / AppLocker - it was blocked on the author's own PC, so the `.bat` remains the supported way to start the app; do not weaken your Windows policy for this), and obfuscating a launcher would only be theater. The vault is protected by encryption and your master password, not by how the program is started. The build never includes your vault.

**Not (yet) covered.** No independent security audit. Python cannot wipe secrets from memory. Windows clipboard history may keep copied passwords. Keystroke loggers see what you type. Backups made with File > Export keep the approvals and log of that moment.

## License
MIT - see `LICENSE`.
