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

## Status (version 1.2.0)
A working Windows version is included here: Python and tkinter, local only, no network code.

- Encrypted vault (Scrypt + AES-256-GCM, fresh nonce on every save, atomic saves with a `.bak`), master password, add/edit/delete/search, copy with auto-clearing clipboard, password generator, encrypted backup/restore, CSV import.
- **Stay unlocked** (1Password-style): enter the master password once; choose 5/15/30/60 minutes idle or "until I lock it" in the Settings menu (default 15). Locks on sleep. Only that preference is saved (`settings.json`); the master password is never stored and the key lives only in memory. Changing the master password still asks for the current one.
- **Auto-type login**: types username, Tab, password, Enter into the window you click (Windows `SendInput`, Unicode-safe, clipboard not used). Variants: password only, username only.
- **Otto inbox**: the vault holds an X25519 key pair; the public key is written to `inbox_public.key`. `otto_add.py` can encrypt a new entry to it and drop it in the `inbox` folder without ever knowing the master password; the app imports it on the next unlock.
- **Standing per-service approval for Otto (optional, off by default)**: tick "Let Otto use this password" on an entry and `otto_get.py` can fetch that one password from the *running, unlocked* app through an encrypted request/response mailbox, without asking again. Locked vault = no answer. The master password is never stored; approvals and an audit log live inside the encrypted vault; every release is logged; you can untick one entry or revoke all. See the security tradeoff in `OTTO_USAGE.md`.

Tests: 95 pytest unit tests (`py -m pytest tests`) plus a headless GUI smoke test (`tests/gui_smoke.py`, run under xvfb on Linux). Real auto-typing into a Windows application and the tkinter GUI on Windows have not been automatically tested, and the app has not been independently audited.

To run it on Windows, read `README.txt`; for the Otto helpers (inbox and approved retrieval) see `OTTO_USAGE.md` (install Python once, then double-click `Run OttoVault.bat`).

## License
MIT - see `LICENSE`.
