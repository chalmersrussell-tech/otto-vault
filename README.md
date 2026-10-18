> **Please read first.** OttoVault is a **homemade hobby project. It has not been independently security-audited and comes with no warranty** (see `LICENSE`). **Do not make it your only copy of your passwords.** Keep an established password manager or your existing vault until you have tested this thoroughly, keep encrypted backups, and remember that a forgotten master password **cannot be recovered**.

# OttoVault - the free password manager your AI assistant can use (with your permission)

**A free, local, encrypted password manager built so an AI assistant can actually help you with logins.** You decide, entry by entry, which services your AI assistant may use. For an approved service it can fetch the username and password and use them (log in, fill a form, paste them where needed) - without ever seeing your master password. Everything else stays locked.

## What makes it different: AI access, with your permission
- **You approve each service.** Tick "Allow AI access to this password" on an entry (for example your email login). Nothing is shared by default; imported or AI-added entries start unapproved.
- **The AI gets only what you approved.** An assistant using `otto_get.py` can request that service's username and password from the running, unlocked app. It never receives your master password or any entry you did not approve. Requests and answers go through an encrypted mailbox on your own computer.
- **Revoke any time.** Untick one entry, or use Settings > "Revoke all AI access approvals...". Approvals can also expire on their own (never / 7 / 30 days; new approvals default to 30).
- **Every grant, revoke and release is logged** in a tamper-evident access log inside the encrypted vault (File > "AI access log...").
- **Your master password is never stored.** Lock the vault and the AI gets nothing (no answer while locked).
- **The AI can add logins too.** `otto_add.py` lets an assistant drop a *new* entry into your vault (encrypted to the vault's public key) without any access to existing entries; you review it and decide whether to approve it.
- **It is a deliberate trade-off, stated plainly:** while the vault is unlocked, any program running as the same Windows user could also file requests for the entries you approved. Approve only what you want automated and lock the vault when away. See "Security notes" below and `OTTO_USAGE.md`.

## Also
- **Free, local, encrypted.** One encrypted file on your PC (Argon2id or Scrypt key derivation + AES-256-GCM, vetted libraries only). No account, no subscription, no cloud, no telemetry, no network calls.
- **A normal, simple password manager too:** add/edit/delete/search, copy with auto-clearing clipboard, password generator, auto-lock, auto-type login, encrypted backup/restore.
- **Saves automatically.** There is no separate "save the vault" step and no File > Save: pressing Save on an entry (or adding, deleting or importing entries, or an AI-added login arriving) writes the encrypted vault to disk right away (atomic write, with a `.bak` backup copy of the previous version).
- **Bring your passwords with you:** import from **KeePass 1 (`.kdb`)** databases directly, **KeePass 2.x XML**, OttoVault XML and **CSV**.

## Principles
- **Your device, your data.** The vault is one encrypted file stored locally. Sync is optional and up to you.
- **One master password** unlocks it. It cannot be recovered if forgotten, and the app says so clearly.
- **Well-known cryptography only.** No homemade ciphers.
- **Open and self-hostable.** Readable source, no telemetry, no network calls by default.
- **Simple first, AI-ready by design.**

## Honest notes
- A new, unaudited app should not be anyone's only copy of their passwords. Keep an existing manager until you trust it, and keep backups.
- Established free options already exist (for example KeePass-family apps and Bitwarden's free tier). OttoVault's reason to exist is the permissioned AI-assistant access above; it is a young project, not a claim to be safer than them.

## Status (version 1.3.2)
A working Windows version is included here: Python and tkinter, local only, no network code.

- Encrypted vault (Argon2id or Scrypt key derivation + AES-256-GCM, fresh nonce on every save, atomic saves with a `.bak`), master password, add/edit/delete/search, copy with auto-clearing clipboard, password generator, encrypted backup/restore, CSV import.
- **Stay unlocked** (1Password-style): enter the master password once; choose 5/15/30/60 minutes idle or "until I lock it" in the Settings menu (default 15). Locks on sleep. Only that preference is saved (`settings.json`); the master password is never stored and the key lives only in memory. Changing the master password still asks for the current one.
- **Auto-type login**: types username, Tab, password, Enter into the window you click (Windows `SendInput`, Unicode-safe, clipboard not used). Variants: password only, username only.
- **XML import/export** (interchange only, like CSV; the live vault stays the encrypted file): File > "Export to XML (not encrypted)..." and "Import from XML...". Reads OttoVault XML and a subset of KeePass 2.x XML exports. See the XML notes below.
- **KeePass 1 (.kdb) import** (KeePassX 0.x / KeePass 1.x databases): File > "Import from KeePass 1 (.kdb)..." asks for the KeePass database password in a hidden-entry box and imports title, username, password, URL and notes directly - no need to export first. See the KeePass 1 notes below.
- **Otto inbox**: the vault holds an X25519 key pair; the public key is written to `inbox_public.key`. `otto_add.py` can encrypt a new entry to it and drop it in the `inbox` folder without ever knowing the master password; the app imports it on the next unlock.
- **Per-service AI access (optional, off by default)**: tick "Allow AI access to this password" on an entry and an AI assistant using `otto_get.py` can fetch that one password from the *running, unlocked* app through an encrypted request/response mailbox, without asking again. Locked vault = no answer. The master password is never stored; approvals and an audit log live inside the encrypted vault; every release is logged; you can untick one entry or revoke all. See the security tradeoff in `OTTO_USAGE.md`.

Tests: 174 pytest unit tests (`py -m pytest tests`) plus a headless GUI smoke test (`tests/gui_smoke.py`, run under xvfb on Linux). Real auto-typing into a Windows application and the tkinter GUI on Windows have not been automatically tested, and the app has not been independently audited.

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

**XML import / export.** XML is a plain-text interchange format, parallel to CSV; it never replaces `vault.dat`. *Export* (File > "Export to XML (not encrypted)...") first shows a warning, then asks you to re-enter your master password (a wrong password counts toward the unlock lockout), then writes every entry **unencrypted**, including passwords - delete the file after use; it is created owner-only where the OS supports that, but cloud-sync or backup software may still copy it. *Import* (File > "Import from XML...") applies the same length/character rules and the same duplicate rule as CSV (exact duplicates are skipped), and **never grants AI access** (the optional `ai_access` / `ai_access_until` attributes in an export are informational and ignored on import). Parsing is hardened: files over 10 MiB or with more than 50,000 entries are refused, and any file containing a `DOCTYPE` or entity declaration is refused before parsing (so no "billion laughs" entity expansion and no external-entity/XXE file reads; only the standard-library ElementTree is used, no new dependencies). Malformed files give a clear error and change nothing. Files must be UTF-8 or UTF-16.

Schema (OttoVault XML, version 1):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ottovault version="1">
  <entry ai_access="true" ai_access_until="2026-11-17">   <!-- attributes optional, informational -->
    <title>...</title>
    <username>...</username>
    <password>...</password>
    <url>...</url>
    <notes>...</notes>
  </entry>
</ottovault>
```

KeePass 2.x XML (File > Export > "KeePass XML (2.x)"): **works** - Title, UserName, Password, URL and Notes of every entry in every group. **Not imported**: group names/hierarchy, entry history, attachments, custom fields, tags, icons, expiry; entries in the "Recycle Bin" group are skipped; entries whose password is stored in KeePass's protected form (`Protected="True"`, not what the XML export normally writes) are skipped and counted rather than importing ciphertext. KeePass 1.x XML, `.kdbx` and other formats are not supported (export CSV or KeePass 2.x XML from those programs). Tested only with hand-made sample files, not with real KeePass exports of every version.

**KeePass 1 (`.kdb`) import** (File > "Import from KeePass 1 (.kdb)..."). The `.kdb` file is read-only interchange input: it is decrypted **in memory only** (nothing is written to disk, the file is never modified), and `vault.dat` stays OttoVault's own encrypted file. You type the *KeePass database's* password into a hidden-entry box; it is used once to open that file and is never saved or logged. A wrong KeePass password only shows an error - it does **not** count toward OttoVault's unlock lockout (it is a different password); after three wrong tries in a row the import pauses for 30 s+ (in memory only, resets on restart). Imported entries follow the same length/character rules and duplicate rule as CSV/XML and **never get AI access**. Files over 32 MiB, more than 50,000 groups/entries, or absurd key-transformation settings are refused.
- *Works:* AES (Rijndael) and Twofish databases; password-only, password + key file, or key file only (a "key file?" question appears after a wrong password); non-ASCII passwords (UTF-8 and the old Windows ANSI encoding are both tried). Imports Title, UserName, Password, URL, Notes.
- *Not imported:* group names/hierarchy, attachments, expiry dates, icons; KeePassX's hidden "Meta-Info" records; the KeePass "Backup" group (old copies, counted and reported). ARCFOUR databases and `.kdbx` (KeePass 2) files are refused with a clear message (for KeePass 2 use its XML export).
- *Tested how:* the reader is checked against databases written by an independent KeePass 1 library (AES; password, key file, password + key file), plus synthetic files written by the test-suite (AES and Twofish, special characters, empty database, duplicates, damaged and hostile files). Twofish is a bundled pure-Python implementation (`twofish.py`, no new dependency) verified against the official Twofish test vectors; it has **not** been tried against a Twofish `.kdb` written by real KeePass. Not tested against every KeePass 1.x/KeePassX build - **keep your `.kdb` as a backup until you have checked the imported entries**.

**Not (yet) covered.** No independent security audit. Python cannot wipe secrets from memory. Windows clipboard history may keep copied passwords. Keystroke loggers see what you type. Backups made with File > Export keep the approvals and log of that moment.

## License
MIT - see `LICENSE`.
