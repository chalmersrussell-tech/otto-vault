# Using OttoVault with an AI assistant

OttoVault is built so an AI assistant can help you with logins, **with your per-entry permission**: for a service you approve, the assistant can retrieve its username and password (`otto_get.py`) and use or paste them for you, and it can add new logins to your vault (`otto_add.py`, below). It never sees your master password, you can revoke access at any time, and every release is logged. Read the security notes at the end before enabling it.

No separate "save vault" step: pressing Save on an entry (or adding, deleting or importing, including a login added by an AI assistant) writes the encrypted vault to disk right away.

# Part 1 - AI adds a login: the inbox (`otto_add.py`)

The inbox lets a helper program or person leave you a **new** entry **without
knowing your master password and without reading your vault**.

## How it works
1. The first time you unlock OttoVault 1.1 or newer, it creates an X25519 key pair
   inside your encrypted vault and writes the **public** key to
   `%APPDATA%\OttoVault\inbox_public.key` (not secret).
2. `otto_add.py` encrypts an entry to that public key (ephemeral X25519 +
   HKDF-SHA256 + AES-256-GCM) and writes one `*.ottoentry` file into
   `%APPDATA%\OttoVault\inbox\`.
3. The next time OttoVault is unlocked (or while it is unlocked, within about
   15 seconds) it decrypts the file with the private key held in the vault, adds
   the entry, deletes the file and shows **"Imported 1 entry from Otto"**.
   Files it cannot read are renamed `*.bad` and are never imported.

The private key never leaves the vault. A repeated/replayed message is imported
only once.

## Commands (Windows; replace `py` with your Python if needed)
Add an entry with a generated username and password (the password is never printed):

    py otto_add.py --service "Example Service" --generate-username --generate-password

Choose your own username, read the password from standard input:

    py otto_add.py --service "Example Service" --username alice --password-stdin

Useful options: `--url`, `--notes`, `--length 24`, `--no-symbols`,
`--dir <folder>` (default `%APPDATA%\OttoVault`).

If it says `inbox_public.key` is missing, open OttoVault and unlock it once.

## Check that it worked
After unlocking OttoVault, the inbox folder should be empty (no `.ottoentry`
and no `.bad` files) and the entry appears in the list.

## Security notes
* Anyone who can write to your inbox folder and has the public key can add
  an entry (not read anything). Review newly imported entries.
* The public key is not secret; the master password and vault stay private.

---

# Part 2 - AI uses an approved login (`otto_get.py`)

Lets an AI assistant (or other automation helper) retrieve the password of **specific services
you approved**, without asking each time, **only while OttoVault is unlocked**.

## Turning it on (owner, in the app only)
1. Unlock OttoVault, click an entry.
2. Tick **"Allow AI access to this password"** and press **Save**.
   The list shows a tick in the **AI** column.
3. Each approval **expires** after 30 days by default (Settings > *AI access
   approval lasts*: 30 days / 7 days / never, for new approvals). When it ends
   the box is switched off and the request is refused until you tick it again.
   Untick + Save to revoke that entry at once, or use
   **Settings > Revoke all AI access approvals...**.

There is no command, file or API that can set the approval: only the app's
form can. New entries (including those added through the inbox or a CSV import) are
**not** approved until you tick them.

## How a request works
1. `otto_get.py` creates a one-time X25519 key pair **in memory** and writes a
   small `*.ottoreq` file (random request id, service name, one-time *public*
   key, timestamp) to `%APPDATA%\OttoVault\requests\`.
2. The unlocked app checks that folder every ~2 seconds. It answers only if
   exactly one entry has that title (case-insensitive, exact) **and** that
   entry is approved. Otherwise it answers *denied*, *not found* or
   *ambiguous* (no password, nothing listed).
3. The answer, `responses\<id>.ottoresp`, is encrypted to the one-time key
   and authenticated with the vault's own key pair, so other programs can
   neither read nor forge it. `otto_get.py` decrypts it in memory and
   deletes both files. Nothing readable is written to disk or logs.
4. If the vault is locked or the app is closed, nothing answers and
   `otto_get.py` reports *vault locked or not running* after ~30 s.

Names are matched exactly after normalising: case, repeated spaces and
look-alike (compatibility) forms are ignored; control and invisible characters
are refused. Safeguards: requests older than 2 minutes are ignored; request files are
size-limited; at most 30 successful releases per minute (more get *rate
limited*) and a flood guard for any requests beyond 60 per minute; a repeated
request id is answered once.

## Commands (Windows; replace `py` with your Python if needed)
Status only (the password is **not** printed):

    py otto_get.py --service "Example Service"

Print the password (only with the explicit flag; use it to hand the password
to the program that needs it, not to show it to people):

    py otto_get.py --service "Example Service" --print

If two entries share a name, narrow it down: `--username alice`.
Other options: `--timeout 30` (max 120), `--dir <folder>`, `--print-username`.

Exit codes: 0 approved, 1 denied, 2 not found, 3 ambiguous, 4 vault locked /
not running, 5 rate limited, 6 error. With `--print`, only the password goes to
standard output; status text goes to standard error.

## Audit log
**File > AI access log...** shows time, service and result (*released*,
*denied*, *not found*, *ambiguous*, *rate limited*, plus *approved*/*revoked*
changes, *expired* and *revoked all*) for the last 500 events. Every grant and
every revoke is recorded. It is stored inside the encrypted vault and never
contains a password. Entries are chained with a keyed MAC and an outside
anchor file checks the newest one, so an edited, deleted or rolled-back log
produces a warning when you unlock (a "log integrity warning" event stays in
the log). That detects silent edits; it cannot stop you deleting the vault.

## Security notes - please read
* Entries brought in through the inbox, CSV import, XML import or KeePass 1
  (.kdb) import are never approved for AI access, whatever the file says. An XML
  *export* lists `ai_access` only as information.
* **This is a deliberate tradeoff.** While the vault is unlocked, any program
  running as the same Windows user could also file a request for an approved
  entry (and the vault cannot tell your AI assistant from such a program). Approve only
  services you actually want automated, and lock the vault when you are away
  (File > Lock now, or a short "stay unlocked" time in Settings).
* The master password is **never stored** anywhere. Approvals and the log live
  inside the encrypted vault; an unlocked app answers from memory.
* Every release is recorded in the access log. Check it now and then.
* The helper script never opens the vault file. A person who knows your master
  password can of course do anything, including changing approvals.
* A backup made with File > Export contains the approvals; restoring it brings
  them back.
* A request for a password you never approved shows in the status bar and in
  the log as *denied*.
* Approvals expire (see above), which limits how long a forgotten approval can
  be used. Shorter is safer: choose 7 days if you only need it occasionally.
