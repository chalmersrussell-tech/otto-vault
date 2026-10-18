OTTOVAULT 1.3.2 - the free password manager your AI assistant can use
=====================================================================
A free password manager that lives only on your PC, built so an AI
assistant can help you with logins: for each service YOU approve, the AI
can fetch the username and password and use them for you - without ever
seeing your master password. You can revoke any time, approvals can expire,
and every grant and release is written to a tamper-evident log.

No cloud. No internet use. No account. No subscription. No tracking.
Your passwords are stored in one encrypted file on this computer.
Also: import from KeePass 1 (.kdb), KeePass 2 XML, OttoVault XML and CSV.

!!  YOUR MASTER PASSWORD CANNOT BE RECOVERED.  !!
If you forget it, your passwords are gone. Nobody (not even the person who
made this) can reset it. Pick one you will remember, and write it on paper
somewhere safe.


HOW TO START (3 steps)
----------------------
1. Open the OttoVault folder you saved (for example Documents\OttoVault).
2. Double-click  "Run OttoVault.bat"
   (First time only: it quietly installs one small helper package. Needs
   internet for that one step. Takes a few seconds. A black window may flash.)
3. First time: type a master password (8+ characters) twice, click
   "Create my vault". Next times: type it and click "Unlock".

If Windows shows a blue "Windows protected your PC" box, click
"More info" and then "Run anyway" (it's a plain text script you own).


IF PYTHON IS MISSING
--------------------
The .bat will tell you "Python was not found". Install it once:
  Option A (easiest): Open the Start menu, type "Microsoft Store", search
          for "Python 3.13" (by Python Software Foundation) and click Get.
  Option B: Go to https://www.python.org/downloads/ , click the big yellow
          Download button, run the installer, and TICK the box
          "Add python.exe to PATH" at the bottom of the first screen,
          then click "Install Now".
Then double-click "Run OttoVault.bat" again.


STAY UNLOCKED (like 1Password) - NEW in 1.1
-------------------------------------------
You type your master password ONCE. After that you can add, edit, delete,
search and copy as much as you like without being asked again.
* Settings > "Stay unlocked for" lets you pick: 5, 15, 30 or 60 minutes of
  no activity, or "Until I lock it or close the app". Default: 15 minutes.
  Any click, key press or mouse movement in OttoVault restarts the timer.
* It also locks right away if the PC went to sleep.
* File > Lock now locks instantly.
* File > Change master password ALWAYS asks for the current password. That
  is on purpose, so nobody sitting at your unlocked PC can change it.
* The master password is never saved anywhere. Only your choice of minutes
  is saved (in settings.json, next to the vault). The key that opens the vault
  lives only in memory while it is unlocked - so a longer time = more risk.
  If you share the PC, use a short time.

AUTO-TYPE A LOGIN - NEW in 1.1
------------------------------
No browser add-on needed.
1. Click an entry in the list.
2. Click "Auto-type login" and choose:
     - Username + Tab + password + Enter  (the usual choice)
     - Password only (then Enter)
     - Username only (then Enter)   (for sites that ask in two steps)
3. OttoVault minimizes and a yellow note counts down 3...2...1.
   During the countdown CLICK the username box of the website/app.
4. It types the login into whatever window is active. Your clipboard is not used.
Careful: it types into whatever window has focus. If you clicked the wrong
place, the password goes there. It cannot type into programs that are running
"as administrator". If OttoVault itself is the active window it types nothing.

OTTO INBOX (for the family helper) - NEW in 1.1
-----------------------------------------------
OttoVault creates a small key pair inside your vault the first time you
unlock it with this version, and writes the PUBLIC half to
%APPDATA%\OttoVault\inbox_public.key (not secret). Otto can use it to leave
you a NEW entry in %APPDATA%\OttoVault\inbox\ - encrypted so that only your
unlocked OttoVault can read it. Otto never sees your master password or your
vault. Next time OttoVault is unlocked it adds the entry, deletes the file and
says "Imported 1 entry from Otto". Files it cannot read are renamed *.bad.

SAFETY FEATURES - NEW in 1.3
----------------------------
* WRONG-PASSWORD DELAY: after 5 wrong master passwords in a row the Unlock
  button pauses for 30 seconds, then 60, 120 ... up to 15 minutes. The right
  password resets it. (A speed bump for someone typing guesses; it cannot slow
  an attack on a stolen copy of the file - the Argon2id cost does that.)
* INPUT LIMITS: title 200, username 256, password 1024, URL 2048, notes 20000
  characters; invisible/control characters are refused (passwords can still
  contain any symbols). Also applied to the inbox and CSV import.
* AI ACCESS EXPIRES: see the next section.
* ACCESS LOG CHECK: the AI access log is chained with a secret code so that
  edits, deleted lines or a restored old copy show a warning when you unlock.
  It cannot stop you (or someone who knows your master password) from deleting
  the vault file itself.
* OttoVault.exe: build_exe.bat builds a real program (no black window) from
  the source - see "OttoVault.exe" below. It is a convenience, not extra
  security, and it is not code-signed (Windows may warn).

ALLOW AI ACCESS TO SOME PASSWORDS - NEW in 1.2
---------------------------------------------
This is OPTIONAL and OFF for every entry until you turn it on.
* In an entry, tick "Allow AI access to this password" and click Save.
  A tick mark appears in the "AI" column of the list.
* While OttoVault is UNLOCKED, an AI assistant (using the helper program
  otto_get.py) can ask
  for the password of that one service, by exact name, without asking you
  again. Entries that are not ticked are always refused.
* When OttoVault is locked or closed, nobody gets anything: it only answers
  while it is unlocked. Your master password is never stored or shown.
* File > AI access log... lists every request (time, service, released /
  denied / not found). Passwords are never written in the log. The log and
  the approvals live inside your encrypted vault.
* Each approval lasts 30 days by default (Settings > "AI access approval
  lasts": 30 days / 7 days / never). Afterwards the box switches itself off
  and you tick it again if you still want it. The entry shows the end date.
* Untick the box and Save to take back one approval immediately.
  Settings > Revoke all AI access approvals... removes all of them.
* The status line tells you when an AI assistant asked ("An AI assistant asked
  for X - not approved").
* Entries added through the inbox are NEVER pre-approved; you tick them.
Honest tradeoff: while the vault is unlocked, ANY program running as your
Windows user could also file a request for an approved entry. So approve only
the services you want automated, and lock the vault (File > Lock now) when
you are away. See OTTO_USAGE.md.

OttoVault.exe (optional)
------------------------
Double-click build_exe.bat once (needs internet for one small download):
it installs PyInstaller for your user only and builds OttoVault.exe into
%LOCALAPPDATA%\Programs\OttoVault\ . Point your shortcut at that file.
Run OttoVault.bat keeps working as the plain way to start the program. Neither
one makes the vault any safer or less safe: the protection is your master
password and the encryption. The exe is not code-signed, so Windows
SmartScreen or antivirus may warn, and some Windows setups (Smart App Control,
AppLocker, company policy) refuse to run unsigned programs altogether. If
Windows says "An Application Control policy has blocked this file", just keep
using Run OttoVault.bat - do not turn Windows protections off for this.
Build it yourself from this folder.
Your vault is never copied into the build. Rebuild after every update.

EVERYDAY USE
------------
* Left side: your list. Type in "Search" to filter by title, username, URL
  or notes.
* "+ New entry": fill in the form on the right, click Save.
* Click an entry to see it. "Show" reveals the password. "Copy password"
  copies it; the clipboard is wiped after 20 seconds.
* "Generate..." makes a strong random password (choose length, symbols on/off),
  then "Use this password" and Save.
* It locks itself after the idle time you chose (Settings menu, default
  15 minutes). File > Lock now locks it immediately.

MOVING YOUR KEEPASSX PASSWORDS IN
---------------------------------
1. In KeePassX: File > Export to... > CSV (or "KeePass Text File (CSV)").
2. In OttoVault: File > Import from CSV... and pick that file.
   (Chrome/Edge/Firefox CSV exports work too.)
3. Check your entries look right.
4. DELETE the CSV file and empty the Recycle Bin - it holds all your
   passwords as plain readable text!
5. Keep your KeePassX vault until you are sure everything came across.

XML IMPORT / EXPORT - NEW in 1.3.2
----------------------------------
File > "Import from XML..." reads an OttoVault XML file or a KeePass 2.x XML
export (KeePass: File > Export > "KeePass XML (2.x)"). Title, username,
password, URL and notes come across; KeePass groups, history, attachments and
custom fields do not, and the Recycle Bin group is skipped. Duplicates are
skipped, too-long or odd-character entries are skipped and counted, and
imported entries never get AI access (you tick that yourself).
File > "Export to XML (not encrypted)..." writes ALL your entries, with
passwords, as READABLE TEXT. It warns you, asks for your master password
again, and you should delete the file after use (and empty the Recycle Bin).
For a normal backup use File > Export encrypted backup... instead.
XML is only for moving data between programs; your vault itself stays
encrypted. Files over 10 MiB, or containing DOCTYPE/entity tricks, are refused.

KEEPASS 1 (.kdb) IMPORT - NEW in 1.3.2
--------------------------------------
File > "Import from KeePass 1 (.kdb)..." opens a KeePassX / KeePass 1.x
database directly. Pick the .kdb file, then type the KeePass database's own
password in the box (NOT your OttoVault master password). It is used only in
memory to open that file and is never saved or logged. A wrong KeePass
password just shows an error; it does not count toward OttoVault's lockout
(after 3 wrong tries in a row the import pauses for a short while).
Title, username, password, URL and notes come across. Duplicates are skipped,
odd entries are skipped and counted, and imported entries never get AI
access. Group names, attachments and KeePass's "Backup" group are not
imported. Key files are supported (the program asks after a wrong password).
KEEP YOUR .kdb FILE as a backup until you have checked the imported entries.
Not supported: ARCFOUR databases and .kdbx (KeePass 2: use its XML export).
Twofish databases are supported but were tested only with test vectors and
synthetic files, not with a file written by real KeePass.

BACKUPS (please do this)
------------------------
* File > Export encrypted backup... saves an encrypted copy wherever you
  choose (a USB stick, another drive). It opens with the master password you
  had when you made it. Do this now and then.
* To use a backup: on the unlock screen click "Restore from a backup file...".
* OttoVault also keeps the previous version as vault.dat.bak next to the
  vault file.

CHANGING THE MASTER PASSWORD
----------------------------
File > Change master password... (needs the current one). Old backups still
need the OLD password.

WHERE THINGS ARE
----------------
Your vault:  %APPDATA%\OttoVault\vault.dat
             (usually C:\Users\<your name>\AppData\Roaming\OttoVault\vault.dat)
Program:     the OttoVault folder you have now.
To uninstall: delete the program folder. Your vault file stays until you
delete the AppData\OttoVault folder.

HOW IT PROTECTS YOU (for the curious)
-------------------------------------
* Master password -> key using Argon2id (64 MiB, 3 passes, 4 lanes, random
  16-byte salt). Older vaults used Scrypt (n=32768, r=8, p=1); they still open
  and are upgraded to Argon2id once, right after you unlock. A copy of the old
  file is kept as vault.dat.pre-upgrade.bak. Needs 'cryptography' 44 or newer
  (Run OttoVault.bat installs/updates it for you).
* The whole vault is encrypted with AES-256-GCM (random 12-byte nonce on each
  save); any change to the file is detected and refused.
* Saves are atomic (temp file then replace). No plain text is ever written
  to disk and no secrets are logged. The program makes no network calls.
* Crypto is from the well-known "cryptography" Python package.

HONEST LIMITS
-------------
* This is a home-made program. It has NOT been independently security
  audited. KeePassX/KeePassXC/Bitwarden are far more battle-tested.
* A virus or keylogger already on your PC can still see what you type.
* Auto-type sends keystrokes to whatever window is active. A keylogger on
  the PC could still see them.
* Windows clipboard history (Win+V), if turned on, may keep a copy of a
  copied password even after OttoVault clears the clipboard.
* Python can't fully wipe secrets from memory while the app is open.
* Forgot master password = data lost. Keep backups.

HOW TO TEST IT (5 minutes, uses a fake entry)
---------------------------------------------
1. Double-click the OttoVault shortcut and unlock. (First time with 1.1 this
   quietly creates the inbox key - nothing to do.)
2. Settings > Stay unlocked for > 30 minutes. Close OttoVault, open it
   again: the choice should still be ticked.
3. Click "+ New entry", type a FAKE title/username/password (e.g. "Test",
   "me", "fake-pass-1"), click Save. You were not asked for the master
   password. Search for it, edit it, copy the password - still no prompt.
4. Open Notepad. Back in OttoVault click the "Test" entry, Auto-type login >
   Username + Tab + password + Enter. Within 3 seconds click inside Notepad.
   You should see:  me   fake-pass-1  on two lines/columns. Delete the test entry.
5. File > Lock now - you should be asked for the master password again.

FOR DEVELOPERS: tests
---------------------
  py -m pip install pytest
  py -m pytest tests          (174 tests)
  otto_get.py asks the unlocked app for an approved password (status only unless --print)
  otto_add.py queues an inbox entry:  py otto_add.py --service "Name" --generate-username --generate-password
