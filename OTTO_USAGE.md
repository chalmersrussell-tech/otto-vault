# Using the OttoVault inbox (`otto_add.py`)

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
