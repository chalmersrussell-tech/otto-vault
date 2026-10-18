"""otto_add.py - queue a NEW entry for OttoVault without the master password.

It encrypts the entry to the vault's PUBLIC key (inbox_public.key) and drops
one file into the OttoVault inbox folder. OttoVault imports it the next time
it is unlocked, then deletes the file. This tool never reads the vault, never
sees the master password and never prints the password it generates.

Examples:
  py otto_add.py --service "My Site" --generate-username --generate-password
  py otto_add.py --service "My Site" --username bob --password-stdin
"""
import argparse
import os
import secrets
import string
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vault as V  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--service", required=True, help="entry title")
    ap.add_argument("--username")
    ap.add_argument("--generate-username", action="store_true")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read the password from standard input")
    ap.add_argument("--generate-password", action="store_true")
    ap.add_argument("--length", type=int, default=24)
    ap.add_argument("--no-symbols", action="store_true")
    ap.add_argument("--url", default="")
    ap.add_argument("--notes", default="Added by Otto")
    ap.add_argument("--dir", help="OttoVault data folder (default: %%APPDATA%%\\OttoVault)")
    a = ap.parse_args(argv)

    base = a.dir or os.path.dirname(V.default_vault_path())
    try:
        pub = V.read_public_key_file(os.path.join(base, V.PUBLIC_KEY_FILENAME))
    except V.VaultError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        print("Open OttoVault and unlock it once so it can create inbox_public.key.",
              file=sys.stderr)
        return 2

    if a.generate_username:
        username = "user-" + "".join(secrets.choice(string.ascii_lowercase + string.digits)
                                     for _ in range(8))
    else:
        username = a.username or ""
    if a.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    elif a.generate_password:
        password = V.generate_password(max(8, a.length), not a.no_symbols)
    else:
        password = ""
    if not password:
        print("ERROR: choose --generate-password or --password-stdin", file=sys.stderr)
        return 2

    blob = V.inbox_seal(pub, {"title": a.service, "username": username,
                              "password": password, "url": a.url, "notes": a.notes})
    inbox = os.path.join(base, V.INBOX_DIRNAME)
    os.makedirs(inbox, exist_ok=True)
    name = "%s-%s%s" % (time.strftime("%Y%m%d-%H%M%S"), secrets.token_hex(4), V.INBOX_EXT)
    V._atomic_write(os.path.join(inbox, name), blob, keep_backup=False)
    print("Queued entry '%s' (username: %s). File: %s (%d bytes)"
          % (a.service, username, name, len(blob)))
    print("It will be added to the vault the next time OttoVault is unlocked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
