r"""otto_get.py - ask the UNLOCKED OttoVault for a password you were approved for.

The owner must have ticked "Allow AI access to this password" on
that entry in OttoVault. This tool never opens the vault and never sees the
master password: it files a request in %APPDATA%\OttoVault\requests\ (service
name + a one-time public key held only in this process's memory) and waits up
to 30 seconds for the running, unlocked app to answer in responses\. The answer
is encrypted to the one-time key and authenticated by the vault's key, so
nothing readable is ever written to disk.

By default only a STATUS is printed (approved / denied / not found / ...).
The password itself is printed only with --print.

Examples:
  py otto_get.py --service "My Site"                 (status only)
  py otto_get.py --service "My Site" --print         (prints the password)
  py otto_get.py --service "My Site" --username bob --print

Exit codes: 0 approved, 1 denied, 2 not found, 3 ambiguous (use --username),
4 vault locked / app not running (no answer), 5 rate limited, 6 error.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vault as V  # noqa: E402

EXIT = {V.R_RELEASED: 0, V.R_DENIED: 1, V.R_NOT_FOUND: 2, V.R_AMBIGUOUS: 3, V.R_RATE: 5}
TEXT = {
    V.R_RELEASED: "approved",
    V.R_DENIED: "denied: the owner has not allowed AI access to this service",
    V.R_NOT_FOUND: "not found",
    V.R_AMBIGUOUS: "ambiguous: more than one entry has that name (add --username)",
    V.R_RATE: "rate limited: too many requests, try again in a minute",
}


def _read_response(path):
    for _ in range(10):          # the app may still be replacing the file
        try:
            with open(path, "rb") as f:
                return f.read(V.RESPONSE_MAX_BYTES + 1)
        except OSError:
            time.sleep(0.05)
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--service", required=True, help="entry title (exact, case-insensitive)")
    ap.add_argument("--username", help="only match the entry with this username")
    ap.add_argument("--print", dest="show", action="store_true",
                    help="print the password to standard output (default: status only)")
    ap.add_argument("--print-username", action="store_true",
                    help="also show the entry's username (status stream, not stdout, with --print)")
    ap.add_argument("--timeout", type=float, default=30.0, help="seconds to wait (max 120)")
    ap.add_argument("--dir", help="OttoVault data folder (default: %%APPDATA%%\\OttoVault)")
    a = ap.parse_args(argv)

    out = sys.stderr if a.show else sys.stdout      # keep stdout clean for the password
    base = a.dir or os.path.dirname(V.default_vault_path())
    try:
        vault_pub = V.read_public_key_file(os.path.join(base, V.PUBLIC_KEY_FILENAME))
        req = V.make_request(a.service, a.username or "")
    except V.VaultError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 6
    rdir = os.path.join(base, V.REQUESTS_DIRNAME)
    odir = os.path.join(base, V.RESPONSES_DIRNAME)
    rfile = os.path.join(rdir, req["id"] + V.REQUEST_EXT)
    ofile = os.path.join(odir, req["id"] + V.RESPONSE_EXT)
    try:
        os.makedirs(rdir, exist_ok=True)
        os.makedirs(odir, exist_ok=True)
        V._atomic_write(rfile, req["blob"], keep_backup=False)
    except OSError as exc:
        print("error: could not write request: %s" % exc, file=sys.stderr)
        return 6

    deadline = time.time() + max(1.0, min(a.timeout, 120.0))
    blob = None
    while time.time() < deadline:
        if os.path.exists(ofile):
            blob = _read_response(ofile)
            if blob:
                break
        time.sleep(0.2)
    if blob is None:
        try:
            os.remove(rfile)        # do not leave a request behind for a later unlock
        except OSError:
            pass
        print("vault locked or not running (no answer in %d s)" % int(a.timeout), file=out)
        return 4
    try:
        os.remove(ofile)
    except OSError:
        pass
    try:
        body = V.response_open(req["eph_private"], vault_pub, blob, req["id"])
    except V.VaultError:
        print("error: the answer could not be verified (ignored)", file=sys.stderr)
        return 6
    status = body.get("status")
    if status not in EXIT:
        print("error: unexpected answer", file=sys.stderr)
        return 6
    if status != V.R_RELEASED:
        print(TEXT[status], file=out)
        return EXIT[status]
    if a.show:
        print(TEXT[status], file=out)
        if a.print_username:
            print("username: %s" % body.get("username", ""), file=out)
        sys.stdout.write("%s\n" % body.get("password", ""))
        sys.stdout.flush()
    else:
        print("approved: password retrieved but NOT printed (add --print to output it)", file=out)
        if a.print_username:
            print("username: %s" % body.get("username", ""), file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
