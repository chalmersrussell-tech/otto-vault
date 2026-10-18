"""OttoVault - failed-unlock lockout (no GUI code, no secrets).

After FREE_ATTEMPTS wrong master passwords in a row the unlock screen refuses
further tries for an increasing time: 30 s, 60 s, 120 s ... capped at 15 min.
A correct password resets the counter.

State lives in lockout.json next to the vault: the failure count, the
"locked until" time and a salted SHA-256 over both. The master password (or
anything derived from it) is NEVER written. The hash only detects accidental
corruption / casual hand-editing; it is not a security boundary - see README
("Unlock lockout"): it slows someone typing guesses into the app, it cannot
slow an offline attack on a copied vault.dat (that is the KDF's job) and any
program running as you could delete the file.
"""
import base64
import hashlib
import json
import os
import secrets
import time

import vault as V

FREE_ATTEMPTS = 5          # wrong passwords before the first delay
BASE_DELAY = 30            # seconds
MAX_DELAY = 15 * 60
FILENAME = "lockout.json"


def lockout_path_for(vault_path):
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), FILENAME)


def delay_for(failures):
    """Seconds of lockout that follow the Nth consecutive failure."""
    if failures < FREE_ATTEMPTS:
        return 0
    return min(BASE_DELAY * 2 ** (failures - FREE_ATTEMPTS), MAX_DELAY)


def _check(salt, failures, until):
    return hashlib.sha256(salt + b"|%d|%d" % (failures, until)).hexdigest()


class Lockout:
    def __init__(self, path, clock=time.time):
        self.path = path
        self._clock = clock
        self.failures = 0
        self.until = 0
        self._load()

    # -- persistence
    def _load(self):
        try:
            with open(self.path, "rb") as f:
                raw = f.read(4096)
        except FileNotFoundError:
            return
        except OSError:
            return
        try:
            doc = json.loads(raw.decode("utf-8"))
            salt = base64.b64decode(doc["salt"], validate=True)
            failures, until = doc["failures"], doc["until"]
            if type(failures) is not int or type(until) is not int or failures < 0 or until < 0:
                raise ValueError
            if doc["check"] != _check(salt, failures, until):
                raise ValueError
        except Exception:
            # damaged or hand-edited: do not brick the vault, but do not reward
            # tampering either - start at the first delay.
            self.failures = FREE_ATTEMPTS
            self.until = int(self._clock()) + delay_for(FREE_ATTEMPTS)
            self._save()
            return
        self.failures, self.until = failures, until

    def _save(self):
        salt = secrets.token_bytes(16)
        doc = {"version": 1, "salt": base64.b64encode(salt).decode("ascii"),
               "failures": self.failures, "until": int(self.until),
               "check": _check(salt, self.failures, int(self.until))}
        try:
            V._atomic_write(self.path, (json.dumps(doc) + "\n").encode("utf-8"),
                            keep_backup=False)
        except OSError:
            pass

    # -- API
    def remaining(self, now=None):
        """Whole seconds left to wait (0 = unlocking allowed)."""
        now = self._clock() if now is None else now
        left = self.until - now
        if left <= 0:
            return 0
        return int(min(left, MAX_DELAY) + 0.999)

    def record_failure(self, now=None):
        """Count one wrong password; returns the seconds now locked out (0 = none)."""
        now = self._clock() if now is None else now
        self.failures += 1
        d = delay_for(self.failures)
        self.until = int(now) + d if d else 0
        self._save()
        return d

    def record_success(self):
        self.failures = 0
        self.until = 0
        try:
            os.remove(self.path)
        except OSError:
            pass

    def tries_left(self):
        return max(0, FREE_ATTEMPTS - self.failures)
