"""OttoVault settings (non-secret) + idle-timeout logic. No GUI code here.

Only a harmless preference is stored (how long to stay unlocked) in
settings.json next to the vault. The master password and keys are never
stored anywhere."""
import json
import os
import time

import vault as V

ALLOWED_MINUTES = (5, 15, 30, 60, "never")
DEFAULT_MINUTES = 15
NEVER = "never"


def default_settings():
    return {"version": 1, "idle_minutes": DEFAULT_MINUTES}


def settings_path_for(vault_path):
    return os.path.join(os.path.dirname(os.path.abspath(vault_path)), "settings.json")


def normalize_minutes(value):
    """Return a valid idle setting (5/15/30/60/'never') or the default."""
    if value == NEVER:
        return NEVER
    if isinstance(value, bool):
        return DEFAULT_MINUTES
    if isinstance(value, (int, float)) and int(value) == value and int(value) in ALLOWED_MINUTES:
        return int(value)
    return DEFAULT_MINUTES


def load_settings(path):
    """Never raises: missing/corrupt/odd file -> defaults."""
    s = default_settings()
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read(65536).decode("utf-8"))
        if isinstance(doc, dict):
            s["idle_minutes"] = normalize_minutes(doc.get("idle_minutes"))
    except Exception:
        pass
    return s


def save_settings(path, settings):
    clean = {"version": 1, "idle_minutes": normalize_minutes(settings.get("idle_minutes"))}
    V._atomic_write(path, (json.dumps(clean, indent=1) + "\n").encode("utf-8"),
                    keep_backup=False)
    return clean


class IdleTracker:
    """Decides when to auto-lock. The clock is injectable for testing.
    time.time() is used so time spent asleep counts as idle."""

    def __init__(self, minutes=DEFAULT_MINUTES, clock=time.time):
        self._clock = clock
        self.minutes = normalize_minutes(minutes)
        self._last = clock()

    def set_minutes(self, minutes):
        self.minutes = normalize_minutes(minutes)
        self.touch()

    def touch(self):
        self._last = self._clock()

    def idle_seconds(self):
        return self._clock() - self._last

    def expired(self):
        if self.minutes == NEVER:
            return False
        return self.idle_seconds() >= self.minutes * 60

    def remaining(self):
        """Seconds until auto-lock, or None in 'never' mode."""
        if self.minutes == NEVER:
            return None
        return max(0.0, self.minutes * 60 - self.idle_seconds())
