"""Test speed-up: new vaults in the test-suite use the weakest Argon2id
parameters the file parser still accepts. The real defaults are checked
explicitly in tests/test_hardening.py (test_default_argon2_parameters)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vault as V  # noqa: E402

V.REAL_ARGON2_PARAMS = dict(V.ARGON2_PARAMS)     # kept for the explicit test
V.ARGON2_PARAMS = dict(V.ARGON2_MIN)
