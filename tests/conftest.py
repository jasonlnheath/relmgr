"""Session guard for spec hard-rule #1: NEVER write to prod contacts.db in tests.

The module-level ``app = create_app()`` at app.py import time boots the full
migration chain against its default path (~/relmgr/contacts.db) — any test
that imports app (directly or in a subprocess inheriting os.environ) mutates
the PROD database through that boot. This conftest redirects the module-level
boot to a throwaway DB before any test module is imported; per-test fixtures
still pass explicit tmp_path DBs everywhere as before.

The variable survives test_refactor_fixes' WHITELIST_* env-stripping because
it is RELMGR_-prefixed. The systemd service runs without it, so production
keeps using contacts.db next to app.py.
"""
import os
import tempfile
from pathlib import Path

_scratch = Path(tempfile.mkdtemp(prefix="relmgr_test_boot_")) / "scratch.db"
os.environ.setdefault("RELMGR_DB_PATH", str(_scratch))
