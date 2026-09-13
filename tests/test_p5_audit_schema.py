"""P5 audit-vocab heal — RED phase for the grant_logs CHECK constraint bugs.

merge_requester_into_contacts logs action='merged' and set_grant_cards logs
action='cards_set'. Production's grant_logs DDL (and every fresh boot via
wl_init / ensure_grant_logs) carries only CHECK(action IN
('created','approved','denied','revoked')) — so BOTH headline P5 features
crash with IntegrityError on the real schema. The T0/T1 fixtures hand-copied
a grant_logs DDL WITHOUT the CHECK, which is why the suite stayed green.

Pins:
- merge + set_grant_cards succeed end-to-end after a full boot (prod-shaped
  DB) and their audit rows land with the correct profile_id
- ensure_grant_log_actions heals an old-DDL table in place: row-preserving
  swap, DDL gains both actions, idempotent no-op once healed
"""
import hashlib
import os
import sys
from pathlib import Path

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
from whitelist_db import (
    wl_connect,
    ensure_whitelist_schema,
    merge_requester_into_contacts,
    set_grant_cards,
    create_card,
)

# The old production DDL — byte-for-byte what prod carried pre-heal.
_OLD_GRANT_LOGS_DDL = """
CREATE TABLE grant_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id TEXT NOT NULL,
    profile_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('created', 'approved', 'denied', 'revoked')),
    requested_expiry TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
)
"""


def _boot_fresh(tmp_path):
    """Full boot on a fresh file DB — the exact prod-shaped path.

    Prod boots both layers: store.init_db (contacts/... tables) then
    whitelist_db.ensure_whitelist_schema. Calling the real entry points
    keeps this fixture prod-equivalent by construction.
    """
    import store
    path = tmp_path / "audit.db"
    store.init_db(path)  # contacts + contact_sources + dedup_log
    conn = wl_connect(path)
    ensure_whitelist_schema(conn)
    return conn


def _seed_profile_and_grant(conn, handle="probe_owner"):
    conn.execute(
        "INSERT INTO profiles (handle, display_name) VALUES (?, ?)",
        (handle, "Probe Owner"),
    )
    pid = conn.execute("SELECT id FROM profiles WHERE handle=?", (handle,)).fetchone()[0]
    conn.execute(
        "INSERT INTO access_grants (id, profile_id, requester_email, status) "
        "VALUES ('g-audit', ?, 'probe@example.com', 'pending')",
        (pid,),
    )
    conn.commit()
    return pid


def _row_digest(conn):
    h = hashlib.sha256()
    for row in conn.execute("SELECT * FROM grant_logs ORDER BY id"):
        h.update(repr(row).encode())
    return h.hexdigest()


class TestMergeOnRealSchema:
    def test_merge_writes_merged_audit_row(self, tmp_path):
        conn = _boot_fresh(tmp_path)
        pid = _seed_profile_and_grant(conn)
        grant = {
            "id": "g-audit",
            "profile_id": pid,
            "requester_email": "newperson@example.com",
            "requester_name": "New Person",
        }
        result = merge_requester_into_contacts(conn, grant)  # used to raise IntegrityError
        assert result is not None
        logs = conn.execute(
            "SELECT profile_id FROM grant_logs WHERE action = 'merged'"
        ).fetchall()
        assert len(logs) == 1
        # Audit row must reference the granting profile, not a placeholder.
        assert logs[0]["profile_id"] == pid

    def test_merge_overwrite_path_writes_audit_row(self, tmp_path):
        conn = _boot_fresh(tmp_path)
        pid = _seed_profile_and_grant(conn)
        grant1 = {
            "id": "g-audit",
            "profile_id": pid,
            "requester_email": "same@example.com",
            "requester_name": "First Name",
        }
        merge_requester_into_contacts(conn, grant1)  # create
        merge_requester_into_contacts(conn, grant1)  # overwrite (idempotent)
        n = conn.execute(
            "SELECT COUNT(*) FROM grant_logs WHERE action = 'merged'"
        ).fetchone()[0]
        assert n == 2


class TestSetGrantCardsOnRealSchema:
    def test_set_grant_cards_writes_audit_row(self, tmp_path):
        conn = _boot_fresh(tmp_path)
        pid = _seed_profile_and_grant(conn)
        card = create_card(conn, pid, "Work", [])
        result = set_grant_cards(conn, "g-audit", [card["id"]])  # used to raise IntegrityError
        assert result is not None
        logs = conn.execute(
            "SELECT * FROM grant_logs WHERE action = 'cards_set' AND grant_id = 'g-audit'"
        ).fetchall()
        assert len(logs) == 1
        assert logs[0]["profile_id"] == pid


class TestEnsureGrantLogActions:
    def test_heals_old_ddl_in_place(self, tmp_path):
        conn = wl_connect(tmp_path / "heal.db")
        # Simulate the prod DB pre-heal: old DDL + one live audit row.
        conn.executescript(_OLD_GRANT_LOGS_DDL)
        conn.execute(
            "INSERT INTO grant_logs (grant_id, profile_id, action, requested_expiry) "
            "VALUES ('g-1', 7, 'approved', '90')"
        )
        conn.commit()  # prod boots over COMMITTED state — the heal must survive it
        before = _row_digest(conn)

        whitelist_db.ensure_grant_log_actions(conn)

        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='grant_logs'"
        ).fetchone()[0]
        assert "merged" in ddl and "cards_set" in ddl, "heal must extend the CHECK"
        # Row-preserving: the surviving row is byte-identical.
        assert _row_digest(conn) == before
        row = conn.execute("SELECT * FROM grant_logs").fetchone()
        assert (row["grant_id"], row["profile_id"], row["action"]) == ("g-1", 7, "approved")

    def test_heal_is_idempotent_no_op_when_current(self, tmp_path):
        conn = wl_connect(tmp_path / "idem.db")
        conn.executescript(_OLD_GRANT_LOGS_DDL)
        conn.execute(
            "INSERT INTO grant_logs (grant_id, profile_id, action) VALUES ('g-2', 1, 'created')"
        )
        conn.commit()

        whitelist_db.ensure_grant_log_actions(conn)
        seq_after_heal = conn.execute("SELECT seq FROM sqlite_sequence WHERE name='grant_logs'").fetchone()[0]
        # A second run on a healed table must not write (no sequence bump).
        whitelist_db.ensure_grant_log_actions(conn)
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='grant_logs'"
        ).fetchone()[0]
        assert "cards_set" in ddl
        seq_after_noop = conn.execute("SELECT seq FROM sqlite_sequence WHERE name='grant_logs'").fetchone()[0]
        assert seq_after_noop == seq_after_heal

    def test_fresh_boot_never_needs_heal(self, tmp_path):
        """Full boot on a fresh DB must produce the current DDL directly."""
        conn = _boot_fresh(tmp_path)
        ddl = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='grant_logs'"
        ).fetchone()[0]
        assert "merged" in ddl and "cards_set" in ddl
        conn.close()
