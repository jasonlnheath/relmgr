"""Quarterly rhythm — grey state, decision actions, and routes.

Tests:
- is_grey(): grey state detection
- mark_grey_pending_review(): boot-time grey marking
- get_grey_contacts() / get_grey_contacts_by_owner(): grey queries
- make_grant_permanent(): permanent decision
- punt_grant(): punt for another quarter
- ensure_access_grants_v3(): schema migration
- API routes: /quarter/make_permanent, /quarter/revoke, /quarter/punt
"""
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from whitelist_db import (
    wl_connect,
    ensure_whitelist_schema,
    ensure_access_grants_v3,
    seed_profile,
    create_grant,
    apply_decision,
    set_grant_cards,
    revoke_grant,
    is_grey,
    mark_grey_pending_review,
    get_grey_contacts,
    get_grey_contacts_by_owner,
    get_grey_contact_count,
    make_grant_permanent,
    punt_grant,
    _now_iso,
    quarter_end_iso,
)


@pytest.fixture
def db():
    """Fresh DB with full schema + profile + cards."""
    db_path = Path(__file__).parent / "test_quarterly_rhythm.db"
    if db_path.exists():
        db_path.unlink()
    conn = wl_connect(db_path)
    ensure_whitelist_schema(conn)
    seed_profile(conn, {
        "handle": "testowner",
        "name": {"display": "Test Owner"},
        "emails": [{"address": "owner@test.com", "visibility": "granted"}],
        "phones": [{"number": "555-0000", "visibility": "granted"}],
    })
    conn.commit()

    owner_id = conn.execute(
        "SELECT id FROM profiles WHERE handle = 'testowner'"
    ).fetchone()["id"]

    email_field_id = conn.execute(
        "SELECT id FROM profile_fields WHERE profile_id = ? AND field_type = 'email'",
        (owner_id,),
    ).fetchone()["id"]

    work_id = conn.execute(
        "INSERT INTO cards (owner_profile_id, name, created_at, updated_at) VALUES (?, 'Work', datetime('now'), datetime('now'))",
        (owner_id,),
    ).lastrowid
    conn.execute("INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)", (work_id, email_field_id))
    conn.commit()

    return conn, owner_id, work_id


# ============================================================
# is_grey tests
# ============================================================

class TestIsGrey:
    def test_granted_not_expired_not_grey(self, db):
        """Live quarter grant is not grey."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant is not None
        assert is_grey(dict(grant)) is False
        conn.close()

    def test_lifetime_not_grey(self, db):
        """Lifetime grant is never grey."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "lifetime")
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert is_grey(dict(grant)) is False
        conn.close()

    def test_expired_pending_review_is_grey(self, db):
        """Expired grant with quarter_status='pending_review' is grey."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z', quarter_status = 'pending_review' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert is_grey(dict(grant)) is True
        conn.close()

    def test_expired_active_is_grey_derived(self, db):
        """Expired grant with quarter_status='active' is grey (derived state)."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert is_grey(dict(grant)) is True
        conn.close()

    def test_expired_punted_is_not_grey(self, db):
        """Expired grant with punted is NOT grey (owner just punted)."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z', quarter_status = 'punted' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert is_grey(dict(grant)) is False
        conn.close()

    def test_denied_not_grey(self, db):
        """Denied grant is not grey."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "deny", "90")
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert is_grey(dict(grant)) is False
        conn.close()

    def test_revoked_not_grey(self, db):
        """Revoked grant is not grey."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        revoke_grant(conn, gid)
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert is_grey(dict(grant)) is False
        conn.close()


# ============================================================
# mark_grey_pending_review tests
# ============================================================

class TestMarkGreyPendingReview:
    def test_marks_expired_quarter_grants(self, db):
        """Expired quarter grants get quarter_status = 'pending_review'."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        # Expire the grant
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()

        count = mark_grey_pending_review(conn, owner_id)
        assert count == 1

        grant = conn.execute("SELECT quarter_status FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant["quarter_status"] == "pending_review"
        conn.close()

    def test_skips_live_grants(self, db):
        """Live quarter grants are not marked pending_review."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        # Grant is live (expires_at is in the future)
        count = mark_grey_pending_review(conn, owner_id)
        assert count == 0
        conn.close()

    def test_skips_lifetime_grants(self, db):
        """Lifetime grants are not marked pending_review."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "lifetime")
        count = mark_grey_pending_review(conn, owner_id)
        assert count == 0
        conn.close()

    def test_marks_null_quarter_status(self, db):
        """NULL quarter_status expired grants are also marked pending_review."""
        conn, owner_id, _ = db
        # 14-day grant gets quarter_status=NULL
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "14")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        count = mark_grey_pending_review(conn, owner_id)
        assert count == 1
        grant = conn.execute("SELECT quarter_status FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant["quarter_status"] == "pending_review"
        conn.close()


# ============================================================
# get_grey_contacts / get_grey_contacts_by_owner tests
# ============================================================

class TestGetGreyContacts:
    def test_returns_grey_contacts(self, db):
        """Returns grey contacts with profile info (derived: expired + not_punted)."""
        conn, owner_id, _ = db

        gid = create_grant(conn, owner_id, "grey@test.com", "Grey User")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()

        grey = get_grey_contacts(conn)
        assert len(grey) == 1
        assert grey[0]["requester_email"] == "grey@test.com"
        assert grey[0]["profile_handle"] == "testowner"
        conn.close()

    def test_excludes_live_grants(self, db):
        """Live quarter grants are not returned."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "live@test.com", "Live User")
        apply_decision(conn, gid, "approve", "quarter")
        conn.commit()

        grey = get_grey_contacts(conn)
        assert len(grey) == 0
        conn.close()

    def test_excludes_lifetime_grants(self, db):
        """Lifetime grants are not returned."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "perm@test.com", "Perm User")
        apply_decision(conn, gid, "approve", "lifetime")
        conn.commit()

        grey = get_grey_contacts(conn)
        assert len(grey) == 0
        conn.close()

    def test_excludes_punted_grants(self, db):
        """Punted grants are not grey (owner just punted)."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "punted@test.com", "Punted User")
        apply_decision(conn, gid, "approve", "quarter")
        punt_grant(conn, gid)
        conn.commit()

        grey = get_grey_contacts(conn)
        assert len(grey) == 0
        conn.close()


class TestGetGreyContactsByOwner:
    def test_groups_by_owner(self, db):
        """Returns dict mapping profile_id -> list of grey contacts (derived)."""
        conn, owner_id, _ = db

        for i in range(3):
            gid = create_grant(conn, owner_id, f"grey{i}@test.com", f"Grey User {i}")
            apply_decision(conn, gid, "approve", "quarter")
            conn.execute(
                "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
                (gid,),
            )
        conn.commit()

        by_owner = get_grey_contacts_by_owner(conn)
        assert owner_id in by_owner
        assert len(by_owner[owner_id]) == 3
        conn.close()


class TestGetGreyContactCount:
    def test_counts_grey_contacts(self, db):
        """Returns correct count for a profile (derived: expired + not_punted)."""
        conn, owner_id, _ = db

        for i in range(2):
            gid = create_grant(conn, owner_id, f"grey{i}@test.com", f"Grey User {i}")
            apply_decision(conn, gid, "approve", "quarter")
            conn.execute(
                "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
                (gid,),
            )
        conn.commit()

        count = get_grey_contact_count(conn, owner_id)
        assert count == 2
        conn.close()


# ============================================================
# make_grant_permanent tests
# ============================================================

class TestMakeGrantPermanent:
    def test_makes_grant_permanent(self, db):
        """Sets expires_at = NULL, quarter_status = NULL."""
        conn, owner_id, _ = db

        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()

        result = make_grant_permanent(conn, gid)
        assert result is not None
        assert result["expires_at"] is None
        assert result["quarter_status"] is None
        assert result["last_reviewed_at"] is not None

        # Verify audit log
        logs = conn.execute(
            "SELECT action FROM grant_logs WHERE grant_id = ?", (gid,)
        ).fetchall()
        actions = [r["action"] for r in logs]
        assert "permanent" in actions
        conn.close()

    def test_raises_on_non_granted(self, db):
        """Raises ValueError on denied grant."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "deny", "90")
        conn.commit()

        with pytest.raises(ValueError):
            make_grant_permanent(conn, gid)
        conn.close()

    def test_returns_none_for_unknown(self, db):
        """Returns None for unknown grant id."""
        conn, owner_id, _ = db
        assert make_grant_permanent(conn, "nonexistent") is None
        conn.close()


# ============================================================
# punt_grant tests
# ============================================================

class TestPuntGrant:
    def test_extends_to_next_quarter(self, db):
        """Extends expires_at to next quarter end, sets quarter_status = 'punted'."""
        conn, owner_id, _ = db

        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()

        result = punt_grant(conn, gid)
        assert result is not None
        assert result["quarter_status"] == "punted"
        assert result["expires_at"] is not None
        assert result["last_reviewed_at"] is not None
        # expires_at should be the next quarter end
        expected_qe = quarter_end_iso()
        assert result["expires_at"] == expected_qe

        # Verify audit log
        logs = conn.execute(
            "SELECT action FROM grant_logs WHERE grant_id = ?", (gid,)
        ).fetchall()
        actions = [r["action"] for r in logs]
        assert "punted" in actions
        conn.close()

    def test_raises_on_non_granted(self, db):
        """Raises ValueError on denied grant."""
        conn, owner_id, _ = db
        gid = create_grant(conn, owner_id, "a@test.com", "A")
        apply_decision(conn, gid, "deny", "90")
        conn.commit()

        with pytest.raises(ValueError):
            punt_grant(conn, gid)
        conn.close()

    def test_returns_none_for_unknown(self, db):
        """Returns None for unknown grant id."""
        conn, owner_id, _ = db
        assert punt_grant(conn, "nonexistent") is None
        conn.close()


# ============================================================
# ensure_access_grants_v3 migration tests
# ============================================================

class TestEnsureAccessGrantsV3:
    def test_adds_columns(self):
        """Adds quarter_status and last_reviewed_at columns."""
        db_path = Path(__file__).parent / "test_v3_migrate.db"
        if db_path.exists():
            db_path.unlink()
        conn = wl_connect(db_path)
        ensure_whitelist_schema(conn)

        cols = [r["name"] for r in conn.execute("PRAGMA table_info(access_grants)")]
        assert "quarter_status" in cols
        assert "last_reviewed_at" in cols
        conn.close()

    def test_idempotent(self):
        """Running twice doesn't crash or duplicate columns."""
        db_path = Path(__file__).parent / "test_v3_idem.db"
        if db_path.exists():
            db_path.unlink()
        conn = wl_connect(db_path)
        ensure_whitelist_schema(conn)
        ensure_access_grants_v3(conn)

        cols = [r["name"] for r in conn.execute("PRAGMA table_info(access_grants)")]
        assert cols.count("quarter_status") == 1
        conn.close()

    def test_seeds_active_on_existing_quarter_grants(self):
        """Existing quarter grants get quarter_status = 'active'."""
        db_path = Path(__file__).parent / "test_v3_seed.db"
        if db_path.exists():
            db_path.unlink()
        conn = wl_connect(db_path)
        ensure_whitelist_schema(conn)

        # Create a quarter grant before migration
        seed_profile(conn, {
            "handle": "oldowner",
            "name": {"display": "Old Owner"},
            "emails": [{"address": "old@test.com", "visibility": "granted"}],
        })
        owner_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = 'oldowner'"
        ).fetchone()["id"]
        gid = create_grant(conn, owner_id, "old@test.com", "Old")
        apply_decision(conn, gid, "approve", "quarter")
        conn.commit()

        # Now run migration
        ensure_access_grants_v3(conn)

        qs = conn.execute(
            "SELECT quarter_status FROM access_grants WHERE id = ?", (gid,)
        ).fetchone()
        assert qs["quarter_status"] == "active"
        conn.close()


# ============================================================
# API route tests
# ============================================================

class TestQuarterRoutes:
    """Test the /owner/{token}/quarter/ routes."""

    def test_make_permanent_route(self):
        """POST /quarter/make_permanent makes a grey grant permanent."""
        from whitelist_db import wl_connect, ensure_whitelist_schema, seed_profile, create_grant, apply_decision
        from app import create_app
        import wl_tokens

        test_db = Path(__file__).parent / "test_route_perm.db"
        if test_db.exists():
            test_db.unlink()

        os.environ["RELMGR_DB_PATH"] = str(test_db)

        test_app = create_app(test_db)
        from starlette.testclient import TestClient
        client = TestClient(test_app)

        # Seed data
        conn = wl_connect(test_db)
        ensure_whitelist_schema(conn)
        seed_profile(conn, {
            "handle": "testowner",
            "name": {"display": "Test Owner"},
            "emails": [{"address": "owner@test.com", "visibility": "granted"}],
        })
        owner_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = 'testowner'"
        ).fetchone()["id"]

        gid = create_grant(conn, owner_id, "grey@test.com", "Grey User")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        conn.close()

        # Make permanent
        owner_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", str(owner_id), expires_days=365)
        resp = client.post(f"/owner/{owner_token}/quarter/make_permanent",
                          data={"grant_id": gid})
        assert resp.status_code == 200

        # Verify grant is permanent
        conn = wl_connect(test_db)
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant["expires_at"] is None
        assert grant["quarter_status"] is None
        conn.close()

        # Clean up
        test_db.unlink()

    def test_revoke_route(self):
        """POST /quarter/revoke revokes a grey grant."""
        from whitelist_db import wl_connect, ensure_whitelist_schema, seed_profile, create_grant, apply_decision
        from app import create_app
        import wl_tokens

        test_db = Path(__file__).parent / "test_route_revoke.db"
        if test_db.exists():
            test_db.unlink()

        os.environ["RELMGR_DB_PATH"] = str(test_db)
        test_app = create_app(test_db)
        from starlette.testclient import TestClient
        client = TestClient(test_app)

        conn = wl_connect(test_db)
        ensure_whitelist_schema(conn)
        seed_profile(conn, {
            "handle": "testowner",
            "name": {"display": "Test Owner"},
            "emails": [{"address": "owner@test.com", "visibility": "granted"}],
        })
        owner_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = 'testowner'"
        ).fetchone()["id"]

        gid = create_grant(conn, owner_id, "grey@test.com", "Grey User")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        conn.close()

        owner_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", str(owner_id), expires_days=365)
        resp = client.post(f"/owner/{owner_token}/quarter/revoke",
                          data={"grant_id": gid})
        assert resp.status_code == 200

        conn = wl_connect(test_db)
        grant = conn.execute("SELECT status FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant["status"] == "revoked"
        conn.close()

        test_db.unlink()

    def test_punt_route(self):
        """POST /quarter/punt extends a grey grant for another quarter."""
        from whitelist_db import wl_connect, ensure_whitelist_schema, seed_profile, create_grant, apply_decision
        from app import create_app
        import wl_tokens

        test_db = Path(__file__).parent / "test_route_punt.db"
        if test_db.exists():
            test_db.unlink()

        os.environ["RELMGR_DB_PATH"] = str(test_db)
        test_app = create_app(test_db)
        from starlette.testclient import TestClient
        client = TestClient(test_app)

        conn = wl_connect(test_db)
        ensure_whitelist_schema(conn)
        seed_profile(conn, {
            "handle": "testowner",
            "name": {"display": "Test Owner"},
            "emails": [{"address": "owner@test.com", "visibility": "granted"}],
        })
        owner_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = 'testowner'"
        ).fetchone()["id"]

        gid = create_grant(conn, owner_id, "grey@test.com", "Grey User")
        apply_decision(conn, gid, "approve", "quarter")
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,),
        )
        conn.commit()
        conn.close()

        owner_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", str(owner_id), expires_days=365)
        resp = client.post(f"/owner/{owner_token}/quarter/punt",
                          data={"grant_id": gid})
        assert resp.status_code == 200

        conn = wl_connect(test_db)
        grant = conn.execute("SELECT quarter_status, expires_at FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant["quarter_status"] == "punted"
        assert grant["expires_at"] is not None
        conn.close()

        test_db.unlink()

    def test_403_on_invalid_token(self):
        """Invalid token returns 403."""
        from app import create_app
        from starlette.testclient import TestClient
        test_db = Path(__file__).parent / "test_route_403.db"
        if test_db.exists():
            test_db.unlink()
        test_app = create_app(test_db)
        client = TestClient(test_app)
        resp = client.post("/owner/invalidtoken/quarter/make_permanent",
                          data={"grant_id": "some-id"})
        assert resp.status_code == 403
        if test_db.exists():
            test_db.unlink()
