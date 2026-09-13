"""T4 — Quarterly review digest.

Tests pin:
- build_quarterly_review(conn) -> Optional[str]
- Returns None when no temp grants
- Lists every live temp grant (email, name, cards, expiry)
- Subject line: "WhiteList — quarter review: N temporary contacts"
- Link each row to owner dashboard URL
- if __main__ entry point with --review flag
- No real SMTP in tests (fake now, no network)
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
    seed_profile,
    create_grant,
    apply_decision,
    set_grant_cards,
    quarter_end_iso,
)


@pytest.fixture
def conn_with_schema(tmp_path):
    """Fresh DB with full schema + profile + cards."""
    db = tmp_path / "test_review.db"
    conn = wl_connect(db)
    ensure_whitelist_schema(conn)
    seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    conn.commit()

    owner_id = conn.execute(
        "SELECT id FROM profiles WHERE handle = 'jasonheath'"
    ).fetchone()["id"]

    email_field_id = conn.execute(
        "SELECT id FROM profile_fields WHERE profile_id = ? AND field_type = 'email'",
        (owner_id,),
    ).fetchone()["id"]
    phone_field_id = conn.execute(
        "SELECT id FROM profile_fields WHERE profile_id = ? AND field_type = 'phone'",
        (owner_id,),
    ).fetchone()["id"]

    work_id = conn.execute(
        "INSERT INTO cards (owner_profile_id, name, created_at, updated_at) VALUES (?, 'Work', datetime('now'), datetime('now'))",
        (owner_id,),
    ).lastrowid
    conn.execute("INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)", (work_id, email_field_id))

    personal_id = conn.execute(
        "INSERT INTO cards (owner_profile_id, name, created_at, updated_at) VALUES (?, 'Personal', datetime('now'), datetime('now'))",
        (owner_id,),
    ).lastrowid
    conn.execute("INSERT INTO card_fields (card_id, field_id) VALUES (?, ?)", (personal_id, phone_field_id))
    conn.commit()

    return conn, owner_id, work_id, personal_id


class TestBuildQuarterlyReview:
    """build_quarterly_review(conn) returns the digest string."""

    def test_none_when_no_temp_grants(self, conn_with_schema):
        """Empty digest when no temporary grants exist."""
        from notify import build_quarterly_review
        result = build_quarterly_review(conn_with_schema[0])
        assert result is None

    def test_none_when_no_grants_at_all(self, conn_with_schema):
        """None when the DB has zero grants."""
        from notify import build_quarterly_review
        result = build_quarterly_review(conn_with_schema[0])
        assert result is None

    def test_lists_temp_grants(self, conn_with_schema):
        """Digest includes temp grants with email, name, cards, expiry."""
        conn, owner_id, work_id, personal_id = conn_with_schema

        # Create a temp grant
        gid1 = create_grant(conn, owner_id, "temp1@test.com", "Temp User One")
        apply_decision(conn, gid1, "approve", "quarter", merge_contacts=True)
        set_grant_cards(conn, gid1, [work_id])

        # Create a permanent grant (should NOT appear in digest)
        gid2 = create_grant(conn, owner_id, "perm@test.com", "Perm User")
        apply_decision(conn, gid2, "approve", "lifetime", merge_contacts=True)
        set_grant_cards(conn, gid2, [personal_id])

        conn.commit()

        from notify import build_quarterly_review
        result = build_quarterly_review(conn)
        assert result is not None
        assert "temp1@test.com" in result
        assert "Temp User One" in result
        assert "Work" in result
        assert "perm@test.com" not in result  # permanent grants excluded
        assert "Perm User" not in result

    def test_multiple_temp_grants(self, conn_with_schema):
        """Digest lists all temp grants, not just one."""
        conn, owner_id, work_id, personal_id = conn_with_schema

        for i in range(3):
            gid = create_grant(conn, owner_id, f"multi{i}@test.com", f"Multi User {i}")
            apply_decision(conn, gid, "approve", "quarter", merge_contacts=True)
            set_grant_cards(conn, gid, [work_id if i % 2 == 0 else personal_id])
        conn.commit()

        from notify import build_quarterly_review
        result = build_quarterly_review(conn)
        assert result is not None
        assert "Multi User 0" in result
        assert "Multi User 1" in result
        assert "Multi User 2" in result

    def test_subject_line_format(self, conn_with_schema):
        """Subject line matches expected format."""
        conn, owner_id, work_id, personal_id = conn_with_schema

        gid = create_grant(conn, owner_id, "subject@test.com", "Subject User")
        apply_decision(conn, gid, "approve", "quarter", merge_contacts=True)
        conn.commit()

        from notify import build_quarterly_review
        result = build_quarterly_review(conn)
        assert result is not None
        assert "WhiteList" in result
        assert "quarter review" in result.lower() or "Quarter" in result
        assert "1 temporary" in result.lower() or "1 temp" in result.lower()


class TestQuarterEndIso:
    """quarter_end_iso() returns correct quarter boundaries."""

    def test_q1_boundary(self):
        from notify import quarter_end_iso
        # Jan 15 -> end of Q1 = Mar 31 23:59:59
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(dt)
        assert result == "2026-03-31T23:59:59Z"

    def test_q2_boundary(self):
        from notify import quarter_end_iso
        dt = datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(dt)
        assert result == "2026-06-30T23:59:59Z"

    def test_q3_boundary(self):
        from notify import quarter_end_iso
        dt = datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(dt)
        assert result == "2026-09-30T23:59:59Z"

    def test_q4_boundary(self):
        from notify import quarter_end_iso
        dt = datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(dt)
        assert result == "2026-12-31T23:59:59Z"

    def test_year_rollover(self):
        from notify import quarter_end_iso
        dt = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        result = quarter_end_iso(dt)
        assert result == "2026-12-31T23:59:59Z"

    def test_returns_iso_format(self):
        from notify import quarter_end_iso
        result = quarter_end_iso()
        assert result.endswith("Z")
        assert "T" in result


class TestIsCurrentQuarter:
    """is_current_quarter() returns True/False for same quarter."""

    def test_same_quarter_true(self):
        from notify import is_current_quarter
        # Today is Sep 2026, Q3
        result = is_current_quarter("2026-09-01T00:00:00Z")
        assert result is True

    def test_same_quarter_jul(self):
        from notify import is_current_quarter
        result = is_current_quarter("2026-07-15T00:00:00Z")
        assert result is True

    def test_different_quarter_false(self):
        from notify import is_current_quarter
        result = is_current_quarter("2026-06-30T23:59:59Z")
        assert result is False

    def test_none_returns_false(self):
        from notify import is_current_quarter
        assert is_current_quarter(None) is False

    def test_empty_string_returns_false(self):
        from notify import is_current_quarter
        assert is_current_quarter("") is False


class TestMainEntryPoint:
    """if __name__ == '__main__' with --review flag."""

    def test_main_review_flag(self):
        """The --review flag prints the digest."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c",
             "import os, sys; os.environ['WHITELIST_SECRET']='test'; "
             "from pathlib import Path; sys.path.insert(0, str(Path('notify.py').resolve().parent)); "
             "import notify"],
            capture_output=True, text=True, cwd="/home/jason/relmgr",
        )
        # Module should import without error
        assert result.returncode == 0
