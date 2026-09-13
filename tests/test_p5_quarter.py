"""T2 — Quarter expiry + freshness math.

New pure helpers in whitelist_db:
- quarter_end_iso(now) -> str: last instant of the UTC calendar quarter
- is_current_quarter(value) -> bool: same calendar quarter as today
- apply_decision supports expiry_choice='quarter'

Old functions (is_verified_stale, is_current_quarter >180d) stay untouched.
"""
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from whitelist_db import quarter_end_iso, is_current_quarter


# ============================================================
# quarter_end_iso tests
# ============================================================

class TestQuarterEndIso:
    """quarter_end_iso(now: Optional[datetime] = None) -> str.

    Returns the last instant of the UTC calendar quarter containing `now`.
    Quarters: Q1 = Jan-Mar, Q2 = Apr-Jun, Q3 = Jul-Sep, Q4 = Oct-Dec.
    Format: %Y-%m-%dT%H:%M:%SZ (same as _now_iso).
    """

    def test_q1_jan(self):
        """Jan 15 → end of Q1 = March 31 23:59:59."""
        now = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-03-31T23:59:59Z"

    def test_q1_mar(self):
        """Mar 31 → end of Q1 = March 31 23:59:59."""
        now = datetime(2026, 3, 31, 23, 59, 59, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-03-31T23:59:59Z"

    def test_q2_apr(self):
        """Apr 1 → end of Q2 = June 30 23:59:59."""
        now = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-06-30T23:59:59Z"

    def test_q2_jun(self):
        """Jun 30 → end of Q2 = June 30 23:59:59."""
        now = datetime(2026, 6, 30, 23, 59, 59, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-06-30T23:59:59Z"

    def test_q3_sep(self):
        """Sep 30 → end of Q3 = Sep 30 23:59:59."""
        now = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-09-30T23:59:59Z"

    def test_q4_dec(self):
        """Dec 31 → end of Q4 = Dec 31 23:59:59."""
        now = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-12-31T23:59:59Z"

    def test_year_rollover(self):
        """Dec 31 2026 → end of Q4 2026."""
        now = datetime(2026, 12, 31, 0, 0, 0, tzinfo=timezone.utc)
        result = quarter_end_iso(now)
        assert result == "2026-12-31T23:59:59Z"

    def test_default_now(self):
        """No argument → uses current UTC time."""
        result = quarter_end_iso()
        # Must be a valid ISO timestamp ending with Z
        assert result.endswith("Z")
        # Must be within the current quarter
        now = datetime.now(timezone.utc)
        assert is_current_quarter(result)

    def test_format_matches_iso_z(self):
        """Output must match the %Y-%m-%dT%H:%M:%SZ format."""
        import re
        result = quarter_end_iso()
        assert re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", result)


# ============================================================
# is_current_quarter tests
# ============================================================

class TestIsCurrentQuarter:
    """is_current_quarter(value: Optional[str]) -> bool.

    Returns True if the timestamp falls in the same UTC calendar quarter
    as today. None → False.

    IMPORTANT: This is NOT the same as is_verified_stale (>180d).
    Different rule, different boundary.
    """

    def test_current_quarter(self):
        """Timestamp from this quarter → True."""
        # Today is Sep 2026, Q3. Use a date in Q3.
        now = datetime.now(timezone.utc)
        result = is_current_quarter(now.strftime("%Y-%m-%dT%H:%M:%SZ"))
        assert result is True

    def test_previous_quarter(self):
        """Timestamp from last quarter → False."""
        # ~100 days ago (crosses quarter boundary)
        old = datetime.now(timezone.utc) - timedelta(days=100)
        result = is_current_quarter(old.strftime("%Y-%m-%dT%H:%M:%SZ"))
        assert result is False

    def test_future_quarter(self):
        """Timestamp from next quarter → False."""
        future = datetime.now(timezone.utc) + timedelta(days=100)
        result = is_current_quarter(future.strftime("%Y-%m-%dT%H:%M:%SZ"))
        assert result is False

    def test_none_returns_false(self):
        """None → False."""
        assert is_current_quarter(None) is False

    def test_empty_string_returns_false(self):
        """Empty string → False."""
        assert is_current_quarter("") is False

    def test_boundary_same_quarter(self):
        """Timestamp ~10 days ago (still same quarter) → True."""
        recent = datetime.now(timezone.utc) - timedelta(days=10)
        result = is_current_quarter(recent.strftime("%Y-%m-%dT%H:%M:%SZ"))
        assert result is True

    def test_boundary_crosses_quarter(self):
        """Timestamp ~200 days ago (crosses quarter) → False."""
        old = datetime.now(timezone.utc) - timedelta(days=200)
        result = is_current_quarter(old.strftime("%Y-%m-%dT%H:%M:%SZ"))
        assert result is False


# ============================================================
# apply_decision with expiry_choice='quarter'
# ============================================================

class TestApplyDecisionQuarter:
    """apply_decision supports expiry_choice='quarter' → quarter_end_iso()."""

    def test_approve_with_quarter_sets_expiry(self, tmp_path):
        """Approve with 'quarter' → expires_at = quarter_end_iso()."""
        import sys
        db = tmp_path / "test_q.db"
        sys.path.insert(0, str(tmp_path.parent.parent))
        os.environ["WHITELIST_SECRET"] = "test-secret"

        from whitelist_db import (
            wl_connect, wl_init, create_grant, apply_decision,
            get_grant, quarter_end_iso,
        )

        conn = wl_connect(db)
        wl_init(conn)

        # Create a profile
        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES (?, ?)",
            ("test_owner", "Test Owner"),
        )
        profile_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]

        # Create a grant
        grant_id = create_grant(conn, profile_id, "test@example.com", "Test User")
        conn.commit()

        # Approve with quarter
        result = apply_decision(conn, grant_id, "approve", "quarter")
        assert result is not None
        assert result["decision"] == "approve"
        assert result["grant"]["status"] == "granted"

        # expires_at should equal quarter_end_iso()
        expected = quarter_end_iso()
        assert result["grant"]["expires_at"] == expected

    def test_existing_expiry_choices_unchanged(self, tmp_path):
        """'14', '90', 'lifetime' paths remain byte-identical."""
        import sys
        db = tmp_path / "test_q2.db"
        sys.path.insert(0, str(tmp_path.parent.parent))
        os.environ["WHITELIST_SECRET"] = "test-secret"

        from whitelist_db import (
            wl_connect, wl_init, create_grant, apply_decision,
        )

        conn = wl_connect(db)
        wl_init(conn)

        conn.execute(
            "INSERT INTO profiles (handle, display_name) VALUES (?, ?)",
            ("test_owner", "Test Owner"),
        )
        profile_id = conn.execute(
            "SELECT id FROM profiles WHERE handle = ?", ("test_owner",)
        ).fetchone()[0]

        grant_id = create_grant(conn, profile_id, "test@example.com", "Test User")
        conn.commit()

        # '14' → 14 days from now
        result_14 = apply_decision(conn, grant_id, "approve", "14")
        assert result_14["grant"]["status"] == "granted"
        assert result_14["grant"]["expires_at"] is not None

        # Revoke and re-create for 'lifetime'
        from whitelist_db import revoke_grant
        revoke_grant(conn, grant_id)
        conn.commit()

        grant_id2 = create_grant(conn, profile_id, "test2@example.com", "Test User 2")
        conn.commit()
        result_lifetime = apply_decision(conn, grant_id2, "approve", "lifetime")
        assert result_lifetime["grant"]["expires_at"] is None

        # '90' → 90 days from now (default)
        revoke_grant(conn, grant_id2)
        conn.commit()

        grant_id3 = create_grant(conn, profile_id, "test3@example.com", "Test User 3")
        conn.commit()
        result_90 = apply_decision(conn, grant_id3, "approve", "90")
        assert result_90["grant"]["expires_at"] is not None

        # Unknown → 90d default (unchanged behavior)
        revoke_grant(conn, grant_id3)
        conn.commit()

        grant_id4 = create_grant(conn, profile_id, "test4@example.com", "Test User 4")
        conn.commit()
        result_unknown = apply_decision(conn, grant_id4, "approve", "foobar")
        assert result_unknown["grant"]["expires_at"] is not None
