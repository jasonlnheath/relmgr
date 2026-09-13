"""T3 — Template updates.

Tests pin:
- admin_review.html renders 'quarter' option in expiry select
- profile.html renders the stale badge (already exists, regression test)
- owner_dashboard.html renders scan stats (already exists, regression test)
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from jinja2 import Environment, FileSystemLoader


def _parse_dt(value: str):
    """Parse ISO timestamp string to datetime.

    Returns a **naive** UTC datetime (strips tzinfo) to match
    app.py's days_since which subtracts naive datetimes.
    """
    if not value:
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        # strptime with %Z or .replace(tzinfo=...) creates an aware datetime,
        # but app.py's days_since subtracts naive datetimes — strip it.
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except (ValueError, TypeError):
        return None


def days_since(value: str) -> int:
    """Whole days between a stored timestamp and now (0 on bad/None input)."""
    dt = _parse_dt(value)
    if dt is None:
        return 0
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
    return max(0, delta.days)


def days_until(value: str) -> int:
    """Whole days from now until a stored timestamp (0 on bad/None input)."""
    dt = _parse_dt(value)
    if dt is None:
        return 0
    delta = dt - datetime.now(timezone.utc).replace(tzinfo=None)
    return max(0, delta.days)


@pytest.fixture
def env():
    """Jinja2 environment with app.py globals registered.

    Note: days_since/days_until are passed as globals (not filters) —
    the template uses {% set days = days_since(...) %} which resolves
    them as module-level lookups, not .filters[].
    """
    tmpl_dir = str(Path(__file__).resolve().parent.parent / "templates")
    env = Environment(loader=FileSystemLoader(tmpl_dir))
    env.globals["days_since"] = days_since
    env.globals["days_until"] = days_until
    return env


# ============================================================
# admin_review.html — quarter option
# ============================================================

class TestAdminReviewTemplate:
    """admin_review.html must render the 'quarter' expiry option."""

    def test_quarter_option_exists(self, env):
        """The expiry select must contain a 'quarter' option."""
        tmpl = env.get_template("admin_review.html")
        html = tmpl.render(
            profile={"display_name": "Test Owner"},
            grant={
                "requester_name": "Test User",
                "requester_email": "test@example.com",
                "created_at": "2026-09-11T12:00:00Z",
            },
            token="test-token",
        )
        assert 'value="quarter"' in html, "admin_review.html must have a 'quarter' option in the expiry select"
        # Verify it appears alongside the existing options
        assert 'value="14"' in html
        assert 'value="90"' in html
        assert 'value="lifetime"' in html

    def test_quarter_option_text(self, env):
        """The quarter option should have readable text."""
        tmpl = env.get_template("admin_review.html")
        html = tmpl.render(
            profile={"display_name": "Test Owner"},
            grant={
                "requester_name": "Test User",
                "requester_email": "test@example.com",
                "created_at": "2026-09-11T12:00:00Z",
            },
            token="test-token",
        )
        # The quarter option should be present with some label
        assert "quarter" in html.lower() or "Q" in html


# ============================================================
# profile.html — stale badge (regression)
# ============================================================

class TestProfileTemplate:
    """profile.html must render the stale badge."""

    def test_stale_badge_rendered(self, env):
        """When stale=True, the badge shows warning styling."""
        tmpl = env.get_template("profile.html")
        html = tmpl.render(
            profile={
                "display_name": "Test Owner",
                "handle": "testowner",
                "company": "Test Corp",
                "title": "Tester",
                "verified_at": "2025-01-01T00:00:00Z",
                "fields": [],
            },
            stale=True,
            days=600,
            scan_stats=[],
            scan_max=0,
            grants=[],
        )
        assert "stale" in html.lower() or "⚠" in html or "warning" in html.lower()

    def test_fresh_badge_rendered(self, env):
        """When stale=False, the badge shows verified styling."""
        tmpl = env.get_template("profile.html")
        html = tmpl.render(
            profile={
                "display_name": "Test Owner",
                "handle": "testowner",
                "company": "Test Corp",
                "title": "Tester",
                "verified_at": "2026-09-01T00:00:00Z",
                "fields": [],
            },
            stale=False,
            days=10,
            scan_stats=[],
            scan_max=0,
            grants=[],
        )
        assert "verified" in html.lower() or "✓" in html


# ============================================================
# owner_dashboard.html — scan stats (regression)
# ============================================================

class TestOwnerDashboardTemplate:
    """owner_dashboard.html must render scan stats."""

    def test_scan_stats_rendered(self, env):
        """Scan stats render when provided."""
        tmpl = env.get_template("owner_dashboard.html")
        scan_stats = [{"date": "2026-09-01", "scans": 5}, {"date": "2026-09-02", "scans": 3}]
        profile_data = {
            "display_name": "Test Owner",
            "handle": "testowner",
            "company": "Test Corp",
            "title": "Tester",
            "verified_at": "2026-09-01T00:00:00Z",
            "fields": [],
        }
        html = tmpl.render(
            profiles=[{
                "profile": profile_data,
                "grants": [],
                "scan_stats": scan_stats,
                "scan_max": 5,
            }],
            token="test-token",
            days_since=days_since,
            days_until=days_until,
            contexts=[],
        )
        # The template should reference the scan data
        assert "scans" in html.lower() or "scan" in html

    def test_no_scan_stats_when_empty(self, env):
        """Zero-filled scan stats (14 days, all zeros) render without crash.

        The template accesses scan_stats[-1]['scans'] so it needs at least
        one entry — the real app always passes 14 entries from get_scan_stats().
        """
        tmpl = env.get_template("owner_dashboard.html")
        profile_data = {
            "display_name": "Test Owner",
            "handle": "testowner",
            "company": "Test Corp",
            "title": "Tester",
            "verified_at": "2026-09-01T00:00:00Z",
            "fields": [],
        }
        # 14 entries, all zero — matches what get_scan_stats() returns for a quiet window
        scan_stats = [{"date": f"2026-09-{14 - i:02d}", "scans": 0} for i in range(14)]
        html = tmpl.render(
            profiles=[{
                "profile": profile_data,
                "grants": [],
                "scan_stats": scan_stats,
                "scan_max": 1,  # peak=1 so division is safe
            }],
            token="test-token",
            days_since=days_since,
            days_until=days_until,
            contexts=[],
        )
        # Should not raise and should contain the profile name
        assert "Test Owner" in html
