"""T3 — Template updates.

Tests pin:
- admin_review.html renders 'quarter' option in expiry select
- profile.html renders the stale badge (already exists, regression test)
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
    # Cache-busting global every template may use (?v=asset_v(...)) —
    # mirrors the production environment from app._make_jinja.
    from app import _static_version
    env.globals["asset_v"] = _static_version
    return env


# ============================================================
# admin_review.html — three-way decision (amber-box redesign)
# ============================================================

class TestAdminReviewTemplate:
    """admin_review.html carries the SAME three-way decision as the
    dashboard amber box: WhiteList / GreyList / BlackList, with row-by-row
    card checkboxes for the share choice (2026-09-26 redesign)."""

    def _render(self, env):
        tmpl = env.get_template("admin_review.html")
        return tmpl.render(
            profile={"display_name": "Test Owner", "handle": "testowner"},
            grant={
                "requester_name": "Test User",
                "requester_email": "test@example.com",
                "created_at": "2026-09-11T12:00:00Z",
            },
            token="test-token",
            cards=[{"id": 1, "name": "Personal", "photo_path": None},
                   {"id": 2, "name": "Work", "photo_path": None}],
            requester_bio="Hello, I make things.",
        )

    def test_three_way_decision_buttons(self, env):
        """White/Grey/Black buttons replace approve/deny + expiry select."""
        html = self._render(env)
        assert 'value="whitelist"' in html
        assert 'value="greylist"' in html
        assert 'value="blacklist"' in html
        assert "WhiteList" in html and "GreyList" in html and "BlackList" in html
        # The old expiry select is gone — the list choice IS the expiry.
        assert 'name="expiry"' not in html
        assert 'value="deny"' not in html

    def test_card_checkboxes_row_by_row(self, env):
        """Every owner card is a checkbox row (multi-select, required)."""
        html = self._render(env)
        assert 'name="card_ids" value="1"' in html
        assert 'name="card_ids" value="2"' in html
        assert 'Personal' in html and 'Work' in html
        assert html.count('type="checkbox"') == 2
        assert "Choose cards to share" in html

    def test_requester_bio_rendered(self, env):
        """The requester's bio shows when their profile has one."""
        html = self._render(env)
        assert "Hello, I make things." in html

    def test_bio_fallback_without_bio(self, env):
        """No bio in context → name + email still render, no crash."""
        tmpl = env.get_template("admin_review.html")
        html = tmpl.render(
            profile={"display_name": "Test Owner", "handle": "testowner"},
            grant={
                "requester_name": "Test User",
                "requester_email": "test@example.com",
                "created_at": "2026-09-11T12:00:00Z",
            },
            token="test-token",
            cards=[],
            requester_bio="",
        )
        assert "test@example.com" in html
        assert "Hello, I make things." not in html


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



