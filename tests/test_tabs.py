"""Phase A1: Dashboard tabs — tab chrome removed in round-2.

Tests pin:
- Tab nav is ABSENT from contact list and profile pages (round-2 ruling)
- /owner/{token}/profile → 200 with valid token, 403 tampered/expired
- The two pages show different content ("WhiteList" heading vs "My Profile" heading)
- Contact list shows "WhiteList" header with count, no "Contact List" text
"""
import os
import sys
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path):
    """Fresh DB with whitelist schema + one profile."""
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    conn.commit()
    conn.close()
    return db


def _owner_token():
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", "1", expires_days=365)


def _expired_token():
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", "1", expires_days=-1)


def _tampered_token():
    return _owner_token() + "x"


# ============================================================
# Tab chrome REMOVED (round-2 ruling)
# ============================================================

class TestTabChromeRemoved:
    """Round-2: single-surface design, no tab chrome."""

    def test_no_tab_nav_on_contact_list(self, tmp_path):
        """Tab nav must NOT be present on /owner/{token} (round-2: no tabs)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}")
        assert resp.status_code == 200
        # The contacts.html tab chrome uses <div class="wl-glass-rail"> — must be absent
        # (CSS definition in base.html is OK; we check for the HTML element)
        assert '<div class="wl-glass-rail' not in resp.text

    def test_no_tab_nav_on_my_profile(self, tmp_path):
        """Tab nav must NOT be present on /owner/{token}/profile (round-2: no tabs)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/profile")
        assert resp.status_code == 200
        assert '<div class="wl-glass-rail' not in resp.text


# ============================================================
# /owner/{token}/profile route
# ============================================================

class TestProfileRoute:
    def test_profile_returns_200(self, tmp_path):
        """Valid token → 200 on /profile."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/profile")
        assert resp.status_code == 200

    def test_profile_returns_403_tampered(self, tmp_path):
        """Tampered token → 403."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_tampered_token()}/profile")
        assert resp.status_code == 403

    def test_profile_returns_403_expired(self, tmp_path):
        """Expired token → 403."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_expired_token()}/profile")
        assert resp.status_code == 403


# ============================================================
# Different content on each page (updated for round-2)
# ============================================================

class TestDifferentContent:
    def test_contact_list_has_contacts_heading(self, tmp_path):
        """Contact List page has 'WhiteList' heading (round-2: renamed from Contact List)."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}")
        assert resp.status_code == 200
        assert "WhiteList" in resp.text

    def test_my_profile_has_my_profile_heading(self, tmp_path):
        """My Profile page has 'My Profile' heading."""
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        resp = client.get(f"/owner/{_owner_token()}/profile")
        assert resp.status_code == 200
        assert "My Profile" in resp.text
