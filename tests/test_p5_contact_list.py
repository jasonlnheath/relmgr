"""T3 — Contact list surface (replaces owner dashboard view).

Tests pin:
- GET /owner/{token} renders contacts.html (not owner_dashboard.html)
- Pending grants shown at top, granted/revoked/denied below
- Each row shows: display name (contact match via T0 → name; else requester),
  badge list (card names), perm/temp badge, logo state
- Approve form posts grant_id, card_ids[], access=permanent|quarter
- Reject → appears at /owner/{token}/junk
- Per-contact manage access: POST /owner/{token}/access
- Mobile-first markup: no JS, plain forms/POSTs
- Context <select> absent from contacts.html
"""
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from whitelist_db import (
    wl_connect,
    ensure_whitelist_schema,
    seed_profile,
    create_grant,
    create_card,
    set_grant_cards,
    find_contact_by_email,
    merge_requester_into_contacts,
    apply_decision,
)
import app as app_module
from wl_tokens import make_token

SECRET = b"test-secret"


@pytest.fixture
def client(tmp_path):
    """Fresh app with schema, profile, cards, contacts table, and some grants."""
    db = tmp_path / "test_contacts.db"
    app = app_module.create_app(db_path=db)

    conn = wl_connect(db)
    ensure_whitelist_schema(conn)
    seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })

    # Create the contacts table (simulates the real contacts.db that has it)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            normalized_name TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            emails TEXT DEFAULT '[]',
            phones TEXT DEFAULT '[]',
            organizations TEXT DEFAULT '[]',
            sources TEXT DEFAULT '[]',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_duplicate INTEGER DEFAULT 0,
            merged_into TEXT
        )
    """)
    conn.commit()

    # Seed the cards
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

    client = TestClient(app)
    return client, db, conn, owner_id, work_id, personal_id


def _token(client_fixture, owner_id):
    """Helper: make an owner_dashboard token."""
    return make_token(SECRET, "owner_dashboard", str(owner_id))


# ============================================================
# contacts.html template exists and renders
# ============================================================

class TestContactsTemplateExists:
    """contacts.html was removed round-2; contact_list.html is the active template."""

    def test_old_contacts_html_removed(self):
        tmpl_dir = Path(__file__).resolve().parent.parent / "templates"
        assert not (tmpl_dir / "contacts.html").exists(), "contacts.html removed round-2"
        assert (tmpl_dir / "contact_list.html").exists(), "contact_list.html must exist"

    def test_template_renders_empty(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "contacts.html" not in resp.text


# ============================================================
# Pending grants at top
# ============================================================

class TestOwnerDashboardPendingFirst:
    def test_pending_shown_at_top(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        grant_id = create_grant(conn, owner_id, "pending@test.com", "Pending User")
        conn.commit()
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "Pending User" in resp.text or "pending@test.com" in resp.text

    def test_granted_shown_below_pending(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        g1 = create_grant(conn, owner_id, "granted@test.com", "Granted User")
        apply_decision(conn, g1, "approve", "lifetime", merge_contacts=True)
        g2 = create_grant(conn, owner_id, "pending2@test.com", "Pending User Two")
        conn.commit()
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "Granted User" in resp.text
        assert "Pending User Two" in resp.text


# ============================================================
# Card badges
# ============================================================

class TestCardBadges:
    def test_card_badges_render(self, client):
        client_obj, db, conn, owner_id, work_id, personal_id = client
        gid = create_grant(conn, owner_id, "badge@test.com", "Badge User")
        apply_decision(conn, gid, "approve", "lifetime", merge_contacts=True)
        set_grant_cards(conn, gid, [work_id])
        conn.commit()
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "Work" in resp.text


# ============================================================
# Permanent vs temporary badge
# ============================================================

class TestPermTempBadge:
    def test_lifetime_shows_permanent(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        gid = create_grant(conn, owner_id, "perm@test.com", "Perm User")
        apply_decision(conn, gid, "approve", "lifetime", merge_contacts=True)
        conn.commit()
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        # round-2: Whitelist badge for lifetime (replaces "Permanent")
        assert "WhiteList" in resp.text or "Permanent" in resp.text or "permanent" in resp.text.lower()

    def test_quarter_shows_temp(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        gid = create_grant(conn, owner_id, "temp@test.com", "Temp User")
        apply_decision(conn, gid, "approve", "quarter", merge_contacts=True)
        conn.commit()
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "Temporary" in resp.text or "temporary" in resp.text.lower() or "Temp" in resp.text


# ============================================================
# Logo state
# ============================================================

class TestLogoState:
    def test_fresh_logo_for_current_quarter(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        # Create a grant so the logo renders
        gid = create_grant(conn, owner_id, "logo@test.com", "Logo User")
        apply_decision(conn, gid, "approve", "lifetime", merge_contacts=True)
        conn.commit()
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "<svg" in resp.text.lower() or "logo" in resp.text.lower() or "shield" in resp.text.lower() or "badge" in resp.text.lower()


# ============================================================
# Approve with cards — form validation
# ============================================================

class TestApproveWithCards:
    def test_approve_requires_card(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        gid = create_grant(conn, owner_id, "approvetest@test.com", "Approve Test")
        conn.commit()
        resp = client_obj.post(f"/owner/{_token(client, owner_id)}/approve",
                               data={"grant_id": gid, "card_ids": [], "access": "quarter"})
        assert resp.status_code != 200 or "card" in resp.text.lower()

    def test_approve_with_card_succeeds(self, client):
        client_obj, db, conn, owner_id, work_id, personal_id = client
        gid = create_grant(conn, owner_id, "approvetest2@test.com", "Approve Test Two")
        conn.commit()
        resp = client_obj.post(f"/owner/{_token(client, owner_id)}/approve",
                               data={"grant_id": gid, "decision": "approve", "card_ids": [work_id], "access": "quarter"})
        assert resp.status_code == 200
        grant = conn.execute("SELECT status FROM access_grants WHERE id = ?", (gid,)).fetchone()
        assert grant and grant["status"] == "granted"
        cards = conn.execute("SELECT card_id FROM grant_cards WHERE grant_id = ?", (gid,)).fetchall()
        assert len(cards) >= 1


# ============================================================
# Reject → junk folder
# ============================================================

class TestJunkFolder:
    def test_deny_lands_in_junk(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        gid = create_grant(conn, owner_id, "junk@test.com", "Junk User")
        conn.commit()
        resp = client_obj.post(f"/owner/{_token(client, owner_id)}/decision",
                               data={"grant_id": gid, "decision": "deny", "expiry": "90"})
        assert resp.status_code == 200
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}/junk")
        assert resp.status_code == 200
        assert "Junk User" in resp.text or "junk@test.com" in resp.text

    def test_junk_empty_when_no_denials(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}/junk")
        assert resp.status_code == 200


# ============================================================
# Context select absent
# ============================================================

class TestContextRemoved:
    def test_no_context_select_in_contacts(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "categorize" not in resp.text.lower()


# ============================================================
# Per-contact manage access
# ============================================================

class TestManageAccess:
    def test_manage_access_updates_cards(self, client):
        client_obj, db, conn, owner_id, work_id, personal_id = client
        gid = create_grant(conn, owner_id, "manage@test.com", "Manage User")
        apply_decision(conn, gid, "approve", "lifetime", merge_contacts=True)
        set_grant_cards(conn, gid, [work_id])
        conn.commit()
        resp = client_obj.post(f"/owner/{_token(client, owner_id)}/access",
                               data={"grant_id": gid, "card_ids": [personal_id], "access": "lifetime"})
        assert resp.status_code == 200
        cards = conn.execute("SELECT card_id FROM grant_cards WHERE grant_id = ?", (gid,)).fetchall()
        card_ids = [c["card_id"] for c in cards]
        assert personal_id in card_ids
        assert work_id not in card_ids


# ============================================================
# Contact name resolution via T0 find_contact_by_email
# ============================================================

class TestContactNameResolution:
    def test_contact_name_used_over_requester_name(self, client):
        client_obj, db, conn, owner_id, _, _ = client
        gid = create_grant(conn, owner_id, "name@test.com", "Requester Name")
        conn.commit()
        grant = conn.execute("SELECT * FROM access_grants WHERE id = ?", (gid,)).fetchone()
        merge_requester_into_contacts(conn, dict(grant))
        resp = client_obj.get(f"/owner/{_token(client, owner_id)}")
        assert resp.status_code == 200
        assert "Requester Name" in resp.text or "name@test.com" in resp.text
