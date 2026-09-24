"""UX pass 5 — Package A regression pins (2026-09-24 captain walk-through).

Covers:
- Contact detail: NO per-card tabs; ALL shared cards on one page laid out
  like the view-profile page; reach badges per card; Access section intact
- Connect personally / connect professionally (John Doe flow): a granted
  contact asks for the other scope's card information; the ask rides
  access_grants.context; dedupe/adoption rules; owner notification
- Amber request box: scoped asks surface "Asks for: …" and an
  approve-with-cards picker pre-selecting the requested scope
- Scoped sharing enforcement: /p/{handle} shows a granted viewer exactly
  the cards their grants were assigned (union), legacy unscoped otherwise
- My Card strip on the WhiteList screen: renders owner card names +
  pictures (owner_profile_id bug), no 'Edit →' link
"""
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import _make_session_cookie, create_app


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _seed_owner(tmp_path: Path) -> Path:
    """Owner profile (handle jasonheath) + default Personal/Work cards.

    Personal (scope=personal) carries the seeded phone; Work (scope=work)
    carries the seeded email + title/company.
    """
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jheath@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "555-1234", "visibility": "granted"}],
    })
    whitelist_db.seed_default_cards(conn)
    conn.commit()
    conn.close()
    return db


def _grant_viewers(db: Path, emails: tuple[str, ...] = ("john@x.com",)):
    """Create + approve grants for the given viewer emails. Returns grant ids."""
    conn = whitelist_db.wl_connect(db)
    gids = []
    for e in emails:
        gid = whitelist_db.create_grant(conn, 1, e, e.split("@")[0].title())
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        gids.append(gid)
    conn.close()
    return gids


def _client(db: Path) -> TestClient:
    return TestClient(create_app(db))


def _owner_token():
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", "1", expires_days=365)


# ------------------------------------------------------------------
# Data layer: create_scope_request
# ------------------------------------------------------------------

class TestCreateScopeRequest:
    def test_mints_pending_scoped_grant_for_already_granted_contact(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        conn = whitelist_db.wl_connect(db)
        gid, created = whitelist_db.create_scope_request(
            conn, 1, "john@x.com", "John", 1, "personal")
        row = whitelist_db.get_grant(conn, gid)
        conn.close()
        assert created is True
        assert row["status"] == "pending"
        assert row["context"] == "personal"

    def test_reclick_same_scope_is_idempotent(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        conn = whitelist_db.wl_connect(db)
        gid1, created1 = whitelist_db.create_scope_request(
            conn, 1, "john@x.com", "John", 1, "personal")
        gid2, created2 = whitelist_db.create_scope_request(
            conn, 1, "john@x.com", "John", 1, "personal")
        conn.close()
        assert created1 and not created2
        assert gid1 == gid2

    def test_other_scope_mints_a_second_request(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        conn = whitelist_db.wl_connect(db)
        gid1, _ = whitelist_db.create_scope_request(
            conn, 1, "john@x.com", "John", 1, "personal")
        gid2, created2 = whitelist_db.create_scope_request(
            conn, 1, "john@x.com", "John", 1, "professional")
        conn.close()
        assert created2 and gid1 != gid2

    def test_adopts_plain_pending_request(self, tmp_path):
        """A context-less pending request is upgraded, not duplicated."""
        db = _seed_owner(tmp_path)
        conn = whitelist_db.wl_connect(db)
        plain = whitelist_db.create_grant(conn, 1, "sue@x.com", "Sue", 1)
        gid, created = whitelist_db.create_scope_request(
            conn, 1, "sue@x.com", "Sue", 1, "professional")
        row = whitelist_db.get_grant(conn, gid)
        conn.close()
        assert created is False
        assert gid == plain
        assert row["context"] == "professional"
        assert row["status"] == "pending"

    def test_rejects_unknown_scope(self, tmp_path):
        db = _seed_owner(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            whitelist_db.create_scope_request(conn, 1, "x@x.com", "X", 1, "weird")
            raised = False
        except ValueError:
            raised = True
        conn.close()
        assert raised


# ------------------------------------------------------------------
# HTTP: POST /p/{handle}/connect
# ------------------------------------------------------------------

class TestConnectRoute:
    def test_granted_viewer_creates_scoped_request(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        client = _client(db)
        r = client.post("/p/jasonheath/connect",
                        data={"scope": "personal", "e": "john@x.com"},
                        follow_redirects=False)
        assert r.status_code == 303
        assert "requested=personal" in r.headers["location"]
        assert "fresh=1" in r.headers["location"]
        conn = whitelist_db.wl_connect(db)
        rows = conn.execute(
            "SELECT * FROM access_grants WHERE context = 'personal'").fetchall()
        conn.close()
        assert len(rows) == 1 and rows[0]["status"] == "pending"

    def test_reclick_shows_already_asked_banner(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        client = _client(db)
        client.post("/p/jasonheath/connect",
                    data={"scope": "personal", "e": "john@x.com"})
        r = client.post("/p/jasonheath/connect",
                        data={"scope": "personal", "e": "john@x.com"},
                        follow_redirects=False)
        assert r.status_code == 303
        assert "fresh=1" not in r.headers["location"]
        html = client.get(r.headers["location"]).text
        assert "already asked" in html

    def test_anonymous_viewer_is_refused(self, tmp_path):
        db = _seed_owner(tmp_path)
        client = _client(db)
        r = client.post("/p/jasonheath/connect",
                        data={"scope": "personal", "e": "rando@x.com"})
        assert r.status_code == 403

    def test_owner_notified_on_fresh_request(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        client = _client(db)
        client.post("/p/jasonheath/connect",
                    data={"scope": "professional", "e": "john@x.com"})
        conn = whitelist_db.wl_connect(db)
        notes = conn.execute(
            "SELECT * FROM notifications WHERE kind = 'connection_request' "
            "AND title LIKE '%professional%'").fetchall()
        conn.close()
        assert len(notes) == 1


# ------------------------------------------------------------------
# Amber box: scoped asks + approve-with-cards picker
# ------------------------------------------------------------------

class TestAmberBoxScopedAsk:
    def _pending_scoped(self, tmp_path, scope="personal"):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        client = _client(db)
        client.post("/p/jasonheath/connect",
                    data={"scope": scope, "e": "john@x.com"})
        return db, client

    def test_ask_and_picker_render(self, tmp_path):
        db, client = self._pending_scoped(tmp_path)
        html = client.get(f"/owner/{_owner_token()}").text
        assert "Asks for: personal contact information" in html
        assert "Approve with cards…" in html
        assert f"/owner/{_owner_token()}/approve" in html

    def test_requested_scope_cards_prechecked(self, tmp_path):
        db, client = self._pending_scoped(tmp_path, scope="personal")
        conn = whitelist_db.wl_connect(db)
        personal_id = conn.execute(
            "SELECT id FROM cards WHERE name = 'Personal'").fetchone()["id"]
        work_id = conn.execute(
            "SELECT id FROM cards WHERE name = 'Work'").fetchone()["id"]
        conn.close()
        html = client.get(f"/owner/{_owner_token()}").text
        import re as _re
        boxes = _re.findall(
            r'<input[^>]*name="card_ids"[^>]*>', " ".join(html.split()))
        checked = [b for b in boxes if "checked" in b]
        assert any(f'value="{personal_id}"' in b for b in checked), \
            "personal-scope cards pre-checked for a personal ask"
        assert not any(f'value="{work_id}"' in b for b in checked), \
            "work-scope cards not pre-checked for a personal ask"

    def test_plain_request_keeps_simple_buttons(self, tmp_path):
        db = _seed_owner(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.create_grant(conn, 1, "plain@x.com", "Plain", 1)
        conn.close()
        client = _client(db)
        html = client.get(f"/owner/{_owner_token()}").text
        assert "Approve with cards…" not in html
        assert "Asks for:" not in html


# ------------------------------------------------------------------
# Scoped sharing enforcement on /p/{handle}
# ------------------------------------------------------------------

class TestScopedCardVisibility:
    def test_no_assignments_shows_all_cards(self, tmp_path):
        db = _seed_owner(tmp_path)
        _grant_viewers(db)
        html = _client(db).get("/p/jasonheath?e=john%40x.com").text
        assert "Personal" in html and "Work" in html

    def test_assigned_cards_only(self, tmp_path):
        db = _seed_owner(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "john@x.com", "John")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        personal_id = conn.execute(
            "SELECT id FROM cards WHERE name = 'Personal'").fetchone()["id"]
        whitelist_db.set_grant_cards(conn, gid, [personal_id])
        conn.close()
        html = _client(db).get("/p/jasonheath?e=john%40x.com").text
        assert "Personal" in html
        assert "Work</h2>" not in html, "unassigned card must not render"
        assert "jheath@waltheremc.com" not in html, "work email hidden"

    def test_union_across_grants(self, tmp_path):
        db = _seed_owner(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid1 = whitelist_db.create_grant(conn, 1, "john@x.com", "John")
        whitelist_db.apply_decision(conn, gid1, "approve", "quarter")
        personal_id = conn.execute(
            "SELECT id FROM cards WHERE name = 'Personal'").fetchone()["id"]
        work_id = conn.execute(
            "SELECT id FROM cards WHERE name = 'Work'").fetchone()["id"]
        whitelist_db.set_grant_cards(conn, gid1, [personal_id])
        # Later scoped ask approved with the work card.
        gid2, _ = whitelist_db.create_scope_request(
            conn, 1, "john@x.com", "John", 1, "professional")
        whitelist_db.apply_decision(conn, gid2, "approve", "quarter")
        whitelist_db.set_grant_cards(conn, gid2, [work_id])
        conn.close()
        html = _client(db).get("/p/jasonheath?e=john%40x.com").text
        assert "Personal" in html and "Work</h2>" in html

    def test_owner_self_view_unscoped(self, tmp_path):
        db = _seed_owner(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "jheath@waltheremc.com", "Self")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        personal_id = conn.execute(
            "SELECT id FROM cards WHERE name = 'Personal'").fetchone()["id"]
        whitelist_db.set_grant_cards(conn, gid, [personal_id])
        conn.close()
        html = _client(db).get("/p/jasonheath?e=jheath%40waltheremc.com").text
        assert "Personal" in html and "Work</h2>" in html


# ------------------------------------------------------------------
# My Card strip (WhiteList screen)
# ------------------------------------------------------------------

class TestMyCardStrip:
    def test_strip_renders_owner_cards(self, tmp_path):
        db = _seed_owner(tmp_path)
        html = _client(db).get(f"/owner/{_owner_token()}").text
        assert "Personal" in html, "owner card name must render"
        assert "Work" in html
        assert "/photos/1/" in html or "wl-btn-slate" in html, \
            "picture circle or initials fallback renders"

    def test_edit_link_removed(self, tmp_path):
        db = _seed_owner(tmp_path)
        html = _client(db).get(f"/owner/{_owner_token()}").text
        assert "Edit →" not in html, "whole strip is the click target now"
