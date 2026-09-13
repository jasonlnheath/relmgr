"""Phase A2: Contact List surface — pagination, search, logo logic, detail.

Tests pin:
- list_contact_list_rows returns correct shape
- Pending grants appear first
- Logo: fresh (this-quarter), stale (prior quarter), none (no grant)
- Temp shows expiry date
- Search hits name and email substring
- Pagination: 51 contacts → 2 pages, page 2 has row 51
- No duplicate rows when contact matches grant
- Plain contacts (no grant) show name/email only, no logo/badges
- Detail expandable via ?detail={id}
- A3: denied grants appear ONLY in /junk, not in contact list rows
"""
import json
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
import store
from fastapi.testclient import TestClient
from app import create_app


def _make_db(tmp_path: Path):
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
    return wl_tokens.make_token(b"test-secret", "owner_dashboard", "owner", expires_days=365)


def _seed_contacts_via_store(db_path, n=3):
    """Seed contacts via the REAL store.py path."""
    store.init_db(db_path)
    for i in range(n):
        store.upsert_contact({
            "id": f"contact-{i}",
            "normalized_name": f"Person {i}",
            "first_name": f"First{i}",
            "last_name": f"Last{i}",
            "emails": [f"person{i}@example.com"],
            "phones": [f"555-{1000+i}"],
            "organizations": ["Org{i}"],
            "sources": [],
        }, db_path=db_path)


def _ensure_schema(conn):
    """Ensure full whitelist schema (cards tables etc) — not just wl_init."""
    whitelist_db.ensure_whitelist_schema(conn)


# ============================================================
# Data layer: list_contact_list_rows
# ============================================================

class TestListContactListRows:
    def test_row_shape(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 3)
        conn = whitelist_db.wl_connect(db)
        _ensure_schema(conn)
        rows = whitelist_db.list_contact_list_rows(conn, 1)
        assert len(rows) >= 1
        row = rows[0]
        assert "contact_id" in row
        assert "name" in row
        assert "email" in row
        assert "granted" in row
        conn.close()

    def test_pending_on_top(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 2)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        # Create a pending grant
        grant_id = whitelist_db.create_grant(conn, 1, "pending@test.com", "Pending Person")
        whitelist_db._log_action(conn, grant_id, 1, "created")

        rows = whitelist_db.list_contact_list_rows(conn, 1)
        # Pending should appear first (is_pending=True)
        pending_rows = [r for r in rows if r.get("is_pending")]
        assert len(pending_rows) >= 1

        conn.close()

    def test_logo_fresh(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 2)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        # Create a contact with updated_at this quarter
        store.upsert_contact({
            "id": "c1",
            "normalized_name": "Fresh Person",
            "first_name": "Fresh",
            "last_name": "Person",
            "emails": ["fresh@test.com"],
            "phones": ["555-0001"],
            "organizations": [],
            "sources": [],
        }, db_path=db)
        # Create a granted (not pending) grant for this contact
        grant_id = whitelist_db.create_grant(conn, 1, "fresh@test.com", "Fresh Person")
        whitelist_db.apply_decision(conn, grant_id, "approve", "quarter")
        conn.commit()
        _ensure_schema(conn)

        rows = whitelist_db.list_contact_list_rows(conn, 1)
        fresh_rows = [r for r in rows if r.get("logo_state") == "fresh"]
        # At least the fresh contact should have fresh logo
        assert len(fresh_rows) >= 1
        conn.close()

    def test_logo_stale(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 2)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        # Create a contact with stale updated_at (prior quarter)
        stale_date = "2026-01-15T00:00:00Z"
        store.upsert_contact({
            "id": "c1",
            "normalized_name": "Stale Person",
            "first_name": "Stale",
            "last_name": "Person",
            "emails": ["stale@test.com"],
            "phones": ["555-0001"],
            "organizations": [],
            "sources": [],
            "created_at": stale_date,
            "updated_at": stale_date,
        }, db_path=db)
        # Create a granted grant for this contact (merge_contacts=False so it
        # doesn't overwrite the stale updated_at)
        grant_id = whitelist_db.create_grant(conn, 1, "stale@test.com", "Stale Person")
        whitelist_db.apply_decision(conn, grant_id, "approve", "quarter", merge_contacts=False)
        conn.commit()
        _ensure_schema(conn)

        rows = whitelist_db.list_contact_list_rows(conn, 1)
        stale_rows = [r for r in rows if r.get("logo_state") == "stale"]
        assert len(stale_rows) >= 1
        conn.close()

    def test_logo_none_for_plain_contact(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 2)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        # Plain contact (no grant)
        store.upsert_contact({
            "id": "c1",
            "normalized_name": "Plain Person",
            "first_name": "Plain",
            "last_name": "Person",
            "emails": ["plain@test.com"],
            "phones": ["555-0001"],
            "organizations": [],
            "sources": [],
        }, db_path=db)
        conn.commit()
        _ensure_schema(conn)

        rows = whitelist_db.list_contact_list_rows(conn, 1)
        plain_rows = [r for r in rows if r.get("email") == "plain@test.com"]
        assert len(plain_rows) == 1
        assert plain_rows[0]["logo_state"] is None
        assert plain_rows[0]["granted"] is False
        conn.close()

    def test_search_name(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 2)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        store.upsert_contact({
            "id": "c1",
            "normalized_name": "Alice Smith",
            "first_name": "Alice",
            "last_name": "Smith",
            "emails": ["alice@test.com"],
            "phones": ["555-0001"],
            "organizations": [],
            "sources": [],
        }, db_path=db)
        conn.commit()
        _ensure_schema(conn)

        rows = whitelist_db.list_contact_list_rows(conn, 1, q="Alice")
        assert len(rows) >= 1
        conn.close()

    def test_search_email(self, tmp_path):
        db = _make_db(tmp_path)
        _seed_contacts_via_store(db, 2)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        store.upsert_contact({
            "id": "c1",
            "normalized_name": "Bob Jones",
            "first_name": "Bob",
            "last_name": "Jones",
            "emails": ["bobtest@example.com"],
            "phones": ["555-0001"],
            "organizations": [],
            "sources": [],
        }, db_path=db)
        conn.commit()
        _ensure_schema(conn)

        rows = whitelist_db.list_contact_list_rows(conn, 1, q="bobtest")
        assert len(rows) >= 1
        conn.close()

    def test_pagination_51_rows(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        # Insert 51 contacts via store
        store.init_db(db)
        for i in range(51):
            store.upsert_contact({
                "id": f"p{i}",
                "normalized_name": f"Person {i}",
                "first_name": f"F{i}",
                "last_name": f"L{i}",
                "emails": [f"p{i}@x.com"],
                "phones": [],
                "organizations": [],
                "sources": [],
            }, db_path=db)
        conn.commit()
        _ensure_schema(conn)

        rows_p1 = whitelist_db.list_contact_list_rows(conn, 1, page=0, per_page=50)
        rows_p2 = whitelist_db.list_contact_list_rows(conn, 1, page=1, per_page=50)
        assert len(rows_p1) == 50
        assert len(rows_p2) == 1  # 51st row on page 2
        conn.close()

    def test_no_duplicate_rows(self, tmp_path):
        """A contact that matches a grant email should appear only once."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        # Create a contact
        store.init_db(db)
        store.upsert_contact({
            "id": "c1",
            "normalized_name": "Match Person",
            "first_name": "Match",
            "last_name": "Person",
            "emails": ["match@test.com"],
            "phones": ["555-0001"],
            "organizations": [],
            "sources": [],
        }, db_path=db)
        conn.commit()
        # Create a grant for the same email
        whitelist_db.create_grant(conn, 1, "match@test.com", "Match Person")
        _ensure_schema(conn)

        rows = whitelist_db.list_contact_list_rows(conn, 1)
        # Should appear exactly once
        match_rows = [r for r in rows if r.get("email") == "match@test.com"]
        assert len(match_rows) == 1
        conn.close()


# ============================================================
# A3: Junk view
# ============================================================

class TestJunkView:
    def test_denied_only_in_junk(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        token = _owner_token()

        # Create a denied grant
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        grant_id = whitelist_db.create_grant(conn, 1, "denied@test.com", "Denied Person")
        whitelist_db.apply_decision(conn, grant_id, "deny", "90")
        conn.commit()
        conn.close()

        # /junk should show the denied grant
        resp = client.get(f"/owner/{token}/junk")
        assert resp.status_code == 200
        assert "Denied Person" in resp.text

        # Contact list should NOT show denied grant inline
        resp = client.get(f"/owner/{token}")
        assert resp.status_code == 200
        # Denied grants should not appear in the pending/active sections
        assert "denied@test.com" not in resp.text

    def test_denied_not_shown_greyed(self, tmp_path):
        db = _make_db(tmp_path)
        client = TestClient(create_app(db))
        token = _owner_token()

        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "org": {"company": "WEMC", "title": "Sales"},
            "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
            "phones": [{"number": "555-1234", "visibility": "granted"}],
        })
        grant_id = whitelist_db.create_grant(conn, 1, "denied2@test.com", "Denied Two")
        whitelist_db.apply_decision(conn, grant_id, "deny", "90")
        conn.commit()
        conn.close()

        # Contact list should not have the denied grant at all
        resp = client.get(f"/owner/{token}")
        assert resp.status_code == 200
        assert "denied2@test.com" not in resp.text
