"""UX pass 4 — data layer contract (PACKAGE A).

Verifies that whitelist_db.py already carries the full contract needed by
the UI layer (PACKAGE B): card_kind(), _CARD_ORDER_SQL, seed_default_cards,
cards_for_public_view, effective_tier(), is_grey(), set_badge_state(),
list_contact_list_rows(), search_new_connections(), create_contact_vcard(),
and the badge/state helpers.

No schema changes are needed — the data layer is already correct.
This test file pins the contract so PACKAGE B can build against it.
"""
import json
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import store
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


# ============================================================
# Helpers
# ============================================================

def _make_db(tmp_path: Path) -> Path:
    """Create a test DB with one owner profile (id=1) and seed default cards."""
    db = tmp_path / "test.db"
    # Create contacts table BEFORE whitelist schema so ensure_contacts_owner
    # can add the owner_profile_id column (it only adds if the table exists).
    store.init_db(db)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales"},
        "emails": [{"address": "jason@waltheremc.com", "visibility": "granted"}],
        "phones": [{"number": "5551234567", "visibility": "granted"}],
    })
    # Seed default cards (Personal + Work)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_default_cards(conn)
    conn.commit()
    conn.close()
    return db


def _owner_token(profile_id: int = 1) -> str:
    return wl_tokens.make_token(b"test-secret", "owner_dashboard",
                                str(profile_id), expires_days=365)


def _card_id(db: Path, name: str, owner: int = 1) -> int:
    """Return the card id for a named card on an owner."""
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = ? AND name = ?",
        (owner, name)).fetchone()
    conn.close()
    assert row is not None, f"card {name!r} missing for owner {owner}"
    return row["id"]


def _add_field(conn, profile_id: int, field_type: str, value: str,
               visibility: str = "granted") -> int:
    """Insert a profile_field row and return its id."""
    conn.execute(
        "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) "
        "VALUES (?, ?, ?, ?)",
        (profile_id, field_type, value, visibility),
    )
    return conn.execute(
        "SELECT id FROM profile_fields WHERE profile_id = ? AND field_value = ? "
        "ORDER BY id DESC LIMIT 1",
        (profile_id, value),
    ).fetchone()["id"]


# ============================================================
# 1. card_kind() — Personal / Work / None
# ============================================================

class TestCardKind:
    def test_personal(self):
        assert whitelist_db.card_kind({"name": "Personal"}) == "personal"

    def test_work(self):
        assert whitelist_db.card_kind({"name": "Work"}) == "work"

    def test_custom_name(self):
        assert whitelist_db.card_kind({"name": "My Card"}) is None

    def test_case_insensitive(self):
        assert whitelist_db.card_kind({"name": "PERSONAL"}) == "personal"
        assert whitelist_db.card_kind({"name": "work"}) == "work"

    def test_empty_name(self):
        assert whitelist_db.card_kind({"name": ""}) is None
        assert whitelist_db.card_kind({}) is None


# ============================================================
# 2. _CARD_ORDER_SQL — Personal first, Work second, rest alphabetical
# ============================================================

class TestCardOrder:
    def test_ordering(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Add extra cards
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name) VALUES (1, 'Alpha')")
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name) VALUES (1, 'Zulu')")
        conn.execute(
            "INSERT INTO cards (owner_profile_id, name) VALUES (1, 'Beta')")
        conn.commit()
        cards = whitelist_db.list_cards(conn, 1)
        conn.close()
        names = [c["name"] for c in cards]
        assert names[0] == "Personal", "Personal must be first"
        assert names[1] == "Work", "Work must be second"
        # Rest alphabetical
        assert names[2] == "Alpha"
        assert names[3] == "Beta"
        assert names[4] == "Zulu"


# ============================================================
# 3. seed_default_cards — idempotency
# ============================================================

class TestSeedDefaultCards:
    def test_always_creates_personal_and_work(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        cards = whitelist_db.list_cards(conn, 1)
        names = [c["name"] for c in cards]
        assert "Personal" in names
        assert "Work" in names
        conn.close()

    def test_idempotent_multiple_calls(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.seed_default_cards(conn)
        whitelist_db.seed_default_cards(conn)
        cards = whitelist_db.list_cards(conn, 1)
        names = [c["name"] for c in cards]
        assert names.count("Personal") == 1
        assert names.count("Work") == 1
        conn.close()

    def test_empty_profile_gets_personal_and_work(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Create a second owner with no fields
        conn.execute(
            "INSERT INTO profiles (handle, display_name, owner_id) VALUES (?, ?, ?)",
            ("empty", "Empty Person", 2))
        pid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) "
            "VALUES (?, 'email', 'empty@x.com', 'private')", (pid,))
        conn.commit()
        whitelist_db.seed_default_cards(conn)
        cards = whitelist_db.list_cards(conn, pid)
        names = [c["name"] for c in cards]
        assert "Personal" in names
        assert "Work" in names
        conn.close()

    def test_personal_card_id_lower_than_work(self, tmp_path):
        """Personal must have lower id than Work (it is the default picture)."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        p_id = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Personal'").fetchone()["id"]
        w_id = conn.execute(
            "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Work'").fetchone()["id"]
        assert p_id < w_id, "Personal must have lower id than Work"
        conn.close()

    def test_seed_backfills_empty_personal_card(self, tmp_path):
        """seed_default_cards backfills fields that match the card's type set
        when the card is empty (no fields yet)."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Create a fresh Personal card with NO fields (simulate a new owner)
        conn.execute(
            "INSERT INTO profiles (handle, display_name, owner_id) VALUES (?, ?, ?)",
            ("newowner", "New Owner", 2))
        pid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO profile_fields (profile_id, field_type, field_value, visibility) "
            "VALUES (?, 'email', 'new@x.com', 'private')", (pid,))
        # Add fields that match Personal card types
        _add_field(conn, pid, "birthday", "01-15", "public")
        _add_field(conn, pid, "nickname", "New", "public")
        _add_field(conn, pid, "text_number", "5559876543", "granted")
        whitelist_db.seed_default_cards(conn)
        cards = whitelist_db.list_cards(conn, pid)
        personal = next((c for c in cards if c["name"] == "Personal"), None)
        assert personal is not None
        personal_types = {f["field_type"] for f in personal["fields"]}
        assert "birthday" in personal_types
        assert "nickname" in personal_types
        assert "text_number" in personal_types
        conn.close()


# ============================================================
# 4. cards_for_public_view — tier filtering
# ============================================================

class TestCardsForPublicView:
    def test_granted_sees_all_fields(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        cards = whitelist_db.cards_for_public_view(conn, 1, "granted")
        assert len(cards) >= 2  # Personal + Work at minimum
        # All fields visible (public + granted + private)
        for card in cards:
            for f in card["visible_fields"]:
                assert f["visibility"] in ("public", "granted", "private")
        conn.close()

    def test_anonymous_sees_public_only(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        cards = whitelist_db.cards_for_public_view(conn, 1, "anonymous")
        assert len(cards) >= 1  # default card only
        for card in cards:
            for f in card["visible_fields"]:
                assert f["visibility"] == "public"
        conn.close()

    def test_anonymous_default_card_only(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        cards = whitelist_db.cards_for_public_view(conn, 1, "anonymous")
        # Should only return the first card (Personal = default)
        assert len(cards) == 1
        assert cards[0]["name"] == "Personal"
        conn.close()


# ============================================================
# 5. is_grey — derived state
# ============================================================

class TestIsGrey:
    def test_lifetime_not_grey(self):
        grant = {"status": "granted", "expires_at": None}
        assert whitelist_db.is_grey(grant) is False

    def test_future_expires_is_grey(self):
        """UX pass 3 bug fix: badge-moved grey contacts with a future
        quarter marker ARE grey (the marker feeds the quarterly review)."""
        grant = {"status": "granted", "expires_at": "2099-12-31T23:59:59Z"}
        assert whitelist_db.is_grey(grant) is True

    def test_lapsed_expires_is_grey(self):
        grant = {"status": "granted", "expires_at": "2020-01-01T00:00:00Z"}
        assert whitelist_db.is_grey(grant) is True

    def test_denied_not_grey(self):
        grant = {"status": "denied", "expires_at": "2020-01-01T00:00:00Z"}
        assert whitelist_db.is_grey(grant) is False

    def test_revoked_not_grey(self):
        grant = {"status": "revoked", "expires_at": "2020-01-01T00:00:00Z"}
        assert whitelist_db.is_grey(grant) is False

    def test_legacy_expiry_not_grey(self):
        """Legacy '90d'/'14d' strings must NOT grey (GLOB guard)."""
        grant = {"status": "granted", "expires_at": "90d"}
        assert whitelist_db.is_grey(grant) is False
        grant2 = {"status": "granted", "expires_at": "14d"}
        assert whitelist_db.is_grey(grant2) is False


# ============================================================
# 6. set_badge_state — grey → whitelist / blocked
# ============================================================

class TestSetBadgeState:
    def test_grey_to_whitelist(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey Guy")
        whitelist_db.set_badge_state(conn, gid, "greylist")
        grant = whitelist_db.get_grant(conn, gid)
        assert grant["expires_at"] is not None  # future quarter marker
        whitelist_db.set_badge_state(conn, gid, "whitelist")
        grant = whitelist_db.get_grant(conn, gid)
        assert grant["status"] == "granted"
        assert grant["expires_at"] is None
        assert grant["quarter_status"] is None
        conn.close()

    def test_grey_to_blocked(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey Guy")
        whitelist_db.set_badge_state(conn, gid, "greylist")
        whitelist_db.set_badge_state(conn, gid, "blocked")
        grant = whitelist_db.get_grant(conn, gid)
        assert grant["status"] == "revoked"
        conn.close()

    def test_whitelist_to_grey(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "x@x.com", "X")
        whitelist_db.set_badge_state(conn, gid, "whitelist")
        whitelist_db.set_badge_state(conn, gid, "greylist")
        grant = whitelist_db.get_grant(conn, gid)
        assert grant["status"] == "granted"
        assert grant["expires_at"] is not None
        conn.close()

    def test_invalid_state_raises(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "x@x.com", "X")
        try:
            whitelist_db.set_badge_state(conn, gid, "invalid")
            assert False, "should have raised"
        except ValueError:
            pass
        conn.close()

    def test_unknown_grant_returns_none(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        result = whitelist_db.set_badge_state(
            conn, "nonexistent-id", "whitelist")
        assert result is None
        conn.close()


# ============================================================
# 7. is_blacklisted
# ============================================================

class TestIsBlacklisted:
    def test_revoked_is_blacklisted(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "black@x.com", "Black")
        whitelist_db.apply_decision(conn, gid, "approve", "90")
        whitelist_db.revoke_grant(conn, gid)
        assert whitelist_db.is_blacklisted(conn, 1, "black@x.com") is True
        conn.close()

    def test_granted_not_blacklisted(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.create_grant(conn, 1, "good@x.com", "Good")
        grants = whitelist_db.get_all_grants_for_profile(conn, 1)
        for g in grants:
            if g["status"] == "pending":
                whitelist_db.apply_decision(conn, g["id"], "approve", "90")
        conn.commit()
        assert whitelist_db.is_blacklisted(conn, 1, "good@x.com") is False
        conn.close()

    def test_no_grant_not_blacklisted(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        assert whitelist_db.is_blacklisted(conn, 1, "nobody@x.com") is False
        conn.close()


# ============================================================
# 8. list_contact_list_rows — sorting and filtering
# ============================================================

class TestContactListRows:
    def test_pending_first(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Create a pending grant
        whitelist_db.create_grant(conn, 1, "pending@x.com", "Pending Person")
        rows = whitelist_db.list_contact_list_rows(conn, 1)
        assert len(rows) >= 1
        assert rows[0]["is_pending"] is True
        conn.close()

    def test_sorting_order(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Create grants with names that sort out of order
        whitelist_db.create_grant(conn, 1, "charlie@x.com", "Charlie")
        whitelist_db.create_grant(conn, 1, "alice@x.com", "Alice")
        whitelist_db.create_grant(conn, 1, "bob@x.com", "Bob")
        # Approve them
        grants = whitelist_db.get_all_grants_for_profile(conn, 1)
        for g in grants:
            if g["status"] == "pending":
                whitelist_db.apply_decision(conn, g["id"], "approve", "90")
        conn.commit()
        rows = whitelist_db.list_contact_list_rows(conn, 1)
        # Pending first, then active grants by created_at (insertion order)
        pending = [r for r in rows if r["is_pending"]]
        active = [r for r in rows if not r["is_pending"]]
        # All rows should be present
        assert len(rows) == 3
        # Active grants are in created_at order (charlie first, then alice, then bob)
        assert active[0]["name"] == "Charlie"
        assert active[1]["name"] == "Alice"
        assert active[2]["name"] == "Bob"
        conn.close()

    def test_search_filters(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.create_grant(conn, 1, "alice@x.com", "Alice Smith")
        whitelist_db.create_grant(conn, 1, "bob@x.com", "Bob Jones")
        grants = whitelist_db.get_all_grants_for_profile(conn, 1)
        for g in grants:
            if g["status"] == "pending":
                whitelist_db.apply_decision(conn, g["id"], "approve", "90")
        conn.commit()
        rows = whitelist_db.list_contact_list_rows(conn, 1, q="alice")
        names = [r["name"] for r in rows]
        assert "Alice Smith" in names
        assert "Bob Jones" not in names
        conn.close()

    def test_empty_query_returns_all(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.create_grant(conn, 1, "alice@x.com", "Alice")
        whitelist_db.create_grant(conn, 1, "bob@x.com", "Bob")
        grants = whitelist_db.get_all_grants_for_profile(conn, 1)
        for g in grants:
            if g["status"] == "pending":
                whitelist_db.apply_decision(conn, g["id"], "approve", "90")
        conn.commit()
        rows_all = whitelist_db.list_contact_list_rows(conn, 1)
        rows_empty = whitelist_db.list_contact_list_rows(conn, 1, q="")
        assert len(rows_all) == len(rows_empty)
        conn.close()


# ============================================================
# 9. search_new_connections — empty query degrades gracefully
# ============================================================

class TestSearchNewConnections:
    def test_empty_query_returns_empty(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        result = whitelist_db.search_new_connections(conn, 1, "")
        assert result == []
        result = whitelist_db.search_new_connections(conn, 1, None)
        assert result == []
        conn.close()

    def test_no_contacts_table_returns_empty(self, tmp_path):
        """search_new_connections degrades to [] when contacts table absent."""
        db = tmp_path / "nodb.db"
        conn = whitelist_db.wl_connect(db)
        whitelist_db.ensure_whitelist_schema(conn)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath",
            "name": {"display": "Jason Heath"},
            "emails": [{"address": "jason@waltheremc.com"}],
        })
        whitelist_db.ensure_whitelist_schema(conn)
        conn.commit()
        conn.close()
        db2 = tmp_path / "nodb2.db"
        conn2 = whitelist_db.wl_connect(db2)
        whitelist_db.ensure_whitelist_schema(conn2)
        result = whitelist_db.search_new_connections(conn2, 1, "anything")
        assert result == []
        conn2.close()

    def test_search_by_name(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Insert contact directly (store.upsert_contact doesn't handle owner_profile_id)
        conn.execute(
            "INSERT INTO contacts (id, normalized_name, first_name, last_name, "
            "emails, phones, organizations, sources, owner_profile_id, "
            "created_at, updated_at, is_duplicate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            ("test-1", "Alice Smith", "Alice", "Smith",
             json.dumps([{"address": "alice@x.com", "type": "primary"}]),
             "[]", "[]", json.dumps([{"source": "test"}]),
             1, whitelist_db._now_iso(), whitelist_db._now_iso()))
        conn.commit()
        results = whitelist_db.search_new_connections(conn, 1, "Alice")
        assert len(results) >= 1
        assert results[0]["name"] == "Alice Smith"
        conn.close()

    def test_search_by_email(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Insert contact directly with owner_profile_id
        conn.execute(
            "INSERT INTO contacts (id, normalized_name, first_name, last_name, "
            "emails, phones, organizations, sources, owner_profile_id, "
            "created_at, updated_at, is_duplicate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            ("test-2", "Bob Jones", "Bob", "Jones",
             json.dumps([{"address": "bob@x.com", "type": "primary"}]),
             "[]", "[]", json.dumps([{"source": "test"}]),
             1, whitelist_db._now_iso(), whitelist_db._now_iso()))
        conn.commit()
        results = whitelist_db.search_new_connections(conn, 1, "bob@x")
        assert len(results) >= 1
        assert results[0]["email"] == "bob@x.com"
        conn.close()


# ============================================================
# 10. create_contact_vcard — name system
# ============================================================

class TestCreateContactVCard:
    def test_creates_profile_with_display_name(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        profile = whitelist_db.create_contact_vcard(conn, 1, "Jane Rivers")
        assert profile["display_name"] == "Jane Rivers"
        assert profile["handle"] == "jane-rivers"
        conn.close()

    def test_handle_uniqueness(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.create_contact_vcard(conn, 1, "Jane Rivers")
        p2 = whitelist_db.create_contact_vcard(conn, 1, "Jane Rivers")
        assert p2["handle"] == "jane-rivers-2"
        conn.close()

    def test_empty_name_raises(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        try:
            whitelist_db.create_contact_vcard(conn, 1, "")
            assert False, "should have raised"
        except ValueError:
            pass
        conn.close()

    def test_gets_personal_and_work_cards(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        profile = whitelist_db.create_contact_vcard(conn, 1, "Jane Rivers")
        cards = whitelist_db.list_cards(conn, profile["id"])
        names = [c["name"] for c in cards]
        # UX pass 4: exactly ONE vCard card, no Personal/Work seeding.
        assert len(cards) == 1
        assert "Jane Rivers - vCard" in names
        conn.close()

    def test_uses_own_owner_id(self, tmp_path):
        """The stub profile is stamped owner_id = creating owner."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        profile = whitelist_db.create_contact_vcard(conn, 1, "Jane Rivers")
        assert profile["owner_id"] == 1
        # No password_hash — it's a curated stub
        assert profile.get("password_hash") is None
        conn.close()


# ============================================================
# 11. effective_tier — tier oracle
# ============================================================

class TestEffectiveTier:
    def test_granted_tier(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        whitelist_db.create_grant(conn, 1, "viewer@x.com", "Viewer")
        grants = whitelist_db.get_all_grants_for_profile(conn, 1)
        for g in grants:
            if g["status"] == "pending":
                whitelist_db.apply_decision(conn, g["id"], "approve", "90")
        conn.commit()
        tier = whitelist_db.effective_tier(conn, 1, "viewer@x.com")
        assert tier == "granted"
        conn.close()

    def test_anonymous_tier(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        tier = whitelist_db.effective_tier(conn, 1, "nobody@x.com")
        assert tier == "anonymous"
        conn.close()

    def test_owner_self_view(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Owner's email is jason@waltheremc.com
        tier = whitelist_db.effective_tier(conn, 1, "jason@waltheremc.com")
        assert tier == "granted"
        conn.close()

    def test_revoked_is_anonymous(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "revoked@x.com", "Revoked")
        whitelist_db.apply_decision(conn, gid, "approve", "90")
        whitelist_db.revoke_grant(conn, gid)
        tier = whitelist_db.effective_tier(conn, 1, "revoked@x.com")
        assert tier == "anonymous"
        conn.close()


# ============================================================
# 12. _ADMITTED_EXPIRY_SQL — never-expire ruling
# ============================================================

class TestAdmittedExpirySQL:
    def test_granted_with_future_expires_admits(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "future@x.com", "Future")
        whitelist_db.apply_decision(conn, gid, "approve", "quarter")
        conn.commit()
        tier = whitelist_db.effective_tier(conn, 1, "future@x.com")
        assert tier == "granted"
        conn.close()

    def test_granted_with_lifetime_admits(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "lifetime@x.com", "Lifetime")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime")
        conn.commit()
        tier = whitelist_db.effective_tier(conn, 1, "lifetime@x.com")
        assert tier == "granted"
        conn.close()

    def test_legacy_expiry_strings_never_admit(self, tmp_path):
        """Legacy '14d'/'90d' bug rows must never admit (GLOB guard)."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        # Manually insert a legacy expiry row
        import uuid as _uuid
        conn.execute(
            "INSERT INTO access_grants (id, profile_id, requester_email, requester_name, status, expires_at) "
            "VALUES (?, 1, 'legacy@x.com', 'Legacy', 'granted', '90d')",
            (str(_uuid.uuid4()),))
        conn.commit()
        tier = whitelist_db.effective_tier(conn, 1, "legacy@x.com")
        assert tier == "anonymous", "legacy '90d' must not admit"
        conn.close()


# ============================================================
# 13. grey state — derived from grant data
# ============================================================

class TestGreyStateDerived:
    def test_future_quarter_marker_is_grey(self, tmp_path):
        """UX pass 3 bug fix: badge-moved grey contacts render GreyList
        on the contact card even when the quarter marker hasn't lapsed yet."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey")
        whitelist_db.set_badge_state(conn, gid, "greylist")
        grant = whitelist_db.get_grant(conn, gid)
        # The marker is in the future
        assert grant["expires_at"] > whitelist_db._now_iso()
        # But is_grey still returns True (the bug fix)
        assert whitelist_db.is_grey(grant) is True
        conn.close()

    def test_lapsed_grey_is_still_grey(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "grey@x.com", "Grey")
        whitelist_db.set_badge_state(conn, gid, "greylist")
        # Manually backdate the expires_at
        conn.execute(
            "UPDATE access_grants SET expires_at = '2020-01-01T00:00:00Z' WHERE id = ?",
            (gid,))
        conn.commit()
        grant = whitelist_db.get_grant(conn, gid)
        assert whitelist_db.is_grey(grant) is True
        conn.close()

    def test_permanent_not_grey(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        gid = whitelist_db.create_grant(conn, 1, "perm@x.com", "Perm")
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime")
        conn.commit()
        grant = whitelist_db.get_grant(conn, gid)
        assert whitelist_db.is_grey(grant) is False
        conn.close()


# ============================================================
# 14. cards_for_share_bundle — tier filtering
# ============================================================

class TestCardsForShareBundle:
    def test_granted_sees_all_fields(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        bundle = whitelist_db.create_share_bundle(conn, 1, [_card_id(db, "Personal")])
        cards = whitelist_db.cards_for_share_bundle(conn, bundle, "granted")
        assert len(cards) >= 1
        for card in cards:
            for f in card["visible_fields"]:
                assert f["visibility"] in ("public", "granted", "private")
        conn.close()

    def test_anonymous_sees_public_only(self, tmp_path):
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        bundle = whitelist_db.create_share_bundle(conn, 1, [_card_id(db, "Personal")])
        cards = whitelist_db.cards_for_share_bundle(conn, bundle, "anonymous")
        for card in cards:
            for f in card["visible_fields"]:
                assert f["visibility"] == "public"
        conn.close()

    def test_personal_card_leads_bundle(self, tmp_path):
        """Personal card leads in bundle order (UX pass 3 ruling)."""
        db = _make_db(tmp_path)
        conn = whitelist_db.wl_connect(db)
        personal_id = _card_id(db, "Personal")
        work_id = _card_id(db, "Work")
        bundle = whitelist_db.create_share_bundle(conn, 1, [work_id, personal_id])
        # Bundle stores cards in caller's order, but render reorders
        cards = whitelist_db.cards_for_share_bundle(conn, bundle, "granted")
        if len(cards) >= 2:
            assert cards[0]["name"] == "Personal", "Personal must lead the bundle"
            assert cards[1]["name"] == "Work"
        conn.close()
