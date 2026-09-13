"""Jemma review (2026-09-12): spec B4 — public page uses cards.

The /p/{handle} page must render the owner's CARDS, not a flat field list:
- Anonymous tier: default card (lowest cards.id for the owner) only — photo,
  name/title/company, bio, fields with visibility='public' — then the
  existing "Some information is hidden / Request access" block.
- Granted tier (incl. owner self-view via ?e= own email): ALL cards that have
  >=1 field the viewer may see (visibility public|granted); photos visible.
  No request-access taunt.

Pins the missing feature: profile.html still renders a flat list with no
cards, no photos, no bio.
"""
import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from app import create_app


def _seed_full(tmp_path: Path) -> Path:
    """Profile with a public email, a granted phone, bio, and two cards."""
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
    # A public field must exist so the anon default card shows something.
    # B3: add_profile_field is an insert only — the owner attaches a field to
    # a card via the picker (set_card_fields), so do that too, keeping Work's
    # seeded fields alongside the new one.
    pub = whitelist_db.add_profile_field(
        conn, 1, "email", "public@waltheremc.com", "public")
    work = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Work'"
    ).fetchone()
    work_ids = [f["id"] for f in conn.execute(
        "SELECT pf.* FROM card_fields cf "
        "JOIN profile_fields pf ON cf.field_id = pf.id WHERE cf.card_id = ?",
        (work["id"],),
    )]
    whitelist_db.set_card_fields(conn, work["id"], work_ids + [pub["id"]])
    whitelist_db.update_bio(conn, 1, "I sell wheel bushings.")
    conn.close()
    return db


def test_anon_sees_default_card_only(tmp_path):
    """Anon: default (lowest id) card only; public fields only; hidden notice kept."""
    db = _seed_full(tmp_path)
    client = TestClient(create_app(db))
    html = client.get("/p/jasonheath").text
    # Work is the default card (lowest id from seed_default_cards).
    assert "Work" in html
    assert "Personal" not in html, "anon must not see non-default cards"
    # Public field visible, granted-visibility fields hidden.
    assert "public@waltheremc.com" in html
    assert "jheath@waltheremc.com" not in html
    assert "555-1234" not in html
    # Existing taunt stays exactly as now for anon.
    assert "Some information is hidden" in html
    assert "Request access" in html


def test_anon_shows_bio_and_photo_block(tmp_path):
    """Anon default card includes bio text; photo renders when set."""
    db = _seed_full(tmp_path)
    # Give the default card a photo path (file absence is fine for markup).
    conn = whitelist_db.wl_connect(db)
    default_card = conn.execute(
        "SELECT * FROM cards WHERE owner_profile_id = 1 ORDER BY id LIMIT 1"
    ).fetchone()
    whitelist_db.update_card_photo(conn, default_card["id"],
                                   f"1_{default_card['id']}.jpg")
    conn.close()

    client = TestClient(create_app(db))
    html = client.get("/p/jasonheath").text
    assert "I sell wheel bushings." in html, "bio must render on the public page"
    assert f"/photos/1/{default_card['id']}" in html, "default card photo missing"


def test_granted_tier_sees_all_cards_and_fields(tmp_path):
    """Granted viewer: every card with >=1 visible field; photos + bio."""
    db = _seed_full(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = whitelist_db.create_grant(conn, 1, "visitor@x.com", "Visitor")
    whitelist_db.apply_decision(conn, gid, "approve", "quarter")
    conn.close()

    client = TestClient(create_app(db))
    html = client.get("/p/jasonheath?e=visitor%40x.com").text
    assert "Work" in html
    assert "Personal" in html, "granted tier must see all cards"
    # Granted-visibility fields now visible.
    assert "jheath@waltheremc.com" in html
    assert "555-1234" in html
    # No taunt for granted viewers.
    assert "Request access" not in html


def test_owner_self_view_shows_all_cards_photos_bio(tmp_path):
    """Self-view (?e= own email -> tier granted): all cards, photos, bio."""
    db = _seed_full(tmp_path)
    conn = whitelist_db.wl_connect(db)
    # Photo on the second card too — self-view must show it.
    cards = list(conn.execute(
        "SELECT * FROM cards WHERE owner_profile_id = 1 ORDER BY id").fetchall())
    for c in cards:
        whitelist_db.update_card_photo(conn, c["id"], f"1_{c['id']}.jpg")
    conn.close()

    client = TestClient(create_app(db))
    me = client.get("/p/jasonheath?e=jheath%40waltheremc.com").text
    assert "Work" in me
    assert "Personal" in me
    assert "jheath@waltheremc.com" in me
    assert "555-1234" in me
    assert "I sell wheel bushings." in me, "bio missing from self-view"
    assert f"/photos/1/{cards[0]['id']}" in me
    assert f"/photos/1/{cards[1]['id']}" in me
    assert "Request access" not in me


def test_anon_still_hides_granted_fields_pin_kept(tmp_path):
    """Regression guard for the pre-B4 anonymous strip (AC #7 first half)."""
    db = _seed_full(tmp_path)
    client = TestClient(create_app(db))
    anon = client.get("/p/jasonheath").text
    assert "Some information is hidden" in anon
    assert "jheath@waltheremc.com" not in anon
