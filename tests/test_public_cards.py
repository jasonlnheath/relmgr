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
    """Profile with a public email, a granted phone, bio, and cards."""
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
    # a card via the picker (set_card_fields), so do that too, keeping the
    # card's other fields alongside the new one.
    # UX pass 3: the DEFAULT card is now PERSONAL (top card, default public
    # picture), so the public field attaches to Personal.
    pub = whitelist_db.add_profile_field(
        conn, 1, "email", "public@waltheremc.com", "public")
    personal = conn.execute(
        "SELECT id FROM cards WHERE owner_profile_id = 1 AND name = 'Personal'"
    ).fetchone()
    personal_ids = [f["id"] for f in conn.execute(
        "SELECT pf.* FROM card_fields cf "
        "JOIN profile_fields pf ON cf.field_id = pf.id WHERE cf.card_id = ?",
        (personal["id"],),
    )]
    whitelist_db.set_card_fields(conn, personal["id"], personal_ids + [pub["id"]])
    whitelist_db.update_bio(conn, 1, "I sell wheel bushings.")
    conn.close()
    return db


def test_anon_sees_default_card_only(tmp_path):
    """Anon: default card only; public fields only; no hidden notice (round-2).

    UX pass 3: the default card is PERSONAL (top card — its picture is the
    default public picture, and its public identity fields are the
    friend-finding surface).
    """
    db = _seed_full(tmp_path)
    client = TestClient(create_app(db))
    html = client.get("/p/jasonheath").text
    assert "Personal" in html
    assert "Work" not in html, "anon must not see non-default cards"
    # Public field visible, granted-visibility fields hidden.
    assert "public@waltheremc.com" in html
    assert "jheath@waltheremc.com" not in html
    assert "555-1234" not in html
    # round-2: no hidden notice or request-access taunt on public profile
    assert "Some information is hidden" not in html
    assert "Request access" not in html
    assert "Connect" in html  # round-2: Connect button replaces Request access


def test_anon_shows_bio_and_photo_block(tmp_path):
    """Anon default card includes bio text; QR renders; per-card photos removed round-2."""
    db = _seed_full(tmp_path)
    conn = whitelist_db.wl_connect(db)
    default_card = conn.execute(
        "SELECT * FROM cards WHERE owner_profile_id = 1 ORDER BY id LIMIT 1"
    ).fetchone()
    conn.close()

    client = TestClient(create_app(db))
    html = client.get("/p/jasonheath").text
    assert "I sell wheel bushings." in html, "bio must render on the public page"
    # UX pass 2 (2026-09-22): the profile QR is REMOVED — the Connect
    # button replaces it (the QR encoded only a profile link).
    assert "/qr/jasonheath" not in html, "QR removed from the public profile"
    assert "Connect" in html, "randos get a single Connect button"
    # round-2: per-card photos removed from public profile (only bio)


def test_granted_tier_sees_all_cards_and_fields(tmp_path):
    """Granted viewer: every card with >=1 visible field; bio + QR."""
    db = _seed_full(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = whitelist_db.create_grant(conn, 1, "visitor@x.com", "Visitor")
    whitelist_db.apply_decision(conn, gid, "approve", "quarter")
    conn.close()

    client = TestClient(create_app(db))
    html = client.get("/p/jasonheath?e=visitor%40x.com").text
    assert "Personal" in html
    assert "Work" in html, "granted tier must see all cards"
    # Granted-visibility fields now visible.
    assert "jheath@waltheremc.com" in html
    assert "555-1234" in html
    # round-2: no request-access taunt; Connect button only for non-granted tier
    assert "Request access" not in html
    assert "Connect" not in html  # granted tier doesn't see Connect button
    # UX pass 2: no QR anywhere on the profile either.
    assert "/qr/jasonheath" not in html


def test_owner_self_view_shows_all_cards_photos_bio(tmp_path):
    """Self-view (?e= own email -> tier granted): all cards, bio, QR.

    round-2: per-card photos removed from profile page (only QR on profile).
    round-2: Connect button only for non-granted tier.
    """
    db = _seed_full(tmp_path)

    client = TestClient(create_app(db))
    me = client.get("/p/jasonheath?e=jheath%40waltheremc.com").text
    assert "Personal" in me
    assert "Work" in me
    assert "jheath@waltheremc.com" in me
    assert "555-1234" in me
    assert "I sell wheel bushings." in me, "bio missing from self-view"
    # UX pass 2: the QR is gone from the profile (Connect replaces it); a
    # self-view (granted tier) sees neither QR nor Connect.
    assert "/qr/jasonheath" not in me, "QR removed from the profile (UX pass 2)"
    assert "Connect" not in me  # self-view (granted tier) doesn't see Connect button
    assert "Request access" not in me
    assert "Forward your card" not in me, "forward section removed (UX pass 2)"


def test_anon_still_hides_granted_fields_pin_kept(tmp_path):
    """Regression guard for the pre-B4 anonymous strip (AC #7 first half).

    round-2: no longer shows "Some information is hidden" text, but still
    hides granted-visibility fields from anonymous viewers.
    """
    db = _seed_full(tmp_path)
    client = TestClient(create_app(db))
    anon = client.get("/p/jasonheath").text
    # granted-visibility fields must still be hidden
    assert "jheath@waltheremc.com" not in anon
    assert "555-1234" not in anon
    # round-2: no hidden notice text, but Connect button present
    assert "Some information is hidden" not in anon
    assert "Connect" in anon
