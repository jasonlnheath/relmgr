"""Jemma's review pass over the P1→P5 lane (2026-09-11).

Bugs found by reading, pinned here RED before fixing:

1. Decision replay resurrection — apply_decision never checks the grant's
   current status, and tokens are stateless (replayable until expiry).
   Approve → revoke → replay the old approve link = access resurrected.
   bulk_apply learned this lesson (pending-only filter); the single-decision
   path never did. Fix: only pending grants can be decided; anything else
   raises ValueError, routes surface 409/400, not a silent overwrite.

2. Junk decision values — any string that isn't 'approve' silently denied
   the grant (else-branch). Unknown decision must be rejected, not guessed.

3. merge_requester_into_contacts data loss — the existing-contact path
   REPLACED sources wholesale (erasing gmail/outlook provenance) and wrote a
   single primary email (dropping secondaries). Docstring promises "keep
   existing phones" — but not emails or sources. Fix: append-merge, dedupe.

4. merge can clobber a dedup tombstone — find_contact_by_email matched rows
   with is_duplicate=1 (93 such rows in prod carry emails). Writing into a
   loser row while the winner diverges splits the person in two. Fix: match
   live rows only (is_duplicate = 0); a tombstone never receives writes.

5. Reseed orphans the cards — seed_profile DELETEs all profile_fields and
   reinserts fresh ids; card_fields FK is ON DELETE CASCADE, so every Work/
   Personal card silently empties on reseed, and seed_default_cards won't
   repair (it skips whenever any card exists). Fix: backfill empty default
   cards by field type.
"""

import json
import os
import sys
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

import wl_tokens
import whitelist_db
from app import create_app


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "testuser",
        "name": {"display": "Test User"},
        "org": {"company": "TestCo", "title": "CTO"},
        "emails": [{"address": "owner@testco.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    conn.close()
    return db


def _grant(db, email, decide=None, expiry="90"):
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    gid = whitelist_db.create_grant(conn, profile["id"], email, "Req")
    if decide:
        whitelist_db.apply_decision(conn, gid, decide, expiry)
    conn.close()
    return gid


# ============================================================
# 1 + 2: decision guards in apply_decision
# ============================================================

def test_apply_decision_blocks_already_granted(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "a@x.com", decide="approve")
    conn = whitelist_db.wl_connect(db)
    with pytest.raises(ValueError):
        whitelist_db.apply_decision(conn, gid, "deny", "90")
    assert whitelist_db.get_grant(conn, gid)["status"] == "granted"
    conn.close()


def test_apply_decision_blocks_revoked(tmp_path):
    """The resurrection case: revoked must never become decided-again."""
    db = _make_db(tmp_path)
    gid = _grant(db, "a@x.com", decide="approve")
    conn = whitelist_db.wl_connect(db)
    whitelist_db.revoke_grant(conn, gid)
    with pytest.raises(ValueError):
        whitelist_db.apply_decision(conn, gid, "approve", "lifetime")
    assert whitelist_db.get_grant(conn, gid)["status"] == "revoked"
    conn.close()


def test_apply_decision_rejects_unknown_decision_value(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "a@x.com")
    conn = whitelist_db.wl_connect(db)
    with pytest.raises(ValueError):
        whitelist_db.apply_decision(conn, gid, "obliterate", "90")
    assert whitelist_db.get_grant(conn, gid)["status"] == "pending"
    conn.close()


def test_replayed_approve_link_cannot_resurrect_revoked(tmp_path):
    """End-to-end: old admin link replayed after revoke must not restore access."""
    db = _make_db(tmp_path)
    gid = _grant(db, "req@x.com", decide="approve")
    token = wl_tokens.make_token(b"test-secret", "grant_review", gid, expires_days=7)

    conn = whitelist_db.wl_connect(db)
    whitelist_db.revoke_grant(conn, gid)
    conn.close()

    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision", data={"decision": "approve", "expiry": "90"})
    assert resp.status_code in (400, 409), f"replay must be rejected, got {resp.status_code}"

    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, gid)
    conn.close()
    assert grant["status"] == "revoked", "replayed link resurrected access!"


def test_junk_decision_route_not_200(tmp_path):
    db = _make_db(tmp_path)
    gid = _grant(db, "req@x.com")
    token = wl_tokens.make_token(b"test-secret", "grant_review", gid, expires_days=7)
    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision", data={"decision": "nuke", "expiry": "90"})
    assert resp.status_code in (400, 409), f"junk decision got {resp.status_code}"
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.get_grant(conn, gid)["status"] == "pending"
    conn.close()


def test_bulk_still_survives_vanished_rows(tmp_path):
    """bulk_apply pre-filters pending; its dead-row skip semantics stay."""
    db = _make_db(tmp_path)
    g1 = _grant(db, "a@x.com", decide="approve")   # not pending -> skipped
    g2 = _grant(db, "b@x.com")
    conn = whitelist_db.wl_connect(db)
    summary = whitelist_db.bulk_apply(conn, [g1, g2], "approve", "14")
    assert summary["approved"] == 1 and summary["skipped"] == 1, summary
    conn.close()


# ============================================================
# 3 + 4: merge safety on the contacts table
# ============================================================

def _contacts_only_db(tmp_path):
    db = tmp_path / "c.db"
    conn = whitelist_db.wl_connect(db)
    conn.executescript("""
        CREATE TABLE grant_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            grant_id TEXT NOT NULL, profile_id INTEGER NOT NULL,
            action TEXT NOT NULL, requested_expiry TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')));
    """)
    conn.execute("""
        CREATE TABLE contacts (
            id TEXT PRIMARY KEY, normalized_name TEXT NOT NULL,
            first_name TEXT, last_name TEXT,
            emails TEXT DEFAULT '[]', phones TEXT DEFAULT '[]',
            organizations TEXT DEFAULT '[]', sources TEXT DEFAULT '[]',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            is_duplicate INTEGER DEFAULT 0, merged_into TEXT)
    """)
    conn.commit()
    return conn


def test_merge_preserves_existing_sources_and_emails(tmp_path):
    """Whitelist name may win, but provenance and secondary emails must survive."""
    conn = _contacts_only_db(tmp_path)
    conn.execute(
        "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate)"
        " VALUES ('c1','Old Name',?,?,datetime('now'),datetime('now'),0)",
        (json.dumps([{"address": "alice@example.com", "type": "primary"},
                     {"address": "alice.alt@example.com", "type": "home"}]),
         json.dumps([{"source": "gmail", "source_id": "m1"}])),
    )
    conn.commit()
    result = whitelist_db.merge_requester_into_contacts(conn, {
        "id": "g1", "profile_id": 1,
        "requester_email": "alice@example.com", "requester_name": "Alice W",
    })
    assert result["normalized_name"] == "Alice W"
    emails = json.loads(result["emails"])
    addrs = {e["address"] for e in emails}
    assert "alice.alt@example.com" in addrs, f"secondary email dropped: {addrs}"
    sources = json.loads(result["sources"])
    src_names = {str(s.get("source", s)) for s in sources}
    assert "gmail" in src_names, f"gmail provenance erased: {src_names}"
    assert any("whitelist-merge" in str(s) for s in sources)
    conn.close()


def test_merge_is_idempotent_on_sources(tmp_path):
    """Re-merging must not duplicate the whitelist-merge source entry."""
    conn = _contacts_only_db(tmp_path)
    grant = {"id": "g1", "profile_id": 1,
             "requester_email": "bob@example.com", "requester_name": "Bob"}
    whitelist_db.merge_requester_into_contacts(conn, grant)   # creates row
    r2 = whitelist_db.merge_requester_into_contacts(conn, grant)  # updates row
    sources = json.loads(r2["sources"])
    wl_sources = [s for s in sources if "whitelist-merge" in str(s)]
    assert len(wl_sources) == 1, f"source duplicated on re-merge: {sources}"
    conn.close()


def test_merge_never_writes_to_dedup_tombstone(tmp_path):
    """is_duplicate=1 loser rows must not receive merge writes."""
    conn = _contacts_only_db(tmp_path)
    conn.execute(
        "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate, merged_into)"
        " VALUES ('loser','Dead Loser',?,'[]',datetime('now'),datetime('now'),1,'winner1')",
        (json.dumps([{"address": "carol@example.com", "type": "primary"}]),),
    )
    conn.commit()
    result = whitelist_db.merge_requester_into_contacts(conn, {
        "id": "g9", "profile_id": 1,
        "requester_email": "carol@example.com", "requester_name": "Carol Live",
    })
    assert result is not None
    assert result["id"] != "loser", "merge wrote into a dedup tombstone!"
    loser = conn.execute("SELECT normalized_name FROM contacts WHERE id='loser'").fetchone()
    assert loser["normalized_name"] == "Dead Loser"
    live = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate=0").fetchone()[0]
    assert live == 1
    conn.close()


def test_find_contact_skips_tombstones():
    """find_contact_by_email must return None for duplicate-flagged rows."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        conn = _contacts_only_db(Path(td))
        conn.execute(
            "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate)"
            " VALUES ('t1','Tomb',?,'[]',datetime('now'),datetime('now'),1)",
            (json.dumps([{"address": "d@x.com", "type": "primary"}]),),
        )
        conn.commit()
        assert whitelist_db.find_contact_by_email(conn, "d@x.com") is None
        conn.close()


# ============================================================
# 5: reseed orphans the default cards
# ============================================================

def test_default_cards_reattach_after_profile_reseed(tmp_path):
    db = tmp_path / "r.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)
    data = {
        "handle": "jasonheath", "name": {"display": "Jason"},
        "org": {},
        "emails": [{"address": "j@w.com", "visibility": "public"}],
        "phones": [{"number": "+1555", "visibility": "holder"}],
    }
    whitelist_db.seed_profile(conn, data)
    whitelist_db.ensure_whitelist_schema(conn)   # boot after profile exists -> seeds cards

    cards = {c["name"]: c for c in whitelist_db.list_cards(conn, 1)}
    assert set(cards) == {"Work", "Personal"}
    assert len(cards["Work"]["fields"]) == 1 and len(cards["Personal"]["fields"]) == 1

    # Reseed: seed_profile deletes + reinserts fields (cascade empties card_fields)
    whitelist_db.seed_profile(conn, data)
    cards = {c["name"]: c for c in whitelist_db.list_cards(conn, 1)}
    assert len(cards["Work"]["fields"]) == 0  # proves the cascade-orphan is real

    # Boot self-heal must backfill them again
    whitelist_db.seed_default_cards(conn)
    cards = {c["name"]: c for c in whitelist_db.list_cards(conn, 1)}
    assert len(cards["Work"]["fields"]) == 1, "Work card still empty after heal"
    assert len(cards["Personal"]["fields"]) == 1, "Personal card still empty after heal"
    conn.close()
