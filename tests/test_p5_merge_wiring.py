"""P5 wiring: approve → merge requester into contacts (2026-09-11).

Design (Jason's ruling pending between auto vs explicit — auto chosen as
default because it's idempotent + fully audited; opt-out flag keeps the
explicit-button option alive without another schema change):

- apply_decision(conn, gid, decision, expiry, merge_contacts=True)
- On approve ONLY: after the status write, merge requester into contacts.db.
- Merge is idempotent (re-approve of a dead grant can't happen post-guard;
  re-merge on the same email updates name, never duplicates rows/sources).
- Deny never merges. Replay/junk still raise before anything is written.
- Audit: existing 'approved' row + merge's own 'merged' row (already logged
  inside merge_requester_into_contacts).

These tests are fully hermetic — no ambient fixture files.
"""

import json
import os
import sqlite3
import sys
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from fastapi.testclient import TestClient

import wl_tokens
import whitelist_db
from app import create_app


def _make_fixture(tmp_path: Path) -> Path:
    """Create a hermetic fixture DB with the same schema + seed data
    that the old gitignored backup provided. No ambient files needed."""
    db = tmp_path / "fixture.db"
    import store
    store.init_db(db)  # creates contacts + contact_sources + dedup_log
    conn = whitelist_db.wl_connect(db)
    whitelist_db.ensure_whitelist_schema(conn)

    # Seed the owner profile
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "VP Sales"},
        "emails": [
            {"address": "jheath@waltheremc.com", "visibility": "public"},
            {"address": "jason@waltheremc.com", "visibility": "granted"},
        ],
        "phones": [{"number": "+15551234567", "visibility": "public"}],
        "verified_at": "2026-03-15T10:00:00Z",
        "bio": "I sell wheel bushings.",
    })

    # Seed some contacts that simulate what the backup had
    conn.execute(
        "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate)"
        " VALUES ('g1','Alice Smith',?,?,datetime('now'),datetime('now'),0)",
        (json.dumps([{"address": "alice@example.com", "type": "primary"}]),
         json.dumps([{"source": "gmail", "source_id": "g1"}])),
    )
    conn.execute(
        "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate)"
        " VALUES ('g2','Bob Jones',?,?,datetime('now'),datetime('now'),0)",
        (json.dumps([{"address": "bob@example.com", "type": "primary"}]),
         json.dumps([{"source": "gmail", "source_id": "g2"}])),
    )
    conn.execute(
        "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate)"
        " VALUES ('v1','Carol Davis',?,?,datetime('now'),datetime('now'),0)",
        (json.dumps([{"address": "carol@example.com", "type": "primary"}]),
         json.dumps([{"source": "vcf", "source_id": "v1"}])),
    )
    conn.commit()
    conn.close()
    return db


def _seed_owner_and_grant(db: Path, email="newperson@example.com", name="New Person"):
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "jasonheath")
    if profile is None:
        whitelist_db.ensure_whitelist_schema(conn)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath", "name": {"display": "Jason Heath"}, "org": {},
            "emails": [{"address": "jheath@waltheremc.com", "visibility": "public"}],
            "phones": [],
        })
        profile = whitelist_db.get_profile(conn, "jasonheath")
    gid = whitelist_db.create_grant(conn, profile["id"], email, name)
    conn.close()
    return gid


# ============================================================
# 1. approve merges by default
# ============================================================

def test_approve_merges_requester_into_contacts(tmp_path):
    db = _make_fixture(tmp_path)
    before_live = None
    conn = whitelist_db.wl_connect(db)
    before_live = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate=0").fetchone()[0]
    gid = _seed_owner_and_grant_on_conn(conn, "brandnew@example.com", "Brand New")
    whitelist_db.apply_decision(conn, gid, "approve", "90")
    after_live = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate=0").fetchone()[0]

    row = whitelist_db.find_contact_by_email(conn, "brandnew@example.com")
    assert row is not None, "approve did not merge requester into contacts"
    assert row["normalized_name"] == "Brand New"
    assert after_live == before_live + 1, "merge should add exactly one live contact"

    logs = [r["action"] for r in conn.execute(
        "SELECT action FROM grant_logs WHERE grant_id = ? ORDER BY id", (gid,)
    ).fetchall()]
    assert "approved" in logs and "merged" in logs, f"audit missing merge: {logs}"
    conn.close()


def _seed_owner_and_grant_on_conn(conn, email, name):
    profile = whitelist_db.get_profile(conn, "jasonheath")
    if profile is None:
        whitelist_db.ensure_whitelist_schema(conn)
        whitelist_db.seed_profile(conn, {
            "handle": "jasonheath", "name": {"display": "Jason Heath"}, "org": {},
            "emails": [{"address": "jheath@waltheremc.com", "visibility": "public"}],
            "phones": [],
        })
        profile = whitelist_db.get_profile(conn, "jasonheath")
    return whitelist_db.create_grant(conn, profile["id"], email, name)


def test_deny_never_merges(tmp_path):
    db = _make_fixture(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = _seed_owner_and_grant_on_conn(conn, "noshow@example.com", "No Show")
    whitelist_db.apply_decision(conn, gid, "deny", "90")
    assert whitelist_db.find_contact_by_email(conn, "noshow@example.com") is None
    logs = [r["action"] for r in conn.execute(
        "SELECT action FROM grant_logs WHERE grant_id = ? ORDER BY id", (gid,)
    ).fetchall()]
    assert "merged" not in logs
    conn.close()


def test_merge_contacts_opt_out(tmp_path):
    db = _make_fixture(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = _seed_owner_and_grant_on_conn(conn, "skipme@example.com", "Skip Me")
    whitelist_db.apply_decision(conn, gid, "approve", "90", merge_contacts=False)
    assert whitelist_db.find_contact_by_email(conn, "skipme@example.com") is None
    conn.close()


def test_approve_matching_existing_contact_updates_name_not_duplicates(tmp_path):
    """Existing gmail contact approved via Whitelist: name wins, row count stable."""
    db = _make_fixture(tmp_path)
    conn = whitelist_db.wl_connect(db)
    conn.execute(
        "INSERT INTO contacts (id, normalized_name, emails, sources, created_at, updated_at, is_duplicate)"
        " VALUES ('gmatch','Old Gmail Name',?,?,datetime('now'),datetime('now'),0)",
        (json.dumps([{"address": "matchy@example.com", "type": "primary"}]),
         json.dumps([{"source": "gmail", "source_id": "m1"}])),
    )
    conn.commit()
    before = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate=0").fetchone()[0]
    gid = _seed_owner_and_grant_on_conn(conn, "matchy@example.com", "Matchy Whitelist")
    whitelist_db.apply_decision(conn, gid, "approve", "90")
    after = conn.execute("SELECT COUNT(*) FROM contacts WHERE is_duplicate=0").fetchone()[0]

    row = whitelist_db.find_contact_by_email(conn, "matchy@example.com")
    assert row["normalized_name"] == "Matchy Whitelist"
    assert after == before, f"duplicate created! {before} -> {after}"
    srcs = json.loads(row["sources"])
    assert any(str(s.get("source", s)) == "gmail" for s in srcs), "provenance lost"
    conn.close()


# ============================================================
# 2. route-level: the dashboard/admin approve path triggers merge
# ============================================================

def test_admin_route_approve_merges(tmp_path):
    db = _make_fixture(tmp_path)
    gid = _seed_owner_and_grant(db, "routemerge@example.com", "Route Merge")
    token = wl_tokens.make_token(b"test-secret", "grant_review", gid, expires_days=7)
    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision", data={"decision": "approve", "expiry": "90"})
    assert resp.status_code == 200
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.find_contact_by_email(conn, "routemerge@example.com") is not None
    conn.close()


# ============================================================
# 3. hermeticity of the whole thing on the copy: run twice, stable
# ============================================================

def test_double_approve_attempt_is_audited_and_not_double_merged(tmp_path):
    """Guard first (replay raises), so merge runs at most once per grant."""
    db = _make_fixture(tmp_path)
    conn = whitelist_db.wl_connect(db)
    gid = _seed_owner_and_grant_on_conn(conn, "once@example.com", "Once Only")
    whitelist_db.apply_decision(conn, gid, "approve", "90")
    with pytest.raises(ValueError):
        whitelist_db.apply_decision(conn, gid, "approve", "90")
    rows = conn.execute(
        "SELECT COUNT(*) FROM contacts WHERE is_duplicate=0"
    ).fetchone()[0]
    merged_count = conn.execute(
        "SELECT COUNT(*) FROM grant_logs WHERE action='merged' AND grant_id=?", (gid,)
    ).fetchone()[0]
    assert merged_count == 1
    conn.close()
