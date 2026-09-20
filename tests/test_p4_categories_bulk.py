"""P4: custom context categories + bulk grant actions.

Two Jason-ruled features from the P3 open questions (2026-09-10):
- Custom categories: registry gets a sanctioned add path (normalized, no
  duplicates) and a dashboard form; set_grant_context's no-free-text rule
  still holds — you can only pick what's in the registry.
- Bulk actions: approve/deny pending grants and revoke granted ones in one
  shot. Per-grant scoping: approve/deny ONLY touch 'pending', revoke ONLY
  touches 'granted'; everything else is skipped, never silently rewritten.
  One dead row must not abort the batch.
"""

import os
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
import wl_tokens
from app import create_app
from fastapi.testclient import TestClient


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "dana_reyes",
        "name": {"display": "Dana Reyes"},
        "emails": [{"address": "dana.r@northgatefreight.com", "visibility": "connection"}],
        "verified_at": "2026-09-01",
    })
    conn.close()
    return db


def _grant(db, email, decide=None):
    """Create a pending grant; optionally apply approve/deny first."""
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "dana_reyes")
    gid = whitelist_db.create_grant(conn, profile["id"], email, "Tester")
    if decide:
        whitelist_db.apply_decision(conn, gid, decide, "90")
    conn.close()
    return gid


def _owner_client(db):
    token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
    return TestClient(create_app(db)), token


# --------------------------------------------------- P4-T1 custom categories

def test_add_context_category_normalizes_and_stores(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    row = whitelist_db.add_context_category(conn, "  Fleet-Client  ")
    assert row is not None and row["category"] == "fleet-client", repr(row)
    cats = [r["category"] for r in whitelist_db.list_contexts(conn)]
    assert "fleet-client" in cats
    # appended after built-ins (registry order stays stable for the UI)
    assert cats[-1] == "fleet-client", cats
    conn.close()


def test_add_context_category_rejects_duplicates_any_case(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.add_context_category(conn, "Vendor") is None      # builtin
    first = whitelist_db.add_context_category(conn, "fleet-client")       # fresh insert
    assert first is not None and first["category"] == "fleet-client"
    assert whitelist_db.add_context_category(conn, "FLEET_CLIENT".replace("_", "-")) is None
    n = conn.execute("SELECT count(*) FROM grant_contexts").fetchone()[0]
    assert n == 7, f"duplicate must not insert: {n} rows"
    conn.close()


def test_add_context_category_rejects_blank(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.add_context_category(conn, "") is None
    assert whitelist_db.add_context_category(conn, "   ") is None
    assert whitelist_db.add_context_category(conn, None) is None
    conn.close()


def test_custom_category_usable_by_set_grant_context(tmp_path):
    """The point of the feature: add 'fleet-client', tag a grant with it.
    set_grant_context stays registry-driven (no free-text) — this proves the
    new row is a first-class registry member."""
    db = _make_db(tmp_path)
    gid = _grant(db, "tagger@x.com")
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.add_context_category(conn, "fleet-client") is not None
    updated = whitelist_db.set_grant_context(conn, gid, "fleet-client")
    assert updated is not None and updated["context"] == "fleet-client", repr(updated)
    conn.close()


# NOTE 2026-09-12: Jason cut the context/category feature from the product UI.
# test_route_add_context_category and test_dashboard_renders_add_category_form
# were removed along with their routes. DB-layer registry tests above stay —
# the functions and historical data remain intact.


# ------------------------------------------------------- P4-T2 bulk actions

def test_bulk_approve_pending_only(tmp_path):
    db = _make_db(tmp_path)
    g1 = _grant(db, "one@x.com")
    g2 = _grant(db, "two@x.com")
    g3 = _grant(db, "three@x.com", decide="deny")  # denied — must not resurrect

    conn = whitelist_db.wl_connect(db)
    summary = whitelist_db.bulk_apply(conn, [g1, g2, g3], "approve", "90")
    assert summary == {"approved": 2, "denied": 0, "revoked": 0, "skipped": 1}, summary
    statuses = {g: whitelist_db.get_grant(conn, g)["status"] for g in (g1, g2, g3)}
    assert statuses == {g1: "granted", g2: "granted", g3: "denied"}, statuses
    # audit rows written per applied transition (T2 convention intact)
    n_appr = conn.execute("SELECT count(*) FROM grant_logs WHERE action='approved'").fetchone()[0]
    assert n_appr == 2, f"approved audit rows: {n_appr}"
    conn.close()


def test_bulk_revoke_granted_only_skips_dead_rows(tmp_path):
    db = _make_db(tmp_path)
    g1 = _grant(db, "live@x.com", decide="approve")
    g2 = _grant(db, "pending@x.com")               # not granted -> skip
    fake = "00000000-dead-beef-0000-000000000000"  # unknown -> skip

    conn = whitelist_db.wl_connect(db)
    summary = whitelist_db.bulk_apply(conn, [g1, g2, fake], "revoke")
    assert summary == {"approved": 0, "denied": 0, "revoked": 1, "skipped": 2}, summary
    assert whitelist_db.get_grant(conn, g1)["status"] == "revoked"
    assert whitelist_db.get_grant(conn, g2)["status"] == "pending"
    # granted_at preserved on revoke (history rule from P3-T1)
    assert whitelist_db.get_grant(conn, g1)["granted_at"] is not None
    conn.close()


def test_bulk_dedupes_repeated_ids(tmp_path):
    db = _make_db(tmp_path)
    g1 = _grant(db, "dup@x.com")
    conn = whitelist_db.wl_connect(db)
    summary = whitelist_db.bulk_apply(conn, [g1, g1, g1], "approve", "14")
    assert summary["approved"] == 1, f"idempotent per id: {summary}"
    n = conn.execute("SELECT count(*) FROM grant_logs WHERE action='approved' AND grant_id=?",
                     (g1,)).fetchone()[0]
    assert n == 1, f"double-submit must not double-log: {n} rows"
    conn.close()


def test_bulk_route_revoke_multiple(tmp_path):
    db = _make_db(tmp_path)
    g1 = _grant(db, "a@x.com", decide="approve")
    g2 = _grant(db, "b@x.com", decide="approve")
    g3 = _grant(db, "c@x.com")  # pending — revoke must not touch it

    client, tok = _owner_client(db)
    r = client.post(f"/owner/{tok}/bulk", data={
        "grant_ids": [g1, g2, g3],
        "decision": "revoke",
    }, follow_redirects=False)
    assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text[:200]}"

    conn = whitelist_db.wl_connect(db)
    st = {g: whitelist_db.get_grant(conn, g)["status"] for g in (g1, g2, g3)}
    conn.close()
    assert st == {g1: "revoked", g2: "revoked", g3: "pending"}, st


def test_bulk_route_approve_with_expiry(tmp_path):
    db = _make_db(tmp_path)
    g1 = _grant(db, "a@x.com")
    g2 = _grant(db, "b@x.com")
    client, tok = _owner_client(db)
    r = client.post(f"/owner/{tok}/bulk", data={
        "grant_ids": [g1, g2],
        "decision": "approve", "expiry": "lifetime",
    }, follow_redirects=False)
    assert r.status_code == 200, f"{r.status_code}: {r.text[:200]}"

    conn = whitelist_db.wl_connect(db)
    for g in (g1, g2):
        grant = whitelist_db.get_grant(conn, g)
        assert grant["status"] == "granted" and grant["expires_at"] is None, \
            f"lifetime bulk approve failed: {grant}"
    conn.close()


def test_bulk_route_rejects_empty_selection_and_bad_decision(tmp_path):
    db = _make_db(tmp_path)
    client, tok = _owner_client(db)
    r1 = client.post(f"/owner/{tok}/bulk", data={"decision": "approve"},
                     follow_redirects=False)
    assert r1.status_code == 400, f"empty selection must be 400, got {r1.status_code}"
    g1 = _grant(db, "z@x.com")
    r2 = client.post(f"/owner/{tok}/bulk", data=[
        ("grant_ids", g1), ("decision", "obliterate"),
    ], follow_redirects=False)
    assert r2.status_code == 400, f"unknown decision must be 400, got {r2.status_code}"


def test_dashboard_renders_bulk_checkboxes(tmp_path):
    """Bulk checkboxes were removed from contacts.html (P5-T3).

    The bulk routes (/owner/{token}/bulk) still exist and work —
    test_bulk_route_rejects_empty_selection_and_bad_decision covers that.
    The contacts.html template no longer renders bulk checkboxes or the
    bulk action form.
    """
    db = _make_db(tmp_path)
    g1 = _grant(db, "box@x.com")
    client, tok = _owner_client(db)
    page = client.get(f"/owner/{tok}").text
    # contacts.html replaced the dashboard — bulk checkboxes are gone
    assert f'/owner/{tok}/bulk' not in page, "contacts.html must not offer the bulk form"
