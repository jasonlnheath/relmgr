"""Q36 Phase 1+2 audit — regression tests for bugs found in the delivered code.

Audit findings (2026-09-10, Jemma, live-checked against prod formats):
- A1: app._days_since/_days_until silently return 0 for every stored value.
  Prod stores date-only verified_at ('2026-09-10') and space-separated
  grant timestamps ('2026-09-05 12:34:56'); the helpers compare a naive
  datetime against an aware one -> TypeError -> swallowed by except -> 0.
  Symptom: every dashboard grant row says 'today', every profile page says
  'Verified 0 days ago'.
- A2: The test suite mutates the live contacts.db on every run —
  test_refactor_fixes.test_seed_demo_adds_aliases_idempotent runs
  seed_demo.seed_all(dry_run=False), which is hardcoded to the prod DB.
  Verified: sha256 of contacts.db changes after `pytest` (and each run appends
  a full-file backup, 13+ already). Fix: parameterized seam; tests point at
  tmp/COPIED dbs and assert the prod file is byte-identical afterwards.
- A3: The /a/{token} admin path re-implements expiry math inline (hardcoded 90)
  instead of going through apply_decision, and admin_review.html has no
  expiry <select> — so the magic-link flow can only ever produce 90d
  decisions while the dashboard offers 14/90/lifetime.
- A4: notify --what owner-link --apply emails the wrong address: it looks up
  handle 'jason_heath' (never seeded — real handle is 'jasonheath'), then
  silently falls back to `SELECT * FROM profiles LIMIT 1` (rowid order -> a
  demo persona). The dashboard link must go to Jason.

TDD: each test here RED before the fix, GREEN after. No prod data touched.
"""

import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db


# ============================================================ A1: date math

def test_days_since_handles_date_only_string():
    """'2026-09-01' (the prod verified_at format) must yield a real day count."""
    from app import days_since
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert days_since("2026-09-01") == (now - datetime(2026, 9, 1)).days


def test_days_since_handles_space_separated_timestamp():
    """'2026-09-05 12:34:56' (the prod grant created_at format) must not blow up."""
    from app import days_since
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert days_since("2026-09-05 12:34:56") == (now - datetime(2026, 9, 5, 12, 34, 56)).days


def test_days_until_handles_iso_z():
    """An ISO-8601 Z expiry must be counted in days, not fail silently to 0."""
    from app import days_until
    target = datetime.now(timezone.utc) + timedelta(days=7)
    assert days_until(target.strftime("%Y-%m-%dT%H:%M:%SZ")) >= 6


def test_dashboard_shows_grant_age_not_today(tmp_path):
    """A grant created 5 days ago must render a date, not 'today'.

    round-2: contact list shows created_at[:10] (date string) instead of
    the old 'X days ago' format. The key assertion is that the date math
    doesn't fail silently (A1 bug).

    UX pass 2 (2026-09-22): the contact LIST is condensed — the granted
    date now lives on the contact-card page's Access section, so this
    regression pins there.
    """
    from app import create_app
    from fastapi.testclient import TestClient
    import wl_tokens

    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "ageuser",
        "name": {"display": "Age User"},
        "org": {},
        "emails": [{"address": "age@co.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    prof = whitelist_db.get_profile(conn, "ageuser")
    gid = whitelist_db.create_grant(conn, prof["id"], "aged@x.com", "Aged")
    five_days_ago = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    conn.execute("UPDATE access_grants SET created_at=? WHERE id=?", (five_days_ago + " 12:00:00", gid))
    whitelist_db.apply_decision(conn, gid, "approve", "quarter")
    conn.execute("UPDATE access_grants SET granted_at=? WHERE id=?", (five_days_ago + "T12:00:00Z", gid))
    conn.commit()
    conn.close()

    client = TestClient(create_app(db))
    resp = client.get(
        f"/owner/{wl_tokens.make_token(b'test-secret', 'owner_dashboard', '1', expires_days=365)}"
        f"/contact/{gid}"
    )
    assert resp.status_code == 200
    # round-2: contact card shows date string from granted_at[:10]
    assert five_days_ago in resp.text, f"contact card must show grant date; got: {resp.text[:400]}"


def test_profile_page_shows_verified_days(tmp_path):
    """Profile page for a profile verified 8 days ago must show verified badge.

    round-2: profile shows '✓ Verified (8d)' badge instead of '8 days ago' text.
    The key assertion is that days_since doesn't fail silently (A1 bug).
    """
    from app import create_app
    from fastapi.testclient import TestClient

    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    eight_days_ago = (datetime.now(timezone.utc) - timedelta(days=8)).strftime("%Y-%m-%d")
    whitelist_db.seed_profile(conn, {
        "handle": "veruser",
        "name": {"display": "Ver User"},
        "org": {},
        "emails": [{"address": "v@co.com", "visibility": "public"}],
        "phones": [],
        "verified_at": eight_days_ago,
    })
    conn.close()

    client = TestClient(create_app(db))
    resp = client.get("/p/veruser")
    assert resp.status_code == 200
    # round-2: profile shows verified badge with day count like 'Verified (8d)'
    assert "Verified" in resp.text
    assert "8d" in resp.text, f"profile must show verified day count; got: {resp.text[:400]}"


# ============================================================ A2: prod mutation

def test_seed_demo_writes_only_to_given_db(tmp_path):
    """seed_all must accept a db path and write only there — never the prod DB."""
    from scripts import seed_demo

    canonical = tmp_path / "canonical.json"
    canonical.write_text(
        '{"handle": "jasonheath", "name": {"display": "Jason Heath"}, '
        '"org": {"company": "Walther EMC", "title": "Sales Director"}, '
        '"emails": [{"address": "jheath@waltheremc.com", "visibility": "holder"}], '
        '"phones": [], "verified_at": "2026-09-10"}'
    )
    db = tmp_path / "d.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    conn.close()

    seed_demo.seed_all(
        dry_run=False,
        db_path=db,
        canonical_path=canonical,
        exports_dir=tmp_path / "exports",
        make_backup=False,
    )
    c2 = whitelist_db.wl_connect(db)
    n = c2.execute("SELECT count(*) FROM profiles").fetchone()[0]
    n_aliases = c2.execute("SELECT count(*) FROM profile_aliases").fetchone()[0]
    c2.close()
    assert n == 5, f"expected 5 seeded profiles in tmp db, got {n}"
    # dana_reyes carries two aliases (dana-sales + dana-reyes-sales);
    # marcus/olivia/ethan one each -> 5 total.
    assert n_aliases == 5, f"expected 5 aliases, got {n_aliases}"


def test_seed_demo_full_suite_does_not_touch_prod_db(tmp_path):
    """Running the whole seed flow against a COPY of the real contacts.db
    must leave the REAL file byte-identical (the exact bug that shipped)."""
    import hashlib
    import shutil

    prod = Path("/home/jason/relmgr/contacts.db")
    if not prod.exists():
        return  # CI without the repo; nothing to guard
    before = hashlib.sha256(prod.read_bytes()).hexdigest()

    db = tmp_path / "copied.db"
    shutil.copy2(prod, db)
    canonical = Path("/home/jason/profile/jason.heath.canonical.json")
    from scripts import seed_demo
    seed_demo.seed_all(
        dry_run=False,
        db_path=db,
        canonical_path=canonical,
        exports_dir=tmp_path / "exports",
        make_backup=False,
    )
    after = hashlib.sha256(prod.read_bytes()).hexdigest()
    assert before == after, "prod contacts.db was modified by seed_all"


# ============================================================ A3: admin parity

def test_admin_review_page_offers_expiry_choice(tmp_path):
    """GET /a/{token} must offer the SAME three-way decision as the
    amber box (2026-09-26 redesign): WhiteList = lifetime, GreyList =
    quarter, BlackList — the expiry select is retired (the list choice
    IS the expiry)."""
    from app import create_app
    from fastapi.testclient import TestClient
    import wl_tokens

    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "parity",
        "name": {"display": "Parity"},
        "org": {},
        "emails": [{"address": "p@co.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    prof = whitelist_db.get_profile(conn, "parity")
    gid = whitelist_db.create_grant(conn, prof["id"], "r@x.com", "R")
    conn.close()

    client = TestClient(create_app(db))
    resp = client.get(f"/a/{wl_tokens.make_token(b'test-secret', 'grant_review', gid, expires_days=7)}")
    assert resp.status_code == 200
    for choice in ("whitelist", "greylist", "blacklist"):
        assert f'name="decision" value="{choice}"' in resp.text, \
            "admin review page carries the three-way decision"
    assert 'name="card_ids"' in resp.text, "checkbox card selection"
    assert 'name="expiry"' not in resp.text, "the expiry select is retired"


def test_admin_route_goes_through_apply_decision(tmp_path):
    """/a/{token}/decision must call whitelist_db.apply_decision (spy-proven)."""
    import app as app_module
    from app import create_app
    from fastapi.testclient import TestClient
    import wl_tokens

    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.seed_profile(conn, {
        "handle": "parity2",
        "name": {"display": "P2"},
        "org": {},
        "emails": [{"address": "p2@co.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    prof = whitelist_db.get_profile(conn, "parity2")
    gid = whitelist_db.create_grant(conn, prof["id"], "a@x.com", "A")
    conn.close()

    calls = []
    orig = app_module.whitelist_db.apply_decision

    def spy(conn, grant_id, decision, expiry_choice):
        calls.append((grant_id, decision, expiry_choice))
        return orig(conn, grant_id, decision, expiry_choice)

    app_module.whitelist_db.apply_decision = spy
    try:
        client = TestClient(create_app(db))
        resp = client.post(f"/a/{wl_tokens.make_token(b'test-secret', 'grant_review', gid, expires_days=7)}/decision",
                           data={"decision": "approve", "expiry": "90"})
        assert resp.status_code == 200
    finally:
        app_module.whitelist_db.apply_decision = orig

    assert (gid, "approve", "90") in calls, \
        f"admin decision must route through apply_decision; saw {calls}"


# ============================================================ A4: owner-link recipient

def test_owner_link_emails_jason_not_first_rowid(tmp_path):
    """--what owner-link --apply must email the canonical owner (jasonheath),
    not whatever profile happens to be rowid 1."""
    from scripts import notify as notify_mod

    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    # Rowid 1 is a DEMO persona — the old fallback would have emailed them.
    whitelist_db.seed_profile(conn, {
        "handle": "zeta_demo",
        "name": {"display": "Zeta Demo"},
        "org": {},
        "emails": [{"address": "zeta@demo.com", "visibility": "public"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    whitelist_db.seed_profile(conn, {
        "handle": "jasonheath",
        "name": {"display": "Jason Heath"},
        "org": {"company": "Walther EMC", "title": "Sales Director"},
        "emails": [{"address": "jheath@waltheremc.com", "visibility": "holder"}],
        "phones": [],
        "verified_at": "2026-09-10",
    })
    conn.close()

    sent = []
    orig = notify_mod.send_email
    notify_mod.send_email = lambda to, subj, body: sent.append((to, subj, body))
    try:
        notify_mod.notify_owner_link(dry_run=False, db_path=db)
    finally:
        notify_mod.send_email = orig

    assert len(sent) == 1, f"expected exactly 1 email, got {len(sent)}"
    assert sent[0][0] == "jheath@waltheremc.com", \
        f"owner link must go to jasonheath's email, got {sent[0][0]}"
