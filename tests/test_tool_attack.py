"""Tool-attack regression tests (2026-09-26, branch
fm/whitelist-tool-attack) — live-fire findings from the BlackArch
toolchain evaluation (nmap/nikto/ffuf/sqlmap + manual batteries):

T1  WHITELIST_RATELIMIT_DISABLED parsed with bool(value): any non-empty
    string — including "0", "false", "no" — silently DISABLED the
    per-IP rate limiter. A deployer writing the natural "off" spelling
    killed a security control with no signal. Verified live: 24
    request-POSTs all 200 with the flag set to "0"; now only the
    explicit truthy set (1/true/yes/on) switches the limiter off.

T2  record_scan capped the stored email LENGTH (audit 2 / A1) but not
    the ROW RATE: ~600 GET rows/s measured against the live instance,
    with ?e= email rotation defeating any per-email dedupe — an
    unauthenticated disk-fill / WAL-churn vector on surfaces the
    POST-only limiter never covers. Now bounded at _SCAN_DAY_MAX rows
    per profile per UTC day.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("WHITELIST_SECRET", "test-secret")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
from fastapi.testclient import TestClient

from app import create_app


def _setup_two_owners(tmp_path):
    """alice (profile 1) + mallory (profile 2), default cards seeded."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_owner_profile(
        conn, "alice", "Alice Owner", "alice@victim.example", "pw-alice-123")
    whitelist_db.create_owner_profile(
        conn, "mallory", "Mallory Attacker", "mallory@attacker.example",
        "pw-mallory-123")
    whitelist_db.seed_default_cards(conn)
    conn.close()
    return db


def _make_db(tmp_path):
    db = tmp_path / "wl.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.ensure_whitelist_schema(conn)
    conn.close()
    return db


# ============================================================
# T1 — rate-limit flag must parse a truthy SET, not bool(string)
# ============================================================

def test_t1_flag_zero_keeps_limiter_on(tmp_path, monkeypatch):
    monkeypatch.setenv("WHITELIST_RATELIMIT_DISABLED", "0")
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    codes = [client.post("/p/alice/request",
                         data={"name": "n", "email": "e@x.com"}).status_code
             for _ in range(12)]
    assert codes[-1] == 429, \
        f"DISABLED=0 must leave the limiter ON; got {codes}"


def test_t1_flag_false_keeps_limiter_on(tmp_path, monkeypatch):
    monkeypatch.setenv("WHITELIST_RATELIMIT_DISABLED", "false")
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    codes = [client.post("/p/alice/request",
                         data={"name": "n", "email": "e@x.com"}).status_code
             for _ in range(12)]
    assert codes[-1] == 429, \
        f"DISABLED=false must leave the limiter ON; got {codes}"


def test_t1_flag_true_still_disables(tmp_path, monkeypatch):
    monkeypatch.setenv("WHITELIST_RATELIMIT_DISABLED", "true")
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    codes = [client.post("/p/alice/request",
                         data={"name": "n", "email": "e@x.com"}).status_code
             for _ in range(12)]
    assert 429 not in codes, f"DISABLED=true must keep working; got {codes}"


def test_t1_flag_one_still_disables(tmp_path, monkeypatch):
    monkeypatch.setenv("WHITELIST_RATELIMIT_DISABLED", "1")
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    codes = [client.post("/p/alice/request",
                         data={"name": "n", "email": "e@x.com"}).status_code
             for _ in range(12)]
    assert 429 not in codes, f"DISABLED=1 must keep working; got {codes}"


# ============================================================
# T2 — scan-event row rate is bounded per profile per day
# ============================================================

def test_t2_scan_rows_capped_per_profile_per_day(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_owner_profile(
        conn, "alice", "Alice Owner", "alice@victim.example", "pw-alice-123")
    whitelist_db.create_owner_profile(
        conn, "mallory", "Mallory Attacker", "mallory@attacker.example",
        "pw-mallory-123")
    whitelist_db.seed_default_cards(conn)

    cap = whitelist_db._SCAN_DAY_MAX
    # Flood profile 1 with rotating emails (email dedupe is useless).
    for i in range(cap + 25):
        whitelist_db.record_scan(conn, 1, f"flood{i}@x.test")
    n1 = conn.execute(
        "SELECT COUNT(*) FROM scan_events WHERE profile_id = 1").fetchone()[0]
    assert n1 == cap, f"row count must cap at {cap}, got {n1}"

    # A different profile's scans are unaffected by profile 1's flood.
    whitelist_db.record_scan(conn, 2, "other@x.test")
    n2 = conn.execute(
        "SELECT COUNT(*) FROM scan_events WHERE profile_id = 2").fetchone()[0]
    conn.close()
    assert n2 == 1, f"profile 2 must not inherit profile 1's cap; got {n2}"


def test_t2_scan_rows_below_cap_insert_normally(tmp_path):
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_owner_profile(
        conn, "alice", "Alice Owner", "alice@victim.example", "pw-alice-123")
    whitelist_db.seed_default_cards(conn)
    for i in range(10):
        whitelist_db.record_scan(conn, 1, f"v{i}@x.test")
    whitelist_db.record_scan(conn, 1, None)  # anonymous view still a scan
    n = conn.execute(
        "SELECT COUNT(*) FROM scan_events WHERE profile_id = 1").fetchone()[0]
    conn.close()
    assert n == 11, f"legit under-cap scans must all insert; got {n}"


def test_t2_scan_cap_survives_get_scan_stats(tmp_path):
    """The chart reader keeps working at (and past) the cap."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.create_owner_profile(
        conn, "alice", "Alice Owner", "alice@victim.example", "pw-alice-123")
    whitelist_db.seed_default_cards(conn)
    cap = whitelist_db._SCAN_DAY_MAX
    for i in range(cap + 5):
        whitelist_db.record_scan(conn, 1, f"f{i}@x.test")
    stats = whitelist_db.get_scan_stats(conn, 1)
    conn.close()
    assert len(stats) == 14
    today = stats[-1]["scans"]
    assert today == cap, f"today's bar saturates at the cap; got {today}"
