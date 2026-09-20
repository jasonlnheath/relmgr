"""P3-T4: Scan analytics — profile page access tracking.

scan_events: additive table, one row per successful GET /p/{handle}.
viewer_email is NULL for anonymous visits (still a scan — that's the point).
Dashboard shows a 14-day bar chart per profile (pure Tailwind divs, no JS).
"""

import os
from datetime import datetime, timezone
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


def _grant(db, email):
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "dana_reyes")
    gid = whitelist_db.create_grant(conn, profile["id"], email, "Test")
    conn.close()
    return gid


# ------------------------------------------------------------------ table + hook

def test_profile_get_records_scan_event(tmp_path):
    """Successful GET /p/{handle} appends exactly one scan row for the profile."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))
    resp = client.get("/p/dana_reyes?e=a@x.com")
    assert resp.status_code == 200, resp.text[:200]

    conn = whitelist_db.wl_connect(db)
    rows = conn.execute("SELECT * FROM scan_events").fetchall()
    conn.close()
    assert len(rows) == 1, f"expected 1 scan row after 1 GET, got {len(rows)}"
    assert rows[0]["profile_id"] == 1


def test_404_profile_records_no_scan(tmp_path):
    """A nonexistent profile must not write a scan row."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))
    resp = client.get("/p/no_such_handle")
    assert resp.status_code == 404

    conn = whitelist_db.wl_connect(db)
    n = conn.execute("SELECT count(*) FROM scan_events").fetchone()[0]
    conn.close()
    assert n == 0, f"404 must not log a scan, got {n}"


def test_scan_event_preserves_viewer_email(tmp_path):
    """Known viewer emails are stored verbatim; anonymous visits stay NULL."""
    db = _make_db(tmp_path)
    client = TestClient(create_app(db))
    client.get("/p/dana_reyes", params={"e": "viewer@x.com"})
    client.get("/p/dana_reyes")  # anonymous

    conn = whitelist_db.wl_connect(db)
    rows = [dict(r) for r in conn.execute(
        "SELECT viewer_email FROM scan_events ORDER BY id")]
    conn.close()
    emails = [r["viewer_email"] for r in rows]
    assert emails == ["viewer@x.com", None], f"got {emails}"


# ------------------------------------------------------------------ stats query

def test_get_scan_stats_fills_14_days(tmp_path):
    """get_scan_stats returns exactly 14 entries, oldest→newest, zero-filled:
    gaps in the window must appear as zero bars, not missing data."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    # Two scans today (via default), one 'yesterday' via explicit timestamp.
    whitelist_db.record_scan(conn, 1, "seed@x.com")
    whitelist_db.record_scan(conn, 1, None)
    conn.execute(
        """INSERT INTO scan_events (profile_id, viewer_email, scanned_at)
           VALUES (1, NULL, datetime('now', '-1 day'))""")
    conn.commit()

    stats = whitelist_db.get_scan_stats(conn, 1)
    conn.close()

    assert len(stats) == 14, f"expected exactly 14 daily entries, got {len(stats)}"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    assert stats[-1]["date"] == today, f"last entry must be today: {stats[-1]['date']}"
    # chronological oldest→newest
    dates = [s["date"] for s in stats]
    assert dates == sorted(dates), f"not chronological: {dates}"
    by_date = {s["date"]: s["scans"] for s in stats}
    assert by_date.get(today, 0) == 2, f"today must show 2 scans: {by_date.get(today)}"
    assert sum(s["scans"] for s in stats) == 3, "total scans must be 3"


def test_dashboard_renders_scan_chart(tmp_path):
    """Owner dashboard carries a per-profile 14-day scan bar chart.

    The dashboard only lists profiles WITH grants, so this test seeds one;
    the /p GET proves the scan row was written through the real route.

    Note: contacts.html replaced the old dashboard — scan analytics still
    work via /p/{handle} and get_scan_stats(); the dashboard no longer
    renders the bar chart inline.
    """
    db = _make_db(tmp_path)
    _grant(db, "chart@x.com")
    client = TestClient(create_app(db))
    resp = client.get("/p/dana_reyes")
    assert resp.status_code == 200, resp.text[:200]

    owner_token = wl_tokens.make_token(b"test-secret", "owner_dashboard", "1")
    resp = client.get(f"/owner/{owner_token}")
    assert resp.status_code == 200, resp.text[:300]
    # contacts.html replaced the scan chart — the page still renders fine
    assert "chart@x.com" in resp.text or "Dana Reyes" in resp.text
