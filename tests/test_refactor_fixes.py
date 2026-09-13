"""Regression tests for the Q36 audit fixes (TDD: RED before any fix).

Fixes under test:
- F1: 14d/90d approvals must store an absolute ISO-8601 Z timestamp in
  expires_at (not the literal strings '14d'/'90d'), and effective_tier()
  must honor ISO timestamps correctly.
- F2: module-level `app` attribute must work as a uvicorn entrypoint without
  requiring WHITELIST_SECRET at import time.
- F3: notify.py --what verify --apply must actually call send_email.
- F4: email comparison is case-insensitive (spec: 'compare emails lowercased').
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import wl_tokens
import whitelist_db


def _make_db(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    data = {
        "handle": "testuser",
        "name": {"display": "Test User"},
        "org": {"company": "TestCo", "title": "CTO"},
        "emails": [
            {"address": "public@testco.com", "visibility": "public"},
            {"address": "private@testco.com", "visibility": "connection"},
        ],
        "phones": [{"number": "+155****4567", "visibility": "holder"}],
        "verified_at": "2026-09-10",
    }
    whitelist_db.seed_profile(conn, data)
    conn.close()
    return db


def _stored_expires_at(db: Path, grant_id: str):
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT expires_at FROM access_grants WHERE id = ?", (grant_id,)
    ).fetchone()
    conn.close()
    assert row is not None, f"grant {grant_id} missing"
    return row[0]


# ------------------------------------------------------------------ F1: expiry

def test_approve_14d_stores_iso_timestamp(tmp_path):
    """POST decision approve/14 must store an ISO-8601 timestamp, not '14d'."""
    from fastapi.testclient import TestClient
    from app import create_app

    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    grant_id = whitelist_db.create_grant(conn, profile["id"], "r14@example.com", "R14")
    conn.close()

    token = wl_tokens.make_token(b"test-secret", "grant_review", grant_id)
    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision", data={"decision": "approve", "expiry": "14"})
    assert resp.status_code == 200

    value = _stored_expires_at(db, grant_id)
    # Must parse as a real ISO-8601 datetime (the bug stored the literal '14d').
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    # And it must be ~14 days in the future, not 1970 or anything arbitrary.
    delta_days = (parsed - datetime.now(timezone.utc)).days
    assert 13 <= delta_days <= 15, f"expected ~14d future, got {delta_days}d: {value!r}"


def test_approve_90d_stores_iso_timestamp(tmp_path):
    """POST decision approve/90 must store an ISO-8601 timestamp ~90d out."""
    from fastapi.testclient import TestClient
    from app import create_app

    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    grant_id = whitelist_db.create_grant(conn, profile["id"], "r90@example.com", "R90")
    conn.close()

    token = wl_tokens.make_token(b"test-secret", "grant_review", grant_id)
    client = TestClient(create_app(db))
    resp = client.post(f"/a/{token}/decision", data={"decision": "approve", "expiry": "90"})
    assert resp.status_code == 200

    value = _stored_expires_at(db, grant_id)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    delta_days = (parsed - datetime.now(timezone.utc)).days
    assert 89 <= delta_days <= 91, f"expected ~90d future, got {delta_days}d: {value!r}"


def test_legacy_14d_string_does_not_leak_private_fields(tmp_path):
    """A legacy row storing the literal '14d' must NOT grant access (no data leak)."""
    from fastapi.testclient import TestClient
    from app import create_app

    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    g14 = whitelist_db.create_grant(conn, profile["id"], "leg14@example.com", "L14")
    g90 = whitelist_db.create_grant(conn, profile["id"], "leg90@example.com", "L90")
    whitelist_db.update_grant_status(
        conn, g14, "granted", granted_at="2026-09-10T12:00:00Z", expires_at="14d"
    )
    whitelist_db.update_grant_status(
        conn, g90, "granted", granted_at="2026-09-10T12:00:00Z", expires_at="90d"
    )
    conn.close()

    client = TestClient(create_app(db))
    # '14d' is lexicographically < any ISO date -> must be anonymous.
    resp = client.get("/p/testuser?e=leg14@example.com")
    assert "private@testco.com" not in resp.text and "+155****4567" not in resp.text
    # '90d' currently happens to be > ISO dates lexicographically -> the OLD code
    # leaks data here. After the fix this must also be anonymous (or, if we keep
    # leniency, at minimum the 14d case above must hold). Spec: expires_at is a
    # timestamp — garbage in = no grant out.
    resp = client.get("/p/testuser?e=leg90@example.com")
    assert "private@testco.com" not in resp.text


def test_iso_expiry_enforced(tmp_path):
    """Stored ISO timestamps: past -> anonymous, future -> granted, NULL -> active."""
    from fastapi.testclient import TestClient
    from app import create_app

    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    gpast = whitelist_db.create_grant(conn, profile["id"], "past@example.com", "P")
    gfut = whitelist_db.create_grant(conn, profile["id"], "fut@example.com", "F")
    glife = whitelist_db.create_grant(conn, profile["id"], "life@example.com", "L")
    whitelist_db.update_grant_status(
        conn, gpast, "granted", granted_at="2026-01-01T00:00:00Z",
        expires_at="2026-02-01T00:00:00Z",
    )
    whitelist_db.update_grant_status(
        conn, gfut, "granted", granted_at="2026-09-01T00:00:00Z",
        expires_at="2027-12-31T00:00:00Z",
    )
    whitelist_db.update_grant_status(
        conn, glife, "granted", granted_at="2026-09-01T00:00:00Z", expires_at=None,
    )
    conn.close()

    client = TestClient(create_app(db))
    assert "private@testco.com" not in client.get("/p/testuser?e=past@example.com").text
    assert "private@testco.com" in client.get("/p/testuser?e=fut@example.com").text
    assert "private@testco.com" in client.get("/p/testuser?e=life@example.com").text


# ------------------------------------------------------------------ F2: uvicorn

def test_module_level_app_entrypoint():
    """`uvicorn app:app` must work in a FRESH process (no create_app() pre-call).

    The check is ROUTE-BASED, not a 404 probe: a bare ``FastAPI()`` stub and a
    fully-routed app BOTH return 404 for an unknown handle, so a 404 assertion
    cannot tell them apart. We assert the profile route actually exists on the
    module-level instance instead.
    """
    import subprocess
    code = (
        "import app as m\n"
        "assert m.app is not None, 'app attr is None'\n"
        "paths = {getattr(r, 'path', '') for r in m.app.routes}\n"
        "assert '/p/{handle}' in paths, f'no profile route on entrypoint app; paths={sorted(paths)}'\n"
        "print('ENTRYPOINT_OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent), timeout=60,
    )
    assert "ENTRYPOINT_OK" in result.stdout, (
        f"entrypoint check failed rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    )


def test_app_import_does_not_require_secret():
    """Importing app.py must NOT require WHITELIST_SECRET (per spec)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("WHITELIST")}
    code = (
        "import app as m\n"
        "assert m.app is not None, 'app attr is None'\n"
        "print('IMPORT_OK')\n"
    )
    import subprocess
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True,
        cwd=str(Path(__file__).resolve().parent.parent), env=env, timeout=30,
    )
    assert "IMPORT_OK" in result.stdout, (
        f"import failed rc={result.returncode}\n{result.stdout}\n{result.stderr}"
    )


# ------------------------------------------------------------------ F4: case

def test_email_case_insensitive_tier(tmp_path):
    """Spec: 'compare emails lowercased' — different casing must still grant."""
    from fastapi.testclient import TestClient
    from app import create_app

    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    g = whitelist_db.create_grant(conn, profile["id"], "CaseSu@Example.COM", "CS")
    whitelist_db.update_grant_status(
        conn, g, "granted", granted_at="2026-09-10T12:00:00Z", expires_at=None,
    )
    conn.close()

    client = TestClient(create_app(db))
    resp = client.get("/p/testuser?e=CASESU@example.com")
    assert resp.status_code == 200
    assert "private@testco.com" in resp.text


# ---------------------------------------------------------------- F5: dedupe

def test_create_grant_dedupes_on_profile_and_email(tmp_path):
    """Spec: 'dedupe on profile+email' — second request returns the same grant."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    g1 = whitelist_db.create_grant(conn, profile["id"], "dupe@example.com", "First")
    g2 = whitelist_db.create_grant(conn, profile["id"], "DUPE@EXAMPLE.com", "Second")
    n = conn.execute("SELECT count(*) FROM access_grants").fetchone()[0]
    conn.close()
    assert g1 == g2, f"expected same grant id reused, got {g1} then {g2}"
    assert n == 1, f"expected exactly 1 row, found {n}"


# ------------------------------------------------------------------ F3: notify

def test_notify_verify_apply_calls_send_email(tmp_path, monkeypatch):
    """notify.py --what verify --apply must call send_email (not just print).

    Hermetic: a tmp DB with one stale profile, never the live contacts.db.
    """
    import scripts.notify as notify_mod

    sent = []
    monkeypatch.setattr(notify_mod, "send_email", lambda to, subj, body: sent.append((to, subj, body)))

    # One stale profile (verified 200 days ago) in a tmp DB.
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    conn.execute(
        "UPDATE profiles SET verified_at='2025-01-01' WHERE handle='testuser'"
    )
    conn.commit()
    stale = whitelist_db.get_profiles_needing_verification(conn, days=90)
    conn.close()
    assert len(stale) == 1, f"precondition: exactly 1 stale profile expected, got {len(stale)}"

    notify_mod.notify_verify(dry_run=False, db_path=db)

    assert len(sent) >= 1, (
        "apply mode never called send_email — the verify path only prints. "
        f"(found {len(stale)} stale profiles)"
    )


# ---------------------------------------------------------------- F6: re-request after deny/expiry

def _grant_rows(conn, profile_id):
    return [dict(r) for r in conn.execute(
        "SELECT id, status, expires_at FROM access_grants WHERE profile_id = ? ORDER BY created_at",
        (profile_id,)).fetchall()]


def test_denied_requester_can_re_request(tmp_path):
    """A denied person who asks again must land back in pending — the deny is
    history, not a life ban. Previously dedupe returned the dead grant id and
    the new request silently vanished."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    g1 = whitelist_db.create_grant(conn, profile["id"], "bob@x.com", "Bob")
    whitelist_db.update_grant_status(conn, g1, "denied")

    g2 = whitelist_db.create_grant(conn, profile["id"], "bob@x.com", "Bob")
    row = conn.execute("SELECT status FROM access_grants WHERE id = ?", (g2,)).fetchone()
    assert row is not None
    assert row["status"] == "pending", (
        f"re-request after denial must be pending, got {row['status']!r} "
        f"(same grant reused: {g1 == g2})")
    # the original denial stays on the books as history
    n = conn.execute("SELECT count(*) FROM access_grants WHERE status='denied'").fetchone()[0]
    assert n == 1, f"original denial must be preserved, found {n}"
    conn.close()


def test_expired_grant_holder_can_re_request(tmp_path):
    """Same trap for expired grants: re-request after expiry creates a fresh
    pending grant instead of reusing the dead one."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")
    g1 = whitelist_db.create_grant(conn, profile["id"], "carol@x.com", "Carol")
    whitelist_db.update_grant_status(
        conn, g1, "granted",
        granted_at="2026-01-01T00:00:00Z",
        expires_at="2026-01-31T00:00:00Z")  # long expired

    g2 = whitelist_db.create_grant(conn, profile["id"], "carol@x.com", "Carol")
    row = conn.execute("SELECT status FROM access_grants WHERE id = ?", (g2,)).fetchone()
    assert row is not None and row["status"] == "pending", (
        f"re-request after expiry must be pending, got {row['status']!r}")
    conn.close()


def test_active_or_pending_requester_still_deduped(tmp_path):
    """Fix must not break F5: an ACTIVE grant or a PENDING request reuses the
    same grant id — no duplicate rows."""
    db = _make_db(tmp_path)
    conn = whitelist_db.wl_connect(db)
    profile = whitelist_db.get_profile(conn, "testuser")

    g1 = whitelist_db.create_grant(conn, profile["id"], "pend@x.com", "P")
    assert whitelist_db.create_grant(conn, profile["id"], "pend@x.com", "P") == g1

    g2 = whitelist_db.create_grant(conn, profile["id"], "act@x.com", "A")
    whitelist_db.update_grant_status(
        conn, g2, "granted", granted_at="2026-09-01T00:00:00Z",
        expires_at="2026-12-31T00:00:00Z")
    assert whitelist_db.create_grant(conn, profile["id"], "act@x.com", "A") == g2

    n = conn.execute("SELECT count(*) FROM access_grants").fetchone()[0]
    assert n == 2, f"expected 2 rows total, got {n}"
    conn.close()
