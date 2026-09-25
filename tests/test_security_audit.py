"""Security audit regression tests (2026-09-25, branch fm/whitelist-security-audit).

Each test pins one fixed hole shut:

S1  ?e=<owner email> used to mint a 365-day owner dashboard token and lift
    the viewer to granted tier (email knowledge = full account access).
    Now owner self-view requires a signed ?ot= token or the session cookie.
S2  /owner/{token}/quarter/{make_permanent,revoke,punt} skipped the grant
    ownership check — any owner could punt/permanent/revoke ANY grant.
S3  /photos/{pid}/{cid}[/hs] served ANY card's photo to ANYONE (sequential
    id enumeration across accounts).
S4  /owner/{legacy-token}/bio-visibility fell back to flipping the FIRST
    profile's bio visibility.
S5  Duplicate /p/{handle}/request POSTs re-pushed the owner email every time.
S6  No request body cap; no decode-pixel cap on uploads (decompression bomb).
S7  Missing Referrer-Policy (capability tokens live in /owner/ URLs) and
    other baseline headers; no per-IP limiter on anonymous POST surfaces.
"""

import io
import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("WHITELIST_SECRET", "test-secret")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import whitelist_db
import wl_tokens
from fastapi.testclient import TestClient
from PIL import Image

from app import create_app


SECRET = b"test-secret"


def _token(pid, days=7):
    return wl_tokens.make_token(SECRET, "owner_dashboard", str(pid), expires_days=days)


def _make_db(tmp_path):
    db = tmp_path / "sec.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    whitelist_db.ensure_whitelist_schema(conn)
    conn.close()
    return db


def _setup_two_owners(tmp_path):
    """alice (victim, profile 1) + mallory (attacker, profile 2)."""
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


# ============================================================
# S1 — email knowledge must never authenticate the owner
# ============================================================

def test_s1_owner_email_does_not_mint_owner_token(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    r = client.get("/p/alice?e=alice@victim.example")
    assert r.status_code == 200
    assert "/owner/" not in r.text, \
        "?e=<owner email> must never render an owner dashboard token"


def test_s1_owner_email_does_not_reveal_private_fields(tmp_path):
    db = _setup_two_owners(tmp_path)
    conn = whitelist_db.wl_connect(db)
    whitelist_db.add_profile_field(
        conn, 1, "phone", "555-000-1234", "private")
    conn.close()
    client = TestClient(create_app(db))
    anon = client.get("/p/alice").text
    assert "555-000-1234" not in anon
    via_email = client.get("/p/alice?e=alice@victim.example").text
    assert "555-000-1234" not in via_email, \
        "?e=<owner email> must not lift the tier to granted"
    # ...while the signed ?ot= token still shows the owner everything.
    me = client.get(f"/p/alice?ot={_token(1)}").text
    assert "555-000-1234" in me


def test_s1_effective_tier_ignores_own_email(tmp_path):
    db = _setup_two_owners(tmp_path)
    conn = whitelist_db.wl_connect(db)
    assert whitelist_db.effective_tier(conn, 1, "alice@victim.example") == "anonymous"
    conn.close()


# ============================================================
# S2 — quarter routes enforce grant ownership
# ============================================================

def _granted_request(db, profile_id, email):
    conn = whitelist_db.wl_connect(db)
    gid = whitelist_db.create_grant(conn, profile_id, email, "Req")
    whitelist_db.apply_decision(conn, gid, "approve", "quarter",
                                merge_contacts=False)
    conn.close()
    return gid


def test_s2_quarter_routes_reject_foreign_grants(tmp_path):
    db = _setup_two_owners(tmp_path)
    gid = _granted_request(db, 1, "someone@x.com")  # ALICE's grant
    mallory_tok = _token(2)
    client = TestClient(create_app(db))
    for route in ("make_permanent", "revoke", "punt"):
        r = client.post(f"/owner/{mallory_tok}/quarter/{route}",
                        data={"grant_id": gid})
        assert r.status_code == 404, \
            f"{route} must 404 on a foreign grant, got {r.status_code}"
    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, gid)
    conn.close()
    assert grant["status"] == "granted", "foreign write must not land"
    assert grant["expires_at"] is not None


def test_s2_quarter_routes_still_work_for_own_grants(tmp_path):
    db = _setup_two_owners(tmp_path)
    gid = _granted_request(db, 1, "someone@x.com")
    client = TestClient(create_app(db))
    r = client.post(f"/owner/{_token(1)}/quarter/make_permanent",
                    data={"grant_id": gid})
    assert r.status_code == 200
    conn = whitelist_db.wl_connect(db)
    grant = whitelist_db.get_grant(conn, gid)
    conn.close()
    assert grant["expires_at"] is None


# ============================================================
# S3 — photo access control
# ============================================================

def _upload_photo(client, token, card_id, color=(120, 40, 40)):
    img = Image.new("RGB", (60, 60), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    buf.seek(0)
    r = client.post(f"/owner/{token}/cards/{card_id}/photo",
                    files={"photo": ("p.jpg", buf, "image/jpeg")})
    assert r.status_code == 200, r.status_code


def _cards(db, profile_id):
    conn = whitelist_db.wl_connect(db)
    rows = conn.execute(
        "SELECT id, name FROM cards WHERE owner_profile_id = ? ORDER BY id",
        (profile_id,)).fetchall()
    conn.close()
    return [(r["id"], r["name"]) for r in rows]


def test_s3_nondefault_card_photo_not_publicly_readable(tmp_path):
    db = _setup_two_owners(tmp_path)
    alice_tok = _token(1)
    client = TestClient(create_app(db))
    cards = _cards(db, 1)
    assert len(cards) >= 2, cards
    default_id, _ = cards[0]
    other_id, _ = cards[1]
    _upload_photo(client, alice_tok, default_id)
    _upload_photo(client, alice_tok, other_id, color=(10, 10, 200))

    # default card photo: public (the anonymous /p page renders it)
    assert client.get(f"/photos/1/{default_id}").status_code == 200
    # non-default card photo: NOT public — enumeration must 404
    assert client.get(f"/photos/1/{other_id}").status_code == 404
    assert client.get(f"/photos/1/{other_id}/hs").status_code == 404
    # a stranger's valid owner token changes nothing
    assert client.get(
        f"/photos/1/{other_id}?t={_token(2)}").status_code == 404


def test_s3_photo_allowed_via_owner_token_session_and_bundle(tmp_path):
    db = _setup_two_owners(tmp_path)
    alice_tok = _token(1)
    client = TestClient(create_app(db))
    cards = _cards(db, 1)
    other_id = cards[1][0]
    _upload_photo(client, alice_tok, other_id)

    # owner token (?t= — what the owner surfaces embed)
    assert client.get(f"/photos/1/{other_id}?t={alice_tok}").status_code == 200
    # session cookie
    client.post("/signin", data={"email": "alice@victim.example",
                                 "password": "pw-alice-123"})
    assert client.get(f"/photos/1/{other_id}").status_code == 200
    client.post("/signout")

    # non-expired share bundle containing the card → anonymous may read
    conn = whitelist_db.wl_connect(db)
    bundle = whitelist_db.create_share_bundle(conn, 1, [other_id])
    conn.close()
    assert client.get(f"/photos/1/{other_id}").status_code == 200

    # expired bundle → anonymous blocked again
    conn = whitelist_db.wl_connect(db)
    conn.execute(
        "UPDATE share_bundles SET expires_at = '2001-01-01T00:00:00Z' "
        "WHERE id = ?", (bundle["id"],))
    conn.commit()
    conn.close()
    assert client.get(f"/photos/1/{other_id}").status_code == 404


def test_s3_photo_allowed_for_granted_contact(tmp_path):
    db = _setup_two_owners(tmp_path)
    alice_tok = _token(1)
    client = TestClient(create_app(db))
    cards = _cards(db, 1)
    other_id = cards[1][0]
    _upload_photo(client, alice_tok, other_id)
    gid = _granted_request(db, 1, "friend@x.com")
    assert gid
    assert client.get(
        f"/photos/1/{other_id}?e=friend@x.com").status_code == 200
    # non-granted email stays out
    assert client.get(
        f"/photos/1/{other_id}?e=stranger@x.com").status_code == 404


# ============================================================
# S4 — bio-visibility legacy fallback removed
# ============================================================

def test_s4_bio_visibility_legacy_token_cannot_flip_first_profile(tmp_path):
    db = _setup_two_owners(tmp_path)
    legacy = wl_tokens.make_token(SECRET, "owner_dashboard", "legacy-owner")
    client = TestClient(create_app(db))
    r = client.post(f"/owner/{legacy}/bio-visibility",
                    data={"bio_visibility": "private"},
                    follow_redirects=False)
    assert r.status_code in (303, 403), r.status_code
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT bio_visibility FROM profiles ORDER BY id LIMIT 1").fetchone()
    conn.close()
    assert row["bio_visibility"] == "public", \
        "legacy payload must not touch the first profile"


def test_s4_bio_visibility_works_for_real_owner(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    r = client.post(f"/owner/{_token(1)}/bio-visibility",
                    data={"bio_visibility": "private"})
    assert r.status_code == 200
    conn = whitelist_db.wl_connect(db)
    row = conn.execute(
        "SELECT bio_visibility FROM profiles WHERE id = 1").fetchone()
    conn.close()
    assert row["bio_visibility"] == "private"


# ============================================================
# S5 — duplicate request POSTs don't re-push the owner email
# ============================================================

def test_s5_duplicate_requests_push_email_once(tmp_path, monkeypatch):
    import app as app_module
    db = _setup_two_owners(tmp_path)
    pushes = []
    monkeypatch.setattr(
        app_module, "_send_connection_request_email",
        lambda db_path, gid: pushes.append(gid))
    client = TestClient(create_app(db))
    for _ in range(3):
        r = client.post("/p/alice/request",
                        data={"name": "Spam", "email": "spammer@x.com"})
        assert r.status_code == 200
    assert len(pushes) == 1, \
        f"deduped re-POSTs must not re-push email (pushes={pushes})"
    # and the notification row is still exactly one
    conn = whitelist_db.wl_connect(db)
    n = conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE kind='connection_request'"
    ).fetchone()[0]
    conn.close()
    assert n == 1


# ============================================================
# S6 — body cap + decode pixel cap
# ============================================================

def _fake_png_header(width, height):
    """Minimal PNG (signature + IHDR + IEND) — enough for PIL's lazy header
    parse; the pixel cap must reject before any decode is attempted."""
    def chunk(tag, data=b""):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", 0)
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND"))


def test_s6_oversized_pixel_dimensions_rejected(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    tok = _token(1)
    cards = _cards(db, 1)
    bomb = _fake_png_header(10_000, 10_000)  # 100 MP > 40 MP cap
    r = client.post(f"/owner/{tok}/cards/{cards[0][0]}/photo",
                    files={"photo": ("bomb.png", bomb, "image/png")})
    assert r.status_code == 400, \
        f"pixel bomb must 400, got {r.status_code}"


def test_s6_request_body_cap(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    big = "x" * (17 * 1024 * 1024)
    r = client.post("/signin", data={"email": big, "password": big})
    assert r.status_code == 413, \
        f"oversized body must 413, got {r.status_code}"


# ============================================================
# S7 — baseline headers + per-IP rate limit
# ============================================================

def test_s7_security_headers_present(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    r = client.get("/signin")
    assert r.headers.get("referrer-policy") == "no-referrer"
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"


def test_s7_rate_limit_on_public_request_post(tmp_path):
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    last = None
    for i in range(12):
        last = client.post("/p/alice/request",
                           data={"name": f"n{i}", "email": f"e{i}@x.com"})
    assert last.status_code == 429, \
        f"11th request POST inside the window must 429, got {last.status_code}"


def test_s7_rate_limit_escape_hatch(tmp_path, monkeypatch):
    monkeypatch.setenv("WHITELIST_RATELIMIT_DISABLED", "1")
    db = _setup_two_owners(tmp_path)
    client = TestClient(create_app(db))
    codes = [client.post("/p/alice/request",
                         data={"name": "n", "email": "e@x.com"}).status_code
             for _ in range(12)]
    assert 429 not in codes
    monkeypatch.delenv("WHITELIST_RATELIMIT_DISABLED")


# ============================================================
# Extra — vCard CR smuggling escape
# ============================================================

def test_vcf_escape_strips_bare_cr():
    from app import _vcf_escape
    assert "\r" not in _vcf_escape("a\rb\nc;d,e")
    assert _vcf_escape("line1\nline2") == "line1\\nline2"
