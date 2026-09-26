"""Shared plumbing for the whitelist web app: time helpers, auth oracles,
image/QR/vCard encoding, and the Jinja environment factory.

Split out of app.py (2026-09-26 refactor): everything here is import-safe
(secrets are read lazily per-request, never at import time) and used by the
route modules in routes_*.py. app.py re-exports the test-facing names.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import hmac
import sys
import time
from datetime import datetime, timezone
from io import BytesIO

from fastapi import Request
from fastapi.responses import HTMLResponse
from PIL import Image
from starlette.templating import Jinja2Templates

import whitelist_db
import wl_tokens
import wl_env
import mailer

_NOW_FMT = "%Y-%m-%dT%H:%M:%SZ"


_JINJA_DIR = Path(__file__).parent / "templates"

# Static assets are content-versioned: every template references them as
# /static/<name>?v=<asset_v(name)>, so browsers may cache them forever —
# a changed file changes the URL (regression-verify pass, 2026-09-26:
# two "fixed on server, still broken on phone" rounds were stale mobile
# caches; versioned URLs + no-cache HTML close that hole for good).
_STATIC_DIR = Path(__file__).parent / "static"


def _parse_dt(value: str):
    """Parse the timestamp formats this DB actually stores.

    Returns a naive UTC datetime, or None if unparseable. Stored values are
    a mix of date-only ('2026-09-10'), space-separated ('2026-09-05 12:34:56')
    and ISO-8601 Z forms — all normalized to naive UTC for arithmetic.
    """
    if value is None:
        return None
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def days_since(value: str) -> int:
    """Whole days between a stored timestamp and now (0 on bad/None input)."""
    dt = _parse_dt(value)
    if dt is None:
        return 0
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
    return max(0, delta.days)


def days_until(value: str) -> int:
    """Whole days from now until a stored timestamp (0 on bad/None input)."""
    dt = _parse_dt(value)
    if dt is None:
        return 0
    delta = dt - datetime.now(timezone.utc).replace(tzinfo=None)
    return max(0, delta.days)


_STALE_AFTER_DAYS = 180


def _rail_letter(name: str) -> str:
    """Pairing-review F2 (2026-09-22): fold a name's initial onto the A–Z
    rail. Accented Latin initials (É, Ü, …) group under their ASCII base
    letter; anything non-alphabetic (digits, CJK, …) lands in the '#'
    bucket so every contact stays reachable from the rail."""
    import unicodedata
    initial = (name or " ")[:1]
    if not initial.isalpha():
        return "#"
    folded = unicodedata.normalize("NFKD", initial) \
        .encode("ascii", "ignore").decode("ascii").upper()
    return folded if folded else "#"


def is_verified_stale(value) -> bool:
    """True when a profile's verified_at is more than 180 days old.

    Boundary (>180 days) lives HERE, not inlined in the /p route. Missing or
    unparseable timestamps are never stale (False) — same as the route's old
    try/except. ``value`` may be date-only, space-separated, or ISO-8601 Z;
    all are normalized via _parse_dt before the comparison.
    """
    dt = _parse_dt(value)
    if dt is None:
        return False
    delta = datetime.now(timezone.utc).replace(tzinfo=None) - dt
    return delta.days > _STALE_AFTER_DAYS


def _get_secret():
    """Read WHITELIST_SECRET at call time (env first, then .env file)."""
    return wl_env.get_secret("WHITELIST_SECRET").encode()


def _encode_square_jpeg(content: bytes) -> bytes:
    """Validate + normalize an uploaded or client-cropped image for storage.

    Magic-byte sniff (JPEG/PNG only), PIL verify, center-crop to square
    (the client cropper already squares; this is defense in depth), then
    Lanczos-resample to the stored display size: 512×512 JPEG q82.

    Security audit 2026-09-25: an explicit pixel cap (40 MP) is enforced
    BEFORE any decode — a compact bomb PNG otherwise decompresses to
    hundreds of MB of RAM per request (DoS). Raises ValueError on
    junk/unsupported/oversized content (route maps to 400).
    """
    import io
    _MAX_PIXELS = 40_000_000  # 40 MP decode ceiling
    if not (content[:3] == b"\xff\xd8\xff" or content[:4] == b"\x89PNG"):
        raise ValueError("unsupported image format")
    try:
        img = Image.open(io.BytesIO(content))
        if img.width * img.height > _MAX_PIXELS:
            raise ValueError("image too large")
        img.verify()
        img = Image.open(io.BytesIO(content))
        if img.format not in ("JPEG", "PNG"):
            raise ValueError("unsupported image format")
        w, h = img.size
        side = min(w, h)
        left = (w - side) // 2
        top = (h - side) // 2
        img = img.crop((left, top, left + side, top + side))
        img = img.resize((512, 512), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=82)
        return buf.getvalue()
    except ValueError:
        raise
    except Exception:
        raise ValueError("invalid image file")


def _static_version(name: str) -> str:
    """Cheap content version for a file under static/ (mtime_ns + size).

    Changes whenever the file changes; stable while it does not. Missing
    files return "0" so templates never crash on a stray reference.
    """
    try:
        st = (_STATIC_DIR / name).stat()
        return f"{st.st_mtime_ns:x}{st.st_size:x}"
    except OSError:
        return "0"


def _make_jinja():
    jinja = Jinja2Templates(directory=str(_JINJA_DIR))
    # UX pass 2: phone label rendering shared by every field-row template.
    jinja.env.globals["label_display"] = whitelist_db.label_display
    # UX pass 3: +1(XXX)XXX-XXXX display formatting, one formatter for every
    # surface (stored values are never rewritten).
    jinja.env.globals["phone_fmt"] = whitelist_db.format_phone_display
    # Cache-busting version for static asset URLs (?v=…) — see
    # _static_version; every /static/ reference in templates goes through
    # it so changed assets get a new URL (and /static can cache forever).
    jinja.env.globals["asset_v"] = _static_version
    return jinja


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    import base64
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _make_session_cookie(profile_id: int, secret: bytes) -> str:
    """Create a signed session cookie value (7-day expiry)."""
    expiry = int(time.time()) + 7 * 86400
    payload = f"{profile_id}|{expiry}"
    payload_b64 = _b64url_encode(payload.encode())
    sig = hmac.new(
        secret, f"session|{payload_b64}".encode(), "sha256"
    ).hexdigest()
    return f"{payload_b64}.{sig}"


def _consume_session_cookie(cookie_value: str, secret: bytes):
    """Validate session cookie; returns profile_id int or None."""
    try:
        parts = cookie_value.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        inner = _b64url_decode(payload_b64).decode()
        parts2 = inner.rsplit("|", 1)
        profile_id = int(parts2[0])
        expiry = int(parts2[1])
        if int(time.time()) > expiry:
            return None
        signing_input = f"session|{payload_b64}"
        expected_sig = hmac.new(
            secret, signing_input.encode(), "sha256"
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        return profile_id
    except Exception:
        return None


class LegacyOwnerLinkRetired(Exception):
    """A validly-signed pre-migration owner dashboard link.

    The old unscoped magic links (non-integer payload, e.g. the 365-day
    'owner' links) are RETIRED — captain ruling 2026-09-20, option A. The
    app-wide handler redirects holders to sign-in with no data access.
    """


def _resolve_owner(
    conn, request, token: str, secret: bytes
):
    """Resolve the owner profile from URL token OR session cookie.

    Returns (profile_id, profile_dict, redirect_token_or_None, is_explicit).
    If redirect_token is set, the caller should redirect to /owner/{token}.
    If profile_id is None, the caller should return 403.
    is_explicit is True when the user was authenticated via session cookie
    or a valid URL token.

    Retired links: a validly-signed token with a non-integer payload (the
    pre-migration format) raises LegacyOwnerLinkRetired — handled app-wide
    as a redirect to /signin with no data access. Legacy owners use the
    same sign-in/sign-up as everyone else (captain ruling, option A).
    Tokens that are tampered/expired return 403 via (None, None, None, False).
    """
    # Try URL token first
    if token:
        payload = wl_tokens.consume_token(secret, "owner_dashboard", token)
        if payload is not None:
            # Token is valid — the payload must be an integer profile ID.
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                # Validly signed but pre-migration format: the legacy
                # DB fallback is retired (ruling 2026-09-20, option A).
                raise LegacyOwnerLinkRetired(payload)
            if profile_id:
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
                if profile:
                    return profile_id, profile, None, True
            # Integer payload but no such profile — dead link → 403.
            return None, None, None, False
        else:
            # Token present but INVALID (tampered/expired) — return 403
            return None, None, None, False

    # Try session cookie (only when no URL token)
    session_cookie = request.cookies.get("wl_session")
    if session_cookie:
        profile_id = _consume_session_cookie(session_cookie, secret)
        if profile_id:
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if profile:
                fresh_token = wl_tokens.make_token(
                    secret, "owner_dashboard", str(profile_id)
                )
                return None, None, fresh_token, True  # signal redirect

    # No token and no session → not authenticated.
    return None, None, None, False


def _verify_grant_ownership(conn, grant, profile_id, is_explicit=True):
    """Verify a grant belongs to the current owner (ruling 2A).

    ALWAYS enforced: a dashboard link may only decide grants owned by the
    profile it resolves to. Fail-closed: a grant with no owner_id
    (unmigrated row) is undecidable → deny. The is_explicit parameter is
    kept for call-site compatibility and ignored.
    """
    if grant is None:
        return False
    return grant.get("owner_id") == profile_id


def _decision_outcome(conn, jinja, request, grant_id, decision,
                      expiry_choice) -> HTMLResponse:
    """Apply a decision and render the outcome page (R4(b)) — shared by
    /a/{token}/decision and /owner/{token}/decision.

    Deliberately does NOT consume tokens: each route keeps its own scope
    ('grant_review' vs 'owner_dashboard') and its own 403 error path. The
    apply/404/render flow is the duplicated part, so that's what lives here.
    decision/expiry_choice arrive from request.form() (str at runtime).

    apply_decision raises ValueError on junk decisions or replay against a
    non-pending grant (revoked access must not resurrect) -> 409.
    """
    try:
        result = whitelist_db.apply_decision(conn, grant_id, decision, expiry_choice)
    except ValueError as exc:
        return HTMLResponse(str(exc), status_code=409)
    if result is None:
        return HTMLResponse("Grant not found", status_code=404)
    return HTMLResponse(jinja.get_template("admin_decision.html").render(
        request=request, grant=result["grant"], profile=result["profile"],
        decision=result["decision"]))


def _owner_email_for(conn, owner_profile_id: int) -> str:
    """First email field on a profile ('' when it has none)."""
    row = conn.execute(
        """SELECT field_value FROM profile_fields
           WHERE profile_id = ? AND field_type = 'email'
           ORDER BY id LIMIT 1""",
        (owner_profile_id,),
    ).fetchone()
    return row["field_value"] if row else ""


def _send_connection_request_email(db_path: Path, grant_id: str) -> None:
    """Email push half of the connection-request two-layer model
    (2026-09-20): the in-app notification row is the source of truth and
    is already committed; this adds the owner's email with a 7-day
    decision link (the same /a/{token} grant_review view the digest
    mails use). Runs as a BackgroundTask so a slow/down SMTP server
    never blocks the public request endpoint; failures are logged,
    never raised.
    """
    conn = whitelist_db.wl_connect(db_path)
    try:
        grant = whitelist_db.get_grant(conn, grant_id)
        if not grant:
            return
        owner_id = grant.get("owner_id") or grant["profile_id"]
        owner_email = _owner_email_for(conn, owner_id)
    finally:
        conn.close()
    if not owner_email:
        print(f"[WARN] No email field on owner profile {owner_id}; "
              f"connection-request email skipped for grant {grant_id}",
              file=sys.stderr)
        return

    who = grant.get("requester_name") or grant["requester_email"]
    token = wl_tokens.make_token(
        _get_secret(), "grant_review", grant_id, expires_days=7)
    link = f"{mailer.app_base_url()}/a/{token}"
    body = (
        "Hi,\n\n"
        f"New connection request on RelMgr from {who} "
        f"({grant['requester_email']}).\n\n"
        f"Review and decide here:\n\n{link}\n\n"
        "This link expires in 7 days. You can also decide from the amber "
        "Requests box at the top of your WhiteList.\n"
    )
    mailer.send_email(owner_email, "RelMgr: new connection request", body)


def _qr_png(payload: str) -> bytes:
    """Render *payload* to a PNG QR code (single generator for the profile
    QR and share-bundle QR — one place to keep size/error-correction)."""
    import qrcode
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _vcf_escape(value: str) -> str:
    """Escape one vCard text value (backslash first, then ; , \r\n, \n).

    Bare \r is stripped too (audit 2026-09-25): CRLF is the vCard line
    delimiter, and a lone CR smuggled through could confuse lenient
    parsers into treating injected text as new properties.
    """
    return (value.replace("\\", "\\\\").replace(";", "\\;")
            .replace(",", "\\,").replace("\r\n", "\\n").replace("\n", "\\n")
            .replace("\r", ""))


def _build_vcard(profile: dict, cards: list[dict]) -> str:
    """vCard 3.0 built from EXACTLY the fields the viewer can see.

    Ruling 2026-09-20 (VCF download): the 'Save to contacts' file
    carries the same visibility-filtered set the shared view renders —
    cards arrive as cards_for_share_bundle output (visible_fields only).
    Fields are deduped by id (cards are lenses: one field can sit in
    several chosen cards). CRLF line endings per the vCard spec.
    """
    display = profile.get("display_name") or "Unknown"
    parts = display.split(" ", 1)
    first = parts[0]
    last = parts[1] if len(parts) > 1 else ""
    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"N:{_vcf_escape(last)};{_vcf_escape(first)};;;",
        f"FN:{_vcf_escape(display)}",
    ]
    if profile.get("title"):
        lines.append(f"TITLE:{_vcf_escape(profile['title'])}")
    if profile.get("company"):
        lines.append(f"ORG:{_vcf_escape(profile['company'])}")
    seen: set[int] = set()
    for card in cards:
        for f in card.get("visible_fields", []):
            fid = f.get("id")
            if fid in seen:
                continue
            seen.add(fid)
            v = _vcf_escape(f["field_value"])
            t = f["field_type"]
            if t == "email":
                lines.append(f"EMAIL;TYPE=INTERNET:{v}")
            elif t == "phone":
                lines.append(f"TEL;TYPE=CELL:{v}")
            elif t == "address":
                lines.append(f"ADR;TYPE=HOME:;;{v};;;")
            elif t == "website":
                lines.append(f"URL:{v}")
            elif t == "birthday":
                lines.append(f"BDAY:{v}")
            elif t == "nickname":
                lines.append(f"NICKNAME:{v}")
            elif t in ("note", "high_school", "maiden_name",
                       "childhood_address1", "childhood_city",
                       "childhood_state", "country"):
                # UX pass 3: personal-history + country fields travel as
                # labeled NOTE lines (vCard has no native slots for them).
                label = ("High school" if t == "high_school"
                         else "Maiden name" if t == "maiden_name"
                         else "Childhood home" if t.startswith("childhood_")
                         else "Country" if t == "country"
                         else "Note")
                lines.append(f"NOTE:{_vcf_escape(label + ': ' + f['field_value'])}")
            elif t == "title":
                lines.append(f"TITLE:{v}")
            elif t == "company":
                lines.append(f"ORG:{v}")
    lines.append("END:VCARD")
    return "\r\n".join(lines) + "\r\n"


@dataclass
class WebContext:
    """Per-app dependencies handed to every routes_* module's register()
    function by create_app (app.py).

    db_path / jinja are the two values the old single-file routes closed
    over. push_connection_email is read from the app module's namespace AT
    CREATE_APP TIME (not imported directly) so tests that monkeypatch
    app._send_connection_request_email before calling create_app() keep
    intercepting the BackgroundTask (see test_security_audit S5).
    """

    db_path: Path
    jinja: Jinja2Templates
    push_connection_email: Callable = _send_connection_request_email
