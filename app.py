"""FastAPI application for the whitelist service.

Module-level ``app`` is a real FastAPI instance so that
``uvicorn app:app`` works out of the box (F2). Secrets are read lazily
per-request, never at import time — importing this module must not
require WHITELIST_SECRET to be present.
"""

from pathlib import Path
import os
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse
from starlette.templating import Jinja2Templates
from jinja2 import pass_context

import whitelist_db
import wl_tokens
import wl_env

_NOW_FMT = "%Y-%m-%dT%H:%M:%SZ"


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


_JINJA_DIR = Path(__file__).parent / "templates"


def _make_jinja():
    return Jinja2Templates(directory=str(_JINJA_DIR))


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


def create_app(db_path: Path = None) -> FastAPI:
    """Create and configure the FastAPI application.

    ``db_path`` defaults to contacts.db next to this module. The returned
    app also assigns to the module-level ``app`` attribute so repeated
    create_app() calls don't leave a dead entrypoint behind.
    """
    global app

    # Resolution order: explicit arg > RELMGR_DB_PATH env > local prod file.
    # The env override exists so tests (and their subprocesses) NEVER boot
    # against the real contacts.db — the module-level `app = create_app()` at
    # import time otherwise mutates prod via the boot chain. Deliberately not
    # WHITELIST_-prefixed: test_refactor_fixes strips WHITELIST_* from env and
    # still must not fall back to the prod file. (q38 review)
    path = Path(db_path or os.environ.get("RELMGR_DB_PATH")
                or Path(__file__).parent / "contacts.db")
    jinja = _make_jinja()
    application = FastAPI(title="Whitelist")

    # Self-heal legacy schema in ONE ordered call (v1 CHECK lacks 'revoked',
    # additive P3 tables, v2-without-context prod case — see
    # whitelist_db.ensure_whitelist_schema for why the order matters).
    # Idempotent; guarded by file existence so importing on an empty CWD
    # doesn't conjure a stray contacts.db.
    if path.exists():
        _mconn = whitelist_db.wl_connect(path)
        try:
            whitelist_db.ensure_whitelist_schema(_mconn)
        finally:
            _mconn.close()

    @application.get("/p/{handle}", response_class=HTMLResponse)
    async def profile_page(
        request: Request,
        handle: str,
        e: str = Query(None, alias="e"),
    ):
        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("<h1>Profile not found</h1>", status_code=404)

            # P3-T4: a successful resolution is the tracked event. Anonymous
            # visits keep viewer_email NULL — still a scan (that's the point).
            whitelist_db.record_scan(conn, profile["id"], e if e else None)

            viewer_email = e if e else None
            tier = whitelist_db.effective_tier(conn, profile["id"], viewer_email)

            stale = is_verified_stale(profile.get("verified_at"))

            # B4: the public page renders cards. Profiles with NO cards at all
            # (seed_default_cards only auto-attaches for jasonheath) keep the
            # legacy flat field list — a card-less profile must not render an
            # empty public page.
            cards = whitelist_db.cards_for_public_view(
                conn, profile["id"], tier)

            return HTMLResponse(jinja.get_template("profile.html").render(
                request=request, profile=profile, tier=tier, stale=stale,
                cards=cards, days_since=days_since))
        finally:
            conn.close()

    @application.get("/p/{handle}/request-form", response_class=HTMLResponse)
    async def request_form_page(request: Request, handle: str):
        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("<h1>Profile not found</h1>", status_code=404)
            return HTMLResponse(jinja.get_template("request_form.html").render(
                request=request, profile=profile))
        finally:
            conn.close()

    @application.post("/p/{handle}/request")
    async def submit_request(request: Request, handle: str):
        form = await request.form()
        name = form.get("name", "")
        email = form.get("email", "")

        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            grant_id = whitelist_db.create_grant(conn, profile["id"], email, name)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("request_success.html").render(
            request=request, profile=profile, grant_id=grant_id))

    @application.get("/a/{token}", response_class=HTMLResponse)
    async def admin_link(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "grant_review", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        grant_id = payload
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_review.html").render(
            request=request, grant=grant, profile=profile, token=token))

    @application.post("/a/{token}/decision")
    async def admin_decision(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "grant_review", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        decision = form.get("decision", "")
        expires_at_choice = form.get("expiry", "90")

        grant_id = payload
        conn = whitelist_db.wl_connect(path)
        try:
            return _decision_outcome(conn, jinja, request, grant_id,
                                     decision, expires_at_choice)
        finally:
            conn.close()

    @application.get("/verify/{token}", response_class=HTMLResponse)
    async def verify_page(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "verify", token)
        if payload is None:
            return HTMLResponse("Invalid or expired verification link", status_code=403)

        profile_id = int(payload)
        conn = whitelist_db.wl_connect(path)
        try:
            whitelist_db.update_verified_at(conn, profile_id)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("verify_success.html").render(
            request=request, profile=profile))

    # ------------------------------------------------------------------ Owner dashboard → contact list (Phase A2)
    @application.get("/owner/{token}", response_class=HTMLResponse)
    async def owner_dashboard(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            # Get query params — junk input must degrade to page 0, not 500.
            q = request.query_params.get("q")
            try:
                page = max(0, int(request.query_params.get("page", 0)))
            except ValueError:
                page = 0
            per_page = 50

            # Owner dashboard aggregates ALL profiles' grants
            all_profiles = conn.execute("SELECT * FROM profiles ORDER BY id").fetchall()
            all_profile_ids = [dict(p)["id"] for p in all_profiles]
            if not all_profile_ids:
                all_profile_ids = [profile_id]

            # Use the new contact list data layer (graceful if contacts table missing)
            if whitelist_db._table_exists(conn, "contacts"):
                # Aggregate across all profiles, then paginate at the HTTP level
                # so page 0 = the first `per_page` rows (AC #3). The data layer
                # already applies search (q) and pending-first ordering; we keep
                # one combined pass for cross-profile email dedupe and the true
                # total, then slice it — "page 1 of 51" stays row 51.
                all_rows: list[dict] = []
                seen_emails: set[str] = set()
                for pid in all_profile_ids:
                    profile_rows = whitelist_db.list_contact_list_rows(conn, pid, q=q, page=0, per_page=999999)
                    for r in profile_rows:
                        email = (r.get("email") or "").lower()
                        if email not in seen_emails:
                            seen_emails.add(email)
                            all_rows.append(r)
                total_rows = len(all_rows)
                start = page * per_page
                rows = all_rows[start:start + per_page]
            else:
                # Pure whitelist mode — list all grants across all profiles
                all_grants = conn.execute(
                    "SELECT * FROM access_grants WHERE profile_id IN ({}) ORDER BY status, created_at".format(",".join("?" for _ in all_profile_ids)),
                    all_profile_ids,
                ).fetchall()
                rows = []
                profile_map = {p["id"]: dict(p) for p in all_profiles}
                for g in all_grants:
                    gd = dict(g)
                    if gd["status"] == "denied":
                        continue
                    prof = profile_map.get(gd["profile_id"])
                    rows.append({
                        "contact_id": None,
                        "name": gd.get("requester_name") or gd.get("requester_email", "Unknown"),
                        "email": gd.get("requester_email", ""),
                        "phone": "",
                        "org": "",
                        "granted": gd["status"] == "granted",
                        "live_grant": gd,
                        "cards": [],
                        "perm": "permanent" if gd.get("expires_at") is None else ("temp" if gd.get("expires_at") else None),
                        "logo_state": ("fresh" if whitelist_db.is_current_quarter(prof.get("verified_at")) else "stale") if prof else None,
                        "refreshed_at": None,
                        "is_pending": gd["status"] == "pending",
                    })
                total_rows = len(rows)

            # Count denied grants across all profiles
            if all_profile_ids:
                denied_count = conn.execute(
                    f"SELECT COUNT(*) FROM access_grants WHERE profile_id IN ({','.join('?' for _ in all_profile_ids)}) AND status = 'denied'",
                    all_profile_ids,
                ).fetchone()[0]
            else:
                denied_count = 0

            # Unified row list for single-surface contact list (round-2)
            all_rows = rows
            total_contacts = total_rows

            # Owner's own card for the "my card" section
            my_card = None
            owner_profile = conn.execute("SELECT * FROM profiles WHERE id = ?", (profile_id,)).fetchone()
            if owner_profile:
                owner_cards = whitelist_db.list_cards(conn, profile_id)
                if owner_cards:
                    first_card = owner_cards[0]
                    my_card = {
                        "owner_id": profile_id,
                        "id": first_card["id"],
                        "name": owner_profile["display_name"],
                        "email": "",
                        "photo_path": first_card.get("photo_path"),
                    }
                    # Grab email from owner's fields
                    owner_fields = conn.execute(
                        "SELECT * FROM profile_fields WHERE profile_id = ? AND field_type = 'email' LIMIT 1",
                        (profile_id,)
                    ).fetchall()
                    if owner_fields:
                        my_card["email"] = owner_fields[0]["field_value"]

            # Fetch all cards for approve forms (pending rows) — use first profile
            all_cards = whitelist_db.list_cards(conn, all_profile_ids[0] if all_profile_ids else profile_id)

            return HTMLResponse(jinja.get_template("contact_list.html").render(
                request=request,
                all_rows=all_rows,
                my_card=my_card,
                all_cards=all_cards,
                token=token,
                q=q,
                page=page,
                per_page=per_page,
                total_rows=total_rows,
                total_contacts=total_contacts,
                denied_count=denied_count,
                days_since=days_since,
                days_until=days_until,
            ))
        finally:
            conn.close()

    # ------------------------------------------------------------------ Approve with cards (P5-T3)
    @application.post("/owner/{token}/approve", response_class=HTMLResponse)
    async def owner_approve(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        decision = form.get("decision", "")
        card_ids_raw = form.getlist("card_ids")
        access = form.get("access", "quarter")

        # Validate: at least one card required
        if not card_ids_raw:
            return HTMLResponse("At least one card must be selected", status_code=400)

        expiry_choice = "lifetime" if access == "lifetime" else "quarter"

        conn = whitelist_db.wl_connect(path)
        try:
            result = _decision_outcome(conn, jinja, request, grant_id,
                                       decision, expiry_choice)
            # If approved, set the card assignments
            if decision == "approve" and result.status_code == 200:
                card_ids = [int(c) for c in card_ids_raw]
                whitelist_db.set_grant_cards(conn, grant_id, card_ids)
            return result
        finally:
            conn.close()

    # ------------------------------------------------------------------ Junk folder (P5-T3)
    @application.get("/owner/{token}/junk", response_class=HTMLResponse)
    async def owner_junk(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)
            denied = conn.execute(
                "SELECT * FROM access_grants WHERE profile_id = ? AND status = 'denied' ORDER BY created_at DESC",
                (profile_id,),
            ).fetchall()
            denied_list = [dict(d) for d in denied]
            return HTMLResponse(jinja.get_template("junk.html").render(
                request=request,
                denied=denied_list,
                token=token,
                days_since=days_since,
            ))
        finally:
            conn.close()

    # ------------------------------------------------------------------ Manage access (P5-T3)
    @application.post("/owner/{token}/access", response_class=HTMLResponse)
    async def owner_manage_access(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        card_ids_raw = form.getlist("card_ids")
        access = form.get("access", "quarter")

        if not grant_id:
            return HTMLResponse("No grant selected", status_code=400)

        expiry_choice = "lifetime" if access == "lifetime" else "quarter"

        conn = whitelist_db.wl_connect(path)
        try:
            # Update expiry if access changed
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)

            # Compute new expires_at
            if grant["status"] == "granted":
                if expiry_choice == "lifetime":
                    expires_at = None
                elif expiry_choice == "quarter":
                    expires_at = whitelist_db.quarter_end_iso()
                else:
                    expires_at = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")

                whitelist_db.update_grant_status(
                    conn, grant_id, "granted",
                    granted_at=grant.get("granted_at"),
                    expires_at=expires_at,
                    commit=False,
                )
                whitelist_db._log_action(conn, grant_id, grant["profile_id"],
                                         "approved", expiry_choice)
                conn.commit()

            # Update cards
            card_ids = [int(c) for c in card_ids_raw] if card_ids_raw else []
            whitelist_db.set_grant_cards(conn, grant_id, card_ids)

            return HTMLResponse("Access updated")
        finally:
            conn.close()

    # ------------------------------------------------------------------ My Profile tab (Phase A1)

    def _my_profile_html(conn, request, token: str, profile: dict,
                        bio_error=None, new_card_error=None,
                        bio_override=None, status_code=200) -> HTMLResponse:
        """Render my_profile.html from ONE place.

        ALL five My Profile sites (GET /profile, POST /bio, /cards/new,
        /cards/{id}/fields, /fields/new, /cards/{id}/photo) must call this —
        forking the render block is how the B2 scan stats got dropped twice
        (bug #5 in the Qwen pass, and again over HTTP in the q38 review).
        `status_code` lets validation failures answer 400 with the friendly
        rendered page (spec B2: dup card / over-limit bio → 400 page).
        """
        profile_id = profile["id"]

        # Get owner email for View profile link
        owner_email = ""
        for f in profile.get("fields", []):
            if f.get("field_type") == "email":
                owner_email = f["field_value"]
                break

        # Get all cards with fields
        cards = whitelist_db.list_cards(conn, profile_id)
        # Enrich with photo_path and field_ids
        for card in cards:
            card["photo_path"] = card.get("photo_path")
            card["field_ids"] = [f["id"] for f in card.get("fields", [])]

        # All profile fields for the field picker
        all_fields = conn.execute(
            "SELECT * FROM profile_fields WHERE profile_id = ? ORDER BY field_type, field_value",
            (profile_id,),
        ).fetchall()
        all_fields = [dict(f) for f in all_fields]

        # B2: header card keeps its scan stats (last 14 days).
        scan_stats = whitelist_db.get_scan_stats(conn, profile_id)
        visit_count = sum(s["scans"] for s in scan_stats)

        bio = profile.get("bio") or ""
        if bio_override is not None:
            # Re-display what the user typed (e.g. an over-limit draft we
            # refused to save) instead of the stale stored value. Copy first —
            # template reads profile.bio for BOTH textarea and header.
            profile = {**profile, "bio": bio_override}
            bio = bio_override
        return HTMLResponse(jinja.get_template("my_profile.html").render(
            request=request,
            profile=profile,
            owner_id=profile_id,
            owner_email=owner_email,
            cards=cards,
            all_fields=all_fields,
            token=token,
            bio=bio,
            bio_len=len(bio),
            bio_error=bio_error,
            new_card_error=new_card_error,
            visit_count=visit_count,
            days_since=days_since,
            days_until=days_until,
        ), status_code=status_code)

    @application.get("/owner/{token}/profile", response_class=HTMLResponse)
    async def owner_profile(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile = whitelist_db.get_profile(conn, row["handle"])
                else:
                    profile = None
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            # Deterministic rebind — the except-branch only sets `profile_id`
            # in one sub-branch, and this route (and the render) depend on it.
            profile_id = profile["id"]

            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/bio")
    async def owner_bio(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        bio = (form.get("bio") or "").strip()
        bio_error = None
        if len(bio) > 2000:
            # B2: over-limit is REJECTED — never silently truncate-and-save.
            # The draft re-renders so the user can trim it themselves.
            bio_error = f"Bio must be 2000 characters or fewer (currently {len(bio)})."
            conn = whitelist_db.wl_connect(path)
            try:
                try:
                    profile_id = int(payload)
                except (ValueError, TypeError):
                    row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                    if row:
                        profile_id = row["id"]
                    else:
                        return HTMLResponse("Profile not found", status_code=404)
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
                if not profile:
                    return HTMLResponse("Profile not found", status_code=404)
                return _my_profile_html(conn, request, token, profile,
                                        bio_error=bio_error, bio_override=bio,
                                        status_code=400)
            finally:
                conn.close()

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            whitelist_db.update_bio(conn, profile_id, bio)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile,
                                    bio_error=bio_error)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/new")
    async def owner_create_card(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        name = (form.get("name") or "").strip()
        name_error = None
        if not name:
            name_error = "Card name is required."
        elif len(name) > 60:
            name_error = "Card name must be 60 characters or fewer."

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            if not name_error:
                try:
                    whitelist_db.create_card(conn, profile_id, name, [])
                except ValueError:
                    name_error = "A card with this name already exists."

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            # Friendly 400 page on dup (spec B2); friendly 200 on success.
            return _my_profile_html(conn, request, token, profile,
                                    new_card_error=name_error,
                                    status_code=400 if name_error else 200)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/fields")
    async def owner_set_card_fields(request: Request, token: str, card_id: int):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        field_ids_raw = form.getlist("field_ids")
        field_ids = [int(f) for f in field_ids_raw if f]

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            # Cross-owner guard (AC #6): the token's profile must own this
            # card. Only an EXISTING foreign card 404s; a missing card falls
            # through to set_card_fields, whose ValueError still 400s (B3:
            # junk field ids → 400, never 500).
            card = whitelist_db.get_card_by_id(conn, card_id)
            if card is not None and card["owner_profile_id"] != profile_id:
                return HTMLResponse("Not found", status_code=404)

            try:
                whitelist_db.set_card_fields(conn, card_id, field_ids)
            except ValueError:
                return HTMLResponse("Invalid field or card", status_code=400)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/fields/new")
    async def owner_add_field(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        field_type = form.get("field_type", "")
        field_value = (form.get("field_value") or "").strip()
        visibility = form.get("visibility", "public")

        if not field_type or field_type not in ("email", "phone"):
            return HTMLResponse("Invalid field type", status_code=400)
        if not field_value:
            return HTMLResponse("Field value is required", status_code=400)
        if visibility not in ("public", "granted"):
            return HTMLResponse("Invalid visibility", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            whitelist_db.add_profile_field(conn, profile_id, field_type, field_value, visibility)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/photo")
    async def owner_upload_photo(request: Request, token: str, card_id: int):
        from starlette.datastructures import UploadFile
        import os

        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        remove_photo = form.get("remove_photo")

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            # Cross-owner guard (same check as the card-preview route).
            card = whitelist_db.get_card_by_id(conn, card_id)
            if not card:
                return HTMLResponse("Card not found", status_code=404)
            if card["owner_profile_id"] != profile_id:
                return HTMLResponse("Not found", status_code=404)

            upload_dir = Path(__file__).parent / "uploads"
            upload_dir.mkdir(exist_ok=True)
            photo_path = f"{profile_id}_{card_id}.jpg"
            full_path = upload_dir / photo_path

            if remove_photo:
                # Remove photo
                if card.get("photo_path"):
                    try:
                        os.unlink(full_path)
                    except OSError:
                        pass
                whitelist_db.update_card_photo(conn, card_id, None)
            else:
                # Upload photo
                photo_file = form.get("photo")
                if isinstance(photo_file, UploadFile) and photo_file.filename:
                    content = await photo_file.read()
                    if len(content) > 10 * 1024 * 1024:  # 10 MB
                        return HTMLResponse("File too large (max 10 MB)", status_code=413)

                    # Sniff magic bytes
                    if content[:3] == b"\xff\xd8\xff" or content[:4] == b"\x89PNG":
                        from PIL import Image
                        import io
                        try:
                            img = Image.open(io.BytesIO(content))
                            img.verify()
                            img = Image.open(io.BytesIO(content))
                            if img.format not in ("JPEG", "PNG"):
                                return HTMLResponse("Unsupported image format", status_code=400)
                            # Center-crop to square
                            w, h = img.size
                            side = min(w, h)
                            left = (w - side) // 2
                            top = (h - side) // 2
                            img = img.crop((left, top, left + side, top + side))
                            # Resize to 512x512
                            img = img.resize((512, 512), Image.LANCZOS)
                            # Save as JPEG
                            buf = io.BytesIO()
                            img.save(buf, format="JPEG", quality=82)
                            buf.seek(0)
                            full_path.write_bytes(buf.read())
                        except Exception:
                            return HTMLResponse("Invalid image file", status_code=400)
                    else:
                        return HTMLResponse("Invalid image file", status_code=400)

                    whitelist_db.update_card_photo(conn, card_id, photo_path)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.get("/owner/{token}/profile/card/{card_id}")
    async def owner_card_preview(request: Request, token: str, card_id: int):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                profile_id = int(payload)
            except (ValueError, TypeError):
                row = conn.execute("SELECT * FROM profiles ORDER BY id LIMIT 1").fetchone()
                if row:
                    profile_id = row["id"]
                else:
                    return HTMLResponse("Profile not found", status_code=404)

            card = whitelist_db.get_card_by_id(conn, card_id)
            if not card:
                return HTMLResponse("Card not found", status_code=404)
            if card["owner_profile_id"] != profile_id:
                return HTMLResponse("Not found", status_code=404)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("card_preview.html").render(
            request=request,
            card=card,
            profile=profile,
            owner_id=profile_id,
            token=token,
            days_since=days_since,
        ))

    @application.get("/photos/{owner_profile_id}/{card_id}")
    async def serve_photo(owner_profile_id: int, card_id: int):
        upload_dir = Path(__file__).parent / "uploads"
        photo_path = f"{owner_profile_id}_{card_id}.jpg"
        full_path = upload_dir / photo_path
        if not full_path.exists():
            return HTMLResponse("Photo not found", status_code=404)
        from fastapi.responses import FileResponse
        return FileResponse(full_path, media_type="image/jpeg")

    @application.get("/exports/qr_{handle}.png")
    async def serve_qr(handle: str):
        """Serve QR code PNG for the given profile handle."""
        qr_dir = Path(__file__).parent / "exports"
        qr_path = qr_dir / f"qr_{handle}.png"
        if not qr_path.exists():
            return HTMLResponse("QR not found", status_code=404)
        from fastapi.responses import FileResponse
        return FileResponse(qr_path, media_type="image/png")

    @application.post("/owner/{token}/decision")
    async def owner_decision(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        decision = form.get("decision", "")
        expiry = form.get("expiry", "90")

        conn = whitelist_db.wl_connect(path)
        try:
            return _decision_outcome(conn, jinja, request, grant_id,
                                     decision, expiry)
        finally:
            conn.close()

    # Context routes (/categorize, /context) REMOVED per Jason ruling
    # 2026-09-12 — feature cut from the product. DB layer untouched; if it's
    # ever revived it's app-layer work only (git history has the code).

    @application.get("/owner/{token}/contact/{grant_id}", response_class=HTMLResponse)
    async def owner_contact_card(request: Request, token: str, grant_id: str):
        """Contact card — single-surface view of one contact from the dashboard.
        Ruling: revoke lives on the contact card, not the list details expander.
        """
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            cards = whitelist_db.list_cards(conn, grant["profile_id"])
            for card in cards:
                card["photo_path"] = card.get("photo_path")
                card["field_ids"] = [f["id"] for f in card.get("fields", [])]
                # Enrich visible_fields
                if card.get("fields"):
                    card["visible_fields"] = card["fields"]
                else:
                    card["visible_fields"] = []
            stale = is_verified_stale(profile.get("verified_at"))
            # Determine tier for this grant
            if grant["status"] == "granted":
                tier = "granted"
            elif grant["status"] == "pending":
                tier = "pending"
            else:
                tier = "denied"
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("contact_card.html").render(
            request=request, profile=profile, grant=grant, cards=cards,
            tier=tier, stale=stale, days_since=days_since, token=token,
            grant_id=grant_id))

    @application.post("/owner/{token}/bulk", response_class=HTMLResponse)
    async def owner_bulk(request: Request, token: str):
        """P4-T2: one decision over many grants. Per-grant scoping lives in
        bulk_apply (approve/deny -> pending only; revoke -> granted only);
        dead rows skip, they never abort the batch."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_ids = form.getlist("grant_ids")
        decision = str(form.get("decision", ""))
        expiry = str(form.get("expiry", "90"))

        if not grant_ids:
            return HTMLResponse("No grants selected", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            try:
                summary = whitelist_db.bulk_apply(conn, grant_ids, decision, expiry)
            except ValueError as exc:
                return HTMLResponse(str(exc), status_code=400)
        finally:
            conn.close()

        return HTMLResponse(
            f"Bulk {decision}: {summary['approved']} approved, "
            f"{summary['denied']} denied, {summary['revoked']} revoked, "
            f"{summary['skipped']} skipped (wrong status or unknown id).")

    @application.post("/owner/{token}/revoke", response_class=HTMLResponse)
    async def owner_revoke(request: Request, token: str):
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            # Only active access can be revoked — anything else is an error,
            # surfaced (not swallowed): the helper raises ValueError.
            whitelist_db.revoke_grant(conn, grant_id)
            grant = whitelist_db.get_grant(conn, grant_id)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=grant, profile=profile, decision="revoke"))

    # ------------------------------------------------------------------ Quarterly actions
    @application.post("/owner/{token}/quarter/make_permanent", response_class=HTMLResponse)
    async def quarter_make_permanent(request: Request, token: str):
        """Make a grey grant permanent (lifetime access)."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            updated = whitelist_db.make_grant_permanent(conn, grant_id)
            if updated is None:
                return HTMLResponse("Grant not found", status_code=404)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=updated, profile=profile, decision="make_permanent"))

    @application.post("/owner/{token}/quarter/revoke", response_class=HTMLResponse)
    async def quarter_revoke(request: Request, token: str):
        """Revoke a grey grant (lands in blocked state)."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            whitelist_db.revoke_grant(conn, grant_id)
            grant = whitelist_db.get_grant(conn, grant_id)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=grant, profile=profile, decision="revoke"))

    @application.post("/owner/{token}/quarter/punt", response_class=HTMLResponse)
    async def quarter_punt(request: Request, token: str):
        """Punt a grey grant for another quarter."""
        payload = wl_tokens.consume_token(_get_secret(), "owner_dashboard", token)
        if payload is None:
            return HTMLResponse("Invalid or expired link", status_code=403)

        form = await request.form()
        grant_id = form.get("grant_id", "")
        conn = whitelist_db.wl_connect(path)
        try:
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            profile = whitelist_db.get_profile_by_id(conn, grant["profile_id"])
            updated = whitelist_db.punt_grant(conn, grant_id)
            if updated is None:
                return HTMLResponse("Grant not found", status_code=404)
        except ValueError as exc:
            return HTMLResponse(str(exc), status_code=409)
        finally:
            conn.close()

        return HTMLResponse(jinja.get_template("admin_decision.html").render(
            request=request, grant=updated, profile=profile, decision="punt"))

    app = application
    return application


# Module-level entrypoint: a fully-routed app (not a bare stub) so that
# ``uvicorn app:app`` serves the real service without any pre-call. Secrets are
# only touched per-request, so building here does not require them at import.
app = create_app()
