"""My Profile routes: the profile page plus its five POST surfaces (bio,
bio-visibility, cards/new, cards/{id}/fields, fields/new) — all rendering
through ONE site (_my_profile_html).

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

import whitelist_db
import wl_tokens

from web_support import (
    WebContext,
    _get_secret,
    _resolve_owner,
    days_since,
    days_until,
)

import mailer


def register_profile_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

    def _my_profile_html(conn, request, token: str, profile: dict,
                        bio_error=None, new_card_error=None,
                        bio_override=None, share_error=None, status_code=200) -> HTMLResponse:
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
        # Resolve BASE_URL for the share-link template (config-driven:
        # APP_BASE_URL > legacy BASE_URL > LAN default, never fails).
        base_url = mailer.app_base_url()
        # Security audit 2026-09-25: 'View profile' carries a SIGNED
        # owner_dashboard token (?ot=), never the owner's raw email —
        # email knowledge must not authenticate the owner self-view.
        view_token = wl_tokens.make_token(
            _get_secret(), "owner_dashboard", str(profile_id))
        profile_view_url = f"{base_url}/p/{profile['handle']}?ot={view_token}"
        # UX pass 3: UNIFIED sharing — the link the QR + Share button carry
        # is the profile URL itself. No bundle, no card-choosing: the
        # access-grant decision lands after a contact requests access.
        share_url = f"{base_url}/p/{profile['handle']}"
        return HTMLResponse(jinja.get_template("my_profile.html").render(
            request=request,
            profile=profile,
            owner_id=profile_id,
            owner_email=owner_email,
            cards=cards,
            token=token,
            bio=bio,
            bio_len=len(bio),
            bio_error=bio_error,
            new_card_error=new_card_error,
            visit_count=visit_count,
            days_since=days_since,
            days_until=days_until,
            share_error=share_error,
            BASE_URL=base_url,
            share_url=share_url,
            profile_view_url=profile_view_url,
            share_message=(f"{profile['display_name']} wants to share their "
                           f"WhiteList card: {share_url}"),
            share_subject=f"{profile['display_name']} WhiteList Card",
        ), status_code=status_code)

    @application.get("/owner/{token}/profile", response_class=HTMLResponse)
    async def owner_profile(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            profile = result[1]
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/bio")
    async def owner_bio(request: Request, token: str):
        form = await request.form()
        bio = (form.get("bio") or "").strip()
        bio_error = None
        if len(bio) > 500:
            # B2: over-limit is REJECTED — never silently truncate-and-save.
            # The draft re-renders so the user can trim it themselves.
            # UX pass 2 (2026-09-22): cap lowered 2000 → 500.
            bio_error = f"Bio must be 500 characters or fewer (currently {len(bio)})."
            conn = whitelist_db.wl_connect(path)
            try:
                result = _resolve_owner(conn, request, token, _get_secret())
                if result[0] is None and result[2] is None:
                    return HTMLResponse("Invalid or expired link", status_code=403)
                if result[2]:
                    return RedirectResponse(url=f"/owner/{result[2]}")
                profile_id = result[0]
                profile = result[1]
                if not profile:
                    return HTMLResponse("Profile not found", status_code=404)
                return _my_profile_html(conn, request, token, profile,
                                        bio_error=bio_error, bio_override=bio,
                                        status_code=400)
            finally:
                conn.close()

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            profile = result[1]
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            whitelist_db.update_bio(conn, profile_id, bio)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile,
                                    bio_error=bio_error)
        finally:
            conn.close()

    @application.post("/owner/{token}/bio-visibility")
    async def owner_bio_visibility(request: Request, token: str):
        """Toggle bio visibility between public and private."""
        conn = whitelist_db.wl_connect(path)
        try:
            # Security audit 2026-09-25: this route used a legacy fallback
            # that resolved a non-integer (pre-migration) token payload to
            # the FIRST profile in the DB and flipped ITS bio visibility.
            # It now resolves the owner exactly like every other /owner
            # route (ruling 2026-09-20 option A: legacy links are retired).
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            profile = result[1]
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            form = await request.form()
            visibility = (form.get("bio_visibility") or "").strip()
            if visibility not in ("public", "private"):
                return HTMLResponse("Invalid visibility value", status_code=400)

            whitelist_db.update_bio_visibility(conn, profile_id, visibility)
            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)

            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/new")
    async def owner_create_card(request: Request, token: str):
        form = await request.form()
        name = (form.get("name") or "").strip()
        name_error = None
        if not name:
            name_error = "Card name is required."
        elif len(name) > 60:
            name_error = "Card name must be 60 characters or fewer."

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

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
        form = await request.form()
        field_ids_raw = form.getlist("field_ids")
        field_ids = [int(f) for f in field_ids_raw if f]

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

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
        form = await request.form()
        field_type = form.get("field_type", "")
        field_value = (form.get("field_value") or "").strip()
        # UX pass 2 defaults ruling: everything defaults to 'granted'.
        visibility = form.get("visibility", "granted")

        if not field_type or field_type not in ("email", "phone"):
            return HTMLResponse("Invalid field type", status_code=400)
        if not field_value:
            return HTMLResponse("Field value is required", status_code=400)
        if visibility not in ("public", "granted"):
            return HTMLResponse("Invalid visibility", status_code=400)

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            whitelist_db.add_profile_field(conn, profile_id, field_type, field_value, visibility)

            profile = whitelist_db.get_profile_by_id(conn, profile_id)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _my_profile_html(conn, request, token, profile)
        finally:
            conn.close()
