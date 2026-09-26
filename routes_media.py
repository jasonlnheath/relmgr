"""Media routes: guarded photo serving (/photos/...) and QR PNGs (/qr/...).

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

import json
from pathlib import Path

from fastapi import Request
from fastapi.responses import HTMLResponse, Response

import whitelist_db

from web_support import (
    WebContext,
    _consume_session_cookie,
    _get_secret,
    _qr_png,
)
import mailer
import wl_tokens


def register_media_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path

    def _photo_allowed(conn, request, card, viewer_email, owner_token):
        """Access predicate for /photos/{pid}/{cid}[/hs] (security audit
        2026-09-25 — the route used to serve ANY card's photo to ANYONE,
        enumerable by sequential profile/card ids).

        A photo is reachable when the card is PUBLICLY VISIBLE — it is the
        owner's default card (what the anonymous /p page renders) or it sits
        in a NON-EXPIRED share bundle — OR the viewer authenticates as the
        card owner's owning account: a signed owner_dashboard token (?t=,
        what the owner surfaces embed) or the session cookie.
        """
        if card is None:
            return False
        card_owner = card["owner_profile_id"]
        # Owner authentication: token/session profile must be the card
        # owner itself or the account that owns it (curated stubs have
        # profiles.owner_id = creating owner).
        auth_pid = None
        if owner_token:
            payload = wl_tokens.consume_token(
                _get_secret(), "owner_dashboard", owner_token)
            if payload and payload.isdigit():
                auth_pid = int(payload)
        if auth_pid is None:
            session_cookie = request.cookies.get("wl_session")
            if session_cookie:
                cand = _consume_session_cookie(session_cookie, _get_secret())
                if cand:
                    auth_pid = cand
        if auth_pid is not None:
            if auth_pid == card_owner:
                return True
            row = conn.execute(
                "SELECT owner_id FROM profiles WHERE id = ?", (card_owner,)
            ).fetchone()
            if row is not None and row["owner_id"] == auth_pid:
                return True
            return False
        # Anonymous: default card of its owner (first by the public order).
        default_row = conn.execute(
            f"SELECT id FROM cards WHERE owner_profile_id = ? "
            f"ORDER BY {whitelist_db._CARD_ORDER_SQL} LIMIT 1",
            (card_owner,),
        ).fetchone()
        if default_row is not None and default_row["id"] == card["id"]:
            return True
        # Anonymous: card present in a non-expired share bundle (the /s
        # pages render chosen cards' photos to anonymous openers).
        bundle_rows = conn.execute(
            "SELECT card_ids, expires_at FROM share_bundles WHERE profile_id = ?",
            (card_owner,),
        ).fetchall()
        for b in bundle_rows:
            try:
                ids = json.loads(b["card_ids"])
            except (ValueError, TypeError):
                continue
            if card["id"] in ids and not whitelist_db.bundle_is_expired(dict(b)):
                return True
        # Granted contact (?e= with an admitted grant) — same tier rule the
        # /p page itself applies before rendering these photos.
        if viewer_email and whitelist_db.effective_tier(
                conn, card_owner, viewer_email) == "granted":
            return True
        return False

    def _serve_photo_response(request: Request, owner_profile_id: int,
                              card_id: int, slot: str):
        upload_dir = Path(__file__).parent / "uploads"
        photo_path = (f"{owner_profile_id}_{card_id}.jpg" if slot == "default"
                      else f"{owner_profile_id}_{card_id}_hs.jpg")
        full_path = upload_dir / photo_path
        if not full_path.exists():
            return HTMLResponse("Photo not found", status_code=404)
        conn = whitelist_db.wl_connect(path)
        try:
            card = whitelist_db.get_card_by_id(conn, card_id)
            if not _photo_allowed(
                    conn, request, card,
                    request.query_params.get("e"),
                    request.query_params.get("t")):
                return HTMLResponse("Photo not found", status_code=404)
        finally:
            conn.close()
        from fastapi.responses import FileResponse
        return FileResponse(full_path, media_type="image/jpeg")

    @application.get("/photos/{owner_profile_id}/{card_id}")
    async def serve_photo(request: Request, owner_profile_id: int, card_id: int):
        return _serve_photo_response(request, owner_profile_id, card_id, "default")

    @application.get("/photos/{owner_profile_id}/{card_id}/hs")
    async def serve_hs_photo(request: Request, owner_profile_id: int, card_id: int):
        """UX pass 3: the HIGH-SCHOOL picture slot on personal cards."""
        return _serve_photo_response(request, owner_profile_id, card_id, "hs")

    @application.get("/qr/share/{bundle_id}")
    async def serve_bundle_qr(bundle_id: str):
        """QR for a share bundle — encodes the single /s/{bundle_id} link."""
        conn = whitelist_db.wl_connect(path)
        try:
            bundle = whitelist_db.get_share_bundle(conn, bundle_id)
            if not bundle:
                return HTMLResponse("Not found", status_code=404)
        finally:
            conn.close()
        return Response(content=_qr_png(f"{mailer.app_base_url()}/s/{bundle_id}"),
                        media_type="image/png")

    @application.get("/qr/{handle}")
    async def serve_qr(handle: str):
        """Serve a QR code PNG for the given profile handle."""
        conn = whitelist_db.wl_connect(path)
        try:
            profile = whitelist_db.resolve_handle(conn, handle)
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
        finally:
            conn.close()

        return Response(content=_qr_png(f"{mailer.app_base_url()}/p/{handle}"),
                        media_type="image/png")
