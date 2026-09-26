"""Card editor routes: the editor page (GET/POST), per-field ✕ delete,
card delete, photo upload, and the card preview.

The editor has exactly TWO seams (2026-09-26 refactor preserved them):
`_card_editor_html` is the ONE render site and `_parse_editor_form` is the
ONE form parser shared by save + ✕-delete (the ✕ posts the whole editor
form; ignoring the body was a real data-loss bug, pass 2).

Split out of app.py; behavior is unchanged.
"""

import re
from pathlib import Path

from fastapi import Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse

import whitelist_db
import wl_env

from web_support import (
    WebContext,
    _encode_square_jpeg,
    _get_secret,
    _resolve_owner,
    days_since,
)


def register_editor_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

    def _resolve_editor_card(conn, request, token: str, card_id: int):
        """Shared auth + ownership guard for the card-editor routes.

        Returns (profile_id, card, error_response) — error_response is set
        when the caller must return it immediately (403 invalid link,
        session-redirect, or 404 unknown/foreign card — ruling 2A).

        UX pass 3 exception: CURATED stub profiles. A profile the owner
        created via the + new-connection flow (owner_id = that owner,
        password_hash NULL — never self-published) is editable by its
        creating owner, so 'Create vCard' can open the new vCard's editor.
        Other accounts still 404 (2A isolation intact), and a profile that
        has signed in / set a password is self-published and closes again.
        """
        result = _resolve_owner(conn, request, token, _get_secret())
        if result[0] is None and result[2] is None:
            return None, None, HTMLResponse("Invalid or expired link", status_code=403)
        if result[2]:
            return None, None, RedirectResponse(url=f"/owner/{result[2]}")
        profile_id = result[0]
        card = whitelist_db.get_card_by_id(conn, card_id)
        if not card:
            return None, None, HTMLResponse("Card not found", status_code=404)
        if card["owner_profile_id"] != profile_id:
            stub = conn.execute(
                "SELECT owner_id, password_hash FROM profiles WHERE id = ?",
                (card["owner_profile_id"],),
            ).fetchone()
            if not (stub is not None and stub["password_hash"] is None
                    and stub["owner_id"] == profile_id):
                return None, None, HTMLResponse("Not found", status_code=404)
        return profile_id, card, None

    def _card_editor_html(conn, request, token: str, profile: dict, card: dict,
                          error: str = None, status_code: int = 200) -> HTMLResponse:
        """Render card_editor.html from ONE place.

        GET /cards/{id}/edit, POST /cards/{id}/edit (validation errors and
        the success re-render) and POST /cards/{id}/photo all answer
        through here so the editor page can never drift between routes.
        """
        field_types = whitelist_db.CARD_EDITOR_FIELD_TYPES
        by_type = {t: [] for t in field_types}
        for f in card.get("fields", []):
            if f["field_type"] in by_type:
                by_type[f["field_type"]].append(dict(f))
        base_url = wl_env.get_secret("BASE_URL") or "http://100.81.77.168:8099"
        # UX pass 5: determine card scope for scoped sections + address
        # blocks. card_kind is name-based ('personal'/'work'/None) — every
        # other card is a generic vCard, so None maps to the 'vcard'
        # scope; the scoped sections (picker_sections) carry the heading
        # 'Addresses' that the editor's grouped-block branch matches.
        card_scope = whitelist_db.card_kind(card) or "vcard"
        address_block = whitelist_db.address_blocks(card_scope)
        return HTMLResponse(jinja.get_template("card_editor.html").render(
            request=request,
            profile=profile,
            card=card,
            by_type=by_type,
            sections=whitelist_db.picker_sections(card_scope),
            labels=whitelist_db.CARD_EDITOR_FIELD_LABELS,
            field_types=field_types,
            multi_types=whitelist_db.CARD_EDITOR_MULTI_TYPES,
            token=token,
            owner_id=profile["id"],
            error=error,
            BASE_URL=base_url,
            address_block=address_block,
            address_block_types=whitelist_db.ADDRESS_BLOCK_TYPES,
            label_choices=whitelist_db.PHONE_LABEL_CHOICES,
            event_label_choices=whitelist_db.EVENT_LABEL_CHOICES,
        ), status_code=status_code)

    @application.get("/owner/{token}/cards/{card_id}/edit", response_class=HTMLResponse)
    async def owner_card_edit(request: Request, token: str, card_id: int):
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err
            # UX pass 3: render the CARD-owner profile — for curated stubs
            # (new-connection vCards) the name being edited is the stub's,
            # never the signed-in owner's.
            profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    _FIELD_KEY_RE = re.compile(r"^field_(\d+)_(value|remove)$")

    # UX pass 3 defaults ruling (2026-09-23): identity/friend-finding fields
    # default PUBLIC — title, company, website, birthday, the personal
    # history types (high school / maiden name / nickname), and the
    # city/state-level address parts. Street-level addresses (address1,
    # address2, zip, childhood street) default 'granted'; everything else
    # defaults 'granted'.
    _PUBLIC_DEFAULT_TYPES = ("title", "company", "website", "birthday",
                             "high_school", "maiden_name", "nickname",
                             "city", "state",
                             "childhood_city", "childhood_state")
    # UX pass 5: custom_field defaults PRIVATE (arbitrary content).
    _PRIVATE_DEFAULT_TYPES = ("custom_field",)

    def _editor_default_visibility(field_type: str) -> str:
        if field_type in _PRIVATE_DEFAULT_TYPES:
            return "private"
        return ("public" if field_type in _PUBLIC_DEFAULT_TYPES else "granted")

    def _parse_editor_form(form):
        """Parse the card-editor POST body into save_card_editor args.

        Shared by the save route AND the per-field ✕ delete route: the ✕
        posts the WHOLE editor form (formaction override), so the delete
        path must persist everything else keyed in — this is the fix for
        the pass-2 data-loss bug (deleting a field used to drop edits).

        Returns (display_name, card_name, updates, labels, removals,
        new_fields) where updates are (fid, value, visibility), labels map
        fid → raw label submission, and new_fields are
        (type, value, visibility[, label]) 4-tuples.
        """
        display_name = (form.get("display_name") or "").strip()
        card_name = (form.get("card_name") or "").strip()

        # Existing rows: field_{id}_value (+ _visibility, + _label +
        # _label_custom, + _remove). Collect all key kinds first — a row
        # with only non-value keys must still register.
        remove_ids: set[int] = set()
        value_rows: dict[int, tuple[str, str | None]] = {}
        for key in form.keys():
            m = _FIELD_KEY_RE.match(key)
            if not m:
                continue
            fid = int(m.group(1))
            if m.group(2) == "remove":
                remove_ids.add(fid)
            else:
                value_rows[fid] = (form.get(key) or "",
                                   form.get(f"field_{fid}_visibility"))
        updates = [(fid, v, vis) for fid, (v, vis) in value_rows.items()
                   if fid not in remove_ids]
        removals = list(remove_ids)

        labels: dict[int, str] = {}
        for key in form.keys():
            m = re.match(r"^field_(\d+)_label$", key)
            if m:
                fid = int(m.group(1))
                raw = form.get(key) or ""
                if raw == "__custom":
                    raw = form.get(f"field_{fid}_label_custom") or ""
                labels[fid] = raw

        # New rows: new_{type}_value[] + new_{type}_visibility[] (+
        # _label[]/_label_custom[]) as parallel getlists (the + Add rows
        # from the editor UI).
        new_fields: list[tuple] = []
        for t in whitelist_db.CARD_EDITOR_FIELD_TYPES:
            values = form.getlist(f"new_{t}_value")
            vis = form.getlist(f"new_{t}_visibility")
            raw_labels = form.getlist(f"new_{t}_label")
            custom_labels = form.getlist(f"new_{t}_label_custom")
            for i, value in enumerate(values):
                # UX pass 2 defaults ruling: 'granted' everywhere, except
                # title/company/website which default 'public'. (Was
                # blanket-private before the ruling.)
                visibility = (vis[i] if i < len(vis)
                              else _editor_default_visibility(t))
                label = ""
                if i < len(raw_labels):
                    label = raw_labels[i]
                    if label == "__custom" and i < len(custom_labels):
                        label = custom_labels[i]
                new_fields.append((t, value, visibility, label))

        return display_name, card_name, updates, labels, removals, new_fields

    @application.post("/owner/{token}/cards/{card_id}/edit", response_class=HTMLResponse)
    async def owner_card_edit_save(request: Request, token: str, card_id: int):
        form = await request.form()
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            (display_name, card_name, updates, labels, removals,
             new_fields) = _parse_editor_form(form)

            try:
                whitelist_db.save_card_editor(
                    conn, card_id,
                    display_name=display_name, card_name=card_name,
                    field_updates=updates, field_labels=labels,
                    field_removals=removals,
                    new_fields=new_fields,
                )
            except ValueError as exc:
                profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
                card = whitelist_db.get_card_by_id(conn, card_id)
                return _card_editor_html(conn, request, token, profile, card,
                                         error=str(exc), status_code=400)

            card = whitelist_db.get_card_by_id(conn, card_id)
            profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/fields/{field_id}/delete")
    async def owner_field_delete(request: Request, token: str, card_id: int,
                                 field_id: int):
        """UX pass (2026-09-22): the editor's per-field ✕ deletes the field
        from the card IMMEDIATELY — no checkbox accumulate-then-save step.

        Pass-2 BUG FIX: the ✕ posts the WHOLE editor form (formaction
        override), and this route used to ignore the body and redirect —
        every other edit keyed into the form was lost on the refresh. The
        full form is now parsed and applied TOGETHER with the removal, so
        deleting a field never drops entered data.

        Unlink semantics match save_card_editor removals: the card_fields
        row goes, the profile_fields row survives (cards are lenses, not
        containers). Ownership/IDOR is enforced by save_card_editor
        (foreign card or field → ValueError → 404).
        """
        form = await request.form()
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            (display_name, card_name, updates, labels, removals,
             new_fields) = _parse_editor_form(form)
            removals.append(field_id)  # the ✕'s own removal
            updates = [(fid, v, vis) for fid, v, vis in updates
                       if fid != field_id]
            labels.pop(field_id, None)
            try:
                whitelist_db.save_card_editor(
                    conn, card_id,
                    display_name=display_name, card_name=card_name,
                    field_updates=updates, field_labels=labels,
                    field_removals=removals,
                    new_fields=new_fields,
                )
            except ValueError as exc:
                # A foreign field id stays a 404 (IDOR, fail closed); any
                # other save error (duplicate value, …) re-renders the
                # editor with the message so keyed data survives.
                row = conn.execute(
                    "SELECT profile_id FROM profile_fields WHERE id = ?",
                    (field_id,),
                ).fetchone()
                if row is None or row["profile_id"] != profile_id:
                    return HTMLResponse("Not found", status_code=404)
                profile = whitelist_db.get_profile_by_id(conn, profile_id)
                card = whitelist_db.get_card_by_id(conn, card_id)
                return _card_editor_html(conn, request, token, profile, card,
                                         error=str(exc), status_code=400)
            # 303 back to the editor GET — the row is gone on landing.
            return RedirectResponse(
                url=f"/owner/{token}/cards/{card_id}/edit", status_code=303)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/delete")
    async def owner_delete_card(request: Request, token: str, card_id: int):
        """Delete ONE card (round-2 captain ask: destructive action with a
        confirm step). The confirm step lives in the editor UI (two-stage
        button); the route itself is the guarded write: ownership is
        enforced by _resolve_editor_card (foreign card → 404, ruling 2A),
        profile_fields survive (cards are lenses, not containers), and
        grant_cards links cascade away with the card."""
        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            whitelist_db.delete_card(conn, card_id, profile_id)

            # The card's photo files have no DB row anymore — unlink both
            # slots (default + high-school picture, UX pass 3).
            for photo_path in (f"{profile_id}_{card_id}.jpg",
                               f"{profile_id}_{card_id}_hs.jpg"):
                try:
                    (Path(__file__).parent / "uploads" / photo_path).unlink()
                except OSError:
                    pass

            # 303 (See Other): the browser must land on My Profile with a
            # GET — a 307 would replay the POST onto /profile (405).
            return RedirectResponse(url=f"/owner/{token}/profile", status_code=303)
        finally:
            conn.close()

    @application.post("/owner/{token}/cards/{card_id}/photo")
    async def owner_upload_photo(request: Request, token: str, card_id: int,
                                 photo_kind: str = Query(None)):
        from starlette.datastructures import UploadFile
        import os

        # Cheap early reject (audit 2026-09-25): a giant body otherwise
        # buffers fully into memory/temp before the 10 MB post-read check.
        content_length = request.headers.get("content-length")
        if (content_length and content_length.isdigit()
                and int(content_length) > 12 * 1024 * 1024):
            return HTMLResponse("File too large (max 10 MB)", status_code=413)

        form = await request.form()
        remove_photo = form.get("remove_photo")
        # UX pass 3: two picture slots on personal cards — the DEFAULT
        # picture (photo_kind absent/'default') and the HIGH-SCHOOL picture
        # ('hs'). Both default public on personal cards.
        kind = "hs" if photo_kind == "hs" else "default"

        conn = whitelist_db.wl_connect(path)
        try:
            profile_id, card, err = _resolve_editor_card(conn, request, token, card_id)
            if err is not None:
                return err

            upload_dir = Path(__file__).parent / "uploads"
            upload_dir.mkdir(exist_ok=True)
            photo_path = f"{profile_id}_{card_id}.jpg"
            hs_photo_path = f"{profile_id}_{card_id}_hs.jpg"
            slot_path = hs_photo_path if kind == "hs" else photo_path
            full_path = upload_dir / slot_path

            if remove_photo:
                # Remove photo
                stored = (card.get("hs_photo_path") if kind == "hs"
                          else card.get("photo_path"))
                if stored:
                    try:
                        os.unlink(full_path)
                    except OSError:
                        pass
                whitelist_db.update_card_photo(
                    conn, card_id, None, kind=kind)
            else:
                # Two upload paths: the client-side cropper posts its result
                # as a base64 data URL (photo_data); a raw file (photo) is
                # the no-JS fallback. photo_data wins when both arrive.
                photo_file = form.get("photo")
                photo_data = form.get("photo_data")
                content = None
                if isinstance(photo_data, str) and photo_data.startswith("data:image/"):
                    import base64
                    m = re.match(r"^data:image/(jpeg|png);base64,(.*)$", photo_data, re.DOTALL)
                    if not m:
                        return HTMLResponse("Invalid image data", status_code=400)
                    try:
                        content = base64.b64decode(m.group(2))
                    except Exception:
                        return HTMLResponse("Invalid image file", status_code=400)
                    if len(content) > 10 * 1024 * 1024:  # 10 MB
                        return HTMLResponse("File too large (max 10 MB)", status_code=413)
                elif isinstance(photo_file, UploadFile) and photo_file.filename:
                    content = await photo_file.read()
                    if len(content) > 10 * 1024 * 1024:  # 10 MB
                        return HTMLResponse("File too large (max 10 MB)", status_code=413)

                if content is not None:
                    try:
                        data = _encode_square_jpeg(content)
                    except ValueError:
                        return HTMLResponse("Invalid image file", status_code=400)
                    full_path.write_bytes(data)
                    whitelist_db.update_card_photo(
                        conn, card_id,
                        hs_photo_path if kind == "hs" else photo_path,
                        kind=kind)

            card = whitelist_db.get_card_by_id(conn, card_id)
            profile = whitelist_db.get_profile_by_id(conn, card["owner_profile_id"])
            if not profile:
                return HTMLResponse("Profile not found", status_code=404)
            # Back to the editor (the upload lives there now).
            return _card_editor_html(conn, request, token, profile, card)
        finally:
            conn.close()

    @application.get("/owner/{token}/profile/card/{card_id}")
    async def owner_card_preview(request: Request, token: str, card_id: int):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

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
