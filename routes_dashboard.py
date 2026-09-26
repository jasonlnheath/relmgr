"""Owner dashboard routes: the contact list (/owner/{token}), badge cycle,
junk list, approve-with-cards, new-connection search/create, access
management, and the per-contact card view.

Split out of app.py (2026-09-26 refactor); behavior is unchanged.
"""

from datetime import datetime, timedelta, timezone

from fastapi import Request, Query
from fastapi.responses import HTMLResponse, RedirectResponse

import whitelist_db

from web_support import (
    WebContext,
    _decision_outcome,
    _get_secret,
    _rail_letter,
    _resolve_owner,
    _verify_grant_ownership,
    days_since,
    days_until,
    is_verified_stale,
)


def register_dashboard_routes(application, ctx: WebContext) -> None:
    path = ctx.db_path
    jinja = ctx.jinja

    @application.post("/owner/{token}/badge")
    async def owner_badge_state(request: Request, token: str):
        """Click-to-change contact-list badges (WhiteList/GreyList/BlackList).

        INSTANT and ALWAYS SILENT: the badge flip is the access governor,
        and the affected contact is NEVER notified — no notification row,
        no email, ever. The notification center only tells the OWNER
        about incoming events, never contacts about rulings.
        """
        form = await request.form()
        grant_id = form.get("grant_id", "")
        state = form.get("state", "")
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)
            try:
                whitelist_db.set_badge_state(conn, grant_id, state)
            except ValueError:
                return HTMLResponse("Invalid badge state", status_code=400)
        finally:
            conn.close()
        return RedirectResponse(url=f"/owner/{token}", status_code=303)

    @application.get("/owner/{token}", response_class=HTMLResponse)
    async def owner_dashboard(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]

            # Get query params — junk input must degrade to page 0, not 500.
            q = request.query_params.get("q")
            try:
                page = max(0, int(request.query_params.get("page", 0)))
            except ValueError:
                page = 0
            # UX pass 3 (2026-09-23): reduced rows (~100 per page).
            per_page = 100

            # Owner dashboard: per-owner isolation (ruling 2A). Every auth
            # path — session cookie, integer-payload token, and the legacy
            # fallback link — sees exactly this owner's world, nothing else.
            all_profiles = conn.execute("SELECT * FROM profiles WHERE owner_id = ? ORDER BY id", (profile_id,)).fetchall()
            all_profile_ids = [dict(p)["id"] for p in all_profiles]
            if not all_profile_ids:
                all_profile_ids = [profile_id]

            # UX pass (2026-09-22): fast alphabetical filter rail — ?letter=X
            # keeps only names STARTING with X (prefix filter, unlike the
            # substring search q). Applied to the merged row list below, so
            # it works in both the contacts and pure-whitelist modes.
            letter = (request.query_params.get("letter") or "")[:1].upper()
            available_letters: list[str] = []

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
                rows = all_rows
            else:
                # Pure whitelist mode — owner-scoped grants (ruling 2A).
                all_grants = conn.execute(
                    "SELECT * FROM access_grants WHERE owner_id = ? AND profile_id IN ({}) ORDER BY status, created_at".format(",".join("?" for _ in all_profile_ids)),
                    [profile_id] + all_profile_ids,
                ).fetchall()
                rows = []
                profile_map = {p["id"]: dict(p) for p in all_profiles}
                for g in all_grants:
                    gd = dict(g)
                    if gd["status"] == "denied":
                        continue
                    prof = profile_map.get(gd["profile_id"])
                    # UX pass 3: card tabs work in pure-whitelist mode too —
                    # resolve each grant's card refs exactly like the data
                    # layer does in contacts mode.
                    gcard_rows = conn.execute(
                        "SELECT c.id, c.name FROM grant_cards gc JOIN cards c ON gc.card_id = c.id "
                        "WHERE gc.grant_id = ?",
                        (gd["id"],),
                    ).fetchall()
                    gcard_refs = [{"id": r["id"], "name": r["name"]}
                                  for r in gcard_rows]
                    rows.append({
                        "contact_id": None,
                        "name": gd.get("requester_name") or gd.get("requester_email", "Unknown"),
                        "email": gd.get("requester_email", ""),
                        "phone": "",
                        "org": "",
                        "granted": gd["status"] == "granted",
                        "live_grant": gd,
                        "cards": [r["name"] for r in gcard_rows],
                        "card_refs": gcard_refs,
                        "perm": "permanent" if gd.get("expires_at") is None else ("temp" if gd.get("expires_at") else None),
                        "logo_state": ("fresh" if whitelist_db.is_current_quarter(prof.get("verified_at")) else "stale") if prof else None,
                        "refreshed_at": None,
                        "is_pending": gd["status"] == "pending",
                    })
                total_rows = len(rows)

            # Count denied grants for this owner
            denied_count = conn.execute(
                "SELECT COUNT(*) FROM access_grants WHERE owner_id = ? AND status = 'denied'",
                (profile_id,),
            ).fetchone()[0]

            # UX pass 3 (2026-09-23): the in-app notification PAGE is retired
            # (requests live in the amber box below; quarterly = the email +
            # the grey rows in this list). The quarterly prompt ROW is still
            # raised here — the append-only event record survives; only the
            # page, its routes, and the header button are gone.
            whitelist_db.sync_quarterly_notifications(conn, profile_id)

            # Unified row list for single-surface contact list (round-2)
            all_rows = rows
            total_contacts = total_rows

            # UX pass ruling (2026-09-22): ONE ROW PER CARD — a contact with
            # two cards appears twice in the list, once per card, each row
            # deep-linking the detail view with that card selected. Contacts
            # and pending grants without cards render one row as before.
            # UX pass 3 (2026-09-23): PENDING rows leave the main list —
            # they land in the amber request box at the top (below the
            # search bar), per the captain's ruling.
            expanded_rows: list[dict] = []
            pending_rows: list[dict] = []
            for r in all_rows:
                if r.get("is_pending"):
                    pending_rows.append(r)
                    continue
                refs = r.get("card_refs") or []
                if refs:
                    for ref in refs:
                        card_row = dict(r)
                        card_row["row_card"] = ref
                        expanded_rows.append(card_row)
                else:
                    expanded_rows.append(r)
            all_rows = expanded_rows

            # UX pass 3 (2026-09-23): PICTURE-BASED MULTI-SELECT FILTER TABS
            # below the search bar. Card tabs carry the card's own picture
            # (Personal first, then Work, then the rest alphabetical); list
            # badge tabs carry the white/grey/black state. ?f=<id>,<id>,...
            # combines selections: card group OR, state group OR, the two
            # groups AND together (e.g. personal + work1 + grey + white).
            owner_cards_all = whitelist_db.list_cards(conn, profile_id)
            filter_tabs: list[dict] = []
            for c in owner_cards_all:
                filter_tabs.append({
                    "kind": "card",
                    "key": str(c["id"]),
                    "card": c,
                })
            for state_key, label in (("whitelist", "WhiteList"),
                                     ("greylist", "GreyList"),
                                     ("blacklist", "BlackList")):
                filter_tabs.append({
                    "kind": "state",
                    "key": state_key,
                    "label": label,
                })
            raw_f = (request.query_params.get("f") or "")
            selected_f = {tok for tok in raw_f.split(",") if tok}
            valid_keys = {t["key"] for t in filter_tabs}
            selected_f &= valid_keys
            sel_cards = {int(k) for k in selected_f if k.isdigit()}
            sel_states = selected_f - {str(k) for k in sel_cards}

            def _row_state(r: dict) -> str:
                gd = r.get("live_grant")
                if not gd:
                    return "blacklist"  # plain address-book contact: no access
                if gd.get("status") != "granted":
                    return "blacklist"
                return "whitelist" if gd.get("expires_at") is None else "greylist"

            if sel_cards or sel_states:
                def _matches(r: dict) -> bool:
                    card_ok = (not sel_cards
                               or (r.get("row_card") is not None
                                   and r["row_card"]["id"] in sel_cards))
                    state_ok = (not sel_states
                                or _row_state(r) in sel_states)
                    return card_ok and state_ok
                all_rows = [r for r in all_rows if _matches(r)]

            # UX pass 3 sort ruling: card type alphabetical, then the state
            # white/grey/black, then name.
            _STATE_RANK = {"whitelist": 0, "greylist": 1, "blacklist": 2}
            all_rows.sort(key=lambda r: (
                (r.get("row_card") or {}).get("name", "") or "",
                _STATE_RANK[_row_state(r)],
                (r.get("name") or "").lower(),
            ))

            # UX pass (2026-09-22): the A–Z rail + prefix filter run on the
            # MERGED rows, whatever mode produced them; pagination slices
            # AFTER the filter so a letter's rows never fall off the page.
            # Keys are ASCII-folded (F2): É lands under E, others under '#'.
            available_letters = sorted({_rail_letter(r.get("name") or "")
                                        for r in all_rows})
            if letter:
                all_rows = [r for r in all_rows
                            if _rail_letter(r.get("name") or "") == letter]
            total_rows = len(all_rows)
            start = page * per_page
            all_rows = all_rows[start:start + per_page]

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
                pending_rows=pending_rows,
                my_card=my_card,
                all_cards=all_cards,
                filter_tabs=filter_tabs,
                selected_f=selected_f,
                token=token,
                q=q,
                letter=letter,
                available_letters=available_letters,
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
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            # Verify grant ownership
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            outcome = _decision_outcome(conn, jinja, request, grant_id,
                                       decision, expiry_choice)
            # If approved, set the card assignments (junk ids degrade to 400,
            # never 500 — spec B3/q38; foreign-card ids are rejected inside
            # set_grant_cards, ruling 2A).
            if decision == "approve" and outcome.status_code == 200:
                try:
                    card_ids = [int(c) for c in card_ids_raw]
                    whitelist_db.set_grant_cards(conn, grant_id, card_ids)
                except ValueError:
                    return HTMLResponse("Invalid card selection", status_code=400)
            return outcome
        finally:
            conn.close()

    # ------------------------------------------------------------------ Junk folder (P5-T3)
    @application.get("/owner/{token}/junk", response_class=HTMLResponse)
    async def owner_junk(request: Request, token: str):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            denied = conn.execute(
                "SELECT * FROM access_grants WHERE owner_id = ? AND status = 'denied' ORDER BY created_at DESC",
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

    # ------------------------------------------------------------------
    # Notification PAGE — ELIMINATED (UX pass 3, 2026-09-23 captain ruling
    # investigation): connection requests and forwards now land at the TOP
    # of the whitelist in the amber request box; the quarterly review is
    # the quarterly email + the grey contacts visible in the list itself;
    # expired-link pings were tied to the retired share-chooser flow. The
    # page carried nothing unique. The notifications TABLE and its data
    # layer stay (append-only event record + the email push's source of
    # truth) — only the page, its routes, and the header button are gone.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------ New connection (+ button, UX pass 2)
    # The round + button RIGHT of the search bar: search the database for
    # 'new connections'; on no hits, offer to create a standard vCard.
    @application.get("/owner/{token}/new-connection", response_class=HTMLResponse)
    async def owner_new_connection(request: Request, token: str,
                                   q: str = Query(None)):
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            matches = whitelist_db.search_new_connections(conn, profile_id, q or "")
        finally:
            conn.close()
        return HTMLResponse(jinja.get_template("new_connection.html").render(
            request=request, token=token, q=q or "", matches=matches))

    @application.post("/owner/{token}/new-connection")
    async def owner_new_connection_create(request: Request, token: str):
        form = await request.form()
        display_name = (form.get("display_name") or "").strip()
        phone = (form.get("phone") or "").strip()
        email = (form.get("email") or "").strip()

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            if not display_name:
                matches = whitelist_db.search_new_connections(conn, profile_id, "")
                return HTMLResponse(jinja.get_template("new_connection.html").render(
                    request=request, token=token, q="", matches=matches,
                    error="Name is required."), status_code=400)
            new_profile = whitelist_db.create_contact_vcard(
                conn, profile_id, display_name, phone=phone, email=email)
            # UX pass 3 (bug fix + create-flow ruling): land DIRECTLY in the
            # new vCard's editor — ALL field sections ready to populate.
            # BUG FIX (pass 9): seed_default_cards maps email→Work, phone→Personal;
            # always landing on Personal hid the email field. Prefer Work when
            # email was provided (it carries the email fields), else Personal.
            cards = whitelist_db.list_cards(conn, new_profile["id"])
            if email:
                target = next((c for c in cards if c["name"].lower() == "work"),
                              cards[0] if cards else None)
            else:
                target = next((c for c in cards if c["name"].lower() == "personal"),
                              cards[0] if cards else None)
        finally:
            conn.close()
        if target is None:
            # 303 See Other: land back on the contact list with a GET.
            return RedirectResponse(url=f"/owner/{token}", status_code=303)
        return RedirectResponse(
            url=f"/owner/{token}/cards/{target['id']}/edit", status_code=303)

    # ------------------------------------------------------------------ Manage access (P5-T3)
    @application.post("/owner/{token}/access", response_class=HTMLResponse)
    async def owner_manage_access(request: Request, token: str):
        form = await request.form()
        grant_id = form.get("grant_id", "")
        card_ids_raw = form.getlist("card_ids")
        access = form.get("access", "quarter")

        if not grant_id:
            return HTMLResponse("No grant selected", status_code=400)

        expiry_choice = "lifetime" if access == "lifetime" else "quarter"

        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            # Verify grant ownership
            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

            # Update expiry if access changed
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

            # Update cards (junk ids degrade to 400, never 500 — spec B3/q38;
            # foreign-card ids are rejected inside set_grant_cards, ruling 2A).
            try:
                card_ids = [int(c) for c in card_ids_raw] if card_ids_raw else []
                whitelist_db.set_grant_cards(conn, grant_id, card_ids)
            except ValueError:
                return HTMLResponse("Invalid card selection", status_code=400)

            return HTMLResponse("Access updated")
        finally:
            conn.close()

    @application.get("/owner/{token}/contact/{grant_id}", response_class=HTMLResponse)
    async def owner_contact_card(request: Request, token: str, grant_id: str):
        """Contact card — single-surface view of one contact from the dashboard.
        Ruling: revoke lives on the contact card, not the list details expander.
        """
        conn = whitelist_db.wl_connect(path)
        try:
            result = _resolve_owner(conn, request, token, _get_secret())
            if result[0] is None and result[2] is None:
                return HTMLResponse("Invalid or expired link", status_code=403)
            if result[2]:
                return RedirectResponse(url=f"/owner/{result[2]}")
            profile_id = result[0]
            is_explicit = result[3]

            grant = whitelist_db.get_grant(conn, grant_id)
            if not grant:
                return HTMLResponse("Grant not found", status_code=404)
            if not _verify_grant_ownership(conn, grant, profile_id, is_explicit):
                return HTMLResponse("Not found", status_code=404)

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
            # UX pass (2026-09-22): the detail view shows ONE card at a
            # time (captain's pass), with a chip switcher when the contact
            # has several. ?card=<id> selects; default is the first card.
            try:
                selected_card_id = int(request.query_params.get("card", ""))
            except ValueError:
                selected_card_id = None
            selected_card = next(
                (c for c in cards if c["id"] == selected_card_id),
                cards[0] if cards else None)
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
            selected_card=selected_card,
            tier=tier, stale=stale, days_since=days_since, token=token,
            grant_id=grant_id, is_grey=whitelist_db.is_grey(grant)))
