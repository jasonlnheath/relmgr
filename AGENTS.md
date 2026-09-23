# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Build & test

- Python deps live in `.venv/` (no system pytest): run tests with `.venv/bin/python -m pytest tests/ -q`.
- `app.py` auto-creates the FastAPI `app` at import time against `contacts.db` unless `RELMGR_DB_PATH` is set — tests must set `WHITELIST_SECRET` before importing `app` and pass an explicit tmp-path DB to `create_app()`.

## Architecture sharp edges

- Whitelist DB schema changes go through ONE ordered entry point: `whitelist_db.ensure_whitelist_schema` (order is load-bearing). Additive tables/columns get their own idempotent `ensure_*` function called there. SQLite cannot ALTER a CHECK constraint — extending an enum CHECK (grant_logs actions, notification kinds) means the row-preserving table-swap heal pattern (see `ensure_notification_kinds`, `ensure_grant_log_actions`).
- Access tiers: `effective_tier()` is the single tier oracle ('granted'/'anonymous'); public surfaces must filter fields through the `visible_fields` pattern in `cards_for_public_view` / `cards_for_share_bundle` (anonymous = public fields only; granted = public+granted+private). Revoked == blocked == blacklisted, one state.
- Silence rule (captain ruling 2026-09-20): contacts are NEVER notified about badge moves, quarantine, or their own status; notifications (`notifications` table) are owner-only. Blacklisted senders' requests go to `quarantined_requests` with an indistinguishable success page.
- Share bundles (`share_bundles`): one stable link `/s/{id}` per chosen card set; fields render live from card IDs; links expire 7 days after creation (`expires_at`).
- Style ruling (captain 2026-09-22, pass 2 extends it): grey EVERYWHERE — no green, red, or blue (and no amber) action buttons; `.wl-btn-approve`/`.wl-btn-deny`/`.wl-btn-revoke`/`.wl-btn-punt` are all aliases of the default slate gray (see `templates/base.html`); status color lives only in badges/text. Share icons use an ink `currentColor` SVG, never the red-rendering 📤 emoji. Badge toggle confirmations say the list names WhiteList/GreyList/BlackList, never the internal 'blocked'.
- Card editor UX: removing a field is an immediate per-row ✕ POST (`/owner/{token}/cards/{id}/fields/{fid}/delete`). The ✕ posts the WHOLE editor form (formaction override), and the delete route MUST apply the full parsed body (`_parse_editor_form`, shared with the save route) together with the removal — ignoring the body was a real data-loss bug (pass 2). Card-editor form parsing has ONE entry point; both routes must use it. Photos are CIRCLE-cropped client-side (disc composited on the `#1A1A1C` backdrop, stored as square JPEG; every display surface clips with `rounded-full`).
- Contact-list badge cycle White→Grey→Black is `whitelist_db.set_badge_state` — grey stamps `expires_at = quarter_end_iso()`, an INTERNAL marker that feeds the quarterly prompt, never an expiry (see next); treat it as the single state-cycle entry point.
- Semantics ruling (captain 2026-09-22, pass 2): greylist/blacklist contacts NEVER expire; no 'Expires' row in any UI; the quarterly review confirms/updates contact info and reviews grey/black contacts — never deletes. `sync_quarterly_notifications` carries the wording.
- Field visibility defaults (pass 2): everything defaults 'granted' EXCEPT title/company/website (public) and bio (public). One decision table: `_editor_default_visibility` in app.py + `default_visibility` macro in card_editor.html; the legacy title/company seed and `/fields/new` follow it.
- Phone labels (pass 2): `profile_fields.label` ('mobile'/'home'/'work'/custom text) via `ensure_profile_field_labels`; editor selects + custom input (`phone_label_select` macro); display via `label_display` (exposed as a Jinja global in `_make_jinja`).
- Direct-DB test writes need the columns/tables the app boot creates: run `TestClient(create_app(db))` BEFORE writing `quarter_status` etc. (boot runs `ensure_whitelist_schema`), and `store.init_db(db)` before touching `contacts`. `search_new_connections` degrades to [] when the contacts table is absent.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
