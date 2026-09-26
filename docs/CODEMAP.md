# RelMgr / WhiteList — Codebase Map

One-read orientation for workers and the captain. Anchors are SYMBOL
names + module (line numbers drift; grep the symbol if it moved).
Companion doc: `AGENTS.md` (rulings and sharp edges). This file is the
map; that file is the law.

## 1. Architecture in one paragraph

A single FastAPI service serves server-rendered HTML (Jinja2,
`templates/`) over one SQLite file (`contacts.db`; path = `create_app()`
arg → `RELMGR_DB_PATH` env → file beside `app.py`). **`app.py` is the
composition root** (~220 lines): it resolves the DB path, builds the
Jinja env, runs the full idempotent schema-heal chain once
(`whitelist_db.ensure_whitelist_schema`), installs the security
middleware (body cap, per-IP rate limit on anonymous POSTs, security
headers, cache discipline), mounts `/static`, registers the
retired-link handler, then delegates every route group to a
`routes_*.py` module via `register_*_routes(application, ctx)` (the
2026-09-26 refactor split the old 2800-line single file; behavior and
route set are unchanged). Shared helpers live in `web_support.py`, and
`WebContext` (db_path, jinja, push_connection_email) is the bundle each
route group closes over. Each route opens its own `sqlite3` connection
(`wl_connect`: WAL + FK + Row factory), calls functions in
`whitelist_db.py` (the entire data layer, pure sqlite3, no ORM), and
returns `HTMLResponse(jinja.get_template(...).render(...))`. Auth is
capability-style: HMAC-signed tokens (`wl_tokens.py`) embedded in
`/owner/{token}` URLs (scope `owner_dashboard`, payload = profile id)
plus a signed `wl_session` cookie (7 days) set by `/signin`/`/signup`;
`web_support._resolve_owner` is the single oracle that accepts either.
The imported address book (`contacts` table, owned by `store.py`/
`cli.py`/`scripts/fetch_*.py`) feeds contact-list rows and
new-connection search; secrets and SMTP config come from env-or-`.env`
(`wl_env.py`), outbound mail goes through `mailer.py`. Photos are files
in `uploads/` served through guarded `/photos/…` routes. `app =
create_app()` at module level makes `uvicorn app:app` work.

## 2. Module map

Root, by role:

| Module | What it is |
|---|---|
| `app.py` (~220 ln) | Composition root: middleware, static mount, retired-link handler, boot heal, route-group registration, module-level `app`. Re-exports the helper names tests import from `app`. |
| `web_support.py` (~490 ln) | Shared plumbing: `_parse_dt`/`days_since`/`days_until`, `_rail_letter`, `is_verified_stale`, `_get_secret`, `_encode_square_jpeg`, `_static_version`, `_make_jinja` (globals `phone_fmt`/`label_display`/`asset_v`), b64 + session-cookie make/consume, `LegacyOwnerLinkRetired`, **`_resolve_owner`** (token-or-session oracle), `_verify_grant_ownership`, `_decision_outcome`, `_owner_email_for`, `_send_connection_request_email`, `_qr_png`, `_vcf_escape`/`_build_vcard`, `WebContext` dataclass. |
| `routes_auth.py` | `/signin` `/signup` `/signout` `/forgot-password` `/reset-password/{token}` (+ shared `_set_session_redirect` cookie helper; lazy `scripts.notify` import — tests patch it). |
| `routes_public.py` | `/` landing, `/owner/`, `/p/{handle}` (auth-only owner detection via `?ot=`/session), request-form, POST request (quarantine + dedupe-email-push), POST forward. |
| `routes_share.py` | `/s/{bundle_id}` (ALWAYS public tier, bio always, expired→owner ping once) + `/s/{bundle_id}/card.vcf`. |
| `routes_review.py` | `/a/{token}` emailed grant-review page + decision, `/verify/{token}`. |
| `routes_dashboard.py` | `/owner/{token}` contact list (q/page/letter/f params, per-card rows, amber pending box, filter tabs, alpha rail data), POST badge, approve-with-cards, junk, new-connection GET/POST, access, `/contact/{grant_id}` card view. |
| `routes_profile.py` | My Profile: GET `/profile`, POST `/bio`, `/bio-visibility`, `/cards/new`, `/cards/{cid}/fields`, `/fields/new`. **`_my_profile_html` = ONE render site for all of them.** |
| `routes_editor.py` | Card editor: GET/POST `/cards/{cid}/edit`, per-field ✕ delete, card delete, photo upload, `/profile/card/{cid}` preview. Seams: **`_card_editor_html`** (one render site), **`_parse_editor_form`** (one parser, shared by save + ✕ delete), `_resolve_editor_card` (auth + curated-stub exception), `_editor_default_visibility` + `_PUBLIC_DEFAULT_TYPES`/`_PRIVATE_DEFAULT_TYPES`. |
| `routes_media.py` | `/photos/{pid}/{cid}[/hs]` via **`_photo_allowed`** (audit predicate) + `/qr/share/{bid}`, `/qr/{handle}`. |
| `routes_decisions.py` | POST `/owner/{token}/decision`, `/bulk`, `/revoke`, quarter make_permanent/revoke/punt (all ownership-enforced). |
| `whitelist_db.py` (~4400 ln) | Entire data layer: schema, migrations, queries. Map below. |
| `wl_tokens.py` | HMAC-SHA256 make/consume tokens (`purpose\|payload\|expiry`). |
| `wl_env.py` | `get_secret(key)`: os.environ first, then `.env` beside app.py. |
| `mailer.py` | SMTP config + `send_email` + `app_base_url()` (APP_BASE_URL > BASE_URL > LAN default). |
| `notify.py` | Quarterly grey-contact digest builder + `--review` CLI. |
| `store.py` | Imported-address-book schema (`contacts`, `contact_sources`, `dedup_log`) + CRUD. |
| `cli.py` | `sync/list/dedup/export/onboard` over store+fetcher (the import pipeline). |
| `fetcher.py`, `normalizer.py`, `deduplicator.py` | Contact import: source fetch → normalize → dedup. |
| `config.py` | Import-pipeline config (sources, dedup thresholds). |
| `scripts/` | `fetch_{gmail,facebook,outlook_csv,vcf}.py`, `merge_*`, `onboard`, `seed_demo`, `notify` (CLI mailer, sys.exits on missing creds), `refresh_token`, `render_snapshot.py` (template-refactor verification harness). |
| `templates/`, `static/`, `uploads/` (runtime), `data/` | See templates below; static = badge/scroll PNGs + vendored tailwind. |
| `Dockerfile`, `docker-compose.yml`, `.env.example`, `SPEC.md`, `README.md` | Deploy + specs. README describes the import pipeline; SPEC the whitelist product. |

### whitelist_db.py section map (symbol anchors)

| Symbols | Section |
|---|---|
| `_PWHASH_ROUNDS`, `hash_password`/`verify_password`, `_dummy_password_hash`/`burn_dummy_password_work`, `_table_exists`, `quarter_end_iso`, `is_current_quarter` | Constants + passwords (pbkdf2 260k, timing parity). |
| **`_LIVE_GRANT_EXPIRY_SQL`**, **`_ADMITTED_EXPIRY_SQL`** | The two expiry oracles: live = display/logo freshness only; admitted = the admission predicate shared by `effective_tier` + `create_grant` dedupe (granted + any real-timestamp expiry admits forever; grey/black never expire; legacy `'14d'` strings never leak via GLOB guard). |
| `CARD_EDITOR_FIELD_TYPES` (THE enum, 36 types), `CARD_EDITOR_FIELD_LABELS`, `ADDRESS_BLOCK_TYPES`/`ADDRESS_BLOCK_SCOPES`/`address_blocks`, `EVENT_LABEL_CHOICES`, **`_SCOPE_TEMPLATES`** (vcard/personal/work section layouts; scoping is NAME-based via `card_kind`), `picker_sections` (falls back to flat `CARD_EDITOR_SECTIONS`), `CARD_EDITOR_MULTI_TYPES`, **`_CARD_ORDER_SQL`** (Personal→Work→alpha), `card_kind`, `format_phone_display` | Editor vocabulary. |
| `wl_connect` (WAL/FK/Row), `wl_init` | Boot: fresh CREATE of every base table. |
| `ensure_vcard_fields_schema` (v2) → `_v3` → `_pass3` → `_pass5`, `_seed_title_company_fields` | profile_fields CHECK-swap heals (detection = distinctive literal in stored DDL; row-preserving, id/label-preserving). |
| `create_owner_profile`, `resolve_owner_by_credentials` (dummy burn), reset tokens (`create/peek/consume_password_reset_token`, SHA-256 at rest, 30 min), `set_profile_password`, `get_profile_by_email` | Owner profiles. |
| `seed_profile` (canonical-JSON upsert) | Seeding. |
| **`effective_tier`** ('granted'/'anonymous' oracle), `_fetch_profile` (fields attached, ORDER BY is contract), `get_profile`/`get_profile_by_id`/`get_grant`, `find_admitting_grant_id` (new-vs-dedupe), **`create_grant`** (dedupe admits forever), `update_grant_status`, `resolve_handle` (+`add_alias`), **`apply_decision`** (pending-only guard, atomic approve+contacts merge) | Grants. |
| `_GRANT_LOGS_CHECK`/`_grant_logs_ddl`/`ensure_grant_logs`/`ensure_grant_log_actions`/`_log_action` | Audit log (append-only; same-commit convention). |
| contexts registry + built-ins, `set_grant_context`, `ensure_access_grants_context`, `record_scan`/`get_scan_stats`, `get_grant_logs` | Contexts (UI removed 2026-09-12; data layer stays) + scans. |
| `ensure_access_grants_v2` ('revoked' CHECK swap) / `_v3` (quarter cols), `revoke_grant` | access_grants migrations. |
| **`set_badge_state`** (White→Grey→Black entry point; grey stamps quarter-end marker = internal, never an expiry; always silent), **`is_grey`** (granted + any real-timestamp expires_at, future marker INCLUDED), `mark_grey_pending_review`, grey digests (`get_grey_contacts` lapsed-only), `make_grant_permanent`, `punt_grant`, `bulk_apply`, `find_contact_by_email` | Rhythm/badges. |
| `merge_requester_into_contacts` | Identity merge (approve → contacts row; provenance append-merge; owner-scoped). |
| `ensure_cards_schema`, `create_card`, `delete_card` (lens semantics), **`get_card_by_id`** (fields attached), `list_cards` (`_CARD_ORDER_SQL`), **`cards_for_public_view`** (anonymous = default card + public fields only; granted = all cards, hide zero-visible; `visible_fields` key), `set_grant_cards` (ownership-checked), `get_active_cards_for_grant` | Cards. |
| `_BUNDLE_TTL_DAYS`/`bundle_expiry_iso`/`bundle_is_expired`, `filter_owned_cards`, **`create_share_bundle`** (data-layer mint only; owner routes retired), `is_blacklisted` (revoked == blacklisted), `quarantine_request` (per-email/day dedupe), **`cards_for_share_bundle`** (bundle order, Personal leads) | Bundles/quarantine. |
| bio cols, `ensure_profile_field_labels`, **`ensure_pass2_visibility_heal`** (ONE-TIME marker-gated backfill), phone labels (`PHONE_LABEL_CHOICES`/`normalize_field_label`/`label_display`), photo cols, forwardings table | Additive heals. |
| `forward_card`, notifications (`_NOTIFICATION_KINDS`, `ensure_notification_kinds` table-swap heal, CRUD + dedupe_key, **`sync_quarterly_notifications`** — runs on dashboard render) | Forwarding + notifications. |
| `ensure_owner_auth_schema`, `ensure_access_grants_owner`, `ensure_contacts_owner`, **`ensure_whitelist_schema`** — THE single ordered entry point (order load-bearing; ends with `seed_default_cards`) | Boot order. |
| **`seed_default_cards`** (Personal+Work ALWAYS for every profile; Personal first = lower id = default public picture; phone→Personal, email→Work; legacy names heal-only), `update_bio`/`update_bio_visibility`/`get_bio_visibility` | Seeding + bio. |
| `set_card_fields`, `add_profile_field`, `update_card_photo`, **`save_card_editor`** (ONE commit; form-keyed rows only — out-of-scope stored fields SURVIVE; IDOR-checked; empty value = unlink) | Editor writes. |
| `_grant_is_live`, **`list_contact_list_rows`** (grants + contacts merged, per-card refs, logo freshness, search haystack) | Contact list. |
| `search_new_connections` (degrades to [] without the table), `_slugify_handle`, **`create_contact_vcard`** (curated stub: owner_id = creator, password_hash NULL) | New connection. |

## 3. "Where do I change X" — the 20 most likely edits

1. **Add a field type**: `CARD_EDITOR_FIELD_TYPES` + `CARD_EDITOR_FIELD_LABELS` → new `ensure_vcard_fields_<pass>_schema` CHECK-swap heal + call in `ensure_whitelist_schema` → add to the relevant `_SCOPE_TEMPLATES` scope(s) (and `CARD_EDITOR_SECTIONS` fallback) → placeholders map in `card_editor.html` → label rendering in `templates/_fields.html` `field_label` (the ONE copy) → vCard export mapping in `web_support._build_vcard` → decide default visibility in BOTH tables (routes_editor `_PUBLIC_DEFAULT_TYPES` + `card_editor.html` sets) → tests.
2. **Change which fields Personal/Work/vCard cards show**: `_SCOPE_TEMPLATES` only — scoping is name-based (`card_kind`), never add scoped enum values.
3. **Change address-block rendering**: `ADDRESS_BLOCK_TYPES`/`ADDRESS_BLOCK_SCOPES` + the `Addresses` branch in `card_editor.html`; block branch fires ONLY on heading `'Addresses'` from scoped sections.
4. **Change card template look (public view)**: `_fields.html` `field_row`/`field_label` (shared by profile + contact_card; share fragment has its own inline row). Verify with `scripts/render_snapshot.py`.
5. **Editor save/delete semantics**: `_parse_editor_form` (routes_editor) + `save_card_editor` (whitelist_db). Any new write path MUST go through `save_card_editor`; the ✕ delete route must keep applying the full parsed body.
6. **Add an owner route**: nested def in the matching `routes_*.py` module's register function after its siblings; resolve with `web_support._resolve_owner`, verify grants with `_verify_grant_ownership`, 403/404 conventions as in neighbors; add to route table below + tests.
7. **Contact-list rows/filters/rail**: route `owner_dashboard` (routes_dashboard) for data/params; `contact_list.html` for markup; `web_support._rail_letter` for letters; `list_contact_list_rows` for the row shape.
8. **Badge cycle**: `set_badge_state` + badge form in `contact_list.html`; confirmations say WhiteList/GreyList/BlackList; contacts are NEVER notified.
9. **Quarterly review**: grey trio = `is_grey`, `make_grant_permanent`/`punt_grant`, quarter routes (routes_decisions), buttons in `contact_card.html`, digest in `notify.py` + `sync_quarterly_notifications`.
10. **Sharing/QR**: QR + native share live in `my_profile.html` + `_my_profile_html` (routes_profile); bundle serving `/s/{id}` (routes_share) + `cards_for_share_bundle`; bundle minting is data-layer only.
11. **Connect-request flow / quarantine**: POST `/p/{handle}/request` (routes_public), `create_grant`, `quarantine_request`, `is_blacklisted`; success page must stay indistinguishable.
12. **Visibility defaults**: routes_editor `_PUBLIC_DEFAULT_TYPES`/`_PRIVATE_DEFAULT_TYPES` + `card_editor.html` sets — one decision, two mirrors. Never re-heal existing data (pass2 heal is one-time by design).
13. **Tier/field exposure**: `effective_tier` + `visible_fields` filtering in `cards_for_public_view` / `cards_for_share_bundle`; public surfaces must go through those, never raw `fields`.
14. **Photos**: upload route (routes_editor) + `web_support._encode_square_jpeg` + cropper JS in `card_editor.html`; serving predicate `_photo_allowed` (routes_media); files `uploads/{pid}_{cid}[_hs].jpg`.
15. **Add a notification kind**: `_NOTIFICATION_KINDS` — CHECK lives in two DDLs (`wl_init` + `ensure_notification_kinds` table-swap heal), writer `create_notification`; there is NO notification page — requests surface in the amber box.
16. **Email sending**: `mailer.send_email` / `app_base_url`; push call sites `_send_connection_request_email` (web_support; injected via `WebContext.push_connection_email` so tests can patch `app._send_connection_request_email` pre-create_app), reset (routes_auth); never block responses — BackgroundTask.
17. **Auth/session**: `_make_session_cookie`/`_consume_session_cookie` (web_support), `_resolve_owner`, `wl_tokens.make_token/consume_token`; scopes: `owner_dashboard`, `grant_review`, `verify`.
18. **Schema change**: additive column → own idempotent `ensure_*` + call in `ensure_whitelist_schema` (order matters); new enum value → row-preserving table-swap heal; copy EVERY column (labels, ids) so `card_fields` links and phone labels survive.
19. **Phone display/labels**: `format_phone_display` + `phone_fmt` global; labels `PHONE_LABEL_CHOICES`/`normalize_field_label`/`label_display`; editor macro `phone_label_select`.
20. **Rate limiting/security headers**: `_rate_limited` + `_security_middleware` (app.py — the ONE middleware); off-switch `WHITELIST_RATELIMIT_DISABLED`.

## 4. Route table

Every URL `app` serves (method path — module — one-liner).

```
GET  /                                          routes_public     landing: session→dashboard else /signin
GET  /signin                                    routes_auth       sign-in page
POST /signin                                    routes_auth       credentials → wl_session cookie → 303 /
GET  /signup                                    routes_auth       sign-up page
POST /signup                                    routes_auth       create owner → session → 303 /
POST /signout                                   routes_auth       clear session → 303 /signin
GET  /forgot-password                           routes_auth       request-reset page
POST /forgot-password                           routes_auth       mint+mail reset in background; same response always
GET  /reset-password/{token}                    routes_auth       set-new-password page (peek token)
POST /reset-password/{token}                    routes_auth       consume token, set password → /signin?reset=1
GET  /owner/                                    routes_public     session → /owner/{fresh token}
GET  /p/{handle}                                routes_public     public profile (tier via ?e=; owner via ?ot=/session)
GET  /p/{handle}/request-form                   routes_public     Connect request form
POST /p/{handle}/request                        routes_public     create grant (or silent quarantine if blacklisted)
POST /p/{handle}/forward                        routes_public     granted contact forwards card → pending grant
GET  /s/{bundle_id}                             routes_share      share link: ALWAYS public-tier page; expired page
GET  /s/{bundle_id}/card.vcf                    routes_share      public-fields-only vCard download
GET  /a/{token}                                 routes_review     emailed grant-review page (grant_review token)
POST /a/{token}/decision                        routes_review     approve/deny from email link
GET  /verify/{token}                            routes_review     verify token → stamp verified_at
GET  /photos/{owner_pid}/{card_id}              routes_media      guarded photo JPEG (default slot)
GET  /photos/{owner_pid}/{card_id}/hs           routes_media      guarded photo JPEG (high-school slot)
GET  /qr/share/{bundle_id}                      routes_media      QR PNG for /s/{bundle_id}
GET  /qr/{handle}                               routes_media      QR PNG for /p/{handle}
     /static/*                                  app.py            mounted static dir
GET  /owner/{token}                             routes_dashboard  contact list dashboard (q,page,letter,f params)
POST /owner/{token}/badge                       routes_dashboard  White/Grey/Black badge flip (silent)
POST /owner/{token}/approve                     routes_dashboard  approve pending + choose cards
GET  /owner/{token}/junk                        routes_dashboard  denied-grants list
GET  /owner/{token}/new-connection              routes_dashboard  search contacts for new connection
POST /owner/{token}/new-connection              routes_dashboard  create curated vCard → its editor
POST /owner/{token}/access                      routes_dashboard  change expiry/cards of a granted contact
GET  /owner/{token}/profile                     routes_profile    My Profile page
POST /owner/{token}/bio                         routes_profile    save bio (≤500 chars, reject over)
POST /owner/{token}/bio-visibility              routes_profile    bio public/private toggle
POST /owner/{token}/cards/new                   routes_profile    create named card
POST /owner/{token}/cards/{cid}/fields          routes_profile    set card field membership (My Profile path)
POST /owner/{token}/fields/new                  routes_profile    add profile email/phone field (My Profile path)
GET  /owner/{token}/cards/{cid}/edit            routes_editor     card editor
POST /owner/{token}/cards/{cid}/edit            routes_editor     save editor form
POST /owner/{token}/cards/{cid}/fields/{fid}/delete  routes_editor per-row ✕: full form + removal
POST /owner/{token}/cards/{cid}/delete          routes_editor     delete card (two-step confirm UI)
POST /owner/{token}/cards/{cid}/photo           routes_editor     upload/remove photo (?photo_kind=hs)
GET  /owner/{token}/profile/card/{cid}          routes_editor     card preview
POST /owner/{token}/decision                    routes_decisions  approve/deny from dashboard
GET  /owner/{token}/contact/{grant_id}          routes_dashboard  contact card detail (?card= selected)
POST /owner/{token}/bulk                        routes_decisions  bulk approve/deny/revoke
POST /owner/{token}/revoke                      routes_decisions  revoke granted access
POST /owner/{token}/quarter/make_permanent      routes_decisions  grey → lifetime
POST /owner/{token}/quarter/revoke              routes_decisions  grey → revoked
POST /owner/{token}/quarter/punt                routes_decisions  grey → next quarter
```

## 5. Database schema in brief

One SQLite file, two worlds: the **whitelist** tables (`wl_init` + heals,
whitelist_db.py) and the **imported address book** (`store.init_db`: contacts,
contact_sources, dedup_log; JSON-array columns emails/phones/organizations/
sources; owner-scoped via `contacts.owner_profile_id`).

Whitelist tables (all created/healed only through `ensure_whitelist_schema`):

- `profiles` — handle (unique), display_name, company/title (legacy cols),
  verified_at, password_hash (NULL = curated stub), owner_id (self-FK;
  per-owner isolation), bio, bio_visibility.
- `profile_fields` — profile_id, field_type (CHECK against
  `CARD_EDITOR_FIELD_TYPES`), field_value, visibility (CHECK
  public/granted/private), label (phone/role labels), UNIQUE(profile_id,
  field_type, field_value). **The enum story**: the CHECK is generated from
  the Python tuple, so widening it means a new table-swap heal each time —
  v2 (base 8) → v3 (round-2 apps, `address`→`address1`) → pass3 (identity +
  country) → pass5 (department, po_box, related_person, event, custom_field,
  name_prefix/suffix). Card scoping is NOT in the schema: `card_kind()` reads
  the card NAME and `_SCOPE_TEMPLATES` decides which types each scope renders.
  **Why preservation matters**: the swap copies rows id-for-id with FKs off,
  because `card_fields` and grant card sets reference `profile_fields.id` and
  the `label` column carries user-typed phone/role labels — a rebuild that
  renumbered ids or dropped columns would silently unlink every card mapping
  and erase labels. Detection is a distinctive literal in the stored DDL
  (e.g. `'department'` = pass5), so heals are idempotent and order-chained.
- `access_grants` — id (uuid), profile_id, requester_email/name, status CHECK
  (pending/granted/denied/revoked), context, granted_at, expires_at (NULL =
  lifetime; quarter-end string = grey marker, never an expiry), owner_id,
  quarter_status, last_reviewed_at.
- `cards` (owner_profile_id, name, photo_path, hs_photo_path),
  `card_fields` (card↔field lens links), `grant_cards` (grant↔card).
- `profile_aliases`, `grant_contexts`, `scan_events`, `password_reset_tokens`
  (hash at rest), `card_forwardings`, `notifications` (kind CHECK; owner-only
  events; dedupe_key unique index), `grant_logs` (action CHECK; append-only
  audit), `share_bundles` (card_ids JSON, expires_at = +7d),
  `quarantined_requests` (blacklist silence), `whitelist_meta` (heal markers).

## 6. Templates

All extend `base.html` (identity tokens, grey-only buttons — the `.wl-btn-*`
aliases are all slate gray and pinned one-rule-per-class by tests;
mobile-squeeze + fixed alpha-rail CSS; visibility-select keyboard JS).

| Template | Role / key spots |
|---|---|
| `base.html` (~250) | Theme tokens, button aliases (one rule per alias — tests parse them), badge trio note, mobile squeeze, alpha-rail fixed positioning. Dead-rule pruned 2026-09-26. |
| `_fields.html` | SHARED MACROS (2026-09-26): `field_label` (the one field-type label map — was 3 copies), `field_row` (display row), `reach_icon` (ink SVG contact icons), `profile_header` (picture/name/title/verified badge; parameterized). |
| `contact_list.html` (~450) | Dashboard: centered title + signout, my-card row, search + `+` button, amber pending box, picture filter tabs, per-card rows (one click target `absolute inset-0`, badge form z-10 above), alpha rail `#letter-rail` + swipe JS, pagination, junk footer. |
| `card_editor.html` (~580) | THE editor: placeholders map, `public_default_types`/`private_default_types` sets (mirror of routes_editor tables), macros `vis_select`/`default_visibility`/`phone_label_select`/`label_editor`/`field_input`/`field_row`/`empty_row` (✕ via formaction, never nested forms); photo slots (two on Personal), name inputs, `{% for heading, types in sections %}` with address-block branch, po_box standalone, multi-type `<template data-newrow>`, danger-zone delete; JS: addFieldRow/addAddressBlock/label custom/photo circle-cropper. |
| `profile.html` (~150) | Public page: header via `_fields.profile_header` (+hs), bio, Connect button (anonymous only), "Reach me" per-card icon rows via `_fields.reach_icon`, card-grouped fields via `_fields.field_row`, flat fallback. |
| `contact_card.html` (~180) | Owner's view of one contact: all cards continuous, Access block (status = list names, no Expires row), grey quarterly three-button row (Keep GreyList / Add WhiteList / Add BlackList), shared macros. |
| `my_profile.html` (~230) | QR + native `navigator.share` (fallback copy/email/SMS), bio + visibility select, My Cards list (+ New card), card preview links. |
| `share_bundle.html` (~90) + `share_cards_fragment.html` (~60) | Recipient page: public-tier only, bio always, per-card blocks with inline reach icons (`_fields.reach_icon`), Save-to-contacts vcf, Connect. |
| `card_preview.html` (~35) | Editor's Preview card view (`_fields.field_label`). |
| `new_connection.html` (85) | Search results + create-vCard form. |
| `junk.html` (38), `admin_review.html`/`admin_decision.html` (46/41), `request_form/success` (34/19), `forward_success` (25), `share_expired` (24), `verify_success` (16), `signin`/`signup`/`forgot_password`/`reset_password` (60/69/53/48) | Small single-purpose pages. |

## 7. Test map

Run: `.venv/bin/python -m pytest tests/ -q`. `tests/conftest.py` forces
`RELMGR_DB_PATH` to a scratch file BEFORE any import so the module-level
`app = create_app()` never boots against prod. Tests set `WHITELIST_SECRET`
before importing `app` and call `TestClient(create_app(tmp_db))`. Template
refactors verify render-equivalence with `scripts/render_snapshot.py`
(seed a world, dump 17 normalized pages, diff).

| File | Covers |
|---|---|
| `test_card_editor.py` (915) | Editor round-2 + scoped sections: per-scope type sets, add/remove round-trips, address blocks, legacy migration; `FIELD_TYPES`/`RETIRED_TYPES` pins. |
| `test_ux_pass1/2/3.py` (583/1048/614) | Captain-pass regression pins per pass: pass1 layout; pass2 phone labels, visibility defaults, my-card strip (`_editor_gets` helper); pass3 default cards, unified share, filter tabs, create-flow landing, quarantine page shape. |
| `test_share_bundle.py` (791) | Bundle lifecycle: mint, live rendering, expiry, renewal, public-only tier, vcf, expired-link ping. |
| `test_quarterly_rhythm.py` (659) + `test_p5_quarter.py` | Grey state machine, quarter routes, digests, never-expire semantics. |
| `test_password_reset.py` (523) | Reset flow end-to-end: token TTL, single-use, timing parity, no enumeration. |
| `test_signin_isolation.py` (393) | Ruling 2A: owner sees only own grants/contacts/cards; retired-link handling. |
| `test_whitelist_features.py` (408) | Bio visibility, QR, trusted forwarding. |
| `test_owner_dashboard.py` / `test_p5_contact_list.py` / `test_contact_list.py` | Contact-list surface: pagination, search, logo freshness, per-card rows. |
| `test_my_profile.py` (386) | My Profile: bio, cards, fields, photo, preview, scan stats. |
| `test_p5_cards.py` / `test_public_cards.py` | Cards CRUD + public tier filtering (B4). |
| `test_security_audit.py` (376) | 2026-09-25 audit: owner-email takeover, quarter IDOR, photo enumeration, headers, rate limit, S5 email-push dedupe (patches `app._send_connection_request_email` BEFORE create_app — `WebContext.push_connection_email` exists to keep that working). |
| `test_p3_*` (refactor/revocation/logs/scans/contexts) | P3 lane: revoke semantics, audit log, scan events, contexts. |
| `test_p4_categories_bulk.py` | Custom context categories + bulk actions. |
| `test_p5_audit_schema.py`, `test_p5_identity.py`, `test_p5_merge_wiring.py`, `test_p5_review_email.py`, `test_p5_templates.py` | grant_logs CHECK heal, identity join/merge, approve→merge wiring, quarterly email, template pins. |
| `test_refactor_fixes.py`, `test_q36_audit.py`, `test_q38_review_fixes.py`, `test_jemma_review.py`, `test_review_tabs_fixes.py` | Historical review/audit regression pins. |
| `test_request_flow.py`, `test_tiers.py`, `test_aliases.py`, `test_tokens.py`, `test_verify.py` | Core grant loop, tier logic, handle aliases, HMAC tokens, verify endpoint. |
| `test_seed.py`, `test_seed_demo.py`, `test_normalizer.py` | `seed_profile` upsert, demo seeding, normalizer. |
| `test_mailer.py`, `test_mail_wiring.py`, `test_notifications.py` | SMTP config/transport injection, outbound wiring, notification CRUD. |
| `test_owner_self_view.py`, `test_tabs.py`, `test_context_removed.py`, `test_whitelist_schema.py` | Self-view auth-only, removed tab chrome, removed context UI, schema idempotency. |

Gotchas that bite tests: the one-time `pass2_visibility_heal` fires on any
fresh DB at first boot (set visibilities AFTER booting the app, or you are
testing the heal); direct DB writes need `TestClient(create_app(db))` first
(boot creates the columns) and `store.init_db(db)` before touching `contacts`;
dedicated add-row slots (`new_{t}_*`) render only when the card has no field
of that type, so pin add-row UI on a fieldless card.
