# RelMgr / WhiteList — Codebase Map

One-read orientation for workers and the captain. Line numbers are pinned to
`fm/whitelist-ux-pass-4b` @ `43b27b9` (PR 22 head); they drift slowly — grep
the symbol name if the range is off. Companion doc: `AGENTS.md` (rulings and
sharp edges). This file is the map; that file is the law.

## 1. Architecture in one paragraph

A single FastAPI server (`app.py`) serves server-rendered HTML (Jinja2,
`templates/`) over one SQLite file (`contacts.db`; path = `create_app()` arg →
`RELMGR_DB_PATH` env → file beside `app.py`). `app.py` defines helpers at
module top, then one giant factory `create_app()` (line 453) that resolves the
DB path, builds the Jinja env, runs the full idempotent schema-heal chain once
(`whitelist_db.ensure_whitelist_schema`, line 557), registers middleware
(body cap, per-IP rate limit on anonymous POSTs, security headers), and
declares every route as a nested `async def` — each route opens its own
`sqlite3` connection (`wl_connect`: WAL + FK + Row factory), calls functions
in `whitelist_db.py` (the entire data layer, pure sqlite3, no ORM), and
returns `HTMLResponse(jinja.get_template(...).render(...))`. Auth is
capability-style: HMAC-signed tokens (`wl_tokens.py`) embedded in
`/owner/{token}` URLs (scope `owner_dashboard`, payload = profile id) plus a
signed `wl_session` cookie (7 days) set by `/signin`/`/signup`; `_resolve_owner`
(app.py:219) is the single oracle that accepts either. The imported address
book (`contacts` table, owned by `store.py`/`cli.py`/`scripts/fetch_*.py`)
feeds contact-list rows and new-connection search; secrets and SMTP config
come from env-or-`.env` (`wl_env.py`), outbound mail goes through `mailer.py`.
Photos are files in `uploads/` served through guarded `/photos/…` routes.
`app = create_app()` at module level (line 2802) makes `uvicorn app:app` work.

## 2. File-by-file tour

Root, by role:

| File | What it is |
|---|---|
| `app.py` (2802 ln) | All routes + render glue. Section map below. |
| `whitelist_db.py` (4431 ln) | Entire data layer: schema, migrations, queries. Map below. |
| `wl_tokens.py` (85) | HMAC-SHA256 make/consume tokens (`purpose\|payload\|expiry`). |
| `wl_env.py` (27) | `get_secret(key)`: os.environ first, then `.env` beside app.py. |
| `mailer.py` (157) | SMTP config + `send_email` + `app_base_url()` (APP_BASE_URL > BASE_URL > LAN default). |
| `notify.py` (121) | Quarterly grey-contact digest builder + `--review` CLI. |
| `store.py` (202) | Imported-address-book schema (`contacts`, `contact_sources`, `dedup_log`) + CRUD. |
| `cli.py` (172) | `sync/list/dedup/export/onboard` over store+fetcher (the import pipeline). |
| `fetcher.py` (399), `normalizer.py` (210), `deduplicator.py` (150) | Contact import: source fetch → normalize → dedup. |
| `config.py` (39) | Import-pipeline config (sources, dedup thresholds). |
| `scripts/` | `fetch_{gmail,facebook,outlook_csv,vcf}.py`, `merge_*`, `onboard`, `seed_demo`, `notify` (CLI mailer, sys.exits on missing creds), `refresh_token`. |
| `templates/`, `static/`, `uploads/` (runtime), `data/` | See templates below; static = badge/scroll PNGs. |
| `Dockerfile`, `docker-compose.yml`, `.env.example`, `SPEC.md`, `README.md` | Deploy + specs. README describes the import pipeline; SPEC the whitelist product. |

### app.py section map

| Lines | Section |
|---|---|
| 1–34 | Imports; `import wl_env` (30). |
| 36–103 | Time/rail helpers: `_parse_dt` 36, `days_since` 55, `days_until` 64, `_rail_letter` 76 (alpha-rail A–Z + `#` fold), `is_verified_stale` 90 (>180d). |
| 105–209 | Secrets + request plumbing: `_get_secret` 105, `_encode_square_jpeg` 113 (magic sniff, 40MP cap, square 512 q82), `_make_jinja` 152 (globals `phone_fmt`, `label_display`), b64url 162/168, session cookie make/consume 175/186. |
| 210–357 | Owner auth + email: `LegacyOwnerLinkRetired` 210, **`_resolve_owner` 219** (token-or-session oracle; retired pre-migration links → redirect to /signin), `_verify_grant_ownership` 273 (ruling 2A), `_decision_outcome` 286 (shared by /a and /owner decision), `_owner_email_for` 310, `_send_connection_request_email` 321 (BackgroundTask; only genuinely NEW requests). |
| 360–450 | vCard export: `_qr_png` 360, `_vcf_escape` 378, `_build_vcard` 390 (built ONLY from `visible_fields`). |
| 453–563 | `create_app()`: db path 467, rate rules 484 (`_rate_limited` 490), security middleware 517 (16MB cap, 429s, Referrer-Policy etc.), static mount 539, retired-link handler 544, **boot heal 557**. |
| 565–810 | Auth pages: `/signin` 565/571, `/signup` 601/607, `/signout` 663, forgot/reset 701–810 (`_issue_and_send_reset` 739; timing-parity + no-enumeration). |
| 812–840 | `/` landing 813, `/owner/` 828 (session→dashboard redirects). |
| 842–910 | **`/p/{handle}` public profile** 843: `record_scan`, owner detection AUTH-ONLY (`?ot=` or session; `?e=` is granted-contact tracking only), `effective_tier`, `cards_for_public_view`; renders `profile.html`. Card-less profiles fall back to flat field list. |
| 912–1054 | Connect flow: request-form 913, **POST request 925** (blacklisted → `quarantine_request` + fake uuid4 grant id, indistinguishable success; else `create_grant` + notification + email push), **POST forward 982** (granted-only, creates pending grant for recipient). |
| 1046–1157 | Sharing: share-url helpers 1046–1056, `/s/{id}/card.vcf` 1058, **`/s/{id}` view 1089** — ALWAYS anonymous-tier public page (F4 ruling), bio always included, expired → `share_expired.html` + one deduped owner ping (never for blacklisted openers). |
| 1160–1248 | Badge + admin links: **POST badge 1161** (instant, always silent), `/a/{token}` grant review 1196 + decision 1215, `/verify/{token}` 1233. |
| 1250–1499 | **Owner contact list** 1251: q/page/letter params, per-card row expansion (pending → amber box), filter tabs `?f=` (card-OR + state-OR, AND across groups), sort (card name, state rank, name), alpha rail letters, `sync_quarterly_notifications` on render, `my_card` header row; renders `contact_list.html`. |
| 1501–1584 | Approve-with-cards 1502, junk (denied) list 1549. |
| 1586–1645 | New connection: search form 1587, **POST create 1604** — `create_contact_vcard`, lands in Work editor if email given else Personal. |
| 1646–1705 | Access management 1647 (expiry + card set for granted contacts). |
| 1708–1990 | My Profile: **`_my_profile_html` 1708** (ONE render site for all five POSTs), `/profile` 1784, `/bio` 1802 (500-char reject), `/bio-visibility` 1851, `/cards/new` 1885, `/cards/{id}/fields` 1920, `/fields/new` 1955. |
| 1993–2291 | **Card editor core**: `_resolve_editor_card` 1993 (auth + ownership; curated-stub exception: owner_id==creator + password_hash NULL), `_card_editor_html` 2026 (ONE render site; `card_scope = card_kind(card) or "vcard"`, `sections = picker_sections(scope)`, `by_type` from `card["fields"]`), default-visibility tables 2086–2101 (`_PUBLIC_DEFAULT_TYPES`, `_PRIVATE_DEFAULT_TYPES=('custom_field',)`, `_editor_default_visibility` 2098), **`_parse_editor_form` 2103** (ONE parser shared by save + ✕-delete — the pass-2 data-loss fix), GET edit 2067, POST save 2173, **POST field delete 2205** (applies FULL parsed body + the removal), card delete 2263. |
| 2293–2408 | Photos: upload 2294 (client circle-crop data URL or raw file; 10MB; default + `?photo_kind=hs` slots), preview 2381. |
| 2410–2495 | Photo serving: `_photo_allowed` 2410 (audit predicate: default card / non-expired bundle / owner token-session / granted `?e=`), `_serve_photo_response` 2476. |
| 2497–2531 | `/photos/{pid}/{cid}` 2498 (+`/hs` 2502), `/qr/share/{bid}` 2507, `/qr/{handle}` 2520. |
| 2533–2801 | Decisions + quarterly: `/decision` 2534, contact card 2567 (chip-less all-cards view, quarterly buttons), `/bulk` 2625, `/revoke` 2666, quarter make_permanent/revoke/punt 2700/2735/2765 (ownership-enforced). |
| 2802 | Module-level `app = create_app()` (uvicorn entrypoint). |

### whitelist_db.py section map

| Lines | Section |
|---|---|
| 14–131 | Constants + passwords: `_PWHASH_ROUNDS` 18 (pbkdf2 260k), hash/verify 21/30, dummy-burn 47/60 (timing parity), `_table_exists` 72, `quarter_end_iso` 79, `is_current_quarter` 96. |
| 133–158 | **The two expiry oracles**: `_LIVE_GRANT_EXPIRY_SQL` 133 (display/logo freshness only), `_ADMITTED_EXPIRY_SQL` 146 (admission predicate shared by `effective_tier` + `create_grant` dedupe — granted + any real-timestamp expiry admits forever; grey/black never expire; legacy `'14d'` strings never leak via GLOB guard). |
| 161–516 | **Editor vocabulary**: `CARD_EDITOR_FIELD_TYPES` 161 (THE enum, 36 types), `CARD_EDITOR_FIELD_LABELS` 185, `ADDRESS_BLOCK_TYPES` 229, `ADDRESS_BLOCK_SCOPES` 231 (vcard+personal), `EVENT_LABEL_CHOICES` 240, **`_SCOPE_TEMPLATES` 250** (vcard/personal/work section layouts — scoping is NAME-based via `card_kind`, no scoped enum values), `picker_sections` 383 (render API; falls back to flat `CARD_EDITOR_SECTIONS` 396), `_PRIVATE_DEFAULT_TYPES` 455 + `editor_default_visibility` 458 (mirror of app.py tables), `CARD_EDITOR_MULTI_TYPES` 472 ("+ Add" types), **`_CARD_ORDER_SQL` 484** (Personal→Work→alpha; used by list/public/share), `card_kind` 490, `format_phone_display` 500 (+1 (XXX) XXX-XXXX, display-only). |
| 518–653 | Boot: `wl_connect` 518 (WAL/FK/Row), `wl_init` 528 (fresh CREATE of every base table). |
| 656–888 | **profile_fields CHECK-swap heals**: `_VCARD_FIELD_TYPES`/`_VCARD_VISIBILITY` 656/657, v2 674 (base 8 types, anonymous→private), v3 744 (round-2 apps, `address`→`address1`), pass3 805 (identity fields + country), pass5 854 (department/po_box/related_person/event/custom_field/name_prefix+suffix), `_seed_title_company_fields` 890. Detection = distinctive literal in `sqlite_master` DDL. |
| 929–1128 | Owner profiles: `create_owner_profile` 929 (email field private, owner_id=self), `resolve_owner_by_credentials` 986 (dummy burn on miss), reset tokens 1020–1097 (SHA-256 at rest, single-use, 30min), `set_profile_password` 1099, `get_profile_by_email` 1111. |
| 1130–1249 | `seed_profile` 1130 (canonical-JSON upsert; org → profiles columns + granted field rows). |
| 1251–1688 | Grants: **`effective_tier` 1251** ('granted'/'anonymous' oracle), `_fetch_profile` 1291 (fields attached, ORDER BY is contract), fetchers 1306–1328, `find_admitting_grant_id` 1330 (new-vs-dedupe for email push), `create_grant` 1356 (dedupe admits forever), `update_grant_status` 1402, `resolve_handle` 1489 (+aliases), `add_alias` 1511, **`apply_decision` 1554** (pending-only guard, atomic approve+contacts merge). |
| 1691–1790 | Audit: `_GRANT_LOGS_CHECK` 1691 (action enum), `_grant_logs_ddl` 1697, `ensure_grant_log_actions` 1722 (legacy-CHECK table-swap heal), `_log_action` 1773 (same-commit convention). |
| 1792–1967 | Contexts (registry + built-ins; UI removed 2026-09-12), `set_grant_context` 1866, `ensure_access_grants_context` 1888, scans 1910–1957 (14-day zero-filled stats), `get_grant_logs` 1959. |
| 1970–2077 | access_grants migrations: v2 1970 ('revoked' CHECK swap), v3 2013 (quarter_status + last_reviewed_at additive), `revoke_grant` 2042 (granted-only). |
| 2079–2371 | **Rhythm/badges**: `set_badge_state` 2079 (White→Grey→Black entry point; grey stamps quarter-end marker = internal, never an expiry; always silent), `is_grey` 2139 (granted + any real-timestamp expires_at, future marker included), `mark_grey_pending_review` 2167, grey digests 2198–2251 (lapsed-only), `make_grant_permanent` 2253, `punt_grant` 2284, `bulk_apply` 2320 (per-grant scoping), `find_contact_by_email` 2383. |
| 2444–2574 | Identity merge: `merge_requester_into_contacts` 2453 (approve → contacts row; provenance append-merge; owner-scoped). |
| 2576–2833 | Cards: `ensure_cards_schema` 2576 (cards/card_fields/grant_cards), `create_card` 2611, `delete_card` 2659 (lens semantics: profile_fields survive), **`get_card_by_id` 2683** (fields attached), `list_cards` 2696 (`_CARD_ORDER_SQL`), **`cards_for_public_view` 2715** (anonymous = default card + public fields only; granted = all cards, hide zero-visible; `visible_fields` key), `set_grant_cards` 2758 (ownership-checked), `get_active_cards_for_grant` 2812. |
| 2835–3074 | Bundles/quarantine: TTL 7d (2835–2883), `filter_owned_cards` 2885, **`create_share_bundle` 2906** (data-layer mint only; owner routes retired), `is_blacklisted` 2975 (revoked == blacklisted), `quarantine_request` 3010 (per-email/day dedupe), `cards_for_share_bundle` 3037 (bundle order, Personal leads). |
| 3076–3233 | Additive heals: bio cols 3076/3083, `ensure_profile_field_labels` 3098, **`ensure_pass2_visibility_heal` 3111** (ONE-TIME marker-gated backfill via `whitelist_meta`), phone labels 3159–3185 (`PHONE_LABEL_CHOICES`, `normalize_field_label`, `label_display`), photo cols 3187/3194, forwardings table 3210. |
| 3235–3464 | Forwarding (`forward_card` 3235 → pending grant) + notifications: kinds CHECK 3300, **`ensure_notification_kinds` 3304** (table-swap heal), CRUD 3348–3431 (dedupe_key idempotency), `sync_quarterly_notifications` 3433 (runs on dashboard render). |
| 3467–3577 | Boot order: owner-auth cols 3467, grants owner 3488, contacts owner 3506, **`ensure_whitelist_schema` 3534** — THE single ordered entry point (order load-bearing; ends with `seed_default_cards`). |
| 3579–3737 | **`seed_default_cards` 3579**: Personal+Work pair ALWAYS for every profile (Personal first = lower id = default public picture); phone→Personal, email→Work links; legacy names (Identity/Contact/…) heal-only; bio updates 3712–3737. |
| 3739–4003 | Editor writes: `set_card_fields` 3739, `add_profile_field` 3770, `update_card_photo` 3799 (kind default/hs), **`save_card_editor` 3819** (ONE commit; form-keyed rows only — out-of-scope stored fields SURVIVE; IDOR-checked; empty value = unlink). |
| 4005–4301 | Contact list: `_grant_is_live` 4005 (Python twin of live SQL), **`list_contact_list_rows` 4024** (grants + contacts merged, per-card refs, logo freshness, search haystack = name/email/phone/org + non-private field values, never bios). |
| 4303–4431 | New connection: `search_new_connections` 4303 (owner-scoped contacts LIKE; degrades to [] without the table), `_slugify_handle` 4373, **`create_contact_vcard` 4380** (curated stub: owner_id = creator, password_hash NULL, defaults seeded). |

### Templates

All extend `base.html` (identity tokens, grey-only buttons — `.wl-btn-*` are
all slate aliases; mobile-squeeze + fixed alpha-rail CSS at ~175–280;
visibility-select keyboard JS).

| Template | Role / key spots |
|---|---|
| `base.html` (283) | Theme tokens, button aliases, badge trio CSS, mobile squeeze, alpha-rail fixed positioning. |
| `contact_list.html` (453) | Dashboard: centered title + signout, my-card row, search + `+` button, amber pending box, picture filter tabs, per-card rows (one click target `absolute inset-0`, badge form z-10 above), alpha rail `#letter-rail` + swipe JS (~330–450), pagination, junk footer. |
| `card_editor.html` (598) | THE editor: placeholders map, `public_default_types`/`private_default_types` sets, macros `vis_select`/`default_visibility`/`phone_label_select`/`label_editor`/`event_label_select`/`field_input`/`field_row` (✕ via formaction, never nested forms)/`empty_row`; photo slots (two on Personal), name inputs, `{% for heading, types in sections %}` with address-block branch (`address_block and heading == 'Addresses'`), po_box standalone, multi-type `<template data-newrow>`, danger-zone delete; JS: addFieldRow/addAddressBlock/label custom/photo circle-cropper. |
| `profile.html` (247) | Public page: header (+hs photo), bio, Connect button (anonymous only), "Reach me" per-card icon rows (granted only), card-grouped fields via `_field_row` macro, `_field_label` enum-label map, flat fallback. |
| `contact_card.html` (249) | Owner's view of one contact: all cards continuous, Access block (status = list names, no Expires row), grey quarterly three-button row (Keep GreyList / Add WhiteList / Add BlackList), same macros. |
| `my_profile.html` (230) | QR + native `navigator.share` (fallback copy/email/SMS), bio + visibility select, My Cards list (+ New card), card preview links. |
| `share_bundle.html` (91) + `share_cards_fragment.html` (80) | Recipient page: public-tier only, bio always, per-card blocks with inline reach icons, Save-to-contacts vcf, Connect. |
| `card_preview.html` (72) | Editor's Preview card view. |
| `new_connection.html` (85) | Search results + create-vCard form. |
| `junk.html` (38), `admin_review.html`/`admin_decision.html` (46/41), `request_form/success` (34/19), `forward_success` (25), `share_expired` (24), `verify_success` (16), `signin`/`signup`/`forgot_password`/`reset_password` (60/69/53/48) | Small single-purpose pages. |

## 3. "Where do I change X" — the 20 most likely edits

1. **Add a field type**: `CARD_EDITOR_FIELD_TYPES` + `CARD_EDITOR_FIELD_LABELS` (whitelist_db 161/185) → new `ensure_vcard_fields_<pass>_schema` CHECK-swap heal + call in `ensure_whitelist_schema` (3534) → add to the relevant `_SCOPE_TEMPLATES` scope(s) (250; and `CARD_EDITOR_SECTIONS` 396 fallback) → placeholders map in `card_editor.html` (~4) → label rendering in the three display templates' `_field_label` macros → vCard export mapping in `_build_vcard` (app.py 390) → decide default visibility in BOTH tables (whitelist_db 455 + app.py 2086 + card_editor sets) → tests.
2. **Change which fields Personal/Work/vCard cards show**: `_SCOPE_TEMPLATES` (whitelist_db 250) only — scoping is name-based (`card_kind` 490), never add scoped enum values (an earlier PR-22 iteration did; it was replaced).
3. **Change address-block rendering**: `ADDRESS_BLOCK_TYPES`/`ADDRESS_BLOCK_SCOPES` (229/231) + the `Addresses` branch in `card_editor.html`; block branch fires ONLY on heading `'Addresses'` from scoped sections.
4. **Change card template look (public view)**: `profile.html` `_field_row`/`_field_label`; owner detail: `contact_card.html`; share: `share_cards_fragment.html`. Three copies of the label map exist — keep them in sync.
5. **Editor save/delete semantics**: `_parse_editor_form` (app.py 2103) + `save_card_editor` (whitelist_db 3819). Any new write path MUST go through `save_card_editor`; the ✕ delete route (2205) must keep applying the full parsed body.
6. **Add an owner route**: nested def in `create_app` after its siblings; resolve with `_resolve_owner` (219), verify grants with `_verify_grant_ownership` (273), 403/404 conventions as in neighbors; add to route table below + tests.
7. **Contact-list rows/filters/rail**: route `owner_dashboard` (1251) for data/params; `contact_list.html` for markup; `_rail_letter` (app.py 76) for letters; `list_contact_list_rows` (whitelist_db 4024) for the row shape.
8. **Badge cycle**: `set_badge_state` (whitelist_db 2079) + badge form in `contact_list.html`; confirmations say WhiteList/GreyList/BlackList; contacts are NEVER notified.
9. **Quarterly review**: grey trio = `is_grey` 2139, `make_grant_permanent`/`punt_grant` 2253/2284, quarter routes (app.py 2700–2801), buttons in `contact_card.html`, digest in `notify.py` + `sync_quarterly_notifications` 3433.
10. **Sharing/QR**: QR + native share live in `my_profile.html` + `_my_profile_html` (1708); bundle serving `/s/{id}` (1089) + `cards_for_share_bundle` (3037); bundle minting is data-layer only (`create_share_bundle` 2906).
11. **Connect-request flow / quarantine**: POST `/p/{handle}/request` (925), `create_grant` (1356), `quarantine_request` (3010), `is_blacklisted` (2975); success page must stay indistinguishable.
12. **Visibility defaults**: whitelist_db 455–470 + app.py 2086–2101 + `card_editor.html` sets — one decision, three mirrors. Never re-heal existing data (pass2 heal is one-time by design).
13. **Tier/field exposure**: `effective_tier` (1251) + `visible_fields` filtering in `cards_for_public_view` (2715) / `cards_for_share_bundle` (3037); public surfaces must go through those, never raw `fields`.
14. **Photos**: upload route (2294) + `_encode_square_jpeg` (113) + cropper JS in `card_editor.html`; serving predicate `_photo_allowed` (2410); files `uploads/{pid}_{cid}[_hs].jpg`.
15. **Add a notification kind**: `_NOTIFICATION_KINDS` (3300) — CHECK lives in two DDLs (`wl_init` 528 + `ensure_notification_kinds` 3304 table-swap heal), writer `create_notification` 3348; there is NO notification page — requests surface in the amber box.
16. **Email sending**: `mailer.send_email` / `app_base_url` (mailer.py); push call sites `_send_connection_request_email` (321), reset (739); never block responses — BackgroundTask.
17. **Auth/session**: `_make_session_cookie`/`_consume_session_cookie` (175/186), `_resolve_owner` (219), `wl_tokens.make_token/consume_token`; scopes: `owner_dashboard`, `grant_review`, `verify`.
18. **Schema change**: additive column → own idempotent `ensure_*` + call in `ensure_whitelist_schema` (3534, order matters); new enum value → row-preserving table-swap heal (copy pattern from 854); copy EVERY column (labels, ids) so `card_fields` links and phone labels survive.
19. **Phone display/labels**: `format_phone_display` (500) + `phone_fmt` global; labels `PHONE_LABEL_CHOICES`/`normalize_field_label`/`label_display` (3159–3185); editor macro `phone_label_select`.
20. **Rate limiting/security headers**: `_RATE_RULES`/`_rate_limited` (484/490) + `_security_middleware` (517); off-switch `WHITELIST_RATELIMIT_DISABLED`.

## 4. Route table

Every URL `app` serves (method path — line — one-liner).

```
GET  /                                          813   landing: session→dashboard else /signin
GET  /signin                                    565   sign-in page
POST /signin                                    571   credentials → wl_session cookie → 303 /
GET  /signup                                    601   sign-up page
POST /signup                                    607   create owner → session → 303 /
POST /signout                                   663   clear session → 303 /signin
GET  /forgot-password                           701   request-reset page
POST /forgot-password                           705   mint+mail reset in background; same response always
GET  /reset-password/{token}                    762   set-new-password page (peek token)
POST /reset-password/{token}                    775   consume token, set password → /signin?reset=1
GET  /owner/                                    828   session → /owner/{fresh token}
GET  /p/{handle}                                843   public profile (tier via ?e=; owner via ?ot=/session)
GET  /p/{handle}/request-form                   913   Connect request form
POST /p/{handle}/request                        925   create grant (or silent quarantine if blacklisted)
POST /p/{handle}/forward                        982   granted contact forwards card → pending grant
GET  /s/{bundle_id}                             1089  share link: ALWAYS public-tier page; expired page
GET  /s/{bundle_id}/card.vcf                    1058  public-fields-only vCard download
GET  /a/{token}                                 1196  emailed grant-review page (grant_review token)
POST /a/{token}/decision                        1215  approve/deny from email link
GET  /verify/{token}                            1233  verify token → stamp verified_at
GET  /photos/{owner_pid}/{card_id}              2498  guarded photo JPEG (default slot)
GET  /photos/{owner_pid}/{card_id}/hs           2502  guarded photo JPEG (high-school slot)
GET  /qr/share/{bundle_id}                      2507  QR PNG for /s/{bundle_id}
GET  /qr/{handle}                               2520  QR PNG for /p/{handle}
     /static/*                                  539   mounted static dir
GET  /owner/{token}                             1251  contact list dashboard (q,page,letter,f params)
POST /owner/{token}/badge                       1161  White/Grey/Black badge flip (silent)
POST /owner/{token}/approve                     1502  approve pending + choose cards
GET  /owner/{token}/junk                        1549  denied-grants list
GET  /owner/{token}/new-connection              1587  search contacts for new connection
POST /owner/{token}/new-connection              1604  create curated vCard → its editor
POST /owner/{token}/access                      1647  change expiry/cards of a granted contact
GET  /owner/{token}/profile                     1784  My Profile page
POST /owner/{token}/bio                         1802  save bio (≤500 chars, reject over)
POST /owner/{token}/bio-visibility              1851  bio public/private toggle
POST /owner/{token}/cards/new                   1885  create named card
POST /owner/{token}/cards/{cid}/fields          1920  set card field membership (My Profile path)
POST /owner/{token}/fields/new                  1955  add profile email/phone field (My Profile path)
GET  /owner/{token}/cards/{cid}/edit            2067  card editor
POST /owner/{token}/cards/{cid}/edit            2173  save editor form
POST /owner/{token}/cards/{cid}/fields/{fid}/delete  2205  per-row ✕: full form + removal
POST /owner/{token}/cards/{cid}/delete          2263  delete card (two-step confirm UI)
POST /owner/{token}/cards/{cid}/photo           2294  upload/remove photo (?photo_kind=hs)
GET  /owner/{token}/profile/card/{cid}          2381  card preview
POST /owner/{token}/decision                    2534  approve/deny from dashboard
GET  /owner/{token}/contact/{grant_id}          2567  contact card detail (?card= selected)
POST /owner/{token}/bulk                        2625  bulk approve/deny/revoke
POST /owner/{token}/revoke                      2666  revoke granted access
POST /owner/{token}/quarter/make_permanent      2700  grey → lifetime
POST /owner/{token}/quarter/revoke              2735  grey → revoked
POST /owner/{token}/quarter/punt                2765  grey → next quarter
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
  the card NAME and `_SCOPE_TEMPLATES` decides which types each scope renders
  (an early pass-4 draft added `email_personal`-style scoped enum values; the
  43b27b9 repair removed them — keep it that way).
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

## 6. Test map

Run: `.venv/bin/python -m pytest tests/ -q` (in the primary checkout; a
worktree has no venv). `tests/conftest.py` forces `RELMGR_DB_PATH` to a
scratch file BEFORE any import so the module-level `app = create_app()` never
boots against prod. Tests set `WHITELIST_SECRET` before importing `app` and
call `TestClient(create_app(tmp_db))`.

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
| `test_security_audit.py` (376) | 2026-09-25 audit: owner-email takeover, quarter IDOR, photo enumeration, headers, rate limit. |
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
