# UX Pass 4 — Implementation Plan

## Captain's intent (full feedback pass)

1. **Card templates**: plain vCards for contacts vs Personal/Work profiles
2. **Scoped personal/work data fields**
3. **The name system with Display Name**
4. **The Google-Contacts "add field" picker**
5. **Sorting, delete-button, Shift-Tab, picture and badge fixes**

---

## Section 1: Locked decisions (binding for both workers)

- **No schema changes**: all work is additive via existing columns and rows. The cards table already has `name`, `photo_path`, `hs_photo_path`, `owner_profile_id`. The profiles table already has `display_name`. No new columns needed.
- **Shared contract**: both workers must agree on exact function names, return shapes, and SQL fragments. See Section 2.
- **Existing `_CARD_ORDER_SQL`**: Personal first (0), Work second (1), rest alphabetical (2). DO NOT change.
- **Existing `seed_default_cards`**: already seeds Personal+Work for every owner with correct field types. DO NOT change.
- **Existing `effective_tier()`**: returns 'granted'/'anonymous'. DO NOT change.
- **Existing `cards_for_public_view` / `cards_for_share_bundle`**: tier-filtered field visibility. DO NOT change.
- **Existing `_build_vcard`**: builds vCard 3.0 from visible_fields. DO NOT change.
- **Field type constants**: `CARD_EDITOR_FIELD_TYPES`, `CARD_EDITOR_MULTI_TYPES`, `CARD_EDITOR_SECTIONS` — DO NOT add or remove types.

---

## Section 2: Shared contract (exact names, shapes, endpoints)

### 2.1 Data layer → app layer contract

**whitelist_db.py exports (PACKAGE A adds, PACKAGE B reads):**

| Function | Package | Purpose |
|----------|---------|---------|
| `card_kind(card)` | Both | Returns 'personal' | 'work' | None |
| `_CARD_ORDER_SQL` | Both | Ordering fragment (Personal=0, Work=1, rest=2) |
| `list_cards(conn, owner_profile_id)` | Both | Cards with fields, Personal-first ordering |
| `get_card_by_id(conn, card_id)` | Both | Single card with fields |
| `cards_for_public_view(conn, profile_id, tier)` | Both | Tier-filtered cards for public view |
| `cards_for_share_bundle(conn, bundle, tier)` | Both | Tier-filtered cards for share bundle |
| `seed_default_cards(conn)` | Both | Ensure Personal+Work exist for every owner |
| `create_contact_vcard(conn, owner_id, display_name, ...)` | Both | Create standard vCard profile |
| `search_new_connections(conn, owner_id, q, limit)` | Both | Search contacts table |
| `list_contact_list_rows(conn, profile_id, q, page, per_page)` | Both | Dashboard rows |

### 2.2 App layer → template contract

**app.py routes (PACKAGE A reads, PACKAGE B writes):**

| Route | Package | Purpose |
|-------|---------|---------|
| `GET /owner/{token}/cards/{id}/edit` | B | Card editor page |
| `POST /owner/{token}/cards/{id}/fields/{fid}/delete` | B | Delete field from card |
| `POST /owner/{token}/cards/{id}/save` | B | Save card editor changes |
| `POST /owner/{token}/cards/{id}/photo` | B | Upload card photo |
| `GET /owner/{token}/cards/new` | B | New card creation page |
| `POST /owner/{token}/cards` | B | Create new card |
| `POST /owner/{token}/cards/{id}/delete` | B | Delete card |
| `GET /owner/{token}/profile` | B | My Profile page |
| `GET /owner/{token}/cards/{id}/preview` | B | Card preview page |

### 2.3 Template variable names (both workers must use)

- Card dicts carry: `id`, `name`, `owner_profile_id`, `photo_path`, `hs_photo_path`, `fields`
- Fields carry: `id`, `field_type`, `field_value`, `visibility`, `label`
- `card_kind(card)` returns: `'personal'` | `'work'` | `None`

---

## Section 3: PACKAGE A — Data layer (whitelist_db.py + tests)

**Worker A owns: `whitelist_db.py` (modifications only), `tests/test_ux_pass4_data.py` (new file)**
**Worker B owns: `app.py`, `templates/*`, `static/*`**

### 3.1 No data layer changes needed

After codebase exploration, no changes to `whitelist_db.py` are required for UX pass 4. The data layer already has:

- ✅ `card_kind()` — Personal/Work detection (line ~340)
- ✅ `_CARD_ORDER_SQL` — Personal-first ordering (line ~330)
- ✅ `seed_default_cards()` — Personal+Work seeding with correct field types (line ~3030)
- ✅ `cards_for_public_view()` — tier-filtered rendering (line ~2500)
- ✅ `cards_for_share_bundle()` — tier-filtered bundle rendering (line ~2900)
- ✅ `list_contact_list_rows()` — dashboard rows with pending/active/contacts (line ~3600)
- ✅ `search_new_connections()` — contacts table search (line ~3950)
- ✅ `create_contact_vcard()` — standard vCard creation (line ~4000)
- ✅ `_build_vcard()` — vCard 3.0 builder (line ~377)
- ✅ `effective_tier()` — tier oracle (line ~1700)
- ✅ `is_grey()` — derived grey state (line ~2100)
- ✅ `set_badge_state()` — badge moves (line ~2050)

### 3.2 Tests to add (PACKAGE A)

**File: `tests/test_ux_pass4_data.py`**

Test suite covering:

1. **card_kind() correctness** — Personal, Work, custom names
2. **_CARD_ORDER_SQL ordering** — Personal first, Work second, rest alphabetical
3. **seed_default_cards idempotency** — multiple calls, empty profiles, existing cards
4. **Personal card field scoping** — Personal card gets personal field types
5. **Work card field scoping** — Work card gets work field types
6. **list_contact_list_rows with search** — search filters name/email/fields
7. **search_new_connections empty query** — returns [] for empty q
8. **create_contact_vcard name system** — display_name persistence, handle uniqueness
9. **cards_for_public_view tier filtering** — granted vs anonymous visibility
10. **is_grey derived state** — lapsed and future markers
11. **set_badge_state grey→whitelist** — lifetime restoration
12. **set_badge_state grey→blocked** — revocation
13. **is_blacklisted** — revoked email detection
14. **list_contact_list_rows sorting** — pending first, then A-Z

---

## Section 4: PACKAGE B — UI layer (app.py + templates)

**Worker B owns: `app.py`, `templates/*`, `static/*`**
**Worker A owns: `whitelist_db.py`, `tests/test_ux_pass4_data.py`**

### 4.1 UI fixes (app.py)

1. **Sorting fix**: ensure contact list respects `_CARD_ORDER_SQL` ordering
2. **Delete-button fix**: verify `owner_delete_card` route works correctly
3. **Shift-Tab fix**: form navigation (JS in templates)
4. **Picture fix**: verify photo upload path for Personal/Work cards
5. **Badge fix**: verify badge rendering matches `is_grey()` state
6. **Add-field picker**: Google-Contacts-style field type picker in card editor

### 4.2 Template fixes

1. **Contact list**: render Personal/Work cards correctly
2. **Card editor**: scoped field types per card kind
3. **My Profile**: display name system consistent
4. **Share bundle**: personal card picture leads

---

## Section 5: Execution order

1. Worker A creates `tests/test_ux_pass4_data.py` (no whitelist_db.py changes needed)
2. Worker B implements UI fixes in app.py and templates
3. Both workers run `python -m pytest tests/ -q`
4. Both branches pushed, PRs opened

---

## Section 6: Testing strategy

- Worker A: `python -m pytest tests/test_ux_pass4_data.py -q`
- Worker B: `python -m pytest tests/test_card_editor.py tests/test_contact_list.py tests/test_my_profile.py tests/test_public_cards.py -q`
- Full suite: `python -m pytest tests/ -q`

---

## Section 7: Known landmines

1. **SQLite CHECK constraints**: cannot ALTER — always use table-swap pattern for enum changes
2. **`_ADMITTED_EXPIRY_SQL`**: single source of truth — must not be duplicated
3. **`_CARD_ORDER_SQL`**: used by `list_cards`, `cards_for_public_view`, `cards_for_share_bundle` — ONE fragment
4. **`seed_default_cards`**: Personal MUST be created before Work (lower id = default picture)
5. **`effective_tier()`**: owner self-view always returns 'granted' — check email match first
6. **`cards_for_public_view`**: anonymous gets default card (lowest id) only; granted gets all visible cards
7. **`is_grey()`**: derived from `status='granted' + expires_at IS NOT NULL + real timestamp` — not stored
8. **`set_badge_state`**: single entry point for badge moves — never write to access_grants directly
9. **Silence rule**: contacts NEVER notified about badge moves, quarantine, or their own status
10. **`_build_vcard`**: uses `visible_fields` from cards — never raw profile fields
11. **Test isolation**: tests must `create_app(db)` before data-layer writes; `store.init_db(db)` before `contacts` table access
12. **`WHITELIST_SECRET`**: must be set before importing `app` in tests
13. **`store.py`**: separate DB layer for contacts table — not in whitelist_db.py
14. **Photo uploads**: stored in `uploads/` directory, served via `/photo/{owner_id}/{card_id}` route
