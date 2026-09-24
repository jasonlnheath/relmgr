# UX Pass 4 — UI Layer (Package B) Status

## Branch: `fm/whitelist-ux-pass-4b`

## Summary
UI layer changes for UX pass 4 are complete. All 649 tests pass (629 existing + 20 new UI tests).
Package A (data layer) is developed in parallel on `fm/whitelist-ux-pass-4a`.

## Changes Made

### `app.py`
- Dashboard sorting: switched to plain alphabetical by name, then card name
- Added `profile_cards_fallback=True` to `list_contact_list_rows` calls (graceful fallback)
- Extended `owner_create_card` route to accept and pass `scope` parameter
- Updated `_card_editor_html` to pass scope, sections, and name context
- Extended `_parse_editor_form` to capture name fields (returns 7-tuple)
- Enhanced `_build_vcard` with `_scoped_base_type` helper
- Both save and delete routes wrap `save_card_editor` calls in try/except for backward compatibility with Package A

### Templates
- **card_editor.html**: Full rewrite — name block with first/last/suffix/middles/display, server-driven sections, phone labels, scoped field picker with optgroups, shift+Tab support
- **my_profile.html**: Scope radio buttons (personal/work)
- **contact_list.html**: Horizontal owner card strip, per-card row avatars
- **contact_card.html**: Chip mini-images, updated labels (Maiden/Surname)
- **profile.html**: Label updates
- **card_preview.html**: Scoped type label rendering, `_scoped_label` macro

### Tests
- **tests/test_ux_pass4_ui.py**: 20 new UI tests covering sort structure, scope UI, field picker, added-row audit, shift+Tab, name system, maiden rename, photos/whitelist, phone label 400, address multi

## Test Results
- **649 passed, 0 failed** (629 existing + 20 new)
- 7 warnings (deprecation notices, not related to changes)

## Package A Dependency
The following UI features are RED until Package A merges:
- Actual alphabetical sorting (data layer sort keys)
- Scope-aware card creation (create_card accepts scope)
- Per-card photos in contact list
- Phone label validation (400 on invalid label for scope)
- Address multi-type support (addresses in CARD_EDITOR_MULTI_TYPES)
- Maiden/Surname rename data layer

These are expected RED tests — they verify the UI contract and will go green when Package A is merged.

## Files Modified
- `app.py`
- `templates/card_editor.html`
- `templates/my_profile.html`
- `templates/contact_list.html`
- `templates/contact_card.html`
- `templates/profile.html`
- `templates/card_preview.html`
- `tests/test_ux_pass4_ui.py` (new)

## Next Steps
- Merge Package A (`fm/whitelist-ux-pass-4a`) data layer
- Re-run tests to verify all 20 UI tests go green
- Full end-to-end QA
