# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

## Environment & commands

- Dependencies live in the repo-root `.venv` (Python 3.14). Run tests with `.venv/bin/python -m pytest tests/ -q` (~20 s, 470 tests). There is no system pytest and no requirements install into the system interpreter.
- Dev server: `uvicorn app:app --port ...` is only the docker path; for a disposable instance build the app in-process with `app.create_app(db_path)` and a throwaway DB seeded via `whitelist_db.seed_profile` + `seed_default_cards` (see `tests/test_card_editor.py::_make_db`).

## Schema migrations

- SQLite CHECK constraints cannot be ALTERed — field-type/visibility vocabulary changes use the table-swap pattern (`ensure_vcard_fields_schema` / `ensure_vcard_fields_v3_schema` in `whitelist_db.py`): detect the current generation by a distinctive literal in the `sqlite_master.sql` DDL, rebuild into `profile_fields_vN` with `PRAGMA foreign_keys=OFF` around the copy, drop + rename, then commit. Every `ensure_*` must stay idempotent and be wired into `ensure_whitelist_schema` in order.
- The card field vocabulary (labels, editor sections, repeatable types) is registered in one place at the top of `whitelist_db.py` (`CARD_EDITOR_FIELD_TYPES`, `CARD_EDITOR_SECTIONS`, `CARD_EDITOR_MULTI_TYPES`); the editor template and the public-view `_field_label` macros must stay in step with it.

## Rendering conventions

- Cards are lenses on profile fields: deleting a card (see `delete_card`) must never touch `profile_fields` — `card_fields`/`grant_cards` cascade via FK. POST-then-redirect routes must use `RedirectResponse(..., status_code=303)`; a bare 307 replays the POST (405).
- Every `<select>` on a glass page carries the `wl-select` class (base.html) — `bg-transparent` renders the native popup white-on-white.
- Card editor renders from ONE site: `_card_editor_html` in `app.py`. Forked render blocks drop state — extend that function, never add a parallel render path.
