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

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
