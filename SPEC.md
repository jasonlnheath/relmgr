# WhiteList / relmgr — Product Specification

> Consolidated from the recovered plan archive (`~/.hermes/plans/`) and the codebase at commit `c0345a4`. Last updated 2026-09-18 (refined 2026-09-18).

## One-liner

**A consent-based, self-updating contact registry and communication firewall.** Scan a QR, get a verified-fresh contact card. The QR is an access key; the verification loop is the moat. Phones don't ring for unauthorized contacts.

## Product Vision

The individual controls their identity. This is not a contact list — it is an identity shield. The user decides who can see what, which identity to present, which communication channels are reachable, and what access each person or entity gets. The app enforces those decisions silently, never overriding user preference.

The system is built on zero-trust by default, with explicit trust granted by the owner. Access is capability-gated — the recipient gets what they need, when they need it, and nothing more. After that, the door closes.

## Core Principles: The Gatekeeper Model

**User decides. App enforces. Always.**

- **Real-time access is a privilege, never a default.** Granted only when the user explicitly approves it.
- **The card/QR is the access token.** A QR code is not a contact dump — it is a controlled invitation.
- **Firewall protects time until access is granted.** Until the user decides otherwise, all inbound communication is filtered silently.
- **App enforces, user decides.** The system never overrides user preference, never auto-approves, never assumes consent.
- **No exceptions.** The user's privacy and time are always secured. Zero-trust by default.
- **Users self-publish. We never ingest other people's address books.** Growth loop is QR exchange, not import.
- **Identity is user-controlled, not platform-controlled.**

## The Object Model

```
Person          — global ID, owned by the human, one per person
  id            — autoincrement integer (internal)
  handle        — unique lowercase slug (e.g. "jasonheath")
  display_name  — human-readable name
  org_company   — company name
  org_title     — job title
  avatar_url    — optional avatar URL
  verified_at   — last self-confirmation timestamp (ISO-8601 Z)
  created_at    — row creation time
  updated_at    — last update time

aliases         — many handles → one person (profile_aliases)
  alias         — lowercase [a-z0-9_] slug, case-insensitive unique
  profile_id    — FK → profiles.id

Field           — NOT records. Each field is a contact attribute attached to a Card.
  field_type    — "email" | "phone" (live; CHECK constraint in profile_fields table)
  field_value   — the actual value
  visibility    — "public" | "granted" (public shown to anonymous viewers; "granted" shown only to authorized viewers)

Standard contact field set (v2, round-2 ruling 2026-09-18):
  The field_type enum was expanded from the original 3-value set (email/phone/other) to
  cover the standard contact attributes used across iOS Contacts, Google Contacts, and
  vCard 4.0. The full set:

  | field_type  | Example values                    | vCard prop  | Notes                  |
  |-------------|-----------------------------------|-------------|------------------------|
  | email       | jason@example.com                 | EMAIL       | Primary key for grants |
  | phone       | +1-555-123-4567                   | TEL         | E.164 normalized       |
  | title       | VP Engineering                    | TITLE       | Displayed on profile   |
  | company     | Acme Inc.                         | ORG         | Displayed on profile   |
  | address     | 123 Main St, City, ST 12345       | ADR         | Future schema          |
  | website     | https://acme.com                  | URL         | Future schema          |
  | other       | Any freeform attribute            | —           | Future schema          |

  Note: the `profiles` table has `title` and `company` columns (top-level profile metadata,
  seeded from the canonical profile). These are NOT stored as profile_fields rows — they are
  separate columns. The `title` and `company` field_type values exist in the spec table above
  but are NOT yet active in the `profile_fields` CHECK constraint, which currently only allows
  `'email'` and `'phone'`. Adding those types requires a schema migration. The `address`,
  `website`, and `other` types are reserved for future expansion.

Card            — an owner-defined field group (e.g. "Work" = email fields; "Personal" = phone fields)
  name          — human-readable label
  card_fields   — which profile_fields belong to this card (card_fields table)

QR              — profile URL only, never baked-in vCard data
  content       — {BASE_URL}/p/{handle}
  generated as  — PNG, saved to exports/qr_<handle>.png
```

### Access Tiers

| Tier | Who | What they see |
|---|---|---|
| **Anonymous** | Anyone who scans the QR without being approved | Profile bio only; all fields and cards require a grant |
| **Granted** | Explicitly approved by owner | All fields the owner's card exposes |
| **Owner** | The profile's human owner | Everything, plus edit + verification controls |

### Time-Bound Access

Every permission has an expiration policy. Exactly three durations:

| Duration type | Behavior |
|---|---|
| **Lifetime** | Permanent access (`expires_at IS NULL`). Rare, high trust. |
| **While employed** | Access while the relationship persists (e.g. employment). |
| **Till next quarterly review** | Greylist — pending quarterly confirmation; expires at the next quarterly review. |

### Quarterly Rhythm

**The quarterly email is the decision moment.** Each quarter, the whitelist emails the owner a digest of all grey contacts (granted contacts whose quarter grant has expired). The email lists each contact with their email, name, cards, expiry, and review status (pending review or punted). The owner reviews the digest and takes action on each contact.

**Three decision actions on the contact card:**

| Action | Effect |
|---|---|
| **Make Permanent** | Sets `expires_at = NULL`, `quarter_status = NULL`. Terminal — no more quarterly reviews for this contact until manually revoked. |
| **Revoke** | Sets `status = 'revoked'`. Merges into the Blocked state (ruling: revoked and blocked are one state). Audit row preserved. |
| **Punt Another Quarter** | Extends `expires_at` to the next quarter end, sets `quarter_status = 'punted'`, stamps `last_reviewed_at`. Contact stays grey. |

**State model:**

- **Grey contact stays grey while punted** — punting extends the grant and keeps the contact in the grey review cycle.
- **Permanent is terminal until manually revoked** — once made permanent, the only way to remove access is revocation.
- **Revoked and blocked are one state** — both rendered as `Blocked` with a red badge in the UI.
- **No 90-day minimum** — a contact becomes prompt-eligible at each quarterly boundary for its owner while grey.
- **No countdowns** — no "X days until review" anywhere in the UI.
- **No auto-expiry** — grey contacts never auto-expire or auto-transition.
- **No expired state** — the concept of "expired" is absorbed into the grey state; there is no separate expired badge or view.

**Grey state** is derived: a grant is grey when `status='granted'`, `expires_at` has passed, and `quarter_status` is `'pending_review'` or `'punted'`. The `quarter_status` column tracks the review cycle:

| quarter_status | Meaning |
|---|---|
| `active` | Live quarter grant — not yet expired |
| `pending_review` | Expired, awaiting quarterly decision |
| `punted` | Owner chose to extend for another quarter |
| `NULL` | Lifetime grant or legacy grant |

**Quarterly review email** uses the existing `notify.py` infrastructure (`build_quarterly_review()`). It groups grey contacts by owner, shows review status per contact, and links to the owner dashboard. No new external services or queues — the digest is built via `build_quarterly_review()`; sending machinery (SMTP/Gmail) is future work.

**Grey contacts become prompt-eligible at each quarterly boundary** for their owner. No age minimums, no countdown display, no auto-expiry. The quarterly email is the sole decision mechanism.

*The revocation path preserves audit rows (append-only). `last_reviewed_at` stamps when the owner last made a decision on a grey contact.*

### Blocked State

Revoked and denied (blocked) merge into a single **Blocked** state with one red badge. There is no distinct "Revoked" badge anywhere in the UI. Both revoked grants (owner-initiated revocation) and denied requests (denial) render as `Blocked` in the contact list. The database retains the `status` distinction (`'revoked'` vs `'denied'`) for audit purposes, but the UI treats them identically.

*Transaction-based and event-based durations were considered and cut during refinement to keep the model minimal.*

### Communication Firewall (Vision — Unbuilt)

The communication firewall is the product's defensible core but remains **unbuilt**. It is preserved here as a design target:

The app sits between the world and the user's devices. Unauthorized contacts are filtered **silently** — no disruption, no unknown numbers ringing.

**Intended flow (phone/email):**
1. Caller initiates contact → Firewall intercepts (no ring, no delivery).
2. Caller is prompted (IVR for phone, auto-reply for email) to state name, title, and reason.
3. Voicemail/message recorded.
4. User receives a single, non-disruptive notification after the attempt.
5. User decides: **Grant Access**, **Deny**, or **Listen to Voicemail**.
6. **Grant** → sets duration/type; future calls go through normally.
7. **Deny** → silent. No message to caller. No notification. Caller never knows they were filtered.
8. **Silent Block (Hounding)** → if a caller persists after denial, future calls are dropped silently.

**Entry points for unauthorized contacts:**
- QR code scan → request access → user approves → firewall grants access.
- "Request access" button on the card.
- Manual add to the allow list.

This feature is **not implemented**. The `firewall_logs` table was never created. The inbox/review flow (request → approve/deny) exists as a lightweight approximation.

### Request Flow Design

The public profile is the contact entry point — a **friend-request model**.

- The reaching-out person must **provide a reason** when requesting access.
- The owner gets to see the requester's bio before deciding.
- **Social-proof links attach by intent:**
  - Friendship requests → link the requester's Facebook/Instagram
  - Work requests → link the requester's LinkedIn
- The owner reviews the request (with bio + social proof) and decides: grant or deny.
- Denials land in the junk view, never greyed inline.

## Standing Captain Rulings (Behavioral Constraints)

The following rulings were established during development and are preserved as binding constraints:

| Ruling | Constraint |
|---|---|
| User decides, app enforces | The system never overrides user preference. No auto-approvals. |
| Context layer | **Bookshelved** — moved to Deferred section below. |
| Denials live in the junk view | Denied contacts go to a separate `/owner/{token}/junk` view — never greyed out inline. |
| Tests never write the prod DB | All tests use tmp_db fixtures. The live `contacts.db` is never modified by the test suite. Hermeticity is verified by a row-sha digest. |
| `merge_all` / `merge_and_dedup` never called | These scripts `DROP TABLE contacts`. They are dead ends. Never executed. |
| `grant_logs` is append-only | The audit log table is never purged. Rows are permanent — the "alibi" convention. |
| No revoke cascade | Revoking a grant marks only that grant as `'revoked'` and stamps `revoked_at`. Audit rows and scan_events are left alone. |
| Scan events stay IP-less | `scan_events` records `profile_handle`, `scan_at`, and optional `viewer_email` — no IP address or user-agent tracking. |
| Standing posture | **Personal-local now, public deployment deferred** — this is a standing decision. |
| Bio only for anonymous | Anonymous visitors see the profile bio only; all fields and cards require a grant. Supersedes the Work-card public default. |
| Photo originals | **Kept** — originals are kept after the 512-square encode. Spec-level ruling; code follow-up pending (current implementation discards them). |
| Contact list shows all live contacts | The contact list view shows all contacts from `contacts.db` (1,920+), not just whitelist-approved ones. |
| Bio cap | **2,000 confirmed** — 2,000 character cap confirmed for now. |

| Seed default cards cover all owners | `seed_default_cards()` now seeds Work (email fields) and Personal (phone fields) cards for every profile, not just the default owner. |

## Implementation Status Map (as of commit c0345a4)

### Contacts Pipeline (Phase 0) — ✅ Complete

| Component | Status | Files |
|---|---|---|
| Phone normalization (E.164) | ✅ Done | `phone_renorm.py`, `normalizer.py` |
| Junk triage | ✅ Done | `cleanup.py`, `scripts/triage.py` |
| Canonical profile export | ✅ Done | `scripts/export_canonical.py` |
| Contacts store | ✅ Done | `store.py` |
| Source fetchers (Gmail, Outlook, VCF, Facebook) | ✅ Done | `fetcher.py`, `scripts/fetch_*.py` |
| Deduplicator | ✅ Done | `deduplicator.py` |

### WhiteList Service (Phases 1–5) — ✅ Complete through P5

| Phase | Component | Status | Files |
|---|---|---|---|
| **P1** | Schema, seed, QR, tiered cards, tokens, request→approve loop, verify loop | ✅ Done | `whitelist_db.py`, `wl_tokens.py`, `wl_env.py`, `app.py`, `scripts/seed_demo.py`, `scripts/notify.py`, 6 templates, 8 test files |
| **P2** | Owner dashboard (approve list), aliases, UI polish | ✅ Done | Extended `app.py`, `templates/owner_dashboard.html`, `templates/contacts.html`, `test_owner_dashboard.py`, `test_aliases.py` |
| **P3** | Revocation, audit logs, context registry, scan analytics | ✅ Done | Extended `whitelist_db.py`, `test_p3_revocation.py`, `test_p3_logs.py`, `test_p3_contexts.py`, `test_p3_scans.py` |
| **Refactor** | Shared helpers, orchestrator, staleness extraction | ✅ Done | `whitelist_db.py` (R1–R4), `app.py` (`is_verified_stale`), `test_p3_refactor.py` |
| **P4** | Category bulk operations, context routes | ✅ Done | Extended `app.py`, `test_p4_categories_bulk.py` |
| **P5** | Cards schema/CRUD, quarter expiry, contact list, merge wiring, quarterly review email | ✅ Done | Extended `whitelist_db.py`, `app.py`, `templates/contacts.html`, `templates/junk.html`, `templates/my_profile.html`, `templates/card_preview.html`, `test_p5_*.py` |

### Unbuilt Features

| Feature | Status | Notes |
|---|---|---|
| QR code generation (print-ready PNG) | ✅ Built | `scripts/seed_demo.py` generates QRs |
| Firewall / voicemail interception | ❌ Unbuilt | Preserved as vision in § above |
| Social verification (Discord, etc.) | ❌ Unbuilt | Manual entry + API verification was the MVP plan |
| Google Contacts write-back | ❌ Unbuilt | OAuth scope granted; E2E verified; not wired into approvals |
| Graph adapter (Microsoft) | ❌ Unbuilt | Personal MS account read only; Walther tenant off-limits |
| Browser extension | ❌ Unbuilt | Thin once hosted API exists |
| Social media integration | ❌ Unbuilt | Phase 3 plan: full OAuth for real-time sync |
| Deploy / hosting | ❌ Unbuilt | Render free tier, personal account, custom domain + TLS |

### Deferred (Bookshelf)

| Feature | Status | Notes |
|---|---|---|
| Book Me (calendar availability) | ❌ Deferred | Explicitly not MVP. Intended as Cal.com embed or Google Calendar API. |
| GUI evaluation pass | ❌ Deferred | GUI evaluation before QR generation; verification-loop testing deferred until after QR. |
| Context layer (category UI) | ❌ Removed 2026-09-12 | Context `<select>` eliminated from all templates. DB columns (`grant_contexts`, `context` on `access_grants`) and routes (`/categorize`, `/context`) remain dormant but functional. See git history for the cut commit. |

### Test Suite

- **302 tests** pass (3 fail due to missing canonical JSON path in detached HEAD — not a code issue).
- 36 test files across 5 phases + audit regressions.
- Baseline: 42 normalizer tests; whitelist adds 260+ tests.
- Hermeticity verified: `contacts.db` sha256 identical before/after full suite.

## Roadmap: Phases 0–6

| Phase | What | Effort | Status |
|---|---|---|---|
| **0** | Personal repo cleanup (junk filter, E.164 phone normalization, canonical profile) | Weekend | ✅ Done |
| **1** | MVP web app: profile + tiers + QR + verify loop | ~1 week | ✅ Done |
| **2** | Approve list UI + aliases + channel integration | 1–2 weeks | ✅ Done |
| **3** | Revocation + audit logs + scan analytics + context categories | ~1 week | ✅ Done |
| **4** | Bulk operations + category routes + polish | Short | ✅ Done |
| **5** | Contact list (replaces dashboard) + cards + quarter expiry + merge wiring + quarterly review | ~1 week | ✅ Done |
| **6** | Browser extension (hover Gmail → "in registry? pull card") | ~2 weeks | ❌ Not started |

> **Note:** Phases 4 and 5 were merged into the P4/P5 development sessions. The original roadmap from the founding spec (contact-registry-mvp.md) listed 7 phases (0–6); P5 subsumed what was originally planned as Phase 4 (Google Contacts write + Graph adapter) into later work.
>
> **Build order note:** GUI evaluation pass first, then QR generation; verification-loop testing deferred until after QR.

## Open Decisions & Current Defaults

| Decision | State | Notes |
|---|---|---|
| Public card scope | **Resolved** | Anonymous sees bio only; all fields/cards require grant. Supersedes Work-card public default. |
| Standing posture | **Resolved** | Personal-local now; public deployment deferred — standing decision. |
| Photo originals | **Resolved** | Kept after 512-square encode; code follow-up pending (current impl discards). |
| Bio length cap | **Resolved** | 2,000 characters confirmed for now. |
| Context layer | **Resolved** | Bookshelved; moved to Deferred section below. |
| Seed default cards | **All owners** | `seed_default_cards()` seeds Work + Personal for every profile. |
| Revocation cascade | **None** | Revoking a grant doesn't cascade to audit rows or scan_events. |
| Scan event IP tracking | **Disabled** | Privacy default — no IP or user-agent stored. |
| `grant_logs` purging | **Never** | Append-only alibi convention. |
| Denials display | **Junk view only** | Denied contacts appear in `/owner/{token}/junk`, never greyed inline. |
| Domain / BASE_URL | `https://whitelist.app` | Placeholder; set via `.env` at deploy time. |
| Hosting | Render free tier, personal account | Never Walther-branded. |
| Email delivery | Gmail API (not SMTP) | `notify.py --apply` exits 1 without SMTP creds; production uses Gmail OAuth. |

## Build Process

The relmgr project follows a **two-worker, one-auditor** development workflow:

1. **Jemma authors** the handoff spec — a detailed, TDD-first task document that defines the scope, schema, routes, tests, acceptance criteria, and guardrails.
2. **QWEN36 implements** the work — writing tests first (RED), then minimal code (GREEN), refactoring when needed. All work is files-on-disk only (no commits). TDD mandate: RED → GREEN → REFACTOR per task.
3. **Jemma reviews** (audits) — runs the full suite, verifies hermeticity, finds bugs, fixes them with regression tests, then hands off to QWEN36 for the next phase.

This cycle repeats: Jemma writes the next handoff → QWEN36 implements → Jemma audits → repeat.

**Key conventions:**
- Flat module imports (no package-relative imports).
- Every new connection replicates `wl_connect()`'s `PRAGMA journal_mode=WAL` + `foreign_keys=ON`.
- `_log_action()` commit ordering is load-bearing: state change + audit row on ONE commit.
- `GLOB '[0-9]*Z'` guard on all expiry comparisons — the only thing preventing legacy `'90d'` rows from leaking access.
- Tests use tmp_db fixtures; never touch the real `contacts.db`.
- No git commits during development — files on disk only. Commits land later via PR.

## Appendix: File Index

### Core Application
| File | Purpose |
|---|---|
| `app.py` | FastAPI routes: profile card, request form, admin review, owner dashboard, contact list, junk, my profile, card preview, verify |
| `whitelist_db.py` | DB layer: connect, init, seed, tiers, grants, aliases, cards, quarters, revocation, logs, contexts, scans, contacts merge |
| `wl_tokens.py` | HMAC-SHA256 token generation/consumption (timing-safe) |
| `wl_env.py` | `get_secret()` — reads env first, then `.env` KEY=VALUE fallback |
| `notify.py` | Outbound email: requests, verify, owner-link, quarterly review |
| `store.py` | Contacts persistence (upsert, search, dedup joins) |
| `normalizer.py` | Name/phone/email normalization |
| `deduplicator.py` | Contact deduplication logic |
| `fetcher.py` | Source fetchers (Gmail, Outlook, VCF) |
| `config.py` | Configuration |
| `cli.py` | CLI entry point (sync, list, dedup, export) |

### Scripts
| File | Purpose |
|---|---|
| `scripts/seed_demo.py` | CLI: `--dry-run` / `--apply`; backs up DB, seeds profiles, generates QR PNGs |
| `scripts/notify.py` | CLI: `--what verify|requests|owner-link|review`; dry-run or SMTP send |
| `scripts/fetch_gmail.py` | Gmail contacts fetch |
| `scripts/fetch_outlook_csv.py` | Outlook CSV import |
| `scripts/fetch_vcf.py` | vCard import |
| `scripts/fetch_facebook.py` | Facebook contacts fetch |
| `scripts/merge_all.py` | ⚠️ DANGEROUS: `DROP TABLE contacts` — never run |
| `scripts/merge_and_dedup.py` | ⚠️ DANGEROUS: `DROP TABLE contacts` — never run |

### Templates (12 files)
`base.html`, `profile.html`, `request_form.html`, `request_success.html`, `admin_review.html`, `admin_decision.html`, `verify_success.html`, `owner_dashboard.html`, `contacts.html`, `contact_list.html`, `junk.html`, `my_profile.html`, `card_preview.html`

### Test Files (36 files)
`test_normalizer.py`, `test_whitelist_schema.py`, `test_seed.py`, `test_seed_demo.py`, `test_tiers.py`, `test_tokens.py`, `test_request_flow.py`, `test_verify.py`, `test_refactor_fixes.py`, `test_owner_dashboard.py`, `test_aliases.py`, `test_p3_*.py` (5 files), `test_p4_categories_bulk.py`, `test_p5_*.py` (7 files), `test_q36_audit.py`, `test_jemma_review.py`, `test_q38_review_fixes.py`, `test_contact_list.py`, `test_context_removed.py`, `test_my_profile.py`, `test_owner_self_view.py`, `test_public_cards.py`, `test_tabs.py`, `test_review_tabs_fixes.py`
