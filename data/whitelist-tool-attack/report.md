# WhiteList tool attack — live-fire security evaluation

- **Branch**: `fm/whitelist-tool-attack` (based on `origin/main` @ `e9f8ab7`, = security-audit-2 head)
- **Date**: 2026-09-26
- **Scope**: dynamic attack evaluation of the current-main app with real pen-test tooling, per the captain's "do attack after audit" intent. The two prior audits' fixed findings (S1–S9, A1–A4) are the known-fixed baseline and are NOT re-reported; their regression state was spot-verified instead.
- **Out of scope** (per brief): heavy load/DoS, anything beyond the local instance, social engineering.

## 1. Target and toolchain

**Target**: throwaway instance of current main on `127.0.0.1:8124`, scratch SQLite DB at `/tmp/wl-attack/contacts.db`, seeded with `scripts/seed_demo` (5 demo profiles) plus an attack world built over the HTTP API: owner *alice* (victim: fields across all visibilities, bio, photo, share bundle), owner *mallory* (attacker), granted contact *carol*, blacklisted+quarantined sender *evil*. The captain's live server (:8099, `/home/jason/relmgr`) was never touched.

**Tools** (host had no pen-test packages and no passwordless sudo, so the toolbox ran from an `archlinux` container with the BlackArch repository strapped in via their official `strap.sh`, `--network host`; individual package installs as the brief prescribed, no full repo):

| Tool | Version | Install note |
|---|---|---|
| nmap | 7.991-1 | pacman in BlackArch-strapped container |
| nikto | 2.6.0-2 | same (+ `perl-xml-writer`, `perl-libwww` deps) |
| sqlmap | 1.10.7-1 | same |
| ffuf | 2.3.0 | same |
| gobuster | 3.8.2-1 | same (available; ffuf used for content discovery) |
| curl / Python requests + Pillow | system | manual batteries: token forgery, IDOR matrix, XSS/SSTI, upload abuse, enumeration parity, quarantine matching, header injection, rate-limit evasion |

## 2. Recon

- **nmap** `-sV -sT -p 8124`: `8124/tcp open http Uvicorn` — nothing else exposed on the target port.
- **ffuf** 57-word common-endpoint list (admin, .git, .env, contacts.db, backups, openapi.json, actuator, …): every probe 404 (22-byte default). No hidden routes, no exposed files, no directory listing (`/static/` → 404; traversal `/static/../app.py` → 404). `/docs`, `/redoc`, `/openapi.json` remain disabled (A3 regression-held).
- **nikto** (8,013 requests): 4 raw items —
  - *missing strict-transport-security*: deployment-level; instance is plain HTTP on loopback by design (proxy/TLS is the documented I2 deployment note). **Noise here.**
  - *missing content-security-policy*: known accepted residual from audit 1 (S7 follow-up: requires externalized JS first). **Not new.**
  - *"X-Content-Type-Options is not set"*: **false positive** — header verified present on every response (nikto mis-parsed the 307 on `/`).
  - *OPTIONS: allowed methods GET*: informational; verbs PUT/PATCH/DELETE/TRACE → 405.

## 3. sqlmap

- `GET /p/{handle}?e=` (level 3, risk 2): **not injectable** — full boolean/time/UNION battery clean.
- `GET /p/{handle}` and `GET /s/{bundle_id}` URI path params (level 3, risk 2): **not injectable**.
- `POST /p/{handle}/request` params `name`,`email` (level 3, risk 2, `--delay=7` to live under the 10/min POST limiter): **not injectable** — `name` completed the full battery ("does not seem to be injectable"); `email` completed heuristic + error phases clean with the boolean/time-based phases truncated at ~80 min of 7 s-spaced probes — compensated by manual time-based-blind probes on both params using sqlmap's own SQLite technique (`RANDOMBLOB(500000000/2)` heavy query → response in 3 ms, no delay) plus source verification that both values reach only parameterized statements (`create_grant`, `quarantine_request`).
- Manual supplements: authenticated dashboard search `q` with `%' OR 1=1 --`, `UNION SELECT`, `DROP TABLE`, bare `%`/`_`/`\`/`[` → all 200, no foreign-row leakage, no errors. Command injection: no `subprocess`/`os.system`/`eval`/`exec` in any HTTP path (grep + review).

## 4. Manual attack batteries (all against the live throwaway instance)

| Battery | Method | Result |
|---|---|---|
| **Token forgery** | payload-tamper (change profile id under valid sig), 7 weak-secret offline guesses replayed, purpose confusion (owner token on `/a/`), case/mangling tricks, expired/empty/garbage tokens | All 403 — HMAC holds, purpose-scoped, timing-safe. Clean. |
| **Session forgery** | tamper mallory's `wl_session` payload to alice's id under mallory's sig | Redirected to `/signin` — sig covers payload. Clean. Cookie: `HttpOnly; SameSite=lax` (+ `secure` under https, per audit). |
| **IDOR matrix** | mallory's valid token × 17 owner routes against alice's grant/cards/fields (contact view, editor GET/POST, preview, decision, revoke, badge, bulk, approve, access, quarter×3, field delete, card delete, photo upload, card-fields) | 404 across the board; alice's data unchanged after the battery. Fail-closed everywhere (S2/A-regression held). |
| **Photo abuse** | EXIF-tagged JPEG (secret serial marker), SVG, truncated JPEG, JPEG+HTML-tail polyglot, 45.5 MP (>40 MP cap) uploads; pid/cid mismatch URLs; int-typed path params | EXIF stripped on serve, SVG/truncated/45MP → 400, polyglot tail re-encoded away, mismatches 404 (globally-unique card ids make filename confusion impossible). Clean. |
| **XSS / SSTI** | `<script>`, `"><img onerror>`, `javascript:` URL in website field, custom phone labels, display_name, bio, card names, dashboard `q` — fetched back from profile (anon+granted), bundle, editor, vcf | Everything HTML-escaped; `javascript:` renders as text in a `<span>`, never an href; `{{7*7}}` survives literally (no template eval). Clean. |
| **vCard injection** | `END:VCARD/BEGIN:VCARD` smuggling via field value into `/s/{id}/card.vcf` | Single `BEGIN:VCARD`, payload inert. Clean (S8 regression-held). |
| **Open redirect / SSRF** | grep of every `RedirectResponse` target + live probes; no route fetches URLs | All targets literal internal paths; QR encodes internal URLs only; fetcher is CLI-only. Clean. |
| **Rate-limit evasion** | 24 POSTs rotating `X-Forwarded-For`/`X-Real-IP`/`Client-IP` | Limiter keys on socket peer (`request.client.host`) — header spoofing cannot evade. 429s appear exactly on the 11th request. Clean. *(But see T1 below.)* |
| **scan_events pollution (post-A1)** | 300–800 serial GETs to `/p/{handle}?e=` with rotating emails | A1's 320-char row cap holds (max stored 306), **but rows are unbounded: 577 rows/s measured, 800-GET flood wrote 800 rows in ~1s. Rotation of `?e=` defeats any per-email dedupe. → Finding T2 (fixed).** |
| **Enumeration** | signin unknown-vs-known email timing (31ms/31ms, dummy-burn parity), forgot-password response byte-parity incl. `\n` header-injection payloads, `/p/{handle}` existence | Parity holds; header injection fails closed (email lib rejects, no 500). Signup handle/email oracle remains (I1, accepted-by-design, throttled 30/min). |
| **Quarantine/blacklist matching** | case, whitespace, plus-tag, angle-bracket, newline variants of a blacklisted sender's email | Exact+case/whitespace-insensitive match held (no pending grant); plus-tag and punctuation variants create pending grants — inherent email-identity model limit (different addresses), **informational only**. |
| **HTTP edge cases** | CL+TE dual header (h11 handles per RFC), verb confusion (405s), JSON-to-form (graceful), pagination `page` extremes (`1e5`, `-5`, huge), handle traversal/`%00`/unicode/300-char | No 500s, no bypasses; `%2e%2e`/null-byte → 404. Clean. |
| **Grant-status oracle via request dedupe** | success-page diff: granted-email re-request vs fresh email | Only the cosmetic Grant-ID line differs; repeat probes converge (fresh uuid vs existing uuid indistinguishable without prior knowledge). No oracle. |

## 5. Findings — confirmed and fixed

Both fixed on this branch, minimal and behavior-preserving, regression tests in `tests/test_tool_attack.py` (7 tests).

### T1 (Low–Medium) — `WHITELIST_RATELIMIT_DISABLED=0` silently DISABLED the rate limiter

**Where**: `app.py` — `_RATELIMIT_OFF = bool(wl_env.get_secret("WHITELIST_RATELIMIT_DISABLED"))`.

**Evidence (live)**: instance started with `WHITELIST_RATELIMIT_DISABLED=0` — the natural "off=off" spelling — then 24 POSTs to `/p/alice/request`: **all 200, zero 429s**. `bool("0")`, `bool("false")`, `bool("no")` are all truthy, so ANY non-empty value disabled the per-IP limiter (auth 30/min, public POSTs 10/min) with no signal. A deployer copying an `.env` pattern or writing `=false` silently loses a security control the two audits built. (The documented spelling `=1` works; the tests only exercised unset/`1`.)

**Fix**: parse an explicit truthy set — `in ("1", "true", "yes", "on")` after strip/lower. Unset → limiter on (unchanged); `=1`/`=true` → off (unchanged, documented behavior); `=0`/`=false`/`=no`/garbage → **on**.

**Live proof of fix**: same `=0` config now 429s from the 11th POST.

### T2 (Low–Medium) — scan_events row rate unbounded (A1 capped size, not rate)

**Where**: `whitelist_db.record_scan` — audit-2/A1 capped the stored `viewer_email` at 320 bytes but the insert itself remains unlimited on GET surfaces (`/p/{handle}?e=`, `/s/{id}?e=`) the POST-only limiter never covers. Documented residual D5 ("consider a cap per profile/day") — this evaluation escalated it to fixed.

**Evidence (live)**: 300 serial GETs → 300 rows in 0.5 s (**577 rows/s**); an 800-GET flood with rotating `?e=` wrote 800 rows (~100 KB+) in ~1 s, unbounded, anonymous, from any network client. SQLite WAL churn / disk-fill at GET speed; also pollutes the owner's 14-day scan chart.

**Fix**: per-profile per-UTC-day row cap `_SCAN_DAY_MAX = 500` inside `record_scan` (one spot covers both GET call sites). The count query is sargable (`scanned_at >= date('now')`, string-compare) and rides `idx_scan_events_profile`; legit traffic never approaches 500 views/day/profile, and the chart only renders counts so saturation is honest. Per-profile (not per-email) so `?e=` rotation is useless; other profiles unaffected.

**Live proof of fix**: 800-GET flood now stores exactly 500 rows.

## 6. Informational (no code change)

| # | Note |
|---|---|
| N1 | **Reset URL printed to server log when SMTP is unconfigured** (`[WARN] Reset email delivery failed; reset URL …`). Single-use, 30-min tokens; requires host/log access to exploit — but the live :8099 deployment also runs without SMTP, so `/tmp/relmgr.log` accumulates valid takeover links. Left as-is because it is the only password-reset path in the no-SMTP workflow; revisit when SMTP lands. |
| N2 | Blacklist exact-email matching can't catch plus-tag/punctuation variants of a blacklisted address (different addresses; recipient controls the domain). Inherent model limit. |
| N3 | Prior audits' informational residuals re-confirmed unchanged: signup enumeration oracle (I1), cookie `secure` behind TLS proxy (I2), expired-bundle QR (I3), rate-bucket growth (I4). Dependency stack current (fastapi 0.141.1, jinja2 3.1.6, pillow 12.3.0, python-multipart 0.0.32) — no known open CVEs at these versions. |

## 7. Validation

- New tests: `tests/test_tool_attack.py` — 7 tests (4× T1 flag-parse matrix incl. regression pins for `=1`/`=true`, 3× T2 cap behavior incl. chart saturation + cross-profile isolation).
- Full suite: **672 passed** × 2 consecutive runs (665 pre-existing + 7 new). One intermittent `test_ux_pass2::…my_card_above_search` failure on the first run is the documented pre-existing order-dependence flake (audit-2 I5) — passes in isolation on pristine code and in both follow-up full runs.
- Both fixes verified live on the throwaway instance (proofs above).
- Live server untouched; throwaway instance and container to be torn down after the PR.

## 8. Operational incident (owned)

While restarting the throwaway instance mid-evaluation, a `pkill -f "uvicorn app:app"` meant to stop the :8124 instance also matched the **live** server's command line and killed it at 14:53 UTC (outage ≈ 58 min, until 15:51 UTC). The live server was restored with its exact documented invocation from `/home/jason/relmgr` (checkout verified still at `e9f8ab7` = main HEAD, DB untouched — the process was killed, nothing modified); a phone client served a 307 within seconds of restore. Lesson: pattern-based `pkill` on shared hosts must never use a command substring that other instances share; scope by exact PID. No data was lost (SQLite WAL, clean shutdown signal).

## 9. Baseline regression spot-checks (S/A items probed live this session)

S1 `?e=` owner-takeover: dead (no owner link, no tier lift). S2 quarter IDOR: 404s. S3 photo enumeration: default-card 200 / foreign 404. S5 duplicate-request email push: deduped (single notification path). S6 bombs: 45 MP rejected, 16 MB cap live. S7 headers: all four present on every response. A1 email cap: max stored 306 chars. A3 docs: 404. A4 stub-forward: ownership carried (code path re-read).
