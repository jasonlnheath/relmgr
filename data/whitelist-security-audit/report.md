# WhiteList security audit — pre-public-beta

**Branch:** `fm/whitelist-security-audit` (based on `origin/fm/whitelist-ux-pass-4b` @ 3de44bd, continues PR 22)
**Date:** 2026-09-25
**Method:** black-box adversarial probing of a live instance (local scratch instance of the PR-branch code on :8123, plus non-destructive + self-account probes against the captain's live copy on 127.0.0.1:8099) combined with full source review (`app.py`, `whitelist_db.py`, templates, `wl_tokens.py`, `mailer.py`, `scripts/`). Every finding below has an executed exploit unless marked otherwise. Regression tests: `tests/test_security_audit.py` (17 tests) + updated `tests/test_owner_self_view.py`, `tests/test_public_cards.py`, `tests/test_ux_pass1.py`. Full suite: **648 passed**.

---

## Findings summary

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| S1 | **Critical** | Knowing an owner's email = full account takeover (`?e=` minted a 365-day owner dashboard token + granted tier) | **Fixed + live-confirmed** |
| S2 | **High** | `/owner/{token}/quarter/*` missing grant-ownership check → cross-account grant manipulation | **Fixed + locally exploited** |
| S3 | **Medium-High** | `/photos/{pid}/{cid}` served any card's photo unauthenticated, enumerable by sequential IDs | **Fixed + live-confirmed** |
| S4 | **Medium** | Legacy-format token on `/owner/{t}/bio-visibility` flipped the FIRST profile's bio visibility | **Fixed** |
| S5 | **Medium** | Duplicate connection-request POSTs re-pushed the owner's email every time (free spam vector); no rate limiting on any public POST | **Fixed** (per-IP limiter + email dedupe) |
| S6 | **Medium** | No request body cap; no pixel cap before image decode (decompression-bomb DoS) | **Fixed** |
| S7 | **Medium** | No `Referrer-Policy` (capability tokens in /owner/ URLs leak via Referer), no nosniff/framing headers; session cookie missing `Secure` on https | **Fixed** |
| S8 | **Low** | vCard export could smuggle a bare CR past the escaper | **Fixed** |
| S9 | **Low** | requirements.txt floors allow known-vulnerable resolutions (python-multipart CVE-2024-24762, Pillow <10.2 decoder CVEs, jinja2 <3.1.4) | **Floors raised** |
| D1–D6 | Info | Accepted-by-design / documented residual risks (see bottom) | Documented |

---

## S1 — CRITICAL: owner email = full account takeover

**Where:** `app.py::profile_page` (old `viewer_is_owner` check) + `whitelist_db.effective_tier` own-email branch.

**The hole:** `/p/{handle}?e=<email>` compared `e` against the profile's own email fields (case-insensitive, ANY visibility — including the private signup email). On match the page (a) rendered a **`← Back to My Profile` link containing a freshly minted 365-day `owner_dashboard` token**, and (b) lifted the viewer to `granted` tier (public+granted+private fields). The owner's signup email is not a secret: it's printed on business cards, lives in other breaches, is guessable.

**Exploit (live server 127.0.0.1:8099, self-account so no victim data touched):**

```
signup  -> handle=sec-audit-77e85d, email=sec-audit-bot-77e85d@example.com   [303]
GET /p/sec-audit-77e85d?e=sec-audit-bot-77e85d@example.com                   [200]
  page contains: href="/owner/MTE4fDE4MjE4Nzc1Nzc.20489290b9a7.../profile"
                 (payload expiry 1821877577 ≈ 2027-09 → 365-day token)
GET /owner/MTE4fDE4MjE4Nzc1Nzc.2048...                                      [200]
  → full dashboard renders for the anonymous attacker session
```

Local scratch instance additionally proved the private-field half: `/p/alice?e=alice@victim.example` rendered a `private`-visibility phone (`555-000-1234`) that anonymous view hides.

**Fix:**
- `profile_page`: owner detection is now AUTH-ONLY — a signed `owner_dashboard` token in `?ot=` (validated: purpose + integer payload + profile match) or the session cookie. `?e=` can no longer mint the owner token or lift the tier; the back-link token is the standard 7-day mint.
- `effective_tier`: own-email branch removed entirely (email knowledge never grants tier). Granted contacts keep tier via the admitted-grant predicate, unchanged.
- `my_profile.html` "View profile" links now carry `profile_view_url` (`/p/{handle}?ot=<signed 7d token>`) instead of the raw email, so the legit owner flow (including magic-link, no-cookie sessions) still works.

**Regression tests:** `test_s1_*` (3), updated `test_owner_self_view.py` (5), `test_public_cards.py::test_owner_self_view_shows_all_cards_photos_bio`, `test_ux_pass1.py` back-link tests.

## S2 — HIGH: quarter routes cross-owner IDOR

**Where:** `app.py::quarter_make_permanent / quarter_revoke / quarter_punt` — they authenticated the token but then loaded ANY `grant_id` from the form without `_verify_grant_ownership` (every sibling route — `/decision`, `/revoke`, `/bulk`, `/approve`, `/access` — checks it; these three were missed).

**Exploit (local scratch instance):** mallory (attacker account, own valid token) vs alice (victim):
```
alice approves mallory's request grant          -> status=granted, expires=quarter-end
POST /owner/{MALLORY_token}/quarter/punt        -> 200, grant.quarter_status='punted'
POST /owner/{MALLORY_token}/quarter/make_permanent -> 200, grant.expires_at=NULL
POST /owner/{MALLORY_token}/quarter/revoke      -> 200, grant.status='revoked'
```
Any registered user could punt / make permanent / revoke ANY other account's grants. (Pre-approval, the same probe returned 409 "cannot punt a 'pending' grant" — a state-disclosure oracle on foreign grants.)

**Fix:** all three routes now use `_resolve_owner` + `_verify_grant_ownership`, returning 404 for foreign grants, exactly like `/owner/{token}/decision`.

**Regression tests:** `test_s2_quarter_routes_reject_foreign_grants` (asserts 404 AND no state change), `test_s2_quarter_routes_still_work_for_own_grants`.

## S3 — MEDIUM-HIGH: unauthenticated, enumerable photo access

**Where:** `app.py::serve_photo / serve_hs_photo` — no auth, no visibility check; files are named `{profile_id}_{card_id}.jpg` (both sequential).

**Exploit (live server, read-only GETs):** `GET /photos/1/1` → `200 image/jpeg` for a stranger. Any card's photo — including cards never exposed on any public surface (e.g. a "Secret Card" with only private fields, invisible on the anonymous profile page and absent from every share bundle) — was world-readable by enumeration across ALL accounts. Local PoC: `/photos/1/3` (non-default card) returned `200` anonymously before the fix.

**Fix:** new `_photo_allowed` predicate (one helper shared by both slots). Anonymous access is allowed exactly when the card is **publicly visible**: it is the owner's default card (what the anonymous `/p` page renders — `_CARD_ORDER_SQL` first) or it sits in a **non-expired share bundle** (what `/s/{id}` renders to anonymous openers). Otherwise the viewer must authenticate as the card owner's account: signed `?t=` owner_dashboard token (owner-surface templates now append `?t={{ token }}` to their `<img>`s) or session cookie; curated-stub cards resolve via `profiles.owner_id`. Granted contacts keep photo access through `?e=` (same admitted-grant tier the page itself applies); `profile.html`'s granted-view card photos now carry `?e=`.

**Regression tests:** `test_s3_*` (4): non-default anon 404 / default 200 / foreign token 404 / owner `?t=` 200 / session 200 / live-bundle 200 / expired-bundle 404 / granted `?e=` 200 / stranger `?e=` 404.

## S4 — MEDIUM: legacy-token fallback flipped profile #1

**Where:** `app.py::owner_bio_visibility` — non-integer (pre-migration) token payload fell back to `SELECT * FROM profiles ORDER BY id LIMIT 1` and toggled THAT profile's bio visibility. Every other route retired this fallback (ruling 2026-09-20 option A); this one was missed.

**Exploit (local):** a validly-signed legacy-format token (`make_token(secret, "owner_dashboard", "legacy-owner")`) POSTed to `/owner/{t}/bio-visibility` flipped profile #1's `bio_visibility` public→private. Reachable only with a pre-migration signed token, hence medium not high.

**Fix:** route now uses `_resolve_owner`; legacy payloads raise `LegacyOwnerLinkRetired` → redirect to `/signin`, no data access.

**Regression tests:** `test_s4_*` (2).

## S5 — MEDIUM: request spam + duplicate owner-email pushes; no rate limiting

**Where:** `app.py::submit_request` + no limiter anywhere.

**Exploit (local):** 3 identical `POST /p/{handle}/request` → in-app notification deduped (by design) **but the email-push BackgroundTask fired on every POST** — an anonymous attacker could mail-bomb any owner's inbox at will. `/p/{handle}/forward` similar; `/signin`/`/forgot-password` had no brute-force throttling either.

**Fix:**
- `find_admitting_grant_id` (new, shares create_grant's dedupe predicate) lets the route distinguish new requests from deduped re-POSTs; only genuinely new requests enqueue the owner email.
- Per-IP sliding-window limiter in the security middleware: `POST /p/*/request` + `/p/*/forward` 10/min; `/signin`, `/signup`, `/forgot-password` 30/min. Single-process by design (uvicorn); `WHITELIST_RATELIMIT_DISABLED=1` switches it off for load tools.

**Regression tests:** `test_s5_duplicate_requests_push_email_once`, `test_s7_rate_limit_*` (2).

## S6 — MEDIUM: body/decompression-bomb DoS

**Where:** photo upload read the whole body before the 10 MB check; `_encode_square_jpeg` had no explicit pixel cap (PIL's default `MAX_IMAGE_PIXELS` ≈178 MP still allows ~700 MB+ decode per request); every other form route accepted unbounded bodies.

**Fix:** global 16 MB `Content-Length` rejection in the middleware (413); the photo route rejects >12 MB before form parsing; `_encode_square_jpeg` enforces a 40 MP cap from the (lazily-parsed) header BEFORE any decode.

**Regression tests:** `test_s6_oversized_pixel_dimensions_rejected` (hand-crafted 100 MP IHDR-only PNG → 400), `test_s6_request_body_cap` (17 MB form → 413).

## S7 — MEDIUM: missing baseline headers + cookie flag

**Evidence (live + local):** responses carried no `Referrer-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, or `Permissions-Policy`. Owner dashboard URLs are capability tokens in the path — any outbound navigation from an `/owner/{token}` page could leak the token via `Referer`. Session cookie had no `Secure` attribute.

**Fix:** middleware sets `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Permissions-Policy: camera=(), microphone=(), geolocation=()` on every response; `set_cookie` adds `secure` when the request scheme is https (http localhost unaffected). CSP deliberately NOT added: templates use inline scripts + the Tailwind CDN, so a script CSP would need `unsafe-inline` and provide no real protection — flagged as follow-up work (vendored Tailwind + externalized JS first).

**Regression tests:** `test_s7_security_headers_present`.

## S8 — LOW: vCard CR smuggling

`_vcf_escape` escaped `\r\n` and `\n` but passed a bare `\r` through; lenient vCard parsers could treat injected text as new properties. Now stripped. Test: `test_vcf_escape_strips_bare_cr`.

## S9 — LOW: dependency floors

Fresh installs already resolve to current versions (Pillow 12.3, python-multipart 0.0.32 — verified in the audit venv), but the floors permitted vulnerable resolutions on stale environments. Raised: `python-multipart>=0.0.7` (CVE-2024-24762 multipart-boundary DoS), `Pillow>=10.2` (multiple fixed decoder CVEs), `jinja2>=3.1.4` (CVE-2024-22195/34064 class). No direct-vuln usage found in `vobject`, `qrcode`, `msal`, `httpx` at current floors.

---

## Verified-not-vulnerable (probed or reviewed, no finding)

- **Share-bundle enumeration:** `share_bundles.id` is `secrets.token_urlsafe(9)` (72 bits); random guesses 404 (live-tested). Expired bundles 404 for everyone; expired-grant leakage is structurally impossible on `/s/` (hardcoded anonymous tier, F4 ruling) and the VCF route applies the same expiry + `cards_for_share_bundle(conn, bundle, "anonymous")` filter.
- **VCF export field leakage:** built exclusively from `visible_fields` (tier-filtered), deduped by field id, escaped.
- **XSS:** Jinja autoescape on for every `.html` template; no `|safe`, no `Markup`, no reflected raw HTML in any route. File uploads re-encode to JPEG (SVG/polyglot impossible); photos served `image/jpeg` + nosniff.
- **Path traversal:** photo filenames are built from int path params only; uploads write into `uploads/` with int-derived names.
- **CSRF:** all state-changing routes are capability-token scoped in the URL (`/owner/{token}/...` — attacker can't know the token); cookie flows are `SameSite=Lax` (blocks cross-site POST cookie carriage in modern browsers).
- **Auth crypto:** pbkdf2-hmac-sha256 260k rounds, per-user salt, timing-safe compares; dummy-burn on unknown email (no enumeration oracle); password reset tokens are hashed at rest, single-use, 30-min TTL, with pre-validation so a bad length doesn't burn the link; forgot-password responses are existence-blind with timing parity.
- **Session fixation:** the session cookie is only ever minted server-side after successful auth; nothing accepts a session from the URL.
- **Cross-account card/field access:** `save_card_editor`, `set_card_fields`, `set_grant_cards`, `filter_owned_cards` all enforce ownership (fail-closed); editor routes 404 foreign cards.
- **Quarantine/silence rule:** blacklisted senders get the indistinguishable success page (cosmetic uuid4 id), no notification/email/ping anywhere.
- **Committed secrets:** `.env` ignored & absent from history; only `.env.example` tracked; no hardcoded credentials in tracked code.
- **SSRF:** `fetcher.py` only calls fixed Google/Microsoft endpoints from CLI scripts, not HTTP routes.

## Residual risks (documented, accepted for beta)

- **D1 — `?e=` is a bearer credential for granted contacts.** Anyone who knows a granted contact's email sees the granted tier (by design — it's the tracking model). Emails leak; the F4 share-link ruling already contains the blast radius (bundles are anonymous-tier). Worth revisiting before wide beta.
- **D2 — Stateless session cookies** can't be revoked server-side; a password reset doesn't kill existing 7-day cookies. Acceptable at this scale; a `pwd_epoch` stamp in the cookie would close it.
- **D3 — Capability tokens in URLs** (the product's magic-link model) persist in browser history/logs; `Referrer-Policy: no-referrer` now blocks the Referer vector.
- **D4 — Tailwind CDN + Google Fonts** are runtime third-party dependencies (availability/supply-chain); vendoring is follow-up work and a prerequisite for a meaningful CSP.
- **D5 — `record_scan` is unbounded** (anyone can inflate scan rows); consider a cap per profile/day.
- **D6 — Signin throttling is 30/min/IP**; combined with 260k-round pbkdf2 this is slow-budget brute force only, but per-account lockout would be stronger.
- `/qr/share/{bundle_id}` renders a QR even for expired bundles (links to the expired page — harmless inconsistency).

## Live-server artifacts from this audit

One clearly-marked account on the live 8099 DB: handle `sec-audit-77e85d`, email `sec-audit-bot-77e85d@example.com` (used for the S1 self-PoC). No other writes were made to live data; no victim accounts were touched. It can be deleted outright (`profiles` row; signup created no cards).

## Proof-of-fix (re-run of the exploit battery against the fixed build)

```
P1  ?e= owner email: owner back-link token found: False           (was True)
P1b private phone via ?e=: False                                   (was True)
P2  mallory punt/make_permanent/revoke on alice's grant: 404 x3,
    grant untouched (status=granted, quarter_status=active)        (was 200 x3, all applied)
P3  /photos/1/3 non-default card anonymously: 404                  (was 200)
    /photos/1/1 default card: 200                                  (still 200)
P4  legacy token bio-visibility: first profile unchanged           (was flipped)
P5  referrer-policy: no-referrer | x-content-type-options: nosniff | x-frame-options: DENY
P6  duplicate request POSTs: single notification row, single email push
```
