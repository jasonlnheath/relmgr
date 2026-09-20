# RelMgr — Relationship Manager

Unified contact layer + CRM for email intelligence.

## Architecture

```
Google Contacts ─┐
Apple/iCloud ────┤
Outlook ─────────┼──→ Aggregator → Normalizer → Deduplicator → SQLite DB
Android ─────────┘
```

## Setup

```bash
cd relmgr
pip install -r requirements.txt
```

## Usage

```bash
# Sync contacts from all enabled sources
python cli.py sync

# List all contacts
python cli.py list

# Check for duplicates
python cli.py dedup

# Export to VCF
python cli.py export -o exports/contacts.vcf
```

## Password reset

`/signin` links to `/forgot-password`: enter your email and a single-use reset
link (valid 30 minutes, one active link per account) is emailed through the
outbound mail layer (`mailer.py`).

## Outbound mail + links (mailer.py)

All email (password resets, connection requests, quarterly digest,
verify/owner-link) resolves its SMTP settings from env vars or `.env`
(never hardcoded, credentials never committed — see `.env.example`):

| Setting | Default | Notes |
| --- | --- | --- |
| `SMTP_HOST` | `smtp.gmail.com` | |
| `SMTP_PORT` | `587` | STARTTLS; `465` switches to implicit SSL |
| `SMTP_USER` | — | required |
| `SMTP_PASS` | — | required; Gmail App Password, never committed |
| `SMTP_FROM` | `jasonlnheath@gmail.com` | 2026-09-20 ruling; switch domains by editing config only |
| `SMTP_REPLY_TO` | — | optional |
| `APP_BASE_URL` | `http://192.168.1.200:8099` | base for reset links, decision views, QR codes; legacy `BASE_URL` still honored |

If email cannot actually deliver from a deployment, the CLI fallback prints
the reset URL directly so first sign-in is never blocked:

```bash
# Prints the single-use /reset-password/<token> URL (no email sent)
python3 scripts/notify.py --what reset --email you@example.com

# Or send it by email once SMTP works
python3 scripts/notify.py --what reset --email you@example.com --apply
```

## Notification center

The signed-in dashboard carries an unread badge; the notification list lives
at `/owner/{token}/notifications`. Connection requests and card forwards each
raise an in-app row (the source of truth) and — when SMTP is configured — an
email push with a 7-day decision link. Quarterly prompts appear once per
quarter when grey contacts are awaiting a decision.

## Docker

Run the whitelist service in a container — same contract as the native service
(`uvicorn app:app --host 0.0.0.0 --port 8099`), but fully self-contained.

```bash
# Build and run (contacts.db mounted from host)
 docker compose up --build
```

The database file lives on the host and is bind-mounted into the container;
rebuilding the image never touches the data.

### Systemd unit (switching from native to container)

Before starting the container service, disable the native venv service to
avoid a port conflict on :8099:

```bash
systemctl --user disable --now whitelist
```

Then create `/etc/systemd/system/relmgr.service`:

```ini
[Unit]
Description=RelMgr Whitelist Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/path/to/relmgr
ExecStart=/usr/bin/docker compose up
Restart=unless-stopped

[Install]
WantedBy=multi-user.target
```

Then:

```bash
systemctl daemon-reload
systemctl enable --now relmgr.service
```

## Configuration

Edit `config.py` to enable/disable data sources:

- **Google**: Uses existing Gmail OAuth token (`~/.hermes/google_token.json`)
- **Apple/iCloud**: Export VCF from iCloud.com → Contacts → Export vCard
- **Outlook**: Requires `OUTLOOK_CLIENT_ID` and `OUTLOOK_TENANT_ID` env vars
- **Android**: Export VCF/CSV from phone's Contacts app → Import/Export

## Data Model

- **contacts** — Unified contact records with all fields normalized
- **contact_sources** — Source tracking (which source each record came from)
- **dedup_log** — Deduplication audit trail

## Integration

RelMgr feeds into the email intelligence pipeline:
1. Fetch contacts → normalize → deduplicate → store in SQLite
2. Onboarding interview builds `context.json` relationship layer
3. Email summarizer/prioritizer uses both raw contact data + relationship context
