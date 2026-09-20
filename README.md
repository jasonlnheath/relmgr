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
