FROM python:3.12-slim

WORKDIR /app

# Install system deps (sqlite dev headers are bundled in python image)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py cli.py config.py deduplicator.py fetcher.py mailer.py \
     normalizer.py notify.py store.py whitelist_db.py wl_env.py wl_tokens.py \
     web_support.py routes_auth.py routes_public.py routes_share.py \
     routes_review.py routes_dashboard.py routes_profile.py routes_editor.py \
     routes_media.py routes_decisions.py ./
COPY templates/ ./templates/
COPY scripts/ ./scripts/

EXPOSE 8099

# Database defaults to contacts.db in the working directory;
# set RELMGR_DB_PATH to override.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8099"]
