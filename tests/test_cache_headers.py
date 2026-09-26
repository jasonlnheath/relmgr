"""Cache discipline (regression-verify pass, 2026-09-26).

Two 'fixed on the server, still broken on the captain's phone' rounds
were stale mobile caches: HTML carried no Cache-Control (Safari kept
old pages), and the Tailwind Play CDN URL was unversioned. Tests pin:
- Every HTML response carries no-cache (phones always revalidate).
- /static carries immutable long-cache AND every template reference to
  it is versioned (?v=asset_v) so content changes change the URL.
- /photos and /qr (same-URL mutable images) revalidate.
"""
import os
import re
from pathlib import Path

os.environ["WHITELIST_SECRET"] = "test-secret"

import whitelist_db
from fastapi.testclient import TestClient
from app import create_app, _static_version

_TEMPLATES = Path(__file__).parent.parent / "templates"


def _app(tmp_path: Path):
    db = tmp_path / "test.db"
    conn = whitelist_db.wl_connect(db)
    whitelist_db.wl_init(conn)
    conn.commit()
    conn.close()
    app = create_app(db)
    return TestClient(app)


def test_html_responses_are_no_cache(tmp_path):
    client = _app(tmp_path)
    for url in ("/signin", "/signup", "/forgot-password"):
        r = client.get(url)
        assert r.status_code == 200, url
        cc = r.headers.get("cache-control", "")
        assert "no-cache" in cc, f"{url}: {cc!r}"


def test_static_is_immutable_long_cache(tmp_path):
    client = _app(tmp_path)
    r = client.get("/static/scroll-mark.png")
    assert r.status_code == 200
    cc = r.headers.get("cache-control", "")
    assert "immutable" in cc and "max-age=31536000" in cc, cc


def test_mutable_images_revalidate(tmp_path):
    client = _app(tmp_path)
    r = client.get("/qr/somebody")
    assert r.status_code in (200, 404)
    cc = r.headers.get("cache-control", "")
    assert "no-cache" in cc, cc


def test_every_static_reference_is_versioned():
    """No template may reference /static/ without ?v= — an unversioned
    reference would freeze a changed asset behind immutable caching."""
    offenders = []
    for tpl in _TEMPLATES.glob("*.html"):
        for m in re.finditer(r'src="/static/[^"]+"|href="/static/[^"]+"', tpl.read_text()):
            if "?v=" not in m.group(0):
                offenders.append(f"{tpl.name}: {m.group(0)}")
    assert not offenders, offenders


def test_static_version_changes_with_file():
    import app as app_mod
    f2 = app_mod._STATIC_DIR / "__probe__.png"
    try:
        f2.write_bytes(b"one")
        v1 = _static_version("__probe__.png")
        f2.write_bytes(b"two-longer")
        v2 = _static_version("__probe__.png")
        assert v1 != "0" and v1 != v2
    finally:
        f2.unlink(missing_ok=True)
