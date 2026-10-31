"""Render a clearly labeled static Cloudflare Pages preview from the FastAPI templates."""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("NORTHCAUSE_DATA", tempfile.mkdtemp(prefix="northcause-pages-preview-"))
os.environ.setdefault("NORTHCAUSE_DB", str(Path(os.environ["NORTHCAUSE_DATA"]) / "preview.sqlite3"))
os.environ.setdefault("NORTHCAUSE_EVIDENCE", str(Path(os.environ["NORTHCAUSE_DATA"]) / "evidence"))
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402
from app.main import app  # noqa: E402

ROUTES = ("/", "/product", "/evidence-loop", "/cli", "/security", "/docs", "/pricing", "/demo", "/contact", "/login")
NOTICE = (
    '<aside class="static-preview-notice" role="status" tabindex="0">'
    'Cloudflare visual preview - interactive workflows run locally on port 8888.'
    '</aside>'
)
SCRIPT = '<script defer src="/static/preview.js"></script>'
STYLE = '<link rel="stylesheet" href="/static/preview.css">'


def main() -> None:
    output = ROOT / "dist"
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    with TestClient(app) as client:
        for route in ROUTES:
            response = client.get(route)
            if response.status_code != 200:
                raise SystemExit(f"Preview render failed: {route} returned {response.status_code}")
            html = response.text.replace("</head>", STYLE + "</head>", 1)
            html = html.replace("<body>", "<body>" + NOTICE, 1)
            html = html.replace("</body>", SCRIPT + "</body>", 1)
            relative = Path("index.html") if route == "/" else Path(route.lstrip("/")) / "index.html"
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(html, encoding="utf-8")
    shutil.copytree(ROOT / "app" / "static", output / "static")
    (output / "static" / "preview.css").write_text(
        ".static-preview-notice{position:relative;z-index:30;padding:9px 16px;text-align:center;background:#eef4ff;color:#274778;border-bottom:1px solid #dbe6fa;font:600 12px/1.4 system-ui,sans-serif}\n",
        encoding="utf-8",
    )
    (output / "static" / "preview.js").write_text(
        "document.addEventListener('submit',function(event){event.preventDefault();var note=document.querySelector('.static-preview-notice');if(note){note.textContent='This is a visual preview. Run the local FastAPI app on port 8888 to use forms and workspace actions.';note.focus();}});\n",
        encoding="utf-8",
    )
    print(f"Built {len(ROUTES)} static preview pages in {output}")


if __name__ == "__main__":
    main()
