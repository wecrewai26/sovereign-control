"""The Control Tower web page (spec §43, §54): static files served by the API at /ui.

The page holds no data of its own. It asks for a user token, keeps it in sessionStorage for
the tab, and calls the same /v1 API as everything else, so every view it shows is
authorized and audited the same way.
"""

from __future__ import annotations

from pathlib import Path

_DIR = Path(__file__).parent

WEB_ASSETS: dict[str, tuple[bytes, str]] = {
    "/ui": ((_DIR / "index.html").read_bytes(), "text/html; charset=utf-8"),
    "/ui/": ((_DIR / "index.html").read_bytes(), "text/html; charset=utf-8"),
    "/ui/app.js": ((_DIR / "app.js").read_bytes(), "text/javascript; charset=utf-8"),
    "/ui/app.css": ((_DIR / "app.css").read_bytes(), "text/css; charset=utf-8"),
}

# Same-origin only, no inline script, no framing: the token in sessionStorage is only
# reachable by the page's own script, which renders data with textContent, never as HTML.
WEB_SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
