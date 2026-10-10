"""Best-effort removal of secrets from free text such as pod logs and event messages.

Logs often carry credentials (connection strings, bearer tokens, `password=...`), and
anything AEGIS shows on screen can end up in screenshots, tickets and evidence. This
catches the common shapes; it is a safety net, not a guarantee.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys (multi-line)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACTED),
    # Authorization headers / bearer tokens
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9\-._~+/]{8,}=*"), r"\1 " + REDACTED),
    # JSON Web Tokens
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), REDACTED),
    # Credentials embedded in URLs: scheme://user:password@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@", re.I), r"\1" + REDACTED + "@"),
    # AWS access key ids
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    # key=value / key: value / "key": "value" for secret-looking keys
    (re.compile(r"(?i)([\"']?\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|"
                r"secret[_-]?key|token|auth[_-]?token|private[_-]?key)\b[\"']?\s*[:=]\s*[\"']?)"
                r"([^\s\"',;&}]+)"), r"\1" + REDACTED),
]


def redact_text(text: str) -> tuple[str, int]:
    """Return (text with secrets replaced, number of replacements)."""
    total = 0
    for pattern, replacement in _PATTERNS:
        text, count = pattern.subn(replacement, text)
        total += count
    return text, total
