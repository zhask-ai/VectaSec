"""Redaction for text that leaves the engine — error strings bound for tenant-readable tables.

This lived in api/main.py, but notify.py needs it on the scan-time delivery path and a
notification module importing from the web layer is backwards. It is here so both callers
share ONE implementation: the audit that prompted this found the two paths had drifted, with
the common one (every scan) writing raw exception text while the rare one (a human clicking
Test) redacted it.

Connector and sender exceptions carry whatever the underlying client library felt like saying,
and those libraries are invoked with VAULTED CREDENTIALS. psycopg echoes a malformed DSN
verbatim (`postgresql://user:pass@host`), httpx can include a URL with userinfo, and several
SDKs put the endpoint and token fragment in the message. That text lands in `audit_log.detail`
and `notification_deliveries.error` — both readable by every tenant member, including VIEWERS.
"""
from __future__ import annotations

import re

_SECRET_PATTERNS = [
    # scheme://user:pass@host  → keep the shape, drop the credential
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),
    # Bearer FIRST. `Authorization: Bearer <jwt>` otherwise matches the key=value rule below,
    # which consumes only the word "Bearer" as the value and leaves the token in the clear —
    # verified: it leaked the JWT until this pair was reordered.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"), "bearer <redacted>"),
    # password / token / secret / api-key = value.
    #
    # The optional quotes are load-bearing. Without them this rule matched `password=hunter2`
    # but NOT the far more common shapes an exception actually carries — a dict or JSON repr:
    #   ValueError("bad config {'password': 'S3cr3tPw'}")     → leaked
    #   ValueError('rejected: {"password": "S3cr3tPw"}')      → leaked
    # because `\S+` began at the quote and the value ran to the closing brace unmatched.
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)"
                r"\b[\"']?\s*[=:]\s*[\"']?([^,}\s\"']+)[\"']?"), r"\1=<redacted>"),
]

ERROR_MAX = 300


def safe_error(e: BaseException) -> str:
    """A message safe to store and return: type name, redacted text, bounded length.

    The type name is always exact — that is the part an operator debugs with — while the free
    text is scrubbed and truncated. The full exception still reaches the server log, where the
    audience is the operator rather than every viewer in the tenant.
    """
    text = str(e)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > ERROR_MAX:
        text = text[:ERROR_MAX] + "… (truncated)"
    return f"{type(e).__name__}: {text}" if text else type(e).__name__
