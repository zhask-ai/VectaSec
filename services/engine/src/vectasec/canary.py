"""Canaries: decoy URLs that alert when someone tries them.

The integration-layer breaches of 2025-26 share a detection story: a trusted integration
account ran unwatched for a day or more. A canary is the cheapest alarm for that. It is a URL
nothing legitimate calls, placed where an intruder reads — a workflow definition, an env file,
a note beside real credentials. A request to it means someone was reading there and tried what
they found.

DESIGN
  * The token is 192 random bits, shown once at creation. Only its SHA-256 is stored, so a
    database reader cannot reconstruct a working canary URL (and cannot silently test one).
  * The public endpoint answers every request — live canary, revoked canary, unknown token —
    with the same generic 404 body and no delay difference worth measuring. It must not tell
    the caller they tripped anything.
  * A hit stores IP, user agent, method and query length. Never the body or headers: an
    intruder's request may carry stolen secrets and this table is tenant-readable.
  * Hits are capped per canary per hour, so a scanner hammering one URL cannot fill the table
    or flood Slack. The first hit in an hour alerts; the rest are counted.
  * An alert is delivered to the tenant's enabled chat / webhook / email / SIEM integrations
    as one critical item. Delivery failure never fails the hit.

WHAT A CANARY IS NOT. It detects someone who finds the decoy and calls it. It does not detect
an intruder who never reads that place, and it is not a decoy credential inside a broker. The
console says where to put it and says this.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from typing import Optional

__all__ = ["mint", "revoke", "record_hit", "public_base", "snippets", "token_hash",
           "HITS_PER_HOUR", "ALERT_TYPES", "PUBLIC_RESPONSE"]

HITS_PER_HOUR = 60
ALERT_TYPES = ("slack", "teams", "webhook", "email", "siem")
# What the public endpoint returns to EVERYONE, tripped or not.
PUBLIC_RESPONSE = {"detail": "Not Found"}


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def public_base() -> Optional[str]:
    """Where canary URLs point. The engine binds to localhost by default, so canaries need an
    operator-set public URL for a host that forwards /c/* to it. None = not configured."""
    base = (os.environ.get("VECTASEC_PUBLIC_URL") or "").strip().rstrip("/")
    return base if base.lower().startswith(("https://", "http://")) else None


def snippets(url: str) -> list[dict]:
    """Ready-made decoys. Names are chosen to look worth trying without imitating any real
    vendor's key format."""
    return [
        {"title": "A line in an environment file or secret store",
         "body": f"LEGACY_BILLING_EXPORT_URL={url}"},
        {"title": "An HTTP node in a disabled n8n / Zapier / Make workflow",
         "body": f"POST {url}\n# name the step: \"Push invoices to finance (old)\""},
        {"title": "A note beside real credentials (wiki, runbook, repo README)",
         "body": f"Break-glass admin API (do not use unless the gateway is down): {url}"},
    ]


def mint(cur, tenant_id: str, name: str, placed_in: str = "", finding_id: Optional[str] = None,
         actor: Optional[str] = None) -> dict:
    token = secrets.token_urlsafe(24)
    cur.execute(
        """insert into canaries (tenant_id, name, placed_in, finding_id, token_hash, token_prefix, created_by)
           values (%s,%s,%s,%s,%s,%s,%s) returning id, created_at""",
        (tenant_id, name[:120], placed_in[:300], finding_id, token_hash(token), token[:6], actor),
    )
    cid, created_at = cur.fetchone()
    base = public_base()
    url = f"{base}/c/{token}" if base else None
    return {"id": str(cid), "name": name[:120], "token_prefix": token[:6],
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
            "url": url, "path": f"/c/{token}",
            "snippets": snippets(url) if url else [],
            "note": ("Copy it now. It is not stored and cannot be shown again."
                     if url else
                     "VECTASEC_PUBLIC_URL is not set, so there is no public address to build the "
                     "URL from. Set it to the public base URL that forwards /c/* to the engine. "
                     "The path is shown once and is not stored.")}


def revoke(cur, tenant_id: str, canary_id: str) -> bool:
    cur.execute("update canaries set revoked_at = now() where tenant_id = %s and id = %s "
                "and revoked_at is null returning id", (tenant_id, canary_id))
    return cur.fetchone() is not None


def record_hit(cur, token: str, *, source_ip: Optional[str], user_agent: Optional[str],
               method: str, query_len: int = 0) -> Optional[dict]:
    """Record a request to /c/{token}. Returns {tenant_id, canary_id, name, placed_in, alert}
    for a live canary, None otherwise. `alert` is True for the first hit in the current hour."""
    if not token or len(token) > 128:
        return None
    cur.execute("select id, tenant_id, name, placed_in from canaries "
                "where token_hash = %s and revoked_at is null", (token_hash(token),))
    row = cur.fetchone()
    if not row:
        return None
    cid, tenant_id, name, placed_in = row
    cur.execute("select count(*) from canary_hits where canary_id = %s and at > now() - interval '1 hour'",
                (cid,))
    recent = int(cur.fetchone()[0])
    cur.execute("update canaries set hit_count = hit_count + 1, last_hit_at = now() where id = %s", (cid,))
    if recent >= HITS_PER_HOUR:
        return {"tenant_id": str(tenant_id), "canary_id": str(cid), "name": name,
                "placed_in": placed_in, "alert": False, "capped": True}
    cur.execute(
        """insert into canary_hits (tenant_id, canary_id, source_ip, user_agent, method, query_len)
           values (%s,%s,%s,%s,%s,%s)""",
        (tenant_id, cid, (source_ip or "")[:64] or None, (user_agent or "")[:300] or None,
         (method or "")[:10], max(0, int(query_len))),
    )
    cur.execute(
        """insert into audit_log (tenant_id, actor, action, target, detail)
           values (%s,'engine','canary.hit',%s,%s)""",
        (tenant_id, str(cid), json.dumps({"name": name, "source_ip": (source_ip or "")[:64],
                                          "method": (method or "")[:10]})),
    )
    return {"tenant_id": str(tenant_id), "canary_id": str(cid), "name": name,
            "placed_in": placed_in, "alert": recent == 0, "capped": False,
            "source_ip": (source_ip or "")[:64], "user_agent": (user_agent or "")[:300]}


def alert_event(hit: dict) -> dict:
    """The notification, shaped as one critical finding so every sender renders it."""
    where = f" (placed in: {hit['placed_in']})" if hit.get("placed_in") else ""
    return {
        "kind": "new_findings", "tenant_id": hit["tenant_id"], "scan_id": None,
        "connection": {"type": "canary", "name": hit["name"]},
        "findings": [{
            "severity": "critical", "rule_id": "CANARY.TRIPPED",
            "title": f"Canary '{hit['name']}' was called from {hit.get('source_ip') or 'an unknown address'}{where}. "
                     "Nothing legitimate uses this URL: someone read the place it was stored.",
            "resource_name": hit["name"], "status": "open",
        }],
        "error": None,
    }


def send_alerts(cur, hit: dict, *, deliver=None) -> list[dict]:
    """Best effort to every enabled alerting integration. Never raises."""
    from .creds import resolve_secrets, runtime_config
    from .redact import safe_error
    if deliver is None:
        from .notify import deliver
    out = []
    try:
        cur.execute("select id::text, type, name, config, creds_ref from integrations "
                    "where tenant_id = %s and enabled and type = any(%s)",
                    (hit["tenant_id"], list(ALERT_TYPES)))
        rows = cur.fetchall() or []
    except Exception as e:                      # noqa: BLE001
        return [{"status": "failed", "error": safe_error(e)}]
    event = alert_event(hit)
    for iid, itype, iname, config, creds_ref in rows:
        try:
            deliver(itype, runtime_config(config or {}, resolve_secrets(cur, creds_ref)), event)
            out.append({"integration_id": iid, "name": iname, "type": itype, "status": "sent"})
        except Exception as e:                  # noqa: BLE001
            out.append({"integration_id": iid, "name": iname, "type": itype,
                        "status": "failed", "error": safe_error(e)})
    return out
