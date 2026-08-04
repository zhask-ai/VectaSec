"""The action layer: route a finished scan's outcome to the outside world.

Six destination types (`integrations.type`): Slack incoming webhooks, Microsoft Teams
incoming webhooks (Adaptive Card), generic JSON webhooks (optionally HMAC-signed), email
over SMTP, Jira Cloud issues, and SIEM export as OCSF Detection Finding (class 2004) JSON.
`routing_rules.match` decides which findings go where.

Design rules, in the same spirit as the scan loop:

  • **A notification failure NEVER fails a scan.** `notify_scan` (the only entry point the
    pipeline calls) catches everything, and each destination is isolated from the others — one
    dead webhook must not silence the Slack channel next to it. Every attempt, sent or failed,
    leaves a `notification_deliveries` row the console can show.
  • **"New" is honest.** Rules are evaluated against findings CREATED by the scan that just
    finished: `scan_id = this scan AND first_seen >= this scan's started_at`. The upsert in
    scan.py stamps `scan_id` on every re-seen finding but never touches `first_seen`, so this
    predicate is exactly "first ever observed during this run" — a re-scan that re-sees 50 old
    findings notifies about none of them.
  • **Secrets live in Vault, not in `integrations.config`.** A webhook URL is a credential
    (whoever holds it can post as us), so URLs, tokens and signing secrets are split out via
    creds.py and stored as one Vault secret per integration (`integrations.creds_ref`). The
    stored config is metadata only; the merge back happens in this process's memory at send
    time, exactly like connection credentials at collect time.

All outbound HTTP goes through httpx with a hard timeout. Senders raise NotifyError; the
router records it and moves on.
"""
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Callable, Optional

import httpx

from .creds import resolve_secrets, runtime_config, store_secrets
from .redact import safe_error

log = logging.getLogger(__name__)

_TIMEOUT = 10.0          # seconds, per outbound call — a slow destination must not stall routing

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# What a rule fires on when its match carries no notify_on of its own.
DEFAULT_EVENTS = ("new_findings", "scan_failed")

# ── Integration contracts ─────────────────────────────────────────────────
# Which config keys are credentials (→ Vault) and which are required to send at all.
# Email deliberately declares no secrets: SMTP credentials are operator-level (env vars,
# below), not per-integration data.
INTEGRATION_SECRET_KEYS: dict[str, tuple[str, ...]] = {
    "slack":   ("webhook_url",),
    "teams":   ("webhook_url",),                # Workflows/legacy-connector URL embeds a signature
    "webhook": ("url", "hmac_secret"),          # hmac_secret optional; secret when present
    "email":   (),
    "jira":    ("api_token",),
    "siem":    ("url", "token"),                # token optional bearer for the SIEM endpoint
}
INTEGRATION_REQUIRED: dict[str, tuple[str, ...]] = {
    "slack":   ("webhook_url",),
    "teams":   ("webhook_url",),
    "webhook": ("url",),
    "email":   ("to",),
    "jira":    ("base_url", "project_key", "email", "api_token"),
    "siem":    ("url",),
}
INTEGRATION_TYPES = tuple(sorted(INTEGRATION_SECRET_KEYS))


class NotifyError(Exception):
    """A delivery that did not happen. Message is safe to store (no secret values)."""


def validate_integration_config(type_: str, config: dict,
                                stored_secret_keys: tuple[str, ...] = ()) -> list[str]:
    """Problems with a submitted integration config, ready for a 400.

    `stored_secret_keys` lets an UPDATE pass validation without retyping a secret that is
    already vaulted — same "empty means unchanged" contract as connection credentials.
    """
    if type_ not in INTEGRATION_SECRET_KEYS:
        return [f"unknown integration type {type_!r} (have: {', '.join(INTEGRATION_TYPES)})"]
    have = {k for k, v in (config or {}).items() if v not in (None, "")} | set(stored_secret_keys)
    return [f"{k} is required for a {type_} integration"
            for k in INTEGRATION_REQUIRED[type_] if k not in have]


def split_integration_config(type_: str, config: dict) -> tuple[dict, dict]:
    """(public_config, secrets) — the type's declared secret keys, split out before storage.

    Empty secret values are dropped, not vaulted: an empty field on a re-submitted form means
    "unchanged" (creds.store_secrets then merges over what is stored)."""
    keys = set(INTEGRATION_SECRET_KEYS.get(type_, ()))
    public = {k: v for k, v in (config or {}).items() if k not in keys}
    secrets = {k: v for k, v in (config or {}).items() if k in keys and v not in (None, "")}
    return public, secrets


def store_integration_secrets(cur, integration_id: str, secrets: dict,
                              existing_ref: Optional[str] = None) -> Optional[str]:
    """Vault the integration's secret fields; returns the creds_ref to store on the row.

    Reuses creds.store_secrets (merge-on-update, recreate-if-vanished) with an
    integration-namespaced id, so the Vault-side name is attributable:
    `vectasec/connection/integration/<id>`."""
    return store_secrets(cur, f"integration/{integration_id}", secrets, existing_ref)


# ── Rendering ─────────────────────────────────────────────────────────────
def _connection_label(event: dict) -> str:
    c = event.get("connection") or {}
    return f"{c.get('type') or '?'}/{c.get('name') or '?'}"


def _summary_text(event: dict) -> str:
    """One human-readable summary, shared by Slack, email and Jira."""
    if event["kind"] == "scan_failed":
        return (f"VectaSec: scan of {_connection_label(event)} FAILED"
                + (f" — {event.get('error')}" if event.get("error") else ""))
    if event["kind"] == "test":
        return "VectaSec test notification — this integration is wired up correctly."
    findings = event.get("findings") or []
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity") or "info"] = by_sev.get(f.get("severity") or "info", 0) + 1
    sev_s = ", ".join(f"{by_sev[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
                      if s in by_sev)
    lines = [f"VectaSec: {len(findings)} new finding(s) on {_connection_label(event)} ({sev_s})"]
    for f in findings[:10]:
        lines.append(f"  • [{f.get('severity')}] {f.get('rule_id')}: {f.get('title')}"
                     + (f" — {f.get('resource_name')}" if f.get("resource_name") else ""))
    if len(findings) > 10:
        lines.append(f"  … and {len(findings) - 10} more")
    return "\n".join(lines)


def _event_body(event: dict) -> dict:
    """The generic-webhook JSON payload. Findings verbatim (they carry no credentials)."""
    return {
        "source": "vectasec",
        "event": event["kind"],
        "tenant_id": event.get("tenant_id"),
        "scan_id": event.get("scan_id"),
        "connection": event.get("connection"),
        "findings": event.get("findings") or [],
        "error": event.get("error"),
    }


# ── OCSF (class 2004 Detection Finding) ───────────────────────────────────
_OCSF_SEVERITY = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


def ocsf_detection_finding(finding: dict, event: dict) -> dict:
    """One VectaSec finding as an OCSF v1.1 Detection Finding (category 2 Findings,
    class_uid 2004, activity Create). This is the SIEM export shape."""
    sev = (finding.get("severity") or "").lower()
    return {
        "activity_id": 1, "activity_name": "Create",
        "category_uid": 2, "category_name": "Findings",
        "class_uid": 2004, "class_name": "Detection Finding",
        "type_uid": 200401, "type_name": "Detection Finding: Create",
        "time": int(time.time() * 1000),
        "severity_id": _OCSF_SEVERITY.get(sev, 0),
        "severity": sev.capitalize() if sev in _OCSF_SEVERITY else "Unknown",
        "status": "New", "status_id": 1,
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "VectaSec", "vendor_name": "VectaSec"},
        },
        "finding_info": {
            "uid": str(finding.get("id") or ""),
            "title": finding.get("title") or "",
            "types": [finding.get("rule_id") or ""],
            "desc": finding.get("detail") or "",
        },
        "resources": [{
            "uid": finding.get("resource_ext_id") or "",
            "name": finding.get("resource_name") or "",
            "type": finding.get("resource_kind") or "",
        }],
        "unmapped": {
            "tenant_id": event.get("tenant_id"),
            "scan_id": event.get("scan_id"),
            "connection": event.get("connection"),
        },
    }


# ── Senders ───────────────────────────────────────────────────────────────
# Each takes the MERGED config (public ∪ Vault secrets, in memory only) and an event dict:
#   {kind: new_findings|scan_failed|test, tenant_id, scan_id, connection: {type,name},
#    findings: [{id, rule_id, title, severity, detail, resource_name, resource_kind,
#    resource_ext_id}], error}
# and raises NotifyError on any failure. `client` is injectable for tests (MockTransport).

def allow_private_targets() -> bool:
    """On-prem estates legitimately notify an internal Splunk/webhook on RFC1918. Off by default
    because in the hosted topology every tenant admin would otherwise hold an HTTP request
    primitive inside the engine's network."""
    return os.environ.get("VECTASEC_ALLOW_PRIVATE_NOTIFY_TARGETS", "").strip().lower() in (
        "1", "true", "yes")


def guard_url(url: str, *, dest: str) -> None:
    """Refuse destinations that are really the engine's own network.

    The URLs here are TENANT-SUPPLIED. Handed straight to httpx they make the engine — the
    process holding a BYPASSRLS database connection and the service-role key — issue arbitrary
    POSTs to anything it can route to, with the response status (and formerly the body) handed
    back through the API. That is a cloud-metadata and internal-port-scan primitive available to
    any tenant admin.

    Link-local is refused ALWAYS, including on-prem: 169.254.169.254 is the cloud metadata
    endpoint and no notification destination is ever legitimately there. The private/loopback
    ranges are refused by default and allowed by the on-prem opt-out, because an internal
    collector on 10.x is the normal case there and blocking it would break the feature.

    A hostname that does not resolve is allowed through to httpx, which will fail it with a
    connection error: refusing here would turn a transient DNS outage into a configuration
    error, and it cannot be used to reach anything.
    """
    import ipaddress
    import socket
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise NotifyError(f"{dest}: only http and https destinations are allowed")
    host = parts.hostname
    if not host:
        raise NotifyError(f"{dest}: destination URL has no host")
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise NotifyError(f"{dest}: destination resolves to a link-local or metadata address")
        if (ip.is_private or ip.is_loopback or ip.is_reserved) and not allow_private_targets():
            raise NotifyError(
                f"{dest}: destination resolves to a private address. Set "
                f"VECTASEC_ALLOW_PRIVATE_NOTIFY_TARGETS=1 if this engine is meant to notify "
                f"systems on its own network.")


def _post(client: Optional[httpx.Client], url: str, *, dest: str, **kwargs) -> httpx.Response:
    """POST with timeout + uniform error mapping. The URL is a secret for most destinations,
    so error text names the destination TYPE, never the URL."""
    # `client` is injected only by tests (MockTransport), which never leave the process.
    if client is None:
        guard_url(url, dest=dest)
    try:
        if client is not None:
            res = client.post(url, **kwargs)
        else:
            with httpx.Client(timeout=_TIMEOUT) as c:
                res = c.post(url, **kwargs)
    except httpx.HTTPError as e:
        raise NotifyError(f"{dest}: {type(e).__name__}") from e
    if res.status_code >= 300:
        raise NotifyError(f"{dest}: HTTP {res.status_code}: {res.text[:200]}")
    return res


def send_slack(config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    url = config.get("webhook_url")
    if not url:
        raise NotifyError("slack: webhook_url is not configured")
    _post(client, url, dest="slack", json={"text": _summary_text(event)})


def send_teams(config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    """Microsoft Teams incoming webhook. Works with both webhook flavours Teams has shipped:
    a Workflows (Power Automate) "When a Teams webhook request is received" trigger URL and
    the legacy Office 365 connector URL — both accept the same message envelope carrying an
    Adaptive Card attachment, which is the format Microsoft documents for incoming webhooks."""
    url = config.get("webhook_url")
    if not url:
        raise NotifyError("teams: webhook_url is not configured")
    lines = _summary_text(event).splitlines()
    body_blocks: list[dict] = [
        {"type": "TextBlock", "text": lines[0], "weight": "Bolder", "wrap": True},
    ]
    if len(lines) > 1:
        body_blocks.append({"type": "TextBlock", "text": "\n".join(lines[1:]),
                            "wrap": True, "spacing": "Small", "isSubtle": True})
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.4",
                "msteams": {"width": "Full"},
                "body": body_blocks,
            },
        }],
    }
    _post(client, url, dest="teams", json=payload)


def send_webhook(config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    url = config.get("url")
    if not url:
        raise NotifyError("webhook: url is not configured")
    body = json.dumps(_event_body(event), default=str).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "vectasec-notify"}
    secret = config.get("hmac_secret")
    if secret:
        sig = hmac.new(str(secret).encode(), body, hashlib.sha256).hexdigest()
        headers["X-VectaSec-Signature"] = f"sha256={sig}"
    _post(client, url, dest="webhook", content=body, headers=headers)


def send_email(config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    """SMTP from env: SMTP_HOST (required), SMTP_PORT (587), SMTP_USERNAME/SMTP_PASSWORD
    (optional; password never lives in integrations.config), SMTP_FROM, SMTP_STARTTLS."""
    import smtplib
    from email.message import EmailMessage

    host = os.environ.get("SMTP_HOST", "").strip()
    if not host:
        raise NotifyError("email: SMTP_HOST is not set")
    to = config.get("to")
    recipients = [a.strip() for a in (to if isinstance(to, list) else str(to or "").split(","))
                  if a and a.strip()]
    if not recipients:
        raise NotifyError("email: no recipients configured")

    msg = EmailMessage()
    if event["kind"] == "scan_failed":
        subject = f"[VectaSec] scan failed: {_connection_label(event)}"
    elif event["kind"] == "test":
        subject = "[VectaSec] test notification"
    else:
        subject = (f"[VectaSec] {len(event.get('findings') or [])} new finding(s): "
                   f"{_connection_label(event)}")
    msg["Subject"] = subject
    msg["From"] = os.environ.get("SMTP_FROM", "vectasec@localhost")
    msg["To"] = ", ".join(recipients)
    msg.set_content(_summary_text(event))

    port = int(os.environ.get("SMTP_PORT", "587") or 587)
    starttls = os.environ.get("SMTP_STARTTLS", "true").strip().lower() not in ("0", "false", "no", "off")
    username = os.environ.get("SMTP_USERNAME", "").strip()
    try:
        with smtplib.SMTP(host, port, timeout=_TIMEOUT) as s:
            if starttls:
                s.starttls()
            if username:
                s.login(username, os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
    except Exception as e:
        raise NotifyError(f"email: {type(e).__name__}: {e}") from e


def send_jira(config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    """Jira Cloud REST v3 create-issue. config: base_url, project_key, email, issue_type
    (default Task); api_token from Vault. Description is ADF (v3 requires it)."""
    base = str(config.get("base_url") or "").rstrip("/")
    project, email_, token = config.get("project_key"), config.get("email"), config.get("api_token")
    if not (base and project and email_ and token):
        raise NotifyError("jira: base_url, project_key, email and api_token are all required")
    summary = _summary_text(event).splitlines()[0][:250]
    body = {
        "fields": {
            "project": {"key": project},
            "issuetype": {"name": config.get("issue_type") or "Task"},
            "summary": summary,
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph",
                             "content": [{"type": "text", "text": _summary_text(event)}]}],
            },
        }
    }
    _post(client, f"{base}/rest/api/3/issue", dest="jira", json=body,
          auth=(str(email_), str(token)))


def send_siem(config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    """SIEM export: POST an array of OCSF Detection Finding (2004) objects to the endpoint.
    Optional bearer `token` (vaulted). A scan-failed event exports an empty findings array —
    the OCSF payload still carries the scan/connection context in `unmapped`."""
    url = config.get("url")
    if not url:
        raise NotifyError("siem: url is not configured")
    payload = [ocsf_detection_finding(f, event) for f in (event.get("findings") or [])]
    headers = {"Content-Type": "application/json"}
    if config.get("token"):
        headers["Authorization"] = f"Bearer {config['token']}"
    _post(client, url, dest="siem", content=json.dumps(payload, default=str).encode(),
          headers=headers)


SENDERS: dict[str, Callable[..., None]] = {
    "slack": send_slack,
    "teams": send_teams,
    "webhook": send_webhook,
    "email": send_email,
    "jira": send_jira,
    "siem": send_siem,
}


def deliver(type_: str, config: dict, event: dict, client: Optional[httpx.Client] = None) -> None:
    sender = SENDERS.get(type_)
    if sender is None:
        raise NotifyError(f"no sender for integration type {type_!r}")
    sender(config, event, client=client)


# ── Routing (pure — unit-tested without a DB) ─────────────────────────────
def rule_wants(match: dict, kind: str) -> bool:
    """Does this rule fire for this event kind? Absent notify_on means both scan events;
    'test' is never routed by rules (it goes through POST /integrations/{id}/test)."""
    events = match.get("notify_on") or list(DEFAULT_EVENTS)
    return kind in events


def rule_matches_connector(match: dict, connector_type: str) -> bool:
    ctypes = match.get("connector_types") or []
    return not ctypes or connector_type in ctypes


def match_findings(match: dict, connector_type: str, findings: list[dict]) -> list[dict]:
    """The findings this rule routes: connector filter (whole scan), severity threshold
    (min_severity, inclusive), rulepack filter (rule_id prefixes). {} matches everything."""
    if not rule_matches_connector(match, connector_type):
        return []
    floor = _SEV_RANK.get(match.get("min_severity") or "", 0)
    prefixes = match.get("rule_prefixes") or []
    out = []
    for f in findings:
        if _SEV_RANK.get(f.get("severity") or "", 0) < floor:
            continue
        if prefixes and not any(str(f.get("rule_id") or "").startswith(p) for p in prefixes):
            continue
        out.append(f)
    return out


# ── The router ────────────────────────────────────────────────────────────
def _new_findings(cur, tenant_id: str, scan_id: str, started_at) -> list[dict]:
    """Findings CREATED by this scan (see module doc: scan_id + first_seen >= started_at is
    the honest 'new'), open only — a finding born suppressed was explicitly not asked about."""
    cur.execute(
        """select f.id::text, f.rule_id, f.title, f.severity, f.detail,
                  r.name, r.kind, r.ext_id
             from findings f left join resources r on r.id = f.resource_id
            where f.tenant_id = %s and f.scan_id = %s and f.first_seen >= %s
              and f.status = 'open'
            order by case f.severity when 'critical' then 0 when 'high' then 1
                     when 'medium' then 2 when 'low' then 3 else 4 end, f.rule_id""",
        (tenant_id, scan_id, started_at),
    )
    return [{"id": r[0], "rule_id": r[1], "title": r[2], "severity": r[3], "detail": r[4],
             "resource_name": r[5], "resource_kind": r[6], "resource_ext_id": r[7]}
            for r in cur.fetchall()]


def _notify_scan(conn, tenant_id: str, scan_id: str) -> list[dict]:
    with conn.cursor() as cur:
        cur.execute(
            """select s.status, s.started_at, s.stats, c.type, c.name
                 from scans s left join connections c on c.id = s.connection_id
                where s.id = %s and s.tenant_id = %s""",
            (scan_id, tenant_id),
        )
        row = cur.fetchone()
        if not row:
            return []
        status, started_at, stats, ctype, cname = row
        if status == "done":
            kind, error = "new_findings", None
        elif status == "error":
            kind, error = "scan_failed", (stats or {}).get("error")
        else:
            return []                       # queued/running: nothing to say yet

        cur.execute(
            """select r.id::text, r.match, i.id::text, i.type, i.name, i.config, i.creds_ref
                 from routing_rules r join integrations i on i.id = r.integration_id
                where r.tenant_id = %s and i.enabled and coalesce(r.enabled, true)""",
            (tenant_id,),
        )
        rules = cur.fetchall()
        if not rules:
            return []

        findings = _new_findings(cur, tenant_id, scan_id, started_at) if kind == "new_findings" else []

        deliveries: list[dict] = []
        for rule_id, match, iid, itype, iname, iconfig, creds_ref in rules:
            match = match if isinstance(match, dict) else {}
            if not rule_wants(match, kind):
                continue
            if kind == "new_findings":
                selected = match_findings(match, ctype or "", findings)
                if not selected:
                    continue                # nothing new that this rule cares about
            else:
                if not rule_matches_connector(match, ctype or ""):
                    continue
                selected = []

            event = {"kind": kind, "tenant_id": tenant_id, "scan_id": scan_id,
                     "connection": {"type": ctype, "name": cname},
                     "findings": selected, "error": error}
            # Vault secrets merged in this process's memory only, per destination.
            merged = runtime_config(iconfig or {}, resolve_secrets(cur, creds_ref))
            try:
                deliver(itype, merged, event)
                sent, err = "sent", None
            except Exception as e:          # per-destination isolation: record and continue
                # safe_error, not raw text. This column is readable by every viewer in the
                # tenant, and not every exception is a NotifyError with its URL already
                # stripped — httpx.InvalidURL, for one, is not an httpx.HTTPError, so it
                # escapes _post's handler carrying the userinfo from the URL that caused it.
                sent, err = "error", safe_error(e)
                log.warning("notify: %s/%s failed for scan %s: %s", itype, iname, scan_id, err)
            cur.execute(
                """insert into notification_deliveries
                     (tenant_id, integration_id, routing_rule_id, scan_id, event,
                      findings_count, status, error)
                   values (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (tenant_id, iid, rule_id, scan_id, kind, len(selected), sent, err),
            )
            deliveries.append({"integration_id": iid, "integration": iname, "type": itype,
                               "rule_id": rule_id, "event": kind, "findings": len(selected),
                               "status": sent, "error": err})

    if not getattr(conn, "autocommit", False):
        conn.commit()
    return deliveries


def notify_scan(conn, tenant_id: str, scan_id: str) -> list[dict]:
    """Route a finished scan (status done → new-findings rules; error → scan-failed rules)
    to every enabled routing rule's destination. NEVER raises: notification is a side effect
    of a scan, and a scan that completed must stay completed whatever the outside world does.
    Returns delivery summaries (also persisted to notification_deliveries)."""
    try:
        return _notify_scan(conn, tenant_id, scan_id)
    except Exception:
        log.exception("notify: routing failed for scan %s (scan outcome unaffected)", scan_id)
        try:
            if not getattr(conn, "autocommit", False):
                conn.rollback()
        except Exception:
            pass
        return []
