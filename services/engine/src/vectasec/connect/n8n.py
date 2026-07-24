"""n8n connector — read-only over the public REST API (/api/v1) plus one unauthenticated probe.

n8n is an integration/automation platform (an iPaaS): workflows wire external SaaS together, each
workflow can expose a public HTTP webhook trigger, and every third-party credential the automations
use is stored on the instance. That makes an n8n instance a dense piece of integration-layer attack
surface — exactly what this product exists to see — and there is no third-party posture tool for it.

What is read, and the discipline around it:

  GET  /api/v1/workflows   the automation inventory. Each workflow's nodes are parsed for webhook
                           TRIGGERS (their `authentication` mode is the posture fact) and for
                           CREDENTIAL REFERENCES (id + name + type only — the public API never
                           returns credential *data*, and neither does this connector).
  GET  /api/v1/users       the human/owner identities (the NHI material). May 401 on an instance
                           where the key lacks the users scope — recorded as not-readable, never
                           read as "no users".
  POST /api/v1/audit       n8n's OWN security-audit generator. It computes a read-only risk report
                           (unprotected webhooks, outdated instance, …) and mutates nothing; we use
                           it as enrichment, never as the sole authority for a finding.
  GET  {base}/rest/settings  the ONE unauthenticated probe, on a client carrying no API key. This
                           endpoint bootstraps the login page, so it answers without auth by design;
                           its value here is `versionCli` (authoritative for the CVE checks) and
                           `userManagement.showSetupOnFirstLoad` (true ⇒ no owner account exists yet,
                           so anyone reaching the instance can claim admin). A probe that inherited
                           the API key would prove nothing about unauthenticated reachability — same
                           reason connect/kong.py keeps a separate anonymous client.

The API key is a ConnectorField secret=True: it is used to build the client and is never copied
into any Resource. Credential *values* are never fetched at all.

Kinds are DISTINCT — n8n_instance / n8n_workflow / n8n_credential / n8n_user — so no other rulepack
runs against an n8n resource by accident (the same reason connect/redis.py refuses to reuse
`broker`).

The parse layer (parse_workflow, parse_user, …) is pure: REST JSON dicts in, Resources out. Tests
drive detectors against parse-layer output from golden fixtures, so httpx (and a live instance) stay
out of the suite and a shape drift between connector and rulepack fails a test rather than
mis-firing in production.
"""
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# n8n node types that publish an inbound HTTP endpoint. The Form Trigger is the Ni8mare
# (CVE-2026-21858) vector specifically; all of these accept requests from whoever can reach the URL,
# so their `authentication` parameter is the posture fact the workflow rulepack reads.
_WEBHOOK_TRIGGER_TYPES = {
    "n8n-nodes-base.webhook",
    "n8n-nodes-base.formTrigger",
    "n8n-nodes-base.form",
    "n8n-nodes-base.chatTrigger",
    "@n8n/n8n-nodes-langchain.chatTrigger",
}

# Nodes that turn a request into command / code execution or arbitrary outbound calls. A workflow
# that reaches one of these FROM an unauthenticated webhook trigger is a materially worse finding
# than an unauthenticated webhook that only, say, appends a row — the rulepack escalates on it.
_EXECUTION_NODE_TYPES = {
    "n8n-nodes-base.executeCommand",
    "n8n-nodes-base.code",
    "n8n-nodes-base.function",
    "n8n-nodes-base.functionItem",
    "n8n-nodes-base.ssh",
}

# `authentication` values that mean "no credential is required to trigger this webhook". n8n's own
# default for a new Webhook node is `none`; an unset value is the same absence.
_UNAUTH_WEBHOOK_MODES = {"none", "", None}


def _origin(base: str) -> str:
    host = (urlsplit(base).hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1") or host.startswith("127."):
        return "loopback"
    return "remote"


# ── parse layer: REST JSON dicts → Resources (pure, no httpx) ─────────────────
def _trigger_nodes(nodes: list) -> list:
    """Webhook/trigger nodes of a workflow, reduced to the posture facts (never the node's data)."""
    out = []
    for n in nodes or []:
        if n.get("type") not in _WEBHOOK_TRIGGER_TYPES:
            continue
        params = n.get("parameters") or {}
        out.append({
            "node": n.get("name"),
            "type": n.get("type"),
            "http_method": params.get("httpMethod") or params.get("method"),
            "path": params.get("path"),
            "authentication": params.get("authentication"),
            "webhook_id": n.get("webhookId"),
        })
    return out


def _credential_refs(nodes: list) -> list:
    """Every credential a workflow's nodes reference: id + name + type only. n8n embeds these as
    node.credentials = {"<credType>": {"id": .., "name": ..}}; the decrypted secret is never here."""
    out = []
    for n in nodes or []:
        for cred_type, ref in (n.get("credentials") or {}).items():
            if not isinstance(ref, dict):
                continue
            out.append({
                "id": ref.get("id"),
                "name": ref.get("name"),
                "type": cred_type,
                "node": n.get("name"),
            })
    return out


def parse_workflow(wf: dict) -> tuple:
    """One workflow → (Resource, list[credential-ref dict]). The refs are returned separately so the
    collector can dedupe credentials across workflows into distinct n8n_credential resources."""
    nodes = wf.get("nodes") or []
    triggers = _trigger_nodes(nodes)
    refs = _credential_refs(nodes)
    node_types = {n.get("type") for n in nodes}
    unauth_triggers = [t for t in triggers if t.get("authentication") in _UNAUTH_WEBHOOK_MODES]
    res = Resource(
        kind="n8n_workflow",
        name=str(wf.get("name") or wf.get("id") or "?"),
        ext_id=f"n8n-workflow-{wf.get('id')}",
        labels={"active": "true" if wf.get("active") else "false",
                "webhook_count": str(len(triggers))},
        raw={
            "id": wf.get("id"),
            "name": wf.get("name"),
            "active": bool(wf.get("active")),
            "archived": bool(wf.get("isArchived") or wf.get("archived")),
            "node_count": len(nodes),
            "webhook_triggers": triggers,
            "has_unauthenticated_webhook": bool(unauth_triggers),
            "execution_node_types": sorted(t for t in node_types if t in _EXECUTION_NODE_TYPES),
            "credential_refs": refs,
            "tags": [t.get("name") for t in (wf.get("tags") or []) if isinstance(t, dict)],
            "created_at": wf.get("createdAt"),
            "updated_at": wf.get("updatedAt"),
        },
    )
    return res, refs


def parse_user(u: dict) -> Resource:
    """One /api/v1/users entry. `mfa_enabled` is stored as the API's value when present and None
    when the field is absent, so the rulepack can answer not-assessable rather than reading a
    missing field as 'MFA off'."""
    role = u.get("role") or u.get("globalRole") or ""
    if isinstance(role, dict):                      # some versions nest {"name": "owner", ...}
        role = role.get("name") or ""
    role = str(role)
    mfa = u.get("mfaEnabled")
    if mfa is None:
        mfa = u.get("isMfaEnabled")                 # field name varies across versions
    return Resource(
        kind="n8n_user",
        name=str(u.get("email") or u.get("id") or "?"),
        ext_id=f"n8n-user-{u.get('id')}",
        labels={"role": role or "?",
                "pending": "true" if u.get("isPending") else "false"},
        raw={
            "id": u.get("id"),
            "email": u.get("email"),
            "role": role,
            "is_owner": role.endswith("owner"),
            "is_admin": role.endswith("admin") or role.endswith("owner"),
            "is_pending": bool(u.get("isPending")),
            "mfa_enabled": mfa,                     # True / False / None(absent → not assessable)
            "created_at": u.get("createdAt"),
        },
    )


def parse_credential(ref: dict, used_by: list, used_by_unauth_webhook: bool) -> Resource:
    """A distinct credential, deduped from the node references across workflows. Metadata only:
    id, name, type, and the blast-radius facts (which workflows use it, whether any of those is
    reachable via an unauthenticated webhook). The credential's decrypted value is never available
    from the public API and is never stored."""
    return Resource(
        kind="n8n_credential",
        name=str(ref.get("name") or ref.get("id") or "?"),
        ext_id=f"n8n-credential-{ref.get('id')}",
        labels={"credential_type": str(ref.get("type") or "?"),
                "used_by_count": str(len(used_by))},
        raw={
            "id": ref.get("id"),
            "name": ref.get("name"),
            "credential_type": ref.get("type"),
            "used_by_workflows": used_by,
            "used_by_unauthenticated_webhook_workflow": used_by_unauth_webhook,
        },
    )


def _audit_facts(audit) -> dict:
    """Reduce n8n's POST /audit report to the facts the instance rulepack reads. The report is an
    object keyed by human titles ('Instance Risk Report'), each value carrying risk + sections;
    parse defensively — a missing section means the audit did not flag it, not an error."""
    facts = {"readable": audit is not None, "unprotected_webhooks": None, "outdated": None}
    if not isinstance(audit, dict):
        return facts
    for report in audit.values():
        if not isinstance(report, dict) or report.get("risk") != "instance":
            continue
        for section in report.get("sections") or []:
            title = str(section.get("title") or "").lower()
            if "unprotected webhook" in title:
                facts["unprotected_webhooks"] = section.get("location") or []
            elif "outdated" in title:
                facts["outdated"] = {
                    "current_version": (section.get("settings") or {}).get("current_version"),
                    "next_versions": (section.get("nextVersions")
                                      or (section.get("settings") or {}).get("next_versions") or []),
                }
    return facts


def build_instance(base: str, *, settings: dict, settings_status, origin: str,
                   audit, users_readable: bool, outcomes: dict) -> Resource:
    """The n8n_instance resource: version + the unauthenticated-probe posture + collection outcomes.
    `settings` is the /rest/settings body (or {} when the probe failed)."""
    um = (settings or {}).get("userManagement") or {}
    audit_facts = _audit_facts(audit)
    version = ((settings or {}).get("versionCli")
               or ((audit_facts.get("outdated") or {}) or {}).get("current_version"))
    host = urlsplit(base).hostname or "n8n"
    return Resource(
        kind="n8n_instance",
        name=host,
        ext_id=f"n8n-instance-{host}",
        labels={"version": str(version or "?"), "origin": origin},
        raw={
            "base_url": base,
            "version": version,
            "origin": origin,
            "settings_probe_status": settings_status,
            "settings_readable_unauthenticated": settings_status == 200,
            # showSetupOnFirstLoad true ⇒ no owner account has been created; the instance is
            # unclaimed and the first visitor can become the owner.
            "owner_setup_pending": um.get("showSetupOnFirstLoad"),
            "smtp_configured": um.get("smtpSetup"),
            "public_api_enabled": (settings or {}).get("publicApi", {}).get("enabled")
                                  if isinstance((settings or {}).get("publicApi"), dict) else None,
            "endpoint_webhook": (settings or {}).get("endpointWebhook"),
            "users_readable": users_readable,
            "audit": audit_facts,
            "collection": outcomes,
        },
    )


# ── collection: httpx in, per-call error isolation ────────────────────────────
def _paginate(client: httpx.Client, base: str, path: str, limit: int = 100) -> list:
    """Walk an /api/v1 list endpoint to exhaustion. n8n returns {"data": [...], "nextCursor": "..."}
    and signals the end with nextCursor == null — never by a short page, so the loop terminates only
    on a null cursor (a truncated inventory silently under-reports every finding)."""
    out, cursor = [], None
    while True:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        r = client.get(f"{base}/api/v1{path}", params=params)
        r.raise_for_status()
        body = r.json()
        out.extend(body.get("data") or [])
        cursor = body.get("nextCursor")
        if not cursor:
            break
    return out


@connector("n8n", fields=[
    ConnectorField("base_url", "Instance URL", required=True,
                   placeholder="https://n8n.example.com",
                   help="Root URL of the n8n instance. The public API is read under {base}/api/v1; "
                        "GETs only, plus one unauthenticated GET {base}/rest/settings."),
    ConnectorField("api_key", "API key", secret=True,
                   help="An n8n public-API key (X-N8N-API-KEY). Use a key scoped to workflow:read, "
                        "user:read and audit — the connector never creates, updates, or deletes."),
])
def collect(config: dict) -> Collected:
    base = (config.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("n8n connector requires config['base_url']")
    timeout = float(config.get("timeout") or 15)
    verify = config.get("verify", True)
    api_key = config.get("api_key")
    origin = _origin(base)
    outcomes: dict = {}

    # ── the one unauthenticated probe: no API key on this client ──
    settings, settings_status = {}, None
    try:
        with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False) as anon:
            r = anon.get(f"{base}/rest/settings")
            settings_status = r.status_code
            if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                body = r.json()
                settings = body.get("data") if isinstance(body.get("data"), dict) else body
    except Exception as e:
        outcomes["settings_probe"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}

    headers = {"X-N8N-API-KEY": api_key} if api_key else {}
    workflows_raw, users_raw, audit = [], [], None
    users_readable = True
    with httpx.Client(timeout=timeout, verify=verify, headers=headers,
                      follow_redirects=False) as client:
        try:
            workflows_raw = _paginate(client, base, "/workflows")
            outcomes["workflows"] = {"outcome": "ok", "count": len(workflows_raw)}
        except Exception as e:
            outcomes["workflows"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}

        try:
            users_raw = _paginate(client, base, "/users")
            outcomes["users"] = {"outcome": "ok", "count": len(users_raw)}
        except httpx.HTTPStatusError as e:
            users_readable = False
            outcomes["users"] = {"outcome": "forbidden" if e.response.status_code in (401, 403)
                                 else "error", "error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            users_readable = False
            outcomes["users"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}

        try:
            r = client.post(f"{base}/api/v1/audit", json={})
            if r.status_code == 200:
                audit = r.json()
                outcomes["audit"] = {"outcome": "ok"}
            else:
                outcomes["audit"] = {"outcome": "error", "error": f"HTTP {r.status_code}"}
        except Exception as e:
            outcomes["audit"] = {"outcome": "error", "error": f"{type(e).__name__}: {e}"}

    resources: list[Resource] = []
    edges: list[Edge] = []

    instance = build_instance(base, settings=settings, settings_status=settings_status,
                              origin=origin, audit=audit, users_readable=users_readable,
                              outcomes=outcomes)
    resources.append(instance)

    # Workflows, and the dedup index that turns node credential references into distinct credentials.
    cred_index: dict = {}                # credential id -> {"ref": ref, "workflows": [...], "unauth": bool}
    for wf in workflows_raw:
        wf_res, refs = parse_workflow(wf)
        resources.append(wf_res)
        edges.append(Edge(src_ext_id=instance.ext_id, dst_ext_id=wf_res.ext_id, kind="hosts"))
        unauth = wf_res.raw["has_unauthenticated_webhook"] and wf_res.raw["active"]
        for ref in refs:
            cid = ref.get("id")
            if cid is None:
                continue
            entry = cred_index.setdefault(cid, {"ref": ref, "workflows": [], "unauth": False})
            entry["workflows"].append(wf.get("id"))
            entry["unauth"] = entry["unauth"] or unauth

    for cid, entry in cred_index.items():
        cred_res = parse_credential(entry["ref"], entry["workflows"], entry["unauth"])
        resources.append(cred_res)
        for wid in entry["workflows"]:
            edges.append(Edge(src_ext_id=f"n8n-workflow-{wid}", dst_ext_id=cred_res.ext_id,
                              kind="uses_credential"))

    for u in users_raw:
        user_res = parse_user(u)
        resources.append(user_res)
        edges.append(Edge(src_ext_id=instance.ext_id, dst_ext_id=user_res.ext_id, kind="has_member"))

    return Collected(resources=resources, edges=edges)


# ── NHI: users → identities/grants, stored credentials → credential material ──
_ROLE_ITYPE = {"owner": "owner", "admin": "admin", "member": "service_account"}


def _role_itype(role: str) -> str:
    r = (role or "").rsplit(":", 1)[-1].lower()
    return _ROLE_ITYPE.get(r, "service_account")


@identity_extractor("n8n")
def _from_n8n(resources: list) -> tuple:
    """The normalized NHI model for n8n:

      n8n_user       → identity (owner/admin/member), a password credential (metadata only — n8n
                       stores a bcrypt hash we never read), and a grant of the user's global role.
      n8n_credential → the stored third-party credential as credential material (type + present +
                       blast-radius count; never the value) attached to an integration identity, with
                       one grant per workflow that can invoke it — grants_access edged to the workflow.

    Edges: credential --credential_of--> identity, grant --granted_to--> identity, and
    grant --grants_access--> the workflow when the grant names one we collected.
    """
    out: list[Resource] = []
    edges: list[Edge] = []
    instance_ext = next((r.ext_id for r in resources if r.kind == "n8n_instance"), "n8n-instance")

    for r in resources:
        if r.kind != "n8n_user":
            continue
        raw = r.raw or {}
        name = raw.get("email") or r.name
        role = raw.get("role") or ""
        idr = _mk_identity("n8n", _role_itype(role), name, source_ext=r.ext_id,
                           tags=(["mfa_disabled"] if raw.get("mfa_enabled") is False else []),
                           extra={"role": role, "is_admin": bool(raw.get("is_admin")),
                                  "mfa_enabled": raw.get("mfa_enabled")})
        out.append(idr)
        # A local login password exists for every non-pending user; metadata only.
        if not raw.get("is_pending"):
            cred = _mk_credential("n8n", idr.ext_id, "password", name=f"{name}:password",
                                  hashing="bcrypt", present=True, plaintext=False,
                                  extra={"mfa_enabled": raw.get("mfa_enabled")})
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        g = _mk_grant("n8n", idr.ext_id, role or "member", "instance",
                      wildcard=bool(raw.get("is_admin")), extra={"role": role})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=instance_ext, kind="grants_access"))

    for r in resources:
        if r.kind != "n8n_credential":
            continue
        raw = r.raw or {}
        ctype = raw.get("credential_type") or "credential"
        label = f"{ctype}:{raw.get('name') or raw.get('id')}"
        idr = _mk_identity("n8n", "integration_credential", label, external=True, source_ext=r.ext_id,
                           extra={"credential_type": ctype})
        out.append(idr)
        used_by = raw.get("used_by_workflows") or []
        cred = _mk_credential("n8n", idr.ext_id, ctype, name=f"{raw.get('name')}:{ctype}",
                              hashing="n8n_encrypted", present=True, plaintext=False,
                              count=len(used_by),
                              extra={"reachable_unauthenticated":
                                     bool(raw.get("used_by_unauthenticated_webhook_workflow"))})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        for wid in used_by:
            g = _mk_grant("n8n", idr.ext_id, "invoked_by", f"n8n-workflow-{wid}",
                          extra={"workflow_id": wid})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=f"n8n-workflow-{wid}",
                              kind="grants_access"))
    return out, edges
