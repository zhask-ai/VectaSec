"""Make (make.com) connector — read-only over the Make API v2 (token auth).

Operators' words (research_notes/Middleware engine AI upgrade research/
pain_points_uncovered_systems.md): when someone inherits Make scenarios, the first thing to check
is whose personal accounts the connections run under. This connector answers that, plus which
connections nothing uses any more, which webhooks anyone with the URL can trigger, and whether
the organisation enforces two-factor sign-in.

Endpoints (developers.make.com/api-documentation, read 2026-11-24). All GET:
  GET /users/me                                     the token's user (scope organizations:read)
  GET /organizations                                orgs the token can see: id, name, tfaEnforced,
                                                    teams[{id,name}]           (organizations:read)
  GET /teams?organizationId=                        teams in an org            (teams:read)
  GET /scenarios?teamId=&cols[]=…                   scenarios: isActive, scheduling, hookId,
                                                    createdByUser, updatedByUser {id,name,email},
                                                    usedPackages, lastEdit     (scenarios:read)
  GET /connections?teamId=&cols[]=…                 connections: accountName, packageName,
                                                    metadata {value,type}, expire, visibility,
                                                    scenarioUsages, hookUsages (connections:read)
  GET /hooks?teamId=                                webhooks: typeName, enabled, gone, url,
                                                    scenarioId, connectionId   (hooks:read)
Auth header: `Authorization: Token <token>`. Base URL per zone: https://<zone>.make.com/api/v2.

What the API does NOT expose (so this connector does not claim it): who created a connection,
any authentication setting on a webhook, and where scenario-failure emails go for other users.
Webhook URLs are stored as host only: the path IS the credential for a Make webhook.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

DEFAULT_ZONE = "eu1"
SCENARIO_COLS = ["id", "name", "teamId", "isActive", "isPaused", "scheduling", "hookId",
                 "createdByUser", "updatedByUser", "usedPackages", "lastEdit", "created"]
CONNECTION_COLS = ["id", "name", "accountName", "accountLabel", "packageName", "expire",
                   "metadata", "teamId", "organizationId", "scoped", "editable", "visibility",
                   "accountType", "scenarioUsages", "hookUsages"]
PAGE = 100
MAX_PAGES = 50
PERSONAL_EMAIL_DOMAINS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "icloud.com", "me.com", "mac.com", "aol.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.de", "gmx.net", "mail.com", "yandex.com",
    "yandex.ru", "zoho.com", "hey.com", "fastmail.com", "tutanota.com", "web.de", "qq.com",
    "163.com", "rediffmail.com"})


def _base(config: dict) -> str:
    base = str(config.get("base_url") or "").strip().rstrip("/")
    if base:
        return base
    zone = str(config.get("zone") or DEFAULT_ZONE).strip().lower()
    return f"https://{zone}.make.com/api/v2"


def _outcome_for(e: Exception) -> dict:
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code in (401, 403):
            return {"outcome": "forbidden", "status": code, "error": f"HTTP {code}"}
        if code == 404:
            return {"outcome": "not_found", "status": code, "error": "HTTP 404"}
        return {"outcome": "error", "status": code, "error": f"HTTP {code}"}
    return {"outcome": "error", "error": f"{type(e).__name__}"}


def _get_list(client: httpx.Client, url: str, key: str, params: dict, paged: bool = True) -> list:
    """Every item of a list endpoint. Pages with pg[offset]/pg[limit] where the endpoint takes
    them; stops at a short page or MAX_PAGES."""
    out: list = []
    for page in range(MAX_PAGES if paged else 1):
        p = dict(params)
        if paged:
            p.update({"pg[limit]": PAGE, "pg[offset]": page * PAGE})
        r = client.get(url, params=p)
        r.raise_for_status()
        items = (r.json() or {}).get(key) or []
        out.extend(i for i in items if isinstance(i, dict))
        if not paged or len(items) < PAGE:
            break
    return out


def _email(v) -> Optional[str]:
    if isinstance(v, dict):
        v = v.get("email")
    v = str(v or "").strip()
    return v.lower() if "@" in v else None


def _domain(email: Optional[str]) -> str:
    return email.rsplit("@", 1)[-1] if email else ""


def _parse_dt(v) -> Optional[datetime]:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ── pure assembly ─────────────────────────────────────────────────────────

def assemble(base: str, *, me: Optional[dict], orgs: list, teams: dict, scenarios: dict,
             connections: dict, hooks: dict, outcomes: dict, now: Optional[datetime] = None) -> Collected:
    """Raw API bodies → Collected. teams/scenarios/connections/hooks are keyed by org id / team id."""
    now = now or datetime.now(timezone.utc)
    host = urlsplit(base).hostname or base
    resources: list[Resource] = []
    edges: list[Edge] = []

    account_ext = f"make-account-{host}"
    resources.append(Resource(
        kind="make_account", name=host, ext_id=account_ext, namespace=host,
        labels={"token_user": _email(me) or "", "orgs": str(len(orgs))},
        raw={"base_url": base, "token_user": {"id": (me or {}).get("id"), "email": _email(me),
                                               "tfa": (me or {}).get("tfaStatus")},
             "collection": outcomes}))

    active_by_scenario: dict = {}
    for org in orgs:
        oid = org.get("id")
        org_ext = f"make-org-{oid}"
        resources.append(Resource(
            kind="make_organization", name=str(org.get("name") or oid), ext_id=org_ext,
            labels={"tfa_enforced": str(org.get("tfaEnforced")).lower() if org.get("tfaEnforced") is not None else "unknown",
                    "sso": str(org.get("ssoType") or "")},
            raw={"id": oid, "name": org.get("name"), "tfa_enforced": org.get("tfaEnforced"),
                 "sso_type": org.get("ssoType"), "zone": org.get("zone"),
                 "active_scenarios": org.get("activeScenarios")}))
        edges.append(Edge(src_ext_id=account_ext, dst_ext_id=org_ext, kind="contains"))

        for team in teams.get(oid) or []:
            tid = team.get("id")
            team_ext = f"make-team-{tid}"
            resources.append(Resource(kind="make_team", name=str(team.get("name") or tid), ext_id=team_ext,
                                      raw={"id": tid, "name": team.get("name"), "organization_id": oid}))
            edges.append(Edge(src_ext_id=org_ext, dst_ext_id=team_ext, kind="contains"))

            for s in scenarios.get(tid) or []:
                sid = s.get("id")
                created_by, updated_by = _email(s.get("createdByUser")), _email(s.get("updatedByUser"))
                active = bool(s.get("isActive")) and not s.get("isPaused")
                active_by_scenario[sid] = active
                resources.append(Resource(
                    kind="make_scenario", name=str(s.get("name") or sid), ext_id=f"make-scenario-{sid}",
                    labels={"active": str(active).lower(), "owner": created_by or "",
                            "team": str(team.get("name") or tid)},
                    raw={"id": sid, "name": s.get("name"), "team_id": tid, "active": active,
                         "hook_id": s.get("hookId"), "scheduling": s.get("scheduling"),
                         "created_by": created_by, "updated_by": updated_by,
                         "used_packages": s.get("usedPackages") or [], "last_edit": s.get("lastEdit")}))
                edges.append(Edge(src_ext_id=team_ext, dst_ext_id=f"make-scenario-{sid}", kind="contains"))

            for c in connections.get(tid) or []:
                cid = c.get("id")
                meta = c.get("metadata") if isinstance(c.get("metadata"), dict) else {}
                account_email = _email(meta.get("value")) if meta.get("type") == "email" or "@" in str(meta.get("value") or "") else None
                expire = _parse_dt(c.get("expire"))
                usages_read = "scenarioUsages" in c or "hookUsages" in c
                used_by = [u.get("id") for u in (c.get("scenarioUsages") or []) if isinstance(u, dict)]
                hooks_using = [u.get("id") for u in (c.get("hookUsages") or []) if isinstance(u, dict)]
                cext = f"make-connection-{cid}"
                resources.append(Resource(
                    kind="make_connection", name=str(c.get("name") or cid), ext_id=cext,
                    labels={"app": str(c.get("accountLabel") or c.get("packageName") or c.get("accountName") or ""),
                            "owner": account_email or "",
                            "personal_account": str(_domain(account_email) in PERSONAL_EMAIL_DOMAINS).lower(),
                            "used_by_count": str(len(used_by)) if usages_read else "unknown",
                            "team": str(team.get("name") or tid)},
                    raw={"id": cid, "name": c.get("name"), "team_id": tid,
                         "app": c.get("accountLabel") or c.get("packageName") or c.get("accountName"),
                         "package": c.get("packageName"), "account_email": account_email,
                         "account_domain": _domain(account_email),
                         "personal_account": _domain(account_email) in PERSONAL_EMAIL_DOMAINS,
                         "expires_at": expire.isoformat() if expire else None,
                         "expired": bool(expire and expire < now),
                         "visibility": c.get("visibility"), "scoped": c.get("scoped"),
                         "usages_readable": usages_read, "used_by_scenarios": used_by,
                         "used_by_hooks": hooks_using}))
                edges.append(Edge(src_ext_id=team_ext, dst_ext_id=cext, kind="contains"))
                for sid in used_by:
                    edges.append(Edge(src_ext_id=f"make-scenario-{sid}", dst_ext_id=cext, kind="uses_connection"))

            for h in hooks.get(tid) or []:
                hid = h.get("id")
                url_host = urlsplit(str(h.get("url") or "")).hostname or ""
                resources.append(Resource(
                    kind="make_hook", name=str(h.get("name") or hid), ext_id=f"make-hook-{hid}",
                    labels={"type": str(h.get("typeName") or ""), "enabled": str(bool(h.get("enabled"))).lower()},
                    raw={"id": hid, "name": h.get("name"), "team_id": tid, "type_name": h.get("typeName"),
                         "enabled": bool(h.get("enabled")), "gone": bool(h.get("gone")),
                         "url_host": url_host, "scenario_id": h.get("scenarioId"),
                         "connection_id": h.get("connectionId")}))
                edges.append(Edge(src_ext_id=team_ext, dst_ext_id=f"make-hook-{hid}", kind="contains"))
                if h.get("scenarioId"):
                    edges.append(Edge(src_ext_id=f"make-hook-{hid}", dst_ext_id=f"make-scenario-{h.get('scenarioId')}",
                                      kind="triggers"))

    for r in resources:
        if r.kind == "make_hook":
            r.raw["scenario_active"] = active_by_scenario.get(r.raw.get("scenario_id"))
    return Collected(resources=resources, edges=edges)


# ── collection ────────────────────────────────────────────────────────────

@connector("make", fields=[
    ConnectorField("zone", "Zone", placeholder="eu1",
                   help="Your Make zone: eu1, eu2, us1 or us2 (the first part of your Make address, "
                        "for example eu1.make.com)."),
    ConnectorField("api_token", "API token", required=True, secret=True,
                   help="A Make API token (Profile → API access) with read scopes only: "
                        "organizations:read, teams:read, scenarios:read, connections:read, hooks:read. "
                        "The connector only reads; it never runs, edits or deletes a scenario."),
    ConnectorField("organization_id", "Organization ID", placeholder="123456",
                   help="Optional. Limit the scan to one organization; otherwise every organization "
                        "the token can see is read."),
    ConnectorField("base_url", "API base URL", placeholder="https://eu1.make.com/api/v2",
                   help="Optional override, for example for Make hosted by Celonis."),
])
def collect(config: dict) -> Collected:
    token = str(config.get("api_token") or "").strip()
    if not token:
        raise ValueError("api_token is required")
    base = _base(config)
    only_org = str(config.get("organization_id") or "").strip()
    timeout = float(config.get("timeout") or 20)
    outcomes: dict = {}
    me, orgs, teams, scenarios, connections, hooks = None, [], {}, {}, {}, {}
    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    with httpx.Client(timeout=timeout, headers=headers, follow_redirects=False,
                      verify=config.get("verify", True)) as client:
        try:
            r = client.get(f"{base}/users/me")
            r.raise_for_status()
            me = (r.json() or {}).get("authUser")
            outcomes["me"] = {"outcome": "ok"}
        except Exception as e:
            outcomes["me"] = _outcome_for(e)
        try:
            orgs = _get_list(client, f"{base}/organizations", "organizations", {})
            if only_org:
                orgs = [o for o in orgs if str(o.get("id")) == only_org]
            outcomes["organizations"] = {"outcome": "ok", "count": len(orgs)}
        except Exception as e:
            outcomes["organizations"] = _outcome_for(e)

        for kind in ("teams", "scenarios", "connections", "hooks"):
            outcomes[kind] = {"outcome": "ok", "count": 0}
        for org in orgs:
            oid = org.get("id")
            try:
                teams[oid] = _get_list(client, f"{base}/teams", "teams", {"organizationId": oid})
                outcomes["teams"]["count"] += len(teams[oid])
            except Exception as e:
                outcomes["teams"] = _outcome_for(e)
                continue
            for team in teams[oid]:
                tid = team.get("id")
                for kind, url, key, params, paged in (
                        ("scenarios", f"{base}/scenarios", "scenarios", {"teamId": tid, "cols[]": SCENARIO_COLS}, True),
                        ("connections", f"{base}/connections", "connections", {"teamId": tid, "cols[]": CONNECTION_COLS}, False),
                        ("hooks", f"{base}/hooks", "hooks", {"teamId": tid}, False)):
                    try:
                        items = _get_list(client, url, key, params, paged)
                        {"scenarios": scenarios, "connections": connections, "hooks": hooks}[kind][tid] = items
                        if outcomes[kind].get("outcome") == "ok":
                            outcomes[kind]["count"] += len(items)
                    except Exception as e:
                        outcomes[kind] = _outcome_for(e)
    return assemble(base, me=me, orgs=orgs, teams=teams, scenarios=scenarios,
                    connections=connections, hooks=hooks, outcomes=outcomes)


# ── NHI model ─────────────────────────────────────────────────────────────

@identity_extractor("make")
def _from_make(resources: list) -> tuple:
    """make_connection → identity (automation_connection, the third-party account it runs as)
    + credential (managed by Make, never a value). owner_label is the account email the
    connection authenticates as, so the Access register and the leaver report show it."""
    out: list[Resource] = []
    edges: list[Edge] = []
    for r in resources:
        if r.kind != "make_connection":
            continue
        raw = r.raw or {}
        label = f"{raw.get('app') or 'app'}:{raw.get('name') or raw.get('id')}"
        idr = _mk_identity("make", "automation_connection", label, external=True, source_ext=r.ext_id,
                           tags=(["expired"] if raw.get("expired") else []),
                           extra={"connection_id": raw.get("id"), "owner_label": raw.get("account_email"),
                                  "used_by_scenarios": raw.get("used_by_scenarios") or []})
        if raw.get("account_email"):
            idr.labels["owner_label"] = raw["account_email"]
        out.append(idr)
        cred = _mk_credential("make", idr.ext_id, "app_connection", name=f"{label}:connection",
                              hashing="make_managed", present=True, plaintext=False,
                              count=len(raw.get("used_by_scenarios") or []),
                              extra={"expired": raw.get("expired"), "expires_at": raw.get("expires_at")})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return out, edges
