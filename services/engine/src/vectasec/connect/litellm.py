"""LiteLLM proxy (AI gateway) connector — read-only.

Why: an AI gateway holds every provider key the company has (OpenAI, Anthropic, Bedrock…) and
hands out "virtual keys" to apps and people. Security research in 2026 found hundreds of
internet-facing LiteLLM gateways with no master key or with the docs' example key `sk-1234`
(CSA research note on LiteLLM default credentials; Wiz). Inside, the usual mess is virtual keys
with no budget, no expiry, access to every model, and no owner.

Facts used (LiteLLM source on main, read 2026-11-23; latest release v1.110.2):
  * Auth: `Authorization: Bearer <key>` (also x-litellm-api-key). With no master_key configured
    the proxy is unauthenticated: every route, key management included, answers anyone.
  * GET /key/list?return_full_object=true&page=&size=(≤100) → {keys, total_count, current_page,
    total_pages}; key fields: token (hash), key_name ("sk-...abcd"), key_alias, spend, max_budget,
    budget_duration, expires, blocked, models ([] = all models), user_id, team_id, created_by,
    created_at, last_active, rotation_count, auto_rotate, last_rotation_at, allowed_routes.
    proxy_admin / proxy_admin_viewer see every key; other callers only their own.
  * GET /user/list?page=&page_size=(≤100) → {users, total, …}; user_role ∈ proxy_admin,
    proxy_admin_viewer, org_admin, internal_user, internal_user_viewer, team, customer.
  * GET /team/list → bare array (the raw `keys` rows it embeds are dropped here).
  * GET /model/info → {data:[{model_name, litellm_params, model_info}]}; provider keys are removed
    by the proxy before returning; only the provider prefix and api_base host are kept here.
  * Version: public /health/readiness carries litellm_version up to v1.83.x; from v1.84.0 it does
    not, so /openapi.json info.version is the fallback.
The only non-configured credential ever sent is the public docs example key `sk-1234`, once, to
GET /key/list (read-only), to see whether it still works — the same idea as RabbitMQ's guest probe.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

DOCS_EXAMPLE_KEY = "sk-1234"
PAGE = 100
MAX_PAGES = 50
ALL_MODELS = {"*", "all-proxy-models"}


def _outcome_for(e: Exception) -> dict:
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code in (401, 403):
            return {"outcome": "forbidden", "status": code, "error": f"HTTP {code}"}
        if code == 404:
            return {"outcome": "not_found", "status": code, "error": "HTTP 404"}
        return {"outcome": "error", "status": code, "error": f"HTTP {code}"}
    return {"outcome": "error", "error": type(e).__name__}


def _dt(v) -> Optional[datetime]:
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def all_models(models) -> bool:
    models = [str(m) for m in (models or [])]
    return not models or bool(ALL_MODELS & set(models))


# ── pure assembly ─────────────────────────────────────────────────────────

def assemble(base: str, *, probes: dict, keys: list, users: list, teams: list, models: list,
             outcomes: dict, now: Optional[datetime] = None) -> Collected:
    now = now or datetime.now(timezone.utc)
    host = urlsplit(base).hostname or base
    pext = f"litellm-proxy-{host}"
    resources: list[Resource] = []
    edges: list[Edge] = []
    resources.append(Resource(
        kind="litellm_proxy", name=host, ext_id=pext, namespace=host,
        labels={"version": str(probes.get("version") or "?"),
                "no_auth": str(bool(probes.get("no_auth"))).lower()},
        raw={"base_url": base, "scheme": urlsplit(base).scheme, **probes,
             "key_count": len(keys), "user_count": len(users), "collection": outcomes}))

    teams_by_id = {}
    for t in teams:
        tid = t.get("team_id")
        teams_by_id[tid] = t
        resources.append(Resource(
            kind="litellm_team", name=str(t.get("team_alias") or tid), ext_id=f"litellm-team-{host}-{tid}",
            namespace=host,
            raw={"team_id": tid, "alias": t.get("team_alias"), "models": t.get("models") or [],
                 "all_models": all_models(t.get("models")), "max_budget": t.get("max_budget"),
                 "blocked": bool(t.get("blocked")),
                 "admins": [m.get("user_email") or m.get("user_id") for m in t.get("members_with_roles") or []
                            if isinstance(m, dict) and m.get("role") == "admin"]}))
        edges.append(Edge(src_ext_id=pext, dst_ext_id=f"litellm-team-{host}-{tid}", kind="contains"))

    email_by_user = {}
    for u in users:
        uid = u.get("user_id")
        email_by_user[uid] = u.get("user_email")
        resources.append(Resource(
            kind="litellm_user", name=str(u.get("user_email") or uid), ext_id=f"litellm-user-{host}-{uid}",
            namespace=host, labels={"role": str(u.get("user_role") or "")},
            raw={"user_id": uid, "email": u.get("user_email"), "role": u.get("user_role"),
                 "models": u.get("models") or [], "max_budget": u.get("max_budget"),
                 "teams": u.get("teams") or []}))
        edges.append(Edge(src_ext_id=pext, dst_ext_id=f"litellm-user-{host}-{uid}", kind="contains"))

    for k in keys:
        if not isinstance(k, dict):
            continue
        token = str(k.get("token") or k.get("key_id") or "")
        kid = token[:16] or str(k.get("key_alias") or k.get("key_name"))
        team = teams_by_id.get(k.get("team_id")) or {}
        expires = _dt(k.get("expires"))
        last_active = _dt(k.get("last_active"))
        created = _dt(k.get("created_at"))
        owner = email_by_user.get(k.get("user_id")) or k.get("user_id") or None
        kext = f"litellm-key-{host}-{kid}"
        key_all = all_models(k.get("models"))
        resources.append(Resource(
            kind="litellm_key", name=str(k.get("key_alias") or k.get("key_name") or kid), ext_id=kext,
            namespace=host,
            labels={"owner": str(owner or ""), "team": str(team.get("team_alias") or k.get("team_id") or ""),
                    "all_models": str(key_all).lower()},
            raw={"id": kid, "alias": k.get("key_alias"), "key_name": k.get("key_name"),
                 "user_id": k.get("user_id"), "owner": owner, "team_id": k.get("team_id"),
                 "team_alias": team.get("team_alias"), "created_by": k.get("created_by"),
                 "models": k.get("models") or [], "all_models": key_all,
                 "team_restricts_models": bool(team) and not all_models(team.get("models")),
                 "max_budget": k.get("max_budget"), "team_max_budget": team.get("max_budget"),
                 "budget_duration": k.get("budget_duration"), "spend": k.get("spend"),
                 "expires": expires.isoformat() if expires else None,
                 "expired": bool(expires and expires < now), "blocked": bool(k.get("blocked")),
                 "created_at": created.isoformat() if created else None,
                 "last_active_known": "last_active" in k,
                 "last_active": last_active.isoformat() if last_active else None,
                 "days_since_active": (now - last_active).days if last_active else None,
                 "days_since_created": (now - created).days if created else None,
                 "auto_rotate": k.get("auto_rotate"), "last_rotation_at": k.get("last_rotation_at"),
                 "allowed_routes": k.get("allowed_routes") or []}))
        edges.append(Edge(src_ext_id=pext, dst_ext_id=kext, kind="contains"))
        if k.get("team_id") in teams_by_id:
            edges.append(Edge(src_ext_id=kext, dst_ext_id=f"litellm-team-{host}-{k.get('team_id')}", kind="member_of"))

    for mdl in models:
        params = mdl.get("litellm_params") or {}
        name = str(mdl.get("model_name") or params.get("model") or "?")
        provider = str(params.get("model") or "").split("/", 1)[0] if "/" in str(params.get("model") or "") else None
        mext = f"litellm-model-{host}-{name}"
        if any(r.ext_id == mext for r in resources):
            continue
        resources.append(Resource(
            kind="litellm_model", name=name, ext_id=mext, namespace=host,
            labels={"provider": str(provider or "")},
            raw={"model_name": name, "provider": provider,
                 "api_base_host": urlsplit(str(params.get("api_base") or "")).hostname}))
        edges.append(Edge(src_ext_id=pext, dst_ext_id=mext, kind="routes_to"))
    return Collected(resources=resources, edges=edges)


# ── collection ────────────────────────────────────────────────────────────

def _probe(client: httpx.Client, base: str) -> dict:
    """Unauthenticated / default-key probes. All GETs."""
    out: dict = {"version": None, "version_source": None, "readiness_public_details": False,
                 "no_auth": False, "default_key_accepted": False}
    try:
        r = client.get(f"{base}/health/readiness")
        if r.status_code == 200:
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            if isinstance(body, dict) and body.get("litellm_version"):
                out.update(version=body["litellm_version"], version_source="/health/readiness",
                           readiness_public_details=True)
    except Exception:
        pass
    if not out["version"]:
        try:
            r = client.get(f"{base}/openapi.json")
            if r.status_code == 200:
                v = ((r.json() or {}).get("info") or {}).get("version")
                if v:
                    out.update(version=str(v), version_source="/openapi.json")
        except Exception:
            pass
    try:
        r = client.get(f"{base}/key/list", params={"size": 1})
        out["no_auth"] = r.status_code == 200
        out["unauth_status"] = r.status_code
    except Exception as e:
        out["unauth_status"] = type(e).__name__
    if not out["no_auth"]:
        try:
            r = client.get(f"{base}/key/list", params={"size": 1},
                           headers={"Authorization": f"Bearer {DOCS_EXAMPLE_KEY}"})
            out["default_key_accepted"] = r.status_code == 200
            out["default_key_status"] = r.status_code
        except Exception as e:
            out["default_key_status"] = type(e).__name__
    return out


@connector("litellm", fields=[
    ConnectorField("base_url", "Proxy URL", required=True, placeholder="https://llm.example.com",
                   help="The LiteLLM proxy address, the same one your apps call."),
    ConnectorField("api_key", "Admin key", required=True, secret=True,
                   help="A key with the proxy_admin_viewer role (read-only admin) so every virtual key, "
                        "user and team is visible. The master key also works but gives more than "
                        "VectaSec needs. Only GET requests are sent."),
])
def collect(config: dict) -> Collected:
    base = str(config.get("base_url") or "").strip().rstrip("/")
    key = str(config.get("api_key") or "").strip()
    if not base or not key:
        raise ValueError("base_url and api_key are required")
    timeout = float(config.get("timeout") or 20)
    outcomes: dict = {}
    keys, users, teams, models = [], [], [], []
    with httpx.Client(timeout=timeout, follow_redirects=False, verify=config.get("verify", True)) as anon:
        probes = _probe(anon, base)
    with httpx.Client(timeout=timeout, follow_redirects=False, verify=config.get("verify", True),
                      headers={"Authorization": f"Bearer {key}"}) as client:
        try:
            for page in range(1, MAX_PAGES + 1):
                r = client.get(f"{base}/key/list", params={"return_full_object": "true", "page": page, "size": PAGE})
                r.raise_for_status()
                body = r.json() or {}
                keys.extend(k for k in body.get("keys") or [] if isinstance(k, dict))
                if page >= int(body.get("total_pages") or 1):
                    break
            outcomes["keys"] = {"outcome": "ok", "count": len(keys)}
        except Exception as e:
            outcomes["keys"] = _outcome_for(e)
        try:
            for page in range(1, MAX_PAGES + 1):
                r = client.get(f"{base}/user/list", params={"page": page, "page_size": PAGE})
                r.raise_for_status()
                body = r.json() or {}
                batch = body.get("users") or []
                users.extend(u for u in batch if isinstance(u, dict))
                if len(batch) < PAGE:
                    break
            outcomes["users"] = {"outcome": "ok", "count": len(users)}
        except Exception as e:
            outcomes["users"] = _outcome_for(e)
        try:
            r = client.get(f"{base}/team/list")
            r.raise_for_status()
            body = r.json()
            teams = [t for t in (body if isinstance(body, list) else body.get("teams") or []) if isinstance(t, dict)]
            outcomes["teams"] = {"outcome": "ok", "count": len(teams)}
        except Exception as e:
            outcomes["teams"] = _outcome_for(e)
        try:
            r = client.get(f"{base}/model/info")
            r.raise_for_status()
            models = [m for m in (r.json() or {}).get("data") or [] if isinstance(m, dict)]
            outcomes["models"] = {"outcome": "ok", "count": len(models)}
        except Exception as e:
            outcomes["models"] = _outcome_for(e)
    return assemble(base, probes=probes, keys=keys, users=users, teams=teams, models=models,
                    outcomes=outcomes)


# ── NHI model ─────────────────────────────────────────────────────────────

@identity_extractor("litellm")
def _from_litellm(resources: list) -> tuple:
    """Each virtual key → identity (service account) + credential (present, never the value) +
    one grant per model, or a single all-models grant."""
    out: list[Resource] = []
    edges: list[Edge] = []
    for r in resources:
        if r.kind != "litellm_key":
            continue
        raw = r.raw or {}
        label = f"litellm:{raw.get('alias') or raw.get('key_name') or raw.get('id')}"
        tags = [t for t, on in (("expired", raw.get("expired")), ("blocked", raw.get("blocked"))) if on]
        idr = _mk_identity("litellm", "service_account", label, source_ext=r.ext_id, tags=tags,
                           extra={"owner_label": raw.get("owner"), "team": raw.get("team_alias")})
        if raw.get("owner"):
            idr.labels["owner_label"] = str(raw["owner"])
        out.append(idr)
        cred = _mk_credential("litellm", idr.ext_id, "virtual_key", name=f"{label}:key", hashing="sha256",
                              present=True, plaintext=False,
                              extra={"expires": raw.get("expires"), "last_active": raw.get("last_active")})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        targets = ["*"] if raw.get("all_models") else [str(m) for m in raw.get("models") or []]
        for t in targets:
            g = _mk_grant("litellm", idr.ext_id, "invoke", f"model:{t}", wildcard=(t == "*"))
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
