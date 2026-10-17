"""Zapier connector — read-only over the Zapier Workflow API (api.zapier.com, bearer token).

Zapier is the automation SMBs actually run. Every Zap is a small non-human identity: it holds a
stored third-party *authentication* (Zapier's word for a saved OAuth grant / API key to Slack,
Salesforce, Postgres, …), and a webhook-triggered Zap is an unauthenticated public entry point
into whatever that authentication can reach. This connector inventories exactly that — which
Zaps exist, which connections they hold, which of them are reachable by anyone with a URL — and
feeds the "Belongs to an automation" column of the access map.

WHAT IS READ, where each call is documented, and what plan it needs. All calls are GETs over
`{base_url}` (default https://api.zapier.com) with `Authorization: Bearer <access_token>`.

  GET /v1/profiles/me
      docs.zapier.com → Powered by Zapier → API reference → Accounts → User profile.
      Scope `profile`. The authenticated user (id, email, full_name). Used as the OWNER of every
      authentication the token can see — the Authentications endpoint only returns ones the user
      owns, so this is the owner attribution the API offers. Any plan.

  GET /v2/zaps?expand=steps.action,steps.authentication&limit=…&offset=…
      docs.zapier.com → API reference → Workflow → Zaps → Get Zaps [v2].
      Scope `zap` (only Zaps that use the partner's own integration), `zap:all` (all the user's
      Zaps) or `zap:account:all` (every Zap the user can access in the account; `include_shared=
      true` only has effect with this scope). The scanner needs `zap:all` or `zap:account:all` —
      with `zap` alone the inventory is a slice and the account resource says so. Any plan for
      the user's own Zaps; `zap:account:all` is only meaningful on Team/Enterprise accounts.
      Without `expand`, steps carry only ids; with it each step's `action` is {key, app, type,
      action_type, …} and `authentication` is {id, app, is_expired, title}.

  GET /v2/authentications?app=<app id>&limit=…&offset=…
      docs.zapier.com → API reference → Workflow → Authentications → Get Authentications.
      Scope `connection:read`. The endpoint requires an `app` parameter, so it is called once per
      app seen in the Zap inventory — it finds connections that exist but no Zap uses. Any plan.

  NOT READ (no public read API): the Zap runs / history endpoint (Enterprise-only, documented
  only in the Enterprise feature list), the account Audit Log (Team/Enterprise, UI export only),
  the Zapier Manager app, and the per-step input values beyond what `/v2/zaps` already returns.
  Those are recorded as "not covered" in docs/coverage-matrix.md rather than imitated.

The discipline:

  * The access token is a ConnectorField secret=True; it builds the client and is never copied
    into any Resource. Authentication *values* (the OAuth refresh token, the API key) are not
    exposed by the API at all and are never stored — a zapier_connection is metadata only
    (id, app, title, owner, is_expired).
  * 401 / 403 / 404 on an endpoint is recorded as NOT READABLE per endpoint. It is never read as
    "no Zaps" or "no connections" — ZAPIER.ACCOUNT.NOT_ASSESSED turns an unreadable endpoint into
    a not-assessable coverage finding.
  * Kinds are DISTINCT (zapier_account / zapier_zap / zapier_connection / zapier_webhook_trigger)
    so no other rulepack runs against a Zapier resource by accident.

The parse layer (parse_zap, parse_authentication, build_account) is pure: API JSON in, Resources
out. Tests drive detectors and the identity extractor from the golden fixture
tests/fixtures/zapier_responses.json, so httpx and a live account stay out of the suite.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

DEFAULT_BASE_URL = "https://api.zapier.com"

# Trigger apps that accept input from ANYONE who has the URL / address. "Webhooks by Zapier"
# Catch Hook / Catch Raw Hook publishes a hooks.zapier.com URL with no authentication by design;
# "Email by Zapier" / "Email Parser by Zapier" accept mail from any sender. Matched on the app's
# title (what the API returns under action.app.title) and on the implementation keys Zapier has
# used for them, case-insensitively.
_WEBHOOK_APP_TITLES = {"webhooks by zapier", "webhook"}
_WEBHOOK_APP_KEYS = {"webhookapi", "webhookcliapi", "webhook"}
_EMAIL_APP_TITLES = {"email by zapier", "email parser by zapier", "email"}
_EMAIL_APP_KEYS = {"emailapi", "emailparserapi", "email"}

# Apps that are "production-shaped": a Zap that WRITES to one of these from an anonymous trigger
# is an unauthenticated path into a system of record. Matched on a lowercase substring of the
# app title or key, so "Google Workspace Admin" and "GoogleAdminAPI" both hit.
PRODUCTION_APPS = (
    "amazon", "aws", "s3", "sqs", "sns", "dynamodb", "lambda",
    "postgres", "postgresql", "mysql", "sql server", "mssql", "mongodb", "snowflake", "bigquery",
    "salesforce", "stripe", "quickbooks", "xero", "netsuite",
    "slack admin", "google workspace admin", "google admin", "g suite admin", "okta", "azure active",
    "github", "gitlab", "bitbucket",
)

_WRITE_ACTION_TYPES = {"WRITE", "SEARCH_OR_WRITE", "SEARCH_AND_WRITE"}
_UNREADABLE_STATUSES = (401, 403, 404)


def _origin(base: str) -> str:
    return (urlsplit(base).hostname or "api.zapier.com").lower()


def _app_facts(app) -> dict:
    """An `app` reference as the API returns it: a full object when expanded, otherwise an id
    string. Reduced to {id, key, title}; title/key are None when only the id is known."""
    if isinstance(app, dict):
        return {"id": app.get("id"), "key": app.get("key"), "title": app.get("title")}
    return {"id": app if app else None, "key": None, "title": None}


def _app_label(app: dict) -> str:
    return str(app.get("key") or app.get("title") or app.get("id") or "?")


def _is_webhook_app(app: dict) -> bool:
    return ((app.get("title") or "").strip().lower() in _WEBHOOK_APP_TITLES
            or (app.get("key") or "").strip().lower() in _WEBHOOK_APP_KEYS)


def _is_email_app(app: dict) -> bool:
    return ((app.get("title") or "").strip().lower() in _EMAIL_APP_TITLES
            or (app.get("key") or "").strip().lower() in _EMAIL_APP_KEYS)


def is_production_app(app: dict) -> bool:
    hay = f"{app.get('title') or ''} {app.get('key') or ''}".lower()
    return any(p in hay for p in PRODUCTION_APPS)


# ── parse layer: API JSON → Resources (pure, no httpx) ───────────────────────
def _step_facts(step, index: int) -> dict:
    """One Zap step → the posture facts. `action`/`authentication` are objects when the list was
    fetched with expand=steps.action,steps.authentication and bare ids otherwise; both shapes
    are accepted, and `expanded` records which one we got so a rule can say 'not determinable'
    instead of guessing from an id."""
    if not isinstance(step, dict):
        return {"index": index, "expanded": False, "action_id": str(step), "app": _app_facts(None),
                "action_key": None, "action_type": None, "authentication_id": None,
                "authentication": None, "title": None}
    action = step.get("action")
    auth = step.get("authentication")
    expanded = isinstance(action, dict)
    app = _app_facts(action.get("app") if expanded else None)
    auth_id = auth.get("id") if isinstance(auth, dict) else (auth or None)
    return {
        "index": index,
        "expanded": expanded,
        "action_id": action.get("id") if expanded else (action or None),
        "action_key": action.get("key") if expanded else None,
        "action_type": (action.get("action_type") or action.get("type")) if expanded else None,
        "app": app,
        "authentication_id": auth_id,
        "authentication": ({"id": auth.get("id"), "app": _app_facts(auth.get("app")),
                            "title": auth.get("title"), "is_expired": auth.get("is_expired"),
                            "auth_type": auth.get("auth_type") or auth.get("authentication_type")}
                           if isinstance(auth, dict) else None),
        "title": step.get("title"),
    }


def parse_zap(z: dict) -> tuple[list[Resource], list[Edge]]:
    """One /v2/zaps entry → [zapier_zap, (zapier_webhook_trigger)?] + edges zap --uses--> connection.

    The trigger is step 0 (Zapier Zaps always start with the trigger). A webhook/email trigger is
    emitted as its OWN zapier_webhook_trigger resource so the public entry point is a first-class
    node the graph and the rulepack can address, mirroring how k8s emits an Ingress separately
    from the Service behind it."""
    zid = z.get("id")
    steps = [_step_facts(s, i) for i, s in enumerate(z.get("steps") or [])]
    trigger = steps[0] if steps else None
    actions = steps[1:] if len(steps) > 1 else []
    enabled = bool(z.get("is_enabled", True))

    webhook_trigger = bool(trigger and _is_webhook_app(trigger["app"]))
    email_trigger = bool(trigger and _is_email_app(trigger["app"]))
    anonymous_trigger = webhook_trigger or email_trigger

    connection_ids = sorted({s["authentication_id"] for s in steps if s.get("authentication_id")})
    apps = sorted({_app_label(s["app"]) for s in steps if s["app"].get("id") or s["app"].get("key")})
    production_writes = [
        {"index": s["index"], "app": _app_label(s["app"]), "action_key": s["action_key"],
         "action_type": s["action_type"], "authentication_id": s["authentication_id"]}
        for s in actions
        if s["expanded"] and is_production_app(s["app"])
        and (s["action_type"] or "").upper() in _WRITE_ACTION_TYPES
    ]
    unexpanded = [s["index"] for s in steps if not s["expanded"]]

    zap = Resource(
        kind="zapier_zap",
        name=str(z.get("title") or zid or "?"),
        ext_id=f"zapier-zap-{zid}",
        labels={"enabled": "true" if enabled else "false",
                "anonymous_trigger": "true" if anonymous_trigger else "false",
                "connection_count": str(len(connection_ids))},
        raw={
            "id": zid,
            "title": z.get("title"),
            "is_enabled": enabled,
            "last_successful_run_date": z.get("last_successful_run_date"),
            "updated_at": z.get("updated_at"),
            "editor_url": (z.get("links") or {}).get("html_editor"),
            "step_count": len(steps),
            "steps_unexpanded": unexpanded,
            "trigger": trigger,
            "actions": [{"index": s["index"], "app": _app_label(s["app"]),
                         "action_key": s["action_key"], "action_type": s["action_type"],
                         "authentication_id": s["authentication_id"]} for s in actions],
            "apps": apps,
            # id → {key, title} for every expanded app in this Zap; assemble() uses it to name
            # connections whose /v2/authentications entry carries only the app id.
            "apps_by_id": {s["app"]["id"]: {"key": s["app"].get("key"), "title": s["app"].get("title")}
                           for s in steps if s["app"].get("id") and s["expanded"]},
            "connection_ids": connection_ids,
            "has_webhook_trigger": webhook_trigger,
            "has_email_trigger": email_trigger,
            "has_anonymous_trigger": anonymous_trigger,
            "production_writes": production_writes,
        },
    )
    resources = [zap]
    edges = [Edge(src_ext_id=zap.ext_id, dst_ext_id=f"zapier-connection-{cid}", kind="uses")
             for cid in connection_ids]

    if webhook_trigger:
        hook = Resource(
            kind="zapier_webhook_trigger",
            name=f"{zap.name} ({trigger['action_key'] or 'catch_hook'})",
            ext_id=f"zapier-webhook-{zid}",
            labels={"zap_enabled": "true" if enabled else "false",
                    "writes_to_production": "true" if production_writes else "false"},
            raw={
                "zap_id": zid,
                "zap_title": z.get("title"),
                "is_enabled": enabled,
                "app": _app_label(trigger["app"]),
                "action_key": trigger["action_key"],
                # Zapier Catch Hook URLs carry no authentication; the API does not return the
                # URL itself and this connector does not try to reconstruct it.
                "authentication": "none",
                "downstream_apps": apps,
                "production_writes": production_writes,
                "connection_ids": connection_ids,
            },
        )
        resources.append(hook)
        edges.append(Edge(src_ext_id=hook.ext_id, dst_ext_id=zap.ext_id, kind="triggers"))
    return resources, edges


def parse_authentication(a: dict, used_by: list, *, owner: dict | None = None,
                         owner_readable: bool = True) -> Resource:
    """One authentication (from /v2/authentications or an expanded zap step) → zapier_connection.
    Metadata only: id, app, title, expiry, owner. The grant/key the connection wraps is never
    returned by the API and never stored. `owner` is the /v1/profiles/me user when readable; the
    Authentications endpoint returns only connections that user owns, so that is the attribution
    the API offers. `owner_readable=False` records that the profile call failed, so the rulepack
    answers not-assessable rather than 'owner unknown'."""
    app = _app_facts(a.get("app"))
    aid = a.get("id")
    auth_type = a.get("auth_type") or a.get("authentication_type")
    actions = []
    for z in used_by:
        for st in z.get("actions") or []:
            if st.get("authentication_id") == aid:
                actions.append({"zap_id": z.get("id"), "app": st.get("app"),
                                "action_key": st.get("action_key"),
                                "action_type": st.get("action_type")})
    return Resource(
        kind="zapier_connection",
        name=str(a.get("title") or aid or "?"),
        ext_id=f"zapier-connection-{aid}",
        labels={"app": _app_label(app), "used_by_count": str(len(used_by)),
                "expired": "true" if a.get("is_expired") else "false",
                "owner": str((owner or {}).get("email") or "")},
        raw={
            "id": aid,
            "title": a.get("title"),
            "app": app,
            "auth_type": auth_type,                 # not in the current schema; read when present
            "is_expired": a.get("is_expired"),
            "owner": owner,                         # {id, email, full_name, deactivated?} or None
            "owner_readable": owner_readable,
            "used_by_zaps": [z.get("id") for z in used_by],
            "used_by_enabled_zaps": [z.get("id") for z in used_by if z.get("is_enabled")],
            "used_by_anonymous_trigger_zaps": [z.get("id") for z in used_by
                                               if z.get("has_anonymous_trigger")],
            "actions": actions,
        },
    )


def build_account(base: str, *, profile: dict | None, account_id: str | None,
                  outcomes: dict, zap_count: int, connection_count: int) -> Resource:
    """The zapier_account resource: who the token is, what was readable, and the inventory sizes.
    The `collection` map is per endpoint: {"outcome": ok|forbidden|not_found|error, …}."""
    host = _origin(base)
    ident = str(account_id or (profile or {}).get("email") or (profile or {}).get("id") or host)
    return Resource(
        kind="zapier_account",
        name=ident,
        ext_id=f"zapier-account-{ident}",
        labels={"host": host,
                "zaps_readable": "true" if outcomes.get("zaps", {}).get("outcome") == "ok" else "false",
                "connections_readable": "true"
                if outcomes.get("authentications", {}).get("outcome") == "ok" else "false"},
        raw={
            "base_url": base,
            "account_id": account_id,
            "profile": profile,
            "zap_count": zap_count,
            "connection_count": connection_count,
            "collection": outcomes,
        },
    )


# ── collection: httpx in, per-endpoint outcome recording ─────────────────────
def _outcome_for(e: Exception) -> dict:
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code in (401, 403):
            return {"outcome": "forbidden", "status": code, "error": f"HTTP {code}"}
        if code == 404:
            return {"outcome": "not_found", "status": code, "error": "HTTP 404"}
        return {"outcome": "error", "status": code, "error": f"HTTP {code}"}
    return {"outcome": "error", "error": f"{type(e).__name__}: {e}"}


def _pages(body) -> list:
    """/v2/zaps documents its 200 body as an ARRAY of page objects; /v2/authentications as a
    single page. Both reduce to [page, …]."""
    if isinstance(body, list):
        return [p for p in body if isinstance(p, dict)]
    return [body] if isinstance(body, dict) else []


def _paginate(client: httpx.Client, url: str, params: dict, limit: int = 100) -> list:
    """Walk a Workflow API list to exhaustion by offset. Terminates on an empty page, on
    `links.next == null`, or when offset reaches `meta.count` — never on a short page alone."""
    out, offset = [], 0
    while True:
        r = client.get(url, params={**params, "limit": limit, "offset": offset})
        r.raise_for_status()
        pages = _pages(r.json())
        got, count, has_next = 0, None, False
        for page in pages:
            data = page.get("data") or []
            out.extend(d for d in data if isinstance(d, dict))
            got += len(data)
            meta = page.get("meta") or {}
            count = meta.get("count", count)
            has_next = has_next or bool((page.get("links") or {}).get("next"))
        if got == 0:
            break
        offset += got
        if count is not None and offset >= int(count):
            break
        if not has_next and got < limit:
            break
    return out


ZAP_EXPAND = "steps.action,steps.authentication"


@connector("zapier", fields=[
    ConnectorField("base_url", "API base URL", placeholder=DEFAULT_BASE_URL,
                   help="Root of the Zapier Workflow API. Leave as https://api.zapier.com unless "
                        "Zapier gives you a regional or dedicated host. GETs only."),
    ConnectorField("access_token", "Access token", required=True, secret=True,
                   help="An OAuth2 bearer token for the Zapier Workflow API, issued to a Zapier "
                        "OAuth app with scopes zap:all (or zap:account:all for a Team/Enterprise "
                        "account), connection:read and profile. The connector reads Zaps, "
                        "connections and the token's profile; it never creates, edits, runs or "
                        "deletes a Zap, and connection secrets are not exposed by the API."),
    ConnectorField("account_id", "Account ID", placeholder="123456",
                   help="Optional Team/Enterprise account id, recorded on the account resource. "
                        "When set, Zaps shared within the account are included (needs "
                        "zap:account:all)."),
])
def collect(config: dict) -> Collected:
    base = (config.get("base_url") or DEFAULT_BASE_URL).strip().rstrip("/")
    token = (config.get("access_token") or "").strip()
    if not token:
        raise SystemExit("zapier connector requires config['access_token']")
    account_id = (str(config.get("account_id") or "").strip()) or None
    timeout = float(config.get("timeout") or 20)
    verify = config.get("verify", True)
    outcomes: dict = {}

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    profile, zaps_raw, auths_raw = None, [], {}
    with httpx.Client(timeout=timeout, verify=verify, headers=headers,
                      follow_redirects=False) as client:
        # 1. who the token is — the owner of every connection it can see
        try:
            r = client.get(f"{base}/v1/profiles/me")
            r.raise_for_status()
            body = r.json()
            profile = body[0] if isinstance(body, list) and body else (body if isinstance(body, dict) else None)
            outcomes["profile"] = {"outcome": "ok"}
        except Exception as e:
            outcomes["profile"] = _outcome_for(e)

        # 2. the Zap inventory, expanded so apps and connections are named, not just ids
        params = {"expand": ZAP_EXPAND}
        if account_id:
            params["include_shared"] = "true"
        try:
            zaps_raw = _paginate(client, f"{base}/v2/zaps", params)
            outcomes["zaps"] = {"outcome": "ok", "count": len(zaps_raw)}
        except Exception as e:
            outcomes["zaps"] = _outcome_for(e)

        # 3. connections, per app seen — finds the ones no Zap uses
        app_ids: set = set()
        for z in zaps_raw:
            for s in z.get("steps") or []:
                if not isinstance(s, dict):
                    continue
                action = s.get("action")
                if isinstance(action, dict):
                    app = action.get("app")
                    aid = app.get("id") if isinstance(app, dict) else app
                    if aid:
                        app_ids.add(str(aid))
                auth = s.get("authentication")
                if isinstance(auth, dict) and auth.get("id"):
                    auths_raw.setdefault(auth["id"], auth)
        per_app: dict = {}
        for aid in sorted(app_ids):
            try:
                for a in _paginate(client, f"{base}/v2/authentications", {"app": aid}):
                    if a.get("id"):
                        auths_raw[a["id"]] = {**auths_raw.get(a["id"], {}), **a}
                per_app[aid] = {"outcome": "ok"}
            except Exception as e:
                per_app[aid] = _outcome_for(e)
        if not app_ids:
            # Nothing to ask for: either no Zaps or Zaps were unreadable. Mirror the zaps outcome
            # so the account rule does not read "no apps" as "connections readable".
            outcomes["authentications"] = (
                {"outcome": "ok", "count": 0} if outcomes["zaps"].get("outcome") == "ok"
                else {"outcome": "skipped", "error": "zaps unreadable, no apps to query"})
        else:
            bad = [o for o in per_app.values() if o.get("outcome") != "ok"]
            outcomes["authentications"] = {
                "outcome": "ok" if not bad else bad[0]["outcome"],
                "count": len(auths_raw), "apps_queried": len(app_ids),
                "apps_failed": len(bad), "per_app": per_app}

    return assemble(base, account_id=account_id, profile=profile, zaps_raw=zaps_raw,
                    auths_raw=list(auths_raw.values()), outcomes=outcomes)


def assemble(base: str, *, account_id, profile, zaps_raw: list, auths_raw: list,
             outcomes: dict) -> Collected:
    """Pure: the raw API bodies → the full Collected. Split from collect() so the fixture test can
    run the exact wiring (dedup, used_by, owner attribution) without httpx."""
    resources: list[Resource] = []
    edges: list[Edge] = []

    zap_resources: list[Resource] = []
    for z in zaps_raw:
        rs, es = parse_zap(z)
        zap_resources.extend(r for r in rs if r.kind == "zapier_zap")
        resources.extend(rs)
        edges.extend(es)

    # connections referenced by Zaps but not returned by /v2/authentications are still real
    by_id = {a.get("id"): dict(a) for a in auths_raw if a.get("id")}
    for zr in zap_resources:
        for st in [zr.raw.get("trigger")] + list(zr.raw.get("actions") or []):
            if not st:
                continue
            emb = st.get("authentication") if isinstance(st.get("authentication"), dict) else None
            cid = st.get("authentication_id")
            if cid and cid not in by_id:
                by_id[cid] = {"id": cid, **({"title": emb.get("title"), "app": emb.get("app"),
                                             "is_expired": emb.get("is_expired")} if emb else {})}

    # name bare app ids from what the expanded Zap steps told us about each app
    apps_by_id: dict = {}
    for zr in zap_resources:
        apps_by_id.update(zr.raw.get("apps_by_id") or {})
    for a in by_id.values():
        app = a.get("app")
        if not isinstance(app, dict) and app in apps_by_id:
            a["app"] = {"id": app, **apps_by_id[app]}

    owner_readable = outcomes.get("profile", {}).get("outcome") == "ok"
    owner = ({"id": profile.get("id"), "email": profile.get("email"),
              "full_name": profile.get("full_name"),
              "deactivated": bool(profile.get("is_deactivated") or profile.get("deactivated"))}
             if isinstance(profile, dict) else None)
    for cid, a in by_id.items():
        used_by = [zr.raw for zr in zap_resources if cid in (zr.raw.get("connection_ids") or [])]
        resources.append(parse_authentication(a, used_by, owner=owner, owner_readable=owner_readable))

    account = build_account(base, profile=profile, account_id=account_id, outcomes=outcomes,
                            zap_count=len(zap_resources), connection_count=len(by_id))
    resources.insert(0, account)
    for zr in zap_resources:
        edges.append(Edge(src_ext_id=account.ext_id, dst_ext_id=zr.ext_id, kind="owns"))
    for cid in by_id:
        edges.append(Edge(src_ext_id=account.ext_id, dst_ext_id=f"zapier-connection-{cid}",
                          kind="holds"))
    return Collected(resources=resources, edges=edges)


# ── NHI: connections → automation identities + credential metadata + per-action grants ───
def _credential_type(auth_type) -> str:
    """The API does not return how an authentication authenticates to its app; when a future
    schema (or an expanded step) carries it, map it; otherwise say 'app_connection' rather than
    guess oauth2 for a key-auth app."""
    t = (auth_type or "").strip().lower().replace("-", "_")
    if t in ("oauth2", "oauth", "oauth1", "oauth_2"):
        return "oauth2"
    if t in ("api_key", "apikey", "key", "basic", "session", "custom", "digest"):
        return "api_key"
    return "app_connection"


@identity_extractor("zapier")
def _from_zapier(resources: list) -> tuple:
    """The normalized NHI model for Zapier:

      zapier_connection → identity (identity_type "automation_connection", system "zapier",
                          external=True) + credential (oauth2 / api_key / app_connection by the
                          authentication's auth type; present=True, never a value) + one grant per
                          distinct (app, action) a Zap performs with it, merged across Zaps.

    Edges: credential --credential_of--> identity, grant --granted_to--> identity, and
    grant --grants_access--> every zapier_zap that performs the action.
    """
    out: list[Resource] = []
    edges: list[Edge] = []
    for r in resources:
        if r.kind != "zapier_connection":
            continue
        raw = r.raw or {}
        app = _app_label(raw.get("app") or {})
        label = f"{app}:{raw.get('title') or raw.get('id')}"
        owner = raw.get("owner") or {}
        idr = _mk_identity("zapier", "automation_connection", label, external=True,
                           source_ext=r.ext_id,
                           tags=(["expired"] if raw.get("is_expired") else []),
                           extra={"app": app, "connection_id": raw.get("id"),
                                  "owner_email": owner.get("email"),
                                  "owner_readable": raw.get("owner_readable"),
                                  "used_by_zaps": raw.get("used_by_zaps") or []})
        out.append(idr)

        ctype = _credential_type(raw.get("auth_type"))
        cred = _mk_credential("zapier", idr.ext_id, ctype, name=f"{label}:{ctype}",
                              hashing="zapier_managed", present=True, plaintext=False,
                              count=len(raw.get("used_by_zaps") or []),
                              extra={"auth_type_known": ctype != "app_connection",
                                     "is_expired": raw.get("is_expired"),
                                     "reachable_anonymously":
                                         bool(raw.get("used_by_anonymous_trigger_zaps"))})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        merged: dict = {}
        for act in raw.get("actions") or []:
            key = (act.get("app") or app, act.get("action_key") or "action")
            entry = merged.setdefault(key, {"zap_ids": [], "action_type": act.get("action_type")})
            if act.get("zap_id") not in entry["zap_ids"]:
                entry["zap_ids"].append(act.get("zap_id"))
        for (tapp, akey), entry in merged.items():
            production_write = (entry["action_type"] or "").upper() in _WRITE_ACTION_TYPES and \
                is_production_app({"key": tapp, "title": tapp})
            g = _mk_grant("zapier", idr.ext_id, f"{tapp}.{akey}", tapp, wildcard=False,
                          extra={"action_type": entry["action_type"], "zap_ids": entry["zap_ids"],
                                 "production_write": production_write})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            for zid in entry["zap_ids"]:
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=f"zapier-zap-{zid}",
                                  kind="grants_access"))
    return out, edges
