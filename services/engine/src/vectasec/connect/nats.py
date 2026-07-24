"""NATS / JetStream connector — read-only HTTP monitoring (httpx) + optional config model.

NATS is the integration-layer backbone of a growing number of agent/event platforms, so its
posture belongs in an integration-security tool. This connector reads two things and writes
nothing:

  monitoring endpoints  GET /varz, /jsz, /connz on the HTTP monitoring port (:8222 by default).
                        /varz carries the server-wide security posture the way it was actually
                        loaded: auth_required, tls_required, tls_verify, version, system_account.
                        These endpoints have NO authentication mechanism of their own (they are
                        meant to be network-isolated + TLS-fronted), which is itself a finding
                        surface — NATS.MONITORING.UNAUTHENTICATED.
  config (optional)     the account / authorization / no_auth_user / leafnode / gateway model,
                        supplied as JSON. nats-server's own config format is a JSON superset, so
                        an operator can hand us their nats-server.conf converted to JSON (or the
                        JSON they already template) and we read the account structure from it.
                        The no_auth_user → $SYS mapping — unauthenticated clients silently landing
                        in the SYSTEM account — is only visible in the config, so that check is
                        config-driven and reports NOT ASSESSABLE when no config was provided.

Credential discipline (same contract as redis/rabbitmq): a user's `password`, `nkey` or `jwt` is
read ONLY to learn that a credential EXISTS. Its value never enters a Resource — only the
booleans has_password/has_nkey/has_jwt and the (non-secret) subject permissions do. The parse
layer (build_resources) is pure: monitoring dicts + config dict in, Resources out, so httpx and a
live server stay out of the test suite.

Kinds are DISTINCT (nats_server, nats_account) so no other rulepack ever runs against a NATS
resource — the same reason connect/redis.py refuses to reuse `broker`.
"""
import json
from urllib.parse import urlparse

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector


def _load_config(config: dict) -> dict:
    """The nats-server config the operator handed us, as a dict. Accepts a JSON string or an
    already-parsed dict; anything unparseable is treated as 'no config provided' (the config
    checks then report NOT ASSESSABLE rather than reading absence as a clean pass)."""
    raw = config.get("config_json") or config.get("server_config")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except (ValueError, TypeError):
            return {}
    return {}


def _users_of_account(acct) -> list:
    """The users list inside an account block. NATS accepts both {"users": [...]} and a bare
    list; tolerate either so a hand-written config does not crash the parse."""
    if isinstance(acct, dict):
        return [u for u in (acct.get("users") or []) if isinstance(u, dict)]
    if isinstance(acct, list):
        return [u for u in acct if isinstance(u, dict)]
    return []


def _user_flags(u: dict, index: int) -> dict:
    """Reduce a user block to metadata. The credential VALUE dies here — only presence booleans
    and the (non-secret) subject permissions survive."""
    name = u.get("user") or u.get("nkey") or f"user-{index}"
    has_password = bool(u.get("password") or u.get("pass"))
    has_nkey = bool(u.get("nkey"))
    has_jwt = bool(u.get("jwt"))
    return {
        "user": name,
        "has_password": has_password,
        "has_nkey": has_nkey,
        "has_jwt": has_jwt,
        "has_credential": has_password or has_nkey or has_jwt,
        "permissions": u.get("permissions") if isinstance(u.get("permissions"), dict) else {},
    }


def _no_auth_user(config: dict):
    """no_auth_user is top-level in modern configs and historically lived under authorization."""
    return (config.get("no_auth_user")
            or (config.get("authorization") or {}).get("no_auth_user"))


def _resolve_no_auth_user(name, accounts: dict, global_users: list, system_account):
    """(account_name, is_system). Which account the no_auth_user lands in, and whether that is the
    system account — the difference between 'anonymous clients get a scoped app account' and
    'anonymous clients get the SYSTEM account'."""
    if not name:
        return None, False
    for u in global_users or []:
        if u.get("user") == name or u.get("nkey") == name:
            return "$G", ("$G" == system_account)
    for acct_name, acct in (accounts or {}).items():
        for u in _users_of_account(acct):
            if u.get("user") == name or u.get("nkey") == name:
                return acct_name, (acct_name == system_account)
    return None, False   # named but not found in any readable account block


def _has_tls_block(block) -> bool:
    return isinstance(block, dict) and bool(block.get("tls"))


def build_resources(*, varz: dict | None, jsz: dict | None, connz: dict | None,
                    base_url: str, scheme: str, tls_verified: bool,
                    monitoring_unauthenticated: bool, config: dict,
                    varz_error: str | None = None) -> Collected:
    """Pure normalisation: monitoring dicts + config dict → Collected. httpx never appears here,
    so tests exercise detectors against exactly what collect() would have produced."""
    v = varz or {}
    cfg = config or {}
    accounts = cfg.get("accounts") if isinstance(cfg.get("accounts"), dict) else {}
    authorization = cfg.get("authorization") if isinstance(cfg.get("authorization"), dict) else {}
    global_users = [u for u in (authorization.get("users") or []) if isinstance(u, dict)]
    system_account = v.get("system_account") or cfg.get("system_account")
    config_provided = bool(cfg)

    no_auth = _no_auth_user(cfg)
    na_account, na_is_system = _resolve_no_auth_user(no_auth, accounts, global_users, system_account)

    leaf = cfg.get("leafnodes") if isinstance(cfg.get("leafnodes"), dict) else None
    gw = cfg.get("gateway") if isinstance(cfg.get("gateway"), dict) else (
        cfg.get("gateways") if isinstance(cfg.get("gateways"), dict) else None)

    host = urlparse(base_url).hostname or base_url
    server_ext = f"nats-{host}"
    server = Resource(
        kind="nats_server",
        name=host,
        ext_id=server_ext,
        labels={"version": str(v.get("version") or "?"),
                "auth_required": str(v.get("auth_required"))},
        raw={
            "version": v.get("version"),
            "auth_required": v.get("auth_required"),
            "tls_required": v.get("tls_required"),
            "tls_verify": v.get("tls_verify"),
            "system_account": system_account,
            "jetstream_enabled": jsz is not None,
            "jetstream_account_count": (jsz or {}).get("total") if isinstance(jsz, dict) else None,
            "connection_count": (connz or {}).get("num_connections") if isinstance(connz, dict) else None,
            "monitoring_url": base_url,
            "monitoring_scheme": scheme,
            "monitoring_tls_verified": tls_verified,
            "monitoring_unauthenticated": monitoring_unauthenticated,
            "varz_readable": varz is not None,
            "varz_error": varz_error,
            "config_provided": config_provided,
            "no_auth_user": no_auth,
            "no_auth_user_account": na_account,
            "no_auth_user_is_system": na_is_system,
            "leafnodes_configured": leaf is not None,
            "leafnodes_tls": _has_tls_block(leaf) if leaf is not None else None,
            "gateway_configured": gw is not None,
            "gateway_tls": _has_tls_block(gw) if gw is not None else None,
        },
    )
    resources: list[Resource] = [server]
    edges: list[Edge] = []

    def _emit_account(acct_name: str, acct_cfg, users: list):
        is_system = acct_name == system_account
        jetstream = bool(acct_cfg.get("jetstream")) if isinstance(acct_cfg, dict) else False
        user_flags = [_user_flags(u, i) for i, u in enumerate(users)]
        ext = f"{server_ext}-account-{acct_name}"
        resources.append(Resource(
            kind="nats_account",
            name=acct_name,
            ext_id=ext,
            namespace=acct_name,
            labels={"is_system": "true" if is_system else "false"},
            raw={
                "name": acct_name,
                "is_system_account": is_system,
                "jetstream_enabled": jetstream,
                "users": user_flags,
                "user_count": len(user_flags),
                "server_ext": server_ext,
            },
        ))
        edges.append(Edge(src_ext_id=server_ext, dst_ext_id=ext, kind="hosts"))

    for acct_name, acct_cfg in accounts.items():
        _emit_account(acct_name, acct_cfg, _users_of_account(acct_cfg))
    # Global users live in the implicit default account "$G"; emit it so NHI sees them too.
    if global_users and "$G" not in accounts:
        _emit_account("$G", {}, global_users)

    return Collected(resources=resources, edges=edges)


def _get(client: httpx.Client, path: str, auth):
    """One monitoring read → an envelope (never a bare value): a non-200 must stay distinguishable
    from an empty body, or a rule gated on this endpoint silently passes."""
    try:
        r = client.get(path, auth=auth)
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code != 200:
        return {"ok": False, "status": r.status_code, "error": f"http_{r.status_code}"}
    try:
        return {"ok": True, "status": 200, "data": r.json()}
    except ValueError:
        return {"ok": False, "status": 200, "error": "non_json_body"}


@connector("nats", fields=[
    ConnectorField("monitoring_url", "Monitoring URL", required=True,
                   placeholder="http://localhost:8222",
                   help="NATS HTTP monitoring base URL (the -m / http port, 8222 by default). "
                        "GETs only: /varz, /jsz, /connz. These endpoints have no auth of their "
                        "own and should be network-isolated behind TLS."),
    ConnectorField("username", "Monitoring username",
                   help="Only if a reverse proxy in front of the monitoring port adds HTTP "
                        "Basic. NATS itself does not authenticate /varz."),
    ConnectorField("password", "Monitoring password", secret=True,
                   help="Used to open the monitoring request, never stored in any resource."),
    ConnectorField("config_json", "Server config (JSON)",
                   help="Optional. The nats-server configuration as JSON (accounts, "
                        "authorization, no_auth_user, leafnodes, gateway). nats-server's config "
                        "format is a JSON superset, so a converted nats-server.conf works. "
                        "Required for the account / no_auth_user / leafnode / gateway checks; "
                        "without it those report 'not assessable'."),
])
def collect(config: dict) -> Collected:
    base = (config.get("monitoring_url") or "").rstrip("/")
    if not base:
        raise SystemExit("nats connector requires config['monitoring_url'] "
                         "(e.g. http://localhost:8222)")
    username = (config.get("username") or "").strip()
    password = config.get("password") or ""
    auth = (username, password) if username else None
    verify = config.get("verify_tls", True)
    timeout = float(config.get("timeout") or 10)
    scheme = urlparse(base).scheme or "http"

    with httpx.Client(base_url=base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False, auth=None) as client:
        varz_res = _get(client, "/varz", auth)
        jsz_res = _get(client, "/jsz", auth)
        connz_res = _get(client, "/connz", auth)

    return build_resources(
        varz=varz_res.get("data") if varz_res.get("ok") else None,
        jsz=jsz_res.get("data") if jsz_res.get("ok") else None,
        connz=connz_res.get("data") if connz_res.get("ok") else None,
        base_url=base,
        scheme=scheme,
        tls_verified=(scheme == "https" and verify is True and varz_res.get("status") is not None),
        # NATS monitoring has no native auth; if we did not present credentials and still read
        # /varz, the monitoring surface is unauthenticated.
        monitoring_unauthenticated=(auth is None and varz_res.get("ok") is True),
        config=_load_config(config),
        varz_error=None if varz_res.get("ok") else varz_res.get("error"),
    )


# ── NHI: NATS accounts/users → identity / credential / grant ──────────────────
@identity_extractor("nats")
def _from_nats(resources: list) -> tuple:
    """The server's non-human identities in the normalized model:

      nats user   → identity (service_account), named "<account>/<user>". Tagged
                    'system_account' when it lives in the SYSTEM account and 'anonymous_mapped'
                    when no_auth_user points at it (unauthenticated clients become this user).
      credential  → one per user that carries a password / nkey / jwt (metadata only — the
                    connector never collected a value).
      grant       → one per publish/subscribe subject in the user's permissions; a user with NO
                    permissions block has full subject access in NATS, recorded as a wildcard
                    grant on ">" so that over-privilege is not silently invisible.
    """
    out: list[Resource] = []
    edges: list[Edge] = []
    server = next((r for r in resources if r.kind == "nats_server"), None)
    no_auth_user = (server.raw or {}).get("no_auth_user") if server else None

    for r in resources:
        if r.kind != "nats_account":
            continue
        acct = r.raw or {}
        acct_name = acct.get("name")
        is_system = bool(acct.get("is_system_account"))
        for u in acct.get("users") or []:
            uname = u.get("user")
            full = f"{acct_name}/{uname}"
            tags = []
            if is_system:
                tags.append("system_account")
            if no_auth_user and uname == no_auth_user:
                tags.append("anonymous_mapped")
            idr = _mk_identity("nats", "service_account", full, tags=tags, source_ext=r.ext_id,
                               extra={"account": acct_name, "no_auth_mapped": uname == no_auth_user})
            out.append(idr)

            if u.get("has_credential"):
                ctype = "nkey" if u.get("has_nkey") else "jwt" if u.get("has_jwt") else "password"
                cred = _mk_credential("nats", idr.ext_id, ctype, name=f"{full}:{ctype}",
                                      hashing="n/a", present=True, plaintext=False)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                                  kind="credential_of"))

            perms = u.get("permissions") or {}
            emitted_grant = False
            for direction in ("publish", "subscribe"):
                spec = perms.get(direction)
                if isinstance(spec, dict):
                    subjects = spec.get("allow")
                else:
                    subjects = spec
                subjects = subjects if isinstance(subjects, list) else ([subjects] if subjects else [])
                for subj in subjects:
                    wildcard = str(subj) in (">", "*") or str(subj).endswith(">")
                    g = _mk_grant("nats", idr.ext_id, direction, str(subj), wildcard=wildcard,
                                  extra={"account": acct_name})
                    out.append(g)
                    edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
                    emitted_grant = True
            if not perms and not emitted_grant:
                # No permissions block == unrestricted publish/subscribe on all subjects.
                g = _mk_grant("nats", idr.ext_id, "all", ">", wildcard=True,
                              extra={"account": acct_name,
                                     "reason": "no permissions block: full subject access"})
                out.append(g)
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
