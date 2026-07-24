"""Coordination / service-discovery / config control-plane connector — read-only posture.

This is the connector that scans the systems every OTHER connector implicitly trusts: the
service registries, distributed locks, leader elections and dynamic-config stores that the
brokers, gateways and meshes VectaSec assesses are themselves wired through. Compromise the
coordination layer and you own the control plane — you can repoint a mesh's discovery, rewrite
a gateway's dynamic config, or hand yourself a leader lease. So its posture belongs squarely in
an integration-security tool.

One connector, four distinct systems, selected by config['system']:

  etcd        v3 HTTP gateway (:2379). /version, /v3/maintenance/status, an unauthenticated
              /v3/auth/user/list probe (its error text reveals whether RBAC auth is enabled),
              an unauthenticated /v3/kv/range probe (does the keyspace answer with no token?),
              and a plaintext probe of the peer port (:2380) for peer-TLS enablement.
  zookeeper   four-letter words over a raw socket (:2181): `ruok`, `conf`, `envi`, `stat`. Which
              commands answer proves the 4lw whitelist exposure; `conf` carries the client/secure
              ports and (on servers that dump it) the SASL enforcement flag.
  nacos       HTTP (:8848). /nacos/v1/console/server/state (version + auth_enabled), a console
              reachability probe, a default-credential login probe (nacos/nacos), and the
              CVE-2021-29441 auth-bypass probe (the `Nacos-Server` User-Agent backdoor).
  consul      HTTP (:8500). /v1/agent/self (ACLsEnabled, ACLDefaultPolicy, serf gossip
              encryption), the anonymous token's attached policies, and the intentions list
              (a `*`→`*` allow intention is service-mesh-wide trust).

Three disciplines carried from the other connectors:

  • Credentials are used, never persisted. `password`/`token` are ConnectorField secret=True; a
    Consul ACL token's SecretID is never read (only the AccessorID + Description via the list
    API), Nacos passwords are hashed server-side and never returned, etcd passwords are never
    exposed. A credential resource records that a secret EXISTS, never its value.
  • The third honest outcome. Every check the target hides (auth port firewalled, 4lw command
    off the whitelist, agent/self denied) is recorded as unreadable so detect/coordination.py can
    answer "not assessable" — never a fabricated pass, never a fabricated failure.
  • DISTINCT kinds prefixed `coord_` (coord_etcd, coord_zookeeper, coord_nacos, coord_consul) so
    no other rulepack ever runs against a coordination resource by accident — the same reason
    connect/redis.py refuses to reuse `broker`.

The parse layer (parse_etcd, parse_zookeeper, parse_nacos, parse_consul) is pure: raw HTTP JSON
dicts and 4lw text in, Resources out. Tests exercise detectors against parse-layer output from
golden fixtures, so httpx and raw sockets (and a live cluster) stay out of the test suite and a
shape drift between connector and rulepack fails a test instead of mis-firing in production.
"""
import base64

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_DEFAULT_PORTS = {"etcd": 2379, "zookeeper": 2181, "nacos": 8848, "consul": 8500}
_ETCD_PEER_DEFAULT = 2380


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _err_text(body) -> str:
    """The lower-cased error/message string out of a gRPC-gateway or REST error body (dict or
    raw text). '' when there is nothing that looks like an error."""
    if isinstance(body, dict):
        return str(body.get("error") or body.get("message") or "").lower()
    if isinstance(body, str):
        return body.lower()
    return ""


# ══ etcd ═══════════════════════════════════════════════════════════════════════
def _etcd_auth_state(auth_probe) -> tuple:
    """(auth_enabled, assessable) from an UNauthenticated POST /v3/auth/user/list. etcd answers
    'authentication is not enabled' when RBAC is off; 'user name is empty' / permission-denied /
    401 when RBAC is on and demanding a token. A 200 that carries a `users` list means RBAC is
    on but the list was readable without auth (still auth_enabled=True)."""
    if not auth_probe:
        return None, False
    status = auth_probe.get("status")
    body = auth_probe.get("body")
    err = _err_text(body)
    if "authentication is not enabled" in err:
        return False, True
    if status == 200 and isinstance(body, dict) and "users" in body:
        return True, True
    if status in (401, 403) or "user name is empty" in err or "permission denied" in err \
            or "invalid auth token" in err or "user name not found" in err:
        return True, True
    return None, False


def _etcd_unauth_read(kv_probe) -> tuple:
    """(unauth_read_ok, assessable) from an UNauthenticated POST /v3/kv/range. A 200 carrying a
    cluster `header` means the keyspace answered with no credential — an empirical read, distinct
    from the RBAC-config fact above. An auth error means the read was refused."""
    if not kv_probe:
        return None, False
    status = kv_probe.get("status")
    body = kv_probe.get("body")
    err = _err_text(body)
    if status == 200 and isinstance(body, dict) and "header" in body:
        return True, True
    if status in (401, 403) or "user name is empty" in err or "permission denied" in err \
            or "invalid auth token" in err:
        return False, True
    return None, False


def _etcd_peer_tls(peer_probe) -> tuple:
    """(peer_tls_on, assessable) from a PLAINTEXT probe of the peer port (:2380). A plaintext
    HTTP response proves peer TLS is OFF; a TLS handshake on the plaintext attempt proves it is
    ON. An unreachable/firewalled peer port is not assessable — the client API never carries
    peer-TLS config, so this network probe is the only honest signal."""
    if not peer_probe:
        return None, False
    if peer_probe.get("plaintext_http"):
        return False, True
    if peer_probe.get("tls_detected"):
        return True, True
    return None, False


def _etcd_list(probe, key):
    if probe and probe.get("status") == 200 and isinstance(probe.get("body"), dict):
        v = probe["body"].get(key)
        if isinstance(v, list):
            return [str(x) for x in v]
    return None


def parse_etcd(host, port, *, tls, version_json, status_json, auth_probe, role_probe,
               kv_probe, peer_probe, peer_port=None, user_roles=None) -> Resource:
    version = None
    cluster_version = None
    if isinstance(version_json, dict):
        version = version_json.get("etcdserver")
        cluster_version = version_json.get("etcdcluster")
    if not version and isinstance(status_json, dict):
        version = status_json.get("version") or status_json.get("Version")
    reachable = bool(version_json or status_json)

    auth_enabled, auth_assessable = _etcd_auth_state(auth_probe)
    unauth_read_ok, read_assessable = _etcd_unauth_read(kv_probe)
    peer_tls_on, peer_assessable = _etcd_peer_tls(peer_probe)
    users = _etcd_list(auth_probe, "users")
    roles = _etcd_list(role_probe, "roles")

    return Resource(
        kind="coord_etcd",
        name=f"{host}:{port}",
        ext_id=f"coord-etcd-{host}:{port}",
        labels={"system": "etcd", "version": version or "?"},
        raw={
            "system": "etcd", "host": host, "port": port,
            "version": version, "cluster_version": cluster_version,
            "reachable": reachable,
            "connected_via_tls": bool(tls),
            "client_tls_assessable": reachable,
            "auth_enabled": auth_enabled, "auth_assessable": auth_assessable,
            "unauth_read_ok": unauth_read_ok, "unauth_read_assessable": read_assessable,
            "peer_port": peer_port,
            "peer_tls_on": peer_tls_on, "peer_tls_assessable": peer_assessable,
            "auth": {"users": users, "roles": roles, "readable": users is not None,
                     "user_roles": user_roles or {}},
        },
    )


# ══ ZooKeeper ══════════════════════════════════════════════════════════════════
_ZK_NOT_WHITELISTED = "is not executed because it is not in the whitelist"


def _zk_lines(text) -> dict:
    """`key=value` lines of a 4lw dump → dict. `conf` and `envi` are both key=value formats
    (envi leads with an 'Environment:' header line that has no '=' and is skipped)."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if "=" in line:
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _zk_command_answered(text) -> bool:
    """Did this specific command return output at all (ruok's `imok` counts)."""
    t = (text or "").strip()
    return bool(t) and _ZK_NOT_WHITELISTED not in t


def _zk_sasl(kv) -> tuple:
    """(sasl_required, assessable). Assessable ONLY when the server actually dumps
    `sessionRequireClientSASLAuth` — that flag is what forces clients to authenticate; without
    it, znodes carry the default world:anyone:cdrwa ACL and any client gets in. A dump that
    omits the flag cannot be assessed from 4lw (honest, not guessed)."""
    for key in ("sessionRequireClientSASLAuth", "zookeeper.sessionRequireClientSASLAuth"):
        if key in kv:
            return kv[key].strip().lower() == "true", True
    return None, False


def parse_zookeeper(host, port, *, tls, ruok, conf, envi, stat) -> Resource:
    conf_kv = _zk_lines(conf)
    envi_kv = _zk_lines(envi)
    merged = {**envi_kv, **conf_kv}

    version = None
    for k, v in envi_kv.items():
        if k == "zookeeper.version":
            version = v.split("-")[0].split(",")[0]

    answered = {"ruok": _zk_command_answered(ruok), "conf": _zk_command_answered(conf),
                "envi": _zk_command_answered(envi), "stat": _zk_command_answered(stat)}
    # conf/envi/stat leak config, environment and live sessions; ruok alone is harmless.
    sensitive_exposed = any(answered[c] for c in ("conf", "envi", "stat"))
    # We could reach the 4lw port and get SOME answer → the exposure question is assessable.
    fourlw_assessable = any(v is not None for v in (ruok, conf, envi, stat)) and \
        any(answered.values())

    sasl_required, sasl_assessable = _zk_sasl(merged)

    scp = conf_kv.get("secureClientPort")
    if scp is None:
        secure_tls, tls_assessable = None, False
    else:
        try:
            secure_tls, tls_assessable = int(scp) > 0, True
        except ValueError:
            secure_tls, tls_assessable = None, False

    return Resource(
        kind="coord_zookeeper",
        name=f"{host}:{port}",
        ext_id=f"coord-zookeeper-{host}:{port}",
        labels={"system": "zookeeper", "version": version or "?"},
        raw={
            "system": "zookeeper", "host": host, "port": port, "version": version,
            "connected_via_tls": bool(tls),
            "commands_answered": answered,
            "sensitive_4lw_exposed": sensitive_exposed,
            "fourlw_assessable": fourlw_assessable,
            "sasl_required": sasl_required, "sasl_assessable": sasl_assessable,
            "client_port": conf_kv.get("clientPort"),
            "secure_client_port": scp,
            "secure_tls": secure_tls, "tls_assessable": tls_assessable,
        },
    )


# ══ Nacos ══════════════════════════════════════════════════════════════════════
def _nacos_console(console_probe) -> tuple:
    if not console_probe:
        return None, False
    status = console_probe.get("status")
    if status == 200 and console_probe.get("is_html"):
        return True, True
    if status in (401, 403):
        return False, True
    return None, False


def _nacos_login(login_probe) -> tuple:
    """(default_creds_valid, assessable) from a POST login with nacos/nacos. A 200 carrying an
    accessToken means the shipped default credential still works; a 401/403 or 'unknown user' /
    'disabled' means it does not."""
    if not login_probe:
        return None, False
    status = login_probe.get("status")
    body = login_probe.get("body")
    if status == 200 and isinstance(body, dict) and (body.get("accessToken") or body.get("data")):
        return True, True
    err = _err_text(body)
    if status in (401, 403) or "unknown user" in err or "user not found" in err \
            or "disabled" in err or "password" in err:
        return False, True
    return None, False


def _nacos_bypass(bypass_probe) -> tuple:
    """(bypass_ok, assessable) from GET /nacos/v1/auth/users with User-Agent `Nacos-Server`. A
    200 that returns a user page proves the CVE-2021-29441 backdoor still bypasses auth; a 403
    proves it is patched/closed."""
    if not bypass_probe:
        return None, False
    status = bypass_probe.get("status")
    body = bypass_probe.get("body")
    if status == 200 and isinstance(body, dict) and (
            "pageItems" in body or "totalCount" in body):
        return True, True
    if status == 200 and isinstance(body, list):
        return True, True
    if status in (401, 403):
        return False, True
    return None, False


def _nacos_users(users_json):
    if isinstance(users_json, dict) and isinstance(users_json.get("pageItems"), list):
        return [str(u.get("username")) for u in users_json["pageItems"] if u.get("username")]
    if isinstance(users_json, list):
        return [str(u.get("username")) for u in users_json
                if isinstance(u, dict) and u.get("username")]
    return None


def parse_nacos(host, port, *, tls, state_json, console_probe, login_probe, bypass_probe,
                users_json=None, admin_users=None) -> Resource:
    version = None
    auth_enabled, auth_assessable = None, False
    if isinstance(state_json, dict):
        version = state_json.get("version") or state_json.get("Version")
        ae = state_json.get("auth_enabled")
        if ae is None:
            ae = state_json.get("authEnabled")
        if isinstance(ae, bool):
            auth_enabled, auth_assessable = ae, True
        elif isinstance(ae, str) and ae.strip().lower() in ("true", "false"):
            auth_enabled, auth_assessable = ae.strip().lower() == "true", True

    console_reachable, console_assessable = _nacos_console(console_probe)
    default_creds, creds_assessable = _nacos_login(login_probe)
    bypass_ok, bypass_assessable = _nacos_bypass(bypass_probe)
    users = _nacos_users(users_json)

    return Resource(
        kind="coord_nacos",
        name=f"{host}:{port}",
        ext_id=f"coord-nacos-{host}:{port}",
        labels={"system": "nacos", "version": version or "?"},
        raw={
            "system": "nacos", "host": host, "port": port, "version": version,
            "connected_via_tls": bool(tls),
            "auth_enabled": auth_enabled, "auth_assessable": auth_assessable,
            "console_reachable": console_reachable, "console_assessable": console_assessable,
            "default_creds_valid": default_creds, "creds_assessable": creds_assessable,
            "auth_bypass_ok": bypass_ok, "bypass_assessable": bypass_assessable,
            "users": users, "admin_users": admin_users or [],
        },
    )


# ══ Consul ═════════════════════════════════════════════════════════════════════
def _consul_acl(debug, cfg) -> tuple:
    """(acls_enabled, default_policy, assessable). Consul has moved the fields across versions:
    top-level DebugConfig.ACLsEnabled / DebugConfig.ACLDefaultPolicy on older builds, nested
    DebugConfig.ACL.{Enabled,DefaultPolicy} on newer ones. Read both shapes."""
    acl_block = debug.get("ACL") if isinstance(debug.get("ACL"), dict) else {}
    enabled = debug.get("ACLsEnabled")
    if enabled is None:
        enabled = acl_block.get("Enabled")
    default = debug.get("ACLDefaultPolicy") or acl_block.get("DefaultPolicy") \
        or cfg.get("ACLDefaultPolicy")
    default = str(default).lower() if default is not None else None
    assessable = enabled is not None or default is not None
    return (enabled if isinstance(enabled, bool) else None), default, assessable


def _consul_gossip(stats) -> tuple:
    serf = stats.get("serf_lan") if isinstance(stats.get("serf_lan"), dict) else {}
    enc = serf.get("encrypted")
    if enc is None:
        return None, False
    return str(enc).strip().lower() == "true", True


def _consul_anon(anon_token) -> tuple:
    """(anonymous_policy_names, assessable). Reading the anonymous token needs a management
    token; when we could not read it the anonymous grant surface is not assessable."""
    if not anon_token or anon_token.get("status") != 200:
        return None, False
    body = anon_token.get("body")
    if not isinstance(body, dict):
        return None, False
    names = [str(p.get("Name") or p.get("ID"))
             for p in (body.get("Policies") or []) if isinstance(p, dict)]
    # Roles and service identities are also grant surface on the anonymous token.
    names += [f"role:{r.get('Name') or r.get('ID')}"
              for r in (body.get("Roles") or []) if isinstance(r, dict)]
    return names, True


def _consul_wildcard_intentions(intentions) -> tuple:
    """(matched, assessable). A matched intention is an allow whose SourceName is '*' — an
    any-source allow, of which '*'→'*' is the mesh-wide worst case."""
    if intentions is None:
        return None, False
    matched = []
    for it in intentions:
        if not isinstance(it, dict):
            continue
        if str(it.get("SourceName")) == "*" and str(it.get("Action")).lower() == "allow":
            matched.append({"source": it.get("SourceName"), "destination": it.get("DestinationName"),
                            "action": it.get("Action")})
    return matched, True


def parse_consul(host, port, *, tls, agent_self, anon_token, intentions,
                 tokens=None, policies=None) -> Resource:
    cfg, debug, stats, version = {}, {}, {}, None
    if isinstance(agent_self, dict):
        cfg = agent_self.get("Config") or {}
        debug = agent_self.get("DebugConfig") or {}
        stats = agent_self.get("Stats") or {}
        version = cfg.get("Version") or debug.get("Version")

    acls_enabled, acl_default, acl_assessable = _consul_acl(debug, cfg)
    gossip_encrypted, gossip_assessable = _consul_gossip(stats)
    anon_policies, anon_assessable = _consul_anon(anon_token)
    wildcard_intentions, intentions_assessable = _consul_wildcard_intentions(intentions)

    return Resource(
        kind="coord_consul",
        name=f"{host}:{port}",
        ext_id=f"coord-consul-{host}:{port}",
        labels={"system": "consul", "version": version or "?",
                "datacenter": str(cfg.get("Datacenter") or "?")},
        raw={
            "system": "consul", "host": host, "port": port, "version": version,
            "datacenter": cfg.get("Datacenter"),
            "connected_via_tls": bool(tls),
            "acls_enabled": acls_enabled, "acl_default_policy": acl_default,
            "acl_assessable": acl_assessable,
            "gossip_encrypted": gossip_encrypted, "gossip_assessable": gossip_assessable,
            "anonymous_policies": anon_policies, "anon_assessable": anon_assessable,
            "wildcard_intentions": wildcard_intentions,
            "intentions_assessable": intentions_assessable,
            "acl": {"tokens": tokens or [], "policies": policies or [],
                    "anonymous_policies": anon_policies or []},
        },
    )


# ══ collection: httpx (HTTP systems) + raw socket (ZooKeeper 4lw) ═══════════════
def _http_probe(client, method: str, url: str, *, headers=None, json_body=None) -> dict:
    """One tolerant HTTP call → {"status", "body"}; body is parsed JSON when possible, else
    text. Any transport failure returns {"status": None, "body": None, "error": ...} so the
    parse layer reads it as 'unreadable', never as a clean answer."""
    try:
        resp = client.request(method, url, headers=headers, json=json_body)
    except Exception as e:  # noqa: BLE001 — a probe failure is data, not a scan-ending error
        return {"status": None, "body": None, "error": f"{type(e).__name__}: {e}"}
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        body = resp.text
    return {"status": resp.status_code, "body": body}


def _zk_4lw(host: str, port: int, command: str, timeout: float):
    """Send one four-letter word over a raw TCP socket, return the decoded reply text (or None
    on any socket failure). This is the stdlib-socket path the task calls for — no dependency."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(command.encode("ascii"))
            chunks = []
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            return b"".join(chunks).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return None


def _collect_etcd(config, host, port, tls, timeout) -> Collected:
    import httpx

    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{port}"
    verify = not _truthy(config.get("insecure_skip_tls_verify"))
    version_json = status_json = None
    auth_probe = role_probe = kv_probe = None

    with httpx.Client(timeout=timeout, verify=verify) as client:
        v = _http_probe(client, "GET", f"{base}/version")
        version_json = v["body"] if isinstance(v.get("body"), dict) else None
        st = _http_probe(client, "POST", f"{base}/v3/maintenance/status", json_body={})
        status_json = st["body"] if isinstance(st.get("body"), dict) else None
        auth_probe = _http_probe(client, "POST", f"{base}/v3/auth/user/list", json_body={})
        role_probe = _http_probe(client, "POST", f"{base}/v3/auth/role/list", json_body={})
        kv_probe = _http_probe(client, "POST", f"{base}/v3/kv/range",
                               json_body={"key": base64.b64encode(b"\x00").decode()})

    peer_port = int(config.get("peer_port") or _ETCD_PEER_DEFAULT)
    peer_probe = _etcd_peer_probe(host, peer_port, timeout)

    r = parse_etcd(host, port, tls=tls, version_json=version_json, status_json=status_json,
                   auth_probe=auth_probe, role_probe=role_probe, kv_probe=kv_probe,
                   peer_probe=peer_probe, peer_port=peer_port)
    return Collected(resources=[r], edges=[])


def _etcd_peer_probe(host, peer_port, timeout) -> dict:
    """Plaintext HTTP probe of the etcd peer port: any HTTP answer ⇒ peer TLS is OFF; a TLS
    handshake on the plaintext attempt ⇒ peer TLS is ON; anything else ⇒ not assessable."""
    import httpx
    try:
        with httpx.Client(timeout=timeout, verify=False) as c:
            c.get(f"http://{host}:{peer_port}/version")
        return {"reachable": True, "plaintext_http": True, "tls_detected": False}
    except Exception as e:  # noqa: BLE001
        msg = f"{type(e).__name__}: {e}".lower()
        if "ssl" in msg or "tls" in msg or "wrong_version" in msg:
            return {"reachable": True, "plaintext_http": False, "tls_detected": True}
        return {"reachable": False, "plaintext_http": False, "tls_detected": False}


def _collect_zookeeper(config, host, port, tls, timeout) -> Collected:
    ruok = _zk_4lw(host, port, "ruok", timeout)
    conf = _zk_4lw(host, port, "conf", timeout)
    envi = _zk_4lw(host, port, "envi", timeout)
    stat = _zk_4lw(host, port, "stat", timeout)
    r = parse_zookeeper(host, port, tls=tls, ruok=ruok, conf=conf, envi=envi, stat=stat)
    return Collected(resources=[r], edges=[])


def _collect_nacos(config, host, port, tls, timeout) -> Collected:
    import httpx

    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{port}"
    verify = not _truthy(config.get("insecure_skip_tls_verify"))
    username = (config.get("username") or "nacos").strip()
    password = config.get("password") or "nacos"
    state_json = users_json = None
    console_probe = login_probe = bypass_probe = None

    with httpx.Client(timeout=timeout, verify=verify) as client:
        s = _http_probe(client, "GET", f"{base}/nacos/v1/console/server/state")
        state_json = s["body"] if isinstance(s.get("body"), dict) else None
        console = _http_probe(client, "GET", f"{base}/nacos/index.html")
        console_probe = {"status": console.get("status"),
                         "is_html": isinstance(console.get("body"), str)
                         and "<html" in (console.get("body") or "").lower()}
        login_probe = _http_probe(client, "POST", f"{base}/nacos/v1/auth/login",
                                  json_body={"username": username, "password": password})
        # The CVE-2021-29441 backdoor: the `Nacos-Server` User-Agent skips the AuthFilter.
        bypass_probe = _http_probe(
            client, "GET", f"{base}/nacos/v1/auth/users?pageNo=1&pageSize=10",
            headers={"User-Agent": "Nacos-Server"})
        if bypass_probe.get("status") == 200 and isinstance(bypass_probe.get("body"), dict):
            users_json = bypass_probe["body"]

    r = parse_nacos(host, port, tls=tls, state_json=state_json, console_probe=console_probe,
                    login_probe=login_probe, bypass_probe=bypass_probe, users_json=users_json)
    return Collected(resources=[r], edges=[])


def _collect_consul(config, host, port, tls, timeout) -> Collected:
    import httpx

    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{port}"
    verify = not _truthy(config.get("insecure_skip_tls_verify"))
    token = (config.get("token") or "").strip()
    headers = {"X-Consul-Token": token} if token else None
    agent_self = intentions = anon_token = None
    tokens = policies = None

    with httpx.Client(timeout=timeout, verify=verify) as client:
        a = _http_probe(client, "GET", f"{base}/v1/agent/self", headers=headers)
        agent_self = a["body"] if isinstance(a.get("body"), dict) else None
        it = _http_probe(client, "GET", f"{base}/v1/connect/intentions", headers=headers)
        intentions = it["body"] if isinstance(it.get("body"), list) else None
        # The anonymous token has a fixed AccessorID; reading it needs a management token.
        anon_token = _http_probe(
            client, "GET",
            f"{base}/v1/acl/token/00000000-0000-0000-0000-000000000002", headers=headers)
        if token:
            tk = _http_probe(client, "GET", f"{base}/v1/acl/tokens", headers=headers)
            tokens = _consul_token_meta(tk["body"]) if isinstance(tk.get("body"), list) else None
            pol = _http_probe(client, "GET", f"{base}/v1/acl/policies", headers=headers)
            policies = _consul_policy_meta(pol["body"]) if isinstance(pol.get("body"), list) else None

    r = parse_consul(host, port, tls=tls, agent_self=agent_self, anon_token=anon_token,
                     intentions=intentions, tokens=tokens, policies=policies)
    return Collected(resources=[r], edges=[])


def _consul_token_meta(tokens) -> list:
    """Token list → NHI metadata ONLY. The SecretID is never read (the list API returns only
    AccessorID + Description); we record that a token credential EXISTS, never its value."""
    out = []
    for t in tokens or []:
        if not isinstance(t, dict):
            continue
        out.append({
            "accessor_id": t.get("AccessorID"),
            "description": t.get("Description") or "",
            "local": bool(t.get("Local")),
            "policies": [str(p.get("Name") or p.get("ID")) for p in (t.get("Policies") or [])
                         if isinstance(p, dict)],
            "roles": [str(rr.get("Name") or rr.get("ID")) for rr in (t.get("Roles") or [])
                      if isinstance(rr, dict)],
        })
    return out


def _consul_policy_meta(policies) -> list:
    out = []
    for p in policies or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("Name") or p.get("ID"))
        out.append({"name": name, "id": p.get("ID"),
                    "global_management": name == "global-management"})
    return out


_COLLECTORS = {
    "etcd": _collect_etcd, "zookeeper": _collect_zookeeper,
    "nacos": _collect_nacos, "consul": _collect_consul,
}


@connector("coord", fields=[
    ConnectorField("system", "System", required=True, placeholder="etcd",
                   help="Which coordination system to scan: etcd, zookeeper, nacos, or consul. "
                        "Every call is read-only (status/config reads and unauthenticated "
                        "reachability probes; no writes, no key scans)."),
    ConnectorField("host", "Host", required=True, placeholder="10.0.0.10",
                   help="Hostname/IP the engine or worker can reach."),
    ConnectorField("port", "Port", placeholder="2379 / 2181 / 8848 / 8500",
                   help="Defaults per system (etcd 2379, zookeeper 2181, nacos 8848, "
                        "consul 8500) when left empty."),
    ConnectorField("peer_port", "etcd peer port", placeholder="2380",
                   help="etcd only: the peer port probed (plaintext) for peer-TLS enablement."),
    ConnectorField("username", "Username", placeholder="nacos",
                   help="Nacos login user for the default-credential probe / etcd RBAC user."),
    ConnectorField("password", "Password", secret=True,
                   help="Used to open the session, never persisted into any resource."),
    ConnectorField("token", "ACL token", secret=True,
                   help="Consul ACL/management token or Nacos accessToken. Read-only; its value "
                        "is never copied into a resource. A management token lets the scan read "
                        "the ACL token/policy inventory for the NHI view."),
    ConnectorField("tls", "Use TLS", placeholder="false",
                   help="'true' to connect to the HTTP systems over https."),
])
def collect(config: dict) -> Collected:
    system = (config.get("system") or "").strip().lower()
    if system not in _COLLECTORS:
        raise SystemExit(
            f"coordination connector requires config['system'] in {sorted(_COLLECTORS)}; "
            f"got {system!r}")
    host = (config.get("host") or "").strip()
    if not host:
        raise SystemExit("coordination connector requires config['host']")
    port = int(config.get("port") or _DEFAULT_PORTS[system])
    tls = _truthy(config.get("tls"))
    timeout = float(config.get("timeout") or 10)
    return _COLLECTORS[system](config, host, port, tls, timeout)


# ══ NHI: Consul tokens/policies, Nacos users, etcd users/roles ═════════════════
@identity_extractor("coord")
def _from_coordination(resources: list) -> tuple:
    """The coordination layer's non-human identities in the normalized model:

      Consul ACL token   → identity (acl_token) + a credential (the SecretID EXISTS, never read)
                           + one grant per attached policy (wildcard when global-management); the
                           anonymous token becomes an identity whose policies are grants.
      Nacos user         → identity (service_account); admin users carry an `admin` grant.
      etcd user          → identity (service_account); one grant per role the user holds.

    Edges: credential --credential_of--> identity, grant --granted_to--> identity.
    """
    out: list[Resource] = []
    edges: list[Edge] = []
    for r in resources:
        if r.kind == "coord_consul":
            o, e = _consul_nhi(r)
        elif r.kind == "coord_nacos":
            o, e = _nacos_nhi(r)
        elif r.kind == "coord_etcd":
            o, e = _etcd_nhi(r)
        else:
            continue
        out.extend(o)
        edges.extend(e)
    return out, edges


def _consul_nhi(r: Resource) -> tuple:
    out, edges = [], []
    acl = (r.raw or {}).get("acl") or {}
    policy_meta = {p.get("name"): p for p in (acl.get("policies") or [])}

    for tok in acl.get("tokens") or []:
        name = tok.get("description") or tok.get("accessor_id") or "acl-token"
        idr = _mk_identity("consul", "acl_token", name, source_ext=r.ext_id,
                           extra={"accessor_id": tok.get("accessor_id"),
                                  "local": tok.get("local")})
        out.append(idr)
        # The token's SecretID is the credential — its existence, never its value.
        cred = _mk_credential("consul", idr.ext_id, "acl_token",
                              name=f"{name}:secret-id", hashing="n/a", present=True,
                              plaintext=False, extra={"accessor_id": tok.get("accessor_id")})
        out.append(cred)
        edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        for pol in tok.get("policies") or []:
            wildcard = pol == "global-management" or bool(
                (policy_meta.get(pol) or {}).get("global_management"))
            g = _mk_grant("consul", idr.ext_id, "policy", pol, wildcard=wildcard,
                          extra={"via": "token"})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))

    # The anonymous token — the identity every unauthenticated caller assumes.
    anon = acl.get("anonymous_policies")
    if anon:
        idr = _mk_identity("consul", "acl_token", "anonymous", source_ext=r.ext_id,
                           extra={"anonymous": True})
        out.append(idr)
        for pol in anon:
            wildcard = pol == "global-management"
            g = _mk_grant("consul", idr.ext_id, "policy", pol, wildcard=wildcard,
                          extra={"via": "anonymous_token"})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges


def _nacos_nhi(r: Resource) -> tuple:
    out, edges = [], []
    raw = r.raw or {}
    admins = set(raw.get("admin_users") or [])
    for user in raw.get("users") or []:
        idr = _mk_identity("nacos", "service_account", user, source_ext=r.ext_id,
                           extra={"admin": user in admins})
        out.append(idr)
        if user in admins:
            g = _mk_grant("nacos", idr.ext_id, "role", "admin", wildcard=True)
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges


def _etcd_nhi(r: Resource) -> tuple:
    out, edges = [], []
    auth = (r.raw or {}).get("auth") or {}
    user_roles = auth.get("user_roles") or {}
    for user in auth.get("users") or []:
        idr = _mk_identity("etcd", "service_account", user, source_ext=r.ext_id)
        out.append(idr)
        for role in user_roles.get(user) or []:
            g = _mk_grant("etcd", idr.ext_id, "role", role,
                          wildcard=(role == "root"))
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
