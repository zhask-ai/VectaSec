"""MQTT / IoT message-broker connector — read-only posture from config or admin API.

MQTT is the substrate the integration atlas keeps landing on: an anonymous-by-default pub/sub
bus that Shodan finds by the hundred-thousand on the open internet. This connector reads three
broker families and writes nothing:

  Mosquitto   parse a mosquitto.conf (a file path OR pasted config text — no live MQTT
              connection): allow_anonymous, password_file/acl_file presence, per-listener TLS,
              per_listener_settings, and `connection` (bridge) blocks. The parser is pure text →
              Collected; nothing here opens a socket, so a pasted config is fully assessable.
  EMQX        the Dashboard HTTP API (:18083, base /api/v5) over httpx — the enabled
              authenticators (empty ⇒ anonymous allowed), authorization sources + `no_match`
              default action, TCP/SSL listeners, dashboard users (the default `admin`), and node
              version. GETs only; the API key is used to open the session, never stored.
  HiveMQ      the REST API (:8888, base /api/v1). Verified against docs: this API exposes only
              MQTT clients / backups / trace recordings and does NOT surface broker
              authentication, authorization, TLS listener, security-extension, or Control Center
              configuration. So HiveMQ posture is deliberately recorded as NOT readable for those
              aspects (detect/mqtt.py raises a coverage-gap finding) — the one thing the REST API
              *does* prove is whether it answers unauthenticated (its own user auth is disabled by
              default even once the API is enabled).

Two disciplines carried from the other connectors:

  • Secrets are used, never persisted. `api_secret`/`token` are ConnectorField secret=True; they
    build the httpx auth inside collect() and are never copied into a Resource. A Mosquitto
    `remote_password` in a bridge block is reduced to a `remote_password_present` boolean — the
    value is dropped, only presence survives (same discipline as the RabbitMQ password-hash).
  • Kinds are DISTINCT and prefixed `mqtt_` (mqtt_broker, mqtt_listener) so no other rulepack —
    Kafka's `broker`, Redis's `redis_server` — ever runs against an MQTT resource by accident.

Every family normalises into ONE shape (mqtt_broker.raw carries `allow_anonymous`,
`authz_default_allow`, `*_readable` flags, `bridges`, `dashboard`, `admin_api`…) so the detectors
read fields, not vendor JSON — the same normalise-then-detect seam k8s uses across Istio/Linkerd.
The parse layer (parse_mosquitto_config / parse_emqx / parse_hivemq) is pure: fixtures in,
Collected out, so httpx and a live broker stay out of the test suite.
"""
from ..contracts import Collected, Edge, Resource
from ..identity import identity_extractor, _mk_credential, _mk_grant, _mk_identity
from ..registry import ConnectorField, connector

# Installer-default administrator accounts, per vendor docs (EMQX Dashboard: admin/public;
# HiveMQ Control Center: admin/hivemq). We can read that the account NAME still exists; the
# password is never readable, so the detector states only the fact it can prove.
_DEFAULT_ADMIN_USERS = {"emqx": "admin", "hivemq": "admin"}

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0.0"}


def _bool(v):
    """A config token → True/False/None. None means 'not one of the known truthy/falsey spellings'
    (an unset directive stays unknown rather than silently defaulting to a security posture)."""
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return None


def _host_of(bind) -> str:
    """The host portion of a `bind`/`address` value ('0.0.0.0:1883' → '0.0.0.0', '[::]:8883' →
    '::'). A bare port ('18083') has no host and reads as all-interfaces."""
    s = str(bind or "").strip()
    if not s:
        return ""
    if s.startswith("["):                          # [::]:8883
        return s[1:].split("]")[0]
    if s.isdigit():                                 # bare port ⇒ all interfaces
        return ""
    if ":" in s and s.count(":") == 1:              # host:port
        return s.rsplit(":", 1)[0]
    return s                                        # bare host


def _is_all_interfaces(bind) -> bool:
    h = _host_of(bind)
    return h in ("", "0.0.0.0", "*", "::", "0.0.0.0/0")


def _is_loopback(bind) -> bool:
    h = (_host_of(bind) or "").strip("[]").lower()
    return h in _LOOPBACK_HOSTS or h == "127.0.0.1"


# ════════════════════════════════════════════════════════════════════════════
# Mosquitto — pure config-text parser
# ════════════════════════════════════════════════════════════════════════════
# Directives that, when they appear inside a `listener` block, configure THAT listener; at global
# scope they configure the default listener. Routed by the current parse context.
_LISTENER_TLS_KEYS = ("certfile", "keyfile", "cafile", "capath", "require_certificate",
                      "psk_hint", "tls_version")
# Directives that mark a credential/authz backend beyond the built-in files.
_AUTH_PLUGIN_KEYS = ("plugin", "auth_plugin")


def _new_listener(port, bind):
    return {"port": port, "bind": bind, "protocol": "mqtt", "certfile": None, "keyfile": None,
            "cafile": None, "capath": None, "require_certificate": None, "psk_hint": None,
            "allow_anonymous": None, "password_file": None, "acl_file": None}


def _new_bridge(name):
    return {"name": name, "address": None, "remote_username": None,
            "remote_password_present": False, "bridge_cafile": None, "bridge_capath": None,
            "bridge_certfile": None, "bridge_keyfile": None, "bridge_insecure": None,
            "topics": []}


def _listener_tls(l: dict) -> bool:
    """A Mosquitto listener speaks TLS iff it carries a cert+key pair or a PSK hint."""
    return bool((l.get("certfile") and l.get("keyfile")) or l.get("psk_hint"))


def parse_mosquitto_config(text: str, *, broker_name: str = "mosquitto") -> Collected:
    """A mosquitto.conf (as text) → Collected. Pure: no file I/O, no socket. Tracks three parse
    contexts (global / listener / bridge) because the same directive means different things in
    each — `certfile` after a `listener` is that listener's cert, at global scope it is the
    default listener's."""
    g: dict = {"allow_anonymous": None, "password_file": None, "acl_file": None,
               "per_listener_settings": None, "port": None, "bind_address": None,
               "has_auth_plugin": False}
    g_tls: dict = {}
    listeners: list[dict] = []
    bridges: list[dict] = []
    cur, cur_kind = None, "global"

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        key = parts[0].lower()
        val = parts[1] if len(parts) > 1 else ""

        if key == "listener":
            cur = _new_listener(val or None, parts[2] if len(parts) > 2 else None)
            listeners.append(cur)
            cur_kind = "listener"
            continue
        if key == "connection":
            cur = _new_bridge(val or f"bridge-{len(bridges)}")
            bridges.append(cur)
            cur_kind = "bridge"
            continue

        if cur_kind == "bridge":
            if key in ("address", "addresses"):
                cur["address"] = " ".join(parts[1:]) or None
            elif key == "remote_username":
                cur["remote_username"] = val or None
            elif key == "remote_password":
                cur["remote_password_present"] = bool(val)      # value dropped — presence only
            elif key in ("bridge_cafile", "bridge_capath", "bridge_certfile", "bridge_keyfile"):
                cur[key] = val or None
            elif key == "bridge_insecure":
                cur["bridge_insecure"] = _bool(val)
            elif key == "topic":
                cur["topics"].append(" ".join(parts[1:]))
            continue

        if cur_kind == "listener":
            if key in _LISTENER_TLS_KEYS:
                cur[key] = val if key != "require_certificate" else _bool(val)
            elif key == "protocol":
                cur["protocol"] = val or "mqtt"
            elif key == "allow_anonymous":
                cur["allow_anonymous"] = _bool(val)
            elif key == "password_file":
                cur["password_file"] = val or None
            elif key == "acl_file":
                cur["acl_file"] = val or None
            elif key in _AUTH_PLUGIN_KEYS:
                g["has_auth_plugin"] = True
            continue

        # global scope
        if key == "allow_anonymous":
            g["allow_anonymous"] = _bool(val)
        elif key == "password_file":
            g["password_file"] = val or None
        elif key == "acl_file":
            g["acl_file"] = val or None
        elif key == "per_listener_settings":
            g["per_listener_settings"] = _bool(val)
        elif key == "port":
            g["port"] = val or None
        elif key == "bind_address":
            g["bind_address"] = val or None
        elif key in _AUTH_PLUGIN_KEYS:
            g["has_auth_plugin"] = True
        elif key in _LISTENER_TLS_KEYS:
            g_tls[key] = val if key != "require_certificate" else _bool(val)

    # No explicit `listener` ⇒ the default listener (global port/bind, global TLS directives).
    if not listeners:
        dflt = _new_listener(g.get("port") or "1883", g.get("bind_address"))
        dflt.update({k: g_tls.get(k) for k in _LISTENER_TLS_KEYS if k in g_tls})
        listeners.append(dflt)

    acl_present = bool(g.get("acl_file") or any(l.get("acl_file") for l in listeners))
    pwd_present = bool(g.get("password_file") or any(l.get("password_file") for l in listeners))
    auth_backend = pwd_present or bool(g.get("has_auth_plugin"))
    # authz default action: no acl_file anywhere ⇒ Mosquitto grants every topic to every
    # connected client. An auth plugin owns authz opaquely ⇒ we cannot tell (None).
    if acl_present:
        authz_default_allow = False
    elif g.get("has_auth_plugin"):
        authz_default_allow = None
    else:
        authz_default_allow = True

    broker_ext = f"mqtt-broker-mosquitto-{broker_name}"
    norm_bridges = [{
        "name": b["name"], "address": b["address"], "remote_username": b["remote_username"],
        "remote_auth": bool(b["remote_username"]),
        "remote_password_present": b["remote_password_present"],
        "tls": bool(b["bridge_cafile"] or b["bridge_capath"] or b["bridge_certfile"]),
        "insecure": b["bridge_insecure"], "topics": b["topics"],
    } for b in bridges]

    broker = Resource(
        kind="mqtt_broker", name=broker_name, ext_id=broker_ext,
        labels={"system": "mosquitto"},
        raw={
            "system": "mosquitto",
            "version": None,
            "allow_anonymous": g.get("allow_anonymous"),
            "allow_anonymous_source": ("mosquitto.conf allow_anonymous"
                                       if g.get("allow_anonymous") is not None
                                       else "unset (version-dependent default)"),
            "auth_backend_present": auth_backend,
            "password_file_present": pwd_present,
            "authz_default_allow": authz_default_allow,
            "authz_source": "acl_file" if acl_present else ("plugin" if g.get("has_auth_plugin")
                                                            else "no acl_file"),
            "per_listener_settings": g.get("per_listener_settings"),
            "bridges": norm_bridges,
            "dashboard": {"enabled": False, "kind": None, "bind": None, "tls": None},
            "default_admin": {"present": None, "username": None},
            "admin_api": None,
            # Everything below is read straight from the config text — fully assessable.
            "authn_readable": True, "authz_readable": True,
            "listeners_readable": True, "dashboard_readable": True,
            "authn_users": [], "authz_rules": [], "dashboard_users": [],
            "collection": {"source": "mosquitto.conf"},
        },
    )
    resources = [broker]
    edges = []
    for i, l in enumerate(listeners):
        tls = _listener_tls(l)
        name = f"{_host_of(l.get('bind')) or '*'}:{l.get('port')}"
        ext = f"{broker_ext}-listener-{l.get('port') or i}-{i}"
        resources.append(Resource(
            kind="mqtt_listener", name=name, ext_id=ext,
            labels={"system": "mosquitto", "tls": "true" if tls else "false",
                    "protocol": l.get("protocol") or "mqtt"},
            raw={
                "system": "mosquitto", "broker_ext": broker_ext,
                "port": l.get("port"), "bind": l.get("bind"),
                "protocol": "websockets" if l.get("protocol") == "websockets" else "mqtt",
                "tls": tls, "tls_source": "certfile+keyfile" if (l.get("certfile") and l.get("keyfile"))
                        else ("psk_hint" if l.get("psk_hint") else None),
                "require_certificate": l.get("require_certificate"),
                "allow_anonymous": l.get("allow_anonymous"),
                "loopback": _is_loopback(l.get("bind")),
                "all_interfaces": _is_all_interfaces(l.get("bind")),
            },
        ))
        edges.append(Edge(src_ext_id=broker_ext, dst_ext_id=ext, kind="exposes"))
    return Collected(resources=resources, edges=edges)


# ════════════════════════════════════════════════════════════════════════════
# EMQX — Dashboard HTTP API (/api/v5), pure parse layer
# ════════════════════════════════════════════════════════════════════════════
def _readable(section) -> bool:
    """A per-endpoint record is {"outcome": "ok"|"denied"|"error", "data": ...}. Only 'ok' means
    we actually read it; denied/error/absent must NOT read as 'nothing configured'."""
    return isinstance(section, dict) and section.get("outcome") == "ok"


def parse_emqx(data: dict, *, base_url: str, broker_name: str = "emqx") -> Collected:
    """EMQX API JSON (per-endpoint {"outcome","data"} records) → Collected. `data` keys:
    nodes, authentication, authorization_sources, authorization_settings, listeners,
    dashboard_users, dashboard, authn_users, authz_rules, api_probe."""
    nodes_sec = data.get("nodes") or {}
    nodes = nodes_sec.get("data") or [] if _readable(nodes_sec) else []
    node0 = nodes[0] if nodes else {}
    version = node0.get("version")
    edition = node0.get("edition")

    authn_sec = data.get("authentication") or {}
    authn_readable = _readable(authn_sec)
    authenticators = authn_sec.get("data") or [] if authn_readable else []
    enabled_authn = [a for a in authenticators if a.get("enable")]
    if not authn_readable:
        allow_anonymous, auth_backend = None, None
    else:
        allow_anonymous = not enabled_authn        # no enabled authenticator ⇒ anyone connects
        auth_backend = bool(enabled_authn)

    authz_src_sec = data.get("authorization_sources") or {}
    authz_set_sec = data.get("authorization_settings") or {}
    authz_readable = _readable(authz_src_sec) and _readable(authz_set_sec)
    enabled_authz = [s for s in (authz_src_sec.get("data") or []) if s.get("enable")]
    no_match = (authz_set_sec.get("data") or {}).get("no_match")
    # Unmatched publish/subscribe is permitted whenever the default action is allow — EMQX ships
    # `authorization.no_match = allow`, so a broker with no deny sources is open by topic.
    authz_default_allow = (str(no_match).lower() == "allow") if authz_readable else None

    listeners_sec = data.get("listeners") or {}
    listeners_readable = _readable(listeners_sec)
    raw_listeners = listeners_sec.get("data") or [] if listeners_readable else []

    dash_users_sec = data.get("dashboard_users") or {}
    dash_users = [u.get("username") for u in (dash_users_sec.get("data") or [])
                  if u.get("username")] if _readable(dash_users_sec) else []
    dash_sec = data.get("dashboard") or {}
    dash_readable = _readable(dash_sec)
    dash_cfg = dash_sec.get("data") or {}
    dash_bind = (((dash_cfg.get("listeners") or {}).get("http") or {}).get("bind")
                 or (dash_cfg.get("http") or {}).get("bind"))
    dash_https = ((dash_cfg.get("listeners") or {}).get("https") or {}).get("enable")

    probe = data.get("api_probe") or {}
    default_admin_present = (_DEFAULT_ADMIN_USERS["emqx"] in dash_users) if _readable(dash_users_sec) else None

    broker_ext = f"mqtt-broker-emqx-{broker_name}"
    broker = Resource(
        kind="mqtt_broker", name=broker_name, ext_id=broker_ext,
        labels={"system": "emqx", "version": str(version or "?"), "edition": str(edition or "?")},
        raw={
            "system": "emqx", "version": version, "edition": edition,
            "allow_anonymous": allow_anonymous,
            "allow_anonymous_source": (f"{len(enabled_authn)} enabled authenticator(s)"
                                       if authn_readable else "authentication API not readable"),
            "auth_backend_present": auth_backend,
            "authz_default_allow": authz_default_allow,
            "authz_source": (f"no_match={no_match}, {len(enabled_authz)} enabled source(s)"
                             if authz_readable else "authorization API not readable"),
            "per_listener_settings": None,
            "bridges": [],
            "dashboard": {"enabled": True, "kind": "dashboard", "bind": dash_bind,
                          "tls": bool(dash_https)} if dash_readable
                         else {"enabled": None, "kind": "dashboard", "bind": None, "tls": None},
            "default_admin": {"present": default_admin_present,
                              "username": _DEFAULT_ADMIN_USERS["emqx"]},
            "admin_api": {"kind": "emqx_dashboard_api", "base_url": base_url,
                          "scheme": _scheme(base_url), "host": _host_of(_netloc(base_url)),
                          "unauthenticated_reachable": probe.get("unauthenticated_reachable"),
                          "authenticated_readable": authn_readable or listeners_readable},
            "authn_readable": authn_readable, "authz_readable": authz_readable,
            "listeners_readable": listeners_readable, "dashboard_readable": dash_readable,
            "authn_users": [u.get("user_id") or u.get("username")
                            for u in (data.get("authn_users") or {}).get("data") or []
                            if (u.get("user_id") or u.get("username"))],
            "authz_rules": (data.get("authz_rules") or {}).get("data") or [],
            "dashboard_users": dash_users,
            "collection": {k: (data.get(k) or {}).get("outcome")
                           for k in ("nodes", "authentication", "authorization_sources",
                                     "authorization_settings", "listeners", "dashboard_users")},
        },
    )
    resources = [broker]
    edges = []
    for l in raw_listeners:
        ltype = str(l.get("type") or "tcp").lower()
        ssl_opts = l.get("ssl_options") or {}
        tls = ltype in ("ssl", "wss") or bool(ssl_opts.get("certfile") or ssl_opts.get("keyfile"))
        bind = l.get("bind")
        lid = l.get("id") or f"{ltype}:{bind}"
        ext = f"{broker_ext}-listener-{lid}"
        resources.append(Resource(
            kind="mqtt_listener", name=str(lid), ext_id=ext,
            labels={"system": "emqx", "tls": "true" if tls else "false", "type": ltype},
            raw={
                "system": "emqx", "broker_ext": broker_ext, "listener_id": lid,
                "port": _port_of(bind), "bind": bind, "type": ltype,
                "protocol": "websockets" if ltype in ("ws", "wss") else "mqtt",
                "tls": tls, "tls_source": "ssl_options" if tls else None,
                "enable": l.get("enable"),
                "allow_anonymous": None,
                "loopback": _is_loopback(bind), "all_interfaces": _is_all_interfaces(bind),
            },
        ))
        edges.append(Edge(src_ext_id=broker_ext, dst_ext_id=ext, kind="exposes"))
    return Collected(resources=resources, edges=edges)


# ════════════════════════════════════════════════════════════════════════════
# HiveMQ — REST API (/api/v1). Deliberately narrow: the REST API exposes clients / backups /
# trace recordings only, so broker authn/authz/TLS/control-center posture is NOT readable and is
# recorded as such (detect/mqtt.py turns that into a coverage-gap finding, never a pass).
# ════════════════════════════════════════════════════════════════════════════
def parse_hivemq(data: dict, *, base_url: str, broker_name: str = "hivemq") -> Collected:
    probe = data.get("api_probe") or {}
    broker_ext = f"mqtt-broker-hivemq-{broker_name}"
    broker = Resource(
        kind="mqtt_broker", name=broker_name, ext_id=broker_ext,
        labels={"system": "hivemq"},
        raw={
            "system": "hivemq", "version": (data.get("version") or {}).get("data"),
            # The REST API cannot report any of these — honest None + not-readable flags.
            "allow_anonymous": None,
            "allow_anonymous_source": "HiveMQ REST API does not expose MQTT authentication config",
            "auth_backend_present": None,
            "authz_default_allow": None,
            "authz_source": "HiveMQ REST API does not expose authorization config",
            "per_listener_settings": None,
            "bridges": [],
            "dashboard": {"enabled": None, "kind": "control_center", "bind": None, "tls": None},
            "default_admin": {"present": None, "username": _DEFAULT_ADMIN_USERS["hivemq"]},
            "admin_api": {"kind": "hivemq_rest_api", "base_url": base_url,
                          "scheme": _scheme(base_url), "host": _host_of(_netloc(base_url)),
                          "unauthenticated_reachable": probe.get("unauthenticated_reachable"),
                          "authenticated_readable": probe.get("authenticated_reachable")},
            "authn_readable": False, "authz_readable": False,
            "listeners_readable": False, "dashboard_readable": False,
            "authn_users": [], "authz_rules": [], "dashboard_users": [],
            "collection": {"mqtt_clients": probe.get("clients_outcome"),
                           "note": "REST API surface: clients/backups/trace only"},
        },
    )
    return Collected(resources=[broker], edges=[])


# ── URL helpers ──────────────────────────────────────────────────────────────
def _scheme(url) -> str:
    return str(url or "").split("://", 1)[0].lower() if "://" in str(url or "") else "http"


def _netloc(url) -> str:
    s = str(url or "")
    if "://" in s:
        s = s.split("://", 1)[1]
    return s.split("/", 1)[0]


def _port_of(bind):
    s = str(bind or "").strip()
    if s.startswith("["):
        s = s.split("]", 1)[-1].lstrip(":")
    if ":" in s:
        s = s.rsplit(":", 1)[-1]
    return int(s) if s.isdigit() else None


# ════════════════════════════════════════════════════════════════════════════
# Live collection (httpx). Kept thin: every real read is a GET, isolated per endpoint so a denied
# endpoint records honestly instead of voiding the scan.
# ════════════════════════════════════════════════════════════════════════════
def _api_get(client, url: str) -> dict:
    """One GET → {"outcome","data","status"}. 401/403 is 'denied' (a coverage gap, not empty);
    any other failure is 'error'. Mirrors the AWS connector's per-service isolation."""
    try:
        r = client.get(url)
    except Exception as e:
        return {"outcome": "error", "data": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code in (401, 403):
        return {"outcome": "denied", "data": None, "status": r.status_code}
    if r.status_code >= 400:
        return {"outcome": "error", "data": None, "status": r.status_code}
    try:
        return {"outcome": "ok", "data": r.json(), "status": r.status_code}
    except Exception as e:
        return {"outcome": "error", "data": None, "error": f"{type(e).__name__}: {e}"}


def _probe_unauth(base: str, path: str, timeout: float, verify) -> bool | None:
    """Does the admin/REST API answer WITHOUT credentials? A 2xx means the management plane is
    world-readable. None on a transport error (unknown, not 'safe')."""
    import httpx
    try:
        with httpx.Client(timeout=timeout, verify=verify, follow_redirects=False) as anon:
            r = anon.get(base.rstrip("/") + path)
            return 200 <= r.status_code < 300
    except Exception:
        return None


def _collect_emqx(config: dict) -> dict:
    import httpx

    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        raise SystemExit("mqtt/emqx connector requires config['base_url']")
    api = base + "/api/v5"
    timeout = float(config.get("timeout") or 10)
    verify = config.get("verify", True)

    auth = None
    if config.get("api_key"):
        auth = (config.get("api_key"), config.get("api_secret") or "")
    headers = {"Authorization": f"Bearer {config['token']}"} if config.get("token") else {}

    probe_reachable = _probe_unauth(api, "/authentication", timeout, verify)

    with httpx.Client(timeout=timeout, verify=verify, headers=headers, auth=auth,
                      follow_redirects=False) as client:
        data = {
            "nodes": _api_get(client, api + "/nodes"),
            "authentication": _api_get(client, api + "/authentication"),
            "authorization_sources": _api_get(client, api + "/authorization/sources"),
            "authorization_settings": _api_get(client, api + "/authorization/settings"),
            "listeners": _api_get(client, api + "/listeners"),
            "dashboard_users": _api_get(client, api + "/users"),
            "dashboard": _api_get(client, api + "/configs/dashboard"),
            "authn_users": _api_get(client, api + "/authentication/password_based:built_in_database/users"),
            "authz_rules": _api_get(client, api + "/authorization/sources/built_in_database/rules/users"),
        }
    data["api_probe"] = {"unauthenticated_reachable": probe_reachable}
    return data


def _collect_hivemq(config: dict) -> dict:
    import httpx

    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        raise SystemExit("mqtt/hivemq connector requires config['base_url']")
    api = base + "/api/v1"
    timeout = float(config.get("timeout") or 10)
    verify = config.get("verify", True)
    headers = {"Authorization": f"Bearer {config['token']}"} if config.get("token") else {}
    auth = (config.get("api_key"), config.get("api_secret") or "") if config.get("api_key") else None

    probe_reachable = _probe_unauth(api, "/mqtt/clients", timeout, verify)
    with httpx.Client(timeout=timeout, verify=verify, headers=headers, auth=auth,
                      follow_redirects=False) as client:
        clients = _api_get(client, api + "/mqtt/clients")
    return {"version": {"outcome": "absent", "data": None},
            "api_probe": {"unauthenticated_reachable": probe_reachable,
                          "authenticated_reachable": clients.get("outcome") == "ok",
                          "clients_outcome": clients.get("outcome")}}


@connector("mqtt", fields=[
    ConnectorField("system", "Broker system", required=True, placeholder="mosquitto",
                   help="One of: mosquitto, emqx, hivemq. Selects how posture is read."),
    ConnectorField("config_path", "Mosquitto config path", placeholder="/etc/mosquitto/mosquitto.conf",
                   help="Mosquitto only: path to a mosquitto.conf the engine can read. Read-only, "
                        "parsed as text — no MQTT connection is opened."),
    ConnectorField("config_text", "Mosquitto config text",
                   help="Mosquitto only: paste the mosquitto.conf contents instead of a path."),
    ConnectorField("base_url", "Admin API base URL", placeholder="http://emqx:18083",
                   help="EMQX Dashboard API (:18083) or HiveMQ REST API (:8888) base URL. GETs only."),
    ConnectorField("api_key", "API key / username",
                   help="EMQX API key or HiveMQ REST user (HTTP Basic). Use a read-only role."),
    ConnectorField("api_secret", "API secret", secret=True,
                   help="Secret half of the API key — opens the session, never persisted."),
    ConnectorField("token", "Bearer token", secret=True,
                   help="Alternative to api_key/api_secret: a bearer token for the admin API."),
])
def collect(config: dict) -> Collected:
    system = (config.get("system") or "").strip().lower()
    name = (config.get("name") or "").strip()
    if system == "mosquitto":
        text = config.get("config_text")
        if not text:
            path = (config.get("config_path") or "").strip()
            if not path:
                raise SystemExit("mqtt/mosquitto connector requires config['config_text'] or "
                                 "config['config_path']")
            import os
            with open(os.path.expanduser(path), "r") as fh:
                text = fh.read()
        return parse_mosquitto_config(text, broker_name=name or "mosquitto")
    if system == "emqx":
        data = _collect_emqx(config)
        return parse_emqx(data, base_url=(config.get("base_url") or "").rstrip("/"),
                          broker_name=name or _host_of(_netloc(config.get("base_url"))) or "emqx")
    if system == "hivemq":
        data = _collect_hivemq(config)
        return parse_hivemq(data, base_url=(config.get("base_url") or "").rstrip("/"),
                            broker_name=name or _host_of(_netloc(config.get("base_url"))) or "hivemq")
    raise SystemExit("mqtt connector requires config['system'] to be one of "
                     "mosquitto | emqx | hivemq")


# ════════════════════════════════════════════════════════════════════════════
# NHI: MQTT users / bridge clients / ACL grants → identity + credential-metadata + grant
# ════════════════════════════════════════════════════════════════════════════
@identity_extractor("mqtt")
def _from_mqtt(resources: list) -> tuple:
    """The MQTT non-human identities in the normalized model:

      EMQX dashboard users   → identity(admin) + credential(password, metadata only; is_default
                               when the account is the installer default `admin`)
      EMQX built-in authn    → identity(mqtt_user) + credential(password, present)
      EMQX authz rules       → one grant per (user/clientid, action, topic)
      Mosquitto bridge       → identity(service_account, external) named bridge:<name>:<user>,
                               credential(password, present-only), grant on each bridged topic

    No secret value ever crosses this boundary — the connector already reduced every password to a
    presence boolean. HiveMQ contributes no NHIs: its REST API exposes no persistent principals.
    """
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "mqtt_broker":
            continue
        raw = r.raw or {}
        system = raw.get("system")
        default_admin = (raw.get("default_admin") or {}).get("username")

        # EMQX dashboard admin accounts
        for uname in raw.get("dashboard_users") or []:
            idr = _mk_identity("mqtt", "admin", f"{system}:dashboard:{uname}",
                               source_ext=r.ext_id, extra={"broker": system, "role": "dashboard"})
            out.append(idr)
            cred = _mk_credential("mqtt", idr.ext_id, "password", name=f"{uname}:password",
                                  hashing="unknown", present=True, plaintext=False,
                                  is_default=(uname == default_admin))
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        # EMQX built-in-database MQTT users
        for uname in raw.get("authn_users") or []:
            idr = _mk_identity("mqtt", "mqtt_user", f"{system}:mqtt:{uname}",
                               source_ext=r.ext_id, extra={"broker": system})
            out.append(idr)
            cred = _mk_credential("mqtt", idr.ext_id, "password", name=f"{uname}:password",
                                  hashing="unknown", present=True, plaintext=False)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        # EMQX authz rules → grants (topic authorizations held by a user/clientid)
        id_by_name: dict[str, str] = {rr.raw.get("principal"): rr.ext_id
                                      for rr in out if rr.kind == "identity"}
        for rule in raw.get("authz_rules") or []:
            who = rule.get("username") or rule.get("clientid") or rule.get("who") or "all"
            action = str(rule.get("action") or "all").lower()
            topic = rule.get("topic") or "#"
            perm = str(rule.get("permission") or "allow").lower()
            owner = id_by_name.get(f"{system}:mqtt:{who}")
            if not owner:
                idr = _mk_identity("mqtt", "mqtt_user", f"{system}:mqtt:{who}",
                                   source_ext=r.ext_id, extra={"broker": system})
                out.append(idr)
                owner = idr.ext_id
                id_by_name[f"{system}:mqtt:{who}"] = owner
            g = _mk_grant("mqtt", owner, action, f"topic:{topic}", permission=perm,
                          wildcard=(topic in ("#", "*") or str(topic).endswith("#")),
                          extra={"topic": topic, "broker": system})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=owner, kind="granted_to"))

        # Mosquitto bridges → an external service account per bridge with a remote username
        for b in raw.get("bridges") or []:
            uname = b.get("remote_username")
            if not uname:
                continue
            label = f"bridge:{b.get('name')}:{uname}"
            idr = _mk_identity("mqtt", "service_account", label, external=True,
                               source_ext=r.ext_id,
                               extra={"broker": system, "bridge": b.get("name"),
                                      "remote_address": b.get("address")})
            out.append(idr)
            if b.get("remote_password_present"):
                cred = _mk_credential("mqtt", idr.ext_id, "password",
                                      name=f"{label}:password", hashing="n/a", present=True,
                                      plaintext=False)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                                  kind="credential_of"))
            for topic in b.get("topics") or []:
                g = _mk_grant("mqtt", idr.ext_id, "bridge", f"topic:{topic}",
                              extra={"topic": topic, "broker": system, "bridge": b.get("name")})
                out.append(g)
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
