"""Redis connector — read-only INFO / CONFIG GET / ACL.

Redis is middleware more often than a database: cache, pub/sub, Streams, and a Lists-based work
queue all run on it, so its posture belongs in an integration-security tool. This connector reads
three things and writes nothing:

  INFO         server version + runtime facts (the version drives the RediShell CVE check)
  CONFIG GET   a curated allow-list of security-relevant settings (protected-mode, bind, tls-port,
               maxmemory…). `requirepass` is read ONLY to learn whether a password is set, then its
               value is dropped — never stored, logged, or returned (same discipline as the
               RabbitMQ connector's password-hash handling).
  ACL          the user list and each user's rule set — the NHI material (identity.py normalizes it)

Emits `redis_server` (the node) and `redis_user` (each ACL user) as DISTINCT kinds so the Kafka/
Kong `broker` and RabbitMQ `user` rulepacks never run against Redis resources by accident — the
generic `broker` kind is shared, but a Redis server is not a Kafka broker and must not be read as
one. A target that has disabled the CONFIG or ACL command (a legitimate hardening choice) is
handled: the connector records what it could not read rather than failing the scan.
"""
from ..registry import ConnectorField, connector
from ..contracts import Collected, Edge, Resource

# The security-relevant CONFIG keys we read. An allow-list, not `CONFIG GET *`: we want a small,
# auditable set and we never want to sweep up a value we didn't mean to store. `requirepass` is
# here only so we can compute has_requirepass; its value is dropped before anything is stored.
_CONFIG_KEYS = (
    "protected-mode", "bind", "port", "tls-port", "requirepass", "maxmemory",
    "maxmemory-policy", "maxclients", "appendonly", "save", "aclfile",
    "enable-debug-command", "enable-protected-configs",
)


@connector("redis", fields=[
    ConnectorField("host", "Host", required=True, placeholder="localhost",
                   help="Hostname/IP the engine or worker can reach. Read-only — no writes, "
                        "no key scans."),
    ConnectorField("port", "Port", placeholder="6379"),
    ConnectorField("password", "Password", secret=True,
                   help="Only if the server sets requirepass or an ACL password."),
    ConnectorField("tls", "Use TLS", placeholder="false",
                   help="'true' to connect over TLS (rediss://)."),
])
def collect(config: dict) -> Collected:
    import redis  # local import: importing vectasec must stay dependency-light (config.py contract)

    host = (config.get("host") or "").strip()
    if not host:
        raise SystemExit("redis connector requires config['host']")
    port = int(config.get("port") or 6379)
    password = config.get("password") or None
    tls = str(config.get("tls", "")).strip().lower() in ("1", "true", "yes", "on")
    timeout = float(config.get("timeout") or 10)

    client = redis.Redis(
        host=host, port=port, password=password, ssl=tls,
        socket_timeout=timeout, socket_connect_timeout=timeout,
        decode_responses=True,
    )

    info = client.info()  # dict — always available

    cfg: dict = {}
    config_readable = True
    try:
        for key in _CONFIG_KEYS:
            got = client.config_get(key)
            if got:
                cfg.update(got)
    except Exception:
        # CONFIG disabled/renamed is a hardening choice; record that we could not read it.
        config_readable = False

    # requirepass: learn presence, then DROP the value. It never leaves this function.
    has_requirepass = bool((cfg.get("requirepass") or "").strip())
    cfg.pop("requirepass", None)

    server_ext = f"redis-{host}:{port}"
    resources: list[Resource] = [Resource(
        kind="redis_server",
        name=f"{host}:{port}",
        ext_id=server_ext,
        labels={"version": info.get("redis_version", "?"),
                "mode": info.get("redis_mode", "?")},
        raw={
            "redis_version": info.get("redis_version"),
            "redis_mode": info.get("redis_mode"),
            "os": info.get("os"),
            "tls_port": cfg.get("tls-port"),
            "port": cfg.get("port"),
            "protected_mode": cfg.get("protected-mode"),
            "bind": cfg.get("bind"),
            "has_requirepass": has_requirepass,
            "maxmemory": cfg.get("maxmemory"),
            "maxmemory_policy": cfg.get("maxmemory-policy"),
            "maxclients": cfg.get("maxclients"),
            "appendonly": cfg.get("appendonly"),
            "aclfile": cfg.get("aclfile"),
            "enable_debug_command": cfg.get("enable-debug-command"),
            "config_readable": config_readable,
            "connected_via_tls": tls,
        },
    )]

    # ACL users — the NHI material. ACL is Redis 6+; older servers or a disabled ACL command
    # leave zero users, recorded honestly rather than raised.
    acl_readable = True
    try:
        usernames = client.acl_users() or []
    except Exception:
        usernames, acl_readable = [], False

    resources[0].raw["acl_readable"] = acl_readable

    for uname in usernames:
        try:
            u = client.acl_getuser(uname) or {}
        except Exception:
            u = {}
        flags = u.get("flags") or []
        # redis-py normalizes some of these into their own keys across versions; read defensively.
        nopass = ("nopass" in flags) or bool(u.get("nopass"))
        enabled = ("on" in flags) or (u.get("enabled") in (True, "on"))
        keys = u.get("keys")
        commands = u.get("commands")
        resources.append(Resource(
            kind="redis_user",
            name=str(uname),
            ext_id=f"redis-user-{host}:{port}-{uname}",
            labels={"enabled": "true" if enabled else "false",
                    "nopass": "true" if nopass else "false"},
            raw={
                "username": str(uname),
                "enabled": enabled,
                "nopass": nopass,
                "keys": keys if isinstance(keys, str) else " ".join(keys) if isinstance(keys, list) else str(keys),
                "channels": u.get("channels"),
                "commands": commands if isinstance(commands, str) else str(commands),
                "server_ext": server_ext,
            },
        ))

    # ── Runtime evidence: who is connected right now ─────────────────────────
    # CLIENT LIST names the authenticated ACL user per connection, plus the last command the
    # client ran. `cmd` is a COMMAND NAME ("get", "auth", "subscribe") and never its arguments,
    # so this reads what clients are doing without reading their data — the same line the
    # RabbitMQ collector draws. Redis <6 has no ACLs, so `user` is absent there and the
    # principal is honestly recorded as unknown rather than invented as "default".
    edges: list = []
    try:
        clients = client.client_list() or []
        client_list_readable = True
    except Exception:
        clients, client_list_readable = [], False
    resources[0].raw["client_list_readable"] = client_list_readable

    # ACL LOG — the "who was REFUSED" signal, and the only agentless way to see credential
    # stuffing against a Redis. Each entry names the username, the reason (auth/command/key/
    # channel) and the client that tried. Unsupported on Redis Cloud/Software, which is
    # recorded honestly rather than silently yielding an empty (and reassuring) list.
    try:
        acl_log = client.acl_log(count=128) or []
        acl_log_readable = True
    except Exception:
        acl_log, acl_log_readable = [], False
    resources[0].raw["acl_log_readable"] = acl_log_readable

    if acl_log_readable and acl_log:
        denials: dict = {}
        for entry in acl_log:
            # redis-py returns bytes or str depending on decode_responses/version.
            def _s(v):
                return v.decode() if isinstance(v, bytes) else (str(v) if v is not None else None)
            uname = _s(entry.get("username")) or "unknown"
            reason = _s(entry.get("reason")) or "unknown"
            key = (uname, reason)
            agg = denials.setdefault(key, {"count": 0, "objects": set(), "clients": set()})
            try:
                agg["count"] += int(entry.get("count") or 1)
            except (TypeError, ValueError):
                agg["count"] += 1
            if entry.get("object"):
                agg["objects"].add(_s(entry.get("object")))
            info = _s(entry.get("client-info")) or ""
            for tok in info.split():
                if tok.startswith("addr="):
                    agg["clients"].add(tok[5:].rsplit(":", 1)[0])

        for (uname, reason), agg in sorted(denials.items()):
            resources.append(Resource(
                kind="access_denial",
                name=f"{uname} denied ({reason})",
                ext_id=f"denial-{host}:{port}-{uname}-{reason}",
                labels={"principal": uname, "reason": reason,
                        "denials": str(agg["count"]), "source": "redis-acl-log"},
                raw={
                    "principal": uname,
                    "reason": reason,          # auth | command | key | channel
                    "denials": agg["count"],
                    # For reason=auth these are failed logins: the brute-force signal.
                    "objects": sorted(o for o in agg["objects"] if o),
                    "peer_hosts": sorted(c for c in agg["clients"] if c),
                    "server_ext": server_ext,
                    "observed_via": "ACL LOG",
                },
            ))

    if client_list_readable:
        seen: dict = {}
        for c in clients:
            addr = str(c.get("addr") or "")
            peer = addr.rsplit(":", 1)[0] if ":" in addr else addr
            principal = c.get("user")            # absent pre-Redis-6
            key = (principal, peer)
            agg = seen.setdefault(key, {"connections": 0, "commands": set(),
                                        "libs": set(), "max_age": 0, "min_idle": None})
            agg["connections"] += 1
            if c.get("cmd"):
                agg["commands"].add(str(c["cmd"]).split("|")[0])
            if c.get("lib-name"):
                agg["libs"].add(f"{c.get('lib-name')} {c.get('lib-ver') or ''}".strip())
            try:
                agg["max_age"] = max(agg["max_age"], int(c.get("age") or 0))
                idle = int(c.get("idle") or 0)
                agg["min_idle"] = idle if agg["min_idle"] is None else min(agg["min_idle"], idle)
            except (TypeError, ValueError):
                pass

        for (principal, peer), agg in sorted(seen.items(), key=lambda kv: str(kv[0])):
            ext = f"runtime-{host}:{port}-{principal or 'unknown'}-{peer}"
            resources.append(Resource(
                kind="runtime_client",
                name=f"{principal or 'unknown principal'} from {peer}",
                ext_id=ext,
                labels={
                    "principal": str(principal) if principal else "unknown",
                    "peer_host": peer,
                    "connections": str(agg["connections"]),
                    "source": "redis-client-list",
                },
                raw={
                    "principal": principal,
                    "principal_known": principal is not None,
                    "peer_host": peer,
                    "connections": agg["connections"],
                    # Command NAMES only. Arguments are never read — AUTH's argv carries a
                    # password and HELLO's carries one too.
                    "commands": sorted(agg["commands"]),
                    "client_libraries": sorted(agg["libs"]),
                    "max_age_seconds": agg["max_age"],
                    "min_idle_seconds": agg["min_idle"],
                    "server_ext": server_ext,
                    "observed_via": "CLIENT LIST",
                },
            ))
            if principal:
                edges.append(Edge(src_ext_id=ext,
                                  dst_ext_id=f"redis-user-{host}:{port}-{principal}",
                                  kind="acts_as"))
            edges.append(Edge(src_ext_id=ext, dst_ext_id=server_ext, kind="uses"))

    return Collected(resources=resources, edges=edges)
