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
from ..contracts import Resource, Collected

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

    return Collected(resources=resources, edges=[])
