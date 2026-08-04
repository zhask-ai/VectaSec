"""PgBouncer connector — read-only over the admin pseudo-database (psycopg).

PgBouncer is the connection-pooling middleware that sits in front of Postgres, so its own auth
and TLS posture is the real edge of every database behind it. This connector connects to the
`pgbouncer` admin console as an admin user and issues only SHOW commands (read-only; none mutate
pool state):

  SHOW CONFIG      the effective settings — auth_type, client_tls_sslmode, server_tls_sslmode,
                   admin_users, stats_users, auth_file (the security-relevant ones)
  SHOW DATABASES   the pooled databases and any pinned backend user (force_user / auth_user)
  SHOW USERS       the configured client users + their pool mode (the NHI material)
  SHOW CLIENTS     the RUNTIME half — who is connected to the pooler right now (user, database,
                   source address, and whether that client's own socket is TLS). A pooler is
                   the one place in an estate where every database client is visible at once,
                   which makes this the highest-yield runtime source we have short of a sensor.

Credential-reduction discipline (same contract as the Redis/RabbitMQ connectors): SHOW commands
never return a password value — PgBouncer masks connection-string passwords and the userlist
hashes are not exposed here — so the NHI layer records that a stored credential EXISTS and its
hashing shape (inferred from auth_type), never a secret. The admin password used to connect lives
only in the psycopg conninfo and is never copied into a Resource.

Kinds are DISTINCT (pgbouncer_pool, pgbouncer_database, pgbouncer_user) — except live clients,
which are emitted as the shared `runtime_client` kind that detect/runtime.py owns, because "a
shared admin account is connected right now from a public address" is the same finding wherever
the socket lands. See the same note in connect/nats.py.

Split for offline testing:
  collect(config)        opens the psycopg connection, runs the SHOW commands
  _parse_* / _build_*    pure: SHOW rows -> Collected (golden-fixture tested, no live psycopg)
"""
from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_TRUST_AUTH = {"trust", "any"}
_WEAK_AUTH = {"plain", "md5"}
# admin_users that name a shared Postgres superuser — giving the DB superuser the pooler console
# is the broad-admin pattern this connector flags.
_SHARED_ADMIN = {"postgres", "admin", "root"}


def _split_list(v) -> list:
    """PgBouncer renders admin_users/stats_users as a comma/space-separated string."""
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [p.strip() for p in str(v or "").replace(",", " ").split() if p.strip()]


# ── pure parse layer (SHOW rows in, normalized data out) ──────────────────────
def _parse_config(rows) -> dict:
    """SHOW CONFIG rows (each a dict with 'key' and 'value') → {key: value}."""
    out: dict = {}
    for row in rows or []:
        key = row.get("key")
        if key is not None:
            out[str(key)] = row.get("value")
    return out


def _parse_databases(rows) -> list:
    out = []
    for row in rows or []:
        name = row.get("name")
        if name is None:
            continue
        out.append({
            "name": name,
            "host": row.get("host"),
            "port": row.get("port"),
            "database": row.get("database"),
            "force_user": row.get("force_user"),
            "auth_user": row.get("auth_user"),
            "pool_mode": row.get("pool_mode"),
            "pool_size": row.get("pool_size"),
        })
    return out


def _parse_users(rows) -> list:
    out = []
    for row in rows or []:
        name = row.get("name")
        if name is None:
            continue
        out.append({"name": name, "pool_mode": row.get("pool_mode")})
    return out


def _parse_clients(rows) -> list:
    """SHOW CLIENTS rows → the live-client facts we keep.

    Only the columns that carry security meaning survive: who (`user`), against what
    (`database`), from where (`addr`), over what (`tls`), and since when (`connect_time`).
    Query text is never present in SHOW CLIENTS output, and we do not go looking for it —
    a posture tool has no business collecting the statements an application runs.
    """
    out = []
    for row in rows or []:
        user = row.get("user")
        if user is None:
            continue
        out.append({
            "user": user,
            "database": row.get("database"),
            "addr": row.get("addr"),
            "port": row.get("port"),
            "state": row.get("state"),
            # PgBouncer 1.14+ reports the client's own TLS as a version string, or an empty
            # string when the client connected in plaintext. Older builds omit the column
            # entirely — which is UNKNOWN, not "no TLS", and must stay distinguishable.
            "tls": row.get("tls"),
            "tls_reported": "tls" in row,
            "connect_time": row.get("connect_time"),
        })
    return out


def _build_runtime_clients(clients: list, pool_ext: str) -> tuple[list, list]:
    """Live pooler clients → `runtime_client` resources, aggregated by (user, database, addr).

    Aggregated for the same reason as NATS: an app server holds a pool of sockets under one
    role from one host, and one finding per socket would bury the one fact that matters.
    """
    agg: dict[tuple, dict] = {}
    for c in clients or []:
        user = str(c.get("user"))
        database = str(c.get("database") or "")
        addr = str(c.get("addr") or "unknown")
        slot = agg.setdefault((user, database, addr), {
            "connections": 0, "tls": set(), "states": set(), "tls_reported": False,
            "earliest_connect": None,
        })
        slot["connections"] += 1
        if c.get("tls_reported"):
            slot["tls_reported"] = True
            slot["tls"].add(bool(str(c.get("tls") or "").strip()))
        if c.get("state"):
            slot["states"].add(str(c["state"]))
        ct = c.get("connect_time")
        if ct and (slot["earliest_connect"] is None or str(ct) < slot["earliest_connect"]):
            slot["earliest_connect"] = str(ct)

    resources: list[Resource] = []
    edges: list[Edge] = []
    for (user, database, addr), a in sorted(agg.items()):
        # tls_all stays None when this PgBouncer build never reported the column: the rulepack
        # then says the transport could not be read, instead of asserting plaintext.
        all_tls = (a["tls"] == {True}) if a["tls_reported"] else None
        ext = f"runtime-{user}@{database}-{addr}"
        resources.append(Resource(
            kind="runtime_client",
            name=f"{user}@{database} from {addr}",
            ext_id=ext,
            namespace=database or None,
            labels={
                "principal": user,
                "database": database,
                "peer_host": addr,
                "connections": str(a["connections"]),
                "tls": str(all_tls).lower() if all_tls is not None else "unknown",
                "source": "pgbouncer-show-clients",
            },
            raw={
                "principal": user,
                "principal_known": True,   # SHOW CLIENTS always names the authenticated role
                "database": database,
                "vhost": database,         # the scope key runtime_evidence folds on
                "peer_host": addr,
                "connections": a["connections"],
                "tls_all": all_tls,
                "tls_mixed": len(a["tls"]) > 1,
                "states": sorted(a["states"]),
                "earliest_connected_at": a["earliest_connect"],
                "pool_ext": pool_ext,
                "observed_via": "SHOW CLIENTS",
            },
        ))
        edges.append(Edge(src_ext_id=ext, dst_ext_id=pool_ext, kind="uses"))
        edges.append(Edge(src_ext_id=ext, dst_ext_id=f"pgbouncer-user-{user}", kind="acts_as"))
    return resources, edges


def _build_resources(config: dict, databases: list, users: list, *,
                     config_readable: bool, outcomes: dict, clients: list | None = None) -> Collected:
    config = config or {}
    admin_users = _split_list(config.get("admin_users"))
    stats_users = _split_list(config.get("stats_users"))
    admin_set = {u.lower() for u in admin_users}

    resources: list[Resource] = []
    edges: list[Edge] = []

    pool_ext = "pgbouncer-pool"
    resources.append(Resource(
        kind="pgbouncer_pool",
        name=config.get("_target") or "pgbouncer",
        ext_id=pool_ext,
        labels={"auth_type": str(config.get("auth_type") or "?")},
        raw={
            "config_readable": config_readable,
            "auth_type": config.get("auth_type"),
            "auth_file": config.get("auth_file"),
            "auth_query": config.get("auth_query"),
            "client_tls_sslmode": config.get("client_tls_sslmode"),
            "server_tls_sslmode": config.get("server_tls_sslmode"),
            "admin_users": admin_users,
            "stats_users": stats_users,
            "max_client_conn": config.get("max_client_conn"),
            "ignore_startup_parameters": config.get("ignore_startup_parameters"),
            "databases_count": len(databases or []),
            "live_client_count": len(clients or []),
            "endpoint_outcomes": outcomes or {},
        },
    ))

    for db in databases or []:
        name = db.get("name")
        resources.append(Resource(
            kind="pgbouncer_database",
            name=str(name),
            ext_id=f"pgbouncer-db-{name}",
            labels={"backend_host": str(db.get("host") or "?")},
            raw={**db, "pool_ext": pool_ext},
        ))

    for u in users or []:
        name = u.get("name")
        resources.append(Resource(
            kind="pgbouncer_user",
            name=str(name),
            ext_id=f"pgbouncer-user-{name}",
            labels={"is_admin": "true" if str(name).lower() in admin_set else "false"},
            raw={**u, "is_admin": str(name).lower() in admin_set, "pool_ext": pool_ext},
        ))

    rt_resources, rt_edges = _build_runtime_clients(clients or [], pool_ext)
    resources.extend(rt_resources)
    edges.extend(rt_edges)

    return Collected(resources=resources, edges=edges)


# ── collection (psycopg admin console) ────────────────────────────────────────
@connector("pgbouncer", fields=[
    ConnectorField("host", "Host", required=True, placeholder="localhost",
                   help="PgBouncer host the engine or worker can reach. Read-only — only SHOW "
                        "commands on the admin console."),
    ConnectorField("port", "Port", placeholder="6432"),
    ConnectorField("admin_user", "Admin user", required=True, placeholder="pgbouncer",
                   help="A user listed in PgBouncer's `admin_users` (needed to run SHOW on the "
                        "admin console)."),
    ConnectorField("admin_password", "Admin password", secret=True,
                   help="Used to open the admin connection; never persisted into any resource."),
    ConnectorField("sslmode", "SSL mode", placeholder="prefer",
                   help="psycopg sslmode for the admin connection (disable/prefer/require/"
                        "verify-full)."),
])
def collect(config: dict) -> Collected:
    import psycopg

    host = (config.get("host") or "").strip()
    if not host:
        raise SystemExit("pgbouncer connector requires config['host']")
    port = int(config.get("port") or 6432)
    admin_user = (config.get("admin_user") or "").strip()
    password = config.get("admin_password") or ""
    sslmode = (config.get("sslmode") or "prefer").strip()
    timeout = int(float(config.get("timeout") or 10))

    conninfo = psycopg.conninfo.make_conninfo(
        host=host, port=port, dbname="pgbouncer", user=admin_user,
        password=password, sslmode=sslmode, connect_timeout=timeout)

    outcomes: dict = {}
    cfg: dict = {}
    databases: list = []
    users: list = []
    clients: list = []
    config_readable = False

    def _rows(cur):
        cols = [d.name for d in cur.description] if cur.description else []
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    conn = psycopg.connect(conninfo, autocommit=True)
    try:
        with conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("SHOW CONFIG")
                    cfg = _parse_config(_rows(cur))
                    config_readable = bool(cfg)
                    outcomes["config"] = "ok" if cfg else "error"
                except psycopg.Error as e:
                    outcomes["config"] = f"error: {type(e).__name__}: {e}"
                try:
                    cur.execute("SHOW DATABASES")
                    databases = _parse_databases(_rows(cur))
                    outcomes["databases"] = "ok"
                except psycopg.Error as e:
                    outcomes["databases"] = f"error: {type(e).__name__}: {e}"
                try:
                    cur.execute("SHOW USERS")
                    users = _parse_users(_rows(cur))
                    outcomes["users"] = "ok"
                except psycopg.Error as e:
                    outcomes["users"] = f"error: {type(e).__name__}: {e}"
                try:
                    cur.execute("SHOW CLIENTS")
                    clients = _parse_clients(_rows(cur))
                    outcomes["clients"] = "ok"
                except psycopg.Error as e:
                    # A stats-only user can read CONFIG but not CLIENTS. That is a coverage
                    # boundary worth recording, not a scan failure: the posture half is still
                    # entirely valid without the runtime half.
                    outcomes["clients"] = f"error: {type(e).__name__}: {e}"
    finally:
        conn.close()

    cfg["_target"] = f"{host}:{port}"
    return _build_resources(cfg, databases, users, config_readable=config_readable,
                            outcomes=outcomes, clients=clients)


# ── NHI: pgbouncer users → identity + credential, backends → identity/credential ──
def _hashing_for_auth_type(auth_type):
    """The credential-storage shape implied by auth_type. md5 is weak (the generic NHI pack
    flags it); plain is plaintext at rest; scram is modern; trust/any means NO stored secret."""
    a = str(auth_type or "").lower()
    if a == "md5":
        return "md5", False
    if a == "plain":
        return "plaintext", True
    if a == "scram-sha-256":
        return "scram-sha-256", False
    return "unknown", None


@identity_extractor("pgbouncer")
def _from_pgbouncer(resources: list) -> tuple:
    """PgBouncer's identities in the normalized NHI model:

      pgbouncer_user     → identity (db_user; 'admin' when in admin_users) + one credential
                           per user whose auth_type stores a secret (metadata only, no value) +
                           a console-admin grant for admin users
      pgbouncer_database → a backend identity per pinned force_user/auth_user + a credential
                           recording that a stored backend secret exists

    Edges: credential --credential_of--> identity, grant --granted_to--> identity.
    """
    out: list[Resource] = []
    edges: list[Edge] = []

    pool = next((r for r in resources if r.kind == "pgbouncer_pool"), None)
    pool_raw = (pool.raw if pool else {}) or {}
    auth_type = pool_raw.get("auth_type")
    admin_users = {u.lower() for u in (pool_raw.get("admin_users") or [])}
    stats_users = {u.lower() for u in (pool_raw.get("stats_users") or [])}
    hashing, plaintext = _hashing_for_auth_type(auth_type)
    stores_secret = str(auth_type or "").lower() not in _TRUST_AUTH and auth_type is not None

    for r in resources:
        if r.kind != "pgbouncer_user":
            continue
        raw = r.raw or {}
        name = str(raw.get("name") or r.name)
        is_admin = bool(raw.get("is_admin"))
        idr = _mk_identity("pgbouncer", "admin" if is_admin else "db_user", name,
                           source_ext=r.ext_id,
                           extra={"pool_mode": raw.get("pool_mode"), "is_admin": is_admin})
        out.append(idr)

        if stores_secret:
            cred = _mk_credential("pgbouncer", idr.ext_id, "password", name=f"{name}:password",
                                  hashing=hashing, present=True, plaintext=plaintext)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))

        if is_admin or name.lower() in stats_users:
            action = "console-admin" if is_admin else "console-stats"
            g = _mk_grant("pgbouncer", idr.ext_id, action, "pgbouncer",
                          wildcard=is_admin, extra={"console": True})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))

    # Backend identities: a database pinned to a force_user/auth_user carries stored backend
    # credentials (in the [databases] connection string or the auth_file), recorded as metadata.
    seen_backends: dict[str, Resource] = {}
    for r in resources:
        if r.kind != "pgbouncer_database":
            continue
        raw = r.raw or {}
        backend_user = raw.get("force_user") or raw.get("auth_user")
        if not backend_user:
            continue
        dbname = raw.get("database") or raw.get("name")
        label = f"{backend_user}@{dbname}"
        idr = seen_backends.get(label)
        if idr is None:
            idr = _mk_identity("pgbouncer", "db_backend", label, source_ext=r.ext_id,
                               extra={"backend_user": backend_user, "database": dbname,
                                      "host": raw.get("host")})
            seen_backends[label] = idr
            out.append(idr)
            cred = _mk_credential("pgbouncer", idr.ext_id, "backend_password",
                                  name=f"{label}:password", hashing="unknown", present=True)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return out, edges
