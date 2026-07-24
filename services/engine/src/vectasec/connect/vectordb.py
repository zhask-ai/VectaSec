"""Vector-DB / RAG-store connector — read-only posture over the AI-era exposed-data substrate.

Vector stores are the new middleware: they hold the embeddings AND the source-document chunks a
RAG pipeline retrieves, so an unauthenticated one is a data-exfiltration surface and — worse — a
*write* surface for RAG poisoning (inject a chunk, and the LLM will faithfully quote your attacker).
The internet is full of them open: Chroma, Weaviate, Qdrant and Milvus all ship auth-OFF by default
and are routinely bound to 0.0.0.0 behind nothing.

One connector, five engines, all read-only:

  chroma     REST :8000   heartbeat + /version + /collections
  weaviate   REST :8080   /v1/meta + /v1/schema + /v1/.well-known/openid-configuration
  qdrant     REST :6333   / (version) + /collections + /metrics
  milvus     REST :9091   /healthz + /metrics  (the health/metrics surface; the 19530 gRPC data
                          plane is deliberately NOT spoken — auth there is recorded not-assessable)
  pgvector   Postgres     the `vector` extension on a host Postgres, read via psycopg: extension
                          presence + the host's auth (passwordless?/superuser?) and TLS as they
                          apply to the vector store

Three disciplines carried from the other connectors:

  • Secrets are used, never persisted. `api_key`/`dsn` are ConnectorField secret=True; they open a
    request/connection inside collect() and are never copied into a Resource. For pgvector the DSN
    password is parsed only to learn presence (dsn_has_password) then dropped.
  • Unauthenticated FIRST. Every REST engine is probed with NO credential first — that probe is the
    load-bearing posture signal (can anyone on the network read/write your vectors?) and the api_key
    probe, if a key was given, only proves the key works. Nothing here ever issues a write: anonymous
    write exposure is DERIVED from the engine's auth model (uniform vs. read-only-possible), never by
    actually inserting a vector.
  • Per-probe error isolation. A denied/unreachable endpoint is recorded in `probe_errors`, so
    detect/vectordb.py surfaces it as a not-assessable coverage gap instead of a clean pass.

The parse layer (`normalize_*` + `build_collected`) is PURE: probe-result dicts in, Resources out.
Tests feed golden dicts shaped like each engine's REST JSON straight through it, so httpx/psycopg
stay out of the test suite and a shape drift fails a test instead of mis-firing in production.

Kinds are DISTINCT and prefixed `vectordb_` (vectordb_server, vectordb_collection) so no other
rulepack ever runs against a vector-store resource by accident — the same reason connect/redis.py
refuses to reuse `broker`.
"""
from urllib.parse import urlsplit

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_REST_ENGINES = ("chroma", "weaviate", "qdrant", "milvus")
_DEFAULT_PORTS = {"chroma": 8000, "weaviate": 8080, "qdrant": 6333, "milvus": 9091}

# How each engine's built-in auth treats an anonymous client that can already READ:
#   uniform          one credential guards read AND write; anonymous-read ⇒ anonymous-write
#                    (Chroma token/basic auth and Qdrant's api-key are all-or-nothing — neither has
#                    an anonymous-read-only mode, so a readable server is a writable one)
#   split_possible   the engine CAN grant anonymous read-only (Weaviate anonymous access + an
#                    admin/read-only list), so write exposure is NOT implied by read exposure
#   opaque           we did not touch the data plane (Milvus 9091 is health/metrics only), so
#                    neither read nor write of the store was assessed
_AUTH_MODEL = {"chroma": "uniform", "qdrant": "uniform",
               "weaviate": "split_possible", "milvus": "opaque"}

# Which engines have a fine-grained authorization layer worth reporting as "supported but off".
# Qdrant OSS has only api-key / read-only-key (no RBAC), so RBAC.DISABLED does not apply to it.
_RBAC_SUPPORTED = {"chroma": True, "weaviate": True, "milvus": True, "qdrant": False}

# Which engines have a tenant/namespace concept a collection can fail to use (landing in the shared
# default). Qdrant collections are flat (no tenancy) so the shared-default rule does not apply.
_TENANCY_SUPPORTED = {"chroma": True, "weaviate": True, "milvus": True,
                      "pgvector": True, "qdrant": False}

# The named shared/default tenants a collection can land in. A tenant of None means the collection
# is ISOLATED (e.g. a Weaviate multi-tenancy-enabled class) or the engine has no tenancy — NOT the
# shared default, so None is deliberately absent here.
_DEFAULT_TENANTS = {"default_tenant", "default_database", "default", "public"}


# ── derivation shared by every REST engine ────────────────────────────────────
def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _derive_access(status, auth_model: str) -> tuple:
    """(unauth_read_ok, auth_enforced, anon_write_possible) from the unauthenticated list status.

    200          → read open; auth not enforced. Write open too iff the auth model is uniform;
                   not-assessable (None) when the engine could be anonymous-read-only or opaque.
    401 / 403    → read refused; auth enforced; write not open.
    None / other → unreachable or an ambiguous status (404/500): every outcome stays None so the
                   rulepack answers not-assessable, never a clean pass.
    """
    if status == 200:
        read_ok, enforced = True, False
    elif status in (401, 403):
        return False, True, False
    else:
        return None, None, None
    if auth_model == "uniform":
        write = True
    else:                       # split_possible (anon RO possible) or opaque (data plane untouched)
        write = None
    return read_ok, enforced, write


def _metrics_exposed(status) -> tuple:
    if status is None:
        return None, None
    return status, status == 200


def _server_facts(engine: str, host: str, port: int, tls: bool, *, api_key_provided: bool,
                  version, unauth_status, auth_model: str, rbac_enabled, metrics_status,
                  probe_errors: dict, extra: dict | None = None) -> dict:
    read_ok, enforced, write = _derive_access(unauth_status, auth_model)
    m_status, m_exposed = _metrics_exposed(metrics_status)
    facts = {
        "engine": engine,
        "host": host,
        "port": port,
        "connected_via_tls": bool(tls),
        "reachable": read_ok is not None or bool(version) or metrics_status is not None,
        "version": version,
        "api_key_provided": bool(api_key_provided),
        "engine_auth_model": auth_model,
        "unauth_list_status": unauth_status,
        "unauth_read_ok": read_ok,
        "auth_enforced": enforced,
        "anon_write_possible": write,
        "rbac_supported": _RBAC_SUPPORTED.get(engine, False),
        "rbac_enabled": rbac_enabled,
        "multitenancy_supported": _TENANCY_SUPPORTED.get(engine, False),
        "metrics_status": m_status,
        "metrics_exposed": m_exposed,
        "probe_errors": {k: v for k, v in (probe_errors or {}).items() if v},
    }
    facts.update(extra or {})
    return facts


def _collection(engine: str, host: str, port: int, tls: bool, name: str, *,
                listed_anonymously, tenant=None, namespace=None, ident: str = "") -> dict:
    return {
        "engine": engine,
        "name": name,
        "id": ident or name,
        "tenant": tenant,
        "namespace": namespace,
        # True = discovered by the unauthenticated probe; False = only the authenticated probe saw
        # it; None = the anonymous probe errored, so anonymous listability is genuinely unknown.
        "listed_anonymously": listed_anonymously,
        # In the shared default only when the tenant is a NAMED default and any namespace is too;
        # a None tenant is isolation/no-tenancy, never the shared default.
        "default_tenant": (tenant in _DEFAULT_TENANTS
                           and (namespace is None or namespace in _DEFAULT_TENANTS)),
        "multitenancy_supported": _TENANCY_SUPPORTED.get(engine, False),
        "connected_via_tls": bool(tls),
        "host": host,
        "port": port,
    }


def _rest_collections(engine, host, port, tls, unauth_probe, auth_probe, extract) -> list:
    """Build collection dicts from whichever list probe succeeded, tagging anonymous-listability.

    `extract(json) -> [{name, id?, tenant?, namespace?}]` is the engine-specific shredder. The
    unauthenticated probe wins when it returns 200 (anonymous listing → listed_anonymously=True);
    otherwise the authenticated probe supplies the inventory, tagged False (auth was required) or
    None (the anonymous probe errored, so we cannot claim it was NOT anonymously listable)."""
    us = (unauth_probe or {}).get("status")
    if us == 200:
        rows, flag = extract((unauth_probe or {}).get("json")), True
    else:
        ap = auth_probe or {}
        if ap.get("status") == 200:
            rows = extract(ap.get("json"))
            flag = None if us is None else False
        else:
            rows, flag = [], None
    return [_collection(engine, host, port, tls, str(row.get("name")),
                        listed_anonymously=flag, tenant=row.get("tenant"),
                        namespace=row.get("namespace"),
                        ident=str(row.get("id") or row.get("name")))
            for row in rows if isinstance(row, dict) and row.get("name") is not None]


def _extract_chroma(js) -> list:
    if not isinstance(js, list):
        return []
    return [{"name": c.get("name"), "id": c.get("id"), "tenant": c.get("tenant"),
             "namespace": c.get("database")} for c in js if isinstance(c, dict)]


def _extract_weaviate(js) -> list:
    if not isinstance(js, dict):
        return []
    out = []
    for c in js.get("classes") or []:
        if not isinstance(c, dict):
            continue
        mt = (c.get("multiTenancyConfig") or {}).get("enabled")
        # A class WITH multi-tenancy isolates data per tenant; without it every object shares one
        # namespace, modelled as the shared default tenant.
        out.append({"name": c.get("class"), "id": c.get("class"),
                    "tenant": None if mt else "default", "namespace": None})
    return out


def _extract_qdrant(js) -> list:
    if not isinstance(js, dict):
        return []
    return [{"name": c.get("name"), "id": c.get("name")}
            for c in ((js.get("result") or {}).get("collections") or []) if isinstance(c, dict)]


# ── per-engine normalize: raw probe dicts → {"server": facts, "collections": [...]} ──
# Each *_probe arg is a dict {"status": int|None, "json": <parsed>|None, "error": str|None}.

def normalize_chroma(host, port, tls, *, api_key_provided, version_probe, list_probe,
                     auth_list_probe=None, metrics_probe=None) -> dict:
    vp = (version_probe or {})
    version = None
    if vp.get("status") == 200:
        v = vp.get("json")
        version = v if isinstance(v, str) else ((v or {}).get("version") if isinstance(v, dict) else None)
    status = (list_probe or {}).get("status")
    cols = _rest_collections("chroma", host, port, tls, list_probe, auth_list_probe, _extract_chroma)
    read_ok, _, _ = _derive_access(status, _AUTH_MODEL["chroma"])
    rbac_enabled = False if read_ok is True else (True if read_ok is False else None)
    facts = _server_facts(
        "chroma", host, port, tls, api_key_provided=api_key_provided, version=version,
        unauth_status=status, auth_model=_AUTH_MODEL["chroma"], rbac_enabled=rbac_enabled,
        metrics_status=(metrics_probe or {}).get("status"),
        probe_errors={"version": vp.get("error"), "collections": (list_probe or {}).get("error"),
                      "metrics": (metrics_probe or {}).get("error")})
    return {"server": facts, "collections": cols}


def normalize_weaviate(host, port, tls, *, api_key_provided, meta_probe, schema_probe,
                       openid_probe=None, auth_schema_probe=None, metrics_probe=None) -> dict:
    mp = (meta_probe or {})
    version = (mp.get("json") or {}).get("version") if mp.get("status") == 200 else None
    status = (schema_probe or {}).get("status")
    cols = _rest_collections("weaviate", host, port, tls, schema_probe, auth_schema_probe,
                             _extract_weaviate)
    op = (openid_probe or {})
    openid_configured = op.get("status") == 200
    read_ok, _, _ = _derive_access(status, _AUTH_MODEL["weaviate"])
    # Weaviate authz = OIDC/RBAC or an admin-list. OIDC configured ⇒ access control exists. Anonymous
    # read working with NO OIDC discovered ⇒ no access control is in force. Otherwise unknown.
    rbac_enabled = True if openid_configured else (False if read_ok is True else None)
    facts = _server_facts(
        "weaviate", host, port, tls, api_key_provided=api_key_provided, version=version,
        unauth_status=status, auth_model=_AUTH_MODEL["weaviate"], rbac_enabled=rbac_enabled,
        metrics_status=(metrics_probe or {}).get("status"),
        probe_errors={"meta": mp.get("error"), "schema": (schema_probe or {}).get("error"),
                      "openid": op.get("error"), "metrics": (metrics_probe or {}).get("error")},
        extra={"openid_configured": openid_configured})
    return {"server": facts, "collections": cols}


def normalize_qdrant(host, port, tls, *, api_key_provided, root_probe, list_probe,
                     auth_list_probe=None, metrics_probe=None) -> dict:
    rp = (root_probe or {})
    version = (rp.get("json") or {}).get("version") if rp.get("status") == 200 else None
    status = (list_probe or {}).get("status")
    cols = _rest_collections("qdrant", host, port, tls, list_probe, auth_list_probe, _extract_qdrant)
    facts = _server_facts(
        "qdrant", host, port, tls, api_key_provided=api_key_provided, version=version,
        unauth_status=status, auth_model=_AUTH_MODEL["qdrant"], rbac_enabled=None,
        metrics_status=(metrics_probe or {}).get("status"),
        probe_errors={"root": rp.get("error"), "collections": (list_probe or {}).get("error"),
                      "metrics": (metrics_probe or {}).get("error")})
    return {"server": facts, "collections": cols}


def normalize_milvus(host, port, tls, *, api_key_provided, health_probe, metrics_probe) -> dict:
    hp = (health_probe or {})
    # The 9091 surface is health/metrics only — the data plane (collections, auth) is on 19530 gRPC
    # which we do not speak, so unauth_list_status stays None → read/write are not-assessable.
    facts = _server_facts(
        "milvus", host, port, tls, api_key_provided=api_key_provided, version=None,
        unauth_status=None, auth_model=_AUTH_MODEL["milvus"], rbac_enabled=None,
        metrics_status=(metrics_probe or {}).get("status"),
        probe_errors={"health": hp.get("error"), "metrics": (metrics_probe or {}).get("error")},
        extra={"health_status": hp.get("status"),
               "health_ok": hp.get("status") == 200})
    return {"server": facts, "collections": []}


def normalize_pgvector(host, port, dbname, *, pg) -> dict:
    """pg is the read-only fact bundle collect() gathered via psycopg (all pure below).

    Expected keys: extension_present, extension_version, ssl_in_use, ssl_setting,
    dsn_has_password, passwordless_auth, current_user, is_superuser, hba_readable,
    roles (list of {rolname, rolsuper, rolcanlogin, has_password}), vector_tables
    (list of {schema, table}), errors (dict).
    """
    ssl_in_use = pg.get("ssl_in_use")
    facts = {
        "engine": "pgvector",
        "host": host,
        "port": port,
        "database": dbname,
        "connected_via_tls": bool(ssl_in_use),
        "reachable": True,
        "version": pg.get("extension_version"),
        "api_key_provided": bool(pg.get("dsn_has_password")),
        # auth-model REST facts are N/A for pgvector; the pgvector-specific rules read the block below
        "engine_auth_model": "postgres",
        "unauth_read_ok": None,
        "auth_enforced": None,
        "anon_write_possible": None,
        "rbac_supported": False,
        "rbac_enabled": None,
        "multitenancy_supported": _TENANCY_SUPPORTED["pgvector"],
        "metrics_status": None,
        "metrics_exposed": None,
        "pgvector": {
            "extension_present": bool(pg.get("extension_present")),
            "extension_version": pg.get("extension_version"),
            "ssl_in_use": ssl_in_use,
            "ssl_setting": pg.get("ssl_setting"),
            "dsn_has_password": bool(pg.get("dsn_has_password")),
            "passwordless_auth": pg.get("passwordless_auth"),
            "current_user": pg.get("current_user"),
            "is_superuser": pg.get("is_superuser"),
            "hba_readable": bool(pg.get("hba_readable")),
        },
        "pg_roles": pg.get("roles") or [],
        "probe_errors": {k: v for k, v in (pg.get("errors") or {}).items() if v},
    }
    cols = []
    for t in pg.get("vector_tables") or []:
        schema = t.get("schema")
        cols.append(_collection(
            "pgvector", host, port, bool(ssl_in_use), f"{schema}.{t.get('table')}",
            listed_anonymously=False, tenant=schema, namespace=None,
            ident=f"{schema}.{t.get('table')}"))
    return {"server": facts, "collections": cols}


# ── pure build: snapshot → Collected ──────────────────────────────────────────
def _server_ext(engine: str, host: str, port: int) -> str:
    return f"vectordb-{engine}-{host}:{port}"


def build_collected(snapshot: dict) -> Collected:
    """{"server": facts, "collections": [...]} → Collected. Pure; no I/O."""
    facts = snapshot["server"]
    engine, host, port = facts["engine"], facts["host"], facts["port"]
    sext = _server_ext(engine, host, port)
    resources = [Resource(
        kind="vectordb_server",
        name=f"{host}:{port}",
        ext_id=sext,
        namespace=host,
        labels={"engine": engine, "version": str(facts.get("version") or "?"),
                "tls": "true" if facts.get("connected_via_tls") else "false"},
        raw={**facts, "endpoint": _endpoint(facts)},
    )]
    edges = []
    for c in snapshot.get("collections") or []:
        cext = f"{sext}/col/{c['name']}"
        resources.append(Resource(
            kind="vectordb_collection",
            name=str(c["name"]),
            ext_id=cext,
            namespace=host,
            labels={"engine": engine,
                    "listed_anonymously": "true" if c.get("listed_anonymously") else "false"},
            raw={**c, "server_ext": sext},
        ))
        edges.append(Edge(src_ext_id=sext, dst_ext_id=cext, kind="contains"))
    return Collected(resources=resources, edges=edges)


def _endpoint(facts: dict) -> str:
    engine, host, port = facts["engine"], facts["host"], facts["port"]
    if engine == "pgvector":
        return f"postgresql://{host}:{port}/{facts.get('database')}"
    scheme = "https" if facts.get("connected_via_tls") else "http"
    return f"{scheme}://{host}:{port}"


# ── live collection (httpx / psycopg in, per-probe isolation) ─────────────────
def _http_get(client, url: str, headers: dict | None = None) -> dict:
    try:
        r = client.get(url, headers=headers or {})
    except Exception as e:                       # unreachable / TLS / timeout — recorded, not raised
        return {"status": None, "json": None, "error": f"{type(e).__name__}: {e}"}
    doc = None
    if r.status_code == 200:
        try:
            doc = r.json()
        except ValueError:
            doc = None
    return {"status": r.status_code, "json": doc, "error": None}


def _rest_target(config: dict, engine: str) -> tuple:
    """(base_url, host, port, tls) from base_url OR host/port/tls."""
    base = (config.get("base_url") or "").strip()
    if base:
        s = urlsplit(base)
        host = s.hostname or ""
        tls = s.scheme == "https"
        port = s.port or (443 if tls else _DEFAULT_PORTS.get(engine, 80))
        return base.rstrip("/"), host, port, tls
    host = (config.get("host") or "").strip()
    if not host:
        raise SystemExit(f"vectordb/{engine} connector requires config['base_url'] or config['host']")
    tls = _truthy(config.get("tls"))
    port = int(config.get("port") or _DEFAULT_PORTS.get(engine, 80))
    scheme = "https" if tls else "http"
    return f"{scheme}://{host}:{port}", host, port, tls


def _auth_headers(engine: str, api_key: str) -> dict:
    if engine == "qdrant":
        return {"api-key": api_key}
    return {"Authorization": f"Bearer {api_key}", "X-Chroma-Token": api_key}


def _collect_rest(config: dict, engine: str) -> Collected:
    import httpx  # local import keeps `import vectasec` dependency-light (config.py contract)

    base, host, port, tls = _rest_target(config, engine)
    api_key = (config.get("api_key") or "").strip() or None
    timeout = float(config.get("timeout") or 10)

    auth = _auth_headers(engine, api_key) if api_key else None

    with httpx.Client(timeout=timeout, follow_redirects=True, verify=False) as client:
        if engine == "chroma":
            snap = normalize_chroma(
                host, port, tls, api_key_provided=bool(api_key),
                version_probe=_http_get(client, f"{base}/api/v1/version"),
                list_probe=_http_get(client, f"{base}/api/v1/collections"),
                auth_list_probe=(_http_get(client, f"{base}/api/v1/collections", auth)
                                 if auth else None),
                metrics_probe=_http_get(client, f"{base}/metrics"))
        elif engine == "weaviate":
            snap = normalize_weaviate(
                host, port, tls, api_key_provided=bool(api_key),
                meta_probe=_http_get(client, f"{base}/v1/meta"),
                schema_probe=_http_get(client, f"{base}/v1/schema"),
                auth_schema_probe=(_http_get(client, f"{base}/v1/schema", auth) if auth else None),
                openid_probe=_http_get(client, f"{base}/v1/.well-known/openid-configuration"),
                metrics_probe=_http_get(client, f"{base}/metrics"))
        elif engine == "qdrant":
            snap = normalize_qdrant(
                host, port, tls, api_key_provided=bool(api_key),
                root_probe=_http_get(client, f"{base}/"),
                list_probe=_http_get(client, f"{base}/collections"),
                auth_list_probe=(_http_get(client, f"{base}/collections", auth) if auth else None),
                metrics_probe=_http_get(client, f"{base}/metrics"))
        elif engine == "milvus":
            snap = normalize_milvus(
                host, port, tls, api_key_provided=bool(api_key),
                health_probe=_http_get(client, f"{base}/healthz"),
                metrics_probe=_http_get(client, f"{base}/metrics"))
        else:  # pragma: no cover - guarded by collect()
            raise SystemExit(f"vectordb: unknown REST engine {engine!r}")

    return build_collected(snap)


def _collect_pgvector(config: dict) -> Collected:
    import psycopg  # local import (same dependency-light contract as above)
    from psycopg import conninfo  # submodule is not auto-imported by `import psycopg`

    dsn = (config.get("dsn") or "").strip()
    if not dsn:
        raise SystemExit("vectordb/pgvector connector requires config['dsn']")
    timeout = int(float(config.get("timeout") or 10))

    # Presence of a password in the DSN — learnt, then the value is never touched again.
    dsn_has_password = False
    try:
        parsed = conninfo.conninfo_to_dict(dsn)
        dsn_has_password = bool(parsed.get("password"))
        host = parsed.get("host") or "localhost"
        port = int(parsed.get("port") or 5432)
        dbname = parsed.get("dbname") or parsed.get("user") or "postgres"
    except Exception:
        host, port, dbname = "unknown", 5432, "postgres"

    errors: dict = {}
    pg = {"dsn_has_password": dsn_has_password, "errors": errors}

    conn = psycopg.connect(dsn, connect_timeout=timeout, autocommit=True)
    try:
        conn.read_only = True
    except Exception:
        pass
    try:
        with conn.cursor() as cur:
            def q1(sql):
                cur.execute(sql)
                row = cur.fetchone()
                return row[0] if row else None

            try:
                pg["extension_version"] = q1(
                    "SELECT extversion FROM pg_extension WHERE extname = 'vector'")
                pg["extension_present"] = pg["extension_version"] is not None
            except Exception as e:
                errors["extension"] = f"{type(e).__name__}: {e}"
                pg["extension_present"] = None

            try:
                pg["ssl_in_use"] = q1(
                    "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            except Exception as e:
                errors["ssl_in_use"] = f"{type(e).__name__}: {e}"
            try:
                pg["ssl_setting"] = q1("SHOW ssl")
            except Exception as e:
                errors["ssl_setting"] = f"{type(e).__name__}: {e}"

            try:
                pg["current_user"] = q1("SELECT current_user")
                pg["is_superuser"] = q1(
                    "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            except Exception as e:
                errors["current_user"] = f"{type(e).__name__}: {e}"

            # pg_hba trust rules require superuser to read; unreadable → passwordless stays unknown.
            hba_trust = None
            try:
                cur.execute("SELECT count(*) FROM pg_hba_file_rules "
                            "WHERE auth_method = 'trust'")
                hba_trust = cur.fetchone()[0]
                pg["hba_readable"] = True
            except Exception:
                pg["hba_readable"] = False
            pg["passwordless_auth"] = _pg_passwordless(hba_trust, pg["hba_readable"],
                                                       dsn_has_password)

            # Roles — the NHI material. rolpassword lives in pg_authid (superuser only); when we
            # cannot read it, credential presence is recorded as unknown, never guessed.
            roles = []
            pw_by_role: dict = {}
            try:
                cur.execute("SELECT rolname, (rolpassword IS NOT NULL) FROM pg_authid")
                pw_by_role = {r[0]: bool(r[1]) for r in cur.fetchall()}
            except Exception:
                pw_by_role = {}
            try:
                cur.execute("SELECT rolname, rolsuper, rolcanlogin FROM pg_roles "
                            "ORDER BY rolname")
                for name, sup, canlogin in cur.fetchall():
                    roles.append({"rolname": name, "rolsuper": bool(sup),
                                  "rolcanlogin": bool(canlogin),
                                  "has_password": pw_by_role.get(name)})
            except Exception as e:
                errors["roles"] = f"{type(e).__name__}: {e}"
            pg["roles"] = roles

            # "Collections" = tables carrying a `vector`-typed column.
            tables = []
            try:
                cur.execute("SELECT table_schema, table_name FROM information_schema.columns "
                            "WHERE udt_name = 'vector' GROUP BY table_schema, table_name "
                            "ORDER BY table_schema, table_name")
                tables = [{"schema": s, "table": t} for s, t in cur.fetchall()]
            except Exception as e:
                errors["vector_tables"] = f"{type(e).__name__}: {e}"
            pg["vector_tables"] = tables
    finally:
        conn.close()

    return build_collected(normalize_pgvector(host, port, dbname, pg=pg))


def _pg_passwordless(hba_trust, hba_readable: bool, dsn_has_password: bool):
    """True/False/None. Trust rules in pg_hba are definitive when readable; otherwise a DSN with a
    password proves password auth (False), and a DSN without one is genuinely unknown (None) —
    peer/cert/ident auth are all passwordless-but-safe, so we must not assert 'passwordless'."""
    if hba_readable and hba_trust is not None:
        return hba_trust > 0
    if dsn_has_password:
        return False
    return None


@connector("vectordb", fields=[
    ConnectorField("engine", "Engine", required=True,
                   placeholder="chroma | weaviate | qdrant | milvus | pgvector",
                   help="Which vector store this connection points at. One connector, read-only, "
                        "covers all five."),
    ConnectorField("base_url", "Base URL", placeholder="http://localhost:8000",
                   help="Full REST base URL (chroma/weaviate/qdrant/milvus). Overrides host/port/tls."),
    ConnectorField("host", "Host", placeholder="localhost",
                   help="Hostname/IP (used with port/tls if base_url is empty)."),
    ConnectorField("port", "Port", placeholder="8000 / 8080 / 6333 / 9091"),
    ConnectorField("tls", "Use TLS", placeholder="false",
                   help="'true' to connect over https. Read-only either way."),
    ConnectorField("api_key", "API key / token", secret=True,
                   help="Only if the store requires one. The unauthenticated probe runs first "
                        "regardless — it is the posture signal."),
    ConnectorField("dsn", "Postgres DSN", secret=True,
                   placeholder="postgresql://user:pass@host:5432/db",
                   help="pgvector only. The password is read to learn presence, then dropped — "
                        "never stored. All queries are read-only."),
])
def collect(config: dict) -> Collected:
    engine = (config.get("engine") or "").strip().lower()
    if engine == "pgvector":
        return _collect_pgvector(config)
    if engine in _REST_ENGINES:
        return _collect_rest(config, engine)
    raise SystemExit(
        f"vectordb connector: unknown engine {engine!r} "
        f"(have: pgvector, {', '.join(_REST_ENGINES)})")


# ── NHI: enumerable Postgres roles behind a pgvector store ────────────────────
@identity_extractor("vectordb")
def _from_vectordb(resources: list) -> tuple:
    """The only vector store that exposes an enumerable principal list read-only is pgvector's host
    Postgres (pg_roles). REST engines expose no user list to an unauthenticated/read client, so they
    contribute no NHIs — absence recorded honestly, not silence. Each login role → one identity; a
    password (when pg_authid was readable) → credential METADATA only (presence, never the hash);
    superuser/login → grants."""
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "vectordb_server" or (r.raw or {}).get("engine") != "pgvector":
            continue
        for role in (r.raw or {}).get("pg_roles") or []:
            name = role.get("rolname")
            if not name:
                continue
            is_super = bool(role.get("rolsuper"))
            can_login = bool(role.get("rolcanlogin"))
            itype = "database_superuser" if is_super else (
                "database_login_role" if can_login else "database_group_role")
            idr = _mk_identity("vectordb", itype, name, source_ext=r.ext_id,
                               extra={"can_login": can_login, "superuser": is_super,
                                      "engine": "pgvector"})
            out.append(idr)

            has_pw = role.get("has_password")
            if can_login and has_pw is not None:
                cred = _mk_credential(
                    "vectordb", idr.ext_id, "password", name=f"{name}:password",
                    hashing="scram-sha-256", present=bool(has_pw), plaintext=False)
                out.append(cred)
                edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                                  kind="credential_of"))

            action = "superuser" if is_super else ("login" if can_login else "nologin")
            g = _mk_grant("vectordb", idr.ext_id, action, r.ext_id,
                          wildcard=is_super, extra={"engine": "pgvector"})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id, kind="grants_access"))
    return out, edges
