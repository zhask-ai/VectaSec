"""Airflow connector — read-only reads of the Airflow 2.x stable REST API (/api/v1/).

Airflow is the orchestration layer that reaches into every connected system via its Connections,
so its posture (who can reach the API, whether the config is exposed, whether DAGs or Connections
carry secrets) is squarely integration-layer security. This connector reads version, config, DAGs,
and Connections with GET-only calls and writes nothing. It also runs one UNAUTHENTICATED GET to
measure anonymous reach — Airflow's historic hole is a webserver left open with no auth.

Secret discipline: the Connections endpoint already masks password/extra values, and this connector
records only KEY PRESENCE for anything credential-shaped — never a value. DAG params are scanned by
KEY NAME only. Nothing secret crosses into a Resource.

The parse layer (parse_version, parse_config, parse_connection, parse_dag_details, parse_users) is
pure: API response dicts in, normalized facts out. Tests feed golden JSON to it, so httpx and a live
Airflow stay out of the test suite.

Emits DISTINCT kinds airflow_instance / airflow_dag / airflow_connection. Airflow users, roles, and
connections normalize into the NHI model via the in-file @identity_extractor("airflow").

config: base_url (required), username + password (basic) or token (bearer); timeout.
"""
import re

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected
from ..identity import _mk_grant, _mk_identity, _mk_credential, identity_extractor

_MAX_DAGS_DETAILED = 25          # cap per-DAG detail fetches so a huge deployment stays one scan
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")

# Key names that indicate a secret is being stored. Matched against KEY NAMES only; values are
# never read. Deliberately narrow to avoid flagging benign keys like "public_key" or "key_id".
_SECRET_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:password|passwd|secret|token|api[_\-]?key|access[_\-]?key|"
    r"private[_\-]?key|client[_\-]?secret|credential|auth)(?:$|[_\-.])",
    re.I,
)


def _looks_secret(key: str) -> bool:
    k = str(key or "")
    if not k:
        return False
    return bool(_SECRET_KEY_RE.search(k) or _SECRET_KEY_RE.search(f"_{k}_"))


# ── pure parse layer (tests feed golden JSON here) ─────────────────────────
def parse_version(doc) -> dict:
    if not isinstance(doc, dict):
        return {"version": None, "git_version": None}
    return {"version": doc.get("version"), "git_version": doc.get("git_version")}


def parse_config(status, doc) -> dict:
    """Airflow returns 200 with sections when expose_config is on; 403 when it is False (the good
    case). `test_connection` is read from the core section when present."""
    out = {"readable": None, "expose_config_on": None, "status": status,
           "test_connection": None, "sections_present": None}
    if status == 403:
        out["readable"] = False
        out["expose_config_on"] = False
        return out
    if status != 200 or not isinstance(doc, dict):
        out["readable"] = None            # unknown (auth failure, network) → coverage gap
        return out
    out["readable"] = True
    out["expose_config_on"] = True
    sections = doc.get("sections") if isinstance(doc.get("sections"), list) else []
    out["sections_present"] = len(sections)
    for sec in sections:
        if not isinstance(sec, dict):
            continue
        for opt in sec.get("options") or []:
            if isinstance(opt, dict) and str(opt.get("key", "")).lower() == "test_connection":
                out["test_connection"] = opt.get("value")
    return out


def parse_connection(doc) -> dict:
    """Normalize one connection object. Records credential KEY presence, never values."""
    if not isinstance(doc, dict):
        return {}
    extra = doc.get("extra")
    extra_keys = []
    if isinstance(extra, dict):
        extra_keys = list(extra.keys())
    elif isinstance(extra, str) and extra.strip():
        # extra is often a JSON string; pull key names without trusting the values
        import json
        try:
            parsed = json.loads(extra)
            if isinstance(parsed, dict):
                extra_keys = list(parsed.keys())
        except ValueError:
            extra_keys = []
    secret_extra_keys = [k for k in extra_keys if _looks_secret(k)]
    return {
        "connection_id": doc.get("connection_id"),
        "conn_type": doc.get("conn_type"),
        "host": doc.get("host"),
        "login": doc.get("login"),
        "schema": doc.get("schema"),
        "port": doc.get("port"),
        # The API masks the value; presence is inferred from the key being present and non-empty.
        "has_password": bool(doc.get("password")),
        "password_key_present": "password" in doc,
        "extra_keys": extra_keys,
        "secret_extra_keys": secret_extra_keys,
    }


def parse_dag_details(doc) -> dict:
    """Normalize DAG details. Scans param KEY names for secret-shaped keys — never values."""
    if not isinstance(doc, dict):
        return {}
    params = doc.get("params") if isinstance(doc.get("params"), dict) else {}
    param_keys = list(params.keys())
    secret_param_keys = [k for k in param_keys if _looks_secret(k)]
    return {
        "dag_id": doc.get("dag_id"),
        "is_paused": doc.get("is_paused"),
        "tags": [t.get("name") for t in (doc.get("tags") or []) if isinstance(t, dict)],
        "owners": doc.get("owners"),
        "param_keys": param_keys,
        "secret_param_keys": secret_param_keys,
    }


def parse_users(doc) -> list:
    if not isinstance(doc, dict):
        return []
    out = []
    for u in doc.get("users") or []:
        if not isinstance(u, dict):
            continue
        roles = [rr.get("name") for rr in (u.get("roles") or []) if isinstance(rr, dict)]
        out.append({"username": u.get("username"), "active": u.get("active"),
                    "roles": roles, "email": u.get("email")})
    return out


# ── network ────────────────────────────────────────────────────────────────
def _get(client, url, *, auth=None, headers=None):
    try:
        r = client.get(url, auth=auth, headers=headers or {})
    except Exception as e:
        return None, None, f"{type(e).__name__}: {e}"
    try:
        return r.status_code, (r.json() if r.status_code == 200 else None), None
    except ValueError:
        return r.status_code, None, "non-json response"


# ── collect ────────────────────────────────────────────────────────────────
@connector("airflow", fields=[
    ConnectorField("base_url", "Airflow base URL", required=True,
                   placeholder="https://airflow.example.com",
                   help="Base URL of the Airflow webserver. The stable REST API at /api/v1/ is "
                        "read with GET-only calls."),
    ConnectorField("username", "Username", help="For basic auth (with password)."),
    ConnectorField("password", "Password", secret=True, help="For basic auth (with username)."),
    ConnectorField("token", "Bearer token", secret=True,
                   help="For token auth instead of username/password."),
])
def collect(config: dict) -> Collected:
    base = (config.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("airflow connector requires config['base_url']")
    api = f"{base}/api/v1"
    timeout = float(config.get("timeout") or 10.0)

    token = config.get("token") or None
    username = config.get("username") or None
    password = config.get("password") or None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    auth = httpx.BasicAuth(username, password) if (username and password) else None

    from urllib.parse import urlsplit
    s = urlsplit(base)
    host = s.hostname or ""

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        v_status, v_doc, v_err = _get(client, f"{api}/version", auth=auth, headers=headers)
        c_status, c_doc, c_err = _get(client, f"{api}/config", auth=auth, headers=headers)
        # Unauthenticated reach: the same endpoint with NO auth. 200 == anonymous access.
        u_status, _u_doc, u_err = _get(client, f"{api}/dags?limit=1")

        conns_status, conns_doc, conns_err = _get(
            client, f"{api}/connections?limit=100", auth=auth, headers=headers)
        users_status, users_doc, users_err = _get(
            client, f"{api}/users?limit=100", auth=auth, headers=headers)
        dags_status, dags_doc, dags_err = _get(
            client, f"{api}/dags?limit=100", auth=auth, headers=headers)

        dag_ids = [d.get("dag_id") for d in ((dags_doc or {}).get("dags") or [])
                   if isinstance(d, dict) and d.get("dag_id")]
        dag_details = []
        for dag_id in dag_ids[:_MAX_DAGS_DETAILED]:
            st, doc, _e = _get(client, f"{api}/dags/{dag_id}/details", auth=auth, headers=headers)
            if st == 200 and doc:
                dag_details.append(parse_dag_details(doc))

    version = parse_version(v_doc)
    cfg = parse_config(c_status, c_doc)
    users = parse_users(users_doc) if users_status == 200 else []
    connections = [parse_connection(c) for c in ((conns_doc or {}).get("connections") or [])
                   if isinstance(c, dict)]

    instance_ext = f"airflow-{base}"
    instance_raw = {
        "base_url": base, "api_base": api, "host": host, "scheme": s.scheme,
        "version": version.get("version"), "git_version": version.get("git_version"),
        "version_status": v_status, "version_error": v_err,
        "config": cfg,
        "unauth_probe": {"status": u_status, "error": u_err,
                         "anonymous_access": u_status == 200},
        "users_readable": users_status == 200,
        "users_status": users_status,
        "users": users,
        "connection_count": len(connections),
        "dag_count": len(dag_ids),
        "authenticated_scan": bool(token or auth),
    }
    resources = [Resource(
        kind="airflow_instance", name=host or base, ext_id=instance_ext, namespace=host,
        labels={"scheme": s.scheme, "version": version.get("version") or "?",
                "anonymous_access": "true" if u_status == 200 else "false",
                "expose_config": "on" if cfg.get("expose_config_on") else "off"},
        raw=instance_raw,
    )]
    edges = []

    for d in dag_details:
        dag_ext = f"airflow-dag-{base}-{d.get('dag_id')}"
        resources.append(Resource(
            kind="airflow_dag", name=str(d.get("dag_id")), ext_id=dag_ext, namespace=host,
            labels={"has_secret_param": "true" if d.get("secret_param_keys") else "false",
                    "is_paused": str(d.get("is_paused"))},
            raw={**d, "instance_ext_id": instance_ext},
        ))
        edges.append(Edge(instance_ext, dag_ext, "contains"))

    for c in connections:
        conn_ext = f"airflow-conn-{base}-{c.get('connection_id')}"
        resources.append(Resource(
            kind="airflow_connection", name=str(c.get("connection_id")), ext_id=conn_ext,
            namespace=host,
            labels={"conn_type": str(c.get("conn_type")),
                    "stores_secret": "true" if (c.get("has_password") or c.get("secret_extra_keys")) else "false"},
            raw={**c, "instance_ext_id": instance_ext},
        ))
        edges.append(Edge(instance_ext, conn_ext, "contains"))

    return Collected(resources=resources, edges=edges)


# ── NHI: Airflow users/roles + connections → identity / credential / grant ──
@identity_extractor("airflow")
def _from_airflow(resources: list) -> tuple:
    """Airflow users (with roles) and Connections normalize into the NHI model:
      - each user → an identity (admin if it holds the Admin role) + a password credential (present
        only; Airflow hashes it, we never read the value) + one grant per role.
      - each connection → a service-account identity for the external system it reaches, a stored
        credential (present only) when it carries a password/secret, and a grant naming the target.
    """
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "airflow_instance":
            continue
        for u in (r.raw or {}).get("users") or []:
            name = u.get("username")
            if not name:
                continue
            roles = u.get("roles") or []
            itype = "admin" if "Admin" in roles else "service_account"
            idr = _mk_identity("airflow", itype, name, tags=roles, source_ext=r.ext_id,
                               extra={"active": u.get("active")})
            out.append(idr)
            # Airflow stores a hashed password per user; presence only, value never read.
            cred = _mk_credential("airflow", idr.ext_id, "password", name=f"{name}:password",
                                  hashing="unknown", present=True, plaintext=False)
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
            for role in roles:
                g = _mk_grant("airflow", idr.ext_id, "role", str(role),
                              wildcard=(role == "Admin"))
                out.append(g)
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))

    for r in resources:
        if r.kind != "airflow_connection":
            continue
        raw = r.raw or {}
        conn_id = raw.get("connection_id")
        if not conn_id:
            continue
        idr = _mk_identity("airflow", "service_account", f"connection:{conn_id}", external=True,
                           source_ext=r.ext_id,
                           extra={"conn_type": raw.get("conn_type"), "host": raw.get("host")})
        out.append(idr)
        if raw.get("has_password") or raw.get("secret_extra_keys"):
            cred = _mk_credential("airflow", idr.ext_id, "connection_secret",
                                  name=f"{conn_id}:secret", hashing="n/a", present=True,
                                  plaintext=False,
                                  extra={"secret_extra_keys": raw.get("secret_extra_keys")})
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
        target = f"{raw.get('conn_type')}:{raw.get('host') or '?'}"
        g = _mk_grant("airflow", idr.ext_id, "connect", target,
                      extra={"login": raw.get("login")})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
    return out, edges
