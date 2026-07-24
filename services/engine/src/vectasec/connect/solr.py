"""Apache Solr connector — read-only Admin REST posture collection.

One HTTP connection reads Solr's node-level security surface and writes nothing (GETs only):

  GET /solr/admin/info/system    Solr/Lucene version + run mode (drives the CVE-2024-45216 check)
  GET /solr/admin/authentication the security.json authentication section (which plugin, if any)
  GET /solr/admin/authorization  the security.json authorization section (which plugin, if any)

The system-info endpoint is also re-issued WITHOUT credentials: whether Solr answers an
unauthenticated admin request at all is the whole finding for SOLR.ADMIN.UNAUTHENTICATED and
cannot be read any other way.

Solr's authentication/authorization config is authorization metadata, not a secret — exactly the
evidence a posture finding must cite — so the plugin class names and `blockUnknown` flag are
stored in Resource.raw. No credential value is ever read (Solr's security.json never returns the
stored password hashes over these endpoints, and this connector requests none).

Kind is DISTINCT (`solr_server`) so no other rulepack runs against a Solr resource by accident.

Split for offline testing:
  collect(config)         talks to Solr, assembles a plain-dict `snapshot`
  _build_resources(...)   pure: snapshot -> Collected (golden-fixture tested)
"""
from urllib.parse import urlparse

from ..contracts import Collected, Resource
from ..registry import ConnectorField, connector


def _parse_version(v):
    """(major, minor, patch) or None when unparseable. Solr reports e.g. '9.4.0' or '8.11.2'."""
    try:
        parts = [int(x) for x in str(v).split(".")[:3]]
    except (ValueError, TypeError):
        return None
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _system_version(system: dict):
    """Solr spec version from GET /solr/admin/info/system: lucene.solr-spec-version."""
    lucene = (system or {}).get("lucene") or {}
    return lucene.get("solr-spec-version") or (system or {}).get("solr-spec-version")


def _build_resources(snapshot: dict) -> Collected:
    system = snapshot.get("system") or {}
    authn = snapshot.get("authentication") or {}
    authz = snapshot.get("authorization") or {}

    version = _system_version(system)
    authn_class = (authn.get("authentication") or {}).get("class") if isinstance(
        authn.get("authentication"), dict) else authn.get("class")
    authz_class = (authz.get("authorization") or {}).get("class") if isinstance(
        authz.get("authorization"), dict) else authz.get("class")
    authn_block = authn.get("authentication") if isinstance(authn.get("authentication"), dict) else authn
    block_unknown = (authn_block or {}).get("blockUnknown")

    resources = [Resource(
        kind="solr_server",
        name=snapshot.get("base_url") or "solr",
        ext_id="solr-server",
        labels={"version": str(version or "?"),
                "mode": str(system.get("mode") or "?")},
        raw={
            "base_url": snapshot.get("base_url"),
            "scheme": snapshot.get("scheme"),
            "version": version,
            "mode": system.get("mode"),
            "zk_host": system.get("zkHost"),
            "authentication_readable": snapshot.get("authentication_readable"),
            "authorization_readable": snapshot.get("authorization_readable"),
            "system_readable": snapshot.get("system_readable"),
            "auth_plugin_class": authn_class,
            "authz_plugin_class": authz_class,
            "block_unknown": block_unknown,
            "anon_admin_status": snapshot.get("anon_admin_status"),
            "endpoint_outcomes": snapshot.get("endpoint_outcomes") or {},
        },
    )]
    return Collected(resources=resources, edges=[])


def _get(client, path, *, auth=None):
    import httpx
    try:
        r = client.get(path, auth=auth)
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    body = None
    try:
        body = r.json()
    except ValueError:
        body = None
    return {"ok": r.status_code == 200, "status": r.status_code, "data": body}


def _outcome(env: dict) -> str:
    if env.get("ok"):
        return "ok"
    if env.get("status") in (401, 403):
        return "forbidden"
    return "error"


@connector("solr", fields=[
    ConnectorField("base_url", "Base URL", required=True, placeholder="http://localhost:8983",
                   help="Solr node base URL (without the trailing /solr). GET-only — admin info "
                        "endpoints, no collection reads."),
    ConnectorField("username", "Username", placeholder="solr",
                   help="Basic-auth user, if BasicAuthPlugin is configured. Leave empty to also "
                        "observe the unauthenticated admin surface."),
    ConnectorField("password", "Password", secret=True,
                   help="Used to open the session; never persisted into any resource."),
    ConnectorField("verify_tls", "Verify TLS", placeholder="true"),
])
def collect(config: dict) -> Collected:
    import httpx

    base = (config.get("base_url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("solr connector requires config['base_url']")
    timeout = float(config.get("timeout") or 15)
    verify = str(config.get("verify_tls", "true")).strip().lower() not in ("0", "false", "no", "off")
    user = (config.get("username") or "").strip()
    password = config.get("password") or ""
    auth = (user, password) if user else None
    scheme = urlparse(base).scheme or "http"

    with httpx.Client(base_url=base, timeout=timeout, verify=verify,
                      follow_redirects=False) as client:
        system = _get(client, "/solr/admin/info/system?wt=json", auth=auth)
        anon_system = _get(client, "/solr/admin/info/system?wt=json")
        authentication = _get(client, "/solr/admin/authentication?wt=json", auth=auth)
        authorization = _get(client, "/solr/admin/authorization?wt=json", auth=auth)

    snapshot = {
        "base_url": base,
        "scheme": scheme,
        "system": system.get("data") if system.get("ok") else {},
        "system_readable": system.get("ok"),
        "authentication": authentication.get("data") if authentication.get("ok") else {},
        "authentication_readable": authentication.get("ok"),
        "authorization": authorization.get("data") if authorization.get("ok") else {},
        "authorization_readable": authorization.get("ok"),
        "anon_admin_status": anon_system.get("status"),
        "endpoint_outcomes": {
            "system": _outcome(system),
            "authentication": _outcome(authentication),
            "authorization": _outcome(authorization),
        },
    }
    return _build_resources(snapshot)
