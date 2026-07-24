"""Flink connector — read-only Apache Flink REST API (:8081) over httpx.

Apache Flink ships with NO authentication on its REST API / web dashboard, and the dashboard
accepts JAR uploads and job submission by default (web.submit.enable=true). An exposed,
unauthenticated Flink REST endpoint is therefore a documented remote-code-execution surface:
submit a job that runs arbitrary code in the cluster. Two path-traversal CVEs also live on this
REST surface — CVE-2020-17518 (arbitrary file WRITE via the upload handler) and CVE-2020-17519
(arbitrary file READ), both unauthenticated and both affecting 1.11.0–1.11.2 (fixed in 1.11.3).

This connector issues GETs only:

  /overview          cluster overview + Flink version, task managers, slots, running jobs
  /jobmanager/config the JobManager configuration (key/value list) — web.submit.enable,
                     security.ssl.rest.enabled, rest.address, …
  /jobs              job inventory (posture context)

`security.ssl.rest.enabled` and `web.submit.enable` are read straight from /jobmanager/config.
If credentials are omitted (Flink has none by default) and /overview returns 200, that anonymous
success is recorded as evidence for the unauthenticated-exposure finding.

Emits one DISTINCT `flink_cluster` resource.
"""
from ..contracts import Collected, Resource
from ..registry import ConnectorField, connector


def _jm_value(jm_config, key: str):
    """/jobmanager/config returns a list of {"key": ..., "value": ...}. Return the value for
    `key`, or None. A dict form is tolerated too."""
    if isinstance(jm_config, dict):
        return jm_config.get(key)
    if isinstance(jm_config, list):
        for item in jm_config:
            if isinstance(item, dict) and item.get("key") == key:
                return item.get("value")
    return None


def _as_bool(v, default=None):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


# ── parse layer: REST dicts → Resources (pure, no httpx) ─────────────────────
def parse_cluster(base_url: str, overview, jm_config, *, tls_url: bool,
                  anonymous_readable: bool, config_readable: bool) -> Resource:
    ov = overview if isinstance(overview, dict) else {}
    version = ov.get("flink-version") or ov.get("version")
    # web.submit.enable defaults to TRUE in Flink; a readable config that omits it means default.
    submit_raw = _jm_value(jm_config, "web.submit.enable")
    ssl_rest_raw = _jm_value(jm_config, "security.ssl.rest.enabled")
    return Resource(
        kind="flink_cluster",
        name=base_url,
        ext_id=f"flink-{base_url}",
        labels={"service": "flink", "version": str(version or "?")},
        raw={
            "base_url": base_url,
            "version": version,
            "over_tls": tls_url,
            "anonymous_readable": anonymous_readable,
            "config_readable": config_readable,
            # None when the config was unreadable; the documented default (True) when readable-but-absent.
            "web_submit_enabled": (None if not config_readable else _as_bool(submit_raw, default=True)),
            "ssl_rest_enabled": (None if not config_readable else _as_bool(ssl_rest_raw, default=False)),
            "taskmanagers": ov.get("taskmanagers"),
            "slots_total": ov.get("slots-total"),
            "jobs_running": ov.get("jobs-running"),
        },
    )


# ── collection: httpx in, anonymous-probe aware ──────────────────────────────
@connector("flink", fields=[
    ConnectorField("url", "Flink REST URL", required=True, placeholder="http://flink-jobmanager:8081",
                   help="Apache Flink REST/dashboard base URL (default port 8081). Read-only — "
                        "only GETs against /overview, /jobmanager/config and /jobs; no job is "
                        "ever submitted."),
    ConnectorField("username", "Username", placeholder="",
                   help="Only if a reverse proxy fronts Flink with Basic auth. Flink itself has "
                        "no built-in auth; leave empty to test anonymous reachability."),
    ConnectorField("password", "Password", secret=True,
                   help="Used to open the session, never persisted into any resource."),
    ConnectorField("verify", "Verify TLS", placeholder="true",
                   help="'false' to skip TLS verification for a self-signed REST cert."),
])
def collect(config: dict) -> Collected:
    import httpx

    base = (config.get("url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("flink connector requires config['url']")
    username = (config.get("username") or "").strip()
    password = config.get("password") or ""
    timeout = float(config.get("timeout") or 15)
    verify = str(config.get("verify", "true")).strip().lower() not in ("0", "false", "no", "off")
    tls_url = base.lower().startswith("https://")

    auth = (username, password) if username else None
    client = httpx.Client(base_url=base, timeout=timeout, verify=verify, auth=auth)

    def _get(path: str):
        r = client.get(path)
        r.raise_for_status()
        return r.json()

    overview = None
    jm_config = None
    config_readable = True
    try:
        overview = _get("/overview")
    except Exception:
        overview = None
    try:
        jm_config = _get("/jobmanager/config")
    except Exception:
        config_readable = False

    anonymous_readable = False
    if overview is not None:
        if auth is None:
            anonymous_readable = True
        else:
            try:
                anon = httpx.Client(base_url=base, timeout=timeout, verify=verify)
                ar = anon.get("/overview")
                anonymous_readable = ar.status_code == 200
                anon.close()
            except Exception:
                anonymous_readable = False

    client.close()
    return Collected(resources=[parse_cluster(
        base, overview, jm_config, tls_url=tls_url, anonymous_readable=anonymous_readable,
        config_readable=config_readable)], edges=[])
