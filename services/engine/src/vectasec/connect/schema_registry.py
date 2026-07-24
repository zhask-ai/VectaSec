"""Schema Registry connector — read-only Schema Registry REST over httpx.

The Confluent/Apicurio-compatible Schema Registry REST API is frequently deployed with no
authentication and on plaintext HTTP, which turns the schema store — the contract layer every
producer and consumer trusts — into an anonymously readable and often anonymously writable
surface. This connector issues GETs only:

  /config     the GLOBAL compatibility level (BACKWARD, FULL, NONE, …). NONE disables schema
              evolution safety entirely.
  /mode       the registry mode (READWRITE / READONLY / IMPORT).
  /subjects   the registered subjects (inventory; also the anonymous-read probe target).

Auth is optional in the connector because "no auth is required" is exactly what we are testing:
if credentials are omitted and /subjects returns 200, that anonymous success is recorded as
evidence. Writability is NOT probed — this connector never issues a POST/PUT/DELETE — so whether
an anonymous client can also *register* a schema is reported as not-assessable rather than
asserted.

Emits one DISTINCT `schema_registry` resource so no other rulepack runs against it by accident.
"""
from ..contracts import Collected, Resource
from ..registry import ConnectorField, connector

# Compatibility levels that provide schema-evolution safety. NONE (and the absence of any level)
# means any incompatible schema change is accepted.
_SAFE_COMPAT = {"BACKWARD", "BACKWARD_TRANSITIVE", "FORWARD", "FORWARD_TRANSITIVE",
                "FULL", "FULL_TRANSITIVE"}


# ── parse layer: REST dicts → Resources (pure, no httpx) ─────────────────────
def parse_registry(base_url: str, *, config_resp, mode_resp, subjects, tls_url: bool,
                   anonymous_readable: bool, config_readable: bool) -> Resource:
    compat = None
    if isinstance(config_resp, dict):
        compat = config_resp.get("compatibilityLevel") or config_resp.get("compatibility")
    mode = None
    if isinstance(mode_resp, dict):
        mode = mode_resp.get("mode")
    return Resource(
        kind="schema_registry",
        name=base_url,
        ext_id=f"schema-registry-{base_url}",
        labels={"service": "schema_registry", "compatibility": str(compat or "?")},
        raw={
            "base_url": base_url,
            "over_tls": tls_url,
            "config_readable": config_readable,
            "anonymous_readable": anonymous_readable,
            "compatibility_level": (str(compat).upper() if compat else None),
            "mode": (str(mode).upper() if mode else None),
            "subject_count": len(subjects or []) if subjects is not None else None,
            "subjects_readable": subjects is not None,
        },
    )


# ── collection: httpx in, anonymous-probe aware ──────────────────────────────
@connector("schema_registry", fields=[
    ConnectorField("url", "Registry URL", required=True, placeholder="http://schema-registry:8081",
                   help="Schema Registry REST base URL (default port 8081). Read-only — only GETs "
                        "against /config, /mode and /subjects; no schema is ever written."),
    ConnectorField("username", "Username", placeholder="",
                   help="Only if the registry requires Basic auth. Leave empty to test whether "
                        "the registry is anonymously readable."),
    ConnectorField("password", "Password", secret=True,
                   help="Used to open the session, never persisted into any resource."),
    ConnectorField("verify", "Verify TLS", placeholder="true",
                   help="'false' to skip TLS verification for a self-signed registry cert."),
])
def collect(config: dict) -> Collected:
    import httpx

    base = (config.get("url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("schema_registry connector requires config['url']")
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

    config_resp = None
    mode_resp = None
    subjects = None
    config_readable = True
    try:
        config_resp = _get("/config")
    except Exception:
        config_readable = False
    try:
        mode_resp = _get("/mode")
    except Exception:
        mode_resp = None
    try:
        subjects = _get("/subjects")
    except Exception:
        subjects = None

    # Anonymous reachability, mirrored from the Redpanda/Kong pattern: prove genuine
    # unauthenticated read rather than reflecting our own credential.
    anonymous_readable = False
    if subjects is not None:
        if auth is None:
            anonymous_readable = True
        else:
            try:
                anon = httpx.Client(base_url=base, timeout=timeout, verify=verify)
                ar = anon.get("/subjects")
                anonymous_readable = ar.status_code == 200
                anon.close()
            except Exception:
                anonymous_readable = False

    client.close()

    return Collected(resources=[parse_registry(
        base, config_resp=config_resp, mode_resp=mode_resp, subjects=subjects,
        tls_url=tls_url, anonymous_readable=anonymous_readable,
        config_readable=config_readable)], edges=[])
