"""Redpanda connector — read-only Redpanda Admin API (:9644) over httpx.

Redpanda is Kafka-API-compatible but its security posture lives in its OWN control plane: the
Admin API, not the Kafka protocol. This connector reads three GETs and writes nothing:

  /v1/cluster_config   cluster-wide security switches — enable_sasl, kafka_enable_authorization,
                       admin_api_require_auth, superusers, audit_logging_enabled.
  /v1/node_config      this node's listeners and their TLS config (kafka_api / kafka_api_tls),
                       which is where transport encryption is actually decided.
  /v1/brokers          broker inventory + the running Redpanda version.

The Admin API is the exposure surface itself: if admin_api_require_auth=false the connector reads
all of the above with NO credentials, and that anonymous success is recorded as evidence
(anonymous_readable=True) — detect/redpanda.py turns it into the REDPANDA.ADMIN_API.NO_AUTH
finding. If the Admin API *does* require auth and none was supplied, the reads 401 and the config
is recorded unreadable, so detectors answer not-assessable rather than inventing a clean pass.

Emits a single DISTINCT `redpanda_cluster` resource (plus `redpanda_broker` inventory) so the
Kafka `broker` rulepack never runs against a Redpanda node by accident — a Redpanda node is not a
Kafka broker and its config keys are entirely different.
"""
from ..contracts import Collected, Resource
from ..registry import ConnectorField, connector

# The cluster-config keys the rulepack reads. An allow-list, not the whole config dump.
_SECURITY_KEYS = (
    "enable_sasl", "kafka_enable_authorization", "admin_api_require_auth",
    "superusers", "audit_enabled", "audit_log_enabled", "enable_schema_id_validation",
)


def _as_bool(v):
    """Redpanda cluster_config returns JSON booleans, but tolerate string forms too.
    None stays None so 'unset' (kafka_enable_authorization defaults to null) is distinguishable
    from an explicit false."""
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _kafka_tls_enabled(node_config: dict) -> bool | None:
    """Whether the Kafka API listener(s) have TLS. node_config carries kafka_api_tls as a list of
    per-listener TLS blocks; enabled=true on at least one means the Kafka API offers TLS. An
    absent/None kafka_api_tls block means no TLS was configured (None => not readable)."""
    rp = node_config.get("redpanda") if isinstance(node_config.get("redpanda"), dict) else node_config
    if not isinstance(rp, dict):
        return None
    tls = rp.get("kafka_api_tls")
    if tls is None:
        return None
    if isinstance(tls, dict):
        tls = [tls]
    if not isinstance(tls, list):
        return None
    if not tls:
        return False
    return any(bool((t or {}).get("enabled")) for t in tls if isinstance(t, dict))


# ── parse layer: Admin API dicts → Resources (pure, no httpx) ────────────────
def parse_cluster(base_url: str, cluster_config: dict, node_config: dict, brokers: list, *,
                  config_readable: bool, anonymous_readable: bool, version: str | None,
                  tls_url: bool) -> Resource:
    cc = cluster_config or {}
    superusers = cc.get("superusers")
    if isinstance(superusers, str):
        superusers = [s.strip() for s in superusers.split(",") if s.strip()]
    return Resource(
        kind="redpanda_cluster",
        name=base_url,
        ext_id=f"redpanda-{base_url}",
        labels={"service": "redpanda", "version": str(version or "?")},
        raw={
            "base_url": base_url,
            "version": version,
            "config_readable": config_readable,
            "anonymous_readable": anonymous_readable,
            "admin_api_over_tls": tls_url,
            "enable_sasl": _as_bool(cc.get("enable_sasl")),
            "kafka_enable_authorization": _as_bool(cc.get("kafka_enable_authorization")),
            "admin_api_require_auth": _as_bool(cc.get("admin_api_require_auth")),
            "audit_enabled": _as_bool(cc.get("audit_enabled") if cc.get("audit_enabled") is not None
                                      else cc.get("audit_log_enabled")),
            "superusers": superusers or [],
            "kafka_api_tls_enabled": _kafka_tls_enabled(node_config or {}),
            "broker_count": len(brokers or []),
        },
    )


def parse_broker(base_url: str, broker: dict) -> Resource:
    bid = broker.get("node_id", broker.get("broker_id"))
    return Resource(
        kind="redpanda_broker",
        name=f"broker-{bid}",
        ext_id=f"redpanda-broker-{base_url}-{bid}",
        labels={"service": "redpanda"},
        raw={"node_id": bid, "membership_status": broker.get("membership_status"),
             "is_alive": broker.get("is_alive"), "base_url": base_url},
    )


# ── collection: httpx in, anonymous-probe aware ──────────────────────────────
@connector("redpanda", fields=[
    ConnectorField("url", "Admin API URL", required=True, placeholder="http://redpanda:9644",
                   help="Redpanda Admin API base URL (default port 9644). Read-only — only GETs "
                        "against /v1/cluster_config, /v1/node_config and /v1/brokers."),
    ConnectorField("username", "Admin username", placeholder="admin",
                   help="Only if admin_api_require_auth is true. Basic-auth superuser."),
    ConnectorField("password", "Admin password", secret=True,
                   help="Used to open the session, never persisted into any resource."),
    ConnectorField("verify", "Verify TLS", placeholder="true",
                   help="'false' to skip TLS verification for a self-signed Admin API cert."),
])
def collect(config: dict) -> Collected:
    import httpx

    base = (config.get("url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("redpanda connector requires config['url']")
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

    cluster_config: dict = {}
    node_config: dict = {}
    brokers: list = []
    version = None
    config_readable = True
    try:
        cluster_config = _get("/v1/cluster_config") or {}
    except Exception:
        config_readable = False
    try:
        node_config = _get("/v1/node_config") or {}
    except Exception:
        node_config = {}
    try:
        brokers = _get("/v1/brokers") or []
        if brokers:
            version = brokers[0].get("version") or brokers[0].get("internal_rpc_version")
    except Exception:
        brokers = []

    # Anonymous reachability: if we sent NO credentials and still read the config, the Admin API
    # is unauthenticated. If we did send credentials, re-probe with a credential-free client so
    # the finding reflects genuine anonymous access, not our own token.
    anonymous_readable = False
    if config_readable:
        if auth is None:
            anonymous_readable = True
        else:
            try:
                anon = httpx.Client(base_url=base, timeout=timeout, verify=verify)
                ar = anon.get("/v1/cluster_config")
                anonymous_readable = ar.status_code == 200
                anon.close()
            except Exception:
                anonymous_readable = False

    client.close()

    resources: list[Resource] = [parse_cluster(
        base, cluster_config, node_config, brokers,
        config_readable=config_readable, anonymous_readable=anonymous_readable,
        version=version, tls_url=tls_url)]
    resources.extend(parse_broker(base, b) for b in (brokers or []) if isinstance(b, dict))
    return Collected(resources=resources, edges=[])
