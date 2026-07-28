"""Kafka Connect connector — read-only Connect REST API (:8083) over httpx.

The Kafka Connect REST API is the canonical integration-layer footgun: it defaults to NO
authentication, and anyone who can reach it can POST a connector config. Since Kafka 2.3.0 a
connector config may carry an arbitrary client `sasl.jaas.config`, and until 3.4.0 that could
name `com.sun.security.auth.module.JndiLoginModule` to make the worker connect to an attacker
LDAP server and deserialize a gadget chain — remote code execution on the Connect worker
(CVE-2023-25194). So an exposed unauthenticated REST endpoint is effectively unauthenticated RCE.

This connector issues GETs only:

  /                     worker version + kafka cluster id
  /connectors           connector names (also the anonymous-read probe target)
  /connectors/{name}    each connector's config

Secret discipline is strict: connector configs routinely carry `connection.password`,
`consumer.override.sasl.jaas.config`, AWS keys, etc. in cleartext. Values are NEVER stored. The
parse layer records, per secret-bearing key, only (a) that the key is PRESENT and (b) whether its
value is an externalized `${provider:...}` reference (safe) or an inline literal (the finding) —
a boolean, never the secret itself.

Emits DISTINCT kinds `kafka_connect_cluster` / `kafka_connect_connector`.
"""
import re

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

# Config keys whose VALUE is a secret. Matched on the key name; the value is inspected only to
# classify externalized-vs-inline and is never stored.
_SECRET_KEY = re.compile(r"(password|passwd|secret|\.key$|^key$|token|credential|jaas\.config)", re.I)

# The per-connector client-override JAAS keys that are the CVE-2023-25194 attack surface. Their
# PRESENCE (not value) is what the rule reads.
_JAAS_OVERRIDE_KEYS = (
    "producer.override.sasl.jaas.config", "consumer.override.sasl.jaas.config",
    "admin.override.sasl.jaas.config", "sasl.jaas.config",
)


def _is_externalized(value) -> bool:
    """True when a config value is a ConfigProvider reference (${file:...}, ${vault:...},
    ${env:...}) rather than an inline literal secret. A leading ${ is Kafka's externalized-config
    syntax."""
    return isinstance(value, str) and value.strip().startswith("${")


# ── parse layer: REST dicts → Resources (pure, no httpx) ─────────────────────
def parse_cluster(base_url: str, root_info, *, tls_url: bool, anonymous_readable: bool,
                  connectors_readable: bool, plugins_readable: bool | None = None) -> Resource:
    info = root_info if isinstance(root_info, dict) else {}
    return Resource(
        kind="kafka_connect_cluster",
        name=base_url,
        ext_id=f"kafka-connect-{base_url}",
        labels={"service": "kafka_connect", "version": str(info.get("version") or "?")},
        raw={
            "base_url": base_url,
            "version": info.get("version"),
            "kafka_cluster_id": info.get("kafka_cluster_id"),
            "over_tls": tls_url,
            "anonymous_readable": anonymous_readable,
            "connectors_readable": connectors_readable,
            # None = this row predates plugin collection (unknown, not a refusal). The
            # NOT_READABLE rule fires only on an explicit False.
            "plugins_readable": plugins_readable,
        },
    )


def parse_plugins(base_url: str, plugins_raw) -> list[Resource]:
    """/connector-plugins → one resource per INSTALLED plugin (class, type, version).

    This is the inventory a build SBOM literally cannot produce: `plugin.path` is scanned at
    worker startup, so what is installed is a runtime fact of the worker, not of any build.
    The version is what the plugin ITSELF reports — bundled plugins report the worker version,
    Debezium and JDBC connectors report their own. A plugin that reports none (older workers
    omit the field; some serialize the literal string "null") carries NO version rather than
    inheriting the worker's: sbom.component_for refuses versionless components, and an
    inherited version would drive CVE matching against a number nobody stated.
    """
    out: list[Resource] = []
    for p in plugins_raw if isinstance(plugins_raw, list) else []:
        if not isinstance(p, dict):
            continue
        cls = str(p.get("class") or "").strip()
        if not cls:
            continue
        version = p.get("version")
        version = None if version in (None, "", "null") else str(version)
        labels = {
            "service": "kafka_connect",
            # `product` is what sbom.component_for names the component after; the full class
            # is the only identity the REST API states, so that is what we claim — a prettied
            # short name would collide across plugins that share a suffix.
            "product": cls.lower(),
            "plugin_type": str(p.get("type") or "?"),
        }
        raw: dict = {
            "plugin_class": cls,
            "plugin_type": p.get("type"),
            "base_url": base_url,
            "cluster_ext": f"kafka-connect-{base_url}",
        }
        if version:
            labels["version"] = version
            raw["version"] = version
        out.append(Resource(
            kind="kafka_connect_plugin",
            name=cls.rsplit(".", 1)[-1],
            ext_id=f"kafka-connect-{base_url}-plugin-{cls}",
            labels=labels,
            raw=raw,
        ))
    return out


def parse_connector(base_url: str, name: str, cfg) -> Resource:
    """One /connectors/{name} config → a resource that records secret-key METADATA only.
    `secret_keys` maps each secret-bearing config key to whether its value is externalized
    (True) or an inline literal (False). No value is ever stored."""
    config = cfg if isinstance(cfg, dict) else {}
    connector_class = config.get("connector.class")
    secret_keys: dict[str, bool] = {}
    inline_secret_keys: list[str] = []
    for k, v in config.items():
        if _SECRET_KEY.search(k):
            ext = _is_externalized(v)
            secret_keys[k] = ext
            if not ext and v not in (None, ""):
                inline_secret_keys.append(k)
    jaas_override_keys = [k for k in _JAAS_OVERRIDE_KEYS if k in config]
    return Resource(
        kind="kafka_connect_connector",
        name=str(name),
        ext_id=f"kafka-connect-{base_url}-connector-{name}",
        labels={"service": "kafka_connect", "connector_class": str(connector_class or "?")},
        raw={
            "base_url": base_url,
            "connector_name": str(name),
            "connector_class": connector_class,
            "tasks_max": config.get("tasks.max"),
            "config_readable": cfg is not None,
            "secret_keys": secret_keys,                 # key -> externalized? (never the value)
            "inline_secret_keys": sorted(inline_secret_keys),
            "jaas_override_keys": jaas_override_keys,
            "cluster_ext": f"kafka-connect-{base_url}",
        },
    )


# ── collection: httpx in, anonymous-probe aware ──────────────────────────────
@connector("kafka_connect", fields=[
    ConnectorField("url", "Connect REST URL", required=True, placeholder="http://connect:8083",
                   help="Kafka Connect REST base URL (default port 8083). Read-only — only GETs "
                        "against /, /connectors, /connectors/{name} and /connector-plugins; no "
                        "connector is created or modified."),
    ConnectorField("username", "Username", placeholder="",
                   help="Only if the REST API is behind Basic auth. Leave empty to test whether "
                        "the endpoint is anonymously reachable."),
    ConnectorField("password", "Password", secret=True,
                   help="Used to open the session, never persisted into any resource."),
    ConnectorField("verify", "Verify TLS", placeholder="true",
                   help="'false' to skip TLS verification for a self-signed REST cert."),
])
def collect(config: dict) -> Collected:
    import httpx

    base = (config.get("url") or "").strip().rstrip("/")
    if not base:
        raise SystemExit("kafka_connect connector requires config['url']")
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

    root_info = None
    names = None
    connectors_readable = True
    try:
        root_info = _get("/")
    except Exception:
        root_info = None
    try:
        names = _get("/connectors")
    except Exception:
        connectors_readable = False

    anonymous_readable = False
    if connectors_readable and names is not None:
        if auth is None:
            anonymous_readable = True
        else:
            try:
                anon = httpx.Client(base_url=base, timeout=timeout, verify=verify)
                ar = anon.get("/connectors")
                anonymous_readable = ar.status_code == 200
                anon.close()
            except Exception:
                anonymous_readable = False

    # Installed-plugin inventory. `connectorsOnly=false` (worker >= 3.2) includes transforms
    # and converters; older workers ignore the unknown parameter and return connector plugins
    # only — still a correct, if narrower, inventory. A failure is recorded as a refusal so
    # the rulepack can file the coverage gap instead of the inventory reading as empty.
    plugins_raw = None
    plugins_readable = True
    try:
        plugins_raw = _get("/connector-plugins?connectorsOnly=false")
    except Exception:
        plugins_readable = False

    resources: list[Resource] = [parse_cluster(
        base, root_info, tls_url=tls_url, anonymous_readable=anonymous_readable,
        connectors_readable=connectors_readable, plugins_readable=plugins_readable)]
    resources.extend(parse_plugins(base, plugins_raw))

    for name in (names or []):
        try:
            cfg = (_get(f"/connectors/{name}") or {}).get("config")
        except Exception:
            cfg = None
        resources.append(parse_connector(base, name, cfg))

    client.close()
    return Collected(resources=resources, edges=[])


# ── NHI: connector-stored credentials → credential metadata ──────────────────
@identity_extractor("kafka_connect")
def _from_kafka_connect(resources: list) -> tuple:
    """Each connector that stores a secret becomes an identity (the connector is a workload
    principal); each secret-bearing config key becomes a credential recording presence and
    whether it is externalized — never the value."""
    out: list[Resource] = []
    edges: list[Edge] = []

    for r in resources:
        if r.kind != "kafka_connect_connector":
            continue
        raw = r.raw or {}
        secret_keys = raw.get("secret_keys") or {}
        if not secret_keys:
            continue
        name = raw.get("connector_name") or r.name
        idr = _mk_identity("kafka_connect", "connector", name, source_ext=r.ext_id,
                           extra={"connector_class": raw.get("connector_class")})
        out.append(idr)
        for key, externalized in secret_keys.items():
            cred = _mk_credential(
                "kafka_connect", idr.ext_id, "connector_secret", name=f"{name}:{key}",
                hashing="n/a", present=True, plaintext=(externalized is False),
                extra={"config_key": key, "externalized": bool(externalized)})
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id, kind="credential_of"))
    return out, edges
