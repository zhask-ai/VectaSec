"""Apache Pulsar rulepack — config-time posture over what connect/pulsar.py collected.

Every rule reads REAL evidence: the broker's runtime ServiceConfiguration values verbatim, the
namespace permission grants as the Admin API returned them, and the cluster service URLs. None
guesses from names. Rules run on the DISTINCT pulsar_cluster / pulsar_namespace / pulsar_topic
kinds, so they never collide with the Kafka/Kong/RabbitMQ/Redis packs.

The broker-wide rules run only on the LOCAL cluster (the one this admin endpoint belongs to), so
one real issue is reported once rather than once per geo-replication peer. When the runtime config
could not be read and no broker.conf was supplied, the auth/authz/TLS checks report a single
not-assessable coverage gap rather than reading absence as a clean pass.

House severities:
  critical  authentication disabled (anyone can connect)
  high      authorization disabled, anonymous-role namespace grant, proxy plaintext, Functions CVE
  medium    broker/cluster no TLS, broad namespace grant, shared tenant admin role
  low       topic in the built-in public/default namespace
"""
from ..connect.pulsar import _ALL_ACTIONS, _is_false, _is_true, cfg_get
from ..contracts import Hit
from ..registry import detector

# CVE-2024-27894 (CVSS 8.8, verified 2026-07-24 against the Apache Pulsar advisory): the Functions
# Worker allows unauthorized local file read, environment-variable disclosure and SSRF proxying.
# Applies only when a Functions Worker is running (functionsWorkerEnabled=true, or a dedicated
# worker). Affected 2.4.0–2.10.5, 2.11.0–2.11.3, 3.0.0–3.0.2, 3.1.0–3.1.2, 3.2.0; fixed in 2.10.6,
# 2.11.4, 3.0.3, 3.1.3, 3.2.1.
_FW_CVE_FIXED = {(2, 10): 6, (2, 11): 4, (3, 0): 3, (3, 1): 3, (3, 2): 1}


def _parse_version(v):
    try:
        parts = [int(x) for x in str(v).split("-")[0].split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except (ValueError, TypeError):
        return None


def _fw_cve_vulnerable(version):
    """True/False when determinable, None when unparseable (→ not assessable)."""
    parsed = _parse_version(version)
    if parsed is None:
        return None
    major, minor, patch = parsed
    if (major, minor) < (2, 4):
        return False
    floor = _FW_CVE_FIXED.get((major, minor))
    if floor is not None:
        return patch < floor
    if (major, minor) < (2, 10):
        return True     # every 2.4–2.9 release is affected
    return False        # 3.3+ and any series above the table ship the fix


def _broker_config(r):
    """(runtime_config, config_source) for a LOCAL cluster resource; (None, None) for a peer."""
    raw = r.raw or {}
    if not raw.get("is_local"):
        return None, None
    return raw.get("runtime_config"), raw.get("config_source")


def _config_gap(r, key: str):
    """The single not-assessable Hit when the broker config could not be read at all."""
    return [Hit(
        observation=(f"the broker runtime configuration could not be read (admin_readable="
                     f"{(r.raw or {}).get('admin_readable')}) and no broker.conf was supplied, so "
                     f"{key} could not be assessed"),
        remediation=("Grant the scanning role access to GET /admin/v2/brokers/configuration/"
                     "runtime, or supply broker.conf as JSON, so the broker security posture can "
                     "be assessed."),
        detail=f"config_source=None key={key}",
        assessable=False,
        assessment_reason="broker runtime config unreadable and no broker.conf provided",
        source_ref={"api": "/admin/v2/brokers/configuration/runtime", "config_key": key},
    )]


# ── Broker authentication / authorization ──────────────────────────────────────
@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.AUTH.AUTHENTICATION_DISABLED", severity="critical",
          title="Pulsar broker authentication is disabled")
def authentication_disabled(r, ctx) -> list:
    cfg, source = _broker_config(r)
    if cfg is None:
        return []
    if not cfg and not source:
        return _config_gap(r, "authenticationEnabled")
    if not _is_false(cfg, "authenticationEnabled"):
        return []
    return [Hit(
        observation=("broker runtime config reports authenticationEnabled=false — the broker "
                     "accepts unauthenticated clients, so any client that can reach the broker "
                     "service port can produce to and consume from every topic"),
        remediation=("Set `authenticationEnabled=true` and configure at least one "
                     "authenticationProviders entry (e.g. token, TLS, or OAuth2), then set "
                     "`authorizationEnabled=true`. Unauthenticated Pulsar is full message-bus "
                     "access to anyone who can open the socket."),
        detail="authenticationEnabled=false",
        source_ref={"api": "/admin/v2/brokers/configuration/runtime",
                    "config_key": "authenticationEnabled"},
    )]


@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.AUTH.AUTHORIZATION_DISABLED", severity="high",
          title="Pulsar broker authorization is disabled")
def authorization_disabled(r, ctx) -> list:
    cfg, source = _broker_config(r)
    if cfg is None or (not cfg and not source):
        return []   # gap already filed by AUTHENTICATION_DISABLED
    if not _is_false(cfg, "authorizationEnabled"):
        return []
    authn = _is_true(cfg, "authenticationEnabled")
    return [Hit(
        observation=(f"broker runtime config reports authorizationEnabled=false"
                     f"{' while authenticationEnabled=true' if authn else ''} — no per-topic ACLs "
                     f"are enforced, so any principal the broker accepts has unrestricted access "
                     f"to every tenant, namespace and topic regardless of granted permissions"),
        remediation=("Set `authorizationEnabled=true` and grant scoped permissions per namespace "
                     "with `pulsar-admin namespaces grant-permission`. With authorization off, "
                     "authentication only identifies clients; it does not constrain them."),
        detail="authorizationEnabled=false",
        source_ref={"api": "/admin/v2/brokers/configuration/runtime",
                    "config_key": "authorizationEnabled"},
    )]


@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.BROKER.TLS_DISABLED", severity="medium",
          title="Pulsar broker has no TLS listener")
def broker_tls_disabled(r, ctx) -> list:
    cfg, source = _broker_config(r)
    if cfg is None or (not cfg and not source):
        return []
    if not _is_false(cfg, "tlsEnabled"):
        # brokerServicePortTls being unset is the other signal, but tlsEnabled=false is dispositive.
        return []
    return [Hit(
        observation=("broker runtime config reports tlsEnabled=false — the broker offers no TLS "
                     "service port, so client connections (including any auth token or password) "
                     "and message payloads cross the network in plaintext"),
        remediation=("Enable TLS: set `tlsEnabled=true`, `brokerServicePortTls`, and "
                     "`tlsCertificateFilePath` / `tlsKeyFilePath`, and require clients to use the "
                     "pulsar+ssl:// service URL. For token auth, plaintext transport exposes the "
                     "bearer token on the wire."),
        detail="tlsEnabled=false",
        source_ref={"api": "/admin/v2/brokers/configuration/runtime", "config_key": "tlsEnabled"},
    )]


@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.PROXY.TLS_DISABLED", severity="high",
          title="Pulsar proxy connects to the broker without TLS")
def proxy_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("is_local"):
        return []
    proxy = raw.get("proxy_config")
    if not proxy:
        return []   # no proxy.conf supplied → nothing to assess (not a gap: proxies are optional)
    if not _is_false(proxy, "tlsEnabledWithBroker"):
        return []
    return [Hit(
        observation=("proxy.conf reports tlsEnabledWithBroker=false — the Pulsar proxy terminates "
                     "client connections and then talks to the broker in plaintext, so traffic on "
                     "the proxy→broker hop (the trust boundary between the DMZ proxy and the "
                     "broker tier) is unencrypted"),
        remediation=("Set `tlsEnabledWithBroker=true` in proxy.conf with the broker's CA, so the "
                     "proxy authenticates and encrypts its connection to the broker. A proxy is "
                     "specifically deployed at a trust boundary, which is exactly where the "
                     "plaintext internal hop matters."),
        detail="tlsEnabledWithBroker=false",
        source_ref={"config_key": "tlsEnabledWithBroker"},
    )]


# ── Tenants ─────────────────────────────────────────────────────────────────────
@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.TENANT.ADMIN_ROLE_SHARED", severity="medium",
          title="One admin role administers multiple tenants")
def tenant_admin_role_shared(r, ctx) -> list:
    raw = r.raw or {}
    tenants = raw.get("tenants")
    if not raw.get("is_local") or not tenants:
        return []
    role_tenants: dict[str, list] = {}
    for tenant, info in tenants.items():
        for role in info.get("admin_roles") or []:
            role_tenants.setdefault(role, []).append(tenant)
    shared = {role: ts for role, ts in role_tenants.items() if len(set(ts)) >= 2}
    if not shared:
        return []
    quoted = "; ".join(f"{role!r} administers {sorted(set(ts))}" for role, ts in sorted(shared.items()))
    return [Hit(
        observation=(f"GET /admin/v2/tenants/* shows admin role(s) shared across tenants: {quoted}"
                     f" — a single compromised role credential grants tenant-admin (create/delete "
                     f"namespaces, grant permissions) across every listed tenant, defeating "
                     f"tenant isolation"),
        remediation=("Give each tenant its own distinct adminRoles so a role's blast radius is one "
                     "tenant. Reserve any cross-tenant role for a small, named set of platform "
                     "operators and audit its use."),
        detail=f"shared_roles={sorted(shared)}",
        source_ref={"api": "/admin/v2/tenants"},
    )]


# ── Clusters ─────────────────────────────────────────────────────────────────────
@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.CLUSTER.NO_TLS_ENDPOINT", severity="medium",
          title="Pulsar cluster advertises no TLS service endpoint")
def cluster_no_tls_endpoint(r, ctx) -> list:
    raw = r.raw or {}
    has_plain = bool(raw.get("broker_service_url") or raw.get("service_url"))
    has_tls = bool(raw.get("broker_service_url_tls") or raw.get("service_url_tls"))
    if not has_plain or has_tls:
        return []
    return [Hit(
        observation=(f"cluster {raw.get('name')!r} advertises brokerServiceUrl="
                     f"{raw.get('broker_service_url')!r} / serviceUrl={raw.get('service_url')!r} "
                     f"but no TLS endpoint (brokerServiceUrlTls and serviceUrlTls are both unset), "
                     f"so clients and replication using the cluster's advertised URLs connect in "
                     f"plaintext"),
        remediation=("Set `brokerServiceUrlTls` (pulsar+ssl://) and `serviceUrlTls` (https://) on "
                     "the cluster metadata via `pulsar-admin clusters update`, and enable TLS on "
                     "the brokers, so the advertised endpoints are encrypted."),
        detail=f"broker_service_url_tls={raw.get('broker_service_url_tls')} "
               f"service_url_tls={raw.get('service_url_tls')}",
        source_ref={"api": "/admin/v2/clusters"},
    )]


# ── Versions ─────────────────────────────────────────────────────────────────────
@detector(kinds=["pulsar_cluster"], rule_id="PULSAR.VERSION.FUNCTIONS_WORKER_CVE", severity="high",
          title="Pulsar version with Functions Worker enabled is affected by CVE-2024-27894")
def functions_worker_cve(r, ctx) -> list:
    cfg, source = _broker_config(r)
    if cfg is None or (not cfg and not source):
        return []
    if not _is_true(cfg, "functionsWorkerEnabled"):
        return []   # the CVE only applies when a Functions Worker runs
    version = (r.raw or {}).get("broker_version")
    vulnerable = _fw_cve_vulnerable(version)
    if vulnerable is False:
        return []
    if vulnerable is None:
        return [Hit(
            observation=(f"broker runtime config reports functionsWorkerEnabled=true, but GET "
                         f"/admin/v2/brokers/version returned {version!r}, which this scanner "
                         f"cannot map to a CVE-2024-27894-patched release — exposure was not "
                         f"determined"),
            remediation=("Confirm the broker version against the CVE-2024-27894 advisory and run "
                         "at least 2.10.6 / 2.11.4 / 3.0.3 / 3.1.3 / 3.2.1 for its series."),
            detail=f"functionsWorkerEnabled=true version={version}",
            assessable=False,
            assessment_reason="broker version not parseable to a known CVE-2024-27894 series",
            source_ref={"api": "/admin/v2/brokers/version", "cve": "CVE-2024-27894"},
        )]
    return [Hit(
        observation=(f"broker runtime config reports functionsWorkerEnabled=true and GET "
                     f"/admin/v2/brokers/version returned {version!r}, below the CVE-2024-27894 "
                     f"(CVSS 8.8) fix for its series — the Functions Worker allows unauthorized "
                     f"local file read, environment-variable disclosure, and using the worker as "
                     f"an HTTP/HTTPS proxy (SSRF)"),
        remediation=("Upgrade to at least 2.10.6 / 2.11.4 / 3.0.3 / 3.1.3 / 3.2.1 for the broker's "
                     "series. If Functions are not used, set `functionsWorkerEnabled=false` to "
                     "remove the exposure entirely."),
        detail=f"functionsWorkerEnabled=true version={version}",
        source_ref={"api": "/admin/v2/brokers/version", "cve": "CVE-2024-27894"},
    )]


# ── Namespaces ───────────────────────────────────────────────────────────────────
@detector(kinds=["pulsar_namespace"], rule_id="PULSAR.NAMESPACE.ANONYMOUS_GRANT", severity="high",
          title="Namespace grants permissions to the anonymous user role")
def namespace_anonymous_grant(r, ctx) -> list:
    raw = r.raw or {}
    anon = raw.get("anonymous_user_role")
    if not anon:
        return []
    perms = raw.get("permissions") or {}
    if anon not in perms:
        return []
    actions = sorted(a.lower() for a in (perms.get(anon) or []))
    return [Hit(
        observation=(f"namespace {raw.get('namespace')!r} grants actions {actions!r} to role "
                     f"{anon!r}, which the broker's anonymousUserRole maps unauthenticated clients "
                     f"onto — so any client that connects without credentials receives these "
                     f"permissions on this namespace"),
        remediation=("Remove the grant to the anonymous role "
                     "(`pulsar-admin namespaces revoke-permission`), and reconsider "
                     "`anonymousUserRole` / `authenticateOriginalAuthData` on the broker unless "
                     "anonymous access to this namespace is genuinely intended."),
        detail=f"anonymous_user_role={anon} actions={actions}",
        source_ref={"api": "/admin/v2/namespaces/*/permissions", "role": anon},
    )]


@detector(kinds=["pulsar_namespace"], rule_id="PULSAR.NAMESPACE.BROAD_GRANT", severity="medium",
          title="Namespace grants the full action set to a single role")
def namespace_broad_grant(r, ctx) -> list:
    raw = r.raw or {}
    perms = raw.get("permissions") or {}
    anon = raw.get("anonymous_user_role")
    broad = []
    for role, actions in perms.items():
        if role == anon:
            continue   # ANONYMOUS_GRANT owns the anonymous-role case
        if frozenset(a.lower() for a in (actions or [])) >= _ALL_ACTIONS:
            broad.append(role)
    if not broad:
        return []
    return [Hit(
        observation=(f"namespace {raw.get('namespace')!r} grants the complete action set "
                     f"({sorted(_ALL_ACTIONS)}) to role(s) {sorted(broad)!r} — that role can "
                     f"produce, consume, and manage functions, connectors and packages across the "
                     f"whole namespace, i.e. effective control of it"),
        remediation=("Grant only the actions each role needs (usually just produce and/or "
                     "consume). Reserve functions/sources/sinks/packages for deployment "
                     "automation, and use a separate role per application."),
        detail=f"broad_roles={sorted(broad)}",
        source_ref={"api": "/admin/v2/namespaces/*/permissions"},
    )]


# ── Topics ───────────────────────────────────────────────────────────────────────
@detector(kinds=["pulsar_topic"], rule_id="PULSAR.TOPIC.PUBLIC_DEFAULT_NAMESPACE", severity="low",
          title="Topic lives in the built-in public/default namespace")
def topic_public_default(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("namespace") != "public/default":
        return []
    return [Hit(
        observation=(f"topic {raw.get('fqtn')!r} is in public/default — the namespace Pulsar "
                     f"ships out of the box, which application topics tend to inherit permissive "
                     f"defaults from and which mixes unrelated tenants' data together"),
        remediation=("Create a dedicated tenant/namespace per application "
                     "(`pulsar-admin tenants create` / `namespaces create`) with scoped "
                     "permissions and retention, and move application topics off public/default."),
        detail=f"namespace=public/default topic={raw.get('topic')}",
        source_ref={"api": "/admin/v2/persistent/public/default"},
    )]
