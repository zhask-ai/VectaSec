"""Elasticsearch / OpenSearch rulepack — config-time posture over what connect/elasticsearch.py
collected.

Every rule reads REAL evidence the connector recorded (a node setting like
`xpack.security.enabled`, the status code of an unauthenticated probe, a snapshot repo's URL)
and cites it; none guesses from names. Rules run on the DISTINCT es_cluster/es_index kinds, so
they never collide with the Kafka/Kong/RabbitMQ/Redis packs. The users/roles the connector
collected become identity/credential/grant via the NHI extractor and are assessed by the generic
detect/identity.py pack — not restated here.

The third honest outcome is used throughout: when the setting a rule needs was not readable
(node settings denied, or no authoritative security signal), the rule returns assessable=False —
a coverage gap, never a clean pass.
"""
from ..contracts import Hit
from ..registry import detector

_SETTINGS_GAP = ("its node settings could not be read (GET /_nodes/settings and "
                 "GET /_cluster/settings were both unreadable), so ")


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.SECURITY.DISABLED", severity="critical",
          title="Elasticsearch/OpenSearch security is disabled")
def security_disabled(r, ctx) -> list:
    raw = r.raw or {}
    disabled = raw.get("security_disabled")
    dist = raw.get("distribution") or "elasticsearch"
    if disabled is False:
        return []
    if disabled is None:
        return [Hit(
            observation=(f"{dist} cluster '{r.name}': {_SETTINGS_GAP}whether the security "
                         f"realm is enabled could not be determined"),
            remediation=("Grant the scan credential the `monitor` cluster privilege (and read on "
                         "the security indices) so security enablement can be assessed."),
            detail=f"security_disabled=unknown reason={raw.get('security_disabled_reason')}",
            assessable=False,
            assessment_reason="no readable xpack.security.enabled / plugins.security.disabled "
                              "setting and no conclusive authenticate probe",
            source_ref={"setting": "xpack.security.enabled / plugins.security.disabled"},
        )]
    return [Hit(
        observation=(f"{dist} cluster '{r.name}' has security disabled "
                     f"({raw.get('security_disabled_reason')}) — there is no authentication, "
                     f"authorization, or audit; any client that reaches the port has full "
                     f"cluster access"),
        remediation=("Enable the security realm: set `xpack.security.enabled: true` "
                     "(Elasticsearch) or install/enable the OpenSearch security plugin "
                     "(`plugins.security.disabled: false`), then configure TLS and native/OIDC "
                     "authentication before exposing the cluster."),
        detail=f"reason={raw.get('security_disabled_reason')}",
        source_ref={"setting": "xpack.security.enabled / plugins.security.disabled"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", severity="critical",
          title="Cluster answers unauthenticated requests")
def anonymous_access(r, ctx) -> list:
    raw = r.raw or {}
    status = raw.get("anon_root_status")
    if status == 200:
        return [Hit(
            observation=(f"an unauthenticated GET / returned HTTP 200 with the cluster's "
                         f"version/name banner — the cluster answers anyone who can reach the "
                         f"port with no credential"),
            remediation=("Enable security and require authentication on the REST layer; remove "
                         "any `xpack.security.authc.anonymous.*` configuration. An anonymous 200 "
                         "on / means the whole search API is open."),
            detail=f"anon_root_status={status}",
            source_ref={"probe": "unauthenticated GET /"},
        )]
    if status in (401, 403):
        return []
    return [Hit(
        observation=(f"the unauthenticated GET / probe did not complete (status={status}), so "
                     f"whether the cluster answers anonymous clients could not be determined"),
        remediation="Confirm the REST endpoint is reachable from the engine and re-run the scan.",
        detail=f"anon_root_status={status}",
        assessable=False,
        assessment_reason="the anonymous probe returned no HTTP status (transport error)",
        source_ref={"probe": "unauthenticated GET /"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.SECURITY.ANONYMOUS_ROLE", severity="high",
          title="An anonymous access role is configured")
def anonymous_role(r, ctx) -> list:
    raw = r.raw or {}
    roles = raw.get("anonymous_roles") or []
    if not roles:
        return []
    return [Hit(
        observation=(f"`xpack.security.authc.anonymous.roles` is set to {roles!r} — requests "
                     f"with no credential are authenticated as an anonymous user holding those "
                     f"roles, so those privileges are granted to anyone who reaches the cluster"),
        remediation=("Remove the anonymous roles unless a documented public read use-case "
                     "requires them; if it does, scope the anonymous role to exactly the indices "
                     "and privileges intended and nothing else."),
        detail=f"anonymous_roles={roles}",
        source_ref={"setting": "xpack.security.authc.anonymous.roles"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.TLS.HTTP_DISABLED", severity="high",
          title="REST (HTTP) layer has no TLS")
def http_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    enabled = raw.get("http_ssl_enabled")
    if enabled is True:
        return []
    if enabled is False:
        return [Hit(
            observation=("the HTTP SSL setting (`xpack.security.http.ssl.enabled` / "
                         "`plugins.security.ssl.http.enabled`) is false — REST traffic, "
                         "including basic-auth credentials and every document, crosses the "
                         "network in plaintext"),
            remediation=("Enable HTTP TLS with a server certificate and require HTTPS for "
                         "clients (`xpack.security.http.ssl.enabled: true`). Rotate any "
                         "credentials that have been sent over the plaintext listener."),
            detail="http_ssl_enabled=False",
            source_ref={"setting": "xpack.security.http.ssl.enabled"},
        )]
    # Setting unreadable: fall back to the observed hop. A plaintext scheme proves plaintext;
    # an https scheme with an unreadable setting is a genuine coverage gap.
    if raw.get("scheme") == "http":
        return [Hit(
            observation=("the cluster was reached over plaintext http:// and the HTTP SSL "
                         "setting was not readable — the REST hop this scan used carried no TLS"),
            remediation=("Enable HTTP TLS and connect over https://. Verify no proxy is "
                         "terminating TLS in front of an otherwise-plaintext node."),
            detail="http_ssl_enabled=unknown scheme=http",
            source_ref={"probe": "connection scheme"},
        )]
    return [Hit(
        observation=("the HTTP SSL setting was not readable and the connection scheme did not "
                     "prove plaintext, so REST-layer TLS could not be assessed"),
        remediation="Grant the scan credential the `monitor` privilege so node settings can be read.",
        detail="http_ssl_enabled=unknown scheme=https",
        assessable=False,
        assessment_reason="xpack.security.http.ssl.enabled was not readable",
        source_ref={"setting": "xpack.security.http.ssl.enabled"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.TLS.TRANSPORT_DISABLED", severity="high",
          title="Inter-node transport has no TLS")
def transport_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    enabled = raw.get("transport_ssl_enabled")
    if enabled is True:
        return []
    if enabled is False:
        return [Hit(
            observation=("the transport SSL setting (`xpack.security.transport.ssl.enabled` / "
                         "`plugins.security.ssl.transport.enabled`) is false — inter-node "
                         "replication and cluster traffic crosses the network unencrypted, and "
                         "a node can join the cluster without mutual TLS"),
            remediation=("Enable transport TLS with node certificates "
                         "(`xpack.security.transport.ssl.enabled: true`, verification_mode "
                         "full). Transport TLS is also what stops a rogue node from joining."),
            detail="transport_ssl_enabled=False",
            source_ref={"setting": "xpack.security.transport.ssl.enabled"},
        )]
    if not raw.get("settings_readable"):
        return [Hit(
            observation=("the transport SSL setting was not readable, so inter-node TLS could "
                         "not be assessed"),
            remediation="Grant the scan credential the `monitor` privilege so node settings can be read.",
            detail="transport_ssl_enabled=unknown",
            assessable=False,
            assessment_reason="xpack.security.transport.ssl.enabled was not readable",
            source_ref={"setting": "xpack.security.transport.ssl.enabled"},
        )]
    return []


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.AUDIT.DISABLED", severity="low",
          title="Security audit logging is disabled")
def audit_disabled(r, ctx) -> list:
    raw = r.raw or {}
    # Only meaningful when security is on; a cluster with security off has the far larger
    # ELASTICSEARCH.SECURITY.DISABLED finding and audit is moot.
    if raw.get("security_disabled") is not False:
        return []
    if raw.get("audit_enabled") is not False:
        return []
    return [Hit(
        observation=("`xpack.security.audit.enabled` is false — authentication and "
                     "authorization events are not recorded, so an intrusion or privilege abuse "
                     "leaves no audit trail to investigate"),
        remediation=("Enable audit logging (`xpack.security.audit.enabled: true`) and ship the "
                     "audit log to your SIEM. Note it requires a Platinum/Enterprise license on "
                     "Elasticsearch; OpenSearch includes it."),
        detail="audit_enabled=False",
        source_ref={"setting": "xpack.security.audit.enabled"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.TLS.TRANSPORT_NO_VERIFY", severity="medium",
          title="Transport TLS does not verify node certificates")
def transport_no_verify(r, ctx) -> list:
    raw = r.raw or {}
    # Only meaningful when transport TLS is actually on; if it is off, ELASTICSEARCH.TLS.TRANSPORT_DISABLED
    # is the finding and verification mode is moot.
    if raw.get("transport_ssl_enabled") is not True:
        return []
    mode = raw.get("transport_verification_mode")
    if str(mode or "").lower() != "none":
        return []
    return [Hit(
        observation=("`xpack.security.transport.ssl.verification_mode` is `none` while transport "
                     "TLS is enabled — traffic is encrypted but node certificates are not "
                     "verified, so a node presenting any certificate can join the cluster and a "
                     "MITM on the transport port is undetected"),
        remediation=("Set `verification_mode: full` (or `certificate`) with a proper CA so "
                     "joining nodes must present a certificate the cluster trusts. Encryption "
                     "without verification stops passive sniffing but not an active attacker."),
        detail=f"transport_verification_mode={mode}",
        source_ref={"setting": "xpack.security.transport.ssl.verification_mode"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.HTTP.CORS_WILDCARD", severity="medium",
          title="HTTP CORS allows any origin")
def cors_wildcard(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("cors_enabled") is not True:
        return []
    origin = str(raw.get("cors_allow_origin") or "").strip()
    if origin not in ("*", "/.*/"):
        return []
    return [Hit(
        observation=(f"`http.cors.enabled` is true with `http.cors.allow-origin` = '{origin}' — "
                     f"any website a user visits can make cross-origin browser requests to the "
                     f"cluster, so a victim's browser becomes a proxy into Elasticsearch"),
        remediation=("Restrict `http.cors.allow-origin` to the exact origins that need browser "
                     "access (never `*`), or disable CORS entirely if no browser client calls "
                     "the cluster directly. Pair with authentication so CORS is not the only "
                     "control."),
        detail=f"cors_enabled=True cors_allow_origin={origin}",
        source_ref={"setting": "http.cors.allow-origin"},
    )]


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.SNAPSHOT.REPO_PLAINTEXT_URL", severity="medium",
          title="Snapshot repository uses a plaintext URL location")
def snapshot_repo_plaintext_url(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for name, repo in (raw.get("snapshot_repos") or {}).items():
        if not isinstance(repo, dict):
            continue
        rtype = str(repo.get("type") or "")
        url = str((repo.get("settings") or {}).get("url") or "")
        if rtype == "url" and url.lower().startswith("http://"):
            hits.append(Hit(
                observation=(f"snapshot repository '{name}' is type `url` pointing at '{url}' — "
                             f"snapshots (a full copy of every index) are read over plaintext "
                             f"HTTP, exposing all indexed data in transit"),
                remediation=("Serve the snapshot repository over https, or use a native "
                             "repository type (fs with restricted permissions, or an object "
                             "store with server-side encryption and a scoped access policy)."),
                detail=f"repo={name} type=url url={url}",
                source_ref={"api": "GET /_snapshot", "repo": name},
            ))
    return hits


@detector(kinds=["es_cluster"], rule_id="ELASTICSEARCH.CLUSTER.NOT_ASSESSED", severity="info",
          title="A security-relevant endpoint could not be read")
def cluster_not_assessed(r, ctx) -> list:
    """The coverage-gap surface at cluster scope: an endpoint the connector recorded as
    forbidden/error is surfaced as not-assessable rather than letting the absence of users,
    roles, or settings read as a clean pass."""
    raw = r.raw or {}
    hits = []
    for endpoint, outcome in sorted((raw.get("endpoint_outcomes") or {}).items()):
        if outcome == "ok":
            continue
        hits.append(Hit(
            observation=(f"endpoint '{endpoint}' returned '{outcome}', so that part of the "
                         f"cluster's posture was not assessed"),
            remediation=("Grant the scan credential read access to this endpoint (the `monitor` "
                         "cluster privilege plus read on the security indices) so it can be "
                         "assessed. Until then its posture is unknown, not clean."),
            detail=f"endpoint={endpoint} outcome={outcome}",
            assessable=False,
            assessment_reason=f"{endpoint} returned {outcome}",
            source_ref={"endpoint": endpoint},
        ))
    return hits


@detector(kinds=["es_index"], rule_id="ELASTICSEARCH.INDEX.ANON_LISTABLE", severity="high",
          title="Index is listable by an unauthenticated client")
def index_anon_listable(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("anon_listable"):
        return []
    system = raw.get("system_index")
    return [Hit(
        observation=(f"index '{r.name}' was returned by an unauthenticated GET /_cat/indices — "
                     f"its existence, health, and document/size metadata are readable with no "
                     f"credential"
                     + (" and it is a system index (a leading dot), which holds security "
                        "configuration and internal state" if system else "")),
        severity="critical" if system else "high",
        remediation=("Require authentication on the REST layer and remove anonymous access; a "
                     "system index (`.security`, `.kibana`) exposed anonymously is a direct read "
                     "of the cluster's own security state."),
        detail=f"index={r.name} system_index={system}",
        source_ref={"probe": "unauthenticated GET /_cat/indices"},
    )]
