"""Coordination rulepack — config-time posture over what connect/coordination.py collected.

Every rule reads REAL evidence the connector observed (etcd's own auth-probe error text, the
ZooKeeper 4lw responses, Nacos's server-state auth_enabled flag, Consul's DebugConfig) and
cites it in the observation; none guesses from names or tags. Rules run on the DISTINCT coord_*
kinds the connector emits, so they never collide with the Kafka/Kong/RabbitMQ/Redis/AWS packs.

Why this pack is high-leverage: the coordination layer IS the control plane. etcd holds the
Kubernetes keyspace; Consul carries the service-mesh intentions; Nacos serves the dynamic config
a fleet reads on boot; ZooKeeper elects the leaders. Unauthenticated access here is not one
service — it is every service downstream of it.

Severity conventions (house):
  critical  anyone who can reach the port gets full control (auth disabled, unauthenticated
            read of the whole keyspace, default creds, the Nacos auth-bypass backdoor, Consul
            ACLs defaulting to allow)
  high      no transport encryption on the wire, no SASL enforcement, admin 4lw exposed,
            an any-source allow intention, the anonymous token carrying policies
  medium    TLS/encryption hygiene (no ZK secure port, console reachable, gossip unencrypted)

The third outcome is used throughout: whatever the target hid (auth port firewalled, 4lw
command off the whitelist, agent/self denied, version unreadable) becomes an assessable=False
coverage gap — never a clean pass, never a fabricated failure.
"""
from ..contracts import Hit
from ..registry import detector


def _gap(observation: str, remediation: str, reason: str, detail: str = "",
         source_ref=None) -> list:
    """The not-assessable Hit: what WAS read is stated, `assessment_reason` says what could not
    be settled, and the finding maps to 'unknown' — never a pass, never a failure."""
    return [Hit(observation=observation, remediation=remediation, detail=detail,
                assessable=False, assessment_reason=reason, source_ref=source_ref or {})]


def _version_tuple(v):
    try:
        head = str(v).strip().split("-")[0].lstrip("vV")
        parts = [int(x) for x in head.split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except (ValueError, TypeError, AttributeError):
        return None


# ══ etcd ═══════════════════════════════════════════════════════════════════════
@detector(kinds=["coord_etcd"], rule_id="COORD.ETCD.AUTH_DISABLED", severity="critical",
          title="etcd has RBAC authentication disabled")
def etcd_auth_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("auth_assessable"):
        return _gap(
            observation=(f"etcd at {r.name} did not return a determinate answer to an "
                         f"unauthenticated /v3/auth/user/list, so whether RBAC authentication "
                         f"is enabled could not be established"),
            remediation="Grant the scan reachability to the etcd client API (:2379) so the auth "
                        "state can be probed, or confirm `etcdctl auth status` out of band.",
            reason="unauthenticated /v3/auth/user/list gave no determinate auth-state signal",
            detail=f"auth_enabled={raw.get('auth_enabled')} reachable={raw.get('reachable')}",
            source_ref={"api": "/v3/auth/user/list"})
    if raw.get("auth_enabled"):
        return []
    return [Hit(
        observation=(f"etcd at {r.name} reports 'authentication is not enabled' to an "
                     f"unauthenticated /v3/auth/user/list — RBAC is off, so any client that can "
                     f"reach :{raw.get('port')} reads and writes the entire keyspace"),
        remediation=("Enable auth: create a root user (`etcdctl user add root`), then "
                     "`etcdctl auth enable`. etcd with RBAC off is full read/write to whoever "
                     "opens the socket — and for a Kubernetes etcd that is every Secret and "
                     "every object in the cluster."),
        detail="auth_enabled=False",
        source_ref={"api": "/v3/auth/user/list", "field": "authentication is not enabled"},
    )]


@detector(kinds=["coord_etcd"], rule_id="COORD.ETCD.UNAUTHENTICATED_READ", severity="critical",
          title="etcd serves keyspace reads with no credential")
def etcd_unauthenticated_read(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("unauth_read_assessable"):
        return _gap(
            observation=(f"etcd at {r.name} gave no determinate answer to an unauthenticated "
                         f"/v3/kv/range, so it could not be confirmed whether the keyspace is "
                         f"readable without a credential"),
            remediation="Ensure the scan can reach the etcd client API so the unauthenticated "
                        "read can be tested.",
            reason="unauthenticated /v3/kv/range gave no determinate read signal",
            detail=f"unauth_read_ok={raw.get('unauth_read_ok')}",
            source_ref={"api": "/v3/kv/range"})
    if not raw.get("unauth_read_ok"):
        return []
    return [Hit(
        observation=(f"etcd at {r.name} answered an unauthenticated /v3/kv/range with a cluster "
                     f"header — the keyspace was read with no token, so any client on the "
                     f"network can dump every key etcd stores"),
        remediation=("Enable RBAC (`etcdctl auth enable`) and require client-certificate or "
                     "password auth, then re-test that /v3/kv/range is rejected without a "
                     "credential. Firewall :2379 to the members and legitimate clients only."),
        detail="unauth_read_ok=True",
        source_ref={"api": "/v3/kv/range"},
    )]


@detector(kinds=["coord_etcd"], rule_id="COORD.ETCD.CLIENT_TLS_DISABLED", severity="high",
          title="etcd client API accepts plaintext connections")
def etcd_client_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("client_tls_assessable"):
        return _gap(
            observation=(f"etcd at {r.name} was not reachable on the client API, so whether the "
                         f"client port requires TLS could not be determined"),
            remediation="Confirm the etcd client endpoint and re-scan so client transport can "
                        "be assessed.",
            reason="client API unreachable — transport not observed",
            detail=f"reachable={raw.get('reachable')}",
            source_ref={"api": "/version"})
    if raw.get("connected_via_tls"):
        return []
    return [Hit(
        observation=(f"etcd at {r.name} answered the client API over plaintext HTTP — the "
                     f"client port accepts non-TLS connections, so client requests (and any "
                     f"password auth) cross the network in the clear"),
        remediation=("Serve the client API over TLS only: set `--cert-file` / `--key-file` and "
                     "`--client-cert-auth` (mutual TLS) on every member, and move clients to the "
                     "https endpoint. Plaintext etcd exposes the keyspace and credentials to any "
                     "on-path listener."),
        detail="connected_via_tls=False",
        source_ref={"transport": "client", "field": "cert-file/client-cert-auth"},
    )]


@detector(kinds=["coord_etcd"], rule_id="COORD.ETCD.PEER_TLS_DISABLED", severity="high",
          title="etcd peer (replication) traffic is not encrypted")
def etcd_peer_tls_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("peer_tls_assessable"):
        return _gap(
            observation=(f"etcd at {r.name} peer port {raw.get('peer_port')} was not reachable "
                         f"for a plaintext probe (firewalled or refused), so peer-TLS "
                         f"enablement could not be determined — the client API never exposes it"),
            remediation="Point the scan at the etcd peer port (default 2380) from a host that "
                        "can reach it, or confirm `--peer-cert-file` / `--peer-client-cert-auth` "
                        "on the members out of band.",
            reason="peer port not reachable for the plaintext probe; not exposed via client API",
            detail=f"peer_port={raw.get('peer_port')} peer_tls_on={raw.get('peer_tls_on')}",
            source_ref={"transport": "peer", "port": raw.get("peer_port")})
    if raw.get("peer_tls_on"):
        return []
    return [Hit(
        observation=(f"etcd at {r.name} peer port {raw.get('peer_port')} answered a plaintext "
                     f"HTTP probe — peer TLS is off, so the raft replication carrying every "
                     f"write between members crosses the network unencrypted and unauthenticated"),
        remediation=("Set `--peer-cert-file`, `--peer-key-file` and `--peer-client-cert-auth` "
                     "on every member and restart with peer TLS required. Unencrypted peer "
                     "traffic lets an on-path attacker read every value and, without peer cert "
                     "auth, impersonate a member."),
        detail=f"peer_port={raw.get('peer_port')} plaintext peer HTTP answered",
        source_ref={"transport": "peer", "field": "peer-cert-file/peer-client-cert-auth"},
    )]


# ══ ZooKeeper ══════════════════════════════════════════════════════════════════
@detector(kinds=["coord_zookeeper"], rule_id="COORD.ZOOKEEPER.FOUR_LETTER_WORDS_EXPOSED",
          severity="high", title="ZooKeeper exposes admin four-letter-word commands unauthenticated")
def zk_four_letter_words_exposed(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("fourlw_assessable"):
        return _gap(
            observation=(f"ZooKeeper at {r.name} did not answer any four-letter-word probe, so "
                         f"the 4lw whitelist exposure could not be assessed"),
            remediation="Confirm the ZooKeeper client port (:2181) is reachable from the scan "
                        "host so the 4lw whitelist can be probed.",
            reason="no four-letter-word command answered (port unreachable or all blocked)",
            detail=f"commands_answered={raw.get('commands_answered')}",
            source_ref={"protocol": "4lw"})
    if not raw.get("sensitive_4lw_exposed"):
        return []
    answered = raw.get("commands_answered") or {}
    exposed = [c for c in ("conf", "envi", "stat") if answered.get(c)]
    return [Hit(
        observation=(f"ZooKeeper at {r.name} answered the four-letter-word command(s) "
                     f"{exposed} with no authentication — 4lw has no auth, so the whitelist is "
                     f"the only control, and it exposes server config (`conf`), the JVM/OS "
                     f"environment (`envi`) and live client sessions (`stat`) to anyone on the "
                     f"port"),
        remediation=("Restrict `zookeeper.4lw.commands.whitelist` to the minimum (commonly just "
                     "`srvr`/`ruok` for health checks) and firewall :2181 to clients only. "
                     "`conf`/`envi`/`stat`/`dump`/`wchp` leak configuration, environment and "
                     "session topology that map the cluster for an attacker."),
        detail=f"answered={answered}",
        source_ref={"protocol": "4lw", "setting": "zookeeper.4lw.commands.whitelist"},
    )]


@detector(kinds=["coord_zookeeper"], rule_id="COORD.ZOOKEEPER.NO_SASL_AUTH", severity="high",
          title="ZooKeeper does not require client SASL authentication")
def zk_no_sasl_auth(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("sasl_assessable"):
        return _gap(
            observation=(f"ZooKeeper at {r.name} did not dump `sessionRequireClientSASLAuth` in "
                         f"its 4lw config, so whether client SASL authentication is required "
                         f"could not be determined from the wire"),
            remediation="Confirm `sessionRequireClientSASLAuth=true` and the SASL authProvider "
                        "in zoo.cfg / JAAS out of band; 4lw does not reliably expose it.",
            reason="sessionRequireClientSASLAuth not present in the 4lw config dump",
            detail=f"sasl_required={raw.get('sasl_required')}",
            source_ref={"config": "sessionRequireClientSASLAuth"})
    if raw.get("sasl_required"):
        return []
    return [Hit(
        observation=(f"ZooKeeper at {r.name} reports sessionRequireClientSASLAuth=false — client "
                     f"SASL authentication is not required, so unauthenticated clients connect "
                     f"and get the default world:anyone:cdrwa ACL: full create/delete/read/write "
                     f"/admin on znodes"),
        remediation=("Set `sessionRequireClientSASLAuth=true`, configure an authProvider "
                     "(Kerberos/DIGEST) with a JAAS login, and set restrictive znode ACLs "
                     "(never world:anyone:cdrwa). Enforce `zookeeper.enforce.auth.enabled=true` "
                     "with `auth` scheme so anonymous sessions are rejected."),
        detail="sessionRequireClientSASLAuth=false",
        source_ref={"config": "sessionRequireClientSASLAuth", "acl": "world:anyone:cdrwa"},
    )]


@detector(kinds=["coord_zookeeper"], rule_id="COORD.ZOOKEEPER.NO_TLS", severity="medium",
          title="ZooKeeper has no TLS (secure) client port")
def zk_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("tls_assessable"):
        return _gap(
            observation=(f"ZooKeeper at {r.name} did not dump `secureClientPort` in its 4lw "
                         f"config, so whether a TLS client port is configured could not be "
                         f"determined"),
            remediation="Confirm `secureClientPort` and the SSL keystore config in zoo.cfg out "
                        "of band.",
            reason="secureClientPort not present in the 4lw config dump",
            detail=f"secure_client_port={raw.get('secure_client_port')}",
            source_ref={"config": "secureClientPort"})
    if raw.get("secure_tls"):
        return []
    return [Hit(
        observation=(f"ZooKeeper at {r.name} reports secureClientPort={raw.get('secure_client_port')} "
                     f"— no TLS client port is configured, so client traffic (including SASL "
                     f"exchanges and every znode value) crosses the network in plaintext"),
        remediation=("Configure `secureClientPort` with `ssl.keyStore.location` / "
                     "`ssl.trustStore.location` and the Netty server cnxn factory, then move "
                     "clients to the TLS port. Plaintext ZooKeeper exposes configuration and "
                     "coordination state to any on-path listener."),
        detail=f"secure_client_port={raw.get('secure_client_port')}",
        source_ref={"config": "secureClientPort"},
    )]


# ══ Nacos ══════════════════════════════════════════════════════════════════════
@detector(kinds=["coord_nacos"], rule_id="COORD.NACOS.AUTH_DISABLED", severity="critical",
          title="Nacos has authentication disabled")
def nacos_auth_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("auth_assessable"):
        return _gap(
            observation=(f"Nacos at {r.name} did not return an auth_enabled flag from "
                         f"/nacos/v1/console/server/state, so whether authentication is enabled "
                         f"could not be determined"),
            remediation="Ensure the scan can reach the Nacos server-state endpoint, or confirm "
                        "`nacos.core.auth.enabled=true` in application.properties.",
            reason="server-state endpoint returned no auth_enabled flag",
            detail=f"auth_enabled={raw.get('auth_enabled')}",
            source_ref={"api": "/nacos/v1/console/server/state", "field": "auth_enabled"})
    if raw.get("auth_enabled"):
        return []
    return [Hit(
        observation=(f"Nacos at {r.name} reports auth_enabled=false — authentication is "
                     f"disabled, so any client that can reach :{raw.get('port')} reads and "
                     f"writes every service registration and config the fleet consumes"),
        remediation=("Set `nacos.core.auth.enabled=true` (and a strong "
                     "`nacos.core.auth.plugin.nacos.token.secret.key` / server identity) and "
                     "restart. Unauthenticated Nacos lets an attacker repoint service discovery "
                     "and push malicious dynamic config to everything that reads from it."),
        detail="auth_enabled=false",
        source_ref={"api": "/nacos/v1/console/server/state", "field": "auth_enabled"},
    )]


@detector(kinds=["coord_nacos"], rule_id="COORD.NACOS.DEFAULT_CREDENTIALS", severity="critical",
          title="Nacos accepts the default nacos/nacos credentials")
def nacos_default_credentials(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("creds_assessable"):
        return _gap(
            observation=(f"Nacos at {r.name} did not return a determinate login result for the "
                         f"default nacos/nacos credential, so it could not be confirmed whether "
                         f"the default account is still active"),
            remediation="Ensure the scan can reach /nacos/v1/auth/login, or confirm the default "
                        "`nacos` account password was changed.",
            reason="default-credential login returned no determinate result",
            detail=f"default_creds_valid={raw.get('default_creds_valid')}",
            source_ref={"api": "/nacos/v1/auth/login"})
    if not raw.get("default_creds_valid"):
        return []
    return [Hit(
        observation=(f"Nacos at {r.name} issued an access token for the shipped default "
                     f"credential nacos/nacos — the default administrator account is still "
                     f"active with its documented password"),
        remediation=("Change the `nacos` account password immediately (Nacos console → "
                     "Authority Control → Users) or delete it and create named admin accounts. "
                     "The nacos/nacos default is published and the first thing scanned for on an "
                     "exposed Nacos."),
        detail="default_creds_valid=True username=nacos",
        source_ref={"api": "/nacos/v1/auth/login", "credential": "nacos/nacos"},
    )]


@detector(kinds=["coord_nacos"], rule_id="COORD.NACOS.CONSOLE_EXPOSED", severity="medium",
          title="Nacos console is reachable over the network")
def nacos_console_exposed(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("console_assessable"):
        return _gap(
            observation=(f"Nacos at {r.name} gave no determinate answer to a console "
                         f"reachability probe, so whether the admin console is network-reachable "
                         f"could not be determined"),
            remediation="Confirm the Nacos console endpoint reachability from the scan host.",
            reason="console reachability probe returned no determinate result",
            detail=f"console_reachable={raw.get('console_reachable')}",
            source_ref={"api": "/nacos/index.html"})
    if not raw.get("console_reachable"):
        return []
    auth_off = raw.get("auth_enabled") is False
    return [Hit(
        observation=(f"Nacos at {r.name} serves its admin console over the network"
                     + (" AND authentication is disabled — the console is an unauthenticated "
                        "control panel over service discovery and config"
                        if auth_off else
                        " — the admin console is exposed beyond the loopback/management network")),
        severity="high" if auth_off else "medium",
        remediation=("Bind the console to a management interface or put it behind a reverse "
                     "proxy with auth and IP allow-listing; do not expose /nacos to untrusted "
                     "networks. Combined with weak or disabled auth, a reachable console is a "
                     "full takeover surface."),
        detail=f"console_reachable=True auth_enabled={raw.get('auth_enabled')}",
        source_ref={"api": "/nacos/index.html"},
    )]


@detector(kinds=["coord_nacos"], rule_id="COORD.NACOS.AUTH_BYPASS_CVE", severity="critical",
          title="Nacos is exposed to the CVE-2021-29441 authentication bypass")
def nacos_auth_bypass_cve(r, ctx) -> list:
    """CVE-2021-29441 (CVSS 8.6): the AuthFilter backdoor skips authentication for requests
    carrying the `Nacos-Server` User-Agent. Fixed in 1.4.1. Preferred evidence is the empirical
    probe (the bypass actually returned protected data); the version comparison is the fallback
    when the probe was inconclusive."""
    raw = r.raw or {}
    version = raw.get("version")
    if raw.get("auth_bypass_ok"):
        return [Hit(
            observation=(f"Nacos at {r.name} returned the protected user list to a request "
                         f"carrying the `Nacos-Server` User-Agent — the CVE-2021-29441 auth "
                         f"bypass backdoor is exploitable, authentication was skipped"),
            remediation=("Upgrade to Nacos ≥ 1.4.1 (the release that removed the User-Agent "
                         "backdoor) and rotate any credentials that were reachable. The bypass "
                         "grants unauthenticated administrative access."),
            detail=f"auth_bypass_ok=True version={version}",
            source_ref={"api": "/nacos/v1/auth/users", "header": "User-Agent: Nacos-Server",
                        "cve": "CVE-2021-29441"},
        )]
    if raw.get("auth_bypass_ok") is False:
        return []   # the backdoor request was rejected (403) — patched/closed
    parsed = _version_tuple(version)
    if parsed is None:
        return _gap(
            observation=(f"Nacos at {r.name} reported version {version!r}, which this scanner "
                         f"could not parse to a release, and the `Nacos-Server` bypass probe was "
                         f"inconclusive, so exposure to CVE-2021-29441 was not determined"),
            remediation="Confirm the running Nacos version against the CVE-2021-29441 advisory "
                        "and upgrade to ≥ 1.4.1.",
            reason="version unparseable and the auth-bypass probe was inconclusive",
            detail=f"version={version} auth_bypass_ok={raw.get('auth_bypass_ok')}",
            source_ref={"cve": "CVE-2021-29441"})
    if parsed >= (1, 4, 1):
        return []
    return [Hit(
        observation=(f"Nacos at {r.name} reports version {version}, which predates 1.4.1 — it "
                     f"carries the CVE-2021-29441 AuthFilter backdoor that skips authentication "
                     f"for requests with the `Nacos-Server` User-Agent (CVSS 8.6)"),
        remediation=("Upgrade to Nacos ≥ 1.4.1, which removed the User-Agent backdoor. Until "
                     "then an attacker performs administrative actions with no credential by "
                     "spoofing one HTTP header."),
        detail=f"version={version} (<1.4.1)",
        source_ref={"api": "/nacos/v1/console/server/state", "field": "version",
                    "cve": "CVE-2021-29441"},
    )]


# ══ Consul ═════════════════════════════════════════════════════════════════════
@detector(kinds=["coord_consul"], rule_id="COORD.CONSUL.ACL_DEFAULT_ALLOW", severity="critical",
          title="Consul ACLs are disabled or default to allow")
def consul_acl_default_allow(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("acl_assessable"):
        return _gap(
            observation=(f"Consul at {r.name} did not return ACLsEnabled or ACLDefaultPolicy "
                         f"from /v1/agent/self, so the effective default access policy could "
                         f"not be determined"),
            remediation="Grant the scan access to /v1/agent/self (or a management token) so the "
                        "ACL configuration can be read.",
            reason="agent/self exposed neither ACLsEnabled nor ACLDefaultPolicy",
            detail=f"acls_enabled={raw.get('acls_enabled')} "
                   f"acl_default_policy={raw.get('acl_default_policy')}",
            source_ref={"api": "/v1/agent/self", "field": "DebugConfig.ACL*"})
    acls_enabled = raw.get("acls_enabled")
    default = raw.get("acl_default_policy")
    if acls_enabled is False:
        reason = "ACLsEnabled=false — ACLs are off entirely"
    elif default == "allow":
        reason = "ACLDefaultPolicy=allow — unmatched requests are permitted"
    else:
        return []   # ACLs enabled with a deny default: the safe posture
    return [Hit(
        observation=(f"Consul at {r.name}: {reason}, so any request without a token (or without "
                     f"a matching rule) is allowed — the datacenter has no default-deny, and an "
                     f"unauthenticated caller can read/write the catalog, KV and intentions"),
        remediation=("Enable ACLs with a default-deny: `acl { enabled = true, "
                     "default_policy = \"deny\", down_policy = \"extend-cache\" }`, bootstrap a "
                     "management token, and issue least-privilege tokens per service. A "
                     "default-allow (or ACLs-off) Consul is an open control plane for the mesh."),
        detail=f"acls_enabled={acls_enabled} acl_default_policy={default}",
        source_ref={"api": "/v1/agent/self",
                    "field": "DebugConfig.ACLsEnabled/ACLDefaultPolicy"},
    )]


@detector(kinds=["coord_consul"], rule_id="COORD.CONSUL.ANONYMOUS_TOKEN_POLICIES", severity="high",
          title="Consul anonymous token carries policies")
def consul_anonymous_token_policies(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("anon_assessable"):
        return _gap(
            observation=(f"Consul at {r.name}: the anonymous token could not be read (a "
                         f"management token is required), so the grants held by unauthenticated "
                         f"callers could not be assessed"),
            remediation="Provide a management token to the scan so the anonymous token's "
                        "attached policies can be inventoried.",
            reason="reading the anonymous token requires a management token",
            detail=f"anonymous_policies={raw.get('anonymous_policies')}",
            source_ref={"api": "/v1/acl/token/00000000-0000-0000-0000-000000000002"})
    policies = raw.get("anonymous_policies") or []
    if not policies:
        return []
    return [Hit(
        observation=(f"Consul at {r.name}: the anonymous token has {len(policies)} policy/policies "
                     f"attached ({policies}) — every unauthenticated request inherits those "
                     f"grants, so 'anonymous' is not 'no access'"),
        remediation=("Detach all policies from the anonymous token (leave it with no rules): "
                     "`consul acl token update -id 00000000-0000-0000-0000-000000000002 "
                     "-policy-name ''` (remove each), and grant access only through named "
                     "least-privilege tokens. Policies on the anonymous token silently widen "
                     "what unauthenticated callers can do."),
        detail=f"anonymous_policies={policies}",
        source_ref={"api": "/v1/acl/token/00000000-0000-0000-0000-000000000002",
                    "field": "Policies"},
    )]


@detector(kinds=["coord_consul"], rule_id="COORD.CONSUL.WILDCARD_INTENTION", severity="high",
          title="Consul has an any-source allow intention")
def consul_wildcard_intention(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("intentions_assessable"):
        return _gap(
            observation=(f"Consul at {r.name}: the connect intentions list could not be read, "
                         f"so wildcard service-to-service allow rules could not be assessed"),
            remediation="Grant the scan read access to /v1/connect/intentions so mesh "
                        "authorization can be assessed.",
            reason="/v1/connect/intentions was not readable",
            detail=f"wildcard_intentions={raw.get('wildcard_intentions')}",
            source_ref={"api": "/v1/connect/intentions"})
    matched = raw.get("wildcard_intentions") or []
    if not matched:
        return []
    worst = next((m for m in matched if str(m.get("destination")) == "*"), matched[0])
    return [Hit(
        observation=(f"Consul at {r.name} has an allow intention with SourceName '*' "
                     f"(→ '{worst.get('destination')}') — any source service is authorized to "
                     f"call the destination, collapsing the Connect mesh's default-deny for that "
                     f"path; '*'→'*' would trust the entire mesh to talk to everything"),
        remediation=("Remove the wildcard-source allow and write explicit source→destination "
                     "intentions (`consul intention create -allow <src> <dst>`) with a "
                     "default-deny. A '*' source intention defeats the point of service-mesh "
                     "authorization."),
        detail=f"wildcard_intentions={matched}",
        source_ref={"api": "/v1/connect/intentions", "field": "SourceName=* Action=allow"},
    )]


@detector(kinds=["coord_consul"], rule_id="COORD.CONSUL.GOSSIP_ENCRYPTION_DISABLED",
          severity="medium", title="Consul gossip (serf) traffic is not encrypted")
def consul_gossip_encryption_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("gossip_assessable"):
        return _gap(
            observation=(f"Consul at {r.name} did not report serf_lan.encrypted in "
                         f"/v1/agent/self Stats, so gossip encryption could not be assessed"),
            remediation="Grant the scan access to /v1/agent/self so the serf gossip encryption "
                        "state can be read.",
            reason="agent/self Stats.serf_lan.encrypted was absent",
            detail=f"gossip_encrypted={raw.get('gossip_encrypted')}",
            source_ref={"api": "/v1/agent/self", "field": "Stats.serf_lan.encrypted"})
    if raw.get("gossip_encrypted"):
        return []
    return [Hit(
        observation=(f"Consul at {r.name} reports Stats.serf_lan.encrypted=false — the gossip "
                     f"pool has no encryption key, so serf membership and event traffic between "
                     f"agents crosses the network in plaintext"),
        remediation=("Generate a key (`consul keygen`) and set `encrypt` (plus "
                     "`verify_incoming`/`verify_outgoing` for RPC TLS) on every agent, then "
                     "rotate it in with `consul keyring`. Unencrypted gossip lets an on-path "
                     "attacker read membership and inject serf events."),
        detail="serf_lan.encrypted=false",
        source_ref={"api": "/v1/agent/self", "field": "Stats.serf_lan.encrypted"},
    )]
