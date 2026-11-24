"""NATS / JetStream rulepack — config-time posture over what connect/nats.py collected.

Every rule reads REAL evidence: the /varz booleans as the server actually loaded them, and the
account / no_auth_user / leafnode / gateway structure from the provided config. None guesses from
names. Rules run on the DISTINCT nats_server / nats_account kinds, so they never collide with the
Kafka/Kong/RabbitMQ/Redis packs.

The third outcome is used deliberately: a check whose evidence lives only in the config (the
no_auth_user → system-account mapping, the account/leafnode/gateway model) returns an
assessable=False coverage gap when no config was provided, rather than reading absence as a pass.

House severities:
  critical  anyone on the internet gets in (auth not required; anonymous → SYSTEM account)
  high      plaintext client transport, anonymous-mapped account, JetStream authz-bypass CVE
  medium    leafnode/gateway plaintext, account users with no credential
  low       unauthenticated monitoring surface, no dedicated system account
"""
from ..contracts import Hit
from ..registry import detector

# CVE-2025-30215 (CVSS 9.6, verified 2026-07-24 against the NATS advisory / NVD): four admin-level
# JetStream APIs in the $JS subject namespace lacked authorization checks, letting any account with
# JetStream management permissions act on assets in ANY other account (at least one path allows
# data destruction). Affected 2.2.0 up to <2.10.27 and <2.11.1; fixed in 2.10.27 and 2.11.1.
_JS_AUTHZ_FIXED = {(2, 10): 27, (2, 11): 1}


def _parse_version(v):
    try:
        parts = [int(x) for x in str(v).split("-")[0].split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except (ValueError, TypeError):
        return None


def _js_authz_vulnerable(version):
    """True/False when determinable, None when the version can't be parsed (→ not assessable)."""
    parsed = _parse_version(version)
    if parsed is None:
        return None
    major, minor, patch = parsed
    if (major, minor) < (2, 2):
        return False                       # predates the affected range
    floor = _JS_AUTHZ_FIXED.get((major, minor))
    if floor is not None:
        return patch < floor
    if (major, minor) < (2, 10):
        return True                        # every 2.2–2.9 release is affected
    return False                           # 2.12+ ships the fix


# ── Authentication ────────────────────────────────────────────────────────────
@detector(kinds=["nats_server"], rule_id="NATS.AUTH.NOT_REQUIRED", severity="critical",
          title="NATS accepts unauthenticated client connections")
def auth_not_required(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("varz_readable"):
        return []   # NATS.MONITORING.NOT_ASSESSABLE files the gap
    if raw.get("auth_required") is not False:
        return []
    return [Hit(
        observation=("GET /varz reports auth_required=false — the server requires no credentials, "
                     "so any client that can reach a client-listener port has full publish and "
                     "subscribe access to every subject the connecting account can see"),
        remediation=("Configure authentication: an `authorization` block with users/passwords or "
                     "nkeys, per-account users, or operator-mode JWT auth. Set `no_auth_user` only "
                     "for a deliberately scoped anonymous account, never the system account. "
                     "Unauthenticated NATS is message-bus access to anyone who can open the socket."),
        detail="auth_required=false",
        source_ref={"api": "/varz", "field": "auth_required"},
    )]


@detector(kinds=["nats_server"], rule_id="NATS.AUTH.NO_AUTH_USER", severity="high",
          title="Anonymous connections are mapped to a real account via no_auth_user")
def no_auth_user_mapped(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("config_provided"):
        return [Hit(
            observation=("no server config was provided, so whether `no_auth_user` maps "
                         "unauthenticated clients into a real (or the system) account could not "
                         "be determined"),
            remediation=("Provide the nats-server config as JSON so the no_auth_user mapping can "
                         "be assessed."),
            detail="config_provided=false",
            assessable=False,
            assessment_reason="no_auth_user is only visible in server config, which was not provided",
            source_ref={"config_key": "no_auth_user"},
        )]
    no_auth = raw.get("no_auth_user")
    if not no_auth:
        return []
    is_system = bool(raw.get("no_auth_user_is_system"))
    account = raw.get("no_auth_user_account")
    where = (f"the SYSTEM account ({account!r})" if is_system
             else f"account {account!r}" if account
             else "a user not found in any readable account block")
    return [Hit(
        observation=(f"server config sets no_auth_user={no_auth!r}, so a client that presents no "
                     f"credentials is silently authenticated as that user, which resolves to "
                     f"{where}. Every anonymous client on the network inherits that user's "
                     f"publish/subscribe permissions"
                     + (" — including full access to $SYS system subjects (server shutdown, "
                        "account claims, monitoring events)." if is_system else ".")),
        remediation=("Point no_auth_user at a narrowly-scoped account with explicit publish/"
                     "subscribe permissions, never the system account and never a user with a "
                     "broad permission set. Prefer removing no_auth_user entirely and requiring "
                     "authentication. If anonymous access is intentional, scope its subjects "
                     "tightly."),
        # Anonymous access to the SYSTEM account is a full-control door, not merely broad.
        severity="critical" if is_system else None,
        detail=f"no_auth_user={no_auth} account={account} is_system={is_system}",
        source_ref={"config_key": "no_auth_user", "account": account},
    )]


# ── Transport ─────────────────────────────────────────────────────────────────
@detector(kinds=["nats_server"], rule_id="NATS.TLS.NOT_REQUIRED", severity="high",
          title="NATS client connections are not required to use TLS")
def tls_not_required(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("varz_readable"):
        return []
    if raw.get("tls_required") is not False:
        return []
    return [Hit(
        observation=("GET /varz reports tls_required=false — client connections are accepted in "
                     "plaintext, so credentials (user/password, tokens) and every published "
                     "message body cross the network unencrypted and are sniffable on-path"),
        remediation=("Add a `tls` block to the server config with a certificate and set the "
                     "listener to require TLS, so clients cannot connect in plaintext. For "
                     "client-certificate auth additionally set `verify: true`."),
        detail="tls_required=false",
        source_ref={"api": "/varz", "field": "tls_required"},
    )]


@detector(kinds=["nats_server"], rule_id="NATS.LEAFNODE.NO_TLS", severity="medium",
          title="Leafnode connections are configured without TLS")
def leafnode_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("config_provided") or not raw.get("leafnodes_configured"):
        return []
    if raw.get("leafnodes_tls"):
        return []
    return [Hit(
        observation=("server config defines a `leafnodes` block with no `tls` — leaf connections "
                     "from remote NATS servers/clusters are accepted in plaintext, carrying "
                     "cross-cluster credentials and message traffic unencrypted"),
        remediation=("Add a `tls` block under `leafnodes` (certificate + `verify: true`) so leaf "
                     "connections are encrypted and the connecting leaf is authenticated. Leaf "
                     "links routinely cross trust and network boundaries."),
        detail="leafnodes_configured=true leafnodes_tls=false",
        source_ref={"config_key": "leafnodes.tls"},
    )]


@detector(kinds=["nats_server"], rule_id="NATS.GATEWAY.NO_TLS", severity="medium",
          title="Gateway (supercluster) connections are configured without TLS")
def gateway_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("config_provided") or not raw.get("gateway_configured"):
        return []
    if raw.get("gateway_tls"):
        return []
    return [Hit(
        observation=("server config defines a `gateway` block with no `tls` — gateway "
                     "connections between superclusters are accepted in plaintext, carrying "
                     "inter-cluster traffic and credentials unencrypted across (often WAN) links"),
        remediation=("Add a `tls` block under `gateway` (certificate + `verify: true`). Gateway "
                     "links connect independent clusters, frequently over untrusted networks, so "
                     "unencrypted gateways expose the whole supercluster's traffic."),
        detail="gateway_configured=true gateway_tls=false",
        source_ref={"config_key": "gateway.tls"},
    )]


# ── Monitoring surface ──────────────────────────────────────────────────────────
@detector(kinds=["nats_server"], rule_id="NATS.MONITORING.UNAUTHENTICATED", severity="low",
          title="NATS HTTP monitoring endpoints answered an unauthenticated request")
def monitoring_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("monitoring_unauthenticated"):
        return []
    tls_note = ("" if raw.get("monitoring_tls_verified")
                else " and the monitoring request was served over plaintext HTTP")
    return [Hit(
        observation=(f"GET {raw.get('monitoring_url')}/varz returned server state to a request "
                     f"that carried no credentials{tls_note}. NATS monitoring endpoints (/varz, "
                     f"/connz, /jsz, /accountz) have no authentication mechanism of their own, so "
                     f"anyone who can reach this port can enumerate server config, connections and "
                     f"JetStream assets. Actual network reachability is not verified by this check"),
        remediation=("Do not expose the monitoring port (default 8222) beyond a trusted admin "
                     "network: bind it to a private interface, firewall it, and front it with TLS "
                     "and an authenticating reverse proxy. The monitoring endpoints leak topology "
                     "and connection metadata even though they cannot publish messages."),
        detail=f"monitoring_url={raw.get('monitoring_url')} tls_verified={raw.get('monitoring_tls_verified')}",
        source_ref={"api": "/varz"},
    )]


@detector(kinds=["nats_server"], rule_id="NATS.SYSTEM_ACCOUNT.NOT_CONFIGURED", severity="low",
          title="No dedicated system account is configured")
def system_account_not_configured(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("varz_readable"):
        return []
    if raw.get("system_account"):
        return []
    return [Hit(
        observation=("neither /varz nor the provided config names a `system_account` — server "
                     "events and $SYS subjects run under NATS's built-in default system account, "
                     "which is harder to place under least-privilege and to audit than an "
                     "explicitly configured one"),
        remediation=("Define a dedicated `system_account` in the server config with its own users "
                     "and scoped permissions, so access to $SYS (monitoring events, account "
                     "claims, server management subjects) is explicit and auditable."),
        detail="system_account=unset",
        source_ref={"api": "/varz", "field": "system_account"},
    )]


# ── Accounts ────────────────────────────────────────────────────────────────────
@detector(kinds=["nats_account"], rule_id="NATS.ACCOUNT.USER_NO_CREDENTIAL", severity="medium",
          title="Account defines a user with no credential")
def account_user_no_credential(r, ctx) -> list:
    raw = r.raw or {}
    users = raw.get("users") or []
    naked = [u.get("user") for u in users if not u.get("has_credential")]
    if not naked:
        return []
    is_system = bool(raw.get("is_system_account"))
    return [Hit(
        observation=(f"account {raw.get('name')!r} defines user(s) {naked!r} with no password, "
                     f"nkey or jwt — the user block sets no credential, so authentication for it "
                     f"relies entirely on connection context rather than a secret"
                     + (" and this is the SYSTEM account, where an unauthenticated user is full "
                        "server control." if is_system else ".")),
        remediation=("Give every user an explicit credential (password, nkey, or operator-signed "
                     "JWT). A user block with no credential is only safe when it is the target of "
                     "a deliberately-scoped no_auth_user mapping; otherwise it is an "
                     "authentication gap."),
        severity="high" if is_system else None,
        detail=f"account={raw.get('name')} users_without_credential={naked}",
        source_ref={"config_key": f"accounts.{raw.get('name')}.users"},
    )]


# ── Versions ────────────────────────────────────────────────────────────────────
@detector(kinds=["nats_server"], rule_id="NATS.VERSION.JETSTREAM_AUTHZ_CVE", severity="high",
          title="NATS version is affected by the JetStream authorization-bypass CVE-2025-30215")
def jetstream_authz_cve(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("varz_readable"):
        return []
    version = raw.get("version")
    vulnerable = _js_authz_vulnerable(version)
    if vulnerable is False:
        return []
    if vulnerable is None:
        return [Hit(
            observation=(f"/varz reports version={version!r}; this scanner cannot map that string "
                         f"to a known JetStream-authz-patched release, so exposure to "
                         f"CVE-2025-30215 was not determined"),
            remediation=("Confirm the running version against the NATS advisory for CVE-2025-30215 "
                         "and run at least 2.10.27 or 2.11.1."),
            detail=f"version={version}",
            assessable=False,
            assessment_reason="version string not parseable to a known JetStream-authz series",
            source_ref={"api": "/varz", "field": "version", "cve": "CVE-2025-30215"},
        )]
    return [Hit(
        observation=(f"/varz reports version={version!r}, below the JetStream authorization-bypass "
                     f"fix for its series (CVE-2025-30215, CVSS 9.6). Four admin-level JetStream "
                     f"APIs in the $JS namespace lacked authorization checks, so any account with "
                     f"JetStream management permissions could act on assets in other accounts, "
                     f"including at least one data-destruction path"),
        remediation=("Upgrade to at least 2.10.27 (2.10.x) or 2.11.1 (2.11.x); there is no "
                     "configuration workaround. Also plan to reach 2.11.15 / 2.12.6, which fix the "
                     "later JetStream restore authorization issue CVE-2026-33222."),
        detail=f"version={version}",
        source_ref={"api": "/varz", "field": "version", "cve": "CVE-2025-30215"},
    )]


@detector(kinds=["nats_account"], rule_id="NATS.PERMISSION.EMPTY_LIST_UNRESTRICTED", severity="high",
          title="A NATS permission list that looks like a lock-down grants everything")
def empty_list_unrestricted(r, ctx) -> list:
    """`publish: []` or `{allow: []}` reads like "may publish nothing"; NATS treats it as "no
    list", which means the user may publish anywhere (docs.nats.io, Authorization). The common
    intent was to block, so this is reported as the trap it is."""
    hits = []
    acct = (r.raw or {}).get("name")
    for u in (r.raw or {}).get("users") or []:
        perms = u.get("permissions") or {}
        for direction in ("publish", "subscribe"):
            if direction not in perms:
                continue
            spec = perms[direction]
            empty = spec in ([], {}, None, "") or (isinstance(spec, dict) and not spec.get("allow")
                                                   and not spec.get("deny"))
            if not empty:
                continue
            hits.append(Hit(
                observation=f"NATS user '{acct}/{u.get('user')}' has `{direction}` set to an empty list "
                            f"({spec!r}); NATS treats an empty list as no list, so this user may "
                            f"{direction} on every subject in account '{acct}'",
                remediation=(f"To block all {direction}s, write `{direction}: {{ deny: [\">\"] }}`. To "
                             f"allow only some subjects, list them under `allow`."),
                source_ref={"account": acct, "user": u.get("user"), "direction": direction},
            ))
    return hits
