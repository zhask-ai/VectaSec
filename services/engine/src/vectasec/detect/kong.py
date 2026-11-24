"""Kong rulepack — every rule is a read-only inference over what connect/kong.py already fetched.

Two shared pieces carry most of the correctness here: the listener parser (`_listen_entries`) and
the plugin scope resolver (`_in_scope`). Both have failure modes that silently invert a verdict, so
they are written once and reused rather than re-derived per rule.

Four rules carry the third outcome, because for them an empty answer and an unread one are the
same shape on the wire and must not be the same verdict:
  • the two KONG.VERSION.* CVE rules — a version the comparator cannot place is reported
    assessable=False, never as "not vulnerable";
  • KONG.CONSUMER.NO_CREDENTIALS — a credential sweep that did not run, or one where no endpoint
    answered 200, is a coverage gap, not a consumer with credentials;
  • KONG.SCOPE.WORKSPACES_NOT_ENUMERATED — a refused /workspaces narrows collection to the default
    workspace, so every route/service/consumer/plugin rule silently covered one workspace.
"""
import ipaddress

from ..registry import detector
from ..contracts import Hit

# ── Plugin name sets ──────────────────────────────────────────────────────
AUTH_PLUGINS = {
    "key-auth", "key-auth-enc", "basic-auth", "hmac-auth", "jwt", "oauth2",
    "oauth2-introspection", "openid-connect", "ldap-auth", "ldap-auth-advanced",
    "mtls-auth", "header-cert-auth", "vault-auth", "saml",
}

# Only these are *verified* to carry config.anonymous. The Enterprise auth plugins are likely to and
# are deliberately excluded until each reference page is checked — a wrong entry here invents a
# finding on a plugin that has no such field.
ANON_CAPABLE = {"key-auth", "basic-auth", "jwt", "oauth2", "ldap-auth", "hmac-auth"}

RL_PLUGINS = {"rate-limiting", "rate-limiting-advanced", "response-ratelimiting",
              "graphql-rate-limiting-advanced", "ai-rate-limiting-advanced"}

EXTERNAL_IDENTITY = {"openid-connect", "ldap-auth-advanced"}

# HTTP auth / body-size plugins cannot run on stream routes at all, so a rule that ignores this fires
# on 100% of them. routes.lua makes the subsets mutually exclusive: {http,https} | {tcp,tls,udp} |
# {tls_passthrough} | {grpc,grpcs}. ws/wss are Enterprise-only and never appear on OSS.
L7_PROTOCOLS = {"http", "https", "grpc", "grpcs", "ws", "wss"}
PLAINTEXT_PROTOCOLS = {"http", "grpc", "ws"}

# Used only to answer "could this unknown plugin be doing auth?". Custom Lua and third-party plugins
# are first-class in Kong and widely used for auth, so an unrecognised name downgrades a finding to
# info rather than asserting it. An omission here therefore errs toward under-reporting, never toward
# a false FAIL — which is why the list not being exhaustive is tolerable.
BUNDLED_PLUGINS = {
    "acl", "acme", "ai-prompt-decorator", "ai-prompt-guard", "ai-prompt-template", "ai-proxy",
    "ai-rate-limiting-advanced", "ai-request-transformer", "ai-response-transformer",
    "application-registration", "aws-lambda", "azure-functions", "basic-auth", "bot-detection",
    "canary", "correlation-id", "cors", "datadog", "degraphql", "exit-transformer", "file-log",
    "forward-proxy", "graphql-proxy-cache-advanced", "graphql-rate-limiting-advanced",
    "grpc-gateway", "grpc-web", "header-cert-auth", "hmac-auth", "http-log", "ip-restriction",
    "jq", "jwt", "jwt-signer", "kafka-log", "kafka-upstream", "key-auth", "key-auth-enc",
    "konnect-application-auth", "ldap-auth", "ldap-auth-advanced", "loggly", "mocking",
    "mtls-auth", "oauth2", "oauth2-introspection", "opa", "openid-connect", "opentelemetry",
    "post-function", "pre-function", "prometheus", "proxy-cache", "proxy-cache-advanced",
    "rate-limiting", "rate-limiting-advanced", "request-size-limiting", "request-termination",
    "request-transformer", "request-transformer-advanced", "response-ratelimiting",
    "response-transformer", "response-transformer-advanced", "route-by-header",
    "route-transformer-advanced", "saml", "session", "standard-webhooks", "statsd",
    "statsd-advanced", "syslog", "tcp-log", "tls-handshake-modifier", "tls-metadata-headers",
    "udp-log", "upstream-timeout", "vault-auth", "websocket-size-limit", "websocket-validator",
    "xml-threat-protection", "zipkin",
}

_WILDCARD_HOSTS = {"0.0.0.0", "::", "*", "0.0.0.0/0"}
_ADMIN_LISTEN_DEFAULT = ("127.0.0.1:8001 reuseport backlog=16384, "
                         "127.0.0.1:8444 http2 ssl reuseport backlog=16384")

# Conservative literal set. Kong anchors origins regexes at both ends (cors/handler.lua appends '$'
# and matches with the 'a' = anchored-start flag), so '.*\\.example\\.com' is a correctly scoped
# config — a substring search for '.*' would fire on it. Only match-anything forms belong here.
_MATCH_ANYTHING = {".*", ".+", "^.*$", ".*$", "^.+$", "(.*)"}


# ── Listener parsing ──────────────────────────────────────────────────────
def _classify(host: str) -> str:
    h = (host or "").strip("[]").lower()
    if h in _WILDCARD_HOSTS:
        return "wildcard"
    if h == "localhost":                       # not an IP literal; ip_address() rejects it, and
        return "loopback"                      # unhandled it reads as non-loopback and FPs
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # admin_listen accepts hostnames. We do not resolve them, and a rule must never FAIL on a
        # host whose location it did not establish.
        return "unknown"
    if ip.is_loopback:                         # the whole of 127.0.0.0/8, plus ::1
        return "loopback"
    if ip.is_unspecified:
        return "wildcard"
    return "unicast"


def _split_hostport(addr: str):
    if addr.startswith("["):                   # [::1]:8444 — listeners.lua brackets IPv6, so a bare
        host, _, rest = addr[1:].partition("]")  # '::1' comparison misses every real IPv6 entry
        return host, rest.lstrip(":") or None
    if addr.count(":") > 1:                    # bare IPv6, no port
        return addr, None
    host, sep, port = addr.rpartition(":")
    return (host, port) if sep else (addr, None)


def _listen_entries(value) -> list:
    """Parse admin_listen / proxy_listen into {entry, host, port, flags, klass} records.

    Kong emits nginx listen directives: an address, then whitespace-separated flags
    ('0.0.0.0:8001 reuseport backlog=16384'). Tokenising on whitespace is mandatory — a substring
    test for 'ssl' matches any flag or path merely containing it and silently passes a plaintext
    listener. The literal entry `off` is dropped: it is valid and disables the Admin API outright,
    and a naive parser reads it as "no loopback host, no ssl flag" and fires every listener rule on a
    node that has no admin listener at all.
    """
    if value is None:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    out = []
    for item in items:
        item = (item or "").strip()
        if not item or item.lower() == "off":
            continue
        tokens = item.split()
        host, port = _split_hostport(tokens[0])
        out.append({"entry": item, "host": host, "port": port,
                    "flags": {t.split("=")[0].lower() for t in tokens[1:]},
                    "klass": _classify(host)})
    return out


# ── Node access ───────────────────────────────────────────────────────────
def _node(ctx):
    nodes = ctx.of_kind("broker")
    return nodes[0] if nodes else None


def _node_config(ctx) -> dict:
    n = _node(ctx)
    return (n.raw.get("configuration") or {}) if n else {}


def _admin_listen(ctx) -> list:
    return _listen_entries(_node_config(ctx).get("admin_listen"))


def _admin_non_loopback(ctx) -> list:
    return [e for e in _admin_listen(ctx) if e["klass"] in ("wildcard", "unicast")]


def _probes(ctx) -> dict:
    n = _node(ctx)
    return (n.raw.get("probes") or {}) if n else {}


def _root_answered_unauthenticated(root: dict) -> bool:
    """Did the anonymous `GET /` get the node-info object back?

    The tagline is matched case-insensitively on purpose: a live Kong 3.9.3 OSS node returns
    'Welcome to kong' (lowercase k), not the 'Welcome to Kong' every doc quotes. An exact-match
    comparison silently never fires KONG.ADMIN.UNAUTHENTICATED — a false negative on the one rule
    in this pack that finds full gateway takeover — and never escalates LISTEN_WILDCARD either.
    """
    return (root.get("status") == 200
            and (root.get("tagline") or "").strip().lower() == "welcome to kong")


# ── Plugin scope resolution (shared by 5 rules) ───────────────────────────
def _enabled(p: dict) -> bool:
    return p.get("enabled", True) is True      # plugins.lua: required, default true


def _protocols_match(p: dict, route: dict) -> bool:
    """Every plugin carries its own protocols array. An auth plugin scoped to ['grpc','grpcs']
    leaves an http route wide open, so omitting this intersection causes false PASSes."""
    pp = set(p.get("protocols") or [])
    if not pp:
        return True                            # field absent ⇒ don't manufacture a FAIL from it
    return bool(pp & set(route.get("protocols") or []))


def _in_scope(p: dict, route: dict, identity_scope: bool = False) -> bool:
    """Does plugin P execute on route R? Scope is nullable object refs on the plugin.

    GET /routes/{id}/plugins is a trap and is never used: it returns only plugins whose `route` field
    points at that route and omits the inherited service-scoped and global plugins that also run,
    so a detector built on it false-FAILs every route protected at a broader scope.
    """
    pr, ps = p.get("route"), p.get("service")
    pc, pg = p.get("consumer"), p.get("consumer_group")
    if (pc or pg) and not identity_scope:
        # Identity is unknown until auth completes, so auth plugins cannot meaningfully be
        # consumer-scoped. Rate limiting can and routinely is — hence the flag.
        return False
    if pr:
        # A plugin with *both* route and service set applies only to that route, so matching on
        # route.id alone is sufficient and correct here.
        return pr.get("id") == route.get("id")
    if ps:
        # `P.route == null` is load-bearing: without it a route+service-scoped plugin on route A is
        # wrongly credited to route B of the same service.
        rs = route.get("service") or {}
        return bool(rs.get("id")) and ps.get("id") == rs.get("id")
    return True                                # global, or consumer/consumer-group when allowed


def _plugins(ctx) -> list:
    return [r.raw for r in ctx.of_kind("plugin")]


def _resolves(ctx, route: dict, names: set, identity_scope: bool = False) -> list:
    return [p for p in _plugins(ctx)
            if p.get("name") in names and _enabled(p)
            and _in_scope(p, route, identity_scope) and _protocols_match(p, route)]


def _service_name(ctx, route: dict) -> str:
    sid = (route.get("service") or {}).get("id")
    if not sid:
        return "none (serviceless route)"
    for r in ctx.of_kind("service"):
        if r.raw.get("id") == sid:
            return f"'{r.name}' (id {sid})"
    return f"id {sid}"


def _extra(ctx, key: str) -> set:
    return {str(x).lower() for x in (ctx.config.get(key) or [])}


def _is_l7(route: dict) -> bool:
    return bool(set(route.get("protocols") or []) & L7_PROTOCOLS)


def _plugin_scope_str(p: dict) -> str:
    for field in ("route", "service", "consumer", "consumer_group"):
        if (ref := p.get(field)) and ref.get("id"):
            return f"{field} {ref['id']}"
    return "global (route, service and consumer all null)"


# ══ KONG.ADMIN.LISTEN_WILDCARD ════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KONG.ADMIN.LISTEN_WILDCARD", severity="high",
          title="Kong Admin API bound to a wildcard address")
def admin_listen_wildcard(resource, ctx):
    entries = _listen_entries((resource.raw.get("configuration") or {}).get("admin_listen"))
    if not entries:
        return []                              # absent, empty, or `off` — no admin interface to bind

    probes = resource.raw.get("probes") or {}
    origin = probes.get("origin", "unknown")
    root = probes.get("root") or {}
    unauth_200 = _root_answered_unauthenticated(root)

    wild = [e["entry"] for e in entries if e["klass"] == "wildcard"]
    unicast = [e["entry"] for e in entries if e["klass"] == "unicast"]
    observed = [e["entry"] for e in entries]

    if wild:
        # Kong's own guidance blesses non-loopback binding *plus* network restriction, so the bind
        # address alone cannot establish exposure. Only an independent unauthenticated 200 arriving
        # over a non-loopback path escalates this — the probe is what turns a config fact into
        # evidence of reachability.
        escalate = unauth_200 and origin == "remote"
        return [Hit(
            observation=(
                f"Admin API node info `GET /` reports .configuration.admin_listen = {observed!r}; "
                f"entries {wild!r} bind the Admin API to a wildcard address rather than the "
                f"documented default '{_ADMIN_LISTEN_DEFAULT}'. The bind address alone does not "
                f"establish network reachability — confirm the compensating control (firewall / "
                f"security group / published container ports / NetworkPolicy) before treating this "
                f"as exposure. Scanner reached this node over: {origin}; unauthenticated `GET /` "
                f"returned status {root.get('status')!r}."
            ),
            severity="critical" if escalate else "high",
            remediation=(
                "Set admin_listen to a loopback or tightly-scoped address (default "
                f"'{_ADMIN_LISTEN_DEFAULT}'); Kong's docs say to avoid values such as '0.0.0.0:8001' "
                "because it could compromise the security of the whole Kong cluster. If the Admin "
                "API must be reachable beyond the local interface, restrict network-layer access "
                "with an L3/L4 firewall or security group, or proxy it through a Kong Service "
                "protected by auth plugins."
            ),
            detail=("Docker (KONG_ADMIN_LISTEN=0.0.0.0:8001) and the Kong Helm chart "
                    "(kong.listen $defaultAddrs = 0.0.0.0, [::]) both default to a wildcard bind and "
                    "rely on port publication / NetworkPolicy instead — verify those before "
                    "escalating."),
            source_ref={"api": "GET /", "config_key": "admin_listen"},
        )]

    if unicast:
        return [Hit(
            observation=(
                f"Admin API node info `GET /` reports .configuration.admin_listen = {observed!r}; "
                f"entries {unicast!r} bind the Admin API to a specific non-loopback unicast address "
                f"rather than loopback. Scanner reached this node over: {origin}."
            ),
            severity="info",
            remediation=("Verify an L3/L4 ACL, RBAC, or mTLS restricts access to this address. "
                         "Kong's Secure-the-Admin-API guidance accepts a non-loopback bind when "
                         "network-layer access is restricted; loopback binding is only one of the "
                         "five listed mitigations."),
            source_ref={"api": "GET /", "config_key": "admin_listen"},
        )]
    return []


# ══ KONG.ADMIN.UNAUTHENTICATED ════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KONG.ADMIN.UNAUTHENTICATED", severity="high",
          title="Kong Admin API answers without credentials")
def admin_unauthenticated(resource, ctx):
    probes = resource.raw.get("probes") or {}
    root = probes.get("root") or {}
    rbac = probes.get("rbac_users") or {}
    origin = probes.get("origin", "unknown")
    edition = resource.raw.get("edition")

    root_open = _root_answered_unauthenticated(root)
    rbac_open = rbac.get("status") == 200
    if not (root_open or rbac_open):
        return []

    listen = _listen_entries((resource.raw.get("configuration") or {}).get("admin_listen"))
    non_loopback = [e["entry"] for e in listen if e["klass"] in ("wildcard", "unicast")]
    admin_listen_val = [e["entry"] for e in listen] or "off/absent"

    rbac_fact = {
        200: f"unauthenticated `GET /rbac/users` returned HTTP 200 with {rbac.get('count')} RBAC "
             f"user(s), so RBAC is not enforcing",
        404: "unauthenticated `GET /rbac/users` returned HTTP 404 (endpoint absent — OSS)",
    }.get(rbac.get("status"),
          f"unauthenticated `GET /rbac/users` returned HTTP {rbac.get('status')!r}")

    # Without this gate the rule fires critical on every default OSS install and the whole rulepack
    # gets muted. A 200 from `GET /` is the documented, only-possible OSS posture — it is a
    # reachability signal, not a defect on its own. What makes it a defect is the path it arrived on.
    if rbac_open or non_loopback or origin == "remote":
        severity = "critical" if (origin == "remote" or non_loopback) else "high"
    else:
        # Loopback probe, loopback-only bind: fires 100% of the time on OSS and there is no fix to
        # apply. Correctly ranked informational rather than noise at high.
        severity = "info"

    if edition == "enterprise":
        remediation = (
            "On a licensed Enterprise node set enforce_rbac=on and issue per-user Kong-Admin-Token "
            "values via POST /rbac/users. RBAC is license-gated (free mode was removed in 3.10), so "
            "on an unlicensed or expired-license node it cannot be enabled — there bind admin_listen "
            "to loopback, apply L3/L4 network controls, and front the Admin API with an "
            "authenticating proxy instead."
        )
    else:
        remediation = (
            "There is no in-gateway Admin API auth to enable on this edition — enforce_rbac does not "
            "exist in OSS. Bind admin_listen to loopback, restrict access with an L3/L4 firewall or "
            "security group, and front the Admin API with an authenticating proxy (or a Kong Service "
            "protected by auth plugins)."
        )

    return [Hit(
        observation=(
            f"Unauthenticated `GET /` to the Admin API returned HTTP {root.get('status')!r} with "
            f".tagline={root.get('tagline')!r}, .edition={root.get('edition')!r} and a sanitized "
            f".configuration object; no Kong-Admin-Token was required. Additionally, {rbac_fact}. "
            f"Probe originated from: {origin}; admin_listen = {admin_listen_val!r}."
        ),
        severity=severity,
        remediation=remediation,
        detail=("`GET /`.configuration is sanitized server-side (remove_sensitive() strips "
                "pg_password, ssl_cert_key, $refs), so this is not secret exposure. If the scanner "
                "was pointed at the backend of an authenticating proxy or mTLS ingress it bypassed "
                "that control and the 200 is a false positive — the recorded probe origin is what "
                "lets a triager tell the two apart. Konnect uses a different auth model entirely; "
                "this rule is scoped to self-managed nodes."),
        source_ref={"api": "GET / (unauthenticated), GET /rbac/users (unauthenticated)"},
    )]


# ══ KONG.RBAC.DISABLED ════════════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KONG.RBAC.DISABLED", severity="medium",
          title="Kong Enterprise Admin API RBAC not enforced")
def rbac_disabled(resource, ctx):
    cfg = resource.raw.get("configuration") or {}
    probes = resource.raw.get("probes") or {}

    # RBAC-on nodes never return the field to an unauthenticated caller; they 401 with a body
    # containing "Invalid RBAC credentials". Substring, not equality — some versions return the
    # longer "...Token or User credentials required".
    rbac_probe = probes.get("rbac_users") or {}
    if "Invalid RBAC credentials" in (rbac_probe.get("body_snippet") or ""):
        return []

    if "enforce_rbac" not in cfg:
        return []                              # OSS: kong_defaults.lua has no such key — N/A, never FAIL
    if cfg.get("database") == "off":
        return []                              # RBAC is unavailable DB-less; the remediation would be
                                               # impossible to follow, and DB-less is the K8s norm
    if cfg.get("role") == "data_plane":
        return []                              # DPs do not own Admin API config; RBAC is a CP concern
    if cfg.get("enforce_rbac") != "off":
        return []                              # enum is on|off|entity|both — 'admin' is not valid

    non_loopback = [e["entry"] for e in _listen_entries(cfg.get("admin_listen"))
                    if e["klass"] in ("wildcard", "unicast")]
    listen_val = [e["entry"] for e in _listen_entries(cfg.get("admin_listen"))] or "off/absent"
    header = cfg.get("rbac_auth_header") or "Kong-Admin-Token"

    return [Hit(
        observation=(
            f"Admin API `GET /` reports .configuration.enforce_rbac = 'off' on Kong "
            f"{resource.raw.get('edition')!r} version {resource.raw.get('version')!r} "
            f"(database = {cfg.get('database')!r}, role = {cfg.get('role')!r}), so Kong enforces no "
            f"RBAC authn/authz on Admin API requests. admin_listen = {listen_val!r} — the Admin API "
            f"may still be protected by loopback-only binding, mTLS, or a fronting auth proxy."
        ),
        # A loopback-bound RBAC-off node is a hardening gap, not an exposure.
        severity="high" if non_loopback else "medium",
        remediation=(
            f"Set enforce_rbac=on in kong.conf (or KONG_ENFORCE_RBAC=on) and reload. Create a super "
            f"admin via POST /rbac/users with a user_token, then send that token on Admin API "
            f"requests using the header this node reports as .configuration.rbac_auth_header "
            f"('{header}'). Verify by confirming an unauthenticated request returns a body "
            f"containing 'Invalid RBAC credentials'."
        ),
        detail=("Read the header name from GET / rather than hardcoding it: Kong-Admin-Token is the "
                "default, not a constant. Note enforce_rbac (not enable_rbac) is the real parameter."),
        source_ref={"api": "GET /", "config_key": "enforce_rbac"},
    )]


# ══ KONG.ADMIN.PLAINTEXT_LISTENER ═════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KONG.ADMIN.PLAINTEXT_LISTENER", severity="high",
          title="Kong Admin API listener without TLS on a non-loopback address")
def admin_plaintext_listener(resource, ctx):
    cfg = resource.raw.get("configuration") or {}
    # admin_ssl_enabled is deliberately not used as a substitute: it is true if *any* listener has
    # ssl, so it cannot see a mixed plaintext+TLS config.
    bad = [e for e in _listen_entries(cfg.get("admin_listen"))
           if e["klass"] in ("wildcard", "unicast") and "ssl" not in e["flags"]]
    if not bad:
        return []

    edition = resource.raw.get("edition")
    # The Enterprise wording ("tokens traverse the network in plaintext") is factually wrong on a
    # community node, where no token exists and the actual risk is worse — branch on .edition.
    if edition == "enterprise":
        impact = "Kong-Admin-Token RBAC credentials are sent in cleartext on this listener"
    else:
        impact = ("no Admin API token exists on this edition at all and full gateway control is "
                  "served over plaintext HTTP without authentication")

    probes = resource.raw.get("probes") or {}
    corroboration = ""
    if probes.get("origin") == "remote" and str(ctx.config.get("url", "")).startswith("http://"):
        corroboration = (" The scanner itself reached `GET /` over plaintext HTTP from a "
                         "non-loopback path, directly corroborating this.")

    return [Hit(
        observation=(
            f"Admin API listener(s) {[e['entry'] for e in bad]!r} bind a non-loopback address with "
            f"no `ssl` flag in the entry's whitespace-tokenized flag list "
            f"(flags seen: {[sorted(e['flags']) for e in bad]!r}); .edition = {edition!r}, so "
            f"{impact}.{corroboration}"
        ),
        remediation=(
            "Restrict the Admin API to 127.0.0.1, firewall it, or drop the plaintext 8001 listener "
            "entirely. Only where off-host admin access is genuinely required, add the `ssl` flag "
            "(the default TLS listener is '127.0.0.1:8444 http2 ssl'). This ordering is deliberate: "
            "Kong's Secure-the-Admin-API page leads with network-layer restriction and does not "
            "recommend enabling ssl on the admin listener anywhere."
        ),
        detail=("Suppress if a service-mesh sidecar (Istio/Linkerd) terminates mTLS in front of this "
                "listener, or if a host firewall / unpublished container port makes it unreachable — "
                "neither is observable from the Admin API. Note this rule passes "
                "'0.0.0.0:8444 http2 ssl', an Admin API exposed to the whole network but encrypted; "
                "KONG.ADMIN.OFF_HOST_LISTENER would be the companion rule for that gap."),
        source_ref={"api": "GET /", "config_key": "admin_listen"},
    )]


# ══ KONG.SCOPE.WORKSPACES_NOT_ENUMERATED ══════════════════════════════════
@detector(kinds=["broker"], rule_id="KONG.SCOPE.WORKSPACES_NOT_ENUMERATED", severity="medium",
          title="Kong workspace list was refused, so the scan covered one workspace only")
def workspaces_not_enumerated(resource, ctx):
    """The third honest outcome at node scope: this scan's reach was narrower than it looks.

    Every route / service / consumer / plugin rule in this pack judges what the connector
    collected, and on Enterprise the connector collects per workspace. A 403 on /workspaces leaves
    it walking the default workspace alone, so the routes in every other workspace are not clean —
    they were never fetched, and KONG.ROUTE.NO_AUTH_PLUGIN never ran on one of them. raw.workspaces
    is [""] whether that happened or the node is plain OSS, which is why the enumeration outcome is
    recorded separately and read here.
    """
    rec = resource.raw.get("workspace_enumeration") or {}
    if rec.get("readable") is not False:
        return []                              # True = enumerated; None = OSS, no workspace layer

    counted = ", ".join(f"{len(ctx.of_kind(k))} {k}(s)"
                        for k in ("route", "service", "consumer", "plugin"))
    err = rec.get("error") or f"HTTP {rec.get('status')!r}"
    return [Hit(
        observation=(
            f"`GET /workspaces` on this Kong Enterprise node returned {err}, so the workspace list "
            f"could not be enumerated and collection fell back to the default workspace alone. "
            f"Everything this scan holds for the node — {counted} — came from that one workspace; "
            f"a route, service, consumer or plugin in any other workspace was never fetched, and "
            f"no rule in this pack was run against it."
        ),
        remediation=(
            "Grant the Admin API token's RBAC role read access to the workspaces endpoint and "
            "re-scan, or add one connection per workspace so each is collected under its own "
            "credential. Until then this node's coverage is one workspace, not the gateway."
        ),
        detail=("Kong Enterprise scopes /routes, /services, /consumers and /plugins per workspace. "
                "raw.workspaces reads [''] both for an OSS node and for an Enterprise node whose "
                "workspace list was refused — only the enumeration outcome separates them."),
        assessable=False,
        assessment_reason=("the workspace list was refused, so every route, service, consumer and "
                           "plugin rule covered the default workspace only"),
        source_ref={"api": "GET /workspaces", "status": rec.get("status")},
    )]


# ══ KONG.ROUTE.NO_AUTH_PLUGIN ═════════════════════════════════════════════
@detector(kinds=["route"], rule_id="KONG.ROUTE.NO_AUTH_PLUGIN", severity="high",
          title="Kong route has no authentication plugin in effect")
def route_no_auth_plugin(resource, ctx):
    route = resource.raw
    if not _is_l7(route):
        # HTTP auth plugins do not support tcp/tls/udp, so the protocol-intersection clause can never
        # be satisfied and the rule would fire on 100% of stream routes. TLS-layer controls (snis,
        # cert config) govern these, not auth plugins.
        return []

    auth = AUTH_PLUGINS | _extra(ctx, "extra_auth_plugins")
    candidates = _resolves(ctx, route, auth)

    # An auth plugin whose config.anonymous is set does not protect anything: authentication failure
    # falls through to the anonymous consumer instead of 4xx. Reported by KONG.AUTH.ANONYMOUS_FALLBACK.
    protecting = [p for p in candidates if not (p.get("config") or {}).get("anonymous")]
    if protecting:
        return []

    protos = route.get("protocols") or []
    known = BUNDLED_PLUGINS | auth
    unknown = sorted({p.get("name") for p in _plugins(ctx)
                      if _enabled(p) and _in_scope(p, route) and p.get("name") not in known})

    anon_fallthrough = [f"{p.get('name')} (id {p.get('id')}, "
                        f"config.anonymous={(p.get('config') or {}).get('anonymous')!r})"
                        for p in candidates]

    if anon_fallthrough:
        extra = (f" An enabled auth plugin does resolve to this route — {anon_fallthrough!r} — but "
                 f"its config.anonymous is set, so requests failing authentication are proxied as "
                 f"the anonymous consumer rather than rejected.")
    elif unknown:
        extra = (f" Enabled plugins {unknown!r} resolve to this route and are not recognised as "
                 f"Kong-bundled plugins; a custom or third-party plugin may be performing "
                 f"authentication, which this rule cannot confirm.")
    else:
        extra = ""

    return [Hit(
        observation=(
            f"Route '{resource.name}' (id {route.get('id')}) on service {_service_name(ctx, route)}, "
            f"protocols={protos!r}, has no enabled authentication plugin at route, service, or "
            f"global scope: fully-paginated /plugins contains no entry from {sorted(auth)!r} with "
            f"route.id={route.get('id')}, service.id={(route.get('service') or {}).get('id')}, or "
            f"(route=null AND service=null) whose protocols intersect {protos!r} and whose "
            f"config.anonymous is null.{extra}"
        ),
        # An unknown plugin could be doing auth; asserting a finding over it is a guess.
        severity="info" if unknown and not anon_fallthrough else "high",
        remediation=(
            "Attach an authentication plugin at route or service scope, e.g. POST "
            f"/routes/{route.get('id')}/plugins with name=key-auth (or jwt / oauth2 / "
            "openid-connect). Prefer service scope for uniform coverage. Ensure the plugin's "
            "protocols overlap the route's, that enabled=true, and that config.anonymous is null."
        ),
        detail=("This rule cannot establish upstream sensitivity or exploitability. Intentionally "
                "public endpoints (/health, /login, /token, OIDC callbacks, webhooks, static "
                "assets), auth enforced at the upstream service, and custom auth plugins all look "
                "identical from here — triage before acting. Escalate only with corroboration: the "
                "route fronts a service flagged sensitive, or no ip-restriction / rate-limiting / "
                "request-termination is present either."),
        source_ref={"api": "GET /routes, GET /plugins (paginated)"},
    )]


# ══ KONG.AUTH.ANONYMOUS_FALLBACK ══════════════════════════════════════════
def _resolve_anon_consumer(ctx, ref: str):
    for r in ctx.of_kind("consumer"):
        if r.raw.get("id") == ref or r.raw.get("username") == ref:
            return r
    return None


@detector(kinds=["plugin"], rule_id="KONG.AUTH.ANONYMOUS_FALLBACK", severity="high",
          title="Kong auth plugin falls through to an anonymous consumer")
def auth_anonymous_fallback(resource, ctx):
    p = resource.raw
    if p.get("name") not in ANON_CAPABLE or not _enabled(p):
        return []
    anon = (p.get("config") or {}).get("anonymous")
    if not anon:
        # `""` is deliberately not reported here. Since Kong 2.0 an empty string raises "failed to
        # load anonymous consumer" at runtime rather than falling through, so the fallthrough impact
        # is factually wrong for that value — it is a broken-config finding the rulepack does not
        # assign a rule id to.
        return []

    consumer = _resolve_anon_consumer(ctx, anon)     # config.anonymous accepts an id OR a username
    if consumer is None:
        return [Hit(
            observation=(
                f"Plugin {p.get('name')} (id {p.get('id')}) scoped to {_plugin_scope_str(p)} has "
                f"config.anonymous={anon!r}, but fully-paginated /consumers contains no consumer "
                f"whose .id or .username equals {anon!r}."
            ),
            severity="medium",
            remediation=("Set config.anonymous to null so failed authentication returns 401, or "
                         "point it at a consumer that exists."),
            source_ref={"api": "GET /plugins, GET /consumers", "config_key": "config.anonymous"},
        )]

    anon_id = consumer.raw.get("id")
    groups = ((consumer.raw.get("credentials") or {}).get("acls") or {}).get("groups")
    others = [q for q in _plugins(ctx) if _enabled(q)]

    # Mitigation 1 (primary): Kong's canonical deny-anonymous pattern scopes request-termination to
    # the *anonymous consumer* — consumer=<anon-id>, service=null, route=null. An exception phrased
    # as "same-or-narrower scope for the same route/service" does not match it, and would FAIL the
    # exact config Kong documents as correct.
    terminated = [q for q in others
                  if q.get("name") == "request-termination"
                  and (q.get("consumer") or {}).get("id") == anon_id]
    if terminated:
        return []

    # Mitigation 2: ACL, allow OR deny. config.allow and config.deny are mutually exclusive arrays of
    # group names. A deny listing the anonymous consumer's groups is the documented pattern; an allow
    # only mitigates if the anonymous consumer's groups are DISJOINT from it — accepting a non-empty
    # allow blindly passes a config that mitigates nothing.
    acl_note = "no acl plugin excludes it"
    if groups is not None:
        gset = set(groups)
        for q in others:
            if q.get("name") != "acl":
                continue
            c = q.get("config") or {}
            deny, allow = set(c.get("deny") or []), set(c.get("allow") or [])
            if deny and gset & deny:
                return []
            if allow and not (gset & allow):
                return []
        acl_note = (f"its ACL groups {sorted(groups)!r} are not denied by any acl plugin's "
                    f"config.deny, nor excluded by any acl plugin's config.allow")
    else:
        acl_note = ("its ACL groups were not enumerated by this scan, so an acl-based mitigation "
                    "could not be checked")

    # An anonymous consumer carrying restrictive plugins is a mixed-auth design under a control, not
    # an open door — the scanner cannot know upstream intent, so downgrade rather than assert.
    restrictive = sorted({q.get("name") for q in others
                          if (q.get("consumer") or {}).get("id") == anon_id
                          and q.get("name") in (RL_PLUGINS | {"ip-restriction", "bot-detection",
                                                              "request-size-limiting"})})

    return [Hit(
        observation=(
            f"Plugin {p.get('name')} (id {p.get('id')}) scoped to {_plugin_scope_str(p)} has "
            f"config.anonymous={anon!r}; consumer '{consumer.name}' (id {anon_id}) has no enabled "
            f"consumer-scoped request-termination plugin and {acl_note}, so requests failing "
            f"{p.get('name')} validation are proxied upstream as '{consumer.name}'."
            + (f" That consumer does carry restrictive plugin(s) {restrictive!r}."
               if restrictive else "")
        ),
        severity="medium" if restrictive else "high",
        remediation=(
            "Set config.anonymous to null so failed authentication returns 401. If an anonymous "
            f"consumer is intentional, attach request-termination to consumer {anon_id} (Kong's "
            "documented multi-auth pattern), or pair it with an acl plugin whose config.allow "
            "excludes that consumer's groups — or whose config.deny includes them."
        ),
        detail=("config.anonymous is a supported design for intentionally public or mixed-auth "
                "services (identify the caller if credentialed, else anonymous). Confirm intent "
                "before acting: this scanner cannot see upstream expectations."),
        source_ref={"api": "GET /plugins, GET /consumers, GET /consumers/{id}/acls",
                    "config_key": "config.anonymous"},
    )]


# ══ KONG.ROUTE.HTTP_PROTOCOL_ALLOWED ══════════════════════════════════════
@detector(kinds=["route"], rule_id="KONG.ROUTE.HTTP_PROTOCOL_ALLOWED", severity="low",
          title="Kong route accepts plaintext protocols")
def route_http_protocol_allowed(resource, ctx):
    route = resource.raw
    protos = set(route.get("protocols") or [])
    plaintext = sorted(protos & PLAINTEXT_PROTOCOLS)
    if not plaintext:
        return []

    cfg = _node_config(ctx)
    proxy = _listen_entries(cfg.get("proxy_listen"))
    plain_listeners = [e["entry"] for e in proxy if "ssl" not in e["flags"]]
    trusted_ips = cfg.get("trusted_ips")

    return [Hit(
        observation=(
            f"Route '{resource.name}' (id {route.get('id')}) has protocols={sorted(protos)!r}, so "
            f"Kong serves this route over plaintext {plaintext!r} rather than redirecting or "
            f"rejecting cleartext requests (https_redirect_status_code="
            f"{route.get('https_redirect_status_code')!r} applies only when the route is "
            f"https-only). Plaintext proxy listener present: "
            f"{'yes — ' + repr(plain_listeners) if plain_listeners else 'no'} "
            f"(proxy_listen = {[e['entry'] for e in proxy]!r}). trusted_ips = {trusted_ips!r}."
        ),
        # Without a plaintext proxy listener the `http` protocol cannot be exercised at all — the
        # finding is inert, and firing it at low would be asserting a risk that does not exist.
        severity="low" if plain_listeners else "info",
        remediation=(
            f"PATCH /routes/{route.get('id')} with protocols=['https'] (or grpcs / wss as "
            "applicable); set https_redirect_status_code=301 if a browser-friendly redirect is "
            "wanted instead of the 426 default. WARNING: if TLS is terminated upstream of Kong, set "
            "trusted_ips to the LB/proxy CIDRs FIRST — Kong honors X-Forwarded-* only from trusted "
            "IPs, so protocols=['https'] would otherwise make Kong treat LB-forwarded HTTPS as "
            "plaintext and redirect all traffic, including already-HTTPS requests, into a loop. Do "
            "not apply the redirect framing to gRPC: clients do not follow HTTP redirects, so "
            "grpc -> grpcs is a client-breaking change."
        ),
        detail=("[http, https] was the shipped default for every Kong release before 3.14, so on a "
                "pre-3.14 install this is a global posture observation, not a per-route finding. "
                "Suppress where TLS is terminated upstream by an ALB/CloudFront/ingress/mesh "
                "sidecar (the dominant topology), for ACME HTTP-01 challenge routes, for "
                "health-check routes on internal plaintext listeners, and for purely internal "
                "east-west instances."),
        source_ref={"api": "GET /routes, GET /", "config_key": "protocols"},
    )]


# ══ KONG.ROUTE.NO_RATE_LIMITING ═══════════════════════════════════════════
@detector(kinds=["route"], rule_id="KONG.ROUTE.NO_RATE_LIMITING", severity="medium",
          title="Kong route has no rate limiting in effect")
def route_no_rate_limiting(resource, ctx):
    route = resource.raw
    rl = RL_PLUGINS | _extra(ctx, "extra_rate_limit_plugins")
    # identity_scope=True is the primary FP control: rate-limiting's config.limit_by defaults to
    # `consumer`, and per-consumer / consumer-group tiered limiting (service=null, route=null,
    # consumer set) is a pattern Kong's own docs promote. A global/service/route-only resolver emits
    # a FAIL on routes that are in fact fully limited.
    if _resolves(ctx, route, rl, identity_scope=True):
        return []

    protos = route.get("protocols") or []
    return [Hit(
        observation=(
            f"Route '{resource.name}' (id {route.get('id')}) on service {_service_name(ctx, route)} "
            f"resolves to no enabled plugin in {sorted(rl)!r} at route, service, global, consumer, "
            f"or consumer-group scope with a protocol matching the route's protocols={protos!r}."
        ),
        severity="medium" if _is_l7(route) else "info",   # ranking hint, not a filter
        remediation=(
            "Attach rate-limiting at service or route scope with at least one of config.second / "
            "minute / hour set, OR rate-limiting-advanced with matching config.limit and "
            "config.window_size arrays — rate-limiting-advanced has no second/minute/hour fields and "
            "no config.policy. For multi-node deployments set rate-limiting's config.policy (or "
            "rate-limiting-advanced's config.strategy) to redis or cluster rather than the `local` "
            "default, so counters are shared across nodes."
        ),
        detail=("Residual and accepted: rate limiting enforced upstream of Kong (CDN/WAF/nginx) is "
                "invisible to the Admin API, as are custom or third-party RL plugins with "
                "non-matching names — extend the set via connection config `extra_rate_limit_plugins`."),
        source_ref={"api": "GET /routes, GET /plugins (paginated)"},
    )]


# ══ KONG.RATELIMIT.FAIL_OPEN ══════════════════════════════════════════════
@detector(kinds=["plugin"], rule_id="KONG.RATELIMIT.FAIL_OPEN", severity="low",
          title="Kong rate-limiting fails open on a datastore outage")
def ratelimit_fail_open(resource, ctx):
    p = resource.raw
    # rate-limiting-advanced is deliberately out of scope: it has no fault_tolerant parameter, its
    # datastore selector is config.strategy not config.policy, and it does not fail open (on a Redis
    # outage it falls back to `local` limiting — it still limits, it just cannot sync counters).
    if p.get("name") != "rate-limiting" or not _enabled(p):
        return []
    cfg = p.get("config") or {}
    policy = cfg.get("policy")
    if policy not in ("redis", "cluster") or cfg.get("fault_tolerant") is not True:
        return []

    # A second rate-limiting plugin with policy='local' on the same scope keeps limiting when the
    # shared datastore is gone — the bypass never materialises.
    scope = (((p.get("route") or {}).get("id")), ((p.get("service") or {}).get("id")))
    for q in _plugins(ctx):
        if (q.get("name") == "rate-limiting" and q.get("id") != p.get("id") and _enabled(q)
                and (q.get("config") or {}).get("policy") == "local"
                and (((q.get("route") or {}).get("id")), ((q.get("service") or {}).get("id"))) == scope):
            return []

    store = "Redis" if policy == "redis" else "Kong's own datastore (cluster policy)"
    return [Hit(
        observation=(
            f"Plugin rate-limiting (id {p.get('id')}) scoped to {_plugin_scope_str(p)} has "
            f"config.policy={policy!r} and config.fault_tolerant=true, so a {store} outage causes "
            f"rate limits to be bypassed rather than enforced (handler.lua logs the error and "
            f"continues without the limit check). GET /plugins returns schema defaults materialised, "
            f"so this rule cannot distinguish a deliberate operator choice from an untouched default "
            f"— fault_tolerant defaults to true."
        ),
        # policy='cluster' is lower signal still: the counter store is Kong's own Postgres, so if it
        # is down the control plane is already degraded and the bypass is largely moot.
        severity="info" if policy == "cluster" else "low",
        remediation=(
            "If this limiter is a security control (abuse / brute-force / DoS defence), consider "
            "config.fault_tolerant=false, accepting that a datastore outage will return HTTP 500 for "
            "ALL traffic on this route/service for its duration — fault_tolerant=false does not "
            "produce a 429. If it is a quota, cost-control, or fairness limiter, the default "
            "fault_tolerant=true is correct and this finding should be dismissed."
        ),
        detail=("Arguably posture rather than a finding: this is the vendor default, it is not a "
                "standing bypass (it requires a concurrent datastore outage to manifest), and "
                "rate-limit bypass is not auth bypass. Suppress where a compensating control exists "
                "— upstream/CDN limiting recorded out-of-band, for instance."),
        source_ref={"api": "GET /plugins (paginated)",
                    "config_key": "config.policy, config.fault_tolerant"},
    )]


# ══ KONG.CORS.WILDCARD_WITH_CREDENTIALS ═══════════════════════════════════
@detector(kinds=["plugin"], rule_id="KONG.CORS.WILDCARD_WITH_CREDENTIALS", severity="high",
          title="Kong CORS allows any origin with credentials")
def cors_wildcard_with_credentials(resource, ctx):
    p = resource.raw
    if p.get("name") != "cors" or not _enabled(p):
        return []
    cfg = p.get("config") or {}
    if cfg.get("credentials") is not True:                # default false
        return []

    origins = cfg.get("origins")
    if origins is None:
        reason = "config.origins is null"
    elif not origins:
        # handler.lua computes n_origins = conf.origins ~= nil and #conf.origins or 0, then allow-alls
        # on n_origins == 0 — an empty array is identical to unset and must fire.
        reason = "config.origins is an empty array []"
    elif "*" in origins:
        # '*' anywhere in a multi-entry array returns allow_all, not only as a lone value.
        reason = f"config.origins={origins!r} contains the literal '*'"
    elif any(o in _MATCH_ANYTHING for o in origins):
        reason = (f"config.origins={origins!r} contains a match-anything regex "
                  f"{[o for o in origins if o in _MATCH_ANYTHING]!r}")
    else:
        loose = [o for o in origins if isinstance(o, str) and ".*" in o]
        if not loose:
            return []
        return [Hit(
            observation=(
                f"Plugin cors (id {p.get('id')}) scoped to {_plugin_scope_str(p)} has "
                f"config.credentials=true and config.origins={origins!r}, of which {loose!r} contain "
                f"'.*'. Kong anchors origins regexes at both ends (handler.lua appends '$' if absent, "
                f"strips a leading '^', and matches with the 'a' anchored-start flag), so these may "
                f"be correctly scoped — this scanner did not evaluate what they match."
            ),
            severity="info",
            remediation=("Confirm each regex in config.origins cannot match an arbitrary origin "
                         "while config.credentials=true."),
            source_ref={"api": "GET /plugins (paginated)",
                        "config_key": "config.origins, config.credentials"},
        )]

    return [Hit(
        observation=(
            f"Plugin cors (id {p.get('id')}) scoped to {_plugin_scope_str(p)} has "
            f"config.credentials=true and {reason}, permitting any site to issue credentialed "
            f"cross-origin requests and read the responses. Kong does not emit the literal '*' here: "
            f"configure_credentials() (kong/plugins/cors/handler.lua) detects that "
            f"Access-Control-Allow-Credentials cannot be true alongside Access-Control-Allow-Origin: "
            f"'*' and substitutes the caller's request Origin verbatim, setting "
            f"Access-Control-Allow-Origin: <attacker-origin> with Access-Control-Allow-Credentials: "
            f"true. The wildcard is reflected, not blocked."
        ),
        remediation=(
            "Enumerate exact trusted origins in config.origins (e.g. ['https://app.example.com']) "
            "whenever config.credentials=true. If a wildcard origin is genuinely required, set "
            "config.credentials=false. Never leave config.origins unset or empty on a credentialed "
            "CORS config — both mean 'allow all origins'."
        ),
        detail=("Triage hint, not a suppression: CORS is browser-enforced, so impact is nil where "
                "the listener is not browser-reachable (east-west / service-mesh traffic) or where "
                "auth is Bearer-token-only in an Authorization header, which `credentials: include` "
                "does not auto-attach."),
        source_ref={"api": "GET /plugins (paginated)",
                    "config_key": "config.origins, config.credentials"},
    )]


# ══ KONG.ROUTE.WILDCARD_HOST_OR_PRESERVE_HOST ═════════════════════════════
def _is_wildcard_host(h: str) -> bool:
    # typedefs.lua: the wildcard must be the leftmost or rightmost character, at most one label.
    return isinstance(h, str) and (h.startswith("*.") or h.endswith(".*"))


@detector(kinds=["route"], rule_id="KONG.ROUTE.WILDCARD_HOST_OR_PRESERVE_HOST", severity="low",
          title="Kong route forwards an unconstrained client Host upstream")
def route_wildcard_host_preserve_host(resource, ctx):
    route = resource.raw
    # Fire only on the conjunction. Each limb alone is noise: `hosts=null` is the canonical path-only
    # route that KIC and decK generate, and preserve_host=true with an explicit non-wildcard hosts
    # allowlist forwards a Host constrained to that allowlist — not attacker-arbitrary.
    if route.get("preserve_host") is not True:
        return []

    hosts = route.get("hosts")
    wildcards = [h for h in (hosts or []) if _is_wildcard_host(h)]
    if hosts and not wildcards:
        return []

    expression = route.get("expression")
    if not hosts and expression and "http.host" in str(expression):
        # routes.lua's validate_route rejects `expression` together with hosts/paths/methods/…, so
        # EVERY expressions-flavor route reports hosts=null over the Admin API while potentially
        # pinning the Host inside the expression. Unhandled, that is a false positive on all of them.
        return []

    if wildcards:
        host_fact = f"hosts={hosts!r}, of which {wildcards!r} contain a wildcard"
    else:
        host_fact = (f"hosts={hosts!r} (matches any Host header, and carries no http.host constraint "
                     f"in .expression={expression!r})")

    return [Hit(
        observation=(
            f"Route '{resource.name}' (id {route.get('id')}) has {host_fact} and "
            f"preserve_host=true, so arbitrary client-supplied Host values are forwarded to the "
            f"upstream service. Kong's routers apply preserve_host unconditionally with no check on "
            f"how the route matched (router/atc.lua: `upstream_host = matched_route.preserve_host "
            f"and req_host or nil`; router/traditional.lua: `if matched_route.preserve_host then "
            f"upstream_host = ctx.raw_req_host end`), despite the docs implying it applies only when "
            f"matching via a hosts domain name."
        ),
        remediation=(
            "Leave preserve_host at its default false unless the upstream genuinely requires the "
            "original Host. If preserve_host must be true, constrain the route with an explicit "
            "non-wildcard .hosts allowlist (or an http.host expression) so the forwarded Host cannot "
            "be attacker-controlled."
        ),
        detail=("Impact is entirely upstream-dependent — Kong itself is not compromised. Host-header "
                "injection, cache poisoning, and reset-link poisoning only bite if the upstream "
                "trusts the Host header. preserve_host=true is legitimately required by upstreams "
                "that build absolute URLs, OAuth redirects, or multi-tenant vhosts."),
        source_ref={"api": "GET /routes", "config_key": "preserve_host, hosts"},
    )]


# ══ KONG.ROUTE.NO_REQUEST_SIZE_LIMIT ══════════════════════════════════════
@detector(kinds=["route"], rule_id="KONG.ROUTE.NO_REQUEST_SIZE_LIMIT", severity="low",
          title="Kong route has no request size limit in effect")
def route_no_request_size_limit(resource, ctx):
    route = resource.raw
    if not _is_l7(route):
        return []                              # an HTTP-layer plugin cannot govern a stream route

    names = {"request-size-limiting"} | _extra(ctx, "extra_size_limit_plugins")
    if _resolves(ctx, route, names, identity_scope=True):
        return []

    nginx_cap = _node_config(ctx).get("nginx_http_client_max_body_size")
    # kong.conf.default ships this at 0 and documents "Setting this value to 0 disables checking the
    # request body size" — so an unset nginx cap is not a bound, it is the absence of one. When it IS
    # set, body size is already capped at the nginx layer and the plugin is largely redundant.
    capped = nginx_cap not in (None, 0, "0")

    return [Hit(
        observation=(
            f"Route '{resource.name}' (id {route.get('id')}) on service {_service_name(ctx, route)} "
            f"resolves to no enabled plugin in {sorted(names)!r} at route, service, global, "
            f"consumer, or consumer-group scope, and .configuration."
            f"nginx_http_client_max_body_size = {nginx_cap!r}"
            + (", so request bodies are capped at the nginx layer and this plugin is largely "
               "redundant." if capped else
               " (its default, 0, disables body-size checking entirely), so request bodies are "
               "effectively unbounded.")
        ),
        severity="info" if capped else "low",
        remediation=(
            "Attach request-size-limiting at service or route scope with config.allowed_payload_size "
            "and config.size_unit set to the smallest workable value (default is 128 megabytes). "
            "Optionally set config.require_content_length=true to reject bodies lacking a valid "
            "Content-Length header with a 411 before the body is read."
        ),
        detail=("DoS-resilience hardening, not a vulnerability, and it fires on the majority of "
                "routes in a typical deployment. Suppress for upload/media/backup APIs that "
                "legitimately accept large bodies, where an upstream CDN/ingress/LB already caps "
                "body size (invisible from here), and where a custom or WAF plugin enforces the "
                "equivalent — extend the matched set via connection config `extra_size_limit_plugins`."),
        source_ref={"api": "GET /routes, GET /plugins (paginated), GET /",
                    "config_key": "nginx_http_client_max_body_size"},
    )]


# ══ KONG.PLUGIN.SECURITY_PLUGIN_DISABLED ══════════════════════════════════
_DISABLED_TIERS = (
    ("access control", "medium", AUTH_PLUGINS | {"acl"}),
    ("network", "medium", {"ip-restriction", "bot-detection"}),
    ("availability", "low", {"rate-limiting", "rate-limiting-advanced", "request-size-limiting"}),
)


def _covers_same_traffic(other: dict, p: dict) -> bool:
    if other.get("id") == p.get("id") or not _enabled(other):
        return False
    if other.get("name") != p.get("name"):
        return False
    if not any(other.get(f) for f in ("route", "service", "consumer", "consumer_group")):
        return True                            # an enabled global instance covers everything
    for field in ("route", "service", "consumer"):
        a, b = other.get(field) or {}, p.get(field) or {}
        if a.get("id") and a.get("id") == b.get("id"):
            return True
    return False


@detector(kinds=["plugin"], rule_id="KONG.PLUGIN.SECURITY_PLUGIN_DISABLED", severity="medium",
          title="Kong security plugin present but disabled")
def plugin_security_disabled(resource, ctx):
    p = resource.raw
    # `cors` is deliberately absent from every tier. The CORS plugin RELAXES the browser same-origin
    # policy to permit cross-origin requests; it does not restrict access. Disabling it makes the
    # browser MORE restrictive, so flagging it would invert the security model.
    if p.get("enabled") is not False:
        return []

    name = p.get("name")
    extra_auth = _extra(ctx, "extra_auth_plugins")
    for label, severity, names in _DISABLED_TIERS:
        if name in (names | extra_auth if label == "access control" else names):
            break
    else:
        return []

    # Do not assert the traffic is unprotected: whether a disabled narrow-scope instance suppresses a
    # broader enabled one or falls through to it is unverified. "Another enabled instance of the same
    # name covers this traffic" is the safe formulation and the safe suppression.
    if any(_covers_same_traffic(q, p) for q in _plugins(ctx)):
        return []

    return [Hit(
        observation=(
            f"Plugin {name} (id {p.get('id')}) scoped to {_plugin_scope_str(p)} has enabled=false, "
            f"so this plugin instance is present in the config and visible in Kong Manager but is "
            f"not executed by Kong. Fully-paginated /plugins contains no other enabled {name} "
            f"instance at global scope or at the same route/service/consumer scope. "
            f"Tier: {label}."
        ),
        severity=severity,
        remediation=(f"Either PATCH /plugins/{p.get('id')} with enabled=true to restore enforcement, "
                     f"or DELETE it so the configuration does not misrepresent the security posture."),
        detail=("Pre-provisioning plugins with enabled=false via decK/GitOps and toggling them on "
                "later is a legitimate, common pattern — confirm intent before acting."),
        source_ref={"api": "GET /plugins (paginated)", "config_key": "enabled"},
    )]


# ══ KONG.CONSUMER.NO_CREDENTIALS ══════════════════════════════════════════
def _credential_sweep_gap(resource, reason: str) -> Hit:
    """This rule's third outcome.

    It fires on 200-with-empty-.data from every credential endpoint. A sweep that never ran, and
    one where no endpoint answered 200, produce the same "no credentials seen" with none of the
    evidence — and returning [] for them renders as "checked, this consumer holds credentials",
    the opposite of what happened.
    """
    creds = resource.raw.get("credentials") or {}
    seen = ", ".join(f"/{k} → {(v or {}).get('status')!r}" for k, v in sorted(creds.items())) \
        or "(no credential endpoint was queried)"
    return Hit(
        observation=(
            f"Consumer '{resource.name}' (id {resource.raw.get('id')}): {reason}. Per-endpoint "
            f"status: {seen}. Whether this consumer holds any credential was therefore not "
            f"established — it is not referenced by any plugin's config.anonymous, by any "
            f"consumer-scoped plugin, or by any consumer group, but its credentials are unknown "
            f"rather than absent."
        ),
        remediation=(
            "Re-scan with connection config collect_consumer_credentials=true and a "
            "consumer_credential_limit above this node's consumer count, using an Admin API token "
            "allowed to read /consumers/{id}/{key-auth,basic-auth,jwt,hmac-auth,oauth2,acls,"
            "mtls-auth}. Until then this consumer cannot be triaged as dead configuration."
        ),
        detail="Coverage gap: the per-consumer credential sweep produced no readable evidence.",
        assessable=False,
        assessment_reason=reason,
        source_ref={"api": "GET /consumers/{id}/{key-auth,basic-auth,jwt,hmac-auth,oauth2,acls,"
                           "mtls-auth}"},
    )


@detector(kinds=["consumer"], rule_id="KONG.CONSUMER.NO_CREDENTIALS", severity="info",
          title="Kong consumer has no credentials and is unreferenced")
def consumer_no_credentials(resource, ctx):
    plugins = _plugins(ctx)

    # Global gate — the rule's whole viability. Kong's documented external-identity-mapping pattern
    # attaches ZERO local credentials to consumers: openid-connect maps IdP claims via
    # config.consumer_claims (config.consumer_claim before 3.14) resolved by config.consumer_by,
    # matching on username or custom_id alone; ldap-auth-advanced does the same. In any such
    # deployment every consumer legitimately has empty .data everywhere and this fires on 100% of
    # them — and it is NOT exemptible per-consumer, because the Admin API cannot enumerate IdP claims.
    if any(p.get("name") in EXTERNAL_IDENTITY for p in plugins):
        return []

    # The reference exemptions are checked before the credential evidence, not after: a consumer
    # the config points at is exempt whatever its credentials turn out to be, so an unread sweep
    # costs this rule nothing on it and must not file a coverage gap for it.
    cid, username = resource.raw.get("id"), resource.raw.get("username")
    for p in plugins:
        anon = (p.get("config") or {}).get("anonymous")
        if anon and anon in (cid, username):
            return []                          # the anonymous consumer — KONG.AUTH.ANONYMOUS_FALLBACK
        if (p.get("consumer") or {}).get("id") == cid:
            return []                          # targeted by a consumer-scoped plugin
    if (resource.raw.get("consumer_groups") or {}).get("names"):
        return []                              # group member, e.g. for rate-limiting-advanced scoping

    creds = resource.raw.get("credentials")
    if not creds:
        return [_credential_sweep_gap(
            resource, "the per-consumer credential sweep did not run for this consumer")]

    # 404 is not a value: mtls-auth is Enterprise-only and simply absent on OSS. Fire only if every
    # endpoint that answered 200 was empty AND at least one answered 200.
    answered = {k: v for k, v in creds.items() if v.get("status") == 200}
    if not answered:
        return [_credential_sweep_gap(
            resource, "no credential endpoint answered 200 for this consumer")]
    if any(v.get("count") for v in answered.values()):
        return []

    empty = sorted(answered)
    absent = sorted(k for k, v in creds.items() if v.get("status") == 404)
    return [Hit(
        observation=(
            f"Consumer '{resource.name}' (id {cid}) returns 200-with-empty .data from "
            f"{[f'/{k}' for k in empty]!r}"
            + (f" (/{', /'.join(absent)} returned 404 — plugin not loaded)" if absent else "")
            + f", and is not referenced by any plugin's config.anonymous (by id or username), by any "
              f"consumer-scoped plugin, or by any consumer group. No external-identity-mapping "
              f"plugin (openid-connect, ldap-auth-advanced) is present in this config."
        ),
        remediation=("DELETE this consumer if it is unused, or attach the intended credential. "
                     "Rationale: unreferenced, credential-less consumers are dead configuration that "
                     "obscures access review. There is no direct exposure — a consumer with no "
                     "credentials cannot be authenticated against and is therefore unreachable."),
        source_ref={"api": "GET /consumers, GET /consumers/{id}/{key-auth,basic-auth,jwt,"
                           "hmac-auth,oauth2,acls,mtls-auth}"},
    )]


# ══ Version rules ═════════════════════════════════════════════════════════
def _parts(version):
    """Numeric per-component parse. Lexicographic compare makes '3.4.3.9' > '3.4.3.26' and misses
    affected nodes; None on anything non-numeric so a rule skips rather than guesses."""
    if not isinstance(version, str):
        return None
    bits = version.split(".")
    try:
        return tuple(int(b) for b in bits)
    except ValueError:
        return None


_CVE_2026_6338_FLOORS = {
    (3, 4): (3, 4, 3, 27), (3, 10): (3, 10, 0, 12), (3, 11): (3, 11, 0, 12),
    (3, 12): (3, 12, 0, 7), (3, 13): (3, 13, 0, 5), (3, 14): (3, 14, 0, 4),
}


@detector(kinds=["broker"], rule_id="KONG.VERSION.CVE_2026_6338_SMUGGLING", severity="medium",
          title="Kong Enterprise below the CVE-2026-6338 fixed floor")
def cve_2026_6338(resource, ctx):
    edition, version = resource.raw.get("edition"), resource.raw.get("version")
    # The edition gate is mandatory, not a parenthetical. Kong OSS 3.4.x is a real, still-deployed
    # LTS line reporting a 3-part version; zero-padding '3.4.3' to '3.4.3.0' drops it inside the
    # 3.4.0.0–3.4.3.26 range and fires on an unaffected community node. Never zero-pad.
    if edition and edition != "enterprise":
        return []
    v = _parts(version)
    if v is None or len(v) != 4 or not edition:
        # Nothing to place: no version, a version string this comparator cannot parse, a scheme
        # that is not the 4-part Enterprise one, or an edition `GET /` did not report (without it
        # the advisory's applicability is itself unknown). Silence here reads in the console as
        # "not vulnerable", which is a claim this rule has no evidence for.
        if v is not None and _CVE_2026_6338_FLOORS.get(v[:2]) is None:
            return []                          # series no floor covers — ruled out on any edition
        floors = ", ".join(".".join(str(x) for x in f)
                           for f in sorted(_CVE_2026_6338_FLOORS.values()))
        return [Hit(
            observation=(
                f"Admin API `GET /` reports .version={version!r} and .edition={edition!r}; that "
                f"pair cannot be placed against the CVE-2026-6338 fixed floors ({floors}), which "
                f"are 4-part Kong Enterprise versions — so this node's exposure to the HTTP "
                f"request-smuggling / desynchronization flaw was not determined."
            ),
            remediation=(
                "Confirm the running edition and version (`kong version`, or the Admin API with a "
                "token that is allowed to read them) and check it against the fixed floor for its "
                "series: 3.4.3.27, 3.10.0.12, 3.11.0.12, 3.12.0.7, 3.13.0.5, 3.14.0.4 (or "
                "3.15.0.0). Kong OSS is not affected by this advisory."
            ),
            detail="Coverage gap: version string unreadable/unparseable, or edition not reported.",
            assessable=False,
            assessment_reason="Kong version string not parseable to a known Enterprise release",
            source_ref={"api": "GET /", "cve": "CVE-2026-6338"},
        )]

    floor = _CVE_2026_6338_FLOORS.get(v[:2])
    if floor is None or v >= floor:            # bounds are exclusive, mirroring versionEndExcluding
        return []

    floor_s = ".".join(str(x) for x in floor)
    return [Hit(
        observation=(
            f"Admin API `GET /` reports .version={version!r}, .edition='enterprise', which falls "
            f"below the CVE-2026-6338 fixed floor {floor_s} for the {v[0]}.{v[1]} series (HTTP "
            f"request smuggling / desynchronization when handling untrusted HTTP/1.1 traffic; "
            f"CVSS v4.0 base 4.9)."
        ),
        remediation=(
            "Upgrade to the fixed floor for your minor series: 3.4.3.27, 3.10.0.12, 3.11.0.12, "
            "3.12.0.7, 3.13.0.5, 3.14.0.4 (or 3.15.0.0). Kong's changelog: the fix preserves inbound "
            "Content-Length headers during hop-by-hop Connection header cleanup, preventing CL.0 "
            "request smuggling with crafted 'Connection: Content-Length' headers on requests with a "
            "body. Until patched, avoid terminating untrusted HTTP/1.1 traffic directly on this node."
        ),
        detail=("Version-only check. A vendor or backported rebuild may carry the fix while still "
                "reporting an affected version string, and a node fronted by a header-normalizing LB "
                "never terminates untrusted HTTP/1.1. In hybrid mode this reads the control plane's "
                "version while the exposure is on the data plane proxy path."),
        source_ref={"api": "GET /", "cve": "CVE-2026-6338",
                    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-6338"},
    )]


@detector(kinds=["broker"], rule_id="KONG.VERSION.CVE_2021_27306_JWT_BYPASS", severity="high",
          title="Kong below the CVE-2021-27306 JWT bypass fix with the jwt plugin enabled")
def cve_2021_27306(resource, ctx):
    edition, version = resource.raw.get("edition"), resource.raw.get("version")

    # Hoisted above the version arithmetic: with no enabled jwt plugin there is no JWT bypass to
    # have on any version, so an unreadable version costs this rule nothing and must not file a
    # coverage gap.
    jwt = [p for p in _plugins(ctx) if p.get("name") == "jwt" and _enabled(p)]
    if not jwt:
        return []

    v = _parts(version)
    if v is not None and v[:3] >= (2, 3, 2):
        return []                              # at or above the fix line in BOTH version schemes,
                                               # so the edition cannot change the answer

    # Branch the threshold; never cross-compare version schemes. Community is 3-part and fixed in
    # 2.3.2; Enterprise is 4-part and fixed in 2.3.2.0. A naive comparator treats 2.3.2 < 2.3.2.0 as
    # true and fires on the exact OSS version that carries the fix.
    scheme_len, floor = (4, "2.3.2.0 (Enterprise)") if edition == "enterprise" \
        else (3, "2.3.2 (OSS)")
    if v is None or len(v) != scheme_len:
        # An absent, unparseable or wrong-scheme version below the fix line cannot be placed —
        # and returning [] here renders as "not vulnerable" on a node running an enabled jwt
        # plugin, which is the one combination this rule exists to catch.
        return [Hit(
            observation=(
                f"Admin API `GET /` reports .version={version!r}, .edition={edition!r}, and "
                f"fully-paginated /plugins contains {len(jwt)} enabled jwt plugin(s) "
                f"(id {jwt[0].get('id')}). The version string could not be placed against the "
                f"CVE-2021-27306 fix line ({floor}), so this node's exposure to the JWT "
                f"access-control bypass was not determined."
            ),
            remediation=(
                "Confirm the running version (`kong version`) and ensure it is at least 2.3.2 "
                "(OSS) / 2.3.2.0 (Enterprise). Kong 2.x is long past its maintenance window — 2.8 "
                "LTS ended 2025-03-01 — so plan an upgrade to a supported 3.x release rather than "
                "a point patch."
            ),
            detail=("Coverage gap: version string unreadable/unparseable, or reported in a scheme "
                    "that does not match .edition. An enabled jwt plugin is present, so the "
                    "advisory is in scope for this node."),
            assessable=False,
            assessment_reason="Kong version string not parseable to a known release",
            source_ref={"api": "GET /, GET /plugins (paginated)", "cve": "CVE-2021-27306"},
        )]

    return [Hit(
        observation=(
            f"Admin API `GET /` reports .version={version!r}, .edition={edition!r}, and "
            f"fully-paginated /plugins contains {len(jwt)} enabled jwt plugin(s) "
            f"(id {jwt[0].get('id')}). This is potentially vulnerable to CVE-2021-27306 (JWT plugin "
            f"improper access control allowing access to authenticated routes without a valid token), "
            f"fixed in {floor}. Unverified preconditions: exploitation additionally requires (a) at "
            f"least one unauthenticated route and (b) a path-normalizing intermediary (nginx / LB) "
            f"between Kong and the upstream that collapses '/public/../api/v1/...'. This rule checks "
            f"neither."
        ),
        remediation=(
            "Upgrade Kong Gateway to 2.3.2 (OSS) / 2.3.2.0 (Enterprise) or later. Kong 2.x is long "
            "past its maintenance window — 2.8 LTS ended 2025-03-01 — so plan an upgrade to a "
            "supported 3.x release (3.9 latest, or 3.4 LTS) rather than a point patch."
        ),
        detail=("NVD's only CPE for this CVE is enterprise-scoped, so a strict CPE-matching auditor "
                "will dispute an OSS attribution. OSS is genuinely affected: Kong/kong PR #6821 "
                "('always normalizing the incoming request's URI before matching against the "
                "Router') landed in OSS 2.3.2, and Enterprise 2.3.2.0 is built on it — cite the OSS "
                "changelog / PR #6821 as primary for community findings."),
        source_ref={"api": "GET /, GET /plugins (paginated)", "cve": "CVE-2021-27306",
                    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-27306"},
    )]


# ══ KONG.ADMIN.NO_AUDIT_LOG ═══════════════════════════════════════════════
@detector(kinds=["broker"], rule_id="KONG.ADMIN.NO_AUDIT_LOG", severity="info",
          title="Kong open-source edition keeps no record of Admin API changes")
def admin_no_audit_log(resource, ctx):
    raw = resource.raw or {}
    cfg = raw.get("configuration") or {}
    if raw.get("edition") == "enterprise" or "enforce_rbac" in cfg:
        return []                              # Enterprise has audit logging and RBAC
    if raw.get("edition") is None and not cfg:
        return []                              # edition unknown: say nothing
    if cfg.get("role") == "data_plane":
        return []                              # changes are made on the control plane
    return [Hit(
        observation=(f"Kong {raw.get('edition')!r} version {raw.get('version')!r}: the open-source "
                     "edition has no Admin API audit log and no admin roles. Kong's own staff confirm "
                     "both are Enterprise-only, so Kong itself cannot say who changed a route, "
                     "plugin or consumer, or when."),
        remediation=("Keep the Admin API on loopback and make changes only through decK files in git, "
                     "so every change has a reviewed commit. Put any remote Admin API access behind a "
                     "proxy that logs the caller. VectaSec's Time machine also records what changed "
                     "between scans."),
        detail=f"database={cfg.get('database')!r} role={cfg.get('role')!r}",
        source_ref={"api": "GET /", "field": "edition"},
    )]
