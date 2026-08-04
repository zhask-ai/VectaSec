"""Offline unit tests for the Kong rulepack.

Every detector gets a fires-on-bad and a does-not-fire-on-good case. The negative is the one that
carries weight: a rule that fires unconditionally is indistinguishable from a rule that works, and
the failure is silent — it lands as noise in the findings table, not as a red test.

Payload shapes are copied from docs/research/platform-apis.md §2.2-2.7 (captured from a live Kong
3.9.3 OSS node), including the parts that surprise: `service` is `{"id": ...}` and never expanded,
`next`-paginated lists are already flattened by the connector, `created_at` is epoch seconds,
`nginx_http_client_max_body_size` is the *string* "0", and `trusted_ips` is `{}`.

No network, no DB — detectors are pure functions of (Resource, ScanContext).
"""
import httpx
import pytest

from vectasec.connect.kong import _workspaces
from vectasec.contracts import Resource, ScanContext
from vectasec.detect.kong import (
    admin_listen_wildcard,
    admin_unauthenticated,
    rbac_disabled,
    admin_plaintext_listener,
    workspaces_not_enumerated,
    route_no_auth_plugin,
    auth_anonymous_fallback,
    route_http_protocol_allowed,
    route_no_rate_limiting,
    ratelimit_fail_open,
    cors_wildcard_with_credentials,
    route_wildcard_host_preserve_host,
    route_no_request_size_limit,
    plugin_security_disabled,
    consumer_no_credentials,
    cve_2026_6338,
    cve_2021_27306,
)

# ── Constants mirroring a real node ───────────────────────────────────────
NODE_EXT = "kong-node-kong.internal:8001"
SVC_ID = "b942142b-f75b-527f-b4d0-d6efe7e1344d"
ROUTE_ID = "b8613a05-2540-5613-a77c-008d3263ece6"
OTHER_ROUTE_ID = "7f2e1c94-3a55-4d18-9b6e-2c1f8a4d0e33"
CONSUMER_ID = "a9c0ddda-1fd5-552c-a6e4-6f5dc9660fc2"

LOOPBACK_ADMIN = ("127.0.0.1:8001 reuseport backlog=16384, "
                  "127.0.0.1:8444 http2 ssl reuseport backlog=16384")
WILDCARD_ADMIN = ("0.0.0.0:8001 reuseport backlog=16384, "
                  "0.0.0.0:8444 http2 ssl reuseport backlog=16384")
PROXY_LISTEN = ("0.0.0.0:8000 reuseport backlog=16384, "
                "0.0.0.0:8443 http2 ssl reuseport backlog=16384")

CREDENTIAL_PATHS = ("key-auth", "basic-auth", "jwt", "hmac-auth", "oauth2", "acls", "mtls-auth")

# Verbatim from platform-apis.md §2.4 — the full materialised schema defaults GET /plugins returns.
KEY_AUTH_CONFIG = {
    "key_in_body": False, "realm": None, "anonymous": None, "hide_credentials": False,
    "key_names": ["apikey"], "run_on_preflight": True, "key_in_header": True, "key_in_query": True,
}


def rate_limiting_config(**over):
    cfg = {
        "month": None, "year": None, "policy": "local", "fault_tolerant": True,
        "hide_client_headers": False,
        # The connector scrubs `redis.password` / `redis_password` to "[redacted]" on the way in;
        # reproduced here so no rule is accidentally written against a value it never sees.
        "redis": {"password": "[redacted]", "username": None, "database": 0, "ssl": False,
                  "server_name": None, "port": 6379, "ssl_verify": False, "timeout": 2000,
                  "host": None},
        "redis_database": 0, "error_code": 429, "error_message": "API rate limit exceeded",
        "sync_rate": -1, "path": None, "redis_timeout": 2000, "redis_host": None,
        "redis_ssl_verify": False, "redis_ssl": False, "redis_username": None,
        "redis_password": "[redacted]", "header_name": None, "redis_port": 6379,
        "redis_server_name": None, "limit_by": "consumer", "second": None, "minute": 10,
        "hour": None, "day": None,
    }
    cfg.update(over)
    return cfg


# ── Builders ──────────────────────────────────────────────────────────────
def probes(origin="loopback", root_status=200, tagline="Welcome to kong",
           edition="community", rbac=None):
    """Shape emitted by connect/kong.py's _probe_unauthenticated.

    tagline defaults to the lowercase-k form a live 3.9.3 node actually returns — not the
    'Welcome to Kong' the docs quote.
    """
    root = {"status": root_status, "tagline": tagline, "edition": edition, "version": "3.9.3"}
    return {"origin": origin, "root": root,
            "rbac_users": rbac if rbac is not None else {"status": 404}}


RBAC_ENFORCING = {"status": 401, "body_snippet": '{"message":"Invalid RBAC credentials"}'}


OSS_WORKSPACES = {"readable": None,
                  "reason": "not attempted: workspaces are an Enterprise feature"}
WORKSPACES_REFUSED = {"readable": False, "status": 403, "error": "http_403"}


def node(configuration=None, *, version="3.9.3", edition="community", probe=None,
         workspaces=None):
    cfg = {
        "admin_listen": LOOPBACK_ADMIN,
        "proxy_listen": PROXY_LISTEN,
        "database": "off",
        "role": "traditional",
        "trusted_ips": {},                     # live node returns {}, not [] or null
        "nginx_http_client_max_body_size": "0",  # the *string* "0", per the live capture
    }
    if configuration:
        cfg.update(configuration)
    return Resource(
        kind="broker", name="3a1b2c3d4e5f", ext_id=NODE_EXT,
        labels={"edition": edition or "", "version": version or ""},
        raw={"version": version, "edition": edition, "hostname": "3a1b2c3d4e5f",
             "node_id": "8f0b2c1a-4e5d-4a9b-9c3e-1d2f3a4b5c6d",
             "configuration": cfg, "probes": probe or probes(),
             # `workspaces` is [""] both on OSS and on an Enterprise node whose /workspaces was
             # refused — the enumeration outcome is the only thing that tells them apart.
             "workspaces": [""], "workspace_enumeration": workspaces or OSS_WORKSPACES,
             "consumer_credential_sweep": True},
    )


def route(*, id=ROUTE_ID, name="demo-route", protocols=("http", "https"), service=SVC_ID, **over):
    raw = {
        "preserve_host": False, "protocols": list(protocols), "paths": ["/demo"],
        "path_handling": "v0", "headers": None,
        "service": {"id": service} if service else None,
        "snis": None, "request_buffering": True, "response_buffering": True,
        "https_redirect_status_code": 426, "destinations": None, "name": name, "id": id,
        "hosts": None, "methods": None, "sources": None, "strip_path": True,
        "regex_priority": 0, "created_at": 1784265794, "updated_at": 1784265794, "tags": None,
    }
    raw.update(over)
    return Resource(kind="route", name=name, ext_id=f"kong-route-{id}",
                    labels={"protocols": ",".join(raw["protocols"])}, raw=raw)


def service(*, id=SVC_ID, name="demo-service"):
    raw = {"protocol": "http", "retries": 5, "port": 80, "client_certificate": None,
           "write_timeout": 60000, "path": None, "tags": None, "ca_certificates": None,
           "read_timeout": 60000, "enabled": True, "id": id, "name": name,
           "connect_timeout": 60000, "host": "httpbin.org", "created_at": 1784265794,
           "tls_verify": None, "updated_at": 1784265794, "tls_verify_depth": None}
    return Resource(kind="service", name=name, ext_id=f"kong-service-{id}",
                    labels={"protocol": "http", "host": "httpbin.org"}, raw=raw)


def plugin(name, *, id=None, config=None, enabled=True,
           protocols=("grpc", "grpcs", "http", "https"),
           route_id=None, service_id=None, consumer_id=None, consumer_group_id=None):
    pid = id or f"plugin-{name}"
    raw = {
        "id": pid, "protocols": list(protocols),
        "route": {"id": route_id} if route_id else None,
        "service": {"id": service_id} if service_id else None,
        "consumer": {"id": consumer_id} if consumer_id else None,
        "config": config if config is not None else {},
        "enabled": enabled, "name": name, "instance_name": None, "tags": None,
        "created_at": 1784265794, "updated_at": 1784265794,
    }
    if consumer_group_id:
        raw["consumer_group"] = {"id": consumer_group_id}
    return Resource(kind="plugin", name=name, ext_id=f"kong-plugin-{pid}",
                    labels={"plugin": name, "enabled": str(enabled).lower()}, raw=raw)


def creds(counts=None, groups=None, mtls_status=404):
    """Connector's per-consumer credential sweep: counts only, plus ACL group names.

    mtls-auth 404s on OSS (Enterprise-only plugin). 404 must not read as "no credentials", so the
    per-endpoint status is preserved rather than collapsed to a count.
    """
    counts = counts or {}
    out = {}
    for path in CREDENTIAL_PATHS:
        if path == "mtls-auth" and mtls_status != 200:
            out[path] = {"status": mtls_status}
            continue
        entry = {"status": 200, "count": counts.get(path, 0)}
        if path == "acls":
            entry["groups"] = list(groups or [])
        out[path] = entry
    return out


def consumer(*, id=CONSUMER_ID, username="demo-consumer", custom_id="demo-123",
             credentials=None, consumer_groups=None):
    raw = {"id": id, "tags": None, "username": username, "created_at": 1784265794,
           "updated_at": 1784265794, "custom_id": custom_id}
    if credentials is not None:
        raw["credentials"] = credentials
    if consumer_groups is not None:
        raw["consumer_groups"] = consumer_groups
    return Resource(kind="consumer", name=username, ext_id=f"kong-consumer-{id}",
                    labels={"custom_id": custom_id or ""}, raw=raw)


def ctx(*resources, **config):
    config.setdefault("url", "http://kong.internal:8001")
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1",
                       resources=list(resources), config=config)


def one(hits):
    assert len(hits) == 1, f"expected exactly one hit, got {len(hits)}"
    return hits[0]


# ══ KONG.ADMIN.LISTEN_WILDCARD ════════════════════════════════════════════
def test_admin_listen_wildcard_fires_on_wildcard_bind():
    n = node({"admin_listen": WILDCARD_ADMIN})
    h = one(admin_listen_wildcard(n, ctx(n)))
    assert h.severity == "high"
    assert "0.0.0.0:8001 reuseport backlog=16384" in h.observation
    assert "loopback" in h.observation          # probe origin is recorded as evidence


def test_admin_listen_wildcard_does_not_fire_on_loopback_default():
    n = node()
    assert admin_listen_wildcard(n, ctx(n)) == []


def test_admin_listen_wildcard_does_not_fire_when_admin_api_is_off():
    # `off` is a valid admin_listen that disables the Admin API. A parser that treats it as an
    # address sees no loopback host and no ssl flag, and fires every listener rule on a node with
    # no admin listener at all.
    n = node({"admin_listen": "off"})
    assert admin_listen_wildcard(n, ctx(n)) == []


def test_admin_listen_wildcard_escalates_to_critical_on_remote_unauthenticated_200():
    n = node({"admin_listen": WILDCARD_ADMIN}, probe=probes(origin="remote"))
    h = one(admin_listen_wildcard(n, ctx(n)))
    assert h.severity == "critical"
    assert "remote" in h.observation


def test_admin_listen_wildcard_stays_high_when_probe_is_loopback_only():
    # Bind address alone cannot establish reachability — only a remote unauthenticated 200 escalates.
    n = node({"admin_listen": WILDCARD_ADMIN}, probe=probes(origin="loopback"))
    assert one(admin_listen_wildcard(n, ctx(n))).severity == "high"


def test_admin_listen_wildcard_ipv6_wildcard_is_classified_wildcard():
    n = node({"admin_listen": "[::]:8001 reuseport"})
    h = one(admin_listen_wildcard(n, ctx(n)))
    assert h.severity == "high"
    assert "[::]:8001 reuseport" in h.observation


def test_admin_listen_wildcard_unicast_bind_is_info_not_high():
    n = node({"admin_listen": "10.0.0.5:8001 reuseport"})
    h = one(admin_listen_wildcard(n, ctx(n)))
    assert h.severity == "info"
    assert "10.0.0.5:8001" in h.observation


def test_admin_listen_wildcard_does_not_fire_on_unresolvable_hostname():
    # A hostname's location was never established; a rule must not FAIL on it.
    n = node({"admin_listen": "kong-admin.svc.cluster.local:8001"})
    assert admin_listen_wildcard(n, ctx(n)) == []


# ══ KONG.ADMIN.UNAUTHENTICATED ════════════════════════════════════════════
def test_admin_unauthenticated_fires_on_remote_unauthenticated_200():
    n = node({"admin_listen": WILDCARD_ADMIN}, probe=probes(origin="remote"))
    h = one(admin_unauthenticated(n, ctx(n)))
    assert h.severity == "critical"
    assert "'Welcome to kong'" in h.observation
    assert "remote" in h.observation


def test_admin_unauthenticated_does_not_fire_when_rbac_enforces():
    n = node({"enforce_rbac": "on", "database": "postgres"}, edition="enterprise",
             probe=probes(origin="remote", root_status=401, tagline=None, rbac=RBAC_ENFORCING))
    assert admin_unauthenticated(n, ctx(n)) == []


def test_admin_unauthenticated_matches_lowercase_tagline_from_live_node():
    # Regression: the rulepack doc specifies .tagline == "Welcome to Kong"; Kong 3.9.3 OSS returns
    # "Welcome to kong". An exact-match comparison silently never fires this rule.
    n = node(probe=probes(origin="remote", tagline="Welcome to kong"))
    assert len(admin_unauthenticated(n, ctx(n))) == 1


def test_admin_unauthenticated_is_info_on_loopback_probe_and_loopback_bind():
    # Default OSS posture: fires 100% of the time with no fix to apply. Ranking it high mutes the
    # whole rulepack.
    n = node(probe=probes(origin="loopback"))
    assert one(admin_unauthenticated(n, ctx(n))).severity == "info"


def test_admin_unauthenticated_fires_high_when_rbac_users_is_world_readable():
    n = node({"enforce_rbac": "off", "database": "postgres"}, edition="enterprise",
             probe=probes(origin="loopback", edition="enterprise",
                          rbac={"status": 200, "count": 3}))
    h = one(admin_unauthenticated(n, ctx(n)))
    assert h.severity == "high"
    assert "3 RBAC user(s)" in h.observation


def test_admin_unauthenticated_does_not_fire_when_root_probe_failed_to_connect():
    n = node(probe={"origin": "remote",
                    "root": {"status": None, "error": "ConnectError: connection refused"},
                    "rbac_users": {"status": None, "error": "ConnectError: connection refused"}})
    assert admin_unauthenticated(n, ctx(n)) == []


def test_admin_unauthenticated_remediation_differs_by_edition():
    oss = node(probe=probes(origin="remote"))
    ent = node({"enforce_rbac": "off", "database": "postgres"}, edition="enterprise",
               probe=probes(origin="remote", edition="enterprise"))
    assert "enforce_rbac does not exist in OSS" in one(admin_unauthenticated(oss, ctx(oss))).remediation
    assert "enforce_rbac=on" in one(admin_unauthenticated(ent, ctx(ent))).remediation


# ══ KONG.RBAC.DISABLED ════════════════════════════════════════════════════
def test_rbac_disabled_fires_on_enterprise_with_enforce_rbac_off():
    n = node({"enforce_rbac": "off", "database": "postgres", "role": "traditional"},
             version="3.11.0.0", edition="enterprise")
    h = one(rbac_disabled(n, ctx(n)))
    assert h.severity == "medium"               # loopback bind — hardening gap, not exposure
    assert "'off'" in h.observation
    assert "'postgres'" in h.observation


def test_rbac_disabled_does_not_fire_when_enforce_rbac_on():
    n = node({"enforce_rbac": "on", "database": "postgres"}, version="3.11.0.0",
             edition="enterprise")
    assert rbac_disabled(n, ctx(n)) == []


def test_rbac_disabled_does_not_fire_on_oss_where_the_key_does_not_exist():
    # kong_defaults.lua has no enforce_rbac. Absent key ⇒ N/A, never a FAIL — this is why the
    # connector allowlists config keys instead of defaulting them.
    n = node()
    assert "enforce_rbac" not in n.raw["configuration"]
    assert rbac_disabled(n, ctx(n)) == []


def test_rbac_disabled_does_not_fire_dbless_where_rbac_is_unavailable():
    n = node({"enforce_rbac": "off", "database": "off"}, version="3.11.0.0", edition="enterprise")
    assert rbac_disabled(n, ctx(n)) == []


def test_rbac_disabled_does_not_fire_on_a_data_plane_node():
    n = node({"enforce_rbac": "off", "database": "postgres", "role": "data_plane"},
             version="3.11.0.0", edition="enterprise")
    assert rbac_disabled(n, ctx(n)) == []


def test_rbac_disabled_does_not_fire_when_probe_shows_rbac_actually_enforcing():
    # Config says off, the live probe says otherwise — trust the probe.
    n = node({"enforce_rbac": "off", "database": "postgres"}, version="3.11.0.0",
             edition="enterprise",
             probe=probes(root_status=401, tagline=None,
                          rbac={"status": 401,
                                "body_snippet": "Invalid RBAC credentials. Token or User "
                                                "credentials required"}))
    assert rbac_disabled(n, ctx(n)) == []


def test_rbac_disabled_escalates_to_high_on_non_loopback_admin_listen():
    n = node({"enforce_rbac": "off", "database": "postgres", "admin_listen": WILDCARD_ADMIN},
             version="3.11.0.0", edition="enterprise")
    assert one(rbac_disabled(n, ctx(n))).severity == "high"


def test_rbac_disabled_cites_the_nodes_own_rbac_auth_header():
    n = node({"enforce_rbac": "off", "database": "postgres",
              "rbac_auth_header": "X-Custom-Admin-Token"}, version="3.11.0.0", edition="enterprise")
    assert "X-Custom-Admin-Token" in one(rbac_disabled(n, ctx(n))).remediation


# ══ KONG.ADMIN.PLAINTEXT_LISTENER ═════════════════════════════════════════
def test_admin_plaintext_listener_fires_on_wildcard_plaintext_bind():
    n = node({"admin_listen": WILDCARD_ADMIN})
    h = one(admin_plaintext_listener(n, ctx(n)))
    assert "0.0.0.0:8001 reuseport backlog=16384" in h.observation
    assert "no Admin API token exists on this edition" in h.observation


def test_admin_plaintext_listener_does_not_fire_on_loopback_only():
    n = node()
    assert admin_plaintext_listener(n, ctx(n)) == []


def test_admin_plaintext_listener_does_not_fire_when_every_exposed_entry_has_ssl():
    n = node({"admin_listen": "0.0.0.0:8444 http2 ssl reuseport backlog=16384"})
    assert admin_plaintext_listener(n, ctx(n)) == []


def test_admin_plaintext_listener_tokenizes_flags_rather_than_substring_matching():
    # 'backlog=16384' and 'reuseport' must not be read as carrying ssl, and an entry whose flags
    # merely contain the letters 'ssl' is not an ssl listener.
    n = node({"admin_listen": "0.0.0.0:8001 reuseport backlog=16384"})
    h = one(admin_plaintext_listener(n, ctx(n)))
    assert "['backlog', 'reuseport']" in h.observation


def test_admin_plaintext_listener_sees_a_mixed_plaintext_and_tls_config():
    # The admin_ssl_enabled trap: that flag is true if *any* listener has ssl, so it cannot see this
    # config at all. Each entry must be judged on its own flags — the plaintext 8001 fires, and the
    # TLS 8444 alongside it must not launder it.
    n = node({"admin_listen": "0.0.0.0:8001, 0.0.0.0:8444 http2 ssl"})
    h = one(admin_plaintext_listener(n, ctx(n)))
    assert "['0.0.0.0:8001']" in h.observation
    assert "8444" not in h.observation


def test_admin_plaintext_listener_uses_enterprise_wording_only_on_enterprise():
    n = node({"admin_listen": WILDCARD_ADMIN, "enforce_rbac": "on", "database": "postgres"},
             version="3.11.0.0", edition="enterprise")
    assert "Kong-Admin-Token RBAC credentials" in one(admin_plaintext_listener(n, ctx(n))).observation


def test_admin_plaintext_listener_corroborates_when_scanner_itself_used_plaintext_remotely():
    n = node({"admin_listen": WILDCARD_ADMIN}, probe=probes(origin="remote"))
    h = one(admin_plaintext_listener(n, ctx(n, url="http://kong.internal:8001")))
    assert "directly corroborating this" in h.observation


# ══ KONG.SCOPE.WORKSPACES_NOT_ENUMERATED ══════════════════════════════════
class FakeAdminClient:
    """Stands in for httpx.Client — hands back canned httpx.Response objects, touches no socket."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.paths = []

    def get(self, url):
        self.paths.append(url)
        return self._responses.pop(0)


def _response(status, body=None):
    return httpx.Response(status, json=body if body is not None else {},
                          request=httpx.Request("GET", "http://kong.internal:8001/workspaces"))


def test_workspace_enumeration_records_a_refusal_instead_of_swallowing_it():
    # A 403 here narrows the scan to the default workspace. The fallback itself is correct — what
    # was missing is any record that it happened.
    client = FakeAdminClient(_response(403))
    spaces, outcome = _workspaces(client, "http://kong.internal:8001", "enterprise")
    assert spaces == [("", "")]
    assert outcome == {"readable": False, "status": 403, "error": "http_403"}


def test_workspace_enumeration_is_readable_when_the_list_answers():
    client = FakeAdminClient(_response(200, {"data": [{"name": "default"}, {"name": "payments"}],
                                             "next": None}))
    spaces, outcome = _workspaces(client, "http://kong.internal:8001", "enterprise")
    assert spaces == [("default", "/default"), ("payments", "/payments")]
    assert outcome == {"readable": True, "count": 2}


def test_workspace_enumeration_is_not_attempted_on_oss():
    # None = never attempted, and correctly so: OSS has no workspace layer to enumerate.
    spaces, outcome = _workspaces(None, "http://kong.internal:8001", "community")
    assert spaces == [("", "")]
    assert outcome["readable"] is None


def test_workspaces_not_enumerated_fires_when_the_list_was_refused():
    n = node({"database": "postgres"}, edition="enterprise", workspaces=WORKSPACES_REFUSED)
    r, p = route(), plugin("key-auth", config=dict(KEY_AUTH_CONFIG))
    h = one(workspaces_not_enumerated(n, ctx(n, r, p)))
    assert "http_403" in h.observation
    assert "1 route(s)" in h.observation and "1 plugin(s)" in h.observation
    assert h.assessable is False
    assert "workspace list was refused" in h.assessment_reason


def test_workspaces_not_enumerated_does_not_fire_on_oss():
    assert workspaces_not_enumerated(node(), ctx(node())) == []


def test_workspaces_not_enumerated_does_not_fire_when_the_list_was_read():
    n = node({"database": "postgres"}, edition="enterprise",
             workspaces={"readable": True, "count": 3})
    assert workspaces_not_enumerated(n, ctx(n)) == []


def test_workspaces_not_enumerated_does_not_fire_without_an_enumeration_record():
    # A node collected before the outcome was recorded: absence of the record is not a refusal.
    n = node()
    n.raw.pop("workspace_enumeration")
    assert workspaces_not_enumerated(n, ctx(n)) == []


# ══ KONG.ROUTE.NO_AUTH_PLUGIN ═════════════════════════════════════════════
def test_route_no_auth_plugin_fires_when_no_auth_plugin_resolves():
    r, s, n = route(), service(), node()
    h = one(route_no_auth_plugin(r, ctx(n, s, r)))
    assert h.severity == "high"
    assert ROUTE_ID in h.observation
    assert "'demo-service'" in h.observation


def test_route_no_auth_plugin_does_not_fire_with_a_global_key_auth():
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG))
    assert route_no_auth_plugin(r, ctx(n, s, r, p)) == []


def test_route_no_auth_plugin_does_not_fire_with_a_service_scoped_auth_plugin():
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), service_id=SVC_ID)
    assert route_no_auth_plugin(r, ctx(n, s, r, p)) == []


def test_route_no_auth_plugin_does_not_fire_with_a_route_scoped_auth_plugin():
    r, s, n = route(), service(), node()
    p = plugin("jwt", config={"anonymous": None}, route_id=ROUTE_ID)
    assert route_no_auth_plugin(r, ctx(n, s, r, p)) == []


def test_route_no_auth_plugin_does_not_fire_on_stream_routes():
    # HTTP auth plugins cannot run on tcp/tls/udp routes, so the rule would fire on 100% of them.
    r = route(protocols=["tcp", "tls"], name="stream-route")
    n = node()
    assert route_no_auth_plugin(r, ctx(n, r)) == []


def test_route_no_auth_plugin_fires_when_auth_plugin_is_scoped_to_a_sibling_route():
    # A route-scoped plugin on route B must never be credited to route A.
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), route_id=OTHER_ROUTE_ID)
    assert len(route_no_auth_plugin(r, ctx(n, s, r, p))) == 1


def test_route_no_auth_plugin_fires_when_route_and_service_scoped_plugin_targets_another_route():
    # `P.route == null` is load-bearing in the service branch: a route+service-scoped plugin on
    # route B shares route A's service, and must not be credited to route A.
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG),
               route_id=OTHER_ROUTE_ID, service_id=SVC_ID)
    assert len(route_no_auth_plugin(r, ctx(n, s, r, p))) == 1


def test_route_no_auth_plugin_fires_when_plugin_protocols_do_not_intersect_the_route():
    # An auth plugin scoped to grpc only leaves an http route wide open.
    r, s, n = route(protocols=["http", "https"]), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), protocols=["grpc", "grpcs"])
    h = one(route_no_auth_plugin(r, ctx(n, s, r, p)))
    assert h.severity == "high"


def test_route_no_auth_plugin_fires_when_the_only_auth_plugin_is_disabled():
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), enabled=False)
    assert len(route_no_auth_plugin(r, ctx(n, s, r, p))) == 1


def test_route_no_auth_plugin_fires_when_auth_plugin_falls_through_to_anonymous():
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    h = one(route_no_auth_plugin(r, ctx(n, s, r, p)))
    assert h.severity == "high"
    assert "config.anonymous is set" in h.observation


def test_route_no_auth_plugin_downgrades_to_info_when_an_unknown_plugin_resolves():
    # A custom Lua plugin may be doing auth; asserting a finding over it is a guess.
    r, s, n = route(), service(), node()
    p = plugin("acme-corp-internal-auth", config={})
    h = one(route_no_auth_plugin(r, ctx(n, s, r, p)))
    assert h.severity == "info"
    assert "acme-corp-internal-auth" in h.observation


def test_route_no_auth_plugin_does_not_fire_for_a_configured_extra_auth_plugin():
    r, s, n = route(), service(), node()
    p = plugin("acme-corp-internal-auth", config={})
    c = ctx(n, s, r, p, extra_auth_plugins=["acme-corp-internal-auth"])
    assert route_no_auth_plugin(r, c) == []


def test_route_no_auth_plugin_ignores_a_consumer_scoped_auth_plugin():
    # Identity is unknown until auth completes, so a consumer-scoped auth plugin protects nothing.
    r, s, n = route(), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), consumer_id=CONSUMER_ID)
    assert len(route_no_auth_plugin(r, ctx(n, s, r, p))) == 1


def test_route_no_auth_plugin_names_a_serviceless_route_as_such():
    r, n = route(service=None), node()
    assert "none (serviceless route)" in one(route_no_auth_plugin(r, ctx(n, r))).observation


def test_route_no_auth_plugin_fires_on_a_serviceless_route_despite_a_service_scoped_plugin():
    # The service branch's `bool(rs.get("id"))` guard: a serviceless route has service=null, and
    # `{}.get("id") == ps.get("id")` must not be allowed to become a match. Without the guard every
    # serviceless route is credited with every service-scoped auth plugin in the config.
    r, s, n = route(service=None), service(), node()
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), service_id=SVC_ID)
    assert len(route_no_auth_plugin(r, ctx(n, s, r, p))) == 1


# ══ KONG.AUTH.ANONYMOUS_FALLBACK ══════════════════════════════════════════
def test_auth_anonymous_fallback_fires_on_anonymous_consumer_with_no_mitigation():
    c = consumer()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID},
               service_id=SVC_ID)
    h = one(auth_anonymous_fallback(p, ctx(node(), c, p)))
    assert h.severity == "high"
    assert CONSUMER_ID in h.observation
    assert "demo-consumer" in h.observation


def test_auth_anonymous_fallback_does_not_fire_when_anonymous_is_null():
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG))
    assert auth_anonymous_fallback(p, ctx(node(), p)) == []


def test_auth_anonymous_fallback_does_not_fire_on_empty_string_anonymous():
    # Since Kong 2.0 an empty string raises "failed to load anonymous consumer" at runtime rather
    # than falling through — the fallthrough impact is factually wrong for this value.
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": ""})
    assert auth_anonymous_fallback(p, ctx(node(), p)) == []


def test_auth_anonymous_fallback_does_not_fire_on_a_non_anon_capable_plugin():
    p = plugin("cors", config={"anonymous": CONSUMER_ID})
    assert auth_anonymous_fallback(p, ctx(node(), consumer(), p)) == []


def test_auth_anonymous_fallback_does_not_fire_when_plugin_is_disabled():
    c = consumer()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID}, enabled=False)
    assert auth_anonymous_fallback(p, ctx(node(), c, p)) == []


def test_auth_anonymous_fallback_resolves_the_consumer_by_username():
    # config.anonymous accepts an id OR a username; an id-only match misses every username form.
    c = consumer()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": "demo-consumer"})
    h = one(auth_anonymous_fallback(p, ctx(node(), c, p)))
    assert "'demo-consumer'" in h.observation


def test_auth_anonymous_fallback_reports_a_dangling_reference_at_medium():
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": "ghost-consumer"})
    h = one(auth_anonymous_fallback(p, ctx(node(), consumer(), p)))
    assert h.severity == "medium"
    assert "'ghost-consumer'" in h.observation
    assert "no consumer" in h.observation


def test_auth_anonymous_fallback_suppressed_by_consumer_scoped_request_termination():
    # Kong's canonical deny-anonymous pattern: consumer=<anon-id>, service=null, route=null.
    c = consumer()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID}, service_id=SVC_ID)
    rt = plugin("request-termination", id="rt-1", config={"status_code": 403},
                consumer_id=CONSUMER_ID)
    assert auth_anonymous_fallback(p, ctx(node(), c, p, rt)) == []


def test_auth_anonymous_fallback_suppressed_by_acl_deny_of_the_anon_groups():
    c = consumer(credentials=creds(groups=["anon-group"]))
    c.raw["credentials"]["acls"]["count"] = 1
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    acl = plugin("acl", id="acl-1", config={"allow": None, "deny": ["anon-group"]},
                 service_id=SVC_ID)
    assert auth_anonymous_fallback(p, ctx(node(), c, p, acl)) == []


def test_auth_anonymous_fallback_suppressed_by_acl_allow_disjoint_from_the_anon_groups():
    c = consumer(credentials=creds(groups=["anon-group"]))
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    acl = plugin("acl", id="acl-1", config={"allow": ["paying-customers"], "deny": None},
                 service_id=SVC_ID)
    assert auth_anonymous_fallback(p, ctx(node(), c, p, acl)) == []


def test_auth_anonymous_fallback_fires_when_acl_allow_includes_the_anon_groups():
    # A non-empty allow that *contains* the anonymous consumer's group mitigates nothing.
    c = consumer(credentials=creds(groups=["anon-group"]))
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    acl = plugin("acl", id="acl-1", config={"allow": ["anon-group", "paying"], "deny": None},
                 service_id=SVC_ID)
    h = one(auth_anonymous_fallback(p, ctx(node(), c, p, acl)))
    assert "['anon-group']" in h.observation


def test_auth_anonymous_fallback_downgrades_when_anon_consumer_carries_restrictive_plugins():
    c = consumer()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    rl = plugin("rate-limiting", id="rl-1", config=rate_limiting_config(),
                consumer_id=CONSUMER_ID)
    h = one(auth_anonymous_fallback(p, ctx(node(), c, p, rl)))
    assert h.severity == "medium"
    assert "rate-limiting" in h.observation


def test_auth_anonymous_fallback_says_so_when_acl_groups_were_not_enumerated():
    c = consumer()                                   # no credentials key — sweep skipped
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    h = one(auth_anonymous_fallback(p, ctx(node(), c, p)))
    assert "not enumerated by this scan" in h.observation


# ══ KONG.ROUTE.HTTP_PROTOCOL_ALLOWED ══════════════════════════════════════
def test_route_http_protocol_allowed_fires_on_http_in_protocols():
    r, n = route(protocols=["http", "https"]), node()
    h = one(route_http_protocol_allowed(r, ctx(n, r)))
    assert h.severity == "low"
    assert "'http'" in h.observation
    assert "0.0.0.0:8000 reuseport backlog=16384" in h.observation   # the plaintext listener


def test_route_http_protocol_allowed_does_not_fire_on_https_only():
    r, n = route(protocols=["https"]), node()
    assert route_http_protocol_allowed(r, ctx(n, r)) == []


def test_route_http_protocol_allowed_does_not_fire_on_grpcs_only():
    r, n = route(protocols=["grpcs"]), node()
    assert route_http_protocol_allowed(r, ctx(n, r)) == []


def test_route_http_protocol_allowed_is_info_without_a_plaintext_proxy_listener():
    # With no plaintext listener the `http` protocol cannot be exercised — the finding is inert.
    n = node({"proxy_listen": "0.0.0.0:8443 http2 ssl reuseport backlog=16384"})
    r = route(protocols=["http", "https"])
    h = one(route_http_protocol_allowed(r, ctx(n, r)))
    assert h.severity == "info"
    assert "Plaintext proxy listener present: no" in h.observation


def test_route_http_protocol_allowed_is_info_when_proxy_listen_is_off():
    # `off` disables the listener entirely. This rule does not filter proxy_listen by address class,
    # so it is the one place the `off` skip in _listen_entries is load-bearing: parsed as an address,
    # `off` has no ssl flag and reads as a live plaintext listener.
    n = node({"proxy_listen": "off"})
    r = route(protocols=["http", "https"])
    h = one(route_http_protocol_allowed(r, ctx(n, r)))
    assert h.severity == "info"
    assert "Plaintext proxy listener present: no" in h.observation


def test_route_http_protocol_allowed_records_trusted_ips_for_the_redirect_warning():
    r, n = route(protocols=["http", "https"]), node()
    h = one(route_http_protocol_allowed(r, ctx(n, r)))
    assert "trusted_ips = {}" in h.observation
    assert "trusted_ips" in h.remediation


# ══ KONG.ROUTE.NO_RATE_LIMITING ═══════════════════════════════════════════
def test_route_no_rate_limiting_fires_when_no_rl_plugin_resolves():
    r, s, n = route(), service(), node()
    h = one(route_no_rate_limiting(r, ctx(n, s, r)))
    assert h.severity == "medium"
    assert ROUTE_ID in h.observation


def test_route_no_rate_limiting_does_not_fire_with_a_service_scoped_rate_limiting():
    r, s, n = route(), service(), node()
    p = plugin("rate-limiting", config=rate_limiting_config(), service_id=SVC_ID)
    assert route_no_rate_limiting(r, ctx(n, s, r, p)) == []


def test_route_no_rate_limiting_does_not_fire_with_consumer_scoped_tiered_limiting():
    # rate-limiting's limit_by defaults to `consumer`; per-consumer tiering (service=null,
    # route=null, consumer set) is a pattern Kong's own docs promote and it does limit the route.
    r, s, n = route(), service(), node()
    p = plugin("rate-limiting", config=rate_limiting_config(), consumer_id=CONSUMER_ID)
    assert route_no_rate_limiting(r, ctx(n, s, r, p)) == []


def test_route_no_rate_limiting_does_not_fire_with_rate_limiting_advanced():
    r, s, n = route(), service(), node()
    p = plugin("rate-limiting-advanced",
               config={"limit": [100], "window_size": [60], "strategy": "redis"},
               service_id=SVC_ID)
    assert route_no_rate_limiting(r, ctx(n, s, r, p)) == []


def test_route_no_rate_limiting_does_not_fire_for_a_configured_extra_rl_plugin():
    r, s, n = route(), service(), node()
    p = plugin("acme-throttle", config={}, service_id=SVC_ID)
    c = ctx(n, s, r, p, extra_rate_limit_plugins=["acme-throttle"])
    assert route_no_rate_limiting(r, c) == []


def test_route_no_rate_limiting_is_info_on_stream_routes():
    r, n = route(protocols=["tcp"], name="stream-route"), node()
    assert one(route_no_rate_limiting(r, ctx(n, r))).severity == "info"


# ══ KONG.RATELIMIT.FAIL_OPEN ══════════════════════════════════════════════
def test_ratelimit_fail_open_fires_on_redis_policy_with_fault_tolerant():
    p = plugin("rate-limiting", config=rate_limiting_config(policy="redis", fault_tolerant=True),
               service_id=SVC_ID)
    h = one(ratelimit_fail_open(p, ctx(node(), p)))
    assert h.severity == "low"
    assert "'redis'" in h.observation
    assert "fault_tolerant=true" in h.observation


def test_ratelimit_fail_open_does_not_fire_on_local_policy():
    # `local` counters live in the node's own shm — there is no datastore to lose.
    p = plugin("rate-limiting", config=rate_limiting_config(policy="local", fault_tolerant=True),
               service_id=SVC_ID)
    assert ratelimit_fail_open(p, ctx(node(), p)) == []


def test_ratelimit_fail_open_does_not_fire_when_fault_tolerant_is_false():
    p = plugin("rate-limiting", config=rate_limiting_config(policy="redis", fault_tolerant=False),
               service_id=SVC_ID)
    assert ratelimit_fail_open(p, ctx(node(), p)) == []


def test_ratelimit_fail_open_does_not_fire_on_rate_limiting_advanced():
    # It has no fault_tolerant parameter and does not fail open — it degrades to local limiting.
    p = plugin("rate-limiting-advanced",
               config={"limit": [100], "window_size": [60], "strategy": "redis",
                       "fault_tolerant": True},
               service_id=SVC_ID)
    assert ratelimit_fail_open(p, ctx(node(), p)) == []


def test_ratelimit_fail_open_is_info_on_cluster_policy():
    p = plugin("rate-limiting", config=rate_limiting_config(policy="cluster", fault_tolerant=True),
               service_id=SVC_ID)
    assert one(ratelimit_fail_open(p, ctx(node(), p))).severity == "info"


def test_ratelimit_fail_open_suppressed_by_a_local_limiter_at_the_same_scope():
    p = plugin("rate-limiting", id="rl-redis",
               config=rate_limiting_config(policy="redis", fault_tolerant=True), service_id=SVC_ID)
    backup = plugin("rate-limiting", id="rl-local",
                    config=rate_limiting_config(policy="local"), service_id=SVC_ID)
    assert ratelimit_fail_open(p, ctx(node(), p, backup)) == []


def test_ratelimit_fail_open_not_suppressed_by_a_local_limiter_at_a_different_scope():
    p = plugin("rate-limiting", id="rl-redis",
               config=rate_limiting_config(policy="redis", fault_tolerant=True), service_id=SVC_ID)
    elsewhere = plugin("rate-limiting", id="rl-local",
                       config=rate_limiting_config(policy="local"), route_id=OTHER_ROUTE_ID)
    assert len(ratelimit_fail_open(p, ctx(node(), p, elsewhere))) == 1


# ══ KONG.CORS.WILDCARD_WITH_CREDENTIALS ═══════════════════════════════════
def test_cors_wildcard_with_credentials_fires_on_star_origin():
    p = plugin("cors", config={"origins": ["*"], "credentials": True, "max_age": None},
               service_id=SVC_ID)
    h = one(cors_wildcard_with_credentials(p, ctx(node(), p)))
    assert h.severity is None                   # inherits the decorator's "high"
    assert "['*']" in h.observation
    assert "config.credentials=true" in h.observation


def test_cors_wildcard_with_credentials_does_not_fire_on_enumerated_origins():
    p = plugin("cors", config={"origins": ["https://app.example.com"], "credentials": True},
               service_id=SVC_ID)
    assert cors_wildcard_with_credentials(p, ctx(node(), p)) == []


def test_cors_wildcard_with_credentials_does_not_fire_without_credentials():
    p = plugin("cors", config={"origins": ["*"], "credentials": False}, service_id=SVC_ID)
    assert cors_wildcard_with_credentials(p, ctx(node(), p)) == []


def test_cors_wildcard_with_credentials_reads_the_credentials_boolean_unredacted():
    # Regression: a `credential` term in the connector's secret scrubber matched cors's
    # `credentials` boolean, redacted it, and silently killed this rule. `credentials` is exempt.
    p = plugin("cors", config={"origins": ["*"], "credentials": True}, service_id=SVC_ID)
    assert p.raw["config"]["credentials"] is True
    assert len(cors_wildcard_with_credentials(p, ctx(node(), p))) == 1


def test_cors_wildcard_with_credentials_fires_on_null_origins():
    p = plugin("cors", config={"origins": None, "credentials": True}, service_id=SVC_ID)
    assert "config.origins is null" in one(cors_wildcard_with_credentials(p, ctx(node(), p))).observation


def test_cors_wildcard_with_credentials_fires_on_empty_origins_array():
    # handler.lua allow-alls on n_origins == 0 — an empty array is identical to unset.
    p = plugin("cors", config={"origins": [], "credentials": True}, service_id=SVC_ID)
    assert "empty array []" in one(cors_wildcard_with_credentials(p, ctx(node(), p))).observation


def test_cors_wildcard_with_credentials_fires_on_star_among_several_origins():
    p = plugin("cors", config={"origins": ["https://app.example.com", "*"], "credentials": True},
               service_id=SVC_ID)
    assert len(cors_wildcard_with_credentials(p, ctx(node(), p))) == 1


def test_cors_wildcard_with_credentials_fires_on_a_match_anything_regex():
    p = plugin("cors", config={"origins": [".*"], "credentials": True}, service_id=SVC_ID)
    h = one(cors_wildcard_with_credentials(p, ctx(node(), p)))
    assert "match-anything regex" in h.observation


def test_cors_wildcard_with_credentials_downgrades_a_scoped_regex_to_info():
    # Kong anchors origins regexes at both ends, so '.*\.example\.com' is correctly scoped.
    p = plugin("cors", config={"origins": [r".*\.example\.com"], "credentials": True},
               service_id=SVC_ID)
    h = one(cors_wildcard_with_credentials(p, ctx(node(), p)))
    assert h.severity == "info"
    assert "did not evaluate what they match" in h.observation


def test_cors_wildcard_with_credentials_does_not_fire_when_disabled():
    p = plugin("cors", config={"origins": ["*"], "credentials": True}, enabled=False,
               service_id=SVC_ID)
    assert cors_wildcard_with_credentials(p, ctx(node(), p)) == []


# ══ KONG.ROUTE.WILDCARD_HOST_OR_PRESERVE_HOST ═════════════════════════════
def test_wildcard_host_fires_on_preserve_host_with_no_hosts():
    r, n = route(preserve_host=True, hosts=None), node()
    h = one(route_wildcard_host_preserve_host(r, ctx(n, r)))
    assert "preserve_host=true" in h.observation
    assert "hosts=None" in h.observation


def test_wildcard_host_does_not_fire_when_preserve_host_is_false():
    # hosts=null alone is the canonical path-only route KIC and decK generate — pure noise.
    r, n = route(preserve_host=False, hosts=None), node()
    assert route_wildcard_host_preserve_host(r, ctx(n, r)) == []


def test_wildcard_host_does_not_fire_with_an_explicit_non_wildcard_host_allowlist():
    r, n = route(preserve_host=True, hosts=["api.example.com"]), node()
    assert route_wildcard_host_preserve_host(r, ctx(n, r)) == []


def test_wildcard_host_fires_on_a_leading_wildcard_host():
    r, n = route(preserve_host=True, hosts=["*.example.com"]), node()
    h = one(route_wildcard_host_preserve_host(r, ctx(n, r)))
    assert "['*.example.com']" in h.observation


def test_wildcard_host_fires_on_a_trailing_wildcard_host():
    r, n = route(preserve_host=True, hosts=["api.*"]), node()
    assert len(route_wildcard_host_preserve_host(r, ctx(n, r))) == 1


def test_wildcard_host_does_not_fire_on_an_expressions_route_pinning_http_host():
    # validate_route rejects `expression` alongside hosts, so EVERY expressions-flavor route reports
    # hosts=null over the Admin API — unhandled, that is a false positive on all of them.
    r = route(preserve_host=True, hosts=None,
              expression='http.host == "api.example.com" && http.path ^= "/v1"')
    n = node()
    assert route_wildcard_host_preserve_host(r, ctx(n, r)) == []


def test_wildcard_host_fires_on_an_expressions_route_that_does_not_pin_host():
    r = route(preserve_host=True, hosts=None, expression='http.path ^= "/v1"')
    n = node()
    assert len(route_wildcard_host_preserve_host(r, ctx(n, r))) == 1


# ══ KONG.ROUTE.NO_REQUEST_SIZE_LIMIT ══════════════════════════════════════
def test_no_request_size_limit_fires_when_nginx_cap_is_the_default_zero():
    # The live node returns the *string* "0", and kong.conf.default documents 0 as "disables
    # checking the request body size" — an unset cap is the absence of a bound, not a bound.
    r, s, n = route(), service(), node()
    h = one(route_no_request_size_limit(r, ctx(n, s, r)))
    assert h.severity == "low"
    assert "'0'" in h.observation
    assert "effectively unbounded" in h.observation


def test_no_request_size_limit_does_not_fire_with_a_request_size_limiting_plugin():
    r, s, n = route(), service(), node()
    p = plugin("request-size-limiting",
               config={"allowed_payload_size": 8, "size_unit": "megabytes",
                       "require_content_length": False},
               service_id=SVC_ID)
    assert route_no_request_size_limit(r, ctx(n, s, r, p)) == []


def test_no_request_size_limit_does_not_fire_on_stream_routes():
    r, n = route(protocols=["tcp"], name="stream-route"), node()
    assert route_no_request_size_limit(r, ctx(n, r)) == []


def test_no_request_size_limit_is_info_when_nginx_caps_the_body():
    n = node({"nginx_http_client_max_body_size": "10m"})
    r, s = route(), service()
    h = one(route_no_request_size_limit(r, ctx(n, s, r)))
    assert h.severity == "info"
    assert "'10m'" in h.observation
    assert "largely redundant" in h.observation


def test_no_request_size_limit_treats_integer_zero_as_uncapped():
    n = node({"nginx_http_client_max_body_size": 0})
    r, s = route(), service()
    assert one(route_no_request_size_limit(r, ctx(n, s, r))).severity == "low"


# ══ KONG.PLUGIN.SECURITY_PLUGIN_DISABLED ══════════════════════════════════
def test_security_plugin_disabled_fires_on_a_disabled_auth_plugin():
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), enabled=False, service_id=SVC_ID)
    h = one(plugin_security_disabled(p, ctx(node(), p)))
    assert h.severity == "medium"
    assert "enabled=false" in h.observation
    assert "Tier: access control" in h.observation


def test_security_plugin_disabled_does_not_fire_on_an_enabled_plugin():
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), enabled=True, service_id=SVC_ID)
    assert plugin_security_disabled(p, ctx(node(), p)) == []


def test_security_plugin_disabled_does_not_fire_on_a_disabled_cors_plugin():
    # CORS *relaxes* the same-origin policy. Disabling it makes the browser more restrictive, so
    # flagging it would invert the security model.
    p = plugin("cors", config={"origins": ["*"], "credentials": True}, enabled=False,
               service_id=SVC_ID)
    assert plugin_security_disabled(p, ctx(node(), p)) == []


def test_security_plugin_disabled_does_not_fire_on_a_non_security_plugin():
    p = plugin("correlation-id", config={"header_name": "Kong-Request-ID"}, enabled=False,
               service_id=SVC_ID)
    assert plugin_security_disabled(p, ctx(node(), p)) == []


def test_security_plugin_disabled_suppressed_by_an_enabled_global_instance():
    p = plugin("key-auth", id="ka-off", config=dict(KEY_AUTH_CONFIG), enabled=False,
               service_id=SVC_ID)
    globally = plugin("key-auth", id="ka-on", config=dict(KEY_AUTH_CONFIG), enabled=True)
    assert plugin_security_disabled(p, ctx(node(), p, globally)) == []


def test_security_plugin_disabled_suppressed_by_an_enabled_instance_at_the_same_scope():
    p = plugin("key-auth", id="ka-off", config=dict(KEY_AUTH_CONFIG), enabled=False,
               service_id=SVC_ID)
    same = plugin("key-auth", id="ka-on", config=dict(KEY_AUTH_CONFIG), enabled=True,
                  service_id=SVC_ID)
    assert plugin_security_disabled(p, ctx(node(), p, same)) == []


def test_security_plugin_disabled_not_suppressed_by_a_different_plugin_name():
    p = plugin("key-auth", id="ka-off", config=dict(KEY_AUTH_CONFIG), enabled=False,
               service_id=SVC_ID)
    other = plugin("jwt", id="jwt-on", config={"anonymous": None}, enabled=True)
    assert len(plugin_security_disabled(p, ctx(node(), p, other))) == 1


def test_security_plugin_disabled_ranks_availability_plugins_at_low():
    p = plugin("rate-limiting", config=rate_limiting_config(), enabled=False, service_id=SVC_ID)
    h = one(plugin_security_disabled(p, ctx(node(), p)))
    assert h.severity == "low"
    assert "Tier: availability" in h.observation


def test_security_plugin_disabled_ranks_network_plugins_at_medium():
    p = plugin("ip-restriction", config={"allow": ["10.0.0.0/8"], "deny": None}, enabled=False,
               service_id=SVC_ID)
    h = one(plugin_security_disabled(p, ctx(node(), p)))
    assert h.severity == "medium"
    assert "Tier: network" in h.observation


# ══ KONG.CONSUMER.NO_CREDENTIALS ══════════════════════════════════════════
def test_consumer_no_credentials_fires_on_an_unreferenced_credential_less_consumer():
    c = consumer(credentials=creds())
    h = one(consumer_no_credentials(c, ctx(node(), c)))
    assert CONSUMER_ID in h.observation
    assert "'/key-auth'" in h.observation
    assert "mtls-auth returned 404" in h.observation


def test_consumer_no_credentials_does_not_fire_when_the_consumer_has_a_key():
    c = consumer(credentials=creds({"key-auth": 1}))
    assert consumer_no_credentials(c, ctx(node(), c)) == []


def test_consumer_no_credentials_does_not_fire_when_openid_connect_is_present():
    # Kong's documented external-identity-mapping pattern attaches ZERO local credentials, so this
    # would fire on 100% of consumers — and is not exemptible per-consumer.
    c = consumer(credentials=creds())
    oidc = plugin("openid-connect", config={"issuer": "https://idp.example.com"})
    assert consumer_no_credentials(c, ctx(node(), c, oidc)) == []


def test_consumer_no_credentials_does_not_fire_when_ldap_auth_advanced_is_present():
    c = consumer(credentials=creds())
    ldap = plugin("ldap-auth-advanced", config={"ldap_host": "ldap.example.com"})
    assert consumer_no_credentials(c, ctx(node(), c, ldap)) == []


def test_consumer_no_credentials_is_not_assessable_when_the_sweep_was_skipped():
    # No credentials key — nothing was observed. Returning [] here renders as "checked, this
    # consumer holds credentials", which is the opposite of what happened.
    c = consumer()
    h = one(consumer_no_credentials(c, ctx(node(), c)))
    assert h.assessable is False
    assert h.assessment_reason == "the per-consumer credential sweep did not run for this consumer"
    assert "no credential endpoint was queried" in h.observation


def test_consumer_no_credentials_is_not_assessable_when_every_endpoint_errored():
    # No endpoint answered 200 — absence of evidence is not evidence of absence.
    c = consumer(credentials={p: {"status": None, "error": "ReadTimeout: timed out"}
                              for p in CREDENTIAL_PATHS})
    h = one(consumer_no_credentials(c, ctx(node(), c)))
    assert h.assessable is False
    assert h.assessment_reason == "no credential endpoint answered 200 for this consumer"
    assert "/key-auth → None" in h.observation


def test_consumer_no_credentials_files_no_gap_for_a_consumer_the_config_references():
    # The reference exemptions are decided before the credential evidence: this consumer is
    # KONG.AUTH.ANONYMOUS_FALLBACK's to report whatever its credentials turn out to be, so an
    # unread sweep costs this rule nothing on it.
    c = consumer()
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    assert consumer_no_credentials(c, ctx(node(), c, p)) == []


def test_consumer_no_credentials_files_no_gap_when_external_identity_mapping_is_present():
    # Not a gap but a genuine N/A: openid-connect consumers legitimately carry zero credentials,
    # so there is nothing this rule wanted to read.
    c = consumer()
    oidc = plugin("openid-connect", config={"issuer": "https://idp.example.com"})
    assert consumer_no_credentials(c, ctx(node(), c, oidc)) == []


def test_consumer_no_credentials_does_not_fire_for_the_anonymous_consumer_by_id():
    c = consumer(credentials=creds())
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": CONSUMER_ID})
    assert consumer_no_credentials(c, ctx(node(), c, p)) == []


def test_consumer_no_credentials_does_not_fire_for_the_anonymous_consumer_by_username():
    c = consumer(credentials=creds())
    p = plugin("key-auth", config={**KEY_AUTH_CONFIG, "anonymous": "demo-consumer"})
    assert consumer_no_credentials(c, ctx(node(), c, p)) == []


def test_consumer_no_credentials_does_not_fire_when_a_consumer_scoped_plugin_targets_it():
    c = consumer(credentials=creds())
    p = plugin("rate-limiting", config=rate_limiting_config(), consumer_id=CONSUMER_ID)
    assert consumer_no_credentials(c, ctx(node(), c, p)) == []


def test_consumer_no_credentials_does_not_fire_for_a_consumer_group_member():
    c = consumer(credentials=creds(), consumer_groups={"status": 200, "names": ["gold-tier"]})
    assert consumer_no_credentials(c, ctx(node(), c)) == []


def test_consumer_no_credentials_does_not_fire_when_only_acls_are_attached():
    c = consumer(credentials=creds({"acls": 1}, groups=["internal"]))
    assert consumer_no_credentials(c, ctx(node(), c)) == []


# ══ KONG.VERSION.CVE_2026_6338_SMUGGLING ══════════════════════════════════
def test_cve_2026_6338_fires_below_the_floor_on_enterprise():
    n = node({"enforce_rbac": "on", "database": "postgres"}, version="3.10.0.5",
             edition="enterprise")
    h = one(cve_2026_6338(n, ctx(n)))
    assert "'3.10.0.5'" in h.observation
    assert "3.10.0.12" in h.observation


def test_cve_2026_6338_does_not_fire_at_the_fixed_floor():
    n = node({"database": "postgres"}, version="3.10.0.12", edition="enterprise")
    assert cve_2026_6338(n, ctx(n)) == []


def test_cve_2026_6338_does_not_fire_above_the_floor():
    n = node({"database": "postgres"}, version="3.12.0.9", edition="enterprise")
    assert cve_2026_6338(n, ctx(n)) == []


def test_cve_2026_6338_does_not_fire_on_oss_three_part_versions():
    # 3.4.x OSS is a real, still-deployed LTS line. Zero-padding '3.4.3' to '3.4.3.0' drops it
    # inside the affected range and fires on an unaffected community node.
    n = node(version="3.4.3", edition="community")
    assert cve_2026_6338(n, ctx(n)) == []


def test_cve_2026_6338_does_not_fire_on_current_oss():
    n = node(version="3.9.3", edition="community")
    assert cve_2026_6338(n, ctx(n)) == []


def test_cve_2026_6338_does_not_fire_on_an_unlisted_minor_series():
    n = node({"database": "postgres"}, version="3.9.0.0", edition="enterprise")
    assert cve_2026_6338(n, ctx(n)) == []


def test_cve_2026_6338_is_not_assessable_on_an_unparseable_version():
    # An unknown version is not a clean bill of health. Silence renders in the console as "not
    # vulnerable" — a claim this rule has no evidence for.
    n = node({"database": "postgres"}, version="3.10.0.5-rc1", edition="enterprise")
    h = one(cve_2026_6338(n, ctx(n)))
    assert h.assessable is False
    assert h.assessment_reason == ("Kong version string not parseable to a known Enterprise "
                                   "release")
    assert "'3.10.0.5-rc1'" in h.observation
    assert "3.10.0.12" in h.observation                 # the floors it could not be placed against


def test_cve_2026_6338_is_not_assessable_when_version_is_absent():
    n = node({"database": "postgres"}, version=None, edition="enterprise")
    h = one(cve_2026_6338(n, ctx(n)))
    assert h.assessable is False
    assert ".version=None" in h.observation


def test_cve_2026_6338_is_not_assessable_when_the_edition_is_unknown():
    # Without .edition the advisory's applicability is itself undetermined: 3.4.3.9 is affected on
    # Enterprise and the version scheme of no OSS release at all.
    n = node({"database": "postgres"}, version="3.4.3.9", edition=None)
    h = one(cve_2026_6338(n, ctx(n)))
    assert h.assessable is False
    assert ".edition=None" in h.observation


def test_cve_2026_6338_files_no_gap_for_a_series_no_floor_covers():
    # An old node that reports no edition is still ruled out by its version alone — 2.3.x is in no
    # affected series, so nothing about it was left undetermined.
    n = node({"database": "postgres"}, version="2.3.1", edition=None)
    assert cve_2026_6338(n, ctx(n)) == []


def test_cve_2026_6338_is_not_assessable_on_an_enterprise_node_reporting_a_three_part_version():
    # Enterprise versions are 4-part; a 3-part string cannot be compared against a 4-part floor.
    n = node({"database": "postgres"}, version="3.10.0", edition="enterprise")
    assert one(cve_2026_6338(n, ctx(n))).assessable is False


def test_cve_2026_6338_compares_components_numerically_not_lexicographically():
    # '3.4.3.9' < '3.4.3.26' numerically; a string compare inverts it and misses affected nodes.
    n = node({"database": "postgres"}, version="3.4.3.9", edition="enterprise")
    assert len(cve_2026_6338(n, ctx(n))) == 1


# ══ KONG.VERSION.CVE_2021_27306_JWT_BYPASS ════════════════════════════════
def test_cve_2021_27306_fires_on_oss_below_fix_with_jwt_enabled():
    n = node(version="2.3.1", edition="community")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    h = one(cve_2021_27306(n, ctx(n, p)))
    assert "'2.3.1'" in h.observation
    assert "2.3.2 (OSS)" in h.observation


def test_cve_2021_27306_does_not_fire_at_the_oss_fix_version():
    # Regression: 2.3.2 (OSS, 3-part) must not be compared against 2.3.2.0 (Enterprise, 4-part).
    # A naive comparator reads 2.3.2 < 2.3.2.0 as true and fires on the exact version that carries
    # the fix.
    n = node(version="2.3.2", edition="community")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_does_not_fire_at_the_enterprise_fix_version():
    n = node({"database": "postgres"}, version="2.3.2.0", edition="enterprise")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_fires_on_enterprise_below_fix():
    n = node({"database": "postgres"}, version="2.3.1.0", edition="enterprise")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    h = one(cve_2021_27306(n, ctx(n, p)))
    assert "2.3.2.0 (Enterprise)" in h.observation


def test_cve_2021_27306_does_not_fire_without_the_jwt_plugin():
    # No jwt plugin ⇒ no jwt bypass to have.
    n = node(version="2.3.1", edition="community")
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_does_not_fire_when_the_jwt_plugin_is_disabled():
    n = node(version="2.3.1", edition="community")
    p = plugin("jwt", config={"anonymous": None}, enabled=False, service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_does_not_fire_on_a_current_oss_node():
    n = node(version="3.9.3", edition="community")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_is_not_assessable_on_an_unparseable_version():
    # An enabled jwt plugin on a node whose version cannot be placed is precisely the combination
    # this rule exists to catch; reporting nothing renders it as not vulnerable.
    n = node(version="2.3.1-alpha", edition="community")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    h = one(cve_2021_27306(n, ctx(n, p)))
    assert h.assessable is False
    assert h.assessment_reason == "Kong version string not parseable to a known release"
    assert "'2.3.1-alpha'" in h.observation
    assert "2.3.2 (OSS)" in h.observation


def test_cve_2021_27306_is_not_assessable_when_the_version_is_absent():
    n = node(version=None, edition="community")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    assert one(cve_2021_27306(n, ctx(n, p))).assessable is False


def test_cve_2021_27306_files_no_gap_when_no_jwt_plugin_is_enabled():
    # Nothing was left undetermined: without the jwt plugin there is no bypass to have on any
    # version, so an unreadable version costs this rule nothing.
    n = node(version=None, edition="community")
    p = plugin("key-auth", config=dict(KEY_AUTH_CONFIG), service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_files_no_gap_for_a_version_above_the_fix_in_both_schemes():
    # 3.10.0.5 is 4-part on a node reporting no edition. The scheme is ambiguous, the verdict is
    # not: it is above 2.3.2 and 2.3.2.0 alike.
    n = node(version="3.10.0.5", edition=None)
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    assert cve_2021_27306(n, ctx(n, p)) == []


def test_cve_2021_27306_is_not_assessable_on_an_enterprise_node_reporting_a_three_part_version():
    n = node({"database": "postgres"}, version="2.3.1", edition="enterprise")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    h = one(cve_2021_27306(n, ctx(n, p)))
    assert h.assessable is False
    assert "2.3.2.0 (Enterprise)" in h.observation


def test_cve_2021_27306_states_its_unverified_preconditions():
    # The rule checks neither precondition; the observation must say so rather than implying
    # exploitability it did not establish.
    n = node(version="2.3.1", edition="community")
    p = plugin("jwt", config={"anonymous": None}, service_id=SVC_ID)
    h = one(cve_2021_27306(n, ctx(n, p)))
    assert "Unverified preconditions" in h.observation
    assert "This rule checks neither." in h.observation
