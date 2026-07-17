"""Offline unit tests for the RabbitMQ rulepack.

Payload shapes come from docs/research/platform-apis.md §3 (captured live from
rabbitmq:4-management 4.3.2). No network, no DB — a Resource is built by hand and handed
straight to the detector.

Every detector gets a fires-on-bad AND a silent-on-good pair. The negative is the load-bearing
one: a rule that cannot pass carries no information, and the whole point of this rulepack's
"decline to assess on a missing key" discipline is that it must still PASS on a good broker
rather than fire on everything.

`date.today()` is frozen at the rulepack's own _EOL_AS_OF. Without that, the EOL grading tests
start failing on 2026-07-31 when the 4.2 series crosses community EOL — a suite that rots into
red on a calendar date is worse than no suite.
"""
from datetime import date

import pytest

from vectasec.contracts import Resource, ScanContext
from vectasec.detect import rabbitmq as rmq

NODE1 = "rabbit@node1"

# Mirrored from connect/rabbitmq.py._TOGGLES rather than imported: importing the connector
# package drags in httpx and confluent-kafka via connect/__init__, and these tests are offline.
_TOGGLE_KEYS = (
    "proxy_terminates_tls", "transparent_tls_mesh", "backported_build",
    "external_auth_backend", "environment_scope", "provisioning_accounts",
    "managed_provider", "reachability_signal",
)


@pytest.fixture(autouse=True)
def _frozen_today(monkeypatch):
    class _Date(date):
        @classmethod
        def today(cls):
            return rmq._EOL_AS_OF

    monkeypatch.setattr(rmq, "date", _Date)


# ── Builders ──────────────────────────────────────────────────────────────
def toggles(**over):
    t = {k: None for k in _TOGGLE_KEYS}
    t.update(over)
    return t


def amqp_tls_listener(node=NODE1, **over):
    listener = {
        "node": node, "protocol": "amqp/ssl", "ip_address": "::", "port": 5671,
        # start_ssl_listener/4 registers a FLAT proplist for amqp/ssl — no ssl_opts nesting.
        "socket_opts": {
            "backlog": 128, "nodelay": True, "linger": [True, 0], "exit_on_close": False,
            "cacertfile": "/etc/rabbitmq/ca.pem", "certfile": "/etc/rabbitmq/cert.pem",
            "keyfile": "/etc/rabbitmq/key.pem",
            "verify": "verify_peer", "fail_if_no_peer_cert": True,
        },
        "tls": True,
    }
    listener.update(over)
    return listener


def amqp_plain_listener(node=NODE1, ip="::", **over):
    listener = {
        "node": node, "protocol": "amqp", "ip_address": ip, "port": 5672,
        "socket_opts": {"backlog": 128, "nodelay": True, "linger": [True, 0],
                        "exit_on_close": False},
        "tls": False,
    }
    listener.update(over)
    return listener


def clustering_listener(node=NODE1, ip="::", **over):
    # socket_opts is a bare [] on a clustering listener, not a dict — the shape helpers must
    # survive that.
    listener = {"node": node, "protocol": "clustering", "ip_address": ip, "port": 25672,
                "socket_opts": [], "tls": False}
    listener.update(over)
    return listener


def mgmt_context_plain(node=NODE1, **over):
    context = {"node": node, "description": "RabbitMQ Management", "path": "/",
               "cowboy_opts": "[{sendfile,false}]", "port": "15672", "ssl_opts": []}
    context.update(over)
    return context


def mgmt_context_tls(node=NODE1, **over):
    # web_context/1 puts ssl_opts at the TOP level of a context, not under socket_opts.
    context = {"node": node, "description": "RabbitMQ Management", "path": "/",
               "cowboy_opts": "[{sendfile,false}]", "port": "15671", "ssl": True,
               "ssl_opts": {"cacertfile": "/etc/rabbitmq/ca.pem",
                            "certfile": "/etc/rabbitmq/cert.pem",
                            "keyfile": "/etc/rabbitmq/key.pem",
                            "verify": "verify_peer"}}
    context.update(over)
    return context


def mechs(anonymous=False, external=False):
    return [
        {"name": "AMQPLAIN", "description": "QPid AMQPLAIN mechanism", "enabled": True},
        {"name": "PLAIN", "description": "SASL PLAIN authentication mechanism", "enabled": True},
        {"name": "ANONYMOUS", "description": "SASL ANONYMOUS authentication mechanism",
         "enabled": anonymous},
        {"name": "EXTERNAL", "description": "TLS peer verification based authentication mechanism",
         "enabled": external},
        {"name": "RABBIT-CR-DEMO",
         "description": "RabbitMQ Demo challenge-response authentication mechanism",
         "enabled": False},
    ]


def overview(**over):
    """A hardened broker: TLS AMQP with peer verification, private-bound clustering, HTTPS mgmt."""
    ov = {
        "management_version": "4.3.2",
        "rabbitmq_version": "4.3.2",
        "product_version": "4.3.2",
        "product_name": "RabbitMQ",
        "erlang_version": "27.3.4.14",
        "node": NODE1,
        "cluster_name": "rabbit@prod",
        "disable_stats": False,
        "object_totals": {"channels": 0, "consumers": 0, "exchanges": 8, "queues": 0,
                          "connections": 0},
        "queue_totals": {},
        "listeners": [amqp_tls_listener(), clustering_listener(ip="10.0.1.5")],
        "contexts": [mgmt_context_tls()],
    }
    ov.update(over)
    return ov


def cluster(**over):
    raw = {
        "role": "cluster",
        "url": "https://rabbit.example:15671",
        "overview": overview(),
        "overview_error": None,
        "nodes_error": None,
        "users_error": None,
        "vhosts_error": None,
        "permissions_error": None,
        "node_versions": {NODE1: "4.3.2"},
        "probes": {
            "auth": {"status": 404, "error": "http_404"},
            "guest_whoami": {"status": 401, "reason": "Not_Authorized"},
        },
        "scanner": {
            "scheme": "http",
            "tls_verified": False,
            "source_is_loopback": False,
            "whoami": {"name": "vectasec", "tags": ["administrator"]},
        },
        "toggles": toggles(),
    }
    raw.update(over)
    return Resource(kind="node", name="rabbit@prod", ext_id="cluster",
                    labels={"role": "cluster"}, raw=raw)


def node(name=NODE1, auth_mechanisms=None, **over):
    raw = {
        "role": "node",
        "name": name,
        "running": True,
        "type": "disc",
        "auth_mechanisms": mechs() if auth_mechanisms is None else auth_mechanisms,
        "rabbitmq_version": "4.3.2",
        "partitions": [],
        "enabled_plugins": ["rabbitmq_management", "rabbitmq_prometheus"],
        "being_drained": False,
        "config_files": ["/etc/rabbitmq/conf.d/10-defaults.conf"],
    }
    raw.update(over)
    return Resource(kind="node", name=name, ext_id=f"node-{name}",
                    labels={"role": "node"}, raw=raw)


def user(name, tags=(), algorithm="rabbit_password_hashing_sha256",
         has_internal_password=True, default_password_confirmed=None):
    tags = list(tags)
    return Resource(kind="user", name=name, ext_id=f"user-{name}",
                    labels={"tags": ",".join(tags)},
                    raw={"name": name, "tags": tags, "hashing_algorithm": algorithm,
                         "has_internal_password": has_internal_password,
                         "default_password_confirmed": default_password_confirmed,
                         "limits": {}})


def vhost(name="/", **over):
    raw = {"name": name, "tracing": False, "description": "Default virtual host", "tags": [],
           "default_queue_type": "classic", "cluster_state": {NODE1: "running"},
           "protected_from_deletion": False}
    raw.update(over)
    return Resource(kind="vhost", name=name, ext_id=f"vhost-{name}", raw=raw)


def permission(user_name, vhost_name="/", configure=".*", write=".*", read=".*"):
    return Resource(kind="permission", name=f"{user_name}@{vhost_name}",
                    ext_id=f"permission-{vhost_name}-{user_name}", namespace=vhost_name,
                    labels={"user": user_name, "vhost": vhost_name},
                    raw={"user": user_name, "vhost": vhost_name, "configure": configure,
                         "write": write, "read": read})


def ctx_of(*resources):
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def one(hits):
    """A detector must return at most one Hit per resource — fingerprint(tenant, rule, ext_id)
    collapses extras into a single finding row, so a second Hit is silently lost evidence."""
    assert len(hits) == 1, f"expected exactly one Hit, got {len(hits)}: {hits}"
    return hits[0]


def guest_probe_200(tags=("administrator",)):
    return {"status": 200, "reason": None, "name": "guest", "tags": list(tags),
            "is_internal_user": True}


def auth_probe_disclosing():
    return {"status": 200, "oauth_client_secret_present": True, "oauth_enabled": True,
            "oauth_client_id": "rabbit_client_code",
            "keys": ["oauth_client_id", "oauth_enabled", "oauth_provider_url"]}


def probes(auth=None, guest_whoami=None):
    return {"auth": auth or {"status": 404, "error": "http_404"},
            "guest_whoami": guest_whoami or {"status": 401, "reason": "Not_Authorized"}}


# ── RABBITMQ.CVE.OAUTH_SECRET_DISCLOSURE ──────────────────────────────────
def test_oauth_secret_disclosure_fires_on_unauthenticated_200_with_a_secret():
    c = cluster(probes=probes(auth=auth_probe_disclosing()))
    hit = one(rmq.oauth_secret_disclosure(c, ctx_of(c)))
    assert "HTTP 200" in hit.observation
    assert "rabbit_client_code" in hit.observation          # the observed client id
    assert "oauth_provider_url" in hit.observation          # the observed response key list
    assert "'4.3.2'" in hit.observation                     # the observed version
    assert hit.source_ref["cve"] == "CVE-2026-57219"


def test_oauth_secret_disclosure_silent_when_endpoint_is_patched_away():
    c = cluster()   # default probe is the 404 a patched broker returns
    assert rmq.oauth_secret_disclosure(c, ctx_of(c)) == []


def test_oauth_secret_disclosure_silent_when_200_carries_no_secret():
    # filter_empty_properties/1 omits the key when unset: 200 alone is not a disclosure.
    c = cluster(probes=probes(auth={"status": 200, "oauth_client_secret_present": False,
                                    "oauth_enabled": False, "oauth_client_id": None,
                                    "keys": []}))
    assert rmq.oauth_secret_disclosure(c, ctx_of(c)) == []


def test_oauth_secret_disclosure_fires_without_a_readable_version():
    # A 200 with a non-empty secret is dispositive; an unreadable version must not suppress it.
    c = cluster(overview=None, overview_error="http_401",
                probes=probes(auth=auth_probe_disclosing()))
    hit = one(rmq.oauth_secret_disclosure(c, ctx_of(c)))
    assert "not corroborated" in hit.observation


def test_oauth_secret_disclosure_ignores_per_node_resources():
    n = node()
    assert rmq.oauth_secret_disclosure(n, ctx_of(cluster(), n)) == []


# ── RABBITMQ.USER.GUEST_REMOTE_LOGIN ──────────────────────────────────────
def test_guest_remote_login_fires_on_200_from_a_remote_source():
    c = cluster(probes=probes(guest_whoami=guest_probe_200()))
    hit = one(rmq.guest_remote_login(c, ctx_of(c)))
    assert '"name": "guest"' in hit.observation
    assert '"tags": ["administrator"]' in hit.observation
    assert '"is_internal_user": true' in hit.observation


def test_guest_remote_login_echoes_the_observed_tags_rather_than_assuming_administrator():
    c = cluster(probes=probes(guest_whoami=guest_probe_200(tags=("management",))))
    hit = one(rmq.guest_remote_login(c, ctx_of(c)))
    assert '"tags": ["management"]' in hit.observation
    assert "administrator" not in hit.observation


def test_guest_remote_login_silent_on_401():
    c = cluster()
    assert rmq.guest_remote_login(c, ctx_of(c)) == []


def test_guest_remote_login_silent_when_the_probe_was_skipped():
    # Scanning from the broker host produces a guaranteed false negative, so the connector
    # skips the probe and reports no status at all.
    c = cluster(probes=probes(guest_whoami={"skipped": "scanner source address is loopback"}))
    assert rmq.guest_remote_login(c, ctx_of(c)) == []


# ── RABBITMQ.USER.GUEST_DEFAULT_PASSWORD_REMOTE ───────────────────────────
def test_guest_default_password_remote_fires_on_the_not_management_user_401():
    c = cluster(probes=probes(guest_whoami={"status": 401, "reason": "Not management user"}))
    hit = one(rmq.guest_default_password_remote(c, ctx_of(c)))
    assert "Not management user" in hit.observation
    assert "HTTP 401" in hit.observation


def test_guest_default_password_remote_silent_on_a_wrong_password_401():
    # Not_Authorized is the password check failing — the exact case this rule must not claim.
    c = cluster()
    assert rmq.guest_default_password_remote(c, ctx_of(c)) == []


def test_guest_default_password_remote_silent_on_200():
    # GUEST_REMOTE_LOGIN owns the 200; firing both would double-report one broker.
    c = cluster(probes=probes(guest_whoami=guest_probe_200()))
    assert rmq.guest_default_password_remote(c, ctx_of(c)) == []


# ── RABBITMQ.USER.DEFAULT_GUEST_PRESENT ───────────────────────────────────
def test_default_guest_present_fires_at_medium_on_presence_alone():
    c = cluster(toggles=toggles(environment_scope="production"))
    g = user("guest", tags=["administrator"], default_password_confirmed=False)
    hit = one(rmq.default_guest_present(g, ctx_of(c, g)))
    assert hit.severity is None        # the decorator's medium stands
    assert 'name="guest"' in hit.observation
    assert "rabbit_password_hashing_sha256" in hit.observation
    assert "no longer the default" in hit.observation


def test_default_guest_present_escalates_to_critical_on_a_confirmed_default_password():
    c = cluster(toggles=toggles(environment_scope="production"))
    g = user("guest", tags=["administrator"], default_password_confirmed=True)
    hit = one(rmq.default_guest_present(g, ctx_of(c, g)))
    assert hit.severity == "critical"
    assert "confirms the password is still the default" in hit.observation


def test_default_guest_present_escalates_to_critical_on_a_confirmed_remote_login():
    c = cluster(toggles=toggles(environment_scope="production"),
                probes=probes(guest_whoami=guest_probe_200()))
    g = user("guest", tags=["administrator"], default_password_confirmed=None)
    hit = one(rmq.default_guest_present(g, ctx_of(c, g)))
    assert hit.severity == "critical"
    assert "loopback restriction is not in effect" in hit.observation


def test_default_guest_present_does_not_escalate_on_the_administrator_tag_alone():
    # administrator is guest's DEFAULT tag — escalating on it would be "critical whenever guest
    # exists" wearing a conditional.
    c = cluster(toggles=toggles(environment_scope="production"))
    g = user("guest", tags=["administrator"], default_password_confirmed=None)
    hit = one(rmq.default_guest_present(g, ctx_of(c, g)))
    assert hit.severity is None


def test_default_guest_present_silent_outside_production_scope():
    c = cluster(toggles=toggles(environment_scope="staging"))
    g = user("guest", tags=["administrator"], default_password_confirmed=True)
    assert rmq.default_guest_present(g, ctx_of(c, g)) == []


def test_default_guest_present_silent_for_a_non_guest_user():
    c = cluster(toggles=toggles(environment_scope="production"))
    u = user("app1")
    assert rmq.default_guest_present(u, ctx_of(c, u)) == []


# ── RABBITMQ.USER.WEAK_PASSWORD_HASHING ───────────────────────────────────
def test_weak_password_hashing_fires_on_md5():
    u = user("legacy-app", algorithm="rabbit_password_hashing_md5")
    hit = one(rmq.weak_password_hashing(u, ctx_of(cluster(), u)))
    assert "rabbit_password_hashing_md5" in hit.observation
    assert "legacy-app" in hit.observation
    assert hit.severity is None


def test_weak_password_hashing_silent_on_sha256():
    u = user("app1")
    assert rmq.weak_password_hashing(u, ctx_of(cluster(), u)) == []


def test_weak_password_hashing_silent_on_sha512():
    u = user("app1", algorithm="rabbit_password_hashing_sha512")
    assert rmq.weak_password_hashing(u, ctx_of(cluster(), u)) == []


def test_weak_password_hashing_silent_when_the_password_is_cleared():
    # An empty password_hash is how a password is cleared: the user authenticates against an
    # external backend and nothing is hashed here, so the algorithm is irrelevant.
    u = user("ldap-user", algorithm="rabbit_password_hashing_md5", has_internal_password=False)
    assert rmq.weak_password_hashing(u, ctx_of(cluster(), u)) == []


def test_weak_password_hashing_reports_a_plugin_module_as_info_not_a_failure():
    # hashing_mod(CustomMod) permits plugin modules that may be STRONGER than sha256.
    u = user("app1", algorithm="rabbit_password_hashing_argon2")
    hit = one(rmq.weak_password_hashing(u, ctx_of(cluster(), u)))
    assert hit.severity == "info"
    assert "rabbit_password_hashing_argon2" in hit.observation


# ── RABBITMQ.USER.ADMIN_TAG_SPRAWL ────────────────────────────────────────
def test_admin_tag_sprawl_fires_when_admins_exceed_both_thresholds():
    c = cluster()
    users = [user("vectasec", tags=["administrator"]),
             user("admin1", tags=["administrator"]), user("admin2", tags=["administrator"]),
             user("admin3", tags=["administrator"]),
             user("app1"), user("app2")]
    hit = one(rmq.admin_tag_sprawl(c, ctx_of(c, *users)))
    assert "returned 6 users" in hit.observation
    assert "3 carry tags" in hit.observation
    assert "admin1, admin2, admin3" in hit.observation
    assert "50%" in hit.observation
    assert "'vectasec'" in hit.observation      # the excluded scanning identity is named


def test_admin_tag_sprawl_excludes_the_scanning_identity_from_the_count():
    # /api/users is administrator-gated, so the scanner MUST carry administrator and would
    # otherwise inflate its own count. 2 real admins + scanner must not fire.
    c = cluster()
    users = [user("vectasec", tags=["administrator"]),
             user("admin1", tags=["administrator"]), user("admin2", tags=["administrator"]),
             user("app1"), user("app2"), user("app3")]
    assert rmq.admin_tag_sprawl(c, ctx_of(c, *users)) == []


def test_admin_tag_sprawl_silent_on_a_small_broker():
    c = cluster()
    users = [user("vectasec", tags=["administrator"]), user("admin1", tags=["administrator"]),
             user("admin2", tags=["administrator"]), user("app1")]
    assert rmq.admin_tag_sprawl(c, ctx_of(c, *users)) == []


def test_admin_tag_sprawl_silent_when_the_ratio_is_low():
    # AND, not OR: 3 admins out of 20 users is a normal operator set.
    c = cluster()
    users = [user("vectasec", tags=["administrator"])]
    users += [user(f"admin{i}", tags=["administrator"]) for i in range(1, 4)]
    users += [user(f"app{i}") for i in range(1, 17)]
    assert rmq.admin_tag_sprawl(c, ctx_of(c, *users)) == []


def test_admin_tag_sprawl_silent_on_an_external_auth_broker():
    # /api/users then holds only break-glass accounts, legitimately all admin-tagged.
    c = cluster(toggles=toggles(external_auth_backend=True))
    users = [user("vectasec", tags=["administrator"])]
    users += [user(f"admin{i}", tags=["administrator"]) for i in range(1, 6)]
    assert rmq.admin_tag_sprawl(c, ctx_of(c, *users)) == []


def test_admin_tag_sprawl_silent_when_users_were_unreadable():
    c = cluster(users_error="http_401")
    assert rmq.admin_tag_sprawl(c, ctx_of(c)) == []


def test_admin_tag_sprawl_downgrades_to_info_on_a_managed_provider():
    c = cluster(toggles=toggles(managed_provider="amazonmq"))
    users = [user("vectasec", tags=["administrator"]),
             user("admin1", tags=["administrator"]), user("admin2", tags=["administrator"]),
             user("admin3", tags=["administrator"]),
             user("app1"), user("app2")]
    hit = one(rmq.admin_tag_sprawl(c, ctx_of(c, *users)))
    assert hit.severity == "info"


def test_admin_tag_sprawl_states_when_the_scanner_could_not_be_identified():
    c = cluster(scanner={"scheme": "http", "tls_verified": False, "source_is_loopback": False,
                         "whoami": None})
    users = [user("admin1", tags=["administrator"]), user("admin2", tags=["administrator"]),
             user("admin3", tags=["administrator"]), user("app1"), user("app2")]
    hit = one(rmq.admin_tag_sprawl(c, ctx_of(c, *users)))
    assert "NOT excluded from this count" in hit.observation


# ── RABBITMQ.PERMISSION.WILDCARD_ALL ──────────────────────────────────────
def test_permission_wildcard_all_fires_at_medium_in_a_shared_vhost():
    c = cluster()
    u1, u2 = user("app1"), user("app2")
    p1, p2 = permission("app1"), permission("app2")
    hit = one(rmq.permission_wildcard_all(p1, ctx_of(c, u1, u2, p1, p2)))
    assert hit.severity is None            # decorator medium stands
    assert '"user": "app1"' in hit.observation
    assert '"configure": ".*"' in hit.observation
    assert '"write": ".*"' in hit.observation
    assert '"read": ".*"' in hit.observation
    assert "2 non-administrator principals" in hit.observation
    assert "crosses a trust boundary" in hit.observation


def test_permission_wildcard_all_downgrades_to_info_in_a_single_tenant_vhost():
    # vhost-per-application is the dominant pattern; the vhost IS the isolation boundary.
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1", vhost_name="app1-vhost")
    hit = one(rmq.permission_wildcard_all(p1, ctx_of(c, u1, p1)))
    assert hit.severity == "info"
    assert "blast radius is the vhost itself" in hit.observation


def test_permission_wildcard_all_silent_for_an_administrator():
    c = cluster()
    u1 = user("ops", tags=["administrator"])
    p1 = permission("ops")
    assert rmq.permission_wildcard_all(p1, ctx_of(c, u1, p1)) == []


def test_permission_wildcard_all_silent_on_a_scoped_grant():
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1", configure="^app1-.*$", write="^app1-.*$", read="^app1-.*$")
    assert rmq.permission_wildcard_all(p1, ctx_of(c, u1, p1)) == []


def test_permission_wildcard_all_silent_when_only_two_of_three_are_wildcards():
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1", configure="^$")
    assert rmq.permission_wildcard_all(p1, ctx_of(c, u1, p1)) == []


def test_permission_wildcard_all_fires_on_the_anchored_wildcard_spelling():
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1", configure="^.*$", write="^.*$", read="^.*$")
    assert len(rmq.permission_wildcard_all(p1, ctx_of(c, u1, p1))) == 1


def test_permission_wildcard_all_silent_for_an_unknown_principal():
    # /api/users lists only the internal data store, so an LDAP/OAuth principal legitimately
    # holds permissions with no user record. Its tags are unknown, not empty — reading absence
    # as "not an administrator" is the same error PERMISSION.CONFIGURE_WILDCARD guards against.
    c = cluster()
    p1 = permission("ldap-app")
    assert rmq.permission_wildcard_all(p1, ctx_of(c, p1)) == []


def test_permission_wildcard_all_never_claims_tags_it_could_not_read():
    # Regression: the observation is the immutable ledger entry and the only thing the AI may
    # cite. Asserting "GET /api/users shows that user with tags=[]" when that endpoint 401'd is
    # a fabricated fact, not a fact read from the target.
    c = cluster(users_error="http_401")
    p1 = permission("app1")
    for hit in rmq.permission_wildcard_all(p1, ctx_of(c, p1)):
        assert "tags=[]" not in hit.observation


def test_permission_wildcard_all_does_not_suppress_on_policymaker():
    # policymaker is orthogonal to resource permissions: it grants policy/parameter management.
    c = cluster()
    u1, u2 = user("app1", tags=["policymaker"]), user("app2")
    p1, p2 = permission("app1"), permission("app2")
    assert len(rmq.permission_wildcard_all(p1, ctx_of(c, u1, u2, p1, p2))) == 1


# ── RABBITMQ.PERMISSION.CONFIGURE_WILDCARD ────────────────────────────────
def test_permission_configure_wildcard_fires_on_a_wildcard_configure_with_scoped_write_read():
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1", configure=".*", write="^app1-.*$", read="^app1-.*$")
    hit = one(rmq.permission_configure_wildcard(p1, ctx_of(c, u1, p1)))
    assert '"configure": ".*"' in hit.observation
    assert '"write": "^app1-.*$"' in hit.observation
    assert "tags=[]" in hit.observation
    # queue.bind/exchange.bind need write+read, not configure — the rule must not claim bindings.
    assert "binding" not in hit.observation


def test_permission_configure_wildcard_silent_when_all_three_are_wildcards():
    # RABBITMQ.PERMISSION.WILDCARD_ALL owns that (user, vhost) pair.
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1")
    assert rmq.permission_configure_wildcard(p1, ctx_of(c, u1, p1)) == []


def test_permission_configure_wildcard_silent_on_a_scoped_configure():
    c = cluster()
    u1 = user("app1")
    p1 = permission("app1", configure="^app1-.*$", write=".*", read=".*")
    assert rmq.permission_configure_wildcard(p1, ctx_of(c, u1, p1)) == []


@pytest.mark.parametrize("tag", ["administrator", "policymaker"])
def test_permission_configure_wildcard_silent_for_management_tagged_users(tag):
    c = cluster()
    u1 = user("ops", tags=[tag])
    p1 = permission("ops", configure=".*", write="^ops-.*$", read="^ops-.*$")
    assert rmq.permission_configure_wildcard(p1, ctx_of(c, u1, p1)) == []


def test_permission_configure_wildcard_silent_for_an_unknown_principal():
    # "Absent from /api/users" is NOT "has no tags": an LDAP/OAuth principal legitimately holds
    # permissions with no internal user record, so its tags are unknown, not empty.
    c = cluster()
    p1 = permission("ldap-app", configure=".*", write="^x-.*$", read="^x-.*$")
    assert rmq.permission_configure_wildcard(p1, ctx_of(c, p1)) == []


def test_permission_configure_wildcard_silent_for_an_allowlisted_provisioning_account():
    c = cluster(toggles=toggles(provisioning_accounts=["terraform"]))
    u1 = user("terraform")
    p1 = permission("terraform", configure=".*", write="^tf-.*$", read="^tf-.*$")
    assert rmq.permission_configure_wildcard(p1, ctx_of(c, u1, p1)) == []


# ── RABBITMQ.VHOST.DEFAULT_VHOST_IN_USE ───────────────────────────────────
def test_default_vhost_in_use_fires_on_two_broad_principals():
    c = cluster()
    u1, u2 = user("app1"), user("app2")
    p1, p2 = permission("app1"), permission("app2")
    v = vhost("/")
    hit = one(rmq.default_vhost_in_use(v, ctx_of(c, v, u1, u2, p1, p2)))
    assert "2 non-admin, non-guest users" in hit.observation
    assert "app1, app2" in hit.observation
    assert 'vhost "/"' in hit.observation


def test_default_vhost_in_use_silent_on_a_single_broad_principal():
    # A single-tenant cluster on "/" is explicitly documented as perfectly fine.
    c = cluster()
    u1, u2 = user("app1"), user("scraper", tags=["monitoring"])
    p1, p2 = permission("app1"), permission("scraper")
    v = vhost("/")
    assert rmq.default_vhost_in_use(v, ctx_of(c, v, u1, u2, p1, p2)) == []


def test_default_vhost_in_use_discriminates_on_acl_breadth_not_principal_count():
    # admin + scraper + guest + two SCOPED apps on "/" is the config the checklist blesses.
    c = cluster()
    users = [user("ops", tags=["administrator"]), user("scraper", tags=["monitoring"]),
             user("guest", tags=["administrator"]), user("app1"), user("app2")]
    perms = [permission("ops"), permission("scraper"), permission("guest"),
             permission("app1", configure="^app1-.*$", write="^app1-.*$", read="^app1-.*$"),
             permission("app2", configure="^app2-.*$", write="^app2-.*$", read="^app2-.*$")]
    v = vhost("/")
    assert rmq.default_vhost_in_use(v, ctx_of(c, v, *users, *perms)) == []


def test_default_vhost_in_use_silent_on_a_non_default_vhost():
    c = cluster()
    u1, u2 = user("app1"), user("app2")
    p1 = permission("app1", vhost_name="prod")
    p2 = permission("app2", vhost_name="prod")
    v = vhost("prod")
    assert rmq.default_vhost_in_use(v, ctx_of(c, v, u1, u2, p1, p2)) == []


def test_default_vhost_in_use_silent_when_permissions_were_unreadable():
    # No permissions read means no evidence — not "no broad grants".
    c = cluster(permissions_error="http_401")
    v = vhost("/")
    assert rmq.default_vhost_in_use(v, ctx_of(c, v)) == []


# ── RABBITMQ.MGMT.HTTP_API_NO_TLS ─────────────────────────────────────────
def test_mgmt_http_api_no_tls_fires_at_high_on_a_plaintext_context():
    c = cluster(overview=overview(contexts=[mgmt_context_plain()]))
    hit = one(rmq.mgmt_http_api_no_tls(c, ctx_of(c)))
    assert hit.severity is None                      # decorator high stands
    assert '"description": "RabbitMQ Management"' in hit.observation
    assert '"port": "15672"' in hit.observation
    assert '"ssl_opts": []' in hit.observation


def test_mgmt_http_api_no_tls_silent_when_only_an_https_context_exists():
    c = cluster()      # default overview carries the TLS context only
    assert rmq.mgmt_http_api_no_tls(c, ctx_of(c)) == []


def test_mgmt_http_api_no_tls_downgrades_to_medium_when_https_also_runs():
    # rabbit_mgmt_app registers BOTH contexts under the identical description literal.
    c = cluster(overview=overview(contexts=[mgmt_context_plain(), mgmt_context_tls()]))
    hit = one(rmq.mgmt_http_api_no_tls(c, ctx_of(c)))
    assert hit.severity == "medium"
    assert "an HTTPS management context is also present" in hit.observation


def test_mgmt_http_api_no_tls_downgrades_to_info_on_a_loopback_bound_context():
    c = cluster(overview=overview(contexts=[mgmt_context_plain(ip="127.0.0.1")]))
    hit = one(rmq.mgmt_http_api_no_tls(c, ctx_of(c)))
    assert hit.severity == "info"
    assert "unreachable off-host" in hit.observation


def test_mgmt_http_api_no_tls_downgrades_to_info_when_the_scanner_hop_was_verified_tls():
    # The mandatory suppression: our own hop proves a terminating proxy the API cannot see.
    c = cluster(overview=overview(contexts=[mgmt_context_plain()]),
                scanner={"scheme": "https", "tls_verified": True, "source_is_loopback": False,
                         "whoami": {"name": "vectasec", "tags": ["administrator"]}})
    hit = one(rmq.mgmt_http_api_no_tls(c, ctx_of(c)))
    assert hit.severity == "info"
    assert "terminated upstream of the broker" in hit.observation


def test_mgmt_http_api_no_tls_silent_when_the_proxy_toggle_is_set():
    c = cluster(overview=overview(contexts=[mgmt_context_plain()]),
                toggles=toggles(proxy_terminates_tls=True))
    assert rmq.mgmt_http_api_no_tls(c, ctx_of(c)) == []


def test_mgmt_http_api_no_tls_silent_when_contexts_are_unreadable():
    # Missing means "the credential lacks monitoring" — never "no contexts".
    c = cluster(overview=overview(contexts=None))
    assert rmq.mgmt_http_api_no_tls(c, ctx_of(c)) == []


def test_mgmt_http_api_no_tls_ignores_per_node_resources():
    n = node()
    assert rmq.mgmt_http_api_no_tls(n, ctx_of(cluster(), n)) == []


# ── RABBITMQ.LISTENER.AMQP_PLAINTEXT ──────────────────────────────────────
def test_amqp_plaintext_fires_on_a_wildcard_bound_plaintext_listener():
    c = cluster(overview=overview(listeners=[amqp_plain_listener()]))
    hit = one(rmq.amqp_plaintext(c, ctx_of(c)))
    assert hit.severity is None
    assert '"protocol": "amqp"' in hit.observation
    assert '"ip_address": "::"' in hit.observation
    assert '"port": 5672' in hit.observation
    assert '"tls": false' in hit.observation
    # ip_address is an interface-binding fact; this API sees no firewall or security group.
    assert "actual reachability is not verified" in hit.observation


def test_amqp_plaintext_silent_on_a_tls_only_broker():
    c = cluster()
    assert rmq.amqp_plaintext(c, ctx_of(c)) == []


def test_amqp_plaintext_silent_on_a_loopback_bound_plaintext_listener():
    c = cluster(overview=overview(listeners=[amqp_plain_listener(ip="127.0.0.1")]))
    assert rmq.amqp_plaintext(c, ctx_of(c)) == []


def test_amqp_plaintext_silent_on_a_private_vpc_bind():
    # Never "not loopback": 10.0.1.5 is a normal private bind and matching it is pure noise.
    c = cluster(overview=overview(listeners=[amqp_plain_listener(ip="10.0.1.5")]))
    assert rmq.amqp_plaintext(c, ctx_of(c)) == []


def test_amqp_plaintext_infers_tls_from_socket_opts_when_the_tls_flag_is_absent():
    # Older brokers omit `tls`; falling back to has_tls_enabled/2's logic beats assuming plaintext.
    listener = amqp_tls_listener(protocol="amqp")
    listener.pop("tls")
    c = cluster(overview=overview(listeners=[listener]))
    assert rmq.amqp_plaintext(c, ctx_of(c)) == []


def test_amqp_plaintext_silent_under_a_transparent_tls_mesh():
    c = cluster(overview=overview(listeners=[amqp_plain_listener()]),
                toggles=toggles(transparent_tls_mesh=True))
    assert rmq.amqp_plaintext(c, ctx_of(c)) == []


def test_amqp_plaintext_escalates_to_high_on_a_reachability_signal():
    c = cluster(overview=overview(listeners=[amqp_plain_listener()]),
                toggles=toggles(reachability_signal="shodan:1.2.3.4:5672"))
    hit = one(rmq.amqp_plaintext(c, ctx_of(c)))
    assert hit.severity == "high"
    assert "shodan:1.2.3.4:5672" in hit.observation


def test_amqp_plaintext_silent_when_listeners_are_unreadable():
    c = cluster(overview=overview(listeners=None))
    assert rmq.amqp_plaintext(c, ctx_of(c)) == []


def test_amqp_plaintext_aggregates_a_dual_stack_three_node_cluster_into_one_hit():
    # active_listeners/0 appends every running node's listeners and dual-stack doubles them:
    # 6 entries, 1 real issue. Fingerprinting on (tenant, rule, ext_id) means extra Hits are lost.
    listeners = []
    for name in ("rabbit@node1", "rabbit@node2", "rabbit@node3"):
        listeners.append(amqp_plain_listener(node=name, ip="0.0.0.0"))
        listeners.append(amqp_plain_listener(node=name, ip="::"))
    c = cluster(overview=overview(listeners=listeners))
    hit = one(rmq.amqp_plaintext(c, ctx_of(c)))
    for name in ("rabbit@node1", "rabbit@node2", "rabbit@node3"):
        assert name in hit.observation


# ── RABBITMQ.CLUSTER.DIST_PORT_EXPOSED ────────────────────────────────────
def test_dist_port_exposed_fires_on_a_wildcard_bound_clustering_listener():
    c = cluster(overview=overview(listeners=[clustering_listener()]))
    hit = one(rmq.dist_port_exposed(c, ctx_of(c)))
    assert hit.severity is None
    assert '"protocol": "clustering"' in hit.observation
    assert '"port": 25672' in hit.observation
    assert '"ip_address": "::"' in hit.observation
    # The dropped ERLANG.DEFAULT_COOKIE rule folds into this remediation.
    assert "cookie" in hit.remediation


def test_dist_port_exposed_silent_on_a_private_bound_clustering_listener():
    c = cluster()      # default clustering listener binds 10.0.1.5
    assert rmq.dist_port_exposed(c, ctx_of(c)) == []


def test_dist_port_exposed_covers_the_tls_clustering_variant():
    c = cluster(overview=overview(listeners=[clustering_listener(protocol="clustering/ssl")]))
    hit = one(rmq.dist_port_exposed(c, ctx_of(c)))
    assert '"protocol": "clustering/ssl"' in hit.observation


def test_dist_port_exposed_escalates_to_medium_on_a_reachability_signal():
    c = cluster(overview=overview(listeners=[clustering_listener()]),
                toggles=toggles(reachability_signal="nmap:25672/open"))
    hit = one(rmq.dist_port_exposed(c, ctx_of(c)))
    assert hit.severity == "medium"
    assert "nmap:25672/open" in hit.observation


def test_dist_port_exposed_silent_when_listeners_are_unreadable():
    c = cluster(overview=overview(listeners=None))
    assert rmq.dist_port_exposed(c, ctx_of(c)) == []


# ── RABBITMQ.TLS.PEER_VERIFICATION_DISABLED ───────────────────────────────
def _tls_listener_without_verify():
    opts = dict(amqp_tls_listener()["socket_opts"])
    opts.pop("verify")
    opts.pop("fail_if_no_peer_cert")
    return amqp_tls_listener(socket_opts=opts)


def test_tls_peer_verification_disabled_fires_when_verify_is_absent():
    c = cluster(overview=overview(listeners=[_tls_listener_without_verify()]))
    n = node()
    hit = one(rmq.tls_peer_verification_disabled(c, ctx_of(c, n)))
    assert "socket_opts.verify=None" in hit.observation
    assert '"protocol": "amqp/ssl"' in hit.observation
    # Server-side `verify` governs CLIENT cert validation — no MITM framing is permitted.
    assert "MITM" not in hit.observation
    assert "still encrypted" in hit.observation


def test_tls_peer_verification_disabled_fires_on_explicit_verify_none():
    opts = dict(amqp_tls_listener()["socket_opts"], verify="verify_none")
    c = cluster(overview=overview(listeners=[amqp_tls_listener(socket_opts=opts)]))
    n = node()
    hit = one(rmq.tls_peer_verification_disabled(c, ctx_of(c, n)))
    assert "socket_opts.verify='verify_none'" in hit.observation


def test_tls_peer_verification_disabled_silent_on_verify_peer():
    c = cluster()      # default amqp/ssl listener carries verify_peer
    n = node()
    assert rmq.tls_peer_verification_disabled(c, ctx_of(c, n)) == []


def test_tls_peer_verification_disabled_reads_the_nested_ssl_opts_shape():
    # ranch/web listeners nest under socket_opts.ssl_opts while amqp/ssl is flat — reading one
    # shape misses half of them.
    opts = {"backlog": 128, "ssl_opts": {"cacertfile": "/etc/rabbitmq/ca.pem",
                                         "verify": "verify_peer"}}
    c = cluster(overview=overview(listeners=[amqp_tls_listener(socket_opts=opts)]))
    n = node()
    assert rmq.tls_peer_verification_disabled(c, ctx_of(c, n)) == []


def test_tls_peer_verification_disabled_silent_when_auth_mechanisms_are_unreadable():
    # Cannot read auth_mechanisms -> cannot gate on EXTERNAL -> not assessable, never a pass.
    c = cluster(overview=overview(listeners=[_tls_listener_without_verify()]))
    assert rmq.tls_peer_verification_disabled(c, ctx_of(c)) == []


def test_tls_peer_verification_disabled_yields_to_the_x509_rule_when_external_is_enabled():
    c = cluster(overview=overview(listeners=[_tls_listener_without_verify()]))
    n = node(auth_mechanisms=mechs(external=True))
    assert rmq.tls_peer_verification_disabled(c, ctx_of(c, n)) == []


def test_tls_peer_verification_disabled_fires_on_a_management_context():
    ctx_tls = mgmt_context_tls(ssl_opts={"cacertfile": "/etc/rabbitmq/ca.pem"})
    c = cluster(overview=overview(listeners=[amqp_tls_listener()], contexts=[ctx_tls]))
    n = node()
    hit = one(rmq.tls_peer_verification_disabled(c, ctx_of(c, n)))
    assert "ssl_opts.verify=None" in hit.observation
    assert '"description": "RabbitMQ Management"' in hit.observation


# ── RABBITMQ.TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION ──────────────────────
def test_x509_auth_without_peer_verification_fires_when_verify_is_absent():
    c = cluster(overview=overview(listeners=[_tls_listener_without_verify()]))
    n = node(auth_mechanisms=mechs(external=True))
    hit = one(rmq.x509_auth_without_peer_verification(c, ctx_of(c, n)))
    assert '"name":"EXTERNAL","enabled":true' in hit.observation
    assert "socket_opts.verify=None" in hit.observation
    assert "fail_if_no_peer_cert=None" in hit.observation


def test_x509_auth_without_peer_verification_fires_when_a_cert_may_be_omitted():
    # verify_peer still lets clients simply omit a certificate unless fail_if_no_peer_cert.
    opts = dict(amqp_tls_listener()["socket_opts"], fail_if_no_peer_cert=False)
    c = cluster(overview=overview(listeners=[amqp_tls_listener(socket_opts=opts)]))
    n = node(auth_mechanisms=mechs(external=True))
    hit = one(rmq.x509_auth_without_peer_verification(c, ctx_of(c, n)))
    assert "fail_if_no_peer_cert=False" in hit.observation
    assert "socket_opts.verify='verify_peer'" in hit.observation


def test_x509_auth_without_peer_verification_silent_on_a_correct_mtls_listener():
    c = cluster()      # verify_peer + fail_if_no_peer_cert=True
    n = node(auth_mechanisms=mechs(external=True))
    assert rmq.x509_auth_without_peer_verification(c, ctx_of(c, n)) == []


def test_x509_auth_without_peer_verification_silent_when_external_is_disabled():
    c = cluster(overview=overview(listeners=[_tls_listener_without_verify()]))
    n = node()
    assert rmq.x509_auth_without_peer_verification(c, ctx_of(c, n)) == []


def test_x509_auth_without_peer_verification_ignores_plaintext_listeners():
    # A plaintext listener has no peer verification to configure; AMQP_PLAINTEXT owns it.
    c = cluster(overview=overview(listeners=[amqp_plain_listener()]))
    n = node(auth_mechanisms=mechs(external=True))
    assert rmq.x509_auth_without_peer_verification(c, ctx_of(c, n)) == []


# ── RABBITMQ.VERSION.UNPATCHED_CVE ────────────────────────────────────────
@pytest.mark.parametrize("version, fires", [
    ("4.2.3", True),
    ("4.2.6", False),
    ("4.1.10", True),
    ("4.1.11", False),
    ("4.0.19", True),
    ("4.0.20", False),
    ("3.13.14", True),
    ("3.13.15", False),
    ("3.12.13", False),   # both CVEs were introduced in 3.13.0 — firing here is a guaranteed FP
    ("3.11.28", False),
    ("4.3.0", False),     # series ships the fix
    ("4.4.0", False),     # unrecognized future series -> PASS, not fail-through
])
def test_version_unpatched_cve_respects_the_per_series_floor(version, fires):
    c = cluster(overview=overview(rabbitmq_version=version, product_version=version),
                node_versions={NODE1: version})
    hits = rmq.version_unpatched_cve(c, ctx_of(c))
    assert bool(hits) is fires
    if fires:
        assert version in hits[0].observation


def test_version_unpatched_cve_names_the_patched_release_for_the_series():
    c = cluster(overview=overview(rabbitmq_version="4.2.3", product_version="4.2.3"),
                node_versions={NODE1: "4.2.3"})
    hit = one(rmq.version_unpatched_cve(c, ctx_of(c)))
    assert "'4.2.3'" in hit.observation
    assert "below the 4.2.6 patched release" in hit.observation
    assert "not asserted here" in hit.observation      # /api/auth returned no secret
    assert hit.severity is None


def test_version_unpatched_cve_escalates_to_high_when_the_oauth_secret_is_disclosed():
    c = cluster(overview=overview(rabbitmq_version="4.2.3", product_version="4.2.3"),
                node_versions={NODE1: "4.2.3"},
                probes=probes(auth=auth_probe_disclosing()))
    hit = one(rmq.version_unpatched_cve(c, ctx_of(c)))
    assert hit.severity == "high"
    assert "confirming exposure to CVE-2026-57219" in hit.observation


def test_version_unpatched_cve_silent_on_a_backported_build():
    c = cluster(overview=overview(rabbitmq_version="4.2.3", product_version="4.2.3"),
                toggles=toggles(backported_build=True))
    assert rmq.version_unpatched_cve(c, ctx_of(c)) == []


def test_version_unpatched_cve_silent_when_the_version_is_unparseable():
    c = cluster(overview=overview(rabbitmq_version="tanzu-custom", product_version=None))
    assert rmq.version_unpatched_cve(c, ctx_of(c)) == []


def test_version_unpatched_cve_tolerates_a_build_suffix():
    c = cluster(overview=overview(rabbitmq_version="4.2.3-rc.1", product_version="4.2.3-rc.1"),
                node_versions={NODE1: "4.2.3-rc.1"})
    hit = one(rmq.version_unpatched_cve(c, ctx_of(c)))
    assert "4.2.3-rc.1" in hit.observation


def test_version_unpatched_cve_reports_per_node_version_drift():
    # rabbitmq_version is the version of the node that PROCESSED the request.
    c = cluster(overview=overview(rabbitmq_version="4.2.3", product_version="4.2.3"),
                node_versions={"rabbit@node1": "4.2.3", "rabbit@node2": "4.2.6"})
    hit = one(rmq.version_unpatched_cve(c, ctx_of(c)))
    assert "mid-upgrade or load-balanced" in hit.observation
    assert "rabbit@node2" in hit.observation


# ── RABBITMQ.VERSION.EOL_SERIES ───────────────────────────────────────────
@pytest.mark.parametrize("version, expected", [
    ("4.4.0", None),        # unrecognized future series -> PASS
    ("4.3.2", None),        # 136 days of community support left
    ("4.2.5", "info"),      # warn: community EOL 2026-07-31 is 14 days out
    ("4.1.5", "low"),       # past community EOL, live commercial track to 2027-04-30
    ("4.0.9", "medium"),    # never had a commercial track -> keeps its tabled severity
    ("3.13.7", "medium"),   # the final freely-distributed 3.13 build
    ("3.13.14", "info"),    # patch above the last community build => licensed
    ("3.12.13", "high"),    # commercial track expired 30 Jun 2025
    ("3.11.28", "high"),    # no support from any party
])
def test_version_eol_series_grades_severity_per_the_spec_table(version, expected):
    c = cluster(overview=overview(rabbitmq_version=version, product_version=version),
                node_versions={NODE1: version})
    hits = rmq.version_eol_series(c, ctx_of(c))
    if expected is None:
        assert hits == []
        return
    hit = one(hits)
    assert (hit.severity or "medium") == expected, f"{version} graded {hit.severity!r}"
    assert version in hit.observation
    assert "27.3.4.14" in hit.observation                  # the observed erlang_version
    assert rmq._EOL_AS_OF.isoformat() in hit.observation   # the matrix's as-of date


def test_version_eol_series_fires_when_the_4_2_fuse_blows(monkeypatch):
    # The matrix is a dated snapshot with a 14-day fuse: 4.2 crosses community EOL on
    # 2026-07-31 and must flip warn -> fail on its own, without a code change.
    class _Date(date):
        @classmethod
        def today(cls):
            return date(2026, 8, 1)

    monkeypatch.setattr(rmq, "date", _Date)
    c = cluster(overview=overview(rabbitmq_version="4.2.5", product_version="4.2.5"),
                node_versions={NODE1: "4.2.5"})
    hit = one(rmq.version_eol_series(c, ctx_of(c)))
    assert hit.severity == "low"          # community over, commercial track still live
    assert "reached end of community support on 2026-07-31" in hit.observation
    assert "2030-06-30" in hit.observation


def test_version_eol_series_explains_a_commercial_only_build():
    c = cluster(overview=overview(rabbitmq_version="3.13.14", product_version="3.13.14"),
                node_versions={NODE1: "3.13.14"})
    hit = one(rmq.version_eol_series(c, ctx_of(c)))
    assert "commercial-only build" in hit.observation
    assert "2029-12-31" in hit.observation


def test_version_eol_series_warns_before_the_community_eol_date():
    c = cluster(overview=overview(rabbitmq_version="4.2.5", product_version="4.2.5"),
                node_versions={NODE1: "4.2.5"})
    hit = one(rmq.version_eol_series(c, ctx_of(c)))
    assert "in 14 days" in hit.observation
    assert "2026-07-31" in hit.observation


def test_version_eol_series_silent_on_a_backported_build():
    c = cluster(overview=overview(rabbitmq_version="4.0.9", product_version="4.0.9"),
                toggles=toggles(backported_build=True))
    assert rmq.version_eol_series(c, ctx_of(c)) == []


def test_version_eol_series_silent_when_the_version_is_unparseable():
    c = cluster(overview=overview(rabbitmq_version=None, product_version=None))
    assert rmq.version_eol_series(c, ctx_of(c)) == []


def test_version_eol_series_prefers_rabbitmq_version_over_branded_product_version():
    # rabbitmq_version is base_product_version(); product_version is branding-overridable.
    c = cluster(overview=overview(rabbitmq_version="4.0.9", product_version="Acme MQ 9.9"),
                node_versions={NODE1: "4.0.9"})
    hit = one(rmq.version_eol_series(c, ctx_of(c)))
    assert "4.0.9" in hit.observation
    assert "Acme MQ" not in hit.observation


# ── RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED ─────────────────────────────────
def test_anonymous_login_enabled_fires_on_an_enabled_mechanism():
    c = cluster()
    n = node(auth_mechanisms=mechs(anonymous=True))
    hit = one(rmq.anonymous_login_enabled(n, ctx_of(c, n)))
    assert hit.severity is None
    assert '"name": "ANONYMOUS"' in hit.observation
    assert '"enabled": true' in hit.observation
    assert "rabbit@node1" in hit.observation


def test_anonymous_login_enabled_silent_when_the_mechanism_is_disabled():
    c = cluster()
    n = node()      # mechs() disables ANONYMOUS
    assert rmq.anonymous_login_enabled(n, ctx_of(c, n)) == []


def test_anonymous_login_enabled_silent_when_the_mechanism_is_absent():
    c = cluster()
    n = node(auth_mechanisms=[{"name": "PLAIN", "description": "SASL PLAIN", "enabled": True}])
    assert rmq.anonymous_login_enabled(n, ctx_of(c, n)) == []


def test_anonymous_login_enabled_silent_when_auth_mechanisms_are_unreadable():
    c = cluster()
    n = node(auth_mechanisms=None)
    assert rmq.anonymous_login_enabled(n, ctx_of(c, n)) == []


def test_anonymous_login_enabled_ignores_the_cluster_resource():
    # auth_mechanisms is a per-node fact projected on /api/nodes, not /api/overview.
    c = cluster()
    assert rmq.anonymous_login_enabled(c, ctx_of(c)) == []


def test_anonymous_login_enabled_declines_on_a_stopped_node_without_flagging_its_peers():
    # A node that is down comes back from /api/nodes with a minimal field set and no
    # auth_mechanisms. It must decline rather than crash, and must not mask its running peer.
    c = cluster()
    down = node(name="rabbit@node2", auth_mechanisms=None, running=False)
    up = node(name=NODE1, auth_mechanisms=mechs(anonymous=True))
    assert rmq.anonymous_login_enabled(down, ctx_of(c, up, down)) == []
    assert len(rmq.anonymous_login_enabled(up, ctx_of(c, up, down))) == 1


def test_tls_peer_verification_gate_survives_a_stopped_node():
    # _external_enabled must not read a stopped node's missing auth_mechanisms as "EXTERNAL is
    # not enabled" for the whole cluster, nor as "not assessable" when a peer answered.
    c = cluster(overview=overview(listeners=[_tls_listener_without_verify()]))
    down = node(name="rabbit@node2", auth_mechanisms=None, running=False)
    up = node(name=NODE1, auth_mechanisms=mechs(external=True))
    assert rmq.tls_peer_verification_disabled(c, ctx_of(c, up, down)) == []
    assert len(rmq.x509_auth_without_peer_verification(c, ctx_of(c, up, down))) == 1


def test_anonymous_login_enabled_escalates_to_medium_when_loopback_is_lifted():
    c = cluster(probes=probes(guest_whoami=guest_probe_200()))
    n = node(auth_mechanisms=mechs(anonymous=True))
    hit = one(rmq.anonymous_login_enabled(n, ctx_of(c, n)))
    assert hit.severity == "medium"
    assert "loopback restriction" in hit.observation


# ── RABBITMQ.SCAN.NOT_ASSESSABLE ──────────────────────────────────────────
def _fully_readable_cluster(**over):
    raw = {"probes": probes(guest_whoami={"status": 401, "reason": "Not_Authorized"})}
    raw.update(over)
    return cluster(**raw)


def test_scan_not_assessable_silent_when_everything_was_readable():
    # The load-bearing negative: a monitoring+administrator credential on a stats-enabled
    # broker must produce a clean coverage report, or every scan carries a permanent info.
    c = _fully_readable_cluster()
    assert rmq.scan_not_assessable(c, ctx_of(c)) == []


def test_scan_not_assessable_reports_an_unreadable_overview():
    c = cluster(overview=None, overview_error="http_401")
    hit = one(rmq.scan_not_assessable(c, ctx_of(c)))
    assert "'http_401'" in hit.observation
    assert "MGMT.HTTP_API_NO_TLS" in hit.observation
    assert "VERSION.EOL_SERIES" in hit.observation


def test_scan_not_assessable_reports_missing_listeners_on_a_management_only_credential():
    # The single largest correctness risk: listeners omitted for a `management`-tagged
    # credential must be not-assessable, never a pass.
    c = cluster(overview=overview(listeners=None))
    hit = one(rmq.scan_not_assessable(c, ctx_of(c)))
    assert "no `listeners` key" in hit.observation
    assert "LISTENER.AMQP_PLAINTEXT" in hit.observation
    assert "disable_stats=False" in hit.observation      # the observed value


def test_scan_not_assessable_reports_missing_contexts():
    c = cluster(overview=overview(contexts=None))
    hit = one(rmq.scan_not_assessable(c, ctx_of(c)))
    assert "no `contexts` key" in hit.observation
    assert "MGMT.HTTP_API_NO_TLS" in hit.observation


def test_scan_not_assessable_reports_an_administrator_only_endpoint_401():
    c = _fully_readable_cluster(users_error="http_401", permissions_error="http_401")
    hit = one(rmq.scan_not_assessable(c, ctx_of(c)))
    assert "GET /api/users" in hit.observation
    assert "GET /api/permissions" in hit.observation
    assert "`administrator` tag" in hit.observation
    assert "USER.DEFAULT_GUEST_PRESENT" in hit.observation


def test_scan_not_assessable_reports_a_skipped_guest_probe():
    c = _fully_readable_cluster(
        probes=probes(guest_whoami={"skipped": "scanner source address is loopback"}))
    hit = one(rmq.scan_not_assessable(c, ctx_of(c)))
    assert "scanner source address is loopback" in hit.observation
    assert "USER.GUEST_REMOTE_LOGIN" in hit.observation


def test_scan_not_assessable_counts_every_gap():
    c = cluster(overview=None, overview_error="http_401", nodes_error="http_401",
                users_error="http_401", vhosts_error="http_401", permissions_error="http_401",
                probes=probes(guest_whoami={"skipped": "loopback"}))
    hit = one(rmq.scan_not_assessable(c, ctx_of(c)))
    assert "could not read 6 part(s)" in hit.observation


def test_scan_not_assessable_ignores_per_node_resources():
    n = node()
    assert rmq.scan_not_assessable(n, ctx_of(cluster(overview=None), n)) == []


# ── Registration ──────────────────────────────────────────────────────────
def test_every_rabbitmq_rule_is_registered_exactly_once():
    from vectasec.registry import DETECTORS

    rule_ids = [d.rule_id for d in DETECTORS if d.rule_id.startswith("RABBITMQ.")]
    assert len(rule_ids) == len(set(rule_ids)), "duplicate rule_id registration"
    assert len(rule_ids) == 18


def test_the_dropped_erlang_cookie_rule_is_not_registered():
    # Folded into DIST_PORT_EXPOSED's remediation per the spec's verdict dependency: it is not
    # observable from any endpoint, so it would fire unconditionally having verified nothing.
    from vectasec.registry import DETECTORS

    assert not any(d.rule_id == "RABBITMQ.ERLANG.DEFAULT_COOKIE" for d in DETECTORS)
