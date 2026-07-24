"""The attack-path / toxic-combination correlation engine: graph_engine + detect/attack_path.

Synthetic ctx.resources model the label-encoded graph a real scan produces (identity.py's
identity/grant encoding, classify.py's data_* labels, detect/data.py's broker config shape). Each
firing combination is paired with a near-miss that must NOT fire, plus a not-assessable coverage
gap, and every firing case asserts the chain is cited hop-by-hop.
"""
from vectasec.contracts import ScanContext, Resource
from vectasec.detect import attack_path as ap
from vectasec import graph_engine as ge


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources, config={})


# ── builders that mirror the real label encoding ────────────────────────────────
def exposed_broker(ext_id="broker-1"):
    return Resource(kind="broker", name=ext_id, ext_id=ext_id, raw={"config": {
        "listener.security.protocol.map": {"value": "CONTROLLER:PLAINTEXT,EXTERNAL:PLAINTEXT"},
        "controller.listener.names": {"value": "CONTROLLER"},
        "authorizer.class.name": {"value": ""}}})


def secure_broker(ext_id="broker-1"):
    return Resource(kind="broker", name=ext_id, ext_id=ext_id, raw={"config": {
        "listener.security.protocol.map": {"value": "EXTERNAL:SASL_SSL"},
        "authorizer.class.name": {"value": "kafka.security.authorizer.AclAuthorizer"}}})


def nhi(ext_id="identity:kafka:user-svc", name="User:svc", source="broker-1"):
    return Resource(kind="identity", name=name, ext_id=ext_id,
                    labels={"identity_type": "service_account", "system": "kafka", "external": "false"},
                    raw={"identity_type": "service_account", "system": "kafka",
                         "principal": name, "source_ext_id": source})


def wildcard_grant(identity="identity:kafka:user-svc", permission="allow",
                   ext_id="grant:kafka:aaa", restype="topic", action="all", target="topic:*"):
    return Resource(kind="grant", name=f"{action} -> {target}", ext_id=ext_id,
                    labels={"system": "kafka", "action": action, "identity": identity,
                            "wildcard": "true", "permission": permission},
                    raw={"system": "kafka", "identity_ext_id": identity, "action": action,
                         "target": target, "wildcard": True, "restype": restype,
                         "permission": permission})


def pci_topic(name="payments", ext_id="topic-payments"):
    return Resource(kind="topic", name=name, ext_id=ext_id,
                    labels={"data_classes": "pci", "data_sensitivity": "high",
                            "data_signals": "pci:payments"})


def plain_topic(name="heartbeat", ext_id="topic-heartbeat"):
    return Resource(kind="topic", name=name, ext_id=ext_id, labels={})


# ── EXPOSED_NHI_SENSITIVE (the full triad) ──────────────────────────────────────
def test_triad_fires_critical_and_cites_every_hop():
    broker, ident, grant, topic = exposed_broker(), nhi(), wildcard_grant(), pci_topic()
    ctx = _ctx([broker, ident, grant, topic])
    hits = ap.exposed_nhi_sensitive(topic, ctx)
    assert len(hits) == 1
    h = hits[0]
    assert h.severity == "critical"          # regulated data on a fully-open surface
    # hop-by-hop chain, every hop's ext_id cited, in order surface -> nhi -> grant -> data
    obs = h.observation
    assert " -> " in obs
    for ext_id in ("broker-1", "identity:kafka:user-svc", "grant:kafka:aaa", "topic-payments"):
        assert ext_id in obs, ext_id
    assert "PLAINTEXT" in obs and "authorizer.class.name is unset" in obs
    assert "payments" in obs and "pci" in obs
    assert h.source_ref["attack_path"] == "EXPOSED_NHI_SENSITIVE"
    assert h.source_ref["hops"] == ["broker-1", "identity:kafka:user-svc",
                                    "grant:kafka:aaa", "topic-payments"]


def test_triad_high_not_critical_when_data_is_only_medium():
    # A pii (medium) topic is still a triad, but not critical.
    pii = Resource(kind="topic", name="customers", ext_id="topic-customers",
                   labels={"data_classes": "pii", "data_sensitivity": "medium",
                           "data_signals": "pii:customers"})
    grant = wildcard_grant()
    ctx = _ctx([exposed_broker(), nhi(), grant, pii])
    hits = ap.exposed_nhi_sensitive(pii, ctx)
    assert hits and hits[0].severity == "high"


def test_triad_supersedes_sensitive_on_exposed_no_duplicate():
    broker, ident, grant, topic = exposed_broker(), nhi(), wildcard_grant(), pci_topic()
    ctx = _ctx([broker, ident, grant, topic])
    assert ap.exposed_nhi_sensitive(topic, ctx)          # triad fires
    assert ap.sensitive_on_exposed(topic, ctx) == []     # 2-factor is superseded, not duplicated


# ── SENSITIVE_ON_EXPOSED (2-factor, generalises the Kafka-only rule) ─────────────
def test_sensitive_on_exposed_fires_without_any_nhi():
    broker, topic = exposed_broker(), pci_topic()
    hits = ap.sensitive_on_exposed(topic, _ctx([broker, topic]))
    assert len(hits) == 1
    h = hits[0]
    assert h.severity == "critical"        # high-sensitivity + plaintext + unauth == fully open
    assert "broker-1" in h.observation and "topic-payments" in h.observation
    assert ap.exposed_nhi_sensitive(topic, _ctx([broker, topic])) == []  # no NHI => no triad


def test_sensitive_on_exposed_generalises_to_a_non_kafka_self_exposed_surface():
    # A gateway route that is its own exposed surface via generic labels (no broker involved).
    route = Resource(kind="route", name="cards", ext_id="route-cards",
                     labels={"data_classes": "pci", "data_sensitivity": "high",
                             "data_signals": "pci:card", "plaintext": "true", "no_auth": "true"})
    hits = ap.sensitive_on_exposed(route, _ctx([route]))
    assert len(hits) == 1
    # self-exposed: the one data resource is both the surface hop and the data hop.
    assert hits[0].observation.count("route-cards") >= 2
    assert hits[0].severity == "critical"


def test_secure_surface_yields_no_paths_at_all():
    broker, ident, grant, topic = secure_broker(), nhi(), wildcard_grant(), pci_topic()
    ctx = _ctx([broker, ident, grant, topic])
    assert ap.exposed_nhi_sensitive(topic, ctx) == []
    assert ap.sensitive_on_exposed(topic, ctx) == []
    assert ap.public_overprivileged(grant, ctx) == []


# ── PUBLIC_OVERPRIVILEGED (exposure x over-privilege, no sensitive data) ─────────
def test_public_overprivileged_fires_on_grant_without_sensitive_data():
    broker, ident, grant, topic = exposed_broker(), nhi(), wildcard_grant(), plain_topic()
    ctx = _ctx([broker, ident, grant, topic])
    hits = ap.public_overprivileged(grant, ctx)
    assert len(hits) == 1
    h = hits[0]
    assert h.severity == "critical"        # fully-open surface + an ALLOW-all grant
    assert "broker-1" in h.observation and "grant:kafka:aaa" in h.observation
    # no sensitive resource in the set => the two data-anchored rules stay silent
    assert ap.sensitive_on_exposed(topic, ctx) == []
    assert ap.exposed_nhi_sensitive(topic, ctx) == []


def test_deny_wildcard_is_not_over_privilege():
    broker, ident = exposed_broker(), nhi()
    deny = wildcard_grant(permission="deny")
    topic = pci_topic()
    ctx = _ctx([broker, ident, deny, topic])
    assert ap.public_overprivileged(deny, ctx) == []          # a deny grant is a guardrail
    assert ap.exposed_nhi_sensitive(topic, ctx) == []         # so no triad
    assert ap.sensitive_on_exposed(topic, ctx)                # but exposure+sensitive still fires


def test_shared_default_principal_is_flagged_in_the_chain():
    guest = nhi(ext_id="identity:kafka:guest", name="guest")
    grant = wildcard_grant(identity="identity:kafka:guest", ext_id="grant:kafka:guest")
    ctx = _ctx([exposed_broker(), guest, grant])
    hits = ap.public_overprivileged(grant, ctx)
    assert hits and "shared/default account" in hits[0].observation


# ── not-assessable coverage gap ─────────────────────────────────────────────────
def test_not_assessable_when_hosting_surface_exposure_is_unreadable():
    # A surface exists (broker) but its exposure config is unreadable, and a sensitive topic sits
    # in the same system: we cannot settle exposure, so this is a coverage gap, not a clean pass.
    blind_broker = Resource(kind="broker", name="b", ext_id="broker-x", raw={})
    topic = pci_topic()
    hits = ap.sensitive_on_exposed(topic, _ctx([blind_broker, topic]))
    assert len(hits) == 1
    assert hits[0].assessable is False
    assert "broker-x" in hits[0].assessment_reason
    assert "could NOT be confirmed" in hits[0].observation
    # and no false-positive elsewhere
    assert ap.exposed_nhi_sensitive(topic, _ctx([blind_broker, topic])) == []


def test_unclassified_data_never_produces_a_path():
    broker, topic = exposed_broker(), plain_topic()
    assert ap.sensitive_on_exposed(topic, _ctx([broker, topic])) == []
    assert ap.exposed_nhi_sensitive(topic, _ctx([broker, topic])) == []


# ── the pure engine, tested directly ────────────────────────────────────────────
def test_assess_exposure_kafka_and_redis_and_generic():
    assert ge.assess_exposure(exposed_broker()).exposed is True
    assert ge.assess_exposure(secure_broker()).exposed is False
    # a surface kind with no readable signal => indeterminate (None), not False
    assert ge.assess_exposure(Resource(kind="broker", name="b", ext_id="b", raw={})).exposed is None
    # a non-surface, non-signalling resource is not a surface at all
    assert ge.assess_exposure(plain_topic()) is None
    open_redis = Resource(kind="redis_server", name="r", ext_id="redis-r",
                          raw={"has_requirepass": False, "tls_port": "0", "protected_mode": "no",
                               "bind": "0.0.0.0"})
    ex = ge.assess_exposure(open_redis, [open_redis])
    assert ex.exposed is True and ex.plaintext and ex.unauth and ex.public


def test_is_overprivileged_grant_only_wildcard_allow():
    assert ge.is_overprivileged_grant(wildcard_grant()) is True
    assert ge.is_overprivileged_grant(wildcard_grant(permission="deny")) is False
    narrow = Resource(kind="grant", name="g", ext_id="g2",
                      labels={"wildcard": "false", "permission": "allow"},
                      raw={"wildcard": False, "permission": "allow"})
    assert ge.is_overprivileged_grant(narrow) is False


def test_grant_reaches_by_restype_and_by_literal_target():
    by_ext = {"topic-payments": pci_topic()}
    # wildcard topic grant reaches any topic
    assert ge._grant_reaches(wildcard_grant(restype="topic"), pci_topic(), by_ext) is True
    # a wildcard grant for a different restype does not reach a topic
    assert ge._grant_reaches(wildcard_grant(restype="group"), pci_topic(), by_ext) is False
    # a literal grant naming the resource reaches it even if not wildcard
    literal = Resource(kind="grant", name="g", ext_id="g3",
                       labels={"wildcard": "false", "permission": "allow"},
                       raw={"wildcard": False, "permission": "allow", "restype": "topic",
                            "target": "topic:payments"})
    assert ge._grant_reaches(literal, pci_topic(), by_ext) is True


def test_compute_paths_emits_each_path_once_by_its_anchor():
    broker, ident, grant, topic = exposed_broker(), nhi(), wildcard_grant(), pci_topic()
    paths = ge.compute_paths([broker, ident, grant, topic])
    cats = sorted(p.category for p in paths)
    # the triad supersedes the 2-factor on the topic; PUBLIC_OVERPRIVILEGED fires on the grant
    assert cats == ["EXPOSED_NHI_SENSITIVE", "PUBLIC_OVERPRIVILEGED"]
    anchors = {p.category: p.anchor_ext_id for p in paths}
    assert anchors["EXPOSED_NHI_SENSITIVE"] == "topic-payments"
    assert anchors["PUBLIC_OVERPRIVILEGED"] == "grant:kafka:aaa"


# ── the pack is cross-cutting: prefix matches no connector, maps to no control ───
def test_rules_registered_and_prefix_is_cross_cutting():
    from vectasec.registry import DETECTORS, CONNECTORS
    ids = {d.rule_id for d in DETECTORS if d.rule_id.startswith("ATTACKPATH.")}
    assert ids == {"ATTACKPATH.EXPOSED_NHI_SENSITIVE", "ATTACKPATH.PUBLIC_OVERPRIVILEGED",
                   "ATTACKPATH.SENSITIVE_ON_EXPOSED"}
    # the prefix must not collide with any connector type (keeps the /connectors catalogue honest)
    assert "attackpath" not in {t.lower() for t in CONNECTORS}


def test_compliance_returns_no_controls_for_attackpath():
    from vectasec.compliance.map import controls_for
    for rid in ("ATTACKPATH.EXPOSED_NHI_SENSITIVE", "ATTACKPATH.PUBLIC_OVERPRIVILEGED",
                "ATTACKPATH.SENSITIVE_ON_EXPOSED"):
        assert controls_for(rid) == ()
