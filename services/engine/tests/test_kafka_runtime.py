"""Agentless runtime evidence for Kafka — DescribeConsumerGroups. Offline: no broker, no network.

Kafka is the flagship connector and was the last major one that could say what the cluster
PERMITS but not who was using it. These tests pin the same contract test_runtime_sources.py pins
for NATS and PgBouncer — a fifth runtime source must earn the shared rulepack by emitting
`runtime_client` with the agreed raw keys, and must need NO new rules to do it.

The other half of what is pinned here is what Kafka may NOT claim. DescribeConsumerGroups is a
generous API in one direction and silent in three others, and each silence is an inviting place
to fabricate a finding:

  * `client.id` is self-asserted, so it must not become a `principal`. The test that a client.id
    of "admin" does not raise a shared-default-account finding is the load-bearing one.
  * per-member transport is unreported, so `tls_all` must be None and never False — asserted
    explicitly as `is not False`, because False is the exact fabrication being guarded against.
  * consumer groups are consumers, so no claim here covers producers.
"""
from vectasec.connect.kafka import _peer_host, build_runtime_clients
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.runtime  # noqa: F401 — registers the shared rulepack

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("RUNTIME.")}

# Mirrors test_runtime_sources.EXPECTED_RUNTIME_RULES: the rules a source gets for free by
# emitting `runtime_client`. Duplicated deliberately — if the shared set changes, Kafka's
# coverage must be re-examined rather than silently follow.
EXPECTED_RUNTIME_RULES = {
    "RUNTIME.CREDENTIAL.CLEARTEXT_ON_WIRE",
    "RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE",
    "RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT",
    "RUNTIME.TRANSPORT.PLAINTEXT_IN_USE",
    "RUNTIME.ACCESS.UNEXPECTED_PEER",
}


def _member(client_id, host, *, member_id="m-1", topics=((("payments"), 0),), instance=None):
    """Shaped exactly like a normalised MemberDescription from _normalise_group()."""
    return {
        "member_id": member_id,
        "client_id": client_id,
        "host": host,
        "group_instance_id": instance,
        "assignment": {"topic_partitions": [{"topic": t, "partition": p} for t, p in topics]},
    }


# Two members of one group share a client.id and a host (a two-pod deployment) and must fold
# into ONE resource; the third is the trap collection — a client.id that looks like a privileged
# account, reached from public address space, with the Java "/" address rendering.
GROUPS = [
    {
        "group_id": "payments-consumer",
        "state": "STABLE",
        "is_simple_consumer_group": False,
        "partition_assignor": "range",
        "coordinator_id": 1,
        "members": [
            _member("payments-worker", "/10.2.0.7", member_id="pw-a",
                    topics=(("payments", 0), ("payments", 1))),
            _member("payments-worker", "/10.2.0.7", member_id="pw-b",
                    topics=(("payments", 2),)),
            _member("admin", "/93.184.216.34", member_id="adm-a",
                    topics=(("payments", 3), ("topic-created-after-our-metadata-read", 0))),
        ],
    },
    {
        "group_id": "audit-archiver",
        "state": "STABLE",
        "is_simple_consumer_group": False,
        "partition_assignor": "cooperative-sticky",
        "coordinator_id": 1,
        "members": [_member(None, "10.2.0.9:41022", member_id="aa-a",
                            topics=(("audit-events", 0),))],
    },
]

KNOWN_TOPICS = {"payments", "audit-events", "orders"}
KNOWN_BROKERS = {1}


_DEFAULT = object()   # sentinel: None is a MEANINGFUL argument here ("the read did not happen")


def _build(groups=_DEFAULT, **kw):
    kw.setdefault("known_topics", KNOWN_TOPICS)
    kw.setdefault("known_brokers", KNOWN_BROKERS)
    return build_runtime_clients(GROUPS if groups is _DEFAULT else groups, **kw)


def _by_client_id(resources, client_id):
    return next(r for r in resources if (r.raw or {}).get("client_id_self_asserted") == client_id)


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def _fire(rule_id, resource, resources=None):
    d = RULES[rule_id]
    assert "runtime_client" in d.kinds, f"{rule_id} must run on runtime_client"
    return d.fn(resource, _ctx(resources or [resource]))


# ── the shared contract ───────────────────────────────────────────────────────
def test_members_aggregate_into_runtime_clients_with_the_rulepack_keys():
    resources, _, summary = _build()
    assert len(resources) == 3, "two members sharing client.id+host are one client, not two"
    assert all(r.kind == "runtime_client" for r in resources)

    pw = _by_client_id(resources, "payments-worker")
    assert pw.raw["connections"] == 2, "same client.id + peer must fold, keeping the count"
    assert pw.raw["consumer_group"] == "payments-consumer"
    assert pw.raw["topics"] == ["payments"]
    assert pw.raw["assigned_partitions"] == 3
    assert summary["runtime_client_count"] == 3
    assert summary["consumer_group_count"] == 2


def test_raw_speaks_the_same_contract_as_the_other_runtime_sources():
    """The exact key set test_runtime_sources.py requires of every source. A missing key does
    not error — the rule reading it just silently no-ops on Kafka and nowhere else."""
    required = {"principal", "principal_known", "peer_host", "connections", "tls_all",
                "observed_via"}
    resources, _, _ = _build()
    for r in resources:
        assert required <= set(r.raw), f"{r.ext_id} is missing {required - set(r.raw)}"
        assert r.labels.get("source"), "every runtime resource must name the source that saw it"


def test_observed_via_states_the_producer_blind_spot_on_every_resource():
    """The rulepack interpolates observed_via into its observation prose, so this is how the
    scope limit reaches the finding a human actually reads."""
    resources, _, _ = _build()
    for r in resources:
        assert "DescribeConsumerGroups" in r.raw["observed_via"]
        assert "producers are not visible" in r.raw["observed_via"]
    hits = _fire("RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT", resources[0])
    assert "producers are not visible" in hits[0].observation


# ── honesty limit 1: client.id is self-asserted, not a principal ──────────────
def test_client_id_is_recorded_but_never_presented_as_a_principal():
    resources, _, _ = _build()
    for r in resources:
        assert r.raw["principal"] is None
        assert r.raw["principal_known"] is False
        assert r.labels["principal"] == "unknown"
    assert _by_client_id(resources, "admin").raw["client_id_self_asserted"] == "admin"


def test_a_client_id_of_admin_does_not_raise_a_shared_default_account_finding():
    """The fabrication this design exists to prevent. client.id is a string the CLIENT chooses,
    so treating it as an identity would let anyone raise — or impersonate — a privileged-account
    finding by renaming their consumer."""
    resources, _, _ = _build()
    assert not _fire("RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE",
                     _by_client_id(resources, "admin"))


def test_every_kafka_client_is_reported_unattributed():
    """The honest outcome, not a gap in the implementation: no Kafka API binds a group member
    to an authenticated principal, and on a PLAINTEXT broker the principal really is ANONYMOUS."""
    resources, _, _ = _build()
    for r in resources:
        hits = _fire("RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT", r)
        assert hits, f"{r.ext_id} must be reported as unattributed"
        assert hits[0].assessable is True, "unattributed is an assessed finding, not a gap"


def test_a_member_with_no_client_id_still_produces_a_resource():
    resources, _, _ = _build()
    anon = _by_client_id(resources, None)
    assert anon.raw["peer_host"] == "10.2.0.9"
    assert anon.raw["connections"] == 1


# ── honesty limit 2: transport is unknown, never plaintext ───────────────────
def test_tls_all_is_unknown_and_specifically_not_false():
    """`is not False` is the assertion that matters. DescribeConsumerGroups cannot tell which
    listener a member reached, so False would be a plaintext session we never observed."""
    resources, _, _ = _build()
    for r in resources:
        assert r.raw["tls_all"] is None
        assert r.raw["tls_all"] is not False
        assert r.labels["tls"] == "unknown"


def test_transport_rule_files_a_coverage_gap_rather_than_a_plaintext_claim():
    resources, _, _ = _build()
    hits = _fire("RUNTIME.TRANSPORT.PLAINTEXT_IN_USE", _by_client_id(resources, "payments-worker"))
    assert hits, "silence would be indistinguishable from 'checked, it is encrypted'"
    assert hits[0].assessable is False
    assert "does not report" in hits[0].assessment_reason
    assert "are not TLS" not in hits[0].observation, "must not assert an unobserved exposure"


def test_tls_mixed_is_absent_because_mixed_transport_is_equally_unknowable():
    resources, _, _ = _build()
    for r in resources:
        assert "tls_mixed" not in r.raw


# ── honesty limit 3: the SASL mechanism is unreported, so nothing is claimed ──
def test_cleartext_credential_rule_stays_silent_because_no_mechanism_was_read():
    """`auth_mechanisms: []` would read as 'checked, nothing cleartext'. The key is absent
    instead, so the rule is silent about a question this source never asked."""
    resources, _, _ = _build()
    for r in resources:
        assert "auth_mechanisms" not in r.raw
        assert not _fire("RUNTIME.CREDENTIAL.CLEARTEXT_ON_WIRE", r)


# ── peer host: the Java "/" rendering ─────────────────────────────────────────
def test_peer_host_normalisation_survives_java_rendering_and_ipv6():
    assert _peer_host("/10.2.0.7") == "10.2.0.7"
    assert _peer_host("10.2.0.9:41022") == "10.2.0.9"
    assert _peer_host("/[2001:db8::1]:41022") == "2001:db8::1"
    assert _peer_host("2001:db8::1") == "2001:db8::1", "a bare IPv6 must not lose its last group"
    assert _peer_host("consumer.internal") == "consumer.internal"
    assert _peer_host(None) is None


def test_public_peer_fires_only_for_the_public_client():
    """Without stripping the "/" this rule would never fire on any Kafka client at all —
    ip_address() raises on "/93.184.216.34" and the rule treats unparseable peers as hostnames."""
    resources, _, _ = _build()
    assert _fire("RUNTIME.ACCESS.UNEXPECTED_PEER", _by_client_id(resources, "admin"))
    assert not _fire("RUNTIME.ACCESS.UNEXPECTED_PEER",
                     _by_client_id(resources, "payments-worker"))


# ── stable identity across scans ──────────────────────────────────────────────
def test_ext_id_is_stable_across_two_identical_builds():
    first, _, _ = _build()
    second, _, _ = _build()
    assert [r.ext_id for r in first] == [r.ext_id for r in second]


def test_ext_id_survives_a_rebalance_that_changes_every_member_id():
    """Kafka mints a new member_id on every rebalance. An ext_id carrying one would mint a new
    resource each scan and re-fingerprint every finding on it — findings would never age."""
    rebalanced = [
        {**g, "members": [{**m, "member_id": f"{m['member_id']}-regenerated"}
                          for m in g["members"]]}
        for g in GROUPS
    ]
    before, _, _ = _build()
    after, _, _ = _build(rebalanced)
    assert [r.ext_id for r in before] == [r.ext_id for r in after]


# ── denied read vs empty estate ───────────────────────────────────────────────
def test_denied_describe_is_unreadable_and_distinguishable_from_zero_groups():
    """The `config_error` discipline, applied to the runtime read: a scanner denied
    DescribeConsumerGroups by an ACL must never render as a cluster nobody is consuming from."""
    denied, denied_edges, denied_summary = _build(
        None, groups_error="KafkaException: GROUP_AUTHORIZATION_FAILED")
    assert denied == [] and denied_edges == []
    assert denied_summary["consumer_groups_error"] == \
        "KafkaException: GROUP_AUTHORIZATION_FAILED"
    assert denied_summary["consumer_group_count"] is None, "None = not read"
    assert denied_summary["consumer_groups_described"] is None
    assert denied_summary["runtime_client_count"] is None

    empty, _, empty_summary = _build([], listed_count=0)
    assert empty == []
    assert empty_summary["consumer_groups_error"] is None
    assert empty_summary["consumer_group_count"] == 0, "0 = read it, there are none"
    assert empty_summary["consumer_groups_described"] == 0
    assert empty_summary["runtime_client_count"] == 0


def test_a_group_that_could_not_be_described_is_recorded_without_voiding_the_rest():
    """Partial evidence is still evidence: discarding the groups we DID read because one was
    denied would lose real observations, so the failure is recorded alongside them."""
    resources, _, summary = _build(group_errors={"secret-group": "KafkaException: denied"},
                                   listed_count=3)
    assert len(resources) == 3, "the readable groups still produce evidence"
    assert summary["consumer_group_errors"] == {"secret-group": "KafkaException: denied"}
    assert summary["consumer_groups_error"] is None
    assert summary["consumer_group_count"] == 3, "three groups exist"
    assert summary["consumer_groups_described"] == 2, "we could only read two of them"


def test_groups_listed_but_all_describes_denied_does_not_read_as_an_idle_cluster():
    """A principal with List but not Describe on the group resource. Every description fails, so
    zero clients are observed — on a cluster with five groups actively consuming."""
    _, _, summary = _build([], listed_count=5,
                           group_errors={f"g{i}": "KafkaException: denied" for i in range(5)})
    assert summary["consumer_group_count"] == 5, "the cluster is demonstrably not empty"
    assert summary["consumer_groups_described"] == 0
    assert summary["runtime_client_count"] == 0
    assert len(summary["consumer_group_errors"]) == 5, "why the zero exists is recorded"


def test_a_group_with_no_members_produces_no_runtime_clients():
    """An EMPTY group is a committed offset with nobody attached. Claiming a live client there
    would be evidence of a connection that does not exist."""
    resources, _, summary = _build([{**GROUPS[0], "state": "EMPTY", "members": []}])
    assert resources == []
    assert summary["consumer_group_count"] == 1, "the group exists; nobody is connected to it"
    assert summary["runtime_client_count"] == 0


# ── edges ─────────────────────────────────────────────────────────────────────
def test_runtime_edges_link_the_client_to_what_it_demonstrably_used():
    resources, edges, _ = _build()
    ext = _by_client_id(resources, "payments-worker").ext_id
    topic_edges = {e.dst_ext_id for e in edges if e.src_ext_id == ext and e.kind == "uses"}
    assert "topic-payments" in topic_edges
    assert "broker-1" in topic_edges, "the group coordinator is the cluster end of the edge"
    assert all(e.src_ext_id.startswith("runtime-kafka-")
               for e in edges), "runtime edges must originate at the observed client"


def test_an_assignment_to_an_uncollected_topic_is_dropped_not_invented():
    """A topic can be created between list_topics() and DescribeConsumerGroups. scan.py drops
    edges to unknown endpoints silently, so the Collected must not carry one to begin with."""
    _, edges, _ = _build()
    assert not [e for e in edges
                if e.dst_ext_id == "topic-topic-created-after-our-metadata-read"]


def test_edges_are_absent_when_the_coordinator_is_not_a_broker_we_collected():
    _, edges, _ = _build(known_brokers=set())
    assert not [e for e in edges if e.dst_ext_id.startswith("broker-")]


# ── the cross-source guarantee ────────────────────────────────────────────────
def test_kafka_earns_the_shared_rules_with_no_rule_changes():
    """The point of the whole exercise: a new runtime source needs no new rules. The exact set
    that fires is pinned, so both a lost rule and a newly fabricated claim fail here."""
    assert EXPECTED_RUNTIME_RULES <= set(RULES)
    resources, _, _ = _build()
    fired = {rule_id for rule_id in EXPECTED_RUNTIME_RULES
             for r in resources if _fire(rule_id, r, resources)}
    assert fired == {
        "RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT",   # correct: no principal is knowable
        "RUNTIME.TRANSPORT.PLAINTEXT_IN_USE",     # correct: fires NOT-ASSESSABLE, see below
        "RUNTIME.ACCESS.UNEXPECTED_PEER",         # correct: one member is on a public address
    }


def test_no_kafka_client_produces_an_assessed_transport_failure():
    """Guards the whole class of regression: any future change that sets tls_all to False turns
    every one of these coverage gaps into an asserted plaintext exposure."""
    resources, _, _ = _build()
    for r in resources:
        for hit in _fire("RUNTIME.TRANSPORT.PLAINTEXT_IN_USE", r):
            assert hit.assessable is False
