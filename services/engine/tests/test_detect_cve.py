"""Offline unit tests for the cross-fabric CVE enrichment pack (detect/cve.py + cve_data.py).

No network, no DB: a Resource is built by hand with the SAME labels/raw keys the connectors set
(confirmed against connect/redis.py, connect/rabbitmq.py, connect/activemq.py, connect/mft.py,
connect/solr.py, connect/k8s.py, connect/kong.py, connect/kafka.py) and handed to the detector.

Every rule gets a fires-on-affected AND a silent-on-fixed pair; the version-unreadable path is
covered too, because "we could not read the version" (not-assessable) and "checked, fine" ([])
are different answers and the whole pack turns on not conflating them.
"""
from vectasec.contracts import Resource, ScanContext
from vectasec.cve_data import CVES, cves_for_product, products_with_cves
from vectasec.detect import cve


def ctx_of(*resources):
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def one(hits):
    assert len(hits) == 1, f"expected exactly one Hit, got {len(hits)}: {hits}"
    return hits[0]


# ── Builders keyed on the real connector shapes ────────────────────────────────
def redis(version):
    return Resource(kind="redis_server", name="cache", ext_id="redis-1",
                    labels={"version": str(version)}, raw={"redis_version": version})


def rabbit_cluster(version):
    return Resource(kind="node", name="rabbit@n1", ext_id="rabbit-cluster",
                    raw={"role": "cluster", "overview": {"rabbitmq_version": version}})


def rabbit_node():
    return Resource(kind="node", name="rabbit@n2", ext_id="rabbit-n2", raw={"role": "disc"})


def kafka_broker():
    return Resource(kind="broker", name="broker-1", ext_id="broker-1",
                    labels={"host": "h", "port": "9092"}, raw={"id": 1, "host": "h", "port": 9092})


def kong_broker(version="3.6.0"):
    return Resource(kind="broker", name="kong", ext_id="kong-1",
                    labels={"edition": "community", "version": version}, raw={"version": version})


def activemq(version):
    return Resource(kind="activemq_broker", name="amq", ext_id="amq-1",
                    labels={"flavor": "classic", "version": str(version)},
                    raw={"flavor": "classic", "broker_version": version})


def solr(version):
    return Resource(kind="solr_server", name="solr", ext_id="solr-1",
                    labels={"version": str(version)}, raw={"version": version})


def k8s(version):
    return Resource(kind="k8s_cluster", name="cluster", ext_id="k8s-1",
                    labels={"version": str(version)}, raw={"version": version})


def mft(product, version):
    return Resource(kind="mft_server", name=f"{product}:host", ext_id="mft-1",
                    labels={"product": product, "version": str(version or "?"), "scheme": "https"},
                    raw={"product": product, "version": version})


# ── Redis (also natively covered; this is the enrichment view) ──────────────────
def test_redis_affected_version_fires_with_cve_and_source():
    hit = one(cve.known_cve(redis("7.2.4"), ctx_of()))
    assert hit.source_ref["cve"] == "CVE-2025-49844"
    assert hit.severity == "critical"                       # CVSS 10.0
    assert "7.2.4" in hit.observation and "redis.io" in hit.remediation
    assert hit.source_ref["fixed_in"] == "7.2.11"


def test_redis_fixed_version_is_silent():
    assert cve.known_cve(redis("7.2.11"), ctx_of()) == []


def test_redis_unreadable_version_is_not_assessable_never_a_vuln():
    hit = one(cve.known_cve(redis(None), ctx_of()))
    assert hit.assessable is False
    assert "not parseable" in hit.assessment_reason
    assert "CVE-2025-49844" in hit.source_ref["candidate_cves"]


def test_redis_series_without_a_declared_interval_is_not_flagged():
    # 7.0.x is EOL and not in any declared interval — the engine asserts only what the ranges say.
    assert cve.known_cve(redis("7.0.5"), ctx_of()) == []


# ── RabbitMQ (fires only on the cluster resource) ──────────────────────────────
def test_rabbitmq_cluster_affected_fires():
    hit = one(cve.known_cve(rabbit_cluster("3.12.3"), ctx_of()))
    assert hit.source_ref["cve"] == "CVE-2023-46118"
    assert hit.severity == "medium"                         # CVSS 4.9, not KEV


def test_rabbitmq_cluster_fixed_is_silent():
    assert cve.known_cve(rabbit_cluster("3.12.7"), ctx_of()) == []


def test_rabbitmq_per_node_resource_carries_no_version_signal():
    assert cve.known_cve(rabbit_node(), ctx_of()) == []


def test_rabbitmq_cluster_with_unreadable_version_is_not_assessable():
    r = Resource(kind="node", name="c", ext_id="c", raw={"role": "cluster", "overview": {}})
    assert one(cve.known_cve(r, ctx_of())).assessable is False


# ── broker kind is shared: Kong has a version but no CVE; Kafka has neither ─────
def test_kafka_broker_has_no_version_signal_and_is_silent():
    assert cve.known_cve(kafka_broker(), ctx_of()) == []


def test_kong_broker_is_tracked_but_has_no_curated_cve_so_stays_silent():
    # Kong maps to a product, but the dataset holds no Kong CVE — nothing to assess is not a gap.
    assert cve.known_cve(kong_broker("3.6.0"), ctx_of()) == []
    assert "kong" not in products_with_cves()


# ── ActiveMQ: KEV escalation ───────────────────────────────────────────────────
def test_activemq_affected_is_escalated_to_critical_by_kev():
    hit = one(cve.known_cve(activemq("5.17.3"), ctx_of()))
    assert hit.source_ref["cve"] == "CVE-2023-46604"
    assert hit.source_ref["kev"] is True
    assert hit.severity == "critical"                       # CVSS 10.0 already critical; KEV caps there


def test_activemq_fixed_branch_is_silent():
    assert cve.known_cve(activemq("5.17.6"), ctx_of()) == []
    assert cve.known_cve(activemq("6.0.0"), ctx_of()) == []  # 6.x is not in any 5.x interval


# ── MFT / MOVEit: product comes from the fingerprint label ─────────────────────
def test_mft_moveit_affected_fires():
    hit = one(cve.known_cve(mft("moveit", "15.0.0"), ctx_of()))
    assert hit.source_ref["cve"] == "CVE-2023-34362"
    assert hit.source_ref["kev"] is True


def test_mft_moveit_fixed_is_silent():
    assert cve.known_cve(mft("moveit", "15.0.1"), ctx_of()) == []


def test_mft_unfingerprinted_product_is_silent():
    assert cve.known_cve(mft("unknown", None), ctx_of()) == []


def test_mft_known_product_without_a_curated_cve_is_silent():
    # goanywhere is a recognised MFT product but carries no dataset entry here.
    assert cve.known_cve(mft("goanywhere", "7.4.0"), ctx_of()) == []


# ── Solr: two disjoint affected branches ───────────────────────────────────────
def test_solr_8x_branch_fires_and_fixed_is_silent():
    assert one(cve.known_cve(solr("8.11.3"), ctx_of())).source_ref["cve"] == "CVE-2024-45216"
    assert cve.known_cve(solr("8.11.4"), ctx_of()) == []


def test_solr_9x_branch_fires_and_fixed_is_silent():
    assert one(cve.known_cve(solr("9.6.1"), ctx_of())).source_ref["cve"] == "CVE-2024-45216"
    assert cve.known_cve(solr("9.7.0"), ctx_of()) == []


def test_solr_below_introduced_floor_is_not_flagged():
    assert cve.known_cve(solr("4.10.0"), ctx_of()) == []     # < 5.3.0 introduced floor


# ── Kubernetes: 'v'-prefixed version, old fires / modern silent ────────────────
def test_k8s_old_version_fires_and_modern_is_silent():
    assert one(cve.known_cve(k8s("v1.11.2"), ctx_of())).source_ref["cve"] == "CVE-2018-1002105"
    assert cve.known_cve(k8s("v1.28.3"), ctx_of()) == []


# ── Interval boundaries and version parsing ────────────────────────────────────
def test_interval_is_half_open_introduced_inclusive_fixed_exclusive():
    assert cve.known_cve(redis("8.2.0"), ctx_of()) != []     # introduced boundary → affected
    assert cve.known_cve(redis("8.2.2"), ctx_of()) == []     # fixed boundary → clean


def test_version_parser_tolerates_prefix_and_extra_segments():
    assert cve._parse_version("v1.11.2") == (1, 11, 2)
    assert cve._parse_version("15.0.1.51") == (15, 0, 1)
    assert cve._parse_version("8.2.1-alpine") == (8, 2, 1)
    assert cve._parse_version("garbage") is None


def test_severity_bands_and_kev_escalation():
    assert cve._severity({"cvss": 4.9, "kev": False}) == "medium"
    assert cve._severity({"cvss": 8.1, "kev": False}) == "high"
    assert cve._severity({"cvss": 8.1, "kev": True}) == "critical"     # high → +1 tier
    assert cve._severity({"cvss": 9.8, "kev": True}) == "critical"     # capped


# ── Dataset integrity ──────────────────────────────────────────────────────────
def test_every_dataset_entry_is_well_formed():
    for c in CVES:
        assert c["cve_id"].startswith("CVE-")
        assert c["product"] and c["product"] == c["product"].lower()
        assert isinstance(c["cvss"], (int, float)) and 0 <= c["cvss"] <= 10
        assert isinstance(c["kev"], bool)
        assert c["source_url"].startswith("http")
        assert c["affected"] and all("fixed" in iv for iv in c["affected"])


def test_cves_for_product_is_case_insensitive_and_empty_for_unknown():
    assert cves_for_product("REDIS") == cves_for_product("redis") != []
    assert cves_for_product("nonexistent") == []
    assert cves_for_product("") == []
