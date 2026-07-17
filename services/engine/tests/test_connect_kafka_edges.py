"""The Kafka connector must emit broker->topic edges whose endpoints resolve.

An edge whose src/dst ext_id does not match an emitted Resource is silently dropped by
scan.py's _persist_edges, so the load-bearing assertion is that every edge endpoint exists
among the collected resource ext_ids. No network: the connector's edge logic is exercised
through a fake ClusterMetadata.
"""
from vectasec.connect import kafka


class _P:
    def __init__(self, leader, replicas):
        self.leader = leader
        self.replicas = replicas


class _Topic:
    def __init__(self, name, partitions):
        self.topic = name
        self.partitions = partitions


class _Broker:
    def __init__(self, bid, host="h", port=9092):
        self.id = bid
        self.host = host
        self.port = port


class _MD:
    def __init__(self, brokers, topics, controller_id=1, cluster_id="c"):
        self.brokers = {b.id: b for b in brokers}
        self.topics = {t.topic: t for t in topics}
        self.controller_id = controller_id
        self.cluster_id = cluster_id


class _Fut:
    def __init__(self, val):
        self._val = val

    def result(self, timeout=None):
        return self._val


class _Admin:
    """Minimal AdminClient: empty configs/acls (the edge logic only reads metadata)."""
    def __init__(self, md):
        self._md = md

    def list_topics(self, timeout=15):
        return self._md

    def describe_configs(self, resources, request_timeout=15):
        return {r: _Fut({}) for r in resources}

    def describe_acls(self, *a, **k):
        return _Fut([])


def _collect(md, monkeypatch):
    import confluent_kafka.admin as adm
    monkeypatch.setattr(adm, "AdminClient", lambda cfg: _Admin(md))
    return kafka.collect({"bootstrap": "x:9092"})


def test_edges_link_broker_to_each_topic_and_resolve(monkeypatch):
    md = _MD(
        brokers=[_Broker(1)],
        topics=[_Topic("payments", {0: _P(1, [1]), 1: _P(1, [1]), 2: _P(1, [1])}),
                _Topic("orders", {0: _P(1, [1])})],
    )
    collected = _collect(md, monkeypatch)

    ext_ids = {r.ext_id for r in collected.resources}
    assert "broker-1" in ext_ids and "topic-payments" in ext_ids

    assert collected.edges, "connector emitted no edges"
    for e in collected.edges:
        assert e.kind == "hosts"
        # THE invariant: both endpoints must be real collected resources, or scan.py drops the edge.
        assert e.src_ext_id in ext_ids, f"dangling src {e.src_ext_id}"
        assert e.dst_ext_id in ext_ids, f"dangling dst {e.dst_ext_id}"

    dsts = {e.dst_ext_id for e in collected.edges}
    assert dsts == {"topic-payments", "topic-orders"}


def test_topic_linked_to_partition_leader_not_every_broker(monkeypatch):
    # Two brokers; topic-a led entirely by broker 2. The edge must be broker-2 -> topic-a only.
    md = _MD(
        brokers=[_Broker(1), _Broker(2)],
        topics=[_Topic("a", {0: _P(2, [2, 1]), 1: _P(2, [2, 1])})],
        controller_id=1,
    )
    collected = _collect(md, monkeypatch)
    a_edges = [e for e in collected.edges if e.dst_ext_id == "topic-a"]
    assert {e.src_ext_id for e in a_edges} == {"broker-2"}, "topic linked to a non-leader broker"


def test_leaderless_topic_falls_back_to_all_brokers(monkeypatch):
    # leader == -1 everywhere (no live leader). The topic must still appear in the graph.
    md = _MD(
        brokers=[_Broker(1), _Broker(2)],
        topics=[_Topic("orphan", {0: _P(-1, [])})],
    )
    collected = _collect(md, monkeypatch)
    o_edges = {e.src_ext_id for e in collected.edges if e.dst_ext_id == "topic-orphan"}
    assert o_edges == {"broker-1", "broker-2"}, "a leaderless topic vanished from the graph"
