"""Kafka connector — read-only. Lists brokers/topics and reads broker config
via the Admin API, normalising into resources."""
from ..registry import connector
from ..contracts import Resource, Edge, Collected


def _normalise(entries: dict) -> dict:
    """ConfigEntry -> the dict shape detectors read.

    `ConfigEntry.source` is an int at runtime even though it is type-hinted ConfigSource, so it
    is resolved to a name HERE — a downstream `entry.source == ConfigSource.X` compare silently
    never fires and yields a wrong answer with no exception.

    `is_sensitive`/`is_default` are kept because the broker redacts PASSWORD-typed values to
    None: without them a detector cannot tell "explicitly configured but unreadable" from
    "not set", and would report the second when the truth is the first.
    """
    from confluent_kafka.admin import ConfigSource

    out: dict[str, dict] = {}
    for e in entries.values():
        try:
            source_name = ConfigSource(e.source).name
        except (ValueError, TypeError):
            source_name = None
        out[e.name] = {
            "value": None if e.is_sensitive else e.value,   # never store a redacted secret
            "source": int(e.source),
            "source_name": source_name,
            "is_default": bool(e.is_default),
            "is_sensitive": bool(e.is_sensitive),
            "is_read_only": bool(e.is_read_only),
        }
    return out


@connector("kafka")
def collect(config: dict) -> Collected:
    from confluent_kafka import KafkaError, KafkaException
    from confluent_kafka.admin import (
        AclBindingFilter, AclOperation, AclPermissionType, AdminClient,
        ConfigResource, ResourcePatternType, ResourceType,
    )

    try:
        broker_type = ConfigResource.Type.BROKER
        topic_type = ConfigResource.Type.TOPIC
    except AttributeError:  # older/newer enum layout
        broker_type, topic_type = 4, 2

    bootstrap = config["bootstrap"]
    timeout = float(config.get("timeout", 15))
    admin = AdminClient({"bootstrap.servers": bootstrap, "socket.timeout.ms": 10000})
    md = admin.list_topics(timeout=15)

    resources: list[Resource] = []

    # Broker configs (the posture surface). One call per broker: the Admin API allows at most one
    # BROKER resource per describe_configs, and the resource name must be a CONCRETE broker id —
    # ConfigResource(BROKER, "") returns only cluster-wide dynamic defaults, where no static
    # security setting (listeners, authorizer.class.name, ssl.*) ever appears.
    broker_cfg: dict[str, dict] = {}
    for b in md.brokers.values():
        res = ConfigResource(broker_type, str(b.id))
        try:
            entries = admin.describe_configs([res], request_timeout=timeout)[res].result(timeout=timeout)
            broker_cfg[str(b.id)] = _normalise(entries)
        except Exception:
            broker_cfg[str(b.id)] = {}

    # The one place the empty resource name is correct: unclean.leader.election.enable has update
    # mode "cluster-wide", and KRaft resolves it from the cluster dynamic config, never from a
    # broker's static config. None means "not read" — distinct from {} meaning "read, empty".
    cluster_dynamic: dict | None
    try:
        res = ConfigResource(broker_type, "")
        cluster_dynamic = _normalise(
            admin.describe_configs([res], request_timeout=timeout)[res].result(timeout=timeout)
        )
    except Exception:
        cluster_dynamic = None

    # ACLs, cluster-wide. The OUTCOME is recorded, not just the result: an empty list does not
    # prove "no authorizer" (an authorizer with zero ACLs returns [] too), and a permissions
    # failure must never be read as "there are no ACLs".
    acls: dict = {"outcome": "error", "bindings": [], "error": None}
    try:
        f = AclBindingFilter(ResourceType.ANY, None, ResourcePatternType.ANY, None, None,
                             AclOperation.ANY, AclPermissionType.ANY)
        bindings = admin.describe_acls(f, request_timeout=timeout).result(timeout=timeout)
        acls = {
            "outcome": "ok",
            "bindings": [
                {"restype": b.restype.name, "name": b.name,
                 "pattern": b.resource_pattern_type.name, "principal": b.principal,
                 "host": b.host, "operation": b.operation.name,
                 "permission_type": b.permission_type.name}
                for b in bindings
            ],
            "error": None,
        }
    except KafkaException as ex:
        err = ex.args[0]
        acls = {
            "outcome": "security_disabled" if err.code() == KafkaError.SECURITY_DISABLED else "error",
            "bindings": [],
            "error": err.name(),
        }

    # ACLs are one cluster-wide fact, but findings are fingerprinted on (rule, resource) — without
    # a single owner an ACL rule would raise N identical findings on an N-broker cluster.
    scope_id = md.controller_id if md.controller_id in md.brokers else (
        min(md.brokers) if md.brokers else None)

    for b in md.brokers.values():
        cfg = broker_cfg.get(str(b.id), {})
        resources.append(Resource(
            kind="broker",
            name=f"broker-{b.id}",
            ext_id=f"broker-{b.id}",
            labels={"host": b.host, "port": str(b.port)},
            raw={"id": b.id, "host": b.host, "port": b.port, "config": cfg,
                 "cluster_id": md.cluster_id, "cluster_dynamic_config": cluster_dynamic,
                 "acls": acls, "cluster_scope": b.id == scope_id},
        ))

    # Topic configs return EFFECTIVE values including what they inherit from the broker, so a
    # topic rule reads them directly rather than reconstructing the inheritance chain. TOPIC
    # resources have no one-per-call limit, so they batch.
    topic_cfg: dict[str, dict] = {}
    tres = [ConfigResource(topic_type, t.topic) for t in md.topics.values() if t.topic]
    if tres:
        try:
            for res, fut in admin.describe_configs(tres, request_timeout=timeout).items():
                try:
                    topic_cfg[res.name] = _normalise(fut.result(timeout=timeout))
                except Exception:
                    topic_cfg[res.name] = {}
        except Exception:
            pass  # a target that denies topic DescribeConfigs leaves topic rules indeterminate

    # broker --hosts--> topic edges. A topic is linked to the broker(s) that actually LEAD its
    # partitions, not to every broker: partition leadership is where a topic's traffic and its
    # exposure live, so "what does this broker touch" and blast-radius stay accurate on a
    # multi-broker cluster. ext_ids match the Resources above exactly, or scan.py's _persist_edges
    # drops the edge. A partition with no live leader (leader == -1) is skipped rather than linked
    # to a broker that isn't there.
    edges: list[Edge] = []
    known_brokers = {b.id for b in md.brokers.values()}
    for t in md.topics.values():
        rfs = [len(p.replicas) for p in t.partitions.values()]
        resources.append(Resource(
            kind="topic",
            name=t.topic,
            ext_id=f"topic-{t.topic}",
            labels={"partitions": str(len(t.partitions))},
            raw={"partitions": len(t.partitions),
                 "replication_factor": min(rfs) if rfs else None,
                 "internal": (t.topic or "").startswith("__"),
                 "config": topic_cfg.get(t.topic, {})},
        ))
        leaders = {p.leader for p in t.partitions.values()
                   if p.leader in known_brokers and p.leader >= 0}
        # Fall back to every broker only if leadership is unknown (metadata gave no usable leader)
        # — a topic must not silently vanish from the graph because leader data was absent.
        for bid in (leaders or known_brokers):
            edges.append(Edge(
                src_ext_id=f"broker-{bid}", dst_ext_id=f"topic-{t.topic}", kind="hosts",
                labels={"leads_partitions": str(sum(1 for p in t.partitions.values()
                                                    if p.leader == bid))},
            ))

    return Collected(resources=resources, edges=edges)
