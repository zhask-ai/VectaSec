"""Kafka connector — read-only. Lists brokers/topics and reads broker config
via the Admin API, normalising into resources.

It also collects RUNTIME EVIDENCE — who is consuming from this cluster right now — from
DescribeConsumerGroups, emitting the shared `runtime_client` kind that detect/runtime.py
fires on. What that API can and cannot honestly support is spelled out at _OBSERVED_VIA.
"""
from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected

# Every runtime claim this connector makes carries this string, because the rulepack
# interpolates `observed_via` into the observation prose of every finding it raises. The scope
# limit therefore travels with the claim instead of living in a doc nobody reads next to it:
# consumer groups contain CONSUMERS. A producer holds no group membership and is invisible to
# this API, so "the clients using this cluster" is never something this source may be read as.
_OBSERVED_VIA = ("DescribeConsumerGroups — consumer-group members only; producers are not "
                 "visible to this API")


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


def _peer_host(host):
    """A group member's address, normalised into something `ipaddress` can parse.

    Kafka reports a member's host the way Java renders an InetAddress — `/10.2.0.7` — and the
    leading slash is a silent poison pill: RUNTIME.ACCESS.UNEXPECTED_PEER calls
    ipaddress.ip_address(), catches ValueError and treats anything unparseable as a hostname,
    which it deliberately says nothing about. A member connecting from public address space
    would therefore never be reported, and the rule would look like it had passed.

    Only a single colon is stripped as a port; a bare IPv6 literal has several and must survive
    intact, or the same rule loses IPv6 peers the same silent way.

    The slash is taken from the RIGHT, not stripped from the left: Java renders the same
    address as `hostname/10.2.0.7` whenever it carries a resolved hostname, and lstrip left
    that form whole — walking straight into the failure this function exists to prevent, for
    exactly the clients a reverse lookup succeeded on.
    """
    h = str(host or "").strip()
    h = h.rsplit("/", 1)[-1]
    if h.startswith("["):                      # [2001:db8::1]:34512
        h = h[1:].split("]", 1)[0]
    elif h.count(":") == 1:                    # 10.2.0.7:34512 — one colon cannot be IPv6
        h = h.rsplit(":", 1)[0]
    return h or None


def _normalise_group(desc) -> dict:
    """ConsumerGroupDescription -> plain dict, so build_runtime_clients() stays pure.

    `state` is an enum whose value differs across confluent-kafka releases, so it is resolved
    to its NAME here for the same reason _normalise() resolves ConfigSource: a downstream
    comparison against an int that shifted under us fails silently and answers wrongly.
    """
    members = []
    for m in getattr(desc, "members", None) or []:
        assignment = getattr(m, "assignment", None)
        tps = getattr(assignment, "topic_partitions", None) or []
        members.append({
            # member_id is captured for completeness but never keys anything: see the ext_id
            # note in build_runtime_clients().
            "member_id": getattr(m, "member_id", None),
            "client_id": getattr(m, "client_id", None),
            "host": getattr(m, "host", None),
            "group_instance_id": getattr(m, "group_instance_id", None),
            "assignment": {"topic_partitions": [
                {"topic": getattr(tp, "topic", None), "partition": getattr(tp, "partition", None)}
                for tp in tps
            ]},
        })
    state = getattr(desc, "state", None)
    coordinator = getattr(desc, "coordinator", None)
    return {
        "group_id": getattr(desc, "group_id", None),
        "state": getattr(state, "name", None) or (str(state) if state is not None else None),
        "is_simple_consumer_group": bool(getattr(desc, "is_simple_consumer_group", False)),
        "partition_assignor": getattr(desc, "partition_assignor", None),
        "coordinator_id": getattr(coordinator, "id", None),
        "members": members,
    }


def _fetch_consumer_groups(admin, timeout: float) -> tuple:
    """ListConsumerGroups + DescribeConsumerGroups. Read-only; returns
    (groups, groups_error, group_errors, listed_count).

    `groups is None` means the read did not happen at all — the caller must not render that as
    an empty estate. A per-group failure is recorded separately and does NOT null the whole
    read: a cluster where the scanner may describe four groups and is denied the fifth has
    partial evidence, and discarding the four would lose real observations.

    `listed_count` is reported separately from what we managed to describe, because the two
    genuinely differ: a principal allowed to List but denied Describe on every group yields
    zero descriptions on a cluster that is demonstrably busy, and a lone "0" would read as an
    idle cluster.
    """
    group_errors: dict[str, str] = {}
    try:
        listing = admin.list_consumer_groups(request_timeout=timeout).result(timeout=timeout)
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:200]}", group_errors, None

    for err in getattr(listing, "errors", None) or []:
        # A partial ListGroups (one broker unreachable) means the group list is a floor, not a
        # census. Recorded so "we saw three groups" is never mistaken for "there are three".
        group_errors["list_consumer_groups"] = f"{type(err).__name__}: {str(err)[:200]}"

    group_ids = [g.group_id for g in (getattr(listing, "valid", None) or []) if g.group_id]
    if not group_ids:
        return [], None, group_errors, 0

    try:
        futures = admin.describe_consumer_groups(group_ids, request_timeout=timeout)
    except Exception as e:
        return None, f"{type(e).__name__}: {str(e)[:200]}", group_errors, len(group_ids)

    groups = []
    for gid, fut in futures.items():
        try:
            groups.append(_normalise_group(fut.result(timeout=timeout)))
        except Exception as e:
            group_errors[str(gid)] = f"{type(e).__name__}: {str(e)[:200]}"
    return groups, None, group_errors, len(group_ids)


def build_runtime_clients(groups, *, groups_error=None, group_errors=None, listed_count=None,
                          known_topics=(), known_brokers=()) -> tuple:
    """Normalised consumer-group descriptions -> (resources, edges, summary). Pure.

    Split from the AdminClient call for the same reason rabbitmq/nats/pgbouncer split theirs:
    the shape the rulepack actually sees is then testable with no broker in the room.

    THREE THINGS THIS SOURCE MAY NOT SAY, encoded in the fields below rather than in prose:

      1. `client.id` is SELF-ASSERTED. Kafka does not authenticate it and nothing binds it to
         a principal — any client may claim any client.id. Putting it in `principal` would let
         RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE raise a "the admin account is in use" finding
         off a string an attacker chooses. So `principal` stays None, `principal_known` is
         False, and the value lives in a field whose name states what it is.
         RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT firing on every Kafka client is the CORRECT
         outcome, and on a PLAINTEXT broker it is also literally true: the principal is
         ANONYMOUS.
      2. Per-member TRANSPORT is unknowable. DescribeConsumerGroups does not report which
         listener a member reached, so `tls_all` is None (unknown) and NEVER False. False would
         make RUNTIME.TRANSPORT.PLAINTEXT_IN_USE assert an unencrypted session we never
         observed; None routes it to its not-assessable branch, which is the honest answer.
      3. The SASL mechanism is equally unreported, so `auth_mechanisms` is absent rather than
         []. An empty list reads as "checked, nothing cleartext" and would silence
         RUNTIME.CREDENTIAL.CLEARTEXT_ON_WIRE on a claim we never checked.
    """
    known_topics = set(known_topics or ())
    known_brokers = set(known_brokers or ())
    summary = {
        # None vs 0 is the entire point, and it is the same distinction `config_error` exists
        # to keep for DescribeConfigs: a denied read that rendered as 0 groups would show a
        # busy cluster as an empty one, which is the most reassuring possible lie.
        "consumer_groups_error": groups_error,
        # How many groups the cluster SAID it has, kept apart from how many we could actually
        # read members of. A principal with List but not Describe reports N groups and zero
        # descriptions, and collapsing those into one number would show a busy cluster as idle.
        "consumer_group_count": (listed_count if listed_count is not None
                                 else (None if groups is None else len(groups))),
        "consumer_groups_described": None if groups is None else len(groups),
        "consumer_group_errors": dict(group_errors or {}),
        "runtime_client_count": None if groups is None else 0,
        "runtime_observed_via": _OBSERVED_VIA,
    }
    if groups is None:
        return [], [], summary

    # One resource per (group, client.id, peer host) rather than per member: a 200-consumer
    # fleet is one fact about one client, and 200 rows would drown the inventory. Same
    # aggregation rabbitmq.py makes over /api/connections, for the same reasons.
    agg: dict = {}
    for g in groups:
        gid = str(g.get("group_id") or "")
        for m in g.get("members") or []:
            client_id = m.get("client_id") or None
            peer = _peer_host(m.get("host"))
            key = (gid, client_id or "", peer or "")
            a = agg.setdefault(key, {
                "group_id": gid, "client_id": client_id, "peer_host": peer,
                "members": 0, "topics": set(), "partitions": 0,
                "state": g.get("state"),
                "coordinator_id": g.get("coordinator_id"),
                "is_simple": bool(g.get("is_simple_consumer_group")),
            })
            a["members"] += 1
            for tp in (m.get("assignment") or {}).get("topic_partitions") or []:
                if tp.get("topic"):
                    a["topics"].add(str(tp["topic"]))
                    a["partitions"] += 1

    resources: list[Resource] = []
    edges: list[Edge] = []
    # The key's fields are sort-normalised ("" for absent) and the aggregate's are not. Reading
    # the VALUES back out matters: a member with no client.id must stay None, because "" reads
    # as a client that asserted an empty string rather than one that asserted nothing.
    for _key, a in sorted(agg.items()):
        gid, client_id, peer = a["group_id"], a["client_id"], a["peer_host"]
        # The ext_id carries no member_id and no group generation. Kafka mints a fresh
        # member_id on every rebalance, so either one would make this a NEW resource on every
        # scan and re-fingerprint each finding on it — an unstable ext_id has cost this
        # codebase a round of phantom findings before.
        ext = f"runtime-kafka-{gid}-{client_id or 'unknown'}-{peer or 'unknown'}"
        topics = sorted(a["topics"])
        resources.append(Resource(
            kind="runtime_client",
            name=f"{client_id or 'unnamed client'} (unattributed) in {gid} from {peer}",
            ext_id=ext,
            namespace=gid or None,
            labels={
                "principal": "unknown",
                "principal_known": "false",
                "client_id_self_asserted": str(client_id or ""),
                "consumer_group": gid,
                "peer_host": str(peer or ""),
                "connections": str(a["members"]),
                # "unknown", never "false" — the label feeds console filters, and a filter that
                # lists this client under "plaintext" is the same fabricated claim as the rule
                # making it.
                "tls": "unknown",
                "source": "kafka-describe-consumer-groups",
            },
            raw={
                # ── the source-agnostic contract detect/runtime.py reads ──────────
                "principal": None,
                "principal_known": False,
                "peer_host": peer,
                # Group MEMBERS, not sockets: one member is one live consumer session, which is
                # a floor on the connection count, never an overstatement of it.
                "connections": a["members"],
                "tls_all": None,
                "observed_via": _OBSERVED_VIA,
                # ── Kafka specifics ───────────────────────────────────────────────
                # Named for what it is so no reader, and no future rule, mistakes it for an
                # authenticated identity.
                "client_id_self_asserted": client_id,
                "consumer_group": gid,
                # `vhost` is the cross-source name for "the scope this client was seen in" —
                # runtime_evidence.record_runtime folds evidence on it (account for NATS,
                # database for PgBouncer, consumer group here). Emitting only the Kafka-native
                # name would fold every Kafka client into one undifferentiated bucket.
                "vhost": gid,
                "group_state": a["state"],
                "group_is_simple": a["is_simple"],
                "coordinator_id": a["coordinator_id"],
                # What this client demonstrably read from — the runtime counterpart to an ACL.
                "topics": topics,
                "assigned_partitions": a["partitions"],
            },
        ))

        # The runtime edge: a static ACL says what a principal MAY read; this says what this
        # client was observed reading. Topics absent from the metadata read are dropped rather
        # than invented — a group can be assigned a topic created between our two calls.
        for t in topics:
            if t in known_topics:
                edges.append(Edge(src_ext_id=ext, dst_ext_id=f"topic-{t}", kind="uses",
                                  labels={"via": "consumer-group-assignment", "group": gid}))
        if a["coordinator_id"] in known_brokers:
            edges.append(Edge(src_ext_id=ext, dst_ext_id=f"broker-{a['coordinator_id']}",
                              kind="uses", labels={"role": "group_coordinator"}))

    summary["runtime_client_count"] = len(resources)
    return resources, edges, summary


@connector("kafka", fields=[
    ConnectorField("bootstrap", "Bootstrap servers", required=True,
                   placeholder="broker-1:9092,broker-2:9092",
                   help="Comma-separated host:port list the engine or worker can reach. "
                        "Read-only AdminClient — nothing is written to the cluster."),
])
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
    config_errors: dict[str, str] = {}
    for b in md.brokers.values():
        res = ConfigResource(broker_type, str(b.id))
        try:
            entries = admin.describe_configs([res], request_timeout=timeout)[res].result(timeout=timeout)
            broker_cfg[str(b.id)] = _normalise(entries)
        except Exception as e:
            # {} here is INDISTINGUISHABLE from "read it, it was empty" — and ~22 broker rules
            # read this dict, so a denied DescribeConfigs (the norm on MSK, Confluent Cloud and
            # any least-privilege principal) silently passed the entire pack. Record the failure
            # so detect/kafka.py can file a coverage gap instead of a clean bill of health.
            # The same distinction is already made for cluster_dynamic below.
            broker_cfg[str(b.id)] = {}
            config_errors[str(b.id)] = f"{type(e).__name__}: {str(e)[:200]}"

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

    # RUNTIME EVIDENCE. Everything above reads what the cluster PERMITS; this reads who was
    # actually consuming from it when we looked. The whole block is isolated: brokers, topics
    # and ACLs are the connector's contract with ~24 rules, and a consumer-group read that
    # explodes (denied, unsupported on an ancient broker, timing out) must not take those with
    # it. A crash lands as `consumer_groups_error`, which is a coverage gap, not a lost scan.
    try:
        cg_groups, cg_error, cg_group_errors, cg_listed = _fetch_consumer_groups(admin, timeout)
    except Exception as e:
        cg_groups, cg_error, cg_group_errors, cg_listed = (
            None, f"{type(e).__name__}: {str(e)[:200]}", {}, None)

    runtime_resources, runtime_edges, runtime_summary = build_runtime_clients(
        cg_groups, groups_error=cg_error, group_errors=cg_group_errors, listed_count=cg_listed,
        known_topics={t.topic for t in md.topics.values() if t.topic},
        known_brokers={b.id for b in md.brokers.values()},
    )

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
                 # None = read fine; a string = DescribeConfigs failed and `config` is empty
                 # because we could not read it, NOT because the broker has no settings.
                 "config_error": config_errors.get(str(b.id)),
                 "cluster_id": md.cluster_id, "cluster_dynamic_config": cluster_dynamic,
                 "acls": acls, "cluster_scope": b.id == scope_id,
                 # Cluster-wide like `acls`, and carried on every broker for the same reason:
                 # `cluster_scope` already marks the one owner a cluster-wide rule should fire
                 # on. A None count here means DescribeConsumerGroups was denied or failed —
                 # never that the cluster has no consumers.
                 **runtime_summary},
        ))

    # Topic configs return EFFECTIVE values including what they inherit from the broker, so a
    # topic rule reads them directly rather than reconstructing the inheritance chain. TOPIC
    # resources have no one-per-call limit, so they batch.
    topic_cfg: dict[str, dict] = {}
    # Same discipline as `config_errors` for brokers above, and for exactly the same reason: `{}`
    # is INDISTINGUISHABLE from "read it, nothing was set", and the topic rules read this dict.
    # Recording nothing here is what let a denied topic-scope DescribeConfigs render as a clean
    # topic — broker-scope can be granted while topic-scope is not, so the broker's config_error
    # is None and its coverage rule stays silent too. detect/kafka.py keys
    # KAFKA.SCAN.TOPIC_NOT_ASSESSABLE off this.
    topic_cfg_errors: dict[str, str] = {}
    tres = [ConfigResource(topic_type, t.topic) for t in md.topics.values() if t.topic]
    if tres:
        try:
            for res, fut in admin.describe_configs(tres, request_timeout=timeout).items():
                try:
                    topic_cfg[res.name] = _normalise(fut.result(timeout=timeout))
                except Exception as e:
                    topic_cfg[res.name] = {}
                    topic_cfg_errors[res.name] = f"{type(e).__name__}: {str(e)[:200]}"
        except Exception as e:
            # The whole batch failed (denied, unsupported, timed out), so no per-topic future
            # exists to fail individually: EVERY topic is unread, not read-and-empty.
            err = f"{type(e).__name__}: {str(e)[:200]}"
            for cr in tres:
                topic_cfg_errors[cr.name] = err

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
                 "config": topic_cfg.get(t.topic, {}),
                 # Same key, same shape and same meaning as the broker resource above, so the
                 # two paths read alike: None = read fine; a string = DescribeConfigs failed and
                 # `config` is empty because we could not read it, NOT because the topic has no
                 # settings (a real topic DescribeConfigs response is never empty).
                 "config_error": topic_cfg_errors.get(t.topic)},
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

    # Appended after the topic resources so every `uses` edge above has an endpoint that exists
    # in this same Collected — scan.py's _persist_edges drops an edge whose target it cannot
    # resolve, silently.
    resources.extend(runtime_resources)
    edges.extend(runtime_edges)

    return Collected(resources=resources, edges=edges)
