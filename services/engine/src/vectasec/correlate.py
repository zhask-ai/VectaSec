"""Estate correlation — the question no single scan can answer.

A detector sees one scan's resources. But "is this broker we just found on the network actually
one we monitor?" needs the whole tenant: the discovered services from a discovery sweep on one
side, every configured connection on the other. That join is what turns a list of open ports
into the sentence a security team actually reacts to — *"there is a Kafka broker on 10.0.4.7
that nobody is watching."*

Shadow middleware is the most valuable finding this product can produce, precisely because it
is the one nobody could have asked for. You cannot request a scan of a broker you forgot you
had, and the systems people forget are the ones still running the defaults.

Runs after persistence, in its own transaction, exactly like `notify_scan` — a correlation
failure must never void a completed scan.

Matching discipline: a connection "covers" a discovered service when their host AND port agree.
Hostnames are compared to hostnames and addresses to addresses WITHOUT resolving either (see
`discover/targets.py` for why a scanner must not decide identity from DNS), with the one safe
normalisation that loopback spellings mean the same host. When we cannot tell — a connection
whose config names no endpoint we understand — the service is reported as UNCERTAIN rather than
unmonitored, because a false "shadow broker!" alarm on the broker you are already scanning is
how a team learns to ignore this rule.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from .scan import _active_suppressions, _is_suppressed, fingerprint

RULE_UNMONITORED = "COVERAGE.SERVICE.UNMONITORED"
RULE_TITLE = "Discovered service is not a monitored connection"

# Config keys a connector might use to name where it points. Deliberately broad: a key we fail
# to recognise costs us a false "unmonitored" claim, so this list errs toward finding endpoints.
_ENDPOINT_KEYS = (
    "bootstrap", "bootstrap_servers", "url", "host", "hosts", "endpoint", "address",
    "admin_url", "server", "servers", "uri", "brokers", "cluster", "node",
)

_LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

# Ports that belong to the SAME logical system, per product. One RabbitMQ broker listens on
# AMQP (5672) and its management API (15672); a connection pointed at either one monitors the
# broker, so finding the other port must not read as a second, unmonitored system.
#
# This is deliberately narrower than "same host, same product, any port": two Redis instances on
# 6379 and 6380 really are two systems, and collapsing them would hide the unmonitored one. So
# ports are grouped only where a single product is KNOWN to serve several standard ports.
_PORT_GROUPS: dict[str, tuple[frozenset[int], ...]] = {
    "rabbitmq": (frozenset({5671, 5672, 15671, 15672}),),
    "amqp": (frozenset({5671, 5672, 15671, 15672}),),
    "kafka": (frozenset({9092, 9093, 9094}),),
    "elasticsearch": (frozenset({9200, 9243, 9300}),),
    "opensearch": (frozenset({9200, 9243, 9300}),),
    "mqtt": (frozenset({1883, 8883}),),
    "kong": (frozenset({8000, 8001, 8443, 8444}),),
    "pulsar": (frozenset({6650, 6651, 8080}),),
    "activemq": (frozenset({61616, 61617, 8161}),),
    "consul": (frozenset({8500, 8501}),),
    "vault": (frozenset({8200, 8201}),),
}


def _same_system(product: str, a: int, b: int) -> bool:
    """Are two ports two listeners of ONE system of this product?"""
    if a == b:
        return True
    for group in _PORT_GROUPS.get((product or "").lower(), ()):
        if a in group and b in group:
            return True
    return False

# Which discovered products a given connection type is capable of monitoring. Prevents the
# absurd match where a Redis connection on host X "covers" the Kafka broker on host X.
_TYPE_COVERS = {
    "kafka": {"kafka"}, "confluent": {"kafka"}, "redpanda": {"kafka"},
    "rabbitmq": {"rabbitmq", "amqp"},
    "redis": {"redis"},
    "kong": {"kong"},
    "mqtt": {"mqtt"}, "nats": {"nats"}, "pulsar": {"pulsar"},
    "elasticsearch": {"elasticsearch", "opensearch"},
    "memcached": {"memcached"}, "etcd": {"etcd"}, "consul": {"consul"},
    "zookeeper": {"zookeeper"}, "vault": {"vault"}, "mcp": {"mcp"},
    "solr": {"solr"}, "activemq": {"activemq"}, "coordination": {"etcd", "consul", "zookeeper"},
    "graphql": {"graphql"}, "openapi": {"openapi"}, "grpc": {"grpc"},
}


def _norm_host(host: str) -> str:
    h = (host or "").strip().strip("[]").lower()
    return "localhost" if h in _LOOPBACK else h


def _endpoints_from_value(value) -> set[tuple[str, int | None]]:
    """Pull (host, port) pairs out of one config value, whatever shape it arrived in."""
    out: set[tuple[str, int | None]] = set()
    if value is None:
        return out
    if isinstance(value, (list, tuple)):
        for v in value:
            out |= _endpoints_from_value(v)
        return out
    if isinstance(value, dict):
        for v in value.values():
            out |= _endpoints_from_value(v)
        return out

    text = str(value).strip()
    if not text:
        return out
    # Strip a scheme, then a path/query, leaving authority. Handles kafka://, https://, amqps://
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    # Drop userinfo (user:pass@host) — a password in a URL must never become a "hostname".
    if "@" in text:
        text = text.rsplit("@", 1)[1]

    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        host, port = part, None
        if part.startswith("["):                       # [::1]:6379
            end = part.find("]")
            if end != -1:
                host = part[1:end]
                rest = part[end + 1:]
                port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
        elif part.count(":") == 1:
            h, _, p = part.partition(":")
            if p.isdigit():
                host, port = h, int(p)
        if host:
            out.add((_norm_host(host), port))
    return out


def connection_endpoints(config: dict) -> set[tuple[str, int | None]]:
    """Every (host, port) a connection's config points at. Empty means "we cannot tell"."""
    config = config or {}
    endpoints: set[tuple[str, int | None]] = set()
    for key in _ENDPOINT_KEYS:
        if key in config:
            endpoints |= _endpoints_from_value(config[key])

    # Several connectors split the endpoint across two keys (`host` + `port`, as redis does).
    # Read separately, that yields (host, None) — a port-agnostic match that would then cover
    # a SECOND instance of the same product on another port of the same host, hiding it.
    # Re-pair them here so `redis://host:6379` does not vouch for `redis://host:6380`.
    sep_port = config.get("port")
    if sep_port is not None:
        try:
            port = int(str(sep_port).strip())
        except (TypeError, ValueError):
            port = None
        if port is not None:
            paired = {(h, port) for h, p in endpoints if p is None}
            if paired:
                endpoints = paired | {(h, p) for h, p in endpoints if p is not None}
    return endpoints


def covers(conn_type: str, config: dict, product: str, host: str, port: int) -> bool | None:
    """Does this connection monitor this discovered service?

    True  — same host, same port, and the connector type can speak that product.
    False — the connection names endpoints, none of which is this one.
    None  — the connection names no endpoint we could parse, so this is UNKNOWN. The caller
            must treat None as "cannot conclude", never as False: claiming a monitored broker
            is unmonitored is the failure mode that gets a rule muted.
    """
    speakable = _TYPE_COVERS.get((conn_type or "").lower())
    if speakable is not None and product and product.lower() not in speakable:
        return False

    endpoints = connection_endpoints(config or {})
    if not endpoints:
        return None

    target_host = _norm_host(host)
    for e_host, e_port in endpoints:
        if e_host != target_host:
            continue
        # No port in the config means the connector uses its product default — the host match
        # is as much as configuration can tell us, and claiming "unmonitored" on that basis
        # would be the false positive this module exists to avoid.
        if e_port is None or _same_system(product, e_port, port):
            return True
    return False


def correlate_estate(conn, tenant_id: str, scan_id: str) -> dict:
    """Flag discovered services this tenant is not monitoring. Returns a small stats dict.

    Only services found by THIS scan are judged, so the finding's evidence is a probe result
    from minutes ago rather than an inference over stale inventory.
    """
    stats = {"checked": 0, "unmonitored": 0, "uncertain": 0}
    with conn.cursor() as cur:
        cur.execute(
            """select r.id, r.ext_id, r.labels, r.raw, r.connection_id
                 from resources r
                where r.tenant_id = %s and r.kind = 'discovered_service'
                  and r.connection_id = (select connection_id from scans where id = %s)
                  -- Vanished services are marked stale, never deleted. Without this filter a
                  -- host decommissioned six months ago keeps producing a fresh HIGH "nothing is
                  -- scanning this system" finding on every scan, stamped with today's scan_id —
                  -- the docstring's claim of "a probe result from minutes ago" would be false.
                  and coalesce(r.stale, false) = false""",
            (tenant_id, scan_id),
        )
        discovered = cur.fetchall()
        if not discovered:
            return stats

        cur.execute(
            "select id, type, name, config from connections where tenant_id = %s",
            (tenant_id,),
        )
        connections = cur.fetchall()

        # Suppressions are re-evaluated every scan by _persist_scan for every OTHER rule. This
        # layer writes findings directly, so without this it ignored them entirely — making the
        # suppression UI a silent no-op for the newest and noisiest rule in the product.
        supps = _active_suppressions(cur, tenant_id)

        for res_id, ext_id, labels, raw, discovery_conn_id in discovered:
            labels = labels or {}
            raw = raw or {}
            product = str(labels.get("product") or raw.get("product") or "")
            host = str(labels.get("host") or raw.get("host") or "")
            try:
                port = int(labels.get("port") or raw.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not host or not port:
                continue
            stats["checked"] += 1

            verdict = False
            unparseable: list[str] = []
            for c_id, c_type, c_name, c_config in connections:
                if str(c_id) == str(discovery_conn_id):
                    continue                      # the discovery connection itself
                got = covers(c_type, c_config or {}, product, host, port)
                if got is True:
                    verdict = True
                    break
                if got is None:
                    unparseable.append(f"{c_type}/{c_name}")
            if verdict:
                continue

            # UNCERTAIN: some connection might cover it, but its config named no endpoint we
            # could parse. Filed as a not-assessable coverage gap, not as a shadow broker.
            uncertain = bool(unparseable)
            if uncertain:
                stats["uncertain"] += 1
                observation = (
                    f"a {product or 'service'} was found at {host}:{port}, and no connection's "
                    f"configuration could be matched to it; "
                    f"{len(unparseable)} connection(s) name no endpoint this correlation "
                    f"understands ({', '.join(sorted(set(unparseable))[:4])})")
                detail = ("This service may already be monitored by one of those connections. "
                          "The match could not be made from configuration alone, so this is "
                          "reported as an unresolved coverage question rather than as an "
                          "unmonitored system.")
                assessment, reason = "not_assessable", (
                    "connection endpoints could not be parsed, so monitoring status is unknown")
                severity = "low"
            else:
                stats["unmonitored"] += 1
                evidence = "; ".join((raw.get("evidence") or [])[:2]) or "identified by probe"
                observation = (
                    f"a {product or 'service'} at {host}:{port} was identified by network "
                    f"discovery and matches no configured connection in this tenant "
                    f"({len(connections) - 1} other connection(s) checked): {evidence}")
                detail = ("Nothing is scanning this system, so none of its posture rules have "
                          "ever run against it: its authentication, transport, ACLs and version "
                          "are unassessed. Systems nobody remembers owning are the ones still "
                          "running defaults.")
                assessment, reason = "assessed", None
                severity = "high"

            suppressed = _is_suppressed(
                supps, RULE_UNMONITORED,
                SimpleNamespace(ext_id=ext_id, kind="discovered_service"))
            fp = fingerprint(tenant_id, str(discovery_conn_id), RULE_UNMONITORED, ext_id)
            cur.execute(
                """insert into findings
                     (tenant_id, scan_id, resource_id, rule_id, fingerprint, title, severity,
                      status, remediation, detail, assessment, assessment_reason)
                   values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                   on conflict (tenant_id, fingerprint) do update
                      set last_seen = now(), scan_id = excluded.scan_id,
                          severity = excluded.severity, detail = excluded.detail,
                          assessment = excluded.assessment,
                          assessment_reason = excluded.assessment_reason,
                      -- Status must be RE-EVALUATED here, not written on INSERT only. An
                      -- INSERT-only status runs once in a finding's life, so suppressing an
                      -- EXISTING finding did nothing (verified: it stayed 'open') and an
                      -- expires_at could never restore it. Same case expression as
                      -- _persist_scan, and for the same reason — it never overwrites a status
                      -- a HUMAN set (resolved/triaged/in_progress/accepted).
                      status = case
                        when excluded.status = 'suppressed'
                              and findings.status in ('open','suppressed') then 'suppressed'
                        when findings.status = 'suppressed'
                              and excluded.status <> 'suppressed' then 'open'
                        else findings.status
                      end
                   returning id""",
                (tenant_id, scan_id, res_id, RULE_UNMONITORED, fp, RULE_TITLE, severity,
                 "suppressed" if suppressed else "open",
                 (f"Add {host}:{port} as a {product or 'middleware'} connection so its rulepack "
                  "runs against it. If it should not be reachable at all, take it off the "
                  "network — an unmonitored broker is not a gap in a report, it is an "
                  "unowned system."),
                 detail, assessment, reason),
            )
            finding_id = cur.fetchone()[0]
            cur.execute(
                """insert into observations (tenant_id, finding_id, resource_id, claim, source_ref)
                   values (%s,%s,%s,%s,%s)""",
                (tenant_id, finding_id, res_id, observation,
                 json.dumps({"rule_id": RULE_UNMONITORED, "resource": ext_id,
                             "scan_id": str(scan_id), "host": host, "port": port,
                             "product": product, "correlation": "discovered_vs_connections"})),
            )

        # Merge into the scan's stats. _persist_scan wrote that row before correlation ran, so
        # without this the console would show a scan whose findings count excludes the shadow
        # services it just filed — the numbers on the page would disagree with the queue.
        cur.execute(
            """update scans
                  set stats = coalesce(stats, '{}'::jsonb) || jsonb_build_object(
                        'correlation', %s::jsonb,
                        'findings', coalesce((stats->>'findings')::int, 0) + %s)
                where id = %s""",
            (json.dumps(stats), stats["unmonitored"] + stats["uncertain"], scan_id),
        )
    return stats
