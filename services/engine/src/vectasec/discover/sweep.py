"""The sweep: run the right probes against approved targets, concurrently and politely.

Port→probe routing keeps the scan cheap and quiet. A host with 21 default ports open would
otherwise get 21 × every-probe connections; instead each port gets the one or two probes that
could plausibly answer it, and an unrecognised port gets nothing but the HTTP descriptor sweep
on the ports where HTTP actually lives. Fewer connections is not only faster, it is the
difference between "a health check went past" and "we were port-scanned".

Concurrency is bounded and per-target failures are swallowed: an unreachable host is the
normal case in a sweep, not an error, and one probe raising must never void the run.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

from . import http_probes as H
from . import probes as P
from .targets import Target

MAX_WORKERS = 24


@dataclass
class Discovery:
    """One identified service, with the target that produced it."""
    target: Target
    result: P.ProbeResult


def _mqtt_tls(host, port, timeout):
    return P.probe_mqtt(host, port, timeout, tls=True)


# Which probes may answer for a port. Order matters: the most specific first, so a RabbitMQ
# management port is identified as RabbitMQ rather than as a generic HTTP surface.
PORT_PROBES: dict[int, tuple] = {
    1883: (P.probe_mqtt,),
    2181: (P.probe_zookeeper,),
    2379: (H.probe_etcd,),
    4222: (P.probe_nats,),
    5671: (P.probe_amqp,),
    5672: (P.probe_amqp,),
    6379: (P.probe_redis,),
    8001: (H.probe_kong_admin, H.probe_api_descriptor),
    8080: (H.probe_kong_admin, H.probe_api_descriptor),
    8161: (H.probe_api_descriptor,),
    8200: (H.probe_vault,),
    8500: (H.probe_consul,),
    8883: (_mqtt_tls,),
    9000: (H.probe_api_descriptor,),
    9092: (P.probe_kafka,),
    9093: (P.probe_kafka,),
    9200: (H.probe_elasticsearch,),
    9243: (H.probe_elasticsearch,),
    11211: (P.probe_memcached,),
    15672: (H.probe_rabbitmq_mgmt, H.probe_api_descriptor),
    15671: (H.probe_rabbitmq_mgmt,),
}

# Ports with no specific probe still get the API-descriptor sweep when they are plausibly HTTP:
# this is where shadow OpenAPI/MCP surfaces turn up.
HTTP_FALLBACK_PORTS = frozenset({80, 443, 3000, 5000, 8000, 8081, 8088, 8443, 9001, 9090})

# Tried in order against a port the OPERATOR named that has no standard mapping. Ordered by
# politeness: NATS first (it speaks without being spoken to), then the probes that send one
# small read-only request, HTTP last because it is the most expensive.
#
# This exists because shadow middleware is, almost by definition, not on a standard port —
# a Redis moved to 6380 to "hide" it is the single most common way an unmonitored broker
# survives. Restricting this to explicitly-named ports keeps a default sweep cheap: we work
# this hard only where somebody asked us to look.
GENERIC_PROBES = (
    P.probe_nats, P.probe_redis, P.probe_amqp, P.probe_kafka,
    P.probe_memcached, P.probe_zookeeper, H.probe_api_descriptor,
)


def probes_for(port: int, explicit: bool = False) -> tuple:
    if port in PORT_PROBES:
        return PORT_PROBES[port]
    if port in HTTP_FALLBACK_PORTS:
        return (H.probe_api_descriptor,)
    return GENERIC_PROBES if explicit else ()


def _probe_one(target: Target, timeout: float) -> Discovery | None:
    """First probe that identifies something wins. Exceptions are contained: a probe that
    blows up on a hostile reply must lose its own target, never the sweep."""
    for probe in probes_for(target.port, target.explicit):
        try:
            result = probe(target.host, target.port, timeout)
        except Exception:                       # noqa: BLE001 - a probe must never break a sweep
            continue
        if result is not None:
            return Discovery(target=target, result=result)
    return None


def sweep(targets: list[Target], timeout: float = P.DEFAULT_TIMEOUT,
          max_workers: int = MAX_WORKERS) -> list[Discovery]:
    """Probe every approved target concurrently. Returns only identified services, sorted for
    a stable ext_id order (so a re-scan of an unchanged estate produces an unchanged diff)."""
    # `explicit` must be threaded through the filter too, not just the probe call: an
    # operator-named port has no standard mapping, so filtering on probes_for(port) alone
    # dropped exactly the non-standard ports shadow middleware hides on.
    probeable = [t for t in targets if probes_for(t.port, t.explicit)]
    if not probeable:
        return []

    found: list[Discovery] = []
    workers = max(1, min(max_workers, len(probeable)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_one, t, timeout): t for t in probeable}
        for fut in as_completed(futures):
            try:
                got = fut.result()
            except Exception:                   # noqa: BLE001 - defensive; _probe_one contains its own
                got = None
            if got is not None:
                found.append(got)
    found.sort(key=lambda d: (d.target.host, d.target.port))
    return found
