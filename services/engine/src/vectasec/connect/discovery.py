"""Discovery connector — inventory the middleware estate by looking, not by being told.

Every other connector in this package answers "what is the posture of the thing you named?".
This one answers the question that comes before it: "what is actually out there?" — because
the systems nobody remembered to name are exactly the ones running a default password.

It emits `discovered_service` resources: one per identified (host, port), carrying the product,
the version where the wire actually revealed one, and the pre-auth signals a rulepack can judge
(anonymous access accepted, an open admin API, plaintext transport). It also emits ONE
`discovery_sweep` resource describing the scan itself — how many targets were probed, and every
target that was REFUSED with the reason. That second resource exists because a discovery scan
that silently dropped half its scope is worse than no scan: it produces confident emptiness.

Safety lives in `discover/targets.py` (scope) and `discover/probes.py` (what a probe may send).
Read those before adding anything here. In short: declared targets only, private ranges unless
public scanning is explicitly declared, a hard host cap, no credentials, no writes.

DO NOT POINT THIS AT MANAGED CLOUD MESSAGING. AWS's published penetration-testing policy
pre-authorises customer scanning of an enumerated service list, and MSK, Amazon MQ, SQS, SNS,
EventBridge and Kinesis are **not on it** — network-probing them is outside the blanket
permission even when the endpoint is yours. The same services are fully covered by the
`aws` / `azure` / `gcp` connectors through their control-plane APIs, which is richer anyway
(a `ListClusters` call reports encryption-in-transit and public-access settings that no
handshake can reveal). Use the cloud connectors for managed middleware; use this one for
the estate you run yourself.

The Censys model is the standard this connector holds itself to: never authenticate, be
identifiable, be attributable. The Kafka probe sends `client_id=vectasec-discovery`, which
brokers surface in their own `clientSoftwareName` metrics — so a customer can see exactly who
knocked, from their side, without asking us.
"""
from __future__ import annotations

from ..contracts import Collected, Resource
from ..discover import resolve_scope, sweep
from ..registry import ConnectorField, connector


@connector("discovery", fields=[
    ConnectorField("targets", "Targets", required=True,
                   placeholder="10.0.0.0/24, kafka.internal:9092, 10.1.2.3",
                   help="Hosts, host:port, or CIDRs to probe — comma or newline separated. "
                        "Only what you name here is ever contacted."),
    ConnectorField("ports", "Ports", required=False, placeholder="9092, 6379, 5672",
                   help="Override the default middleware port set for targets that do not "
                        "name their own port."),
    ConnectorField("allow_public", "Allow public IP ranges", required=False,
                   placeholder="false",
                   help="Off by default. Set true ONLY if you are authorized to scan the "
                        "public addresses you named — scanning hosts you do not own is "
                        "not something to do by accident."),
    ConnectorField("timeout", "Per-probe timeout (seconds)", required=False, placeholder="3"),
])
def collect(config: dict) -> Collected:
    targets_raw = config.get("targets") or []
    if isinstance(targets_raw, str):
        targets_raw = [t for t in targets_raw.replace("\n", ",").split(",") if t.strip()]

    ports_raw = config.get("ports") or []
    if isinstance(ports_raw, str):
        ports_raw = [p for p in ports_raw.replace("\n", ",").split(",") if p.strip()]
    ports: list[int] = []
    bad_ports: list[str] = []
    for p in ports_raw:
        try:
            ports.append(int(str(p).strip()))
        except (TypeError, ValueError):
            bad_ports.append(str(p))

    allow_public = str(config.get("allow_public", "")).strip().lower() in ("1", "true", "yes")
    try:
        timeout = float(config.get("timeout") or 3.0)
    except (TypeError, ValueError):
        timeout = 3.0

    scope = resolve_scope(targets_raw, ports=ports or None, allow_public=allow_public)
    for bad in bad_ports:
        scope.refusals.append(f"port {bad!r}: not a number — ignored")

    found = sweep(scope.targets, timeout=timeout)

    resources: list[Resource] = []
    for d in found:
        r = d.result
        host, port = d.target.host, d.target.port
        resources.append(Resource(
            kind="discovered_service",
            name=f"{host}:{port}",
            ext_id=f"{host}:{port}",
            labels={
                "product": r.product,
                "host": host,
                "port": str(port),
                "transport": r.transport,
                # Strings throughout: labels are jsonb the console filters on with ->>, and a
                # mix of bool and string in one key makes those filters silently miss rows.
                **({"version": r.version} if r.version else {}),
                **({"version_inferred": "true"} if r.version_inferred else {}),
                **({"auth_required": str(bool(r.signals.get("auth_required"))).lower()}
                   if "auth_required" in r.signals else {}),
                **({"anonymous_accepted": "true"} if r.signals.get("anonymous_accepted") else {}),
                **({"admin_api_open": "true"} if r.signals.get("admin_api_open") else {}),
                **({"descriptor": str(r.signals["descriptor"])} if r.signals.get("descriptor") else {}),
            },
            raw={
                "host": host,
                "port": port,
                "product": r.product,
                "version": r.version,
                "version_inferred": r.version_inferred,
                "transport": r.transport,
                # The evidence strings ARE the observations a detector quotes. Keeping them on
                # the resource means a finding never has to re-derive what the probe saw.
                "evidence": r.evidence,
                "signals": r.signals,
                "probe": r.raw,
                "target_source": d.target.source,
            },
        ))

    # The scan's own coverage, as a first-class resource. `refusals` is the honest part: a
    # rulepack turns a non-empty list into a not-assessable finding, so a narrowed scope shows
    # up as a coverage gap in the console instead of as a clean bill of health.
    resources.append(Resource(
        kind="discovery_sweep",
        name="discovery sweep",
        ext_id="discovery-sweep",
        labels={
            "targets_probed": str(len(scope.targets)),
            "hosts": str(len(scope.hosts)),
            "services_found": str(len(found)),
            "refusals": str(len(scope.refusals)),
            "allow_public": str(allow_public).lower(),
        },
        raw={
            "declared_targets": [str(t) for t in targets_raw],
            "targets_probed": len(scope.targets),
            "hosts": sorted(scope.hosts),
            "services_found": len(found),
            "refusals": scope.refusals,
            "allow_public": allow_public,
            "timeout": timeout,
            "products": sorted({d.result.product for d in found}),
        },
    ))

    return Collected(resources=resources, edges=[])
