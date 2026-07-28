"""CycloneDX 1.6 SBOM + config-grounded VEX for a running middleware estate.

Most SBOMs describe what a build INTENDED to ship. This one describes what is actually
running, read from the systems themselves — which is a different and, for middleware, more
honest document. A build SBOM of Kafka Connect literally cannot enumerate the installed
connectors, because `plugin.path` is scanned at startup. Ours can.

Two CycloneDX features carry the weight here, and neither has an equivalent in SPDX:

  * `metadata.lifecycles[].phase` — `operations` when the component's version was read from a
    system we authenticated to, `discovery` when it came from an unauthenticated network probe.
    The spec defines these exact phases for exactly this distinction, so the consumer can see
    how the inventory was obtained without reading our documentation.

  * `analysis.justification: requires_configuration` — VEX's way of saying "this CVE does not
    affect us because a setting is not enabled". It exists ONLY in CycloneDX (OpenVEX and CSAF
    can only approximate it), and it is the one claim a config-reading posture scanner is
    uniquely able to make. Every such claim we emit carries the config key, the observed value,
    and the timestamp we read it — because the standing criticism of published VEX is that it
    is bulk "not affected" with no evidence, and machine-checked evidence is the answer to it.

A VEX claim of this kind is true only until somebody flips the setting, so `analysis.detail`
always names the condition that would invalidate it, and the document is regenerated per scan
rather than cached.
"""
from __future__ import annotations

import hashlib
import json
import uuid as _uuid

SPEC_VERSION = "1.6"
SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"

# Verified CPE bases. These are not guesses — each was confirmed to return CVEs from the NVD
# dictionary, and the wrong-but-plausible spellings are recorded because they silently return
# ZERO rather than erroring, which is the worst failure mode a security scanner can have.
#
#   redis      -> `redislabs:redis` exists and returns 0 CVEs for 7.2.4. Use `redis:redis`.
#   rabbitmq   -> neither `rabbitmq:rabbitmq` nor `broadcom:rabbitmq` resolve. Use `vmware:`.
#   nats       -> `nats_server` with an UNDERSCORE; the hyphenated form returns 0.
#   elastic    -> `elasticsearch:elasticsearch` is stale; `elastic:elasticsearch` is current.
#   valkey     -> has NO CPE at all, so it is deliberately absent: emitting a fabricated one
#                 would make an empty CVE result look like a clean bill of health.
CPE_VENDOR_PRODUCT: dict[str, tuple[str, str]] = {
    "kafka": ("apache", "kafka"),
    "redis": ("redis", "redis"),
    "rabbitmq": ("vmware", "rabbitmq"),
    "kong": ("konghq", "kong_gateway"),
    "vault": ("hashicorp", "vault"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "opensearch": ("elastic", "elasticsearch"),
    "pulsar": ("apache", "pulsar"),
    "nats": ("nats", "nats_server"),
    "etcd": ("etcd", "etcd"),
    "activemq": ("apache", "activemq"),
    "zookeeper": ("apache", "zookeeper"),
    "memcached": ("memcached", "memcached"),
    "solr": ("apache", "solr"),
    "consul": ("hashicorp", "consul"),
}

# PURLs in the Bitnami OSV ecosystem, which indexes APPLICATIONS rather than OS packages —
# the only free feed that maps a running broker version to advisories. Kong and Pulsar are
# absent from it upstream, so they carry no purl here and rely on the CPE path instead.
BITNAMI_PURL = {
    "kafka", "redis", "rabbitmq", "vault", "elasticsearch", "nats", "etcd",
    "activemq", "zookeeper", "memcached", "solr", "consul", "valkey",
}


def _cpe(product: str, version: str) -> str | None:
    vp = CPE_VENDOR_PRODUCT.get((product or "").lower())
    if not vp or not version:
        return None
    vendor, prod = vp
    return f"cpe:2.3:a:{vendor}:{prod}:{version}:*:*:*:*:*:*:*"


def _purl(product: str, version: str) -> str | None:
    p = (product or "").lower()
    if not version or p not in BITNAMI_PURL:
        return None
    return f"pkg:bitnami/{p}@{version}"


def _bom_ref(kind: str, ext_id: str) -> str:
    return f"{kind}/{ext_id}"


def _serial_number(tenant_id: str, scan_ids: list[str]) -> str:
    """Deterministic per (tenant, scan set): re-exporting the same scan yields the same
    serialNumber, so a consumer diffing two downloads sees no spurious change. The schema
    requires lowercase hex, which uuid5 gives us."""
    seed = f"{tenant_id}:{','.join(sorted(scan_ids))}"
    return f"urn:uuid:{_uuid.uuid5(_uuid.NAMESPACE_URL, seed)}"


def _version_of(resource: dict) -> tuple[str | None, bool]:
    """(version, inferred). Reads the several places connectors record a version, and reports
    whether it was READ or INFERRED — an inferred version must never be presented as fact."""
    raw = resource.get("raw") or {}
    labels = resource.get("labels") or {}
    inferred = bool(raw.get("version_inferred") or labels.get("version_inferred") == "true")
    for key in ("version", "redis_version", "rabbitmq_version", "broker_version",
                "kafka_version", "etcdserver"):
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip(), inferred
    v = labels.get("version")
    return (v.strip(), inferred) if isinstance(v, str) and v.strip() else (None, inferred)


def _product_of(resource: dict) -> str | None:
    raw, labels = resource.get("raw") or {}, resource.get("labels") or {}
    for candidate in (labels.get("product"), raw.get("product"), resource.get("connection_type")):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().lower()
    return None


def component_for(resource: dict) -> dict | None:
    """One CycloneDX component from a scanned resource, or None when there is no version to
    report. A component with no version tells a consumer nothing and matches no advisory."""
    product = _product_of(resource)
    version, inferred = _version_of(resource)
    if not product or not version:
        return None

    ext_id = str(resource.get("ext_id") or resource.get("name") or product)
    comp: dict = {
        "type": "application",
        "bom-ref": _bom_ref(str(resource.get("kind") or "component"), ext_id),
        "name": product,
        "version": version,
        "scope": "required",
    }
    purl, cpe = _purl(product, version), _cpe(product, version)
    # BOTH identifiers, deliberately: purl reaches OSV/GHSA, cpe reaches NVD, and the two
    # feeds disagree about which products they cover. RabbitMQ and NATS are invisible to NVD;
    # Pulsar is invisible to OSV. Emitting one identifier halves the estate's coverage.
    if purl:
        comp["purl"] = purl
    if cpe:
        comp["cpe"] = cpe

    props = []
    raw = resource.get("raw") or {}
    if raw.get("host"):
        props.append({"name": "vectasec:host", "value": str(raw["host"])})
    if raw.get("port"):
        props.append({"name": "vectasec:port", "value": str(raw["port"])})
    if raw.get("transport"):
        props.append({"name": "vectasec:transport", "value": str(raw["transport"])})
    if props:
        comp["properties"] = props

    if inferred:
        # Confidence, expressed in the schema's own vocabulary rather than buried in prose.
        # An inferred version drives CVE matching, so a consumer must be able to see that it
        # was derived from a capability matrix rather than read off the wire.
        comp["evidence"] = {"identity": [{
            "field": "version",
            "confidence": 0.5,
            "methods": [{"technique": "instrumentation", "confidence": 0.5,
                         "value": "inferred from the service's advertised protocol capability "
                                  "matrix; no version string was disclosed"}],
        }]}
    return comp


def vex_analysis(key: str, observed_value: str, observed_at: str, why: str,
                 invalidated_by: str) -> dict:
    """A `requires_configuration` VEX claim, with its evidence attached.

    This is the justification that only CycloneDX can express, and only a scanner that reads
    live configuration can honestly assert. The detail names the config key, the value we
    observed, when we observed it, and — critically — the change that would make the claim
    false, because a not-affected claim that outlives its condition is worse than none.
    """
    return {
        "state": "not_affected",
        "justification": "requires_configuration",
        "detail": (f"{why} Observed {key}={observed_value!r} at {observed_at}. "
                   f"This assessment is invalidated if {invalidated_by}."),
        "response": ["workaround_available"],
    }


def vulnerabilities_section(entries: list[dict]) -> list[dict]:
    """CycloneDX `vulnerabilities[]` from the advisory observations the scan loop stored.

    One entry per (advisory id, component bom-ref) pair comes in; one vulnerability per
    advisory id goes out, with every affected component listed under `affects`. Nothing here
    queries a feed — this section is the product's own filed findings, re-expressed in the
    schema's vocabulary, so the SBOM download and the findings queue can never disagree.

    Input keys: id, url, source_name, band, score (float|None), fixed (list), ref (bom-ref),
    description. `score` present means it was derived from a CVSS v3 vector; absent means the
    band came from a feed label or an explicit default, and no number is fabricated for it.
    """
    by_id: dict[str, dict] = {}
    for e in entries:
        vid = e.get("id")
        ref = e.get("ref")
        if not vid or not ref:
            continue
        v = by_id.get(vid)
        if v is None:
            rating: dict = {"severity": e.get("band") or "unknown"}
            if e.get("score") is not None:
                rating["score"] = e["score"]
                rating["method"] = "CVSSv31"
            v = by_id[vid] = {
                "id": vid,
                "source": {"name": e.get("source_name") or "OSV",
                           **({"url": e["url"]} if e.get("url") else {})},
                "ratings": [rating],
                "affects": [],
            }
            if e.get("description"):
                v["description"] = str(e["description"])[:512]
            if e.get("fixed"):
                v["recommendation"] = (
                    "Upgrade to a fixed release: " + ", ".join(map(str, e["fixed"][:5])))
        if not any(a["ref"] == ref for a in v["affects"]):
            v["affects"].append({"ref": ref})
    out = sorted(by_id.values(), key=lambda v: v["id"])
    for v in out:
        v["affects"].sort(key=lambda a: a["ref"])
    return out


def to_cyclonedx(resources: list, *, tenant_name: str, tenant_id: str,
                 scan_ids: list[str], timestamp: str,
                 authenticated: bool = True,
                 vulnerabilities: list | None = None) -> dict:
    """Build the estate SBOM.

    `authenticated` picks the lifecycle phase: a scan that logged in reports `operations`, an
    unauthenticated network sweep reports `discovery`. The spec defines both for precisely
    this distinction, and conflating them would overstate how the inventory was obtained.
    """
    components, refs = [], []
    for r in resources:
        comp = component_for(r)
        if comp is None:
            continue
        components.append(comp)
        refs.append(comp["bom-ref"])

    estate_ref = f"estate/{tenant_id}"
    phase = "operations" if authenticated else "discovery"

    bom: dict = {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(tenant_id, scan_ids),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "lifecycles": [{"phase": phase}],
            "tools": {"components": [{
                "type": "application", "name": "VectaSec", "group": "vectasec",
            }]},
            "component": {
                "type": "platform",
                "bom-ref": estate_ref,
                "name": f"{tenant_name} middleware estate",
                "version": timestamp[:10],
            },
        },
        "components": components,
        # An explicit empty dependsOn means "verified none"; OMITTING it means "unknown".
        # Leaves therefore get an explicit empty list, and the estate lists what it contains.
        "dependencies": ([{"ref": estate_ref, "dependsOn": sorted(refs)}]
                         + [{"ref": ref, "dependsOn": []} for ref in sorted(refs)]),
        # A scanner sees the services it was pointed at, never a whole software supply chain.
        # Declaring that stops a consumer reading "no vulnerabilities listed" as "safe".
        "compositions": [{
            "aggregate": "incomplete_third_party_only",
            "assemblies": sorted(refs) or [estate_ref],
        }],
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def to_cyclonedx_json(*args, **kwargs) -> str:
    return json.dumps(to_cyclonedx(*args, **kwargs), indent=2, sort_keys=False)


def content_hash(bom: dict) -> str:
    """Stable hash of the inventory, ignoring the fields that change every export (timestamp,
    serial). Lets a caller answer "did the estate actually change?" — which is the correct
    trigger for re-issuing VEX, rather than a fixed schedule."""
    material = json.dumps(
        {"components": bom.get("components", []), "dependencies": bom.get("dependencies", [])},
        sort_keys=True,
    )
    return hashlib.sha256(material.encode()).hexdigest()
