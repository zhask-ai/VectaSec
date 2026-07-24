"""Cross-fabric CVE/KEV enrichment — one detector over EVERY product+version resource.

Other connectors already read a product version off the target and write it into the resource
(``redis_version``, ``rabbitmq_version``, an ActiveMQ ``BrokerVersion``, a MOVEit banner, …).
This pack does not re-collect anything: it maps a resource's kind/labels to a `cve_data`
product key, parses the version the connector recorded, and compares it against the curated
affected ranges. A match becomes a CVE finding whose severity comes from the CVSS band and is
escalated one tier when the CVE is on CISA's Known-Exploited list.

Honesty discipline (contracts.Hit):
  * The observation states a FACT read from the target — "redis version 7.2.4 is within the
    affected range <7.2.11 for CVE-… per <source>" — never a conclusion.
  * A resource whose kind carries NO product+version signal → the detector is silent ([]).
  * A resource whose product IS tracked but whose version is unreadable/redacted → a
    not-assessable Hit (a coverage gap, never an assumed vulnerability from absence).
  * A product we track but hold no CVE for → silent (nothing to assess ≠ a gap).

Deliberate overlap: Redis RediShell and ActiveMQ OpenWire are also checked by their native
packs. Those findings carry a different rule id, so this cross-fabric view (KEV/EPSS/source/
ATT&CK) is additive, not a duplicate row. See cve_data.py MODULE NOTES.
"""
import re

from ..contracts import Hit
from ..cve_data import cves_for_product, products_with_cves
from ..registry import detector

# CVSS v3.1 base-score → house severity band.
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))
_RANK = ["info", "low", "medium", "high", "critical"]

# Kinds this pack runs on. Each is mapped to a cve_data product by `_product_signal`. Listing a
# kind here is cheap even when no CVE currently targets its product (kong, kafka via MSK): the
# detector just finds an empty catalogue and stays silent. Registering for a kind no connector
# emits is harmless — it simply never runs.
_CVE_KINDS = [
    "redis_server",        # redis        (connect/redis.py:        raw.redis_version)
    "node",                # rabbitmq     (connect/rabbitmq.py:     raw.overview.rabbitmq_version)
    "broker",              # kong/kafka   (connect/kong.py:         raw.version)
    "k8s_cluster",         # kubernetes   (connect/k8s.py:          raw.version)
    "aws_msk_cluster",     # kafka        (connect/aws.py:          raw.kafka_version)
    "activemq_broker",     # activemq     (connect/activemq.py:     raw.broker_version)
    "solr_server",         # solr         (connect/solr.py:         raw.version)
    "mft_server",          # moveit/…     (connect/mft.py:          raw.version + labels.product)
]


def _parse_version(v):
    """Dotted version → (major, minor, patch) ints, tolerant of a leading 'v', pre-release/build
    suffixes ('8.2.1-alpine', '3.13.7+build') and >3 segments ('15.0.1.51' → 15.0.1). Returns
    None when nothing numeric is present — the caller turns that into 'not assessable'."""
    m = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", str(v or ""))
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _in_interval(version: tuple, interval: dict):
    """[introduced, fixed) on version tuples. `introduced` defaults to (0,0,0); `fixed` is
    required by every dataset entry. Returns the fixed-in string when matched, else None."""
    lo = _parse_version(interval.get("introduced")) or (0, 0, 0)
    hi = _parse_version(interval.get("fixed"))
    if hi is None:
        return None
    return interval.get("fixed") if lo <= version < hi else None


def _affected_fix(cve: dict, version: tuple):
    """The fixed-in string for the first affected interval the version falls in, else None."""
    for interval in cve.get("affected") or []:
        fixed = _in_interval(version, interval)
        if fixed is not None:
            return fixed
    return None


def _severity(cve: dict) -> str:
    """CVSS band, escalated one tier (capped at critical) when the CVE is CISA Known-Exploited."""
    cvss = cve.get("cvss") or 0.0
    base = "info"
    for floor, name in _CVSS_BANDS:
        if cvss >= floor:
            base = name
            break
    if cve.get("kev"):
        return _RANK[min(_RANK.index(base) + 1, len(_RANK) - 1)]
    return base


def _product_signal(r):
    """Map a resource to (product_key, raw_version_string), or None when this resource carries no
    product+version signal at all (→ detector stays silent).

    A returned raw_version may be None/'' when the product IS tracked but the version was
    unreadable — the caller then files a not-assessable coverage gap, never a vulnerability.
    """
    kind = r.kind
    raw = r.raw or {}
    labels = r.labels or {}

    if kind == "redis_server":
        return "redis", raw.get("redis_version")

    if kind == "node":                              # rabbitmq — only the cluster carries the version
        if raw.get("role") != "cluster":
            return None                             # a per-node resource is not the version carrier
        ov = raw.get("overview") or {}
        return "rabbitmq", ov.get("rabbitmq_version") or raw.get("product_version")

    if kind == "broker":                            # kong AND kafka both use kind="broker"
        # Kong records a node version (labels.edition/version, raw.version); a Kafka broker does
        # not. Absent any version signal this is a Kafka broker → not a tracked product here.
        if raw.get("version") or "edition" in labels or "version" in labels:
            return "kong", raw.get("version")
        return None

    if kind == "k8s_cluster":
        return "kubernetes", raw.get("version")

    if kind == "aws_msk_cluster":
        return "kafka", raw.get("kafka_version")

    if kind == "activemq_broker":
        return "activemq", raw.get("broker_version")

    if kind == "solr_server":
        return "solr", raw.get("version")

    if kind == "mft_server":                        # product is the fingerprinted appliance family
        product = str(raw.get("product") or labels.get("product") or "").lower()
        if not product or product == "unknown":
            return None                             # unfingerprinted appliance — no product to map
        return product, raw.get("version")

    return None


def _cve_hit(product: str, raw_version: str, version: tuple, cve: dict) -> Hit:
    fixed = _affected_fix(cve, version)
    kev_clause = " (on CISA's Known-Exploited list)" if cve.get("kev") else ""
    epss = cve.get("epss")
    epss_clause = f", EPSS {epss}" if epss is not None else ""
    tags = ", ".join((cve.get("attack") or []) + (cve.get("owasp") or []))
    ver_str = ".".join(str(x) for x in version)
    return Hit(
        observation=(
            f"{product} reports version {raw_version!r} ({ver_str}), which is within the affected "
            f"range (< {fixed}) for {cve['cve_id']} — {cve['title']} — per {cve['source_url']}"
        ),
        remediation=(
            f"Upgrade {product} to >= {fixed} (the fixed release for this branch) to resolve "
            f"{cve['cve_id']} (CVSS {cve.get('cvss')}{kev_clause}{epss_clause}). Source: "
            f"{cve['source_url']}."
        ),
        detail=(
            f"cve={cve['cve_id']} product={product} version={raw_version!r} fixed_in={fixed} "
            f"cvss={cve.get('cvss')} kev={bool(cve.get('kev'))}"
            + (f" tags={tags}" if tags else "")
        ),
        severity=_severity(cve),
        source_ref={
            "cve": cve["cve_id"], "product": product, "version_read": raw_version,
            "fixed_in": fixed, "cvss": cve.get("cvss"), "kev": bool(cve.get("kev")),
            "epss": epss, "source": cve["source_url"],
            "attack": cve.get("attack") or [], "owasp": cve.get("owasp") or [],
        },
    )


@detector(kinds=_CVE_KINDS, rule_id="CVE.KNOWN_VULNERABILITY", severity="high",
          title="Resource runs a version with a known CVE")
def known_cve(r, ctx) -> list:
    signal = _product_signal(r)
    if signal is None:
        return []                                   # not a tracked product+version resource
    product, raw_version = signal

    catalogue = cves_for_product(product)
    if not catalogue:
        return []                                   # tracked product, but no curated CVE for it

    version = _parse_version(raw_version)
    if version is None:
        # The product IS tracked and we DO hold CVEs for it, but the version could not be read.
        # Never assert a vuln from absence — file the coverage gap instead.
        return [Hit(
            observation=(
                f"{product} {r.kind} '{r.name}' exposes no parseable version (value read: "
                f"{raw_version!r}); its exposure to {len(catalogue)} curated {product} CVE(s) "
                f"could not be determined"
            ),
            remediation=(
                f"Give the scanner read access to the {product} version (or record it) so its "
                f"exposure to the {len(catalogue)} tracked CVE(s) can be assessed."
            ),
            detail=f"product={product} version={raw_version!r} candidate_cves={len(catalogue)}",
            assessable=False,
            assessment_reason=f"version string {raw_version!r} is not parseable to compare against ranges",
            source_ref={"product": product, "version_read": raw_version,
                        "candidate_cves": [c["cve_id"] for c in catalogue]},
        )]

    # One Hit per matched CVE. scan.py files them under one findings row (worst severity wins) with
    # every Hit's observation preserved in the ledger, so multiple CVEs on one resource are all cited.
    return [_cve_hit(product, raw_version, version, c)
            for c in catalogue if _affected_fix(c, version) is not None]


# Re-exported so the picker/tests can introspect coverage without importing the data module.
TRACKED_PRODUCTS_WITH_CVES = products_with_cves()
