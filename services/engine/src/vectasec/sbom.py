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
    "rabbitmq": ("broadcom", "rabbitmq_server"),
    "kong": ("konghq", "kong_gateway"),
    "vault": ("hashicorp", "vault"),
    "elasticsearch": ("elastic", "elasticsearch"),
    "opensearch": ("amazon", "opensearch"),
    "pulsar": ("apache", "pulsar"),
    "nats": ("linuxfoundation", "nats-server"),
    "etcd": ("etcd", "etcd"),
    "activemq": ("apache", "activemq"),
    "zookeeper": ("apache", "zookeeper"),
    "memcached": ("memcached", "memcached"),
    "solr": ("apache", "solr"),
    "consul": ("hashicorp", "consul"),
}

# ONE CPE per product is structurally not enough, because NVD keeps filing under the vendor
# string that was current when each CVE was published and never back-fills a rename. RabbitMQ
# has passed through Pivotal → VMware → Broadcom, and its advisories are split across all three:
# querying only the current name silently loses the older two thirds of its history.
#
# Every pair below was checked against the live NVD API on 2026-08-03 with a wildcard-version
# `virtualMatchString` and the CVE count it returned is recorded, because a pair that matches
# nothing does not error — it returns an empty list that reads exactly like "no known CVEs".
# That check is what caught two wrong entries above:
#   nats       was `nats:nats_server`      → 0 results. Real: `linuxfoundation:nats-server` (36).
#              The old comment blamed the hyphen, but the VENDOR half was the wrong one.
#   opensearch was `elastic:elasticsearch` → wrong product entirely. It inherited Elastic's
#              post-fork CVEs while missing its own; `amazon:opensearch` (11) is OpenSearch.
CPE_ALIASES: dict[str, tuple[tuple[str, str], ...]] = {
    # (25 under broadcom, above) + the two historic owners.
    "rabbitmq": (("vmware", "rabbitmq"),                 # 6
                 ("pivotal_software", "rabbitmq"),       # 11
                 ("pivotal_software", "rabbitmq_management")),
    # OpenSearch's security plugin is filed as its own product.
    "opensearch": (("amazon", "opensearch_security"),),
}


def cpes_for(product: str, version: str) -> list[str]:
    """Every CPE a vulnerability feed might have filed this component under — primary first.

    The SBOM publishes only the primary (the schema has one `cpe` field per component), but a
    feed query must try all of them or a vendor rename becomes a coverage hole.
    """
    key = (product or "").lower()
    primary = _cpe(product, version)
    if not primary or not version:
        return []
    out = [primary]
    for vendor, prod in CPE_ALIASES.get(key, ()):
        out.append(f"cpe:2.3:a:{vendor}:{prod}:{version}:*:*:*:*:*:*:*")
    return out

# PURLs in the Bitnami OSV ecosystem, which indexes APPLICATIONS rather than OS packages —
# the only free feed that maps a running broker version to advisories. Kong and Pulsar are
# absent from it upstream, so they carry no purl here and rely on the CPE path instead.
BITNAMI_PURL = {
    "kafka", "redis", "rabbitmq", "vault", "elasticsearch", "nats", "etcd",
    "activemq", "zookeeper", "memcached", "solr", "consul", "valkey",
}


# ── Licensing ─────────────────────────────────────────────────────────────────
# Middleware licensing is NOT a per-product constant, and treating it as one is how estates end
# up out of compliance without a single thing changing on their side. Several of these products
# relicensed mid-life, so the version you are RUNNING decides which terms bind you: Redis 7.2 is
# BSD, Redis 7.4 is source-available, Redis 8.0 is AGPL. A build-time SBOM commonly records
# whatever the project's LICENSE file says today and attaches it to whatever version it found,
# which silently reverses the answer for the exact estates that never upgraded.
#
# Every entry below was verified against a primary source (recorded per entry) on 2026-08-03.
# `osi` is deliberately separate from the identifier list: "is this OSI-approved open source"
# is the question legal actually asks, and SSPL/RSAL/BUSL all answer no while still being
# perfectly legal to run. Absent product or unparseable version => NO license claim at all,
# because a wrong license assertion is worse than an honest silence.
#
# Each rule: (minimum version this applies from, [(spdx_id_or_None, display_name)], osi, url).
# Rules are ordered high-to-low and the first whose floor the version meets wins.
_APACHE = [("Apache-2.0", "Apache-2.0")]

LICENSE_RULES: dict[str, list[tuple[tuple[int, int, int], list, bool, str]]] = {
    # Redis: BSD → dual source-available (7.4) → AGPL added (8.0).
    "redis": [
        ((8, 0, 0), [("AGPL-3.0-only", "AGPL-3.0-only"), ("SSPL-1.0", "SSPL-1.0"),
                     (None, "RSALv2")], True,
         "https://redis.io/legal/licenses/"),
        ((7, 4, 0), [("SSPL-1.0", "SSPL-1.0"), (None, "RSALv2")], False,
         "https://redis.io/blog/redis-adopts-dual-source-available-licensing/"),
        ((0, 0, 0), [("BSD-3-Clause", "BSD-3-Clause")], True,
         "https://redis.io/legal/licenses/"),
    ],
    # Elasticsearch: Apache → SSPL/Elastic (7.11) → AGPL added (8.16, Sept 2024).
    "elasticsearch": [
        ((8, 16, 0), [("AGPL-3.0-only", "AGPL-3.0-only"), ("SSPL-1.0", "SSPL-1.0"),
                      ("Elastic-2.0", "Elastic-2.0")], True,
         "https://www.elastic.co/pricing/faq/licensing"),
        ((7, 11, 0), [("SSPL-1.0", "SSPL-1.0"), ("Elastic-2.0", "Elastic-2.0")], False,
         "https://www.elastic.co/pricing/faq/licensing"),
        ((0, 0, 0), _APACHE, True, "https://www.elastic.co/pricing/faq/licensing"),
    ],
    # OpenSearch exists BECAUSE of that 7.11 change and has stayed Apache-2.0 throughout.
    "opensearch": [((0, 0, 0), _APACHE, True, "https://opensearch.org/license/")],
    "vault": [
        ((1, 15, 0), [("BUSL-1.1", "BUSL-1.1")], False,
         "https://discuss.hashicorp.com/t/hashicorp-projects-changing-license-to-business-source-license-v1-1/57106"),
        ((0, 0, 0), [("MPL-2.0", "MPL-2.0")], True,
         "https://discuss.hashicorp.com/t/hashicorp-projects-changing-license-to-business-source-license-v1-1/57106"),
    ],
    "consul": [
        ((1, 17, 0), [("BUSL-1.1", "BUSL-1.1")], False,
         "https://github.com/hashicorp/consul/blob/main/LICENSE"),
        ((0, 0, 0), [("MPL-2.0", "MPL-2.0")], True,
         "https://github.com/hashicorp/consul/blob/main/LICENSE"),
    ],
    # RabbitMQ relicensed MPL 1.1 → MPL 2.0 in 3.8.6; both are OSI-approved.
    "rabbitmq": [
        ((3, 8, 6), [("MPL-2.0", "MPL-2.0")], True,
         "https://github.com/rabbitmq/rabbitmq-server/blob/main/LICENSE"),
        ((0, 0, 0), [("MPL-1.1", "MPL-1.1")], True,
         "https://groups.google.com/g/rabbitmq-users/c/Ex8a2vHTw7I"),
    ],
    "kafka": [((0, 0, 0), _APACHE, True, "https://github.com/apache/kafka/blob/trunk/LICENSE")],
    "pulsar": [((0, 0, 0), _APACHE, True, "https://github.com/apache/pulsar/blob/master/LICENSE")],
    "activemq": [((0, 0, 0), _APACHE, True,
                  "https://github.com/apache/activemq/blob/main/LICENSE")],
    "zookeeper": [((0, 0, 0), _APACHE, True,
                   "https://github.com/apache/zookeeper/blob/master/LICENSE")],
    "solr": [((0, 0, 0), _APACHE, True, "https://github.com/apache/solr/blob/main/LICENSE.txt")],
    "nats": [((0, 0, 0), _APACHE, True,
              "https://github.com/nats-io/nats-server/blob/main/LICENSE")],
    "etcd": [((0, 0, 0), _APACHE, True, "https://github.com/etcd-io/etcd/blob/main/LICENSE")],
    # Kong Gateway OSS. The Enterprise build is separately licensed and is NOT claimed here.
    "kong": [((0, 0, 0), _APACHE, True, "https://github.com/Kong/kong/blob/master/LICENSE")],
    "memcached": [((0, 0, 0), [("BSD-3-Clause", "BSD-3-Clause")], True,
                   "https://github.com/memcached/memcached/blob/master/LICENSE")],
    "valkey": [((0, 0, 0), [("BSD-3-Clause", "BSD-3-Clause")], True,
                "https://github.com/valkey-io/valkey/blob/unstable/COPYING")],
}


def parse_version(v) -> tuple[int, int, int] | None:
    """Dotted version → (major, minor, patch), tolerant of 'v' prefixes and -alpine/+build tails.

    Deliberate twin of detect/cve.py's `_parse_version`: sbom.py must not import from the
    `detect` package, because importing any detector executes detect/__init__'s pkgutil sweep
    over every rulepack — and rulepacks import sbom. Six lines duplicated beats an import cycle.
    """
    import re
    m = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", str(v or ""))
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def license_for(product: str, version: str) -> dict | None:
    """The licensing that binds THIS version, or None when we cannot say.

    Returns {ids: [...], names: [...], osi: bool, source_url: str, choice: bool}. `choice` marks
    a disjunction (Redis 8 is "any one of three"), which matters because CycloneDX's licenses[]
    array does not itself distinguish AND from OR — so the caller states it in words rather than
    letting a consumer guess that we meant all three at once.
    """
    rules = LICENSE_RULES.get((product or "").lower())
    parsed = parse_version(version)
    if not rules or parsed is None:
        return None
    for floor, entries, osi, url in sorted(rules, key=lambda r: r[0], reverse=True):
        if parsed >= floor:
            return {
                "ids": [spdx for spdx, _ in entries if spdx],
                "names": [name for _, name in entries],
                "osi": osi,
                "source_url": url,
                "choice": len(entries) > 1,
            }
    return None


def _licenses_field(product: str, version: str) -> tuple[list | None, list]:
    """(CycloneDX licenses[], extra component properties). Non-SPDX terms (RSALv2 has no SPDX
    identifier) are emitted as `license.name` rather than invented as an `id`, because a made-up
    SPDX id is exactly the kind of thing a downstream compliance tool would trust."""
    lic = license_for(product, version)
    if not lic:
        return None, []
    spdx = {i for i in lic["ids"]}
    licenses = [
        {"license": ({"id": name} if name in spdx else {"name": name})}
        for name in lic["names"]
    ]
    props = [
        {"name": "vectasec:license-osi-approved", "value": str(lic["osi"]).lower()},
        {"name": "vectasec:license-source", "value": lic["source_url"]},
    ]
    if lic["choice"]:
        props.append({"name": "vectasec:license-terms",
                      "value": "offered under ANY ONE of: " + ", ".join(lic["names"])})
    return licenses, props


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

    # An INFERRED version is a floor derived from a protocol capability matrix at confidence
    # 0.5, not a version read off the wire — and the licence boundaries sit between adjacent
    # minors (Redis 7.2 is BSD, 7.4 is not open source at all). detect/lifecycle.py refuses to
    # assert on an inferred version for exactly this reason; a claim that "travels straight
    # into somebody's compliance report" cannot hold itself to a lower bar.
    licenses, license_props = ((None, []) if inferred
                               else _licenses_field(product, version))
    if licenses:
        comp["licenses"] = licenses

    props = list(license_props)
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


# ── VEX ───────────────────────────────────────────────────────────────────────
# CycloneDX analysis states, and what each one honestly means HERE:
#   in_triage      — we filed it and nobody has ruled on it yet. The default, and the only
#                    honest state for an open finding: "we found it" is not "it is exploitable".
#   not_affected   — a human suppressed it, with a written reason. The reason is reproduced
#                    verbatim rather than compressed into a justification enum, because the
#                    enum would be OUR guess at THEIR reasoning.
#   resolved       — the finding is closed: the estate no longer reports the vulnerable version.
#
# What never appears: anything derived from a not_assessable finding. A check that did not run
# is not a "not affected" claim, and publishing it as one is precisely the bulk-unevidenced-VEX
# behaviour that made consumers stop trusting VEX documents in the first place.
_VEX_STATE = {"open": "in_triage", "suppressed": "not_affected", "resolved": "resolved",
              "closed": "resolved", "accepted": "not_affected"}

# How reassuring each state is to a consumer. When one CVE affects several components the
# merged record must carry the LEAST reassuring of them, or suppressing it on one host would
# publish it as handled everywhere.
_VEX_STRENGTH = {"in_triage": 0, "not_affected": 1, "resolved": 2}


def vex_entry(e: dict) -> dict | None:
    """One CycloneDX vulnerability with an `analysis`, or None if it must not be published.

    Input keys: id, ref, band, score, url, source_name, status, assessment, reason,
    suppressed_by, expires_at, observed_at, config_key, config_value.
    """
    vid, ref = e.get("id"), e.get("ref")
    if not vid or not ref:
        return None
    if (e.get("assessment") or "assessed") == "not_assessable":
        return None                      # unknown is not a claim — see the note above
    state = _VEX_STATE.get(str(e.get("status") or "open").lower())
    if state is None:
        return None

    # A not_affected claim with NO reason attached is the bulk-unevidenced VEX this module was
    # written to avoid, and it is reachable: the state comes from `findings.status` while the
    # reason comes from the CURRENTLY ACTIVE suppressions, and those are written at different
    # times. A suppression that was deleted or expired after the finding was last scanned
    # leaves a suppressed finding with nothing to cite. Publishing "not affected — no reason
    # given" is worse than publishing nothing; downgrade to the honest state instead.
    if state == "not_affected" and not (e.get("reason") or e.get("config_key")):
        state = "in_triage"

    if state == "not_affected" and e.get("config_key"):
        # The one justification a config-reading scanner can assert on its own evidence.
        analysis = vex_analysis(
            key=str(e["config_key"]), observed_value=str(e.get("config_value")),
            observed_at=str(e.get("observed_at") or ""),
            why=str(e.get("reason") or "Not exploitable in the observed configuration."),
            invalidated_by=f"{e['config_key']} changes")
    else:
        analysis = {"state": state}
        detail_bits = []
        if e.get("reason"):
            # Verbatim: this is a human's stated reasoning and paraphrasing it would launder
            # an opinion into a machine claim.
            detail_bits.append(f"Assessed by a VectaSec operator: {e['reason']!r}.")
        if e.get("suppressed_by"):
            detail_bits.append(f"Recorded by {e['suppressed_by']}.")
        if state == "not_affected":
            detail_bits.append(
                f"This assessment is scheduled to lapse on {e['expires_at']}, after which the "
                f"finding reopens and this claim should not be relied on."
                if e.get("expires_at") else
                "This assessment carries NO review date — it holds only until the estate or the "
                "reasoning behind it changes, and nothing here re-checks that.")
        elif state == "in_triage":
            detail_bits.append("Filed by a VectaSec scan and not yet ruled on. Its presence is "
                               "evidence the component is affected, not that it is exploitable "
                               "in this deployment.")
        if detail_bits:
            analysis["detail"] = " ".join(detail_bits)

    rating: dict = {"severity": e.get("band") or "unknown"}
    if e.get("score") is not None:
        rating["score"] = e["score"]
        rating["method"] = "CVSSv31"
    out = {
        "id": vid,
        "source": {"name": e.get("source_name") or "OSV",
                   **({"url": e["url"]} if e.get("url") else {})},
        "ratings": [rating],
        "analysis": analysis,
        "affects": [{"ref": ref}],
    }
    return out


def to_vex(entries: list[dict], *, tenant_name: str, tenant_id: str, scan_ids: list[str],
           timestamp: str) -> dict:
    """A standalone CycloneDX 1.6 VEX document for the estate.

    Separate from the SBOM on purpose: an SBOM answers "what is running" and is regenerated when
    the inventory changes, while VEX answers "and what do we say about the vulnerabilities in
    it" and changes every time a human rules on something. Consumers ingest them on different
    cadences, and the spec supports exactly this split.

    Entries whose analysis must not be published (not_assessable) are dropped by `vex_entry`,
    and the count of those drops is reported in `properties` so a reader can see that the
    document is deliberately incomplete rather than assume it is exhaustive.
    """
    published, withheld = [], 0
    for e in entries:
        v = vex_entry(e)
        if v is None:
            withheld += 1
        else:
            published.append(v)

    merged: dict[str, dict] = {}
    for v in published:
        cur = merged.get(v["id"])
        if cur is None:
            merged[v["id"]] = v
            continue
        for a in v["affects"]:
            if not any(x["ref"] == a["ref"] for x in cur["affects"]):
                cur["affects"].append(a)
        # A CVE that is open on one component and suppressed on another is NOT globally
        # "not affected": keep the weaker (less reassuring) claim for the merged record.
        # Ranked rather than special-cased on not_affected, because `resolved` is at least as
        # reassuring and was not covered — ['resolved','open'] published a CVE still open on
        # another component as remediated, while ['open','resolved'] did not. A silent coin
        # flip on database row order is the worst shape for a claim like this.
        if _VEX_STRENGTH.get(v["analysis"]["state"], 0) < _VEX_STRENGTH.get(
                cur["analysis"]["state"], 0):
            cur["analysis"] = v["analysis"]

    out = sorted(merged.values(), key=lambda v: v["id"])
    for v in out:
        v["affects"].sort(key=lambda a: a["ref"])

    return {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial_number(tenant_id, scan_ids + ["vex"]),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "lifecycles": [{"phase": "operations"}],
            "tools": {"components": [{
                "type": "application", "name": "VectaSec", "group": "vectasec",
            }]},
            "component": {
                "type": "platform",
                "bom-ref": f"estate/{tenant_id}",
                "name": f"{tenant_name} middleware estate",
                "version": timestamp[:10],
            },
            "properties": [
                {"name": "vectasec:vex-withheld-not-assessable", "value": str(withheld)},
                {"name": "vectasec:vex-scope",
                 "value": ("Claims cover only vulnerabilities VectaSec itself filed against this "
                           "estate. Absence of a CVE here is not a not-affected claim about it.")},
            ],
        },
        "vulnerabilities": out,
    }


def to_vex_json(*args, **kwargs) -> str:
    return json.dumps(to_vex(*args, **kwargs), indent=2, sort_keys=False)


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
