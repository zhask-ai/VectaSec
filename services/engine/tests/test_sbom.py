"""CycloneDX SBOM + config-grounded VEX. Offline — no schema fetch, no OSV call.

The assertions that matter most here are about IDENTIFIERS, because a wrong-but-plausible CPE
does not error: it returns zero CVEs and renders as a clean bill of health. `redislabs:redis`
is a real vendor string that exists in the NVD dictionary and matches nothing for Redis 7.2.4;
`rabbitmq:rabbitmq` resolves to nothing at all. Each of those spellings is pinned here so a
well-meaning "tidy-up" of the vendor table fails a test instead of silently blinding the scanner.

The other theme is honesty markers: an inferred version must carry evidence of its inference, a
leaf must declare an explicit empty dependency list (omission means "unknown", not "none"), and
the composition must declare itself incomplete so nobody reads a short vulnerability list as
proof of safety.
"""
import json

import pytest

from vectasec.sbom import (
    CPE_VENDOR_PRODUCT, component_for, content_hash, to_cyclonedx, vex_analysis,
)


def resource(kind="redis_server", product="redis", version="7.2.4", ext_id="redis-1",
             inferred=False, **raw):
    return {
        "kind": kind, "name": ext_id, "ext_id": ext_id,
        "labels": {"product": product},
        "raw": {"product": product, "version": version,
                "version_inferred": inferred, **raw},
    }


def bom_of(*resources, **kw):
    opts = {"tenant_name": "Demo", "tenant_id": "t-1", "scan_ids": ["s1"],
            "timestamp": "2026-07-27T12:00:00Z"}
    opts.update(kw)
    return to_cyclonedx(list(resources), **opts)


# ═══ identifiers: the silent-failure surface ═══════════════════════════════
# Each pair was re-checked against the live NVD API on 2026-08-03 with a wildcard-version
# `virtualMatchString`; the CVE count it returned is in the comment. Two entries here were
# WRONG and matched nothing, which does not error — it returns an empty list that renders as
# "no known CVEs", so the products with the thinnest coverage looked like the cleanest ones.
@pytest.mark.parametrize("product,expected_vendor,expected_product", [
    ("redis", "redis", "redis"),                    # 46 — NOT redislabs (0 for 7.2.4)
    ("rabbitmq", "broadcom", "rabbitmq_server"),    # 25 — Pivotal→VMware→Broadcom; see aliases
    ("nats", "linuxfoundation", "nats-server"),     # 36 — was nats:nats_server, which is 0
    ("opensearch", "amazon", "opensearch"),         # 11 — was elastic:elasticsearch (wrong fork)
    ("elasticsearch", "elastic", "elasticsearch"),  # 52
    ("kafka", "apache", "kafka"),                   # 16
])
def test_cpe_vendor_strings_are_the_ones_that_actually_match(product, expected_vendor,
                                                             expected_product):
    assert CPE_VENDOR_PRODUCT[product] == (expected_vendor, expected_product)


def test_nats_cpe_is_the_linux_foundation_one_not_the_nats_vendor_string():
    """The previous entry blamed the hyphen and fixed the wrong half of the pair: NVD files
    NATS CVEs under vendor `linuxfoundation` with a HYPHENATED product. `nats:nats_server`
    returns zero results — and zero results is what a clean broker looks like."""
    from vectasec.sbom import cpes_for
    assert CPE_VENDOR_PRODUCT["nats"] == ("linuxfoundation", "nats-server")
    assert cpes_for("nats", "2.10.7") == ["cpe:2.3:a:linuxfoundation:nats-server:2.10.7:*:*:*:*:*:*:*"]


def test_opensearch_does_not_borrow_elasticsearchs_cpe():
    """They forked at 7.10. Sharing a CPE both inherits Elastic's post-fork CVEs (false
    positives) and misses OpenSearch's own (false negatives)."""
    assert CPE_VENDOR_PRODUCT["opensearch"] != CPE_VENDOR_PRODUCT["elasticsearch"]


def test_a_renamed_vendor_keeps_its_historic_cpes_for_feed_queries():
    """NVD never back-fills a rename, so RabbitMQ's advisories are split across all three
    owners. Querying only the current name silently loses most of its history."""
    from vectasec.sbom import cpes_for
    cpes = cpes_for("rabbitmq", "3.13.7")
    assert cpes[0] == "cpe:2.3:a:broadcom:rabbitmq_server:3.13.7:*:*:*:*:*:*:*"
    assert "cpe:2.3:a:vmware:rabbitmq:3.13.7:*:*:*:*:*:*:*" in cpes
    assert "cpe:2.3:a:pivotal_software:rabbitmq:3.13.7:*:*:*:*:*:*:*" in cpes
    # The SBOM still publishes exactly one, because the schema has one cpe field.
    assert component_for(resource(product="rabbitmq", version="3.13.7"))["cpe"] == cpes[0]


def test_cpes_for_makes_no_claim_without_a_version():
    from vectasec.sbom import cpes_for
    assert cpes_for("rabbitmq", "") == []
    assert cpes_for("valkey", "8.0") == []      # no CPE exists; fabricating one fakes safety


def test_valkey_has_no_cpe_because_none_exists():
    """Fabricating one would make an empty CVE result look like a clean bill of health."""
    assert "valkey" not in CPE_VENDOR_PRODUCT


def test_a_component_carries_BOTH_purl_and_cpe():
    """They reach different feeds and the feeds disagree about coverage — RabbitMQ and NATS
    are invisible to NVD, Pulsar is invisible to OSV. One identifier halves the estate."""
    comp = component_for(resource())
    assert comp["purl"] == "pkg:bitnami/redis@7.2.4"
    assert comp["cpe"] == "cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*"


def test_rabbitmq_carries_both_a_purl_and_its_current_vendor_cpe():
    """The purl is the feed that answers for a specific running version (OSV returns three
    advisories for 3.13.7 where an exact-version NVD query returns none), and the CPE reaches
    the NVD history — under the CURRENT vendor, with the historic ones queried alongside it."""
    comp = component_for(resource(product="rabbitmq", version="3.13.7"))
    assert comp["purl"] == "pkg:bitnami/rabbitmq@3.13.7"
    assert comp["cpe"].startswith("cpe:2.3:a:broadcom:rabbitmq_server:")


def test_a_product_outside_the_bitnami_ecosystem_still_gets_a_cpe():
    """Kong is absent from OSV's Bitnami index, so the CPE path is all it has."""
    comp = component_for(resource(product="kong", version="3.6.0"))
    assert "purl" not in comp
    assert comp["cpe"].startswith("cpe:2.3:a:konghq:kong_gateway:")


def test_a_resource_with_no_version_produces_no_component():
    """A versionless component matches no advisory and tells a consumer nothing."""
    assert component_for(resource(version=None)) is None


def test_an_unknown_product_with_a_version_still_appears_without_identifiers():
    comp = component_for(resource(product="brand-new-broker", version="1.2.3"))
    assert comp["name"] == "brand-new-broker" and comp["version"] == "1.2.3"
    assert "purl" not in comp and "cpe" not in comp


# ═══ honesty markers ═══════════════════════════════════════════════════════
def test_an_inferred_version_carries_evidence_of_its_inference():
    """Kafka's version comes from a capability matrix, and it drives CVE matching. A consumer
    must be able to see that it was derived rather than read."""
    comp = component_for(resource(product="kafka", version="3.7", inferred=True))
    assert comp["evidence"]["identity"][0]["field"] == "version"
    assert comp["evidence"]["identity"][0]["confidence"] < 1.0


def test_a_version_read_off_the_wire_carries_no_inference_evidence():
    assert "evidence" not in component_for(resource())


def test_leaves_declare_an_explicit_empty_dependency_list():
    """In CycloneDX, omitting dependsOn means UNKNOWN; an empty array means VERIFIED NONE."""
    bom = bom_of(resource())
    leaf = [d for d in bom["dependencies"] if d["ref"].startswith("redis_server/")][0]
    assert leaf["dependsOn"] == []


def test_the_composition_declares_itself_incomplete():
    """A scanner sees the services it was pointed at, never a whole supply chain. Without
    this, a short vulnerability list reads as proof of safety."""
    bom = bom_of(resource())
    assert bom["compositions"][0]["aggregate"] == "incomplete_third_party_only"


def test_an_authenticated_scan_is_operations_and_a_probe_is_discovery():
    """The spec defines both phases for exactly this distinction; conflating them would
    overstate how the inventory was obtained."""
    assert bom_of(resource(), authenticated=True)["metadata"]["lifecycles"][0]["phase"] == "operations"
    assert bom_of(resource(), authenticated=False)["metadata"]["lifecycles"][0]["phase"] == "discovery"


# ═══ document shape ════════════════════════════════════════════════════════
def test_the_document_has_the_fields_the_schema_requires():
    bom = bom_of(resource())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    for comp in bom["components"]:
        assert comp["type"] and comp["name"]


def test_the_serial_number_matches_the_schemas_lowercase_hex_pattern():
    import re
    bom = bom_of(resource())
    assert re.match(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    bom["serialNumber"])


def test_the_serial_number_is_stable_so_re_exporting_shows_no_spurious_diff():
    a = bom_of(resource(), timestamp="2026-07-27T12:00:00Z")
    b = bom_of(resource(), timestamp="2026-07-28T09:30:00Z")
    assert a["serialNumber"] == b["serialNumber"]


def test_the_content_hash_ignores_the_timestamp_but_tracks_the_inventory():
    """This is what makes 're-issue VEX when the estate changes' possible, instead of
    re-issuing on a schedule and letting stale claims outlive their conditions."""
    a = bom_of(resource(), timestamp="2026-07-27T12:00:00Z")
    b = bom_of(resource(), timestamp="2026-07-28T09:30:00Z")
    c = bom_of(resource(version="7.2.11"), timestamp="2026-07-27T12:00:00Z")
    assert content_hash(a) == content_hash(b)
    assert content_hash(a) != content_hash(c)


def test_the_whole_document_serialises_to_json():
    json.loads(json.dumps(bom_of(resource(), resource(product="kafka", version="3.9.0",
                                                      ext_id="kafka-1"))))


# ═══ VEX: the justification only CycloneDX can express ═════════════════════
def test_a_config_grounded_claim_uses_requires_configuration():
    a = vex_analysis("connector.client.config.override.policy", "None",
                     "2026-07-27T11:58:00Z",
                     why="The override policy rejects the keys this CVE requires.",
                     invalidated_by="the policy changes to All or Principal")
    assert a["state"] == "not_affected"
    assert a["justification"] == "requires_configuration"


def test_the_claim_carries_the_key_the_value_and_when_it_was_read():
    """The standing criticism of published VEX is bulk 'not affected' with no evidence.
    Machine-checked evidence is the answer, so it must be in the document."""
    a = vex_analysis("allow.everyone.if.no.acl.found", "false", "2026-07-27T11:58:00Z",
                     why="ACLs are enforced.", invalidated_by="the setting becomes true")
    assert "allow.everyone.if.no.acl.found" in a["detail"]
    assert "'false'" in a["detail"]
    assert "2026-07-27T11:58:00Z" in a["detail"]


def test_the_claim_names_what_would_invalidate_it():
    """A not-affected claim that outlives its condition is worse than no claim at all."""
    a = vex_analysis("protected-mode", "yes", "2026-07-27T11:58:00Z",
                     why="Protected mode blocks the path.",
                     invalidated_by="protected-mode is set to no")
    assert "invalidated if protected-mode is set to no" in a["detail"]


# ═══ vulnerabilities: the product's own findings, in schema vocabulary ═════
def _entry(**kw):
    e = {"id": "BIT-redis-2024-31449", "ref": "redis_server/redis-1",
         "source_name": "OSV", "url": "https://osv.dev/vulnerability/BIT-redis-2024-31449",
         "band": "high", "score": 7.0, "fixed": ["7.2.6"], "description": "Lua stack overflow"}
    e.update(kw)
    return e


def test_vulnerabilities_dedupe_by_advisory_and_collect_affects():
    from vectasec.sbom import vulnerabilities_section
    out = vulnerabilities_section([
        _entry(ref="redis_server/redis-1"),
        _entry(ref="redis_server/redis-2"),
        _entry(ref="redis_server/redis-1"),          # ledger repeat — one affect, not two
        _entry(id="CVE-2023-46118", ref="node/cluster", band="medium", score=4.9,
               source_name="VectaSec curated dataset",
               url="https://nvd.nist.gov/vuln/detail/CVE-2023-46118",
               fixed=["3.12.7"], description="HTTP API DoS"),
    ])
    assert [v["id"] for v in out] == ["BIT-redis-2024-31449", "CVE-2023-46118"]
    assert out[0]["affects"] == [{"ref": "redis_server/redis-1"},
                                 {"ref": "redis_server/redis-2"}]
    assert out[0]["ratings"] == [{"severity": "high", "score": 7.0, "method": "CVSSv31"}]
    assert out[0]["recommendation"] == "Upgrade to a fixed release: 7.2.6"
    assert out[1]["source"]["name"] == "VectaSec curated dataset"


def test_a_band_without_a_vector_score_carries_no_fabricated_number():
    """A severity that came from a feed label ('Critical') has no CVSS score to report.
    Emitting method=CVSSv31 with an invented number would be a fabricated measurement."""
    from vectasec.sbom import vulnerabilities_section
    out = vulnerabilities_section([_entry(score=None)])
    assert out[0]["ratings"] == [{"severity": "high"}]


def test_entries_missing_id_or_ref_are_dropped_not_guessed():
    from vectasec.sbom import vulnerabilities_section
    assert vulnerabilities_section([_entry(id=None), _entry(ref=None)]) == []


def test_vulnerabilities_land_in_the_document():
    from vectasec.sbom import vulnerabilities_section
    bom = bom_of(resource(), vulnerabilities=vulnerabilities_section([_entry()]))
    assert bom["vulnerabilities"][0]["id"] == "BIT-redis-2024-31449"
    # And an empty section is OMITTED, not an empty list pretending to be an assessment.
    assert "vulnerabilities" not in bom_of(resource())


# ═══ licensing: a version-dependent legal fact ═════════════════════════════
# Several of these products relicensed mid-life, so a per-product constant would be WRONG for
# exactly the estates that never upgraded. Each boundary below is pinned against the primary
# source recorded in sbom.LICENSE_RULES.
@pytest.mark.parametrize("product,version,expect_names,expect_osi", [
    ("redis", "7.2.4", ["BSD-3-Clause"], True),
    ("redis", "7.4.0", ["SSPL-1.0", "RSALv2"], False),          # source-available, not OSI
    ("redis", "8.0.1", ["AGPL-3.0-only", "SSPL-1.0", "RSALv2"], True),
    ("vault", "1.14.9", ["MPL-2.0"], True),
    ("vault", "1.15.0", ["BUSL-1.1"], False),
    ("consul", "1.16.9", ["MPL-2.0"], True),
    ("consul", "1.17.0", ["BUSL-1.1"], False),
    ("elasticsearch", "7.10.2", ["Apache-2.0"], True),
    ("elasticsearch", "8.15.0", ["SSPL-1.0", "Elastic-2.0"], False),
    ("elasticsearch", "8.16.0", ["AGPL-3.0-only", "SSPL-1.0", "Elastic-2.0"], True),
    ("rabbitmq", "3.8.5", ["MPL-1.1"], True),
    ("rabbitmq", "3.13.7", ["MPL-2.0"], True),
    ("kafka", "3.9.0", ["Apache-2.0"], True),
])
def test_license_is_resolved_per_version_not_per_product(product, version,
                                                         expect_names, expect_osi):
    from vectasec.sbom import license_for
    lic = license_for(product, version)
    assert lic["names"] == expect_names
    assert lic["osi"] is expect_osi
    assert lic["source_url"].startswith("https://")


def test_unknown_product_or_version_makes_no_license_claim():
    """A wrong licence assertion travels into somebody's compliance report. Silence is the
    only honest answer when the table does not cover it."""
    from vectasec.sbom import license_for
    assert license_for("mysteryware", "1.0") is None
    assert license_for("redis", "not-a-version") is None
    assert license_for("", "") is None


def test_component_carries_licences_and_the_osi_flag():
    comp = component_for(resource(product="redis", version="7.4.0"))
    assert comp["licenses"] == [{"license": {"id": "SSPL-1.0"}},
                                {"license": {"name": "RSALv2"}}]   # RSALv2 has no SPDX id
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["vectasec:license-osi-approved"] == "false"
    assert props["vectasec:license-terms"].startswith("offered under ANY ONE of")
    assert props["vectasec:license-source"].startswith("https://")


def test_a_product_with_no_licence_data_omits_the_field_entirely():
    comp = component_for(resource(kind="broker", product="ibmmq", version="9.3.0"))
    assert "licenses" not in comp


# ═══ VEX: claims grounded in our own finding lifecycle ═════════════════════
def _vex(**over):
    e = {"id": "CVE-2025-49844", "ref": "redis_server/redis-1", "band": "critical",
         "score": 10.0, "status": "open", "assessment": "assessed",
         "source_name": "OSV", "url": "https://osv.dev/vulnerability/x"}
    e.update(over)
    return e


def vex_of(*entries, **kw):
    from vectasec.sbom import to_vex
    opts = {"tenant_name": "Demo", "tenant_id": "t-1", "scan_ids": ["s1"],
            "timestamp": "2026-08-03T12:00:00Z"}
    opts.update(kw)
    return to_vex(list(entries), **opts)


def test_open_finding_is_in_triage_never_exploitable():
    """"We found it" is not "it is exploitable here". in_triage is the only honest state for a
    finding nobody has ruled on."""
    from vectasec.sbom import vex_entry
    v = vex_entry(_vex(status="open"))
    assert v["analysis"]["state"] == "in_triage"
    assert "not yet ruled on" in v["analysis"]["detail"]


def test_suppressed_finding_publishes_the_humans_verbatim_reason_and_its_lapse_date():
    from vectasec.sbom import vex_entry
    v = vex_entry(_vex(status="suppressed", reason="Lua scripting disabled on this cluster",
                       suppressed_by="alice@corp.io", expires_at="2026-12-01"))
    assert v["analysis"]["state"] == "not_affected"
    detail = v["analysis"]["detail"]
    assert "Lua scripting disabled on this cluster" in detail   # verbatim, not paraphrased
    assert "alice@corp.io" in detail
    assert "2026-12-01" in detail and "lapse" in detail


def test_a_permanent_suppression_says_it_has_no_review_date():
    """The standing criticism of published VEX is not-affected claims that outlive their
    reasoning. A suppression with no expiry must say so rather than read as durable truth."""
    from vectasec.sbom import vex_entry
    v = vex_entry(_vex(status="suppressed", reason="accepted", expires_at=None))
    assert "NO review date" in v["analysis"]["detail"]


def test_config_grounded_claim_uses_the_requires_configuration_justification():
    from vectasec.sbom import vex_entry
    v = vex_entry(_vex(status="suppressed", reason="Feature is off.",
                       config_key="enable-lua", config_value="no",
                       observed_at="2026-08-03T12:00:00Z"))
    assert v["analysis"]["justification"] == "requires_configuration"
    assert "enable-lua" in v["analysis"]["detail"]
    assert "invalidated if" in v["analysis"]["detail"]


def test_not_assessable_findings_are_withheld_and_the_omission_is_declared():
    """A check that could not run is not a not-affected claim. It must not be published — and
    the document must admit it is incomplete rather than read as exhaustive."""
    from vectasec.sbom import vex_entry
    assert vex_entry(_vex(assessment="not_assessable")) is None
    doc = vex_of(_vex(), _vex(id="CVE-2000-0001", assessment="not_assessable"))
    assert [v["id"] for v in doc["vulnerabilities"]] == ["CVE-2025-49844"]
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["vectasec:vex-withheld-not-assessable"] == "1"
    assert "not a not-affected claim" in props["vectasec:vex-scope"]


def test_one_cve_on_two_components_merges_and_keeps_the_weaker_claim():
    """Suppressed on one host and open on another does NOT make the CVE globally not-affected."""
    doc = vex_of(_vex(ref="redis_server/a", status="suppressed", reason="off here"),
                 _vex(ref="redis_server/b", status="open"))
    v = doc["vulnerabilities"][0]
    assert [a["ref"] for a in v["affects"]] == ["redis_server/a", "redis_server/b"]
    assert v["analysis"]["state"] == "in_triage"


def test_vex_document_is_a_valid_standalone_cyclonedx_bom():
    doc = vex_of(_vex())
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["type"] == "platform"
    json.dumps(doc)     # serialisable — it is served as a download


def test_not_affected_without_a_reason_is_downgraded_not_published():
    """The state comes from findings.status, the reason from the CURRENTLY ACTIVE suppressions,
    and those are written at different times — so a suppression deleted or expired after the
    last scan leaves a suppressed finding with nothing to cite. Publishing "not affected, no
    reason given" is the bulk-unevidenced VEX this module exists to avoid. Observed live: 8
    CVEs published as not_affected against an empty suppressions table."""
    from vectasec.sbom import vex_entry
    v = vex_entry(_vex(status="suppressed", reason=None, expires_at=None))
    assert v["analysis"]["state"] == "in_triage"
    # …and a reason still produces the real claim.
    assert vex_entry(_vex(status="suppressed",
                          reason="Lua disabled"))["analysis"]["state"] == "not_affected"


def test_merge_keeps_the_least_reassuring_state_in_either_row_order():
    """`resolved` is at least as reassuring as `not_affected` and was not covered, so
    ['resolved','open'] published a CVE still open elsewhere as remediated while
    ['open','resolved'] did not — a coin flip on database row order."""
    for order in ((("resolved", "a"), ("open", "b")), (("open", "b"), ("resolved", "a"))):
        doc = vex_of(*[_vex(ref=f"redis_server/{r}", status=s) for s, r in order])
        assert doc["vulnerabilities"][0]["analysis"]["state"] == "in_triage", order
