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
@pytest.mark.parametrize("product,expected_vendor", [
    ("redis", "redis"),          # NOT redislabs — that spelling matches 0 CVEs for 7.2.4
    ("rabbitmq", "vmware"),      # NOT rabbitmq, NOT broadcom — neither resolves
    ("nats", "nats"),
    ("elasticsearch", "elastic"),  # NOT elasticsearch:elasticsearch, which is stale
    ("kafka", "apache"),
])
def test_cpe_vendor_strings_are_the_ones_that_actually_match(product, expected_vendor):
    assert CPE_VENDOR_PRODUCT[product][0] == expected_vendor


def test_nats_product_keeps_its_underscore():
    """`nats-server` with a hyphen returns zero from NVD. The underscore is load-bearing."""
    assert CPE_VENDOR_PRODUCT["nats"][1] == "nats_server"


def test_valkey_has_no_cpe_because_none_exists():
    """Fabricating one would make an empty CVE result look like a clean bill of health."""
    assert "valkey" not in CPE_VENDOR_PRODUCT


def test_a_component_carries_BOTH_purl_and_cpe():
    """They reach different feeds and the feeds disagree about coverage — RabbitMQ and NATS
    are invisible to NVD, Pulsar is invisible to OSV. One identifier halves the estate."""
    comp = component_for(resource())
    assert comp["purl"] == "pkg:bitnami/redis@7.2.4"
    assert comp["cpe"] == "cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*"


def test_rabbitmq_gets_a_purl_because_that_is_its_only_working_feed():
    comp = component_for(resource(product="rabbitmq", version="3.13.7"))
    assert comp["purl"] == "pkg:bitnami/rabbitmq@3.13.7"
    assert comp["cpe"].startswith("cpe:2.3:a:vmware:rabbitmq:")


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
