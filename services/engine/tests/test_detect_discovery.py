"""The discovery rulepack. Synthetic resources in, findings out — no network.

The through-line: a finding here is only as good as the wire fact behind it, so every test
checks that the observation quotes the probe's evidence rather than restating the rule's title.
The not-assessable cases matter most — a sweep whose scope was cut must never render as an
estate that is clean.
"""
import pytest

from vectasec.contracts import Resource, ScanContext
from vectasec.detect import discovery as D


def service(product="redis", host="10.0.0.5", port=6379, version=None, transport="plaintext",
            evidence=None, **signals) -> Resource:
    return Resource(
        kind="discovered_service", name=f"{host}:{port}", ext_id=f"{host}:{port}",
        labels={"product": product},
        raw={"host": host, "port": port, "product": product, "version": version,
             "version_inferred": signals.pop("version_inferred", False),
             "transport": transport,
             "evidence": evidence or [f"{product} answered a probe"],
             "signals": signals},
    )


def ctx(*resources) -> ScanContext:
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


# ═══ unauthenticated access ════════════════════════════════════════════════
def test_redis_answering_without_auth_is_critical():
    r = service(product="redis", auth_required=False,
                evidence=["Redis answered PING with +PONG on an unauthenticated connection"])
    hits = D.unauthenticated_access(r, ctx(r))
    assert len(hits) == 1
    assert hits[0].severity == "critical"
    assert "+PONG" in hits[0].observation, "the observation must quote the wire, not the rule"


def test_a_service_that_demanded_authentication_produces_no_finding():
    r = service(product="redis", auth_required=True)
    assert D.unauthenticated_access(r, ctx(r)) == []


def test_mqtt_accepting_anonymous_clients_fires():
    r = service(product="mqtt", port=1883, anonymous_accepted=True, auth_required=False)
    hits = D.unauthenticated_access(r, ctx(r))
    assert len(hits) == 1 and hits[0].severity == "high"


def test_a_product_whose_public_endpoint_is_by_design_does_not_fire():
    """Vault's sys/health and an OpenAPI document are MEANT to be readable. Firing on them
    would bury the Redis that actually is exposed."""
    r = service(product="vault", port=8200, auth_required=False)
    assert D.unauthenticated_access(r, ctx(r)) == []


def test_an_unsettled_auth_question_is_filed_as_a_gap_not_as_silence():
    """Unknown must not be reported as exposed — and must not be reported as CLEAN either.

    This test originally asserted `== []`, which is byte-identical to the answer a properly
    authenticated service gives. On the one rule in this pack whose job is finding open doors,
    that meant a probe which timed out mid-handshake rendered as "checked, nothing wrong".
    """
    r = service(product="redis")
    hits = D.unauthenticated_access(r, ctx(r))
    assert len(hits) == 1
    assert hits[0].assessable is False
    assert "could not determine whether it requires authentication" in hits[0].observation


@pytest.mark.parametrize("product", ["redis", "elasticsearch", "etcd", "consul", "rabbitmq"])
def test_the_serious_products_are_all_critical_when_open(product):
    r = service(product=product, auth_required=False)
    hits = D.unauthenticated_access(r, ctx(r))
    assert hits and hits[0].severity == "critical"


# ═══ admin API ═════════════════════════════════════════════════════════════
def test_an_open_kong_admin_api_fires_critical():
    r = service(product="kong", port=8001, admin_api_open=True,
                evidence=["the Kong Admin API answered an unauthenticated GET /"])
    hits = D.admin_api_exposed(r, ctx(r))
    assert len(hits) == 1
    assert "every API the gateway fronts" in hits[0].detail


def test_a_protected_admin_api_does_not_fire():
    r = service(product="kong", port=8001, admin_api_open=False, auth_required=True)
    assert D.admin_api_exposed(r, ctx(r)) == []


# ═══ transport and certificates ════════════════════════════════════════════
def test_plaintext_transport_fires():
    r = service(transport="plaintext")
    assert len(D.plaintext_transport(r, ctx(r))) == 1


def test_tls_transport_does_not_fire():
    r = service(transport="tls")
    assert D.plaintext_transport(r, ctx(r)) == []


def test_an_untrusted_certificate_is_reported_with_the_verifier_error():
    r = service(transport="tls", tls_cert_error="SSLCertVerificationError: self-signed")
    hits = D.untrusted_certificate(r, ctx(r))
    assert len(hits) == 1 and "self-signed" in hits[0].observation


def test_a_valid_certificate_does_not_fire():
    r = service(transport="tls", tls_cert_error=None)
    assert D.untrusted_certificate(r, ctx(r)) == []


# ═══ version disclosure: read vs inferred ══════════════════════════════════
def test_a_version_read_off_the_wire_is_reported():
    r = service(version="7.2.4")
    hits = D.preauth_version_disclosure(r, ctx(r))
    assert len(hits) == 1 and "7.2.4" in hits[0].observation


def test_an_INFERRED_version_is_not_reported_as_a_disclosure():
    """Kafka's floor comes from a capability matrix. Calling that 'the service disclosed its
    version' would be a claim the wire does not support."""
    r = service(product="kafka", version="3.7", version_inferred=True)
    assert D.preauth_version_disclosure(r, ctx(r)) == []


def test_no_version_means_no_disclosure_finding():
    assert D.preauth_version_disclosure(service(), ctx()) == []


# ═══ API descriptors ═══════════════════════════════════════════════════════
def test_an_openapi_document_without_declared_security_fires():
    r = service(product="openapi", port=8080, descriptor="openapi",
                declares_security=False, path_count=37)
    hits = D.openapi_no_security(r, ctx(r))
    assert len(hits) == 1 and "37 paths" in hits[0].observation


def test_an_openapi_document_that_declares_security_does_not_fire():
    r = service(product="openapi", descriptor="openapi", declares_security=True, path_count=4)
    assert D.openapi_no_security(r, ctx(r)) == []


def test_an_mcp_endpoint_found_by_sweep_is_surfaced_as_unmanaged():
    r = service(product="mcp", port=3000, descriptor="mcp",
                evidence=["an MCP-shaped endpoint answered GET /mcp with HTTP 200"])
    hits = D.mcp_surface(r, ctx(r))
    assert len(hits) == 1
    assert "not currently a monitored connection" in hits[0].detail


# ═══ coverage honesty ══════════════════════════════════════════════════════
def sweep(refusals=None, probed=10) -> Resource:
    return Resource(
        kind="discovery_sweep", name="discovery sweep", ext_id="discovery-sweep",
        labels={}, raw={"refusals": refusals or [], "targets_probed": probed,
                        "declared_targets": ["10.0.0.0/24"]},
    )


def test_refused_targets_are_a_not_assessable_coverage_gap_never_a_pass():
    r = sweep(refusals=["8.8.8.8: refused — public IP", "10.0.0.0/8: over the cap"])
    hits = D.scope_refused(r, ctx(r))
    assert len(hits) == 1
    assert hits[0].assessable is False, "an unprobed range is unknown, not clean"
    assert "never probed" in hits[0].observation


def test_a_fully_probed_scope_produces_no_gap():
    assert D.scope_refused(sweep(), ctx()) == []


def test_a_sweep_that_probed_nothing_says_so_loudly():
    r = sweep(probed=0)
    hits = D.nothing_probed(r, ctx(r))
    assert len(hits) == 1 and hits[0].assessable is False


def test_a_sweep_that_probed_something_does_not_fire_the_empty_rule():
    assert D.nothing_probed(sweep(probed=21), ctx()) == []


def test_many_refusals_are_summarised_without_dropping_the_count():
    r = sweep(refusals=[f"10.{i}.0.0/8: over the cap" for i in range(9)])
    hits = D.scope_refused(r, ctx(r))
    assert "9 declared target(s)" in hits[0].observation
    assert "+4 more" in hits[0].observation
