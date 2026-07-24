"""Offline unit tests for the cross-fabric TLS / cert-lifecycle sweep (detect/tls.py).

No network: Resources are built with the SAME labels/raw keys the connectors set (confirmed
against connect/mcp.py `raw.tls`, connect/mft.py `raw.tls`, connect/azure.py
`raw.minimum_tls_version`, connect/aws.py `raw.encryption_in_transit_client_broker`,
connect/gcp.py `raw.targets`, connect/k8s.py ingress `labels.tls` and gateway `raw.listeners`).

Every rule gets fires / does-not-fire / (where applicable) not-assessable coverage. The
not-assessable cases matter most: a connector that recorded no usable cert/TLS data must produce
a coverage gap, never an invented pass or fail.
"""
from vectasec.contracts import Resource, ScanContext
from vectasec.detect import tls


def ctx_of(*resources):
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def one(hits):
    assert len(hits) == 1, f"expected exactly one Hit, got {len(hits)}: {hits}"
    return hits[0]


# ── Builders keyed on the real connector shapes ────────────────────────────────
def mcp(scheme="https", **tls_over):
    t = {"negotiated": "TLSv1.3", "cert_status": "valid", "cert_error": None, "floor": "UNTESTED"}
    t.update(tls_over)
    return Resource(kind="mcp_server", name="mcp", ext_id="mcp-1",
                    labels={"scheme": scheme}, raw={"scheme": scheme, "tls": t})


def mft(enabled=True, scheme="https", **tls_over):
    t = {"enabled": enabled, "cert_status": "valid", "cert_error": None,
         "negotiated": "TLSv1.3", "not_after": None, "expired": False}
    t.update(tls_over)
    return Resource(kind="mft_server", name="moveit:host", ext_id="mft-1",
                    labels={"product": "moveit", "scheme": scheme}, raw={"tls": t})


def azure_sb(min_tls):
    return Resource(kind="azure_servicebus_namespace", name="ns", ext_id="ns-1",
                    raw={"minimum_tls_version": min_tls})


def apigee(targets, readable=True):
    return Resource(kind="gcp_apigee_proxy", name="proxy", ext_id="proxy-1",
                    raw={"targets_readable": readable, "targets": targets})


def msk(mode):
    return Resource(kind="aws_msk_cluster", name="msk", ext_id="msk-1",
                    raw={"encryption_in_transit_client_broker": mode})


def ingress(tls_flag):
    return Resource(kind="k8s_ingress", name="ns/ing", ext_id="ing-1",
                    labels={"tls": tls_flag}, raw={"tls": []})


def gateway(listeners):
    return Resource(kind="k8s_gateway", name="ns/gw", ext_id="gw-1", raw={"listeners": listeners})


# ── TLS.CERT.EXPIRED ───────────────────────────────────────────────────────────
def test_cert_expired_fires_on_mcp_cert_error():
    hit = one(tls.cert_expired(mcp(cert_status="invalid", cert_error="certificate has expired"),
                               ctx_of()))
    assert hit.severity is None and "expired" in hit.observation


def test_cert_expired_fires_on_mft_expired_flag():
    assert one(tls.cert_expired(mft(cert_status="invalid", expired=True), ctx_of()))


def test_cert_expired_silent_on_valid_cert():
    assert tls.cert_expired(mcp(), ctx_of()) == []
    assert tls.cert_expired(mft(), ctx_of()) == []


def test_cert_expired_silent_when_endpoint_is_not_tls():
    assert tls.cert_expired(mcp(scheme="http", cert_status=None), ctx_of()) == []
    assert tls.cert_expired(mft(enabled=False, scheme="http", cert_status=None), ctx_of()) == []


# ── TLS.CERT.UNTRUSTED ─────────────────────────────────────────────────────────
def test_cert_untrusted_fires_on_self_signed():
    hit = one(tls.cert_untrusted(mcp(cert_status="invalid",
                                     cert_error="self-signed certificate"), ctx_of()))
    assert "self-signed" in hit.observation


def test_cert_untrusted_fires_on_hostname_mismatch():
    hit = one(tls.cert_untrusted(mcp(cert_status="invalid",
                                     cert_error="Hostname mismatch, certificate is not valid"),
                                 ctx_of()))
    assert "name does not match" in hit.observation


def test_cert_untrusted_defers_expired_to_the_expiry_rule():
    # An expired cert is EXPIRED's finding, not UNTRUSTED's — no double-filing.
    assert tls.cert_untrusted(mcp(cert_status="invalid",
                                  cert_error="certificate has expired"), ctx_of()) == []


def test_cert_untrusted_silent_on_valid():
    assert tls.cert_untrusted(mcp(), ctx_of()) == []


def test_cert_untrusted_is_not_assessable_on_failed_handshake():
    hit = one(tls.cert_untrusted(mcp(cert_status="unknown",
                                     cert_error="ConnectionRefusedError"), ctx_of()))
    assert hit.assessable is False and "handshake" in hit.assessment_reason


# ── TLS.PROTOCOL.WEAK ──────────────────────────────────────────────────────────
def test_protocol_weak_fires_on_negotiated_below_1_2():
    assert one(tls.protocol_weak(mcp(negotiated="TLSv1.1"), ctx_of()))


def test_protocol_weak_fires_on_downgrade_floor():
    assert one(tls.protocol_weak(mcp(negotiated="TLSv1.3", floor="TLSv1"), ctx_of()))


def test_protocol_weak_silent_on_modern_tls():
    assert tls.protocol_weak(mcp(negotiated="TLSv1.3", floor="TLSv1.2+"), ctx_of()) == []


def test_protocol_weak_fires_on_azure_low_floor():
    assert one(tls.protocol_weak(azure_sb("1.0"), ctx_of()))


def test_protocol_weak_silent_on_azure_1_2():
    assert tls.protocol_weak(azure_sb("1.2"), ctx_of()) == []


def test_protocol_weak_not_assessable_when_azure_floor_absent():
    hit = one(tls.protocol_weak(azure_sb(None), ctx_of()))
    assert hit.assessable is False


def test_protocol_weak_fires_on_apigee_weak_protocol():
    r = apigee([{"name": "t1", "url": "https://b", "ssl_enabled": True, "protocols": ["TLSv1.1"]}])
    assert one(tls.protocol_weak(r, ctx_of()))


def test_protocol_weak_silent_on_apigee_strong_protocol():
    r = apigee([{"name": "t1", "url": "https://b", "ssl_enabled": True, "protocols": ["TLSv1.2"]}])
    assert tls.protocol_weak(r, ctx_of()) == []


# ── TLS.LISTENER.MISSING ───────────────────────────────────────────────────────
def test_listener_missing_fires_high_on_plaintext_mcp():
    hit = one(tls.listener_missing(mcp(scheme="http", cert_status=None), ctx_of()))
    assert hit.severity == "high"


def test_listener_missing_silent_on_https_mcp():
    assert tls.listener_missing(mcp(scheme="https"), ctx_of()) == []


def test_listener_missing_fires_on_plaintext_mft():
    hit = one(tls.listener_missing(mft(enabled=False, scheme="http", cert_status=None), ctx_of()))
    assert hit.severity == "high"


def test_listener_missing_fires_high_on_msk_plaintext():
    assert one(tls.listener_missing(msk("PLAINTEXT"), ctx_of())).severity == "high"


def test_listener_missing_silent_on_msk_tls():
    assert tls.listener_missing(msk("TLS"), ctx_of()) == []


def test_listener_missing_not_assessable_when_msk_mode_absent():
    assert one(tls.listener_missing(msk(None), ctx_of())).assessable is False


def test_listener_missing_fires_on_apigee_plaintext_backend():
    r = apigee([{"name": "t1", "url": "http://b", "ssl_enabled": False, "protocols": []}])
    assert one(tls.listener_missing(r, ctx_of()))


def test_listener_missing_not_assessable_when_apigee_targets_unreadable():
    assert one(tls.listener_missing(apigee([], readable=False), ctx_of())).assessable is False


def test_listener_missing_ignores_apigee_unknown_ssl():
    # ssl_enabled None is 'unknown', never assumed plaintext.
    r = apigee([{"name": "t1", "url": "https://b", "ssl_enabled": None, "protocols": []}])
    assert tls.listener_missing(r, ctx_of()) == []


def test_listener_missing_fires_on_ingress_without_tls():
    assert one(tls.listener_missing(ingress("false"), ctx_of()))


def test_listener_missing_silent_on_ingress_with_tls():
    assert tls.listener_missing(ingress("true"), ctx_of()) == []


def test_listener_missing_fires_on_gateway_https_listener_without_tls_block():
    r = gateway([{"name": "web", "port": 443, "protocol": "HTTPS", "has_tls": False}])
    assert one(tls.listener_missing(r, ctx_of()))


def test_listener_missing_silent_on_gateway_with_tls_block():
    r = gateway([{"name": "web", "port": 443, "protocol": "HTTPS", "has_tls": True}])
    assert tls.listener_missing(r, ctx_of()) == []


# ── TLS.MTLS.PERMISSIVE ────────────────────────────────────────────────────────
def test_mtls_permissive_fires_on_tls_plaintext():
    assert one(tls.mtls_permissive(msk("TLS_PLAINTEXT"), ctx_of()))


def test_mtls_permissive_silent_on_strict_or_plaintext_only():
    assert tls.mtls_permissive(msk("TLS"), ctx_of()) == []
    assert tls.mtls_permissive(msk("PLAINTEXT"), ctx_of()) == []   # LISTENER.MISSING owns that
    assert tls.mtls_permissive(msk(None), ctx_of()) == []          # not-assessable owned elsewhere
