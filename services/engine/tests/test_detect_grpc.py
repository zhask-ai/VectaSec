"""gRPC rulepack + parse-layer tests. Offline: no grpcio channel, no live server.

`derive_service_facts` is exercised against the golden reflection service list; every detector gets
fire / does-not-fire / not-assessable cases, including the key nuance that reflection being DISABLED
is the good outcome (silent reflection rules, a coverage-gap auth rule that says reflection-off is
recommended).
"""
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.registry import DETECTORS
from vectasec.connect import grpc as c
from vectasec.detect import grpc as g

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "grpc_reflection.json").read_text())

TARGET = "api.example.com:443"
EXT = f"grpc-{TARGET}"

EXPECTED_RULES = {
    "GRPC.REFLECTION.EXPOSED", "GRPC.REFLECTION.UNAUTHENTICATED", "GRPC.HEALTH.EXPOSED",
    "GRPC.TRANSPORT.PLAINTEXT", "GRPC.TLS.CERT_INVALID", "GRPC.AUTH.NO_PER_RPC_SIGNAL",
}


def ctx():
    return ScanContext(connection_id="c", tenant_id="t", resources=[], config={})


def server(**over) -> Resource:
    """Reflection ON and unauthenticated (the fixture case): a service catalogue is disclosed."""
    reflection = {"enabled": True, "reached": True, "unauthenticated_ok": True,
                  "authenticated_scan": False, "services": FIX["services"],
                  "methods": FIX["methods"], "status_code": "OK", "error": None,
                  "unauth_status": "OK"}
    facts = c.derive_service_facts(reflection)
    raw = {
        "target": TARGET, "host": "api.example.com", "port": 443,
        "tls_configured": True, "resolved_ip": "203.0.113.9", "ip_class": "public",
        "source_zone": "corp", "reflection": reflection, **facts,
        "plaintext": {"reachable": False, "status_code": "UNAVAILABLE", "error": "handshake"},
        "tls": {"negotiated": "TLSv1.3", "cert_status": "valid", "cert_error": None},
    }
    raw.update(over)
    return Resource(kind="grpc_service", name=TARGET, ext_id=EXT, raw=raw)


def hardened(**over) -> Resource:
    """Reflection DISABLED (UNIMPLEMENTED) but the server did answer at the gRPC layer over TLS."""
    reflection = {"enabled": False, "reached": True, "unauthenticated_ok": False,
                  "authenticated_scan": False, "services": [], "methods": {},
                  "status_code": "UNIMPLEMENTED", "error": "UNIMPLEMENTED: reflection disabled",
                  "unauth_status": "UNIMPLEMENTED"}
    facts = c.derive_service_facts(reflection)
    raw = {
        "target": TARGET, "host": "api.example.com", "port": 443,
        "tls_configured": True, "resolved_ip": "203.0.113.9", "ip_class": "public",
        "source_zone": "corp", "reflection": reflection, **facts,
        "plaintext": {"reachable": False, "status_code": "UNAVAILABLE", "error": "handshake"},
        "tls": {"negotiated": "TLSv1.3", "cert_status": "valid", "cert_error": None},
    }
    raw.update(over)
    return Resource(kind="grpc_service", name=TARGET, ext_id=EXT, raw=raw)


# ── parse layer ────────────────────────────────────────────────────────────
def test_derive_service_facts_golden():
    facts = c.derive_service_facts(FIX)
    assert facts["service_count"] == 4
    assert facts["app_service_count"] == 2       # excludes reflection + health
    assert facts["method_count"] == 5
    assert facts["health_service_present"] is True
    assert facts["reflection_service_present"] is True


def test_derive_service_facts_empty():
    facts = c.derive_service_facts({"services": [], "methods": {}})
    assert facts["service_count"] == 0
    assert facts["health_service_present"] is False


def test_status_name_mapping():
    assert c._status_name(12) == "UNIMPLEMENTED"
    assert c._status_name(16) == "UNAUTHENTICATED"
    assert c._status_name(99) == "CODE_99"


# ── registration ───────────────────────────────────────────────────────────
def test_rules_registered_once():
    got = [d.rule_id for d in DETECTORS if d.rule_id.startswith("GRPC.")]
    assert sorted(got) == sorted(EXPECTED_RULES)
    for d in DETECTORS:
        if d.rule_id.startswith("GRPC."):
            assert d.severity in ("info", "low", "medium", "high", "critical")
            assert d.kinds == ("grpc_service",)


# ── reflection exposed ─────────────────────────────────────────────────────
def test_reflection_exposed_fires():
    hits = g.reflection_exposed(server(), ctx())
    assert hits and hits[0].assessable


def test_reflection_exposed_clean_when_disabled():
    assert g.reflection_exposed(hardened(), ctx()) == []


def test_reflection_exposed_not_assessable_when_unreachable():
    r = hardened(reflection={"enabled": False, "reached": False, "unauthenticated_ok": False,
                             "services": [], "methods": {}, "status_code": "UNAVAILABLE",
                             "error": "UNAVAILABLE: connect failed"},
                 plaintext={"reachable": False, "status_code": "UNAVAILABLE", "error": "x"})
    hits = g.reflection_exposed(r, ctx())
    assert hits and hits[0].assessable is False


# ── reflection unauthenticated ─────────────────────────────────────────────
def test_reflection_unauthenticated_fires():
    assert g.reflection_unauthenticated(server(), ctx())


def test_reflection_unauthenticated_clean_when_auth_required():
    r = server(reflection={**server().raw["reflection"], "unauthenticated_ok": False})
    assert g.reflection_unauthenticated(r, ctx()) == []


# ── health exposed ─────────────────────────────────────────────────────────
def test_health_exposed_fires():
    assert g.health_exposed(server(), ctx())


def test_health_exposed_clean_when_absent():
    assert g.health_exposed(hardened(), ctx()) == []


# ── plaintext transport ────────────────────────────────────────────────────
def test_transport_plaintext_fires():
    r = server(plaintext={"reachable": True, "status_code": "UNIMPLEMENTED", "error": None})
    assert g.transport_plaintext(r, ctx())


def test_transport_plaintext_clean_when_tls_only():
    assert g.transport_plaintext(server(), ctx()) == []


def test_transport_plaintext_clean_on_loopback():
    r = server(ip_class="loopback",
               plaintext={"reachable": True, "status_code": "UNIMPLEMENTED", "error": None})
    assert g.transport_plaintext(r, ctx()) == []


def test_transport_plaintext_not_assessable():
    r = server(plaintext={"reachable": None, "status_code": None, "error": "boom"})
    hits = g.transport_plaintext(r, ctx())
    assert hits and hits[0].assessable is False


# ── TLS cert ───────────────────────────────────────────────────────────────
def test_tls_cert_invalid_fires():
    r = server(tls={"negotiated": "TLSv1.3", "cert_status": "invalid",
                    "cert_error": "self signed certificate"})
    assert g.tls_cert_invalid(r, ctx())


def test_tls_cert_invalid_clean_when_valid():
    assert g.tls_cert_invalid(server(), ctx()) == []


def test_tls_cert_invalid_not_assessable_on_unknown():
    r = server(tls={"negotiated": None, "cert_status": "unknown", "cert_error": "timeout"})
    hits = g.tls_cert_invalid(r, ctx())
    assert hits and hits[0].assessable is False


def test_tls_cert_clean_when_plaintext_configured():
    assert g.tls_cert_invalid(server(tls_configured=False), ctx()) == []


# ── per-RPC auth ───────────────────────────────────────────────────────────
def test_no_per_rpc_signal_fires_on_unauth_reflection():
    hits = g.no_per_rpc_signal(server(), ctx())
    assert hits and hits[0].assessable is True


def test_no_per_rpc_signal_not_assessable_when_reflection_off():
    hits = g.no_per_rpc_signal(hardened(), ctx())
    assert hits and hits[0].assessable is False
    assert "reflection-off is itself good posture" in hits[0].assessment_reason


def test_no_per_rpc_signal_silent_when_unreachable():
    r = hardened(reflection={"enabled": False, "reached": False, "unauthenticated_ok": False,
                             "services": [], "methods": {}, "status_code": "UNAVAILABLE",
                             "error": "x"},
                 plaintext={"reachable": False, "status_code": "UNAVAILABLE", "error": "x"})
    assert g.no_per_rpc_signal(r, ctx()) == []


# ── robustness ─────────────────────────────────────────────────────────────
def test_no_detector_raises_on_degraded_target():
    r = Resource(kind="grpc_service", name="x", ext_id=EXT, raw={
        "target": TARGET, "reflection": {"enabled": None, "reached": False,
                                          "unauthenticated_ok": False, "status_code": None},
        "plaintext": {"reachable": None, "error": "x"}, "tls": {}, "tls_configured": True})
    for d in DETECTORS:
        if d.rule_id.startswith("GRPC."):
            d.fn(r, ctx())
