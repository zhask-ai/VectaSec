"""GraphQL rulepack + parse-layer tests. Offline: no httpx, no live endpoint.

The pure parse layer `parse_introspection` is exercised against the golden introspection fixture,
and every detector gets a fire / does-not-fire / not-assessable case. Detectors run against `raw`
dicts shaped exactly like what connect/graphql.py records off the wire.
"""
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.registry import DETECTORS
from vectasec.connect import graphql as c
from vectasec.detect import graphql as g

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "graphql_introspection.json").read_text())

URL = "https://api.example.com/graphql"
EXT = f"graphql-{URL}"

EXPECTED_RULES = {
    "GRAPHQL.INTROSPECTION.ENABLED", "GRAPHQL.INTROSPECTION.UNAUTHENTICATED",
    "GRAPHQL.SCHEMA.FIELD_SUGGESTIONS", "GRAPHQL.AUTHZ.UNAUTH_MUTATION_SURFACE",
    "GRAPHQL.DOS.BATCHING_ENABLED", "GRAPHQL.DOS.NO_DEPTH_LIMIT",
    "GRAPHQL.DOS.NO_PERSISTED_QUERIES", "GRAPHQL.TRANSPORT.GET_QUERIES", "GRAPHQL.TLS.PLAINTEXT",
}


def ctx(config=None):
    return ScanContext(connection_id="c", tenant_id="t", resources=[], config=config or {})


def _empty_intro():
    return {"enabled": False, "query_type": None, "mutation_type": None,
            "subscription_type": None, "type_count": None, "query_field_count": None,
            "mutation_field_count": None, "error_message": None}


def endpoint(**over) -> Resource:
    """A hardened https endpoint: introspection off, no suggestions, batching off, depth limited,
    persisted queries supported, no GET. Individual tests override into a finding."""
    raw = {
        "url": URL, "host": "api.example.com", "port": 443, "scheme": "https",
        "resolved_ip": "203.0.113.5", "ip_class": "public", "source_zone": "corp",
        "authenticated_scan": True,
        "introspection": _empty_intro(),
        "introspection_status": 200, "introspection_error": None,
        "unauth_introspection": _empty_intro(),
        "unauth_status": 401,
        "field_suggestions": {"probed": True, "enabled": False,
                              "sample": 'Cannot query field "x".', "error": None},
        "batching": {"probed": True, "enabled": False, "count_echoed": 1, "error": None},
        "depth_probe": {"probed": True, "accepted": False,
                        "error_message": "max query depth exceeded", "error": None},
        "get_method": {"probed": True, "enabled": False, "status": 400, "error": None},
        "persisted_queries": {"probed": True, "signal": "supported", "error": None},
        "tls": {"negotiated": "TLSv1.3", "cert_status": "valid", "cert_error": None},
    }
    raw.update(over)
    return Resource(kind="graphql_endpoint", name="api", ext_id=EXT, raw=raw)


def _schema(enabled=True, mutation="Mutation", mfields=3, tc=7):
    return {"enabled": enabled, "query_type": "Query", "mutation_type": mutation,
            "subscription_type": "Subscription", "type_count": tc, "query_field_count": 4,
            "mutation_field_count": mfields, "error_message": None}


# ── parse layer ────────────────────────────────────────────────────────────
def test_parse_introspection_golden_fixture():
    got = c.parse_introspection(FIX)
    assert got["enabled"] is True
    assert got["query_type"] == "Query"
    assert got["mutation_type"] == "Mutation"
    assert got["subscription_type"] == "Subscription"
    assert got["type_count"] == 7
    assert got["query_field_count"] == 4
    assert got["mutation_field_count"] == 3


def test_parse_introspection_errors_body():
    got = c.parse_introspection({"errors": [{"message": "GraphQL introspection is not allowed"}]})
    assert got["enabled"] is False
    assert "not allowed" in got["error_message"]


def test_parse_introspection_malformed():
    assert c.parse_introspection(None)["enabled"] is False
    assert c.parse_introspection({"data": {}})["enabled"] is False


def test_field_suggestions_present_helper():
    assert c.field_suggestions_present({"errors": [{"message": 'Did you mean "__typename"?'}]})
    assert not c.field_suggestions_present({"errors": [{"message": "Unknown field."}]})


def test_apq_signal_helper():
    assert c.apq_signal({"errors": [{"message": "PersistedQueryNotSupported"}]}) == "not_supported"
    assert c.apq_signal({"errors": [{"message": "PersistedQueryNotFound"}]}) == "supported"
    assert c.apq_signal({"data": {"__typename": "Query"}}) == "unknown"


# ── registration ───────────────────────────────────────────────────────────
def test_rules_registered_once_with_valid_severity():
    got = [d.rule_id for d in DETECTORS if d.rule_id.startswith("GRAPHQL.")]
    assert sorted(got) == sorted(EXPECTED_RULES)
    for d in DETECTORS:
        if d.rule_id.startswith("GRAPHQL."):
            assert d.severity in ("info", "low", "medium", "high", "critical")
            assert d.kinds == ("graphql_endpoint",)


# ── introspection enabled ──────────────────────────────────────────────────
def test_introspection_enabled_fires():
    hits = g.introspection_enabled(endpoint(introspection=_schema()), ctx())
    assert hits and hits[0].assessable


def test_introspection_enabled_clean_when_off():
    assert g.introspection_enabled(endpoint(), ctx()) == []


def test_introspection_enabled_not_assessable_on_error():
    r = endpoint(introspection=_empty_intro(), introspection_error="ConnectTimeout: ")
    hits = g.introspection_enabled(r, ctx())
    assert hits and hits[0].assessable is False


# ── unauthenticated introspection + mutation surface ───────────────────────
def test_introspection_unauthenticated_fires():
    hits = g.introspection_unauthenticated(endpoint(unauth_introspection=_schema()), ctx())
    assert hits and hits[0].severity is None and "no credential" in hits[0].observation


def test_introspection_unauthenticated_clean():
    assert g.introspection_unauthenticated(endpoint(), ctx()) == []


def test_unauth_mutation_surface_fires():
    hits = g.unauth_mutation_surface(endpoint(unauth_introspection=_schema()), ctx())
    assert hits and "mutation" in hits[0].observation.lower()


def test_unauth_mutation_surface_clean_without_mutations():
    r = endpoint(unauth_introspection=_schema(mutation=None, mfields=None))
    assert g.unauth_mutation_surface(r, ctx()) == []


# ── field suggestions ──────────────────────────────────────────────────────
def test_field_suggestions_fire():
    r = endpoint(field_suggestions={"probed": True, "enabled": True,
                                    "sample": 'Did you mean "__typename"?', "error": None})
    assert g.field_suggestions(r, ctx())


def test_field_suggestions_clean():
    assert g.field_suggestions(endpoint(), ctx()) == []


def test_field_suggestions_not_assessable():
    r = endpoint(field_suggestions={"probed": True, "enabled": None, "sample": None,
                                    "error": "ConnectError"})
    hits = g.field_suggestions(r, ctx())
    assert hits and hits[0].assessable is False


# ── batching ───────────────────────────────────────────────────────────────
def test_batching_fires():
    r = endpoint(batching={"probed": True, "enabled": True, "count_echoed": 2, "error": None})
    assert g.batching_enabled(r, ctx())


def test_batching_clean():
    assert g.batching_enabled(endpoint(), ctx()) == []


def test_batching_not_assessable():
    r = endpoint(batching={"probed": True, "enabled": None, "count_echoed": None, "error": "boom"})
    hits = g.batching_enabled(r, ctx())
    assert hits and hits[0].assessable is False


# ── depth limit ────────────────────────────────────────────────────────────
def test_no_depth_limit_fires_when_deep_query_accepted():
    r = endpoint(introspection=_schema(),
                 depth_probe={"probed": True, "accepted": True, "error_message": None, "error": None})
    assert g.no_depth_limit(r, ctx())


def test_no_depth_limit_clean_when_rejected():
    r = endpoint(introspection=_schema())  # depth_probe.accepted False by default
    assert g.no_depth_limit(r, ctx()) == []


def test_no_depth_limit_not_assessable_when_introspection_off():
    # introspection off (default) → the __schema-based depth probe cannot run
    r = endpoint(depth_probe={"probed": True, "accepted": True, "error_message": None, "error": None})
    hits = g.no_depth_limit(r, ctx())
    assert hits and hits[0].assessable is False


# ── persisted queries ──────────────────────────────────────────────────────
def test_no_persisted_queries_fires():
    r = endpoint(introspection=_schema(),
                 persisted_queries={"probed": True, "signal": "not_supported", "error": None})
    assert g.no_persisted_queries(r, ctx())


def test_no_persisted_queries_clean_when_supported():
    assert g.no_persisted_queries(endpoint(introspection=_schema()), ctx()) == []


def test_no_persisted_queries_not_assessable_on_error():
    r = endpoint(persisted_queries={"probed": True, "signal": "unknown", "error": "ConnectError"})
    hits = g.no_persisted_queries(r, ctx())
    assert hits and hits[0].assessable is False


# ── GET queries ────────────────────────────────────────────────────────────
def test_get_queries_fires():
    r = endpoint(get_method={"probed": True, "enabled": True, "status": 200, "error": None})
    assert g.get_queries(r, ctx())


def test_get_queries_clean():
    assert g.get_queries(endpoint(), ctx()) == []


def test_get_queries_not_assessable():
    r = endpoint(get_method={"probed": True, "enabled": None, "status": None, "error": "boom"})
    hits = g.get_queries(r, ctx())
    assert hits and hits[0].assessable is False


# ── TLS plaintext ──────────────────────────────────────────────────────────
def test_tls_plaintext_fires():
    r = endpoint(scheme="http", ip_class="public")
    assert g.tls_plaintext(r, ctx())


def test_tls_plaintext_clean_on_https():
    assert g.tls_plaintext(endpoint(), ctx()) == []


def test_tls_plaintext_clean_on_loopback_http():
    r = endpoint(scheme="http", ip_class="loopback")
    assert g.tls_plaintext(r, ctx()) == []


# ── robustness ─────────────────────────────────────────────────────────────
def test_no_detector_raises_on_degraded_endpoint():
    r = Resource(kind="graphql_endpoint", name="x", ext_id=EXT, raw={
        "url": URL, "scheme": "https", "introspection": _empty_intro(),
        "introspection_error": "ConnectTimeout: ", "unauth_introspection": _empty_intro(),
        "field_suggestions": {"probed": True, "enabled": None, "error": "x"},
        "batching": {"probed": True, "enabled": None, "error": "x"},
        "depth_probe": {"probed": True, "accepted": None, "error": "x"},
        "get_method": {"probed": True, "enabled": None, "error": "x"},
        "persisted_queries": {"probed": True, "signal": "unknown", "error": "x"},
        "tls": {}})
    for d in DETECTORS:
        if d.rule_id.startswith("GRAPHQL."):
            d.fn(r, ctx())  # must not raise
