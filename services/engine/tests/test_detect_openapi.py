"""REST/OpenAPI rulepack + parse-layer tests. Offline: no httpx.

`parse_spec` is exercised against the golden OpenAPI fixture, and the connector's own collect layer
turns that fixture into rest_api/rest_route resources the detectors run on — so the detectors see
exactly the shapes connect/openapi.py emits. Every rule gets fire / does-not-fire / not-assessable.
"""
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.registry import DETECTORS
from vectasec.connect import openapi as c
from vectasec.detect import openapi as d

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "openapi_spec.json").read_text())

EXPECTED_RULES = {
    "OPENAPI.AUTH.UNAUTHENTICATED_OPERATION", "OPENAPI.AUTH.NO_GLOBAL_SECURITY",
    "OPENAPI.AUTH.APIKEY_IN_QUERY", "OPENAPI.TRANSPORT.HTTP_SERVER", "OPENAPI.OPS.DEPRECATED_LIVE",
    "OPENAPI.DOS.NO_RATE_LIMIT_DOCUMENTED", "OPENAPI.CORS.PERMISSIVE",
    "OPENAPI.SPEC.NO_SECURITY_SCHEMES",
}


def ctx():
    return ScanContext(connection_id="c", tenant_id="t", resources=[], config={})


def collect(doc):
    return c.collect({"spec": json.dumps(doc)})


def api_resource(collected):
    return next(r for r in collected.resources if r.kind == "rest_api")


def routes(collected):
    return [r for r in collected.resources if r.kind == "rest_route"]


# ── parse layer ────────────────────────────────────────────────────────────
def test_parse_spec_golden():
    facts = c.parse_spec(FIX)
    assert facts["valid"] and facts["spec_kind"] == "openapi"
    assert facts["has_global_security"] is True
    assert facts["apikey_query_schemes"] == ["legacyKey"]
    assert len(facts["operations"]) == 4
    ops = {(o["method"], o["path"]): o for o in facts["operations"]}
    assert ops[("GET", "/orders")]["is_authenticated"] is True     # inherits global security
    assert ops[("GET", "/health")]["is_authenticated"] is False    # security: [] -> public
    assert ops[("GET", "/health")]["explicitly_public"] is True
    assert ops[("GET", "/legacy/export")]["deprecated"] is True
    assert ops[("GET", "/legacy/export")]["uses_apikey_query"] is True


def test_parse_spec_swagger2_servers():
    facts = c.parse_spec({"swagger": "2.0", "host": "api.x.com", "basePath": "/v2",
                          "schemes": ["http", "https"], "paths": {}})
    urls = {s["url"] for s in facts["servers"]}
    assert "http://api.x.com/v2" in urls and "https://api.x.com/v2" in urls
    assert facts["spec_kind"] == "swagger"


def test_parse_spec_malformed():
    assert c.parse_spec(None)["valid"] is False
    assert c.parse_spec({"paths": "nope"})["valid"] is False


def test_rate_limit_and_cors_facts():
    assert c.parse_spec({"openapi": "3.0.0", "paths": {},
                         "x-throttling": {"burst": 10}})["rate_limit"]["documented"] is True
    cors = c.parse_spec({"openapi": "3.0.0", "paths": {},
                         "x-amazon-apigateway-cors": {"allowOrigins": ["*"]}})["cors"]
    assert cors["documented"] is True and cors["permissive"] is True


# ── registration ───────────────────────────────────────────────────────────
def test_rules_registered_once():
    got = [x.rule_id for x in DETECTORS if x.rule_id.startswith("OPENAPI.")]
    assert sorted(got) == sorted(EXPECTED_RULES)
    for x in DETECTORS:
        if x.rule_id.startswith("OPENAPI."):
            assert x.severity in ("info", "low", "medium", "high", "critical")
            assert x.kinds in (("rest_api",), ("rest_route",))


# ── unauthenticated operation ──────────────────────────────────────────────
def test_unauthenticated_operation_fires_on_public_route():
    col = collect(FIX)
    health = next(r for r in routes(col) if r.raw["path"] == "/health")
    hits = d.unauthenticated_operation(health, ctx())
    assert hits and "explicitly disables auth" in hits[0].observation


def test_unauthenticated_operation_clean_on_secured_route():
    col = collect(FIX)
    post_orders = next(r for r in routes(col)
                       if r.raw["path"] == "/orders" and r.raw["method"] == "POST")
    assert d.unauthenticated_operation(post_orders, ctx()) == []


# ── global security ────────────────────────────────────────────────────────
def test_no_global_security_fires():
    doc = {**FIX}
    doc.pop("security", None)
    api = api_resource(collect(doc))
    assert d.no_global_security(api, ctx())


def test_no_global_security_clean():
    assert d.no_global_security(api_resource(collect(FIX)), ctx()) == []


def test_no_global_security_not_assessable_on_bad_spec():
    api = api_resource(collect({"not": "a spec"}))
    hits = d.no_global_security(api, ctx())
    assert hits and hits[0].assessable is False


# ── apiKey in query ────────────────────────────────────────────────────────
def test_apikey_in_query_fires():
    assert d.apikey_in_query(api_resource(collect(FIX)), ctx())


def test_apikey_in_query_clean():
    doc = json.loads(json.dumps(FIX))
    doc["components"]["securitySchemes"].pop("legacyKey")
    assert d.apikey_in_query(api_resource(collect(doc)), ctx()) == []


# ── http server ────────────────────────────────────────────────────────────
def test_http_server_fires():
    assert d.http_server(api_resource(collect(FIX)), ctx())


def test_http_server_clean_https_only():
    doc = json.loads(json.dumps(FIX))
    doc["servers"] = [{"url": "https://api.example.com/v1"}]
    assert d.http_server(api_resource(collect(doc)), ctx()) == []


def test_http_server_ignores_localhost():
    doc = json.loads(json.dumps(FIX))
    doc["servers"] = [{"url": "http://localhost:8080"}]
    assert d.http_server(api_resource(collect(doc)), ctx()) == []


# ── deprecated live ────────────────────────────────────────────────────────
def test_deprecated_live_fires():
    col = collect(FIX)
    legacy = next(r for r in routes(col) if r.raw["path"] == "/legacy/export")
    assert d.deprecated_live(legacy, ctx())


def test_deprecated_live_clean():
    col = collect(FIX)
    orders = next(r for r in routes(col) if r.raw["path"] == "/orders" and r.raw["method"] == "GET")
    assert d.deprecated_live(orders, ctx()) == []


# ── rate limit ─────────────────────────────────────────────────────────────
def test_no_rate_limit_not_assessable_when_undocumented():
    hits = d.no_rate_limit(api_resource(collect(FIX)), ctx())
    assert hits and hits[0].assessable is False


def test_no_rate_limit_clean_when_documented():
    doc = json.loads(json.dumps(FIX))
    doc["x-throttling"] = {"rateLimit": 100}
    assert d.no_rate_limit(api_resource(collect(doc)), ctx()) == []


# ── CORS ───────────────────────────────────────────────────────────────────
def test_cors_permissive_fires():
    doc = json.loads(json.dumps(FIX))
    doc["x-amazon-apigateway-cors"] = {"allowOrigins": ["*"]}
    assert d.cors_permissive(api_resource(collect(doc)), ctx())


def test_cors_clean_when_scoped():
    doc = json.loads(json.dumps(FIX))
    doc["x-amazon-apigateway-cors"] = {"allowOrigins": ["https://app.example.com"]}
    assert d.cors_permissive(api_resource(collect(doc)), ctx()) == []


def test_cors_not_assessable_when_undocumented():
    hits = d.cors_permissive(api_resource(collect(FIX)), ctx())
    assert hits and hits[0].assessable is False


# ── no security schemes ────────────────────────────────────────────────────
def test_no_security_schemes_fires():
    doc = json.loads(json.dumps(FIX))
    doc.pop("components", None)
    assert d.no_security_schemes(api_resource(collect(doc)), ctx())


def test_no_security_schemes_clean():
    assert d.no_security_schemes(api_resource(collect(FIX)), ctx()) == []


# ── robustness ─────────────────────────────────────────────────────────────
def test_no_detector_raises_on_bad_spec():
    col = collect({"garbage": True})
    api = api_resource(col)
    for x in DETECTORS:
        if x.rule_id.startswith("OPENAPI.") and x.kinds == ("rest_api",):
            x.fn(api, ctx())
