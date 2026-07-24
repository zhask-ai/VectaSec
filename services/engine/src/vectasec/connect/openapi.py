"""OpenAPI/Swagger connector — read-only fetch + static analysis of an API description.

A published OpenAPI/Swagger document is authorization config: it states which operations require
which security scheme, what transports the API is served over, and where API keys travel. That is
exactly the evidence a posture finding must cite, so this connector fetches the doc (or accepts a
pasted one) and analyses the spec itself — it never calls the described operations.

The parse layer `parse_spec(doc)` is pure: an OpenAPI/Swagger dict in, normalized facts out. It
handles both OpenAPI 3.x (`openapi`, `components.securitySchemes`, `servers`) and Swagger 2.0
(`swagger`, `securityDefinitions`, `host`+`schemes`+`basePath`). Tests feed golden docs to it, so
httpx stays out of the test suite.

Emits DISTINCT kinds `rest_api` (the whole description) and `rest_route` (one per operation) so no
other rulepack runs against them by accident.

config: spec_url (fetch) OR spec (pasted JSON string / dict); one is required. timeout.
"""
import json
from urllib.parse import urlsplit

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


# ── pure parse layer (tests feed golden docs here) ─────────────────────────
def _scheme_of(url: str):
    s = urlsplit(url)
    return (s.scheme or None), (s.hostname or None)


def _servers(doc: dict) -> list:
    """Normalize server URLs across OpenAPI 3.x and Swagger 2.0 into [{url, scheme, host}]."""
    out = []
    if isinstance(doc.get("servers"), list):                      # OpenAPI 3.x
        for srv in doc["servers"]:
            if isinstance(srv, dict) and isinstance(srv.get("url"), str):
                scheme, host = _scheme_of(srv["url"])
                out.append({"url": srv["url"], "scheme": scheme, "host": host})
    elif doc.get("host") or doc.get("schemes"):                   # Swagger 2.0
        host = doc.get("host") or ""
        base = doc.get("basePath") or ""
        schemes = doc.get("schemes") if isinstance(doc.get("schemes"), list) else []
        for sch in schemes or [None]:
            url = f"{sch}://{host}{base}" if sch else f"{host}{base}"
            out.append({"url": url, "scheme": sch, "host": host or None})
    return out


def _security_schemes(doc: dict) -> dict:
    """components.securitySchemes (3.x) or securityDefinitions (2.0) → {name: {type, in, scheme}}."""
    comps = doc.get("components") if isinstance(doc.get("components"), dict) else {}
    raw = comps.get("securitySchemes") if isinstance(comps.get("securitySchemes"), dict) else None
    if raw is None:
        raw = doc.get("securityDefinitions") if isinstance(doc.get("securityDefinitions"), dict) else {}
    out = {}
    for name, defn in (raw or {}).items():
        if not isinstance(defn, dict):
            continue
        out[name] = {"type": defn.get("type"), "in": defn.get("in"),
                     "scheme": defn.get("scheme"), "flows": bool(defn.get("flows") or defn.get("flow"))}
    return out


def _security_names(sec_list) -> list:
    """A `security` requirement list is [{schemeName: [scopes]}, ...]; return the scheme names."""
    names = []
    if isinstance(sec_list, list):
        for req in sec_list:
            if isinstance(req, dict):
                names.extend(req.keys())
    return names


def parse_spec(doc) -> dict:
    """Normalize an OpenAPI/Swagger document. Pure; never raises on malformed input."""
    if not isinstance(doc, dict):
        return {"valid": False, "spec_kind": None, "spec_version": None, "servers": [],
                "security_schemes": {}, "has_global_security": False, "global_security_names": [],
                "operations": [], "apikey_query_schemes": [], "cors": {"documented": False, "permissive": None},
                "rate_limit": {"documented": False}, "title": None}

    spec_kind = "openapi" if doc.get("openapi") else ("swagger" if doc.get("swagger") else None)
    spec_version = doc.get("openapi") or doc.get("swagger")
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}

    schemes = _security_schemes(doc)
    apikey_query = [n for n, d in schemes.items()
                    if (d.get("type") == "apiKey" and d.get("in") == "query")]

    global_sec = doc.get("security")
    has_global = isinstance(global_sec, list) and len(global_sec) > 0
    global_names = _security_names(global_sec)

    operations = []
    paths = doc.get("paths") if isinstance(doc.get("paths"), dict) else {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            op_sec_present = "security" in op
            op_sec = op.get("security")
            if op_sec_present:
                eff_names = _security_names(op_sec)
                explicitly_public = isinstance(op_sec, list) and len(op_sec) == 0
            else:
                eff_names = list(global_names)
                explicitly_public = False
            authenticated = len(eff_names) > 0
            uses_apikey_query = any(n in apikey_query for n in eff_names)
            operations.append({
                "path": path, "method": method.upper(),
                "operation_id": op.get("operationId"),
                "deprecated": bool(op.get("deprecated")),
                "security_scheme_names": eff_names,
                "is_authenticated": authenticated,
                "explicitly_public": explicitly_public,
                "op_level_security": op_sec_present,
                "uses_apikey_query": uses_apikey_query,
            })

    return {
        "valid": spec_kind is not None,
        "spec_kind": spec_kind, "spec_version": spec_version,
        "title": info.get("title"),
        "servers": _servers(doc),
        "security_schemes": schemes,
        "apikey_query_schemes": apikey_query,
        "has_global_security": has_global,
        "global_security_names": global_names,
        "operations": operations,
        "cors": _cors_facts(doc),
        "rate_limit": _rate_limit_facts(doc),
    }


def _walk(node):
    """Yield every (key, value) pair and list element in a nested dict/list, depth-first."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k, v
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _cors_facts(doc: dict) -> dict:
    """CORS is not a standard OpenAPI field, so this only reports what is DOCUMENTED: an
    x-amazon-apigateway-cors extension or an Access-Control-Allow-Origin response header. Absence
    is reported as not-documented (the detector treats that as not-assessable, never a pass)."""
    documented, permissive = False, None
    for k, v in _walk(doc):
        kl = str(k).lower()
        if kl == "x-amazon-apigateway-cors" and isinstance(v, dict):
            documented = True
            origins = v.get("allowOrigins") or v.get("allowOrigin")
            if origins == "*" or (isinstance(origins, list) and "*" in origins):
                permissive = True
            elif permissive is None:
                permissive = False
        if kl == "access-control-allow-origin":
            documented = True
            val = v.get("example") if isinstance(v, dict) else v
            default = v.get("default") if isinstance(v, dict) else None
            schema = v.get("schema") if isinstance(v, dict) else None
            sdefault = schema.get("default") if isinstance(schema, dict) else None
            if "*" in (str(val), str(default), str(sdefault)):
                permissive = True
            elif permissive is None:
                permissive = False
    return {"documented": documented, "permissive": permissive}


def _rate_limit_facts(doc: dict) -> dict:
    """Report whether rate limiting is DOCUMENTED: a rate-limit/throttle vendor extension, a
    documented 429 response, or an X-RateLimit-* header. Enforcement at a gateway is invisible
    here, so a not-documented result is a coverage gap, not a verdict."""
    documented = False
    for k, v in _walk(doc):
        kl = str(k).lower()
        if any(tok in kl for tok in ("ratelimit", "rate-limit", "throttl")):
            documented = True
            break
        if kl == "429":
            documented = True
            break
    return {"documented": documented}


# ── collect ────────────────────────────────────────────────────────────────
def _load_doc(config: dict) -> tuple:
    """Return (doc, source, error). Prefers a pasted spec; otherwise fetches spec_url as JSON."""
    pasted = config.get("spec")
    if isinstance(pasted, dict):
        return pasted, "pasted", None
    if isinstance(pasted, str) and pasted.strip():
        try:
            return json.loads(pasted), "pasted", None
        except ValueError as e:
            return None, "pasted", f"pasted spec is not valid JSON: {e}"
    url = (config.get("spec_url") or "").strip()
    if not url:
        raise SystemExit("openapi connector requires config['spec_url'] or config['spec']")
    timeout = float(config.get("timeout") or 10.0)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            r = client.get(url, headers={"Accept": "application/json"})
        try:
            return r.json(), "url", None
        except ValueError:
            return None, "url", f"spec URL returned non-JSON (status {r.status_code})"
    except Exception as e:
        return None, "url", f"{type(e).__name__}: {e}"


@connector("openapi", fields=[
    ConnectorField("spec_url", "OpenAPI/Swagger URL",
                   placeholder="https://api.example.com/openapi.json",
                   help="URL of the JSON spec. Read-only — the described operations are never "
                        "called; only the document is analysed."),
    ConnectorField("spec", "Pasted spec (JSON)",
                   help="Paste the JSON spec directly instead of a URL."),
])
def collect(config: dict) -> Collected:
    doc, source, error = _load_doc(config)
    facts = parse_spec(doc)
    spec_url = (config.get("spec_url") or "").strip()

    http_servers = [s for s in facts["servers"]
                    if s.get("scheme") == "http" and (s.get("host") or "") not in _LOCAL_HOSTS]
    unauth_ops = [o for o in facts["operations"] if not o["is_authenticated"]]
    deprecated_ops = [o for o in facts["operations"] if o["deprecated"]]

    api_ext = f"rest-api-{spec_url or facts.get('title') or 'pasted'}"
    api_raw = {
        "source": source, "spec_url": spec_url or None, "load_error": error,
        "valid": facts["valid"], "spec_kind": facts["spec_kind"],
        "spec_version": facts["spec_version"], "title": facts["title"],
        "servers": facts["servers"], "http_servers": http_servers,
        "security_schemes": facts["security_schemes"],
        "security_scheme_count": len(facts["security_schemes"]),
        "apikey_query_schemes": facts["apikey_query_schemes"],
        "has_global_security": facts["has_global_security"],
        "global_security_names": facts["global_security_names"],
        "operation_count": len(facts["operations"]),
        "unauthenticated_operation_count": len(unauth_ops),
        "deprecated_operation_count": len(deprecated_ops),
        "cors": facts["cors"], "rate_limit": facts["rate_limit"],
    }
    resources = [Resource(
        kind="rest_api", name=facts.get("title") or spec_url or "REST API",
        ext_id=api_ext,
        labels={"spec_kind": facts["spec_kind"] or "?",
                "operations": str(len(facts["operations"])),
                "global_security": "true" if facts["has_global_security"] else "false"},
        raw=api_raw,
    )]
    edges = []
    for o in facts["operations"]:
        route_ext = f"rest-route-{api_ext}#{o['method']} {o['path']}"
        resources.append(Resource(
            kind="rest_route", name=f"{o['method']} {o['path']}", ext_id=route_ext,
            labels={"method": o["method"], "authenticated": "true" if o["is_authenticated"] else "false",
                    "deprecated": "true" if o["deprecated"] else "false"},
            raw={**o, "api_ext_id": api_ext, "spec_kind": facts["spec_kind"],
                 "security_scheme_defs": {n: facts["security_schemes"].get(n)
                                          for n in o["security_scheme_names"]}},
        ))
        edges.append(Edge(api_ext, route_ext, "exposes"))
    return Collected(resources=resources, edges=edges)
