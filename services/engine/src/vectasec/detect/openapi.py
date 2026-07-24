"""REST/OpenAPI rulepack — detectors over the spec facts connect/openapi.py extracted.

Rules run on the DISTINCT `rest_api` (whole description) and `rest_route` (per operation) kinds.
Every observation cites a value read from the spec — which operation, which scheme, which server
URL. Things the spec cannot tell us (is rate limiting enforced at a gateway? is CORS actually
permissive at runtime?) are recorded as coverage gaps, never as clean passes.
"""
from ..registry import detector
from ..contracts import Hit

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def _spec_unusable(raw) -> Hit | None:
    """A rest_api whose document never loaded/parsed cannot be assessed — return the coverage gap."""
    if not raw.get("valid"):
        return Hit(
            observation=f"OpenAPI/Swagger document ({raw.get('source')}) did not parse as a valid "
                        f"spec (error: {raw.get('load_error')})",
            remediation="Provide a reachable JSON OpenAPI 3.x or Swagger 2.0 document and re-run.",
            detail=f"spec_kind={raw.get('spec_kind')} load_error={raw.get('load_error')}",
            assessable=False,
            assessment_reason="spec document was unreachable or not a recognizable OpenAPI/Swagger doc",
            source_ref={"source": raw.get("source")},
        )
    return None


@detector(kinds=["rest_route"], rule_id="OPENAPI.AUTH.UNAUTHENTICATED_OPERATION", severity="high",
          title="REST operation requires no authentication")
def unauthenticated_operation(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("is_authenticated"):
        return []
    how = ("op-level `security: []` explicitly disables auth" if raw.get("explicitly_public")
           else "no operation-level or global `security` applies")
    return [Hit(
        observation=f"REST operation {raw.get('method')} {raw.get('path')} has no security "
                    f"requirement ({how})",
        remediation="Attach a security requirement to this operation, or set a global `security` "
                    "default that it inherits. An operation with no scheme is callable by anyone "
                    "who can reach the API.",
        detail=f"explicitly_public={raw.get('explicitly_public')} op_level_security={raw.get('op_level_security')}",
        source_ref={"path": raw.get("path"), "method": raw.get("method"), "field": "security"},
    )]


@detector(kinds=["rest_api"], rule_id="OPENAPI.AUTH.NO_GLOBAL_SECURITY", severity="medium",
          title="REST spec defines no global security requirement")
def no_global_security(r, ctx) -> list:
    raw = r.raw or {}
    gap = _spec_unusable(raw)
    if gap:
        return [gap]
    if raw.get("has_global_security"):
        return []
    return [Hit(
        observation=f"OpenAPI spec {raw.get('title')!r} declares no top-level `security`, so every "
                    f"operation is unauthenticated unless it opts in individually "
                    f"({raw.get('unauthenticated_operation_count')} of {raw.get('operation_count')} "
                    f"operation(s) currently have none)",
        remediation="Declare a global `security` requirement and let operations override it where "
                    "they must differ. A missing global default makes 'public' the accidental "
                    "fallback for any operation someone forgets to annotate.",
        detail=f"operation_count={raw.get('operation_count')} unauthenticated={raw.get('unauthenticated_operation_count')}",
        source_ref={"field": "security", "spec": raw.get("spec_version")},
    )]


@detector(kinds=["rest_api"], rule_id="OPENAPI.AUTH.APIKEY_IN_QUERY", severity="high",
          title="REST API key is passed in the URL query string")
def apikey_in_query(r, ctx) -> list:
    raw = r.raw or {}
    gap = _spec_unusable(raw)
    if gap:
        return [gap]
    schemes = raw.get("apikey_query_schemes") or []
    if not schemes:
        return []
    return [Hit(
        observation=f"OpenAPI spec defines apiKey security scheme(s) with `in: query`: "
                    f"{', '.join(schemes)}",
        remediation="Move the API key to a header (`in: header`) or Authorization scheme. Keys in "
                    "the query string are written to access logs, proxy caches, browser history, "
                    "and Referer headers.",
        detail=f"apikey_query_schemes={schemes}",
        source_ref={"field": "securitySchemes", "in": "query"},
    )]


@detector(kinds=["rest_api"], rule_id="OPENAPI.TRANSPORT.HTTP_SERVER", severity="medium",
          title="REST spec advertises a plaintext HTTP server")
def http_server(r, ctx) -> list:
    raw = r.raw or {}
    gap = _spec_unusable(raw)
    if gap:
        return [gap]
    http_servers = raw.get("http_servers") or []
    if not http_servers:
        return []
    urls = [s.get("url") for s in http_servers]
    return [Hit(
        observation=f"OpenAPI spec advertises {len(http_servers)} server URL(s) over plaintext "
                    f"http://: {', '.join(u for u in urls if u)}",
        remediation="Serve the API over HTTPS only and list only https:// servers in the spec. A "
                    "documented http endpoint invites clients to send credentials in the clear.",
        detail=f"http_servers={urls}",
        source_ref={"field": "servers"},
    )]


@detector(kinds=["rest_route"], rule_id="OPENAPI.OPS.DEPRECATED_LIVE", severity="low",
          title="REST operation is deprecated but still described as live")
def deprecated_live(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("deprecated"):
        return []
    return [Hit(
        observation=f"REST operation {raw.get('method')} {raw.get('path')} is marked "
                    f"`deprecated: true` yet remains in the served spec",
        remediation="Track deprecated-but-live operations to a removal date and confirm they still "
                    "enforce current authentication/validation. Deprecated endpoints are a classic "
                    "source of unmaintained, under-secured surface.",
        detail=f"deprecated=True authenticated={raw.get('is_authenticated')}",
        source_ref={"path": raw.get("path"), "method": raw.get("method"), "field": "deprecated"},
    )]


@detector(kinds=["rest_api"], rule_id="OPENAPI.DOS.NO_RATE_LIMIT_DOCUMENTED", severity="low",
          title="REST spec documents no rate limiting")
def no_rate_limit(r, ctx) -> list:
    raw = r.raw or {}
    gap = _spec_unusable(raw)
    if gap:
        return [gap]
    if (raw.get("rate_limit") or {}).get("documented"):
        return []
    return [Hit(
        observation=f"OpenAPI spec {raw.get('title')!r} documents no rate limiting (no "
                    f"X-RateLimit headers, 429 responses, or throttle extension)",
        remediation="Document and enforce rate limits (429 + Retry-After, or a gateway throttle). "
                    "Whether a gateway enforces limits cannot be seen from the spec, so confirm "
                    "enforcement independently.",
        detail="rate_limit.documented=False",
        assessable=False,
        assessment_reason="rate-limit enforcement lives at a gateway the spec does not describe",
        source_ref={"spec": raw.get("spec_version")},
    )]


@detector(kinds=["rest_api"], rule_id="OPENAPI.CORS.PERMISSIVE", severity="medium",
          title="REST spec documents a wildcard CORS policy")
def cors_permissive(r, ctx) -> list:
    raw = r.raw or {}
    gap = _spec_unusable(raw)
    if gap:
        return [gap]
    cors = raw.get("cors") or {}
    if not cors.get("documented"):
        return [Hit(
            observation=f"OpenAPI spec {raw.get('title')!r} documents no CORS policy, so its "
                        f"cross-origin exposure could not be assessed from the spec",
            remediation="Document the CORS policy (allowed origins) and confirm it is not a "
                        "wildcard at runtime — CORS is enforced by the server/gateway, not the spec.",
            detail="cors.documented=False",
            assessable=False,
            assessment_reason="CORS is not a standard OpenAPI field; none was documented in this spec",
            source_ref={"field": "x-amazon-apigateway-cors / Access-Control-Allow-Origin"},
        )]
    if not cors.get("permissive"):
        return []
    return [Hit(
        observation=f"OpenAPI spec documents a wildcard CORS origin (Access-Control-Allow-Origin: "
                    f"* or allowOrigins: *)",
        remediation="Restrict allowed origins to the specific trusted sites. A wildcard origin lets "
                    "any website's script call the API with the browser's ambient credentials.",
        detail="cors.permissive=True",
        source_ref={"field": "CORS allowOrigins"},
    )]


@detector(kinds=["rest_api"], rule_id="OPENAPI.SPEC.NO_SECURITY_SCHEMES", severity="medium",
          title="REST spec defines no security schemes at all")
def no_security_schemes(r, ctx) -> list:
    raw = r.raw or {}
    gap = _spec_unusable(raw)
    if gap:
        return [gap]
    if raw.get("security_scheme_count"):
        return []
    return [Hit(
        observation=f"OpenAPI spec {raw.get('title')!r} defines zero security schemes "
                    f"(components.securitySchemes / securityDefinitions is empty) across "
                    f"{raw.get('operation_count')} operation(s)",
        remediation="Define at least one security scheme (OAuth2, bearer, or apiKey-in-header) and "
                    "reference it from `security`. With no schemes declared, the API describes no "
                    "way to authenticate any caller.",
        detail=f"security_scheme_count=0 operation_count={raw.get('operation_count')}",
        source_ref={"field": "securitySchemes"},
    )]
