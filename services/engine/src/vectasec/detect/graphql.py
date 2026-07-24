"""GraphQL rulepack — detectors over what connect/graphql.py read from a GraphQL endpoint.

Every observation states a value read off the wire (introspection returned a schema, the endpoint
answered a batched array, an error carried a field suggestion) — nothing here concludes. Remote
error strings are attacker-controlled, so anything quoted from the server passes through `_cap`.

Not-assessable is a first-class outcome: when a probe could not run (endpoint unreachable, error),
the dependent rule records a coverage gap, never a clean pass.
"""
from ..registry import detector
from ..contracts import Hit


def _cap(s, n=120):
    """Quote a remote, attacker-controlled string for evidence: repr (control chars show) with a
    length cap so a hostile server cannot pad an observation into the immutable ledger."""
    s = str(s)
    return repr(s[:n] + "…") if len(s) > n else repr(s)


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.INTROSPECTION.ENABLED", severity="medium",
          title="GraphQL introspection is enabled")
def introspection_enabled(r, ctx) -> list:
    raw = r.raw or {}
    intro = raw.get("introspection") or {}
    if raw.get("introspection_error") and intro.get("enabled") is False and intro.get("type_count") is None:
        return [Hit(
            observation=f"GraphQL introspection request to {raw.get('url')} did not return a "
                        f"parseable schema (error: {_cap(raw.get('introspection_error'))})",
            remediation="Re-run once the endpoint is reachable; introspection state could not be "
                        "determined from this response.",
            detail=f"status={raw.get('introspection_status')}",
            assessable=False,
            assessment_reason="introspection response was unreachable/unparseable",
            source_ref={"api": f"POST {raw.get('url')}"},
        )]
    if not intro.get("enabled"):
        return []
    return [Hit(
        observation=f"GraphQL introspection is enabled: __schema returned {intro.get('type_count')} "
                    f"types (query root {intro.get('query_type')!r})",
        remediation="Disable introspection in production (e.g. ApolloServer introspection:false, "
                    "graphql-ruby disable_introspection_entry_points, or a validation rule). An open "
                    "schema hands an attacker the full map of types, fields, and mutations.",
        detail=f"type_count={intro.get('type_count')} query_fields={intro.get('query_field_count')}",
        source_ref={"api": f"POST {raw.get('url')}", "field": "__schema"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.INTROSPECTION.UNAUTHENTICATED", severity="high",
          title="GraphQL introspection is served without authentication")
def introspection_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    unauth = raw.get("unauth_introspection") or {}
    if not unauth.get("enabled"):
        return []
    return [Hit(
        observation=f"an UNAUTHENTICATED introspection query to {raw.get('url')} returned the full "
                    f"schema ({unauth.get('type_count')} types) — no credential was sent",
        remediation="Require authentication before the GraphQL layer answers introspection, and "
                    "disable introspection in production regardless. Unauthenticated schema access "
                    "is a free reconnaissance map of every query and mutation.",
        detail=f"unauth_status={raw.get('unauth_status')} type_count={unauth.get('type_count')}",
        source_ref={"api": f"POST {raw.get('url')} (no auth header)", "field": "__schema"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.SCHEMA.FIELD_SUGGESTIONS", severity="medium",
          title="GraphQL field suggestions leak schema names")
def field_suggestions(r, ctx) -> list:
    raw = r.raw or {}
    sg = raw.get("field_suggestions") or {}
    if not sg.get("probed"):
        return []
    if sg.get("enabled") is None:
        return [Hit(
            observation=f"field-suggestion probe to {raw.get('url')} did not return a usable error "
                        f"body (error: {_cap(sg.get('error'))})",
            remediation="Re-run when the endpoint is reachable to determine whether 'Did you mean' "
                        "suggestions are enabled.",
            detail="field-suggestion probe inconclusive",
            assessable=False,
            assessment_reason="suggestion probe response was unreachable/unparseable",
            source_ref={"api": f"POST {raw.get('url')}"},
        )]
    if not sg.get("enabled"):
        return []
    return [Hit(
        observation=f"GraphQL endpoint returned a field suggestion for an unknown field: "
                    f"{_cap(sg.get('sample'))}",
        remediation="Disable 'did you mean' field suggestions in production (Apollo "
                    "GRAPHQL_INTROSPECTION off does not cover this — use a validation rule or "
                    "NoSuggestions plugin). Suggestions reconstruct the schema even with "
                    "introspection disabled.",
        detail="field suggestion present in error message",
        source_ref={"api": f"POST {raw.get('url')}", "signal": "Did you mean"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.AUTHZ.UNAUTH_MUTATION_SURFACE", severity="high",
          title="GraphQL mutations are discoverable without authentication")
def unauth_mutation_surface(r, ctx) -> list:
    raw = r.raw or {}
    unauth = raw.get("unauth_introspection") or {}
    if not unauth.get("enabled"):
        return []
    mut = unauth.get("mutation_type")
    count = unauth.get("mutation_field_count")
    if not mut or not count:
        return []
    return [Hit(
        observation=f"an unauthenticated introspection of {raw.get('url')} exposed a mutation root "
                    f"{mut!r} with {count} mutation field(s)",
        remediation="Enforce authentication/authorization at the GraphQL layer (per-resolver or a "
                    "global auth directive) and hide the schema from unauthenticated callers. A "
                    "mutation surface reachable without auth is a state-changing attack surface.",
        detail=f"mutation_type={mut} mutation_field_count={count}",
        source_ref={"api": f"POST {raw.get('url')} (no auth header)", "field": "mutationType"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.DOS.BATCHING_ENABLED", severity="medium",
          title="GraphQL query batching is enabled")
def batching_enabled(r, ctx) -> list:
    raw = r.raw or {}
    b = raw.get("batching") or {}
    if not b.get("probed"):
        return []
    if b.get("enabled") is None:
        return [Hit(
            observation=f"array-batching probe to {raw.get('url')} was inconclusive "
                        f"(error: {_cap(b.get('error'))})",
            remediation="Re-run when the endpoint is reachable to determine whether array batching "
                        "is honoured.",
            detail="batching probe inconclusive",
            assessable=False,
            assessment_reason="batching probe response was unreachable/unparseable",
            source_ref={"api": f"POST {raw.get('url')}"},
        )]
    if not b.get("enabled"):
        return []
    return [Hit(
        observation=f"GraphQL endpoint honoured an array of {b.get('count_echoed')} batched "
                    f"operations in one request",
        remediation="Disable array-based query batching, or cap batch size and apply per-operation "
                    "cost limits. Batching multiplies a single request into many, amplifying "
                    "brute-force and resource-exhaustion attacks.",
        detail=f"count_echoed={b.get('count_echoed')}",
        source_ref={"api": f"POST {raw.get('url')} (JSON array body)"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.DOS.NO_DEPTH_LIMIT", severity="medium",
          title="GraphQL accepted a deeply nested query without a depth limit")
def no_depth_limit(r, ctx) -> list:
    raw = r.raw or {}
    d = raw.get("depth_probe") or {}
    intro = raw.get("introspection") or {}
    if not d.get("probed"):
        return []
    # The depth probe rides on __schema; if introspection is off the probe is meaningless.
    if d.get("accepted") is None or not intro.get("enabled"):
        reason = ("introspection is disabled, so the __schema-based depth probe could not run"
                  if not intro.get("enabled") else "depth probe response was unreachable/unparseable")
        return [Hit(
            observation=f"GraphQL query-depth limit at {raw.get('url')} was not determined "
                        f"({reason})",
            remediation="Confirm a depth/complexity limit is enforced (graphql-depth-limit, "
                        "graphql-cost-analysis, or the server's built-in maxDepth).",
            detail=f"accepted={d.get('accepted')} introspection={intro.get('enabled')}",
            assessable=False,
            assessment_reason=reason,
            source_ref={"api": f"POST {raw.get('url')}"},
        )]
    if not d.get("accepted"):
        return []   # server rejected the deep query — a limit is enforced
    return [Hit(
        observation=f"GraphQL endpoint accepted a 7-level self-referential query without a "
                    f"depth/complexity rejection",
        remediation="Enforce a query-depth and cost/complexity limit (graphql-depth-limit, "
                    "graphql-cost-analysis, Apollo maxDepth). Without one, a nested recursive query "
                    "can exhaust CPU and memory.",
        detail="deep nested query accepted",
        source_ref={"api": f"POST {raw.get('url')} (nested __schema query)"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.DOS.NO_PERSISTED_QUERIES", severity="low",
          title="GraphQL has no persisted-query allowlist")
def no_persisted_queries(r, ctx) -> list:
    raw = r.raw or {}
    pq = raw.get("persisted_queries") or {}
    intro = raw.get("introspection") or {}
    if not pq.get("probed"):
        return []
    if pq.get("signal") == "unknown" and pq.get("error"):
        return [Hit(
            observation=f"persisted-query (APQ) probe to {raw.get('url')} was inconclusive "
                        f"(error: {_cap(pq.get('error'))})",
            remediation="Confirm whether a persisted-query allowlist is enforced.",
            detail="APQ probe inconclusive",
            assessable=False,
            assessment_reason="APQ probe response was unreachable/unparseable",
            source_ref={"api": f"POST {raw.get('url')}"},
        )]
    # Arbitrary ad-hoc queries were accepted this scan (introspection/typename ran), and APQ is not
    # the same as an enforced allowlist — but 'not_supported' + arbitrary queries is the clear case.
    if pq.get("signal") != "not_supported":
        return []
    if not intro.get("enabled"):
        return []   # we only assert "arbitrary queries accepted" when we saw one run
    return [Hit(
        observation=f"GraphQL endpoint answered 'PersistedQueryNotSupported' and served an arbitrary "
                    f"ad-hoc introspection query — no persisted-query allowlist is enforced",
        remediation="Adopt persisted queries / a trusted-document allowlist (Apollo APQ with "
                    "allowlisting, or relay persisted queries) so only pre-registered operations "
                    "run. An open query interface is the widest possible attack surface.",
        detail="apq_signal=not_supported, arbitrary query accepted",
        source_ref={"api": f"POST {raw.get('url')}", "signal": "PersistedQueryNotSupported"},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.TRANSPORT.GET_QUERIES", severity="medium",
          title="GraphQL queries are served over HTTP GET")
def get_queries(r, ctx) -> list:
    raw = r.raw or {}
    g = raw.get("get_method") or {}
    if not g.get("probed"):
        return []
    if g.get("enabled") is None:
        return [Hit(
            observation=f"GET-query probe to {raw.get('url')} was inconclusive "
                        f"(error: {_cap(g.get('error'))})",
            remediation="Confirm whether the endpoint serves queries over GET.",
            detail=f"status={g.get('status')}",
            assessable=False,
            assessment_reason="GET probe response was unreachable/unparseable",
            source_ref={"api": f"GET {raw.get('url')}"},
        )]
    if not g.get("enabled"):
        return []
    return [Hit(
        observation=f"GraphQL endpoint answered a query sent via HTTP GET (status "
                    f"{g.get('status')}), placing query text in the URL",
        remediation="Restrict queries to POST (allow GET only for whitelisted persisted queries). "
                    "Queries in URLs land in access logs, proxy caches, and Referer headers, and "
                    "GET makes the endpoint reachable by simple CSRF.",
        detail=f"get_status={g.get('status')}",
        source_ref={"api": f"GET {raw.get('url')}?query=..."},
    )]


@detector(kinds=["graphql_endpoint"], rule_id="GRAPHQL.TLS.PLAINTEXT", severity="medium",
          title="GraphQL endpoint is served over plaintext HTTP")
def tls_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    if (raw.get("scheme") or "").lower() != "http":
        return []
    if (raw.get("ip_class") or "") == "loopback":
        return []   # a loopback dev endpoint over http is not a network exposure
    return [Hit(
        observation=f"GraphQL endpoint {raw.get('url')} is served over plaintext http:// "
                    f"(host resolves to a {raw.get('ip_class')} address)",
        remediation="Serve GraphQL over HTTPS only and redirect http to https. Over plaintext, "
                    "every query, variable, and auth token crosses the network in the clear.",
        detail=f"scheme=http ip_class={raw.get('ip_class')}",
        source_ref={"endpoint": raw.get("url")},
    )]
