"""GraphQL connector — read-only introspection + a small set of consent-free posture probes.

GraphQL sits on the integration layer as the query/data plane in front of many services, so its
posture (schema disclosure, unauthenticated reach, DoS amplification) belongs in this tool. This
connector POSTs the standard introspection query over httpx and runs a handful of tiny, read-only
probes; it never issues a mutation (that would be a side effect on a customer system) and it never
stores schema prose — only counts and the small, capped error strings the rules cite.

Everything the server returns is SEMI-TRUSTED remote text (a hostile endpoint controls its own
error messages), so the connector stores raw error samples verbatim but the detectors quote them
through a length cap (same discipline as connect/mcp.py's `_cap`).

The parse layer `parse_introspection(doc)` is pure: an introspection JSON body in, normalized
schema facts out. Tests feed golden JSON to it directly, so httpx stays out of the test suite and
a shape drift between the wire and the rulepack fails a test rather than mis-firing in production.

Emits the DISTINCT kind `graphql_endpoint` so no other rulepack ever runs against it by accident.

config: url (required), auth_header_value (secret), auth_header_name, timeout, source_zone.
"""
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit, urlencode

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Collected

# Trimmed introspection query: the rules read type kinds, root types, and field COUNTS — never
# descriptions or deprecation prose, so we don't request them (smaller response, nothing to store).
INTROSPECTION_QUERY = (
    "query VectasecIntrospection { __schema { "
    "queryType { name } mutationType { name } subscriptionType { name } "
    "types { kind name fields { name } } } }"
)

# A deliberately deep, self-referential introspection query used only to observe whether the server
# imposes a query-depth/complexity limit. Uses fields that exist on every GraphQL server.
_DEPTH_PROBE_QUERY = (
    "{ __schema { types { fields { type { ofType { ofType { ofType { ofType "
    "{ name } } } } } } } } }"
)
# Misspelling of __typename (which exists on every type). A server with field suggestions answers
# with `Did you mean "__typename"?`; one without suggestions just says the field is unknown.
_SUGGESTION_PROBE_QUERY = "{ __typenam }"
# 64 hex zeros — an APQ hash that will never match a stored query. The server's answer discloses
# whether Automatic Persisted Queries are supported at all.
_APQ_FAKE_HASH = "0" * 64


# ── pure parse layer (tests feed golden JSON here) ─────────────────────────
def _first_error_message(errors):
    if isinstance(errors, list):
        for e in errors:
            if isinstance(e, dict) and e.get("message"):
                return str(e["message"])
            if isinstance(e, str):
                return e
    return None


def parse_introspection(doc) -> dict:
    """Normalize an introspection response body ({"data": {"__schema": {...}}} or {"errors": [...]}).
    Pure: no network, no exceptions raised on malformed input."""
    out = {"enabled": False, "query_type": None, "mutation_type": None,
           "subscription_type": None, "type_count": None, "query_field_count": None,
           "mutation_field_count": None, "error_message": None}
    if not isinstance(doc, dict):
        return out
    if doc.get("errors"):
        out["error_message"] = _first_error_message(doc["errors"])
    data = doc.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return out
    out["enabled"] = True
    qt = (schema.get("queryType") or {}).get("name") if isinstance(schema.get("queryType"), dict) else None
    mt = (schema.get("mutationType") or {}).get("name") if isinstance(schema.get("mutationType"), dict) else None
    st = (schema.get("subscriptionType") or {}).get("name") if isinstance(schema.get("subscriptionType"), dict) else None
    out["query_type"], out["mutation_type"], out["subscription_type"] = qt, mt, st
    types = schema.get("types") if isinstance(schema.get("types"), list) else []
    out["type_count"] = len(types)
    by_name = {t.get("name"): t for t in types if isinstance(t, dict)}

    def _fieldcount(name):
        fs = (by_name.get(name) or {}).get("fields")
        return len(fs) if isinstance(fs, list) else None

    out["query_field_count"] = _fieldcount(qt) if qt else None
    out["mutation_field_count"] = _fieldcount(mt) if mt else None
    return out


def field_suggestions_present(body) -> bool:
    """True when an error body carries a GraphQL field-suggestion ('Did you mean ...')."""
    msg = _first_error_message((body or {}).get("errors") if isinstance(body, dict) else None) or ""
    return "did you mean" in msg.lower()


def apq_signal(body):
    """Classify an APQ probe response: 'not_supported' | 'supported' | 'unknown'."""
    msg = (_first_error_message((body or {}).get("errors") if isinstance(body, dict) else None) or "").lower()
    if "persistedquerynotsupported" in msg.replace(" ", ""):
        return "not_supported"
    if "persistedquerynotfound" in msg.replace(" ", ""):
        return "supported"
    return "unknown"


# ── network vantage ────────────────────────────────────────────────────────
def _ip_class(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if a.is_loopback:
        return "loopback"
    if a.is_private or a.is_link_local:
        return "private"
    return "public"


def _resolve(host):
    try:
        ip = socket.gethostbyname(host)
    except OSError:
        return None, "unresolved"
    return ip, _ip_class(ip)


def _tls_probe(host, port, timeout) -> dict:
    """Passive: what a modern client negotiates + cert validity. No downgrade handshake."""
    out = {"negotiated": None, "cert_status": None, "cert_error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["negotiated"] = ss.version()
                out["cert_status"] = "valid"
    except ssl.SSLCertVerificationError as e:
        out["cert_status"] = "invalid"
        out["cert_error"] = str(e)
    except Exception as e:
        out["cert_status"] = "unknown"
        out["cert_error"] = f"{type(e).__name__}: {e}"
    return out


# ── read-only wire probes ──────────────────────────────────────────────────
def _post_graphql(client, url, headers, payload):
    """POST a GraphQL body. Returns (status, json_or_none, error_or_none)."""
    try:
        r = client.post(url, json=payload, headers=headers)
    except Exception as e:
        return None, None, f"{type(e).__name__}: {e}"
    try:
        return r.status_code, r.json(), None
    except ValueError:
        return r.status_code, None, "non-json response"


def _probe_batching(client, url, headers):
    """POST a 2-element array. A server that honours batching answers a 2-element array."""
    out = {"probed": True, "enabled": None, "count_echoed": None, "error": None}
    body = [{"query": "{__typename}"}, {"query": "{__typename}"}]
    try:
        r = client.post(url, json=body, headers=headers)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out
    try:
        doc = r.json()
    except ValueError:
        out["enabled"] = False
        return out
    if isinstance(doc, list):
        out["enabled"] = len(doc) == 2
        out["count_echoed"] = len(doc)
    else:
        out["enabled"] = False
    return out


def _probe_depth(client, url, headers):
    """POST a deep self-referential introspection query. Accepted → no depth/complexity limit was
    observed at this depth; a depth/complexity error → a limit is enforced. Only meaningful when
    introspection is reachable (the probe rides on __schema)."""
    out = {"probed": True, "accepted": None, "error_message": None, "error": None}
    status, doc, err = _post_graphql(client, url, headers, {"query": _DEPTH_PROBE_QUERY})
    if err:
        out["error"] = err
        return out
    errs = (doc or {}).get("errors") if isinstance(doc, dict) else None
    if errs:
        out["accepted"] = False
        out["error_message"] = _first_error_message(errs)
    elif isinstance(doc, dict) and isinstance(doc.get("data"), dict):
        out["accepted"] = True
    return out


def _probe_get(client, url):
    """GET ?query={__typename}. A 200 with data proves queries are served over GET (CSRF + cache
    leakage surface). Sent unauthenticated on purpose — GET-over-auth is not the concern here."""
    out = {"probed": True, "enabled": None, "status": None, "error": None}
    q = urlencode({"query": "{__typename}"})
    try:
        r = client.get(f"{url}?{q}", headers={"Accept": "application/json"})
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out
    out["status"] = r.status_code
    try:
        doc = r.json()
    except ValueError:
        out["enabled"] = False
        return out
    out["enabled"] = bool(isinstance(doc, dict) and isinstance(doc.get("data"), dict)
                          and doc["data"].get("__typename"))
    return out


def _probe_apq(client, url, headers):
    out = {"probed": True, "signal": "unknown", "error": None}
    payload = {"extensions": {"persistedQuery": {"version": 1, "sha256Hash": _APQ_FAKE_HASH}}}
    status, doc, err = _post_graphql(client, url, headers, payload)
    if err:
        out["error"] = err
        return out
    out["signal"] = apq_signal(doc)
    return out


def _headers(auth_name, auth_value):
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if auth_value:
        h[auth_name or "Authorization"] = auth_value
    return h


# ── collect ────────────────────────────────────────────────────────────────
@connector("graphql", fields=[
    ConnectorField("url", "GraphQL endpoint", required=True,
                   placeholder="https://api.example.com/graphql",
                   help="The HTTP endpoint that answers POST introspection queries. Read-only — "
                        "no mutations are ever sent."),
    ConnectorField("auth_header_value", "Auth header value", secret=True,
                   help="Only if the endpoint requires auth, e.g. 'Bearer eyJ...'. Passive checks "
                        "run with and without it to measure unauthenticated reach."),
    ConnectorField("auth_header_name", "Auth header name", placeholder="Authorization",
                   help="Header the auth value is sent in (default Authorization)."),
])
def collect(config: dict) -> Collected:
    url = (config.get("url") or "").strip().rstrip("/")
    if not url:
        raise SystemExit("graphql connector requires config['url']")
    auth_name = config.get("auth_header_name") or "Authorization"
    auth_value = config.get("auth_header_value") or None
    timeout = float(config.get("timeout") or 10.0)
    source_zone = config.get("source_zone", "unspecified")

    s = urlsplit(url)
    host = s.hostname or ""
    port = s.port or (443 if s.scheme == "https" else 80)
    resolved_ip, ip_class = _resolve(host)

    auth_headers = _headers(auth_name, auth_value)
    unauth_headers = _headers(None, None)

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Main introspection uses auth if supplied; the unauth pass is always run — it is both a
        # posture signal and the gate for the "reachable without auth" rules.
        m_status, m_body, m_err = _post_graphql(
            client, url, auth_headers, {"query": INTROSPECTION_QUERY})
        u_status, u_body, u_err = _post_graphql(
            client, url, unauth_headers, {"query": INTROSPECTION_QUERY})

        main_intro = parse_introspection(m_body if auth_value else u_body)
        unauth_intro = parse_introspection(u_body)

        headers_for_probes = auth_headers
        # field-suggestion probe (works even when introspection is disabled — it rides on an error)
        sg_status, sg_body, sg_err = _post_graphql(
            client, url, headers_for_probes, {"query": _SUGGESTION_PROBE_QUERY})
        suggestions = {"probed": True, "enabled": None,
                       "sample": _first_error_message(sg_body.get("errors")) if isinstance(sg_body, dict) else None,
                       "error": sg_err}
        if sg_err is None and isinstance(sg_body, dict):
            suggestions["enabled"] = field_suggestions_present(sg_body)

        batching = _probe_batching(client, url, headers_for_probes)
        depth = _probe_depth(client, url, headers_for_probes)
        get_method = _probe_get(client, url)
        apq = _probe_apq(client, url, headers_for_probes)
        tls = (_tls_probe(host, port, timeout) if s.scheme == "https"
               else {"negotiated": None, "cert_status": None, "cert_error": None})

    raw = {
        "url": url, "host": host, "port": port, "scheme": s.scheme,
        "resolved_ip": resolved_ip, "ip_class": ip_class, "source_zone": source_zone,
        "authenticated_scan": bool(auth_value),
        "introspection": main_intro,
        "introspection_status": (m_status if auth_value else u_status),
        "introspection_error": (m_err if auth_value else u_err),
        # Whether introspection came back WITHOUT any credential — the sharper disclosure.
        "unauth_introspection": unauth_intro,
        "unauth_status": u_status,
        "field_suggestions": suggestions,
        "batching": batching,
        "depth_probe": depth,
        "get_method": get_method,
        "persisted_queries": apq,
        "tls": tls,
    }

    intro = raw["introspection"]
    resource = Resource(
        kind="graphql_endpoint",
        name=host or url,
        ext_id=f"graphql-{url}",
        namespace=host,
        labels={"scheme": s.scheme, "ip_class": ip_class,
                "introspection": "on" if intro.get("enabled") else "off",
                "authenticated_scan": "true" if auth_value else "false"},
        raw=raw,
    )
    return Collected(resources=[resource], edges=[])
