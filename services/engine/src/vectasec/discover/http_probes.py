"""HTTP-surface fingerprints: admin APIs, health endpoints and API descriptors.

Same discipline as `probes.py` — unauthenticated GETs to endpoints that exist to be read, one
per service, no credentials, no writes, no redirect-following out of scope. Several of these
endpoints are *supposed* to be public (Vault's `sys/health`, Elasticsearch's `/`); what makes
them interesting to a posture product is not that they answered but WHAT they answered with,
and which of them should never have been reachable at all (a Kong Admin API on a routable
address is an estate-wide compromise waiting to happen).

The API-descriptor sweep (`probe_api_descriptor`) is the shadow-API half of discovery: an
OpenAPI document, a GraphQL introspection response or an MCP endpoint on an unmanaged host is
an integration surface nobody put in the inventory.
"""
from __future__ import annotations

import json

from .probes import ProbeResult

DEFAULT_TIMEOUT = 3.0
MAX_BODY = 65536


def _get(url: str, timeout: float, headers: dict | None = None):
    """One unauthenticated GET. Returns (status, body_text, headers, tls_error) or None.

    Certificate verification is off by design (we are identifying what is listening, and a bad
    certificate is a finding to record rather than a reason to go blind) — but whether
    verification WOULD have failed is captured and returned, because "serving TLS with an
    untrusted certificate" is exactly the sort of thing this product exists to say out loud.
    """
    import httpx

    tls_error = None
    if url.startswith("https://"):
        try:
            with httpx.Client(timeout=timeout, verify=True, follow_redirects=False) as c:
                c.get(url, headers=headers)
        except Exception as e:                       # noqa: BLE001 - any verify failure counts
            name = type(e).__name__
            if "SSL" in name or "Certificate" in name or "ssl" in str(e).lower():
                tls_error = f"{name}: {str(e)[:120]}"
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=False) as c:
            r = c.get(url, headers=headers)
            return r.status_code, r.text[:MAX_BODY], dict(r.headers), tls_error
    except Exception:                                # noqa: BLE001 - unreachable is not an error
        return None


def _json(body: str):
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def _scheme_attempts(port: int) -> tuple[str, ...]:
    """Which schemes to try, cheapest-first. TLS-only ports skip the plaintext attempt."""
    if port in (8883, 9243, 443):
        return ("https",)
    return ("http", "https")


# ── Elasticsearch / OpenSearch ─────────────────────────────────────────────
def probe_elasticsearch(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    for scheme in _scheme_attempts(port):
        res = _get(f"{scheme}://{host}:{port}/", timeout)
        if not res:
            continue
        status, body, _headers, tls_error = res
        if status in (401, 403):
            if "security_exception" in body or "missing authentication" in body.lower():
                return ProbeResult(
                    product="elasticsearch", version=None,
                    transport="tls" if scheme == "https" else "plaintext",
                    evidence=[f"Elasticsearch/OpenSearch at {scheme}://{host}:{port}/ answered "
                              f"HTTP {status} demanding authentication (no credential was sent)"],
                    signals={"auth_required": True, "tls_cert_error": tls_error},
                    raw={"status": status},
                )
            continue
        doc = _json(body)
        if not isinstance(doc, dict) or "version" not in doc:
            continue
        version = (doc.get("version") or {}).get("number")
        distro = (doc.get("version") or {}).get("distribution") or "elasticsearch"
        ev = [f"{distro} answered an unauthenticated GET / with version.number {version!r} "
              f"and cluster_name {doc.get('cluster_name')!r}"]
        if tls_error:
            ev.append(f"the TLS certificate does not validate ({tls_error})")
        return ProbeResult(
            product="opensearch" if distro == "opensearch" else "elasticsearch",
            version=version,
            transport="tls" if scheme == "https" else "plaintext",
            evidence=ev,
            signals={"auth_required": False, "tls_cert_error": tls_error,
                     "cluster_name": doc.get("cluster_name")},
            raw={"version": doc.get("version"), "cluster_name": doc.get("cluster_name")},
        )
    return None


# ── HashiCorp Vault ────────────────────────────────────────────────────────
def probe_vault(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    for scheme in _scheme_attempts(port):
        res = _get(f"{scheme}://{host}:{port}/v1/sys/health", timeout)
        if not res:
            continue
        _status, body, _headers, tls_error = res
        doc = _json(body)
        if not isinstance(doc, dict) or "sealed" not in doc:
            continue
        version = doc.get("version")
        ev = [f"Vault answered the unauthenticated sys/health endpoint with version {version!r}, "
              f"sealed={doc.get('sealed')}, initialized={doc.get('initialized')}"]
        if scheme == "http":
            ev.append("sys/health was served over plaintext HTTP")
        if tls_error:
            ev.append(f"the TLS certificate does not validate ({tls_error})")
        return ProbeResult(
            product="vault", version=version,
            transport="tls" if scheme == "https" else "plaintext",
            evidence=ev,
            signals={"sealed": doc.get("sealed"), "initialized": doc.get("initialized"),
                     "tls_cert_error": tls_error},
            raw={k: doc.get(k) for k in ("version", "sealed", "initialized", "standby",
                                         "cluster_name")},
        )
    return None


# ── Kong Admin API ─────────────────────────────────────────────────────────
def probe_kong_admin(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    """A reachable Kong Admin API is the crown jewel: it can rewrite every route and plugin in
    the gateway. Finding one answering unauthenticated is not a fingerprint, it is an incident."""
    for scheme in _scheme_attempts(port):
        res = _get(f"{scheme}://{host}:{port}/", timeout)
        if not res:
            continue
        status, body, _headers, tls_error = res
        doc = _json(body)
        if not isinstance(doc, dict):
            continue
        if "configuration" not in doc and "plugins" not in doc and "version" not in doc:
            continue
        # The Admin API root returns both; the proxy port does not.
        if "configuration" not in doc and "plugins" not in doc:
            continue
        version = doc.get("version")
        ev = [f"the Kong Admin API answered an unauthenticated GET / with version {version!r} "
              "and a full `configuration` object"]
        if status == 200:
            ev.append("no credential was sent and none was demanded: the Admin API is open to "
                      "anyone who can reach this port")
        return ProbeResult(
            product="kong", version=version,
            transport="tls" if scheme == "https" else "plaintext",
            evidence=ev,
            signals={"admin_api_open": status == 200, "auth_required": status in (401, 403),
                     "tls_cert_error": tls_error},
            raw={"version": version, "lua_version": doc.get("lua_version"),
                 "node_id": doc.get("node_id")},
        )
    return None


# ── etcd ───────────────────────────────────────────────────────────────────
def probe_etcd(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    for scheme in _scheme_attempts(port):
        res = _get(f"{scheme}://{host}:{port}/version", timeout)
        if not res:
            continue
        _status, body, _headers, tls_error = res
        doc = _json(body)
        if not isinstance(doc, dict) or "etcdserver" not in doc:
            continue
        version = doc.get("etcdserver")
        return ProbeResult(
            product="etcd", version=version,
            transport="tls" if scheme == "https" else "plaintext",
            evidence=[f"etcd answered an unauthenticated GET /version with etcdserver "
                      f"{version!r} (cluster {doc.get('etcdcluster')!r})"],
            signals={"auth_required": False, "tls_cert_error": tls_error},
            raw=doc,
        )
    return None


# ── Consul ─────────────────────────────────────────────────────────────────
def probe_consul(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    """`/v1/agent/self` names the version when ACLs allow it; `/v1/catalog/datacenters` needs
    no ACL token at all, so a hardened cluster is still identified rather than missed."""
    for scheme in _scheme_attempts(port):
        res = _get(f"{scheme}://{host}:{port}/v1/agent/self", timeout)
        if not res:
            # Even with the agent API locked down, the datacenters endpoint is readable
            # without a token — enough to say "Consul is here", which is the discovery job.
            dcs = _get(f"{scheme}://{host}:{port}/v1/catalog/datacenters", timeout)
            if dcs and dcs[0] == 200 and _json(dcs[1]) is not None:
                return ProbeResult(
                    product="consul", version=None,
                    transport="tls" if scheme == "https" else "plaintext",
                    evidence=["Consul answered /v1/catalog/datacenters without an ACL token "
                              "(this endpoint requires no token by design)"],
                    signals={"auth_required": True, "tls_cert_error": dcs[3]},
                    raw={"datacenters": _json(dcs[1])},
                )
            continue
        status, body, _headers, tls_error = res
        if status in (401, 403) and "ACL" in body:
            return ProbeResult(
                product="consul", version=None,
                transport="tls" if scheme == "https" else "plaintext",
                evidence=[f"Consul answered /v1/agent/self with HTTP {status} and an ACL "
                          "message: the agent API requires a token"],
                signals={"auth_required": True, "tls_cert_error": tls_error},
                raw={"status": status},
            )
        doc = _json(body)
        if not isinstance(doc, dict) or "Config" not in doc:
            continue
        version = (doc.get("Config") or {}).get("Version")
        return ProbeResult(
            product="consul", version=version,
            transport="tls" if scheme == "https" else "plaintext",
            evidence=[f"Consul answered an unauthenticated GET /v1/agent/self with its full "
                      f"agent configuration, version {version!r} — no ACL token was sent"],
            signals={"auth_required": False, "tls_cert_error": tls_error,
                     "datacenter": (doc.get("Config") or {}).get("Datacenter")},
            raw={"version": version,
                 "datacenter": (doc.get("Config") or {}).get("Datacenter")},
        )
    return None


# ── RabbitMQ management plugin ─────────────────────────────────────────────
def probe_rabbitmq_mgmt(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    for scheme in _scheme_attempts(port):
        res = _get(f"{scheme}://{host}:{port}/api/overview", timeout)
        if not res:
            continue
        status, body, headers, tls_error = res
        auth_header = headers.get("www-authenticate", "")
        doc = _json(body)
        if status == 401 and "rabbit" in auth_header.lower():
            ev = [f"the RabbitMQ management API answered /api/overview with HTTP 401 and "
                  f"WWW-Authenticate {auth_header!r} (no credential was sent)"]
            if scheme == "http":
                ev.append("the management API is served over plaintext HTTP")
            return ProbeResult(
                product="rabbitmq", version=None,
                transport="tls" if scheme == "https" else "plaintext",
                evidence=ev,
                signals={"auth_required": True, "management_api": True,
                         "tls_cert_error": tls_error},
                raw={"www_authenticate": auth_header},
            )
        if isinstance(doc, dict) and "rabbitmq_version" in doc:
            return ProbeResult(
                product="rabbitmq", version=doc.get("rabbitmq_version"),
                transport="tls" if scheme == "https" else "plaintext",
                evidence=[f"the RabbitMQ management API served /api/overview WITHOUT "
                          f"authentication, reporting rabbitmq_version "
                          f"{doc.get('rabbitmq_version')!r} and cluster "
                          f"{doc.get('cluster_name')!r}"],
                signals={"auth_required": False, "management_api": True,
                         "tls_cert_error": tls_error},
                raw={"rabbitmq_version": doc.get("rabbitmq_version"),
                     "cluster_name": doc.get("cluster_name")},
            )
    return None


# ── API descriptors: the shadow-API sweep ──────────────────────────────────
_DESCRIPTOR_PATHS = (
    ("/openapi.json", "openapi"),
    ("/swagger.json", "openapi"),
    ("/v3/api-docs", "openapi"),
    ("/.well-known/openapi.json", "openapi"),
    ("/graphql", "graphql"),
    ("/mcp", "mcp"),
    ("/.well-known/oauth-protected-resource", "mcp"),
)


def probe_api_descriptor(host: str, port: int, timeout: float = DEFAULT_TIMEOUT):
    """Look for a self-describing API surface. An OpenAPI document or an MCP endpoint on a host
    nobody registered is a shadow integration — the thing this capability exists to surface.

    GraphQL is detected by its error shape on a plain GET, never by POSTing an introspection
    query: introspection is a write-shaped request to some servers, and we do not send those.
    """
    for scheme in _scheme_attempts(port):
        base = f"{scheme}://{host}:{port}"
        root = _get(f"{base}/", timeout)
        if root is None:
            continue                       # nothing is speaking HTTP here at all
        _status, _body, headers, tls_error = root
        server = headers.get("server")

        for path, kind in _DESCRIPTOR_PATHS:
            res = _get(f"{base}{path}", timeout)
            if not res:
                continue
            status, body, _h, _t = res
            if status >= 400 and kind != "graphql":
                continue
            doc = _json(body)

            if kind == "openapi" and isinstance(doc, dict) and (doc.get("openapi") or doc.get("swagger")):
                paths = doc.get("paths") or {}
                title = ((doc.get("info") or {}).get("title") or "").strip()
                has_auth = bool(doc.get("security") or (doc.get("components") or {}).get("securitySchemes"))
                ev = [f"an OpenAPI document is served unauthenticated at {path}: "
                      f"title {title!r}, {len(paths)} paths declared"]
                if not has_auth:
                    ev.append("the document declares no `security` requirement and no "
                              "`securitySchemes` component")
                return ProbeResult(
                    product="openapi", version=str(doc.get("openapi") or doc.get("swagger")),
                    transport="tls" if scheme == "https" else "plaintext",
                    evidence=ev,
                    signals={"descriptor": "openapi", "path_count": len(paths),
                             "declares_security": has_auth, "tls_cert_error": tls_error,
                             "server_header": server},
                    raw={"title": title, "paths": sorted(paths)[:50], "server": server},
                )

            if kind == "graphql" and isinstance(doc, dict) and "errors" in doc:
                return ProbeResult(
                    product="graphql", version=None,
                    transport="tls" if scheme == "https" else "plaintext",
                    evidence=[f"a GraphQL endpoint at {path} answered a plain GET with a "
                              "GraphQL error document (no query was sent)"],
                    signals={"descriptor": "graphql", "tls_cert_error": tls_error,
                             "server_header": server},
                    raw={"server": server},
                )

            if kind == "mcp" and status < 400 and body.strip():
                if "jsonrpc" in body or "mcp" in body.lower() or "resource" in body.lower():
                    return ProbeResult(
                        product="mcp", version=None,
                        transport="tls" if scheme == "https" else "plaintext",
                        evidence=[f"an MCP-shaped endpoint answered GET {path} with HTTP "
                                  f"{status} — this is an AI tool surface, not a plain API"],
                        signals={"descriptor": "mcp", "tls_cert_error": tls_error,
                                 "server_header": server},
                        raw={"path": path, "server": server},
                    )
    return None
