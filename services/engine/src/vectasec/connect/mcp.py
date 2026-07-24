"""MCP connector — read-only introspection of a Streamable HTTP MCP server.

Speaks BOTH protocol generations. It first tries the 2026-07-28 stateless discovery RPC
`server/discover`; if the server does not answer it (older revisions), it falls back to the
`initialize` handshake used by <= 2025-11-25. Which generation the server actually speaks is
recorded on the resource (`spec_generation`, `discovery_method`) as both raw and a label — the
product covers both, so scanning older servers must never break.

Collects only discovery + `tools/list` (both read-only RPCs) and unauthenticated OAuth-discovery
GETs. `tools/call` is never issued: invoking a tool is a side effect on a customer system, and
`readOnlyHint` is self-asserted ("clients MUST consider tool annotations to be untrusted"), so it
can never license one.

`initialize` allocates server-side session state on spec 2025-11-25, so every legacy session
opened here is closed with an HTTP DELETE. The 2026-07-28 stateless path mints no `Mcp-Session-Id`
and owes no DELETE: protocol version and client identity ride in `_meta`, and load-balancer
routing headers `Mcp-Method`/`Mcp-Name` accompany each POST. Probes beyond the read-only baseline
— an intentionally invalid protocol version, a forged Origin, N sessions for the session-entropy
rules, a TLS downgrade handshake — only run when config["active_probes"] is set.

config: url (required), token, active_probes, source_zone, timeout,
        public_allowlist (read by detectors via ScanContext.config).
"""
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected

MCP_SPEC_CURRENT = "2026-07-28"      # the pinned revision we prefer: the stateless server/discover
                                     # generation. Offered first; a server that speaks it wins.
MCP_SPEC_LEGACY_FALLBACK = "2025-11-25"   # what we offer on the initialize handshake fallback
SPEC_VERSION = MCP_SPEC_LEGACY_FALLBACK   # back-compat alias for the legacy handshake path; the
                                          # negotiated protocolVersion from the server always wins
CLIENT_INFO = {"name": "vectasec-scanner", "version": "0.1.0"}
ACCEPT = "application/json, text/event-stream"   # a MUST for clients on POST; a JSON-only
                                                 # Accept silently misses SSE-mode servers
SESSION_SAMPLES = 10                 # 8-12 per the session rules; 32 buys nothing and leaks sessions
MAX_PAGES = 50                       # a server looping on nextCursor must not hang the scan

# 2026-07-28 _meta keys (SEP-2575): protocol version and client identity travel per-request.
_META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
_META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
_META_CLIENT_CAPS = "io.modelcontextprotocol/clientCapabilities"
_META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"
_TRACE_KEYS = ("traceparent", "tracestate", "baggage")   # W3C/OTel propagation in _meta (SEP-414)
# A fixed, obviously-synthetic W3C traceparent, sent so a server that propagates trace context
# echoes something we can recognise. Sampled flag 00 (do-not-record) keeps it inert.
_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"

_WWW_PARAM_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*"([^"]*)"')


# ── wire ──────────────────────────────────────────────────────────────────
def _headers(token, version, *, sid=None, origin=None, method=None, name=None) -> dict:
    h = {"Content-Type": "application/json", "Accept": ACCEPT, "MCP-Protocol-Version": version}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if sid:
        h["MCP-Session-Id"] = sid            # servers requiring a session answer 400 without it
    if origin:
        h["Origin"] = origin
    if method:
        h["Mcp-Method"] = method             # 2026-07-28 routing header (SEP-2243): lets gateways
    if name:                                 # route on the operation without reading the body
        h["Mcp-Name"] = name
    return h


def _parse_rpc(r: httpx.Response):
    """Servers MAY answer application/json OR text/event-stream. FastMCP — the most common
    implementation — returns SSE even for initialize, so a .json()-only client fails 100%."""
    if "text/event-stream" in r.headers.get("content-type", ""):
        for line in r.text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except ValueError:
                    return None
        return None
    try:
        return json.loads(r.text)
    except ValueError:
        return None


def _parse_www_authenticate(value):
    if not value:
        return None
    return {"raw": value, "scheme": value.split(" ", 1)[0],
            "params": dict(_WWW_PARAM_RE.findall(value))}


def _initialize(client, url, token, *, version=SPEC_VERSION, origin=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
               "params": {"protocolVersion": SPEC_VERSION, "capabilities": {},
                          "clientInfo": CLIENT_INFO}}
    r = client.post(url, json=payload, headers=_headers(token, version, origin=origin))
    return r, _parse_rpc(r), r.headers.get("mcp-session-id")


def _discover(client, url, token, *, version=MCP_SPEC_CURRENT, origin=None):
    """2026-07-28 stateless discovery (SEP-2575): the `server/discover` RPC. Protocol version and
    client identity ride in `_meta`; no session is minted, so no DELETE is owed. A sacrificial
    traceparent is sent so a trace-propagating server echoes something recognisable."""
    meta = {_META_PROTOCOL_VERSION: version, _META_CLIENT_INFO: CLIENT_INFO,
            _META_CLIENT_CAPS: {}, "traceparent": _TRACEPARENT}
    payload = {"jsonrpc": "2.0", "id": 1, "method": "server/discover",
               "params": {"_meta": meta}}
    r = client.post(url, json=payload,
                    headers=_headers(token, version, origin=origin, method="server/discover"))
    return r, _parse_rpc(r)


def _extract_discovery(result: dict) -> dict:
    """Normalise a server/discover result. The RC schema places identity either at the top level
    or in result `_meta`; we read both and keep whatever is present without trusting its shape."""
    meta = result.get("_meta")
    meta = meta if isinstance(meta, dict) else {}
    si = result.get("serverInfo")
    if not isinstance(si, dict):
        si = meta.get(_META_SERVER_INFO) if isinstance(meta.get(_META_SERVER_INFO), dict) else None
    pv = result.get("protocolVersion") or meta.get(_META_PROTOCOL_VERSION)
    versions = result.get("protocolVersions")
    if not pv and isinstance(versions, list):
        dates = [v for v in versions if isinstance(v, str)]
        pv = max(dates) if dates else None      # advertise-list form: the highest revision offered
    caps = result.get("capabilities")
    instr = result.get("instructions")
    return {"server_info": si, "protocol_version": pv,
            "protocol_versions": versions if isinstance(versions, list) else None,
            "capabilities": caps if isinstance(caps, dict) else None,
            "instructions": instr if isinstance(instr, str) else None,
            "trace_echoed": any(k in meta for k in _TRACE_KEYS)}


def _delete_session(client, url, token, sid, version) -> None:
    if not sid:
        return
    try:
        client.request("DELETE", url, headers=_headers(token, version, sid=sid))
    except Exception:
        pass   # cleanup is best-effort — the server MAY legitimately answer 405


def _list_tools(client, url, token, version, sid=None, *, stateless=False):
    tools, cursor, pages = [], None, 0
    while pages < MAX_PAGES:
        params = {"cursor": cursor} if cursor else {}
        if stateless:       # 2026-07-28: version rides in _meta, routing header names the method
            params["_meta"] = {_META_PROTOCOL_VERSION: version}
        headers = _headers(token, version, sid=sid,
                           method="tools/list" if stateless else None)
        r = client.post(url, json={"jsonrpc": "2.0", "id": 2 + pages, "method": "tools/list",
                                   "params": params}, headers=headers)
        res = (_parse_rpc(r) or {}).get("result")
        if not isinstance(res, dict):
            return tools, pages, False
        tools.extend(t for t in res.get("tools", []) if isinstance(t, dict))
        pages += 1
        cursor = res.get("nextCursor")
        if not cursor:
            return tools, pages, True     # drained — hashing a partial list flaps on page shifts
    return tools, pages, False


def _introspect(client, url, token) -> dict:
    """One read-only discovery pass across BOTH generations: try the 2026-07-28 stateless
    `server/discover` first; on no result fall back to the legacy `initialize` handshake
    (-> notifications/initialized -> tools/list -> DELETE). Records which generation answered."""
    out = {"status": None, "error": None, "www_authenticate": None, "session_id": None,
           "has_result": False, "protocol_version": None, "server_info": None,
           "capabilities": None, "instructions": None, "rpc_error": None,
           "tools": [], "pages": 0, "cursor_drained": False, "authenticated": bool(token),
           "spec_generation": "unknown", "discovery_method": None,
           "protocol_versions": None, "trace_echoed": False}

    # ── 2026-07-28 stateless: server/discover (no session, no DELETE) ──
    try:
        r, body = _discover(client, url, token)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out
    out["status"] = r.status_code
    out["www_authenticate"] = _parse_www_authenticate(r.headers.get("www-authenticate"))
    disc_err = (body or {}).get("error")
    disc_result = (body or {}).get("result")

    if isinstance(disc_result, dict):
        out["discovery_method"] = "server/discover"
        out["spec_generation"] = "stateless"
        info = _extract_discovery(disc_result)
        out.update(has_result=True, protocol_version=info["protocol_version"],
                   server_info=info["server_info"], capabilities=info["capabilities"],
                   instructions=info["instructions"], protocol_versions=info["protocol_versions"],
                   trace_echoed=info["trace_echoed"])
        neg = out["protocol_version"] or MCP_SPEC_CURRENT
        try:
            out["tools"], out["pages"], out["cursor_drained"] = _list_tools(
                client, url, token, neg, sid=None, stateless=True)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
        return out

    # ── fall back to the legacy initialize handshake (<= 2025-11-25) ──
    try:
        r2, body2, sid = _initialize(client, url, token)
    except Exception as e:
        out["rpc_error"] = disc_err     # keep the discover-layer JSON-RPC error as context
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    init_result = (body2 or {}).get("result")
    # Prefer the initialize response's status/header once we commit to the legacy path.
    out["status"] = r2.status_code
    out["www_authenticate"] = (_parse_www_authenticate(r2.headers.get("www-authenticate"))
                               or out["www_authenticate"])
    out["session_id"] = sid
    out["rpc_error"] = (body2 or {}).get("error") or disc_err

    if not isinstance(init_result, dict):
        return out       # neither generation produced a result — status/error recorded above

    out["discovery_method"] = "initialize"
    out["spec_generation"] = "legacy"
    out["rpc_error"] = (body2 or {}).get("error")
    out.update(has_result=True, protocol_version=init_result.get("protocolVersion"),
               server_info=init_result.get("serverInfo"),
               capabilities=init_result.get("capabilities"),
               instructions=init_result.get("instructions"))
    neg = out["protocol_version"] or SPEC_VERSION   # echo what was negotiated, never hardcoded
    try:
        client.post(url, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers=_headers(token, neg, sid=sid))
        out["tools"], out["pages"], out["cursor_drained"] = _list_tools(
            client, url, token, neg, sid=sid)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    finally:
        _delete_session(client, url, token, sid, neg)
    return out


# ── network vantage ───────────────────────────────────────────────────────
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


def _tls_probe(host, port, timeout, active: bool) -> dict:
    """Records what a modern client negotiates plus certificate validity. `floor` stays UNTESTED
    unless active: a client offering modern defaults negotiates the best mutual version and can
    never observe that TLS 1.0/1.1 remain enabled — that needs a deliberate downgrade handshake."""
    out = {"negotiated": None, "cert_status": None, "cert_error": None, "floor": "UNTESTED"}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["negotiated"] = ss.version()
                out["cert_status"] = "valid"
    except ssl.SSLCertVerificationError as e:
        out["cert_status"] = "invalid"
        out["cert_error"] = str(e)
        lax = ssl.create_default_context()
        lax.check_hostname = False
        lax.verify_mode = ssl.CERT_NONE
        try:    # re-handshake unverified only to learn the version; the verdict is already recorded
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with lax.wrap_socket(sock, server_hostname=host) as ss:
                    out["negotiated"] = ss.version()
        except Exception:
            pass
    except Exception as e:
        out["cert_status"] = "unknown"
        out["cert_error"] = f"{type(e).__name__}: {e}"

    if active and out["negotiated"]:
        out["floor"] = _tls_floor(host, port, timeout)
    return out


def _tls_floor(host, port, timeout) -> str:
    """Lowest version the server still accepts. Best-effort — many OpenSSL builds refuse to
    offer TLS 1.0/1.1 at all, in which case the question stays unanswered rather than answered wrong."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception:
        return "UNTESTED"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                return ss.version() or "UNTESTED"
    except ssl.SSLError:
        return "TLSv1.2+"       # the server refused everything below 1.2
    except Exception:
        return "UNTESTED"


# ── OAuth discovery (unauthenticated GETs) ────────────────────────────────
def _get_json(client, url):
    try:
        r = client.get(url, headers={"Accept": "application/json"})
    except Exception as e:
        return {"url": url, "status": None, "error": f"{type(e).__name__}: {e}"}, None
    try:
        doc = r.json() if r.status_code == 200 else None
    except ValueError:
        doc = None
    return {"url": url, "status": r.status_code}, doc if isinstance(doc, dict) else None


def _discover_prm(client, url, www) -> dict:
    """RFC 9728 discovery in spec order. `served_from` is load-bearing: RFC 9728 §3.3 compares
    `resource` against the identifier the well-known suffix was INSERTED INTO — i.e. derived from
    the URL that served the document, NOT the MCP endpoint URL."""
    s = urlsplit(url)
    origin = f"{s.scheme}://{s.netloc}"
    path = s.path.rstrip("/")
    rm = ((www or {}).get("params") or {}).get("resource_metadata")

    candidates = []
    if rm:
        candidates.append(rm)
    if path:
        candidates.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    candidates.append(f"{origin}/.well-known/oauth-protected-resource")

    tried = []
    for c in candidates:
        rec, doc = _get_json(client, c)
        tried.append(rec)
        if doc is not None:
            return {"resource_metadata_param": rm, "served_from": c, "document": doc,
                    "candidates": tried}
    return {"resource_metadata_param": rm, "served_from": None, "document": None,
            "candidates": tried}


def prm_base(served_from: str):
    """The resource identifier implied by the URL that served the PRM (RFC 9728 §3.3)."""
    marker = "/.well-known/oauth-protected-resource"
    s = urlsplit(served_from)
    if marker not in s.path:
        return None
    prefix, _, suffix = s.path.partition(marker)
    return f"{s.scheme}://{s.netloc}{prefix}{suffix}"


def _discover_as(client, issuer: str) -> dict:
    """AS metadata in MCP spec priority order; records which candidate actually resolved,
    because the first candidate 404ing is normal (Entra falls through to the OIDC document)."""
    s = urlsplit(issuer)
    origin = f"{s.scheme}://{s.netloc}"
    path = s.path.rstrip("/")
    if path:
        candidates = [f"{origin}/.well-known/oauth-authorization-server{path}",
                      f"{origin}/.well-known/openid-configuration{path}",
                      f"{issuer.rstrip('/')}/.well-known/openid-configuration"]
    else:
        candidates = [f"{origin}/.well-known/oauth-authorization-server",
                      f"{origin}/.well-known/openid-configuration"]

    tried = []
    for n, c in enumerate(candidates, start=1):
        rec, doc = _get_json(client, c)
        tried.append(rec)
        if doc is not None:
            return {"issuer": issuer, "metadata_url": c, "candidate_n": n, "document": doc,
                    "candidates": tried}
    return {"issuer": issuer, "metadata_url": None, "candidate_n": None, "document": None,
            "candidates": tried}


def _oauth_urls(prm: dict, as_meta: list) -> list:
    """Every URL discovered during introspection, tagged with its role — the plaintext rule fires
    per URL and the role carries the authority (AS endpoints have an HTTPS MUST). Hosts are
    resolved here: a detector must not do network I/O, and the rule's evidence needs the IP."""
    found = []
    doc = prm.get("document") or {}
    for iss in doc.get("authorization_servers") or []:
        if isinstance(iss, str):
            found.append(("PRM authorization_servers entry", iss))
    for m in as_meta:
        d = m.get("document") or {}
        for key in ("issuer", "authorization_endpoint", "token_endpoint",
                    "registration_endpoint", "jwks_uri"):
            v = d.get(key)
            if isinstance(v, str):
                found.append((f"AS metadata {key}", v))

    out, cache = [], {}
    for role, u in found:
        host = urlsplit(u).hostname
        if host and host not in cache:
            cache[host] = _resolve(host)
        ip, cls = cache.get(host, (None, "unresolved"))
        out.append({"role": role, "url": u, "host": host, "resolved_ip": ip, "ip_class": cls})
    return out


# ── legacy transport probe ────────────────────────────────────────────────
def _legacy_sse_probe(client, url, intro, timeout) -> dict:
    """The deprecated 2024-11-05 handshake: GET yields text/event-stream whose first event is
    named `endpoint`, advertising a separate POST message endpoint."""
    out = {"ran": False, "skip_reason": None, "content_type": None, "first_event": None,
           "endpoint_data": None, "modern_endpoint": None, "modern_detected": None}

    if intro.get("status") not in (400, 404, 405):
        # Known false negative: an auth-gated legacy server answers 401 and is never probed.
        out["skip_reason"] = f"initialize returned {intro.get('status')}; GET fallback only runs on 400/404/405"
        return out
    if intro.get("rpc_error"):
        out["skip_reason"] = "modern JSON-RPC error body — not a legacy transport"
        return out

    out["ran"] = True
    try:
        with client.stream("GET", url, headers={"Accept": "text/event-stream"},
                           timeout=httpx.Timeout(timeout, read=5.0)) as r:
            out["content_type"] = r.headers.get("content-type")
            if "text/event-stream" in (out["content_type"] or ""):
                for line in r.iter_lines():
                    if line.startswith("event:"):
                        out["first_event"] = line[6:].strip()
                    elif line.startswith("data:"):
                        out["endpoint_data"] = line[5:].strip()
                        break
                    elif not line and out["first_event"]:
                        break
    except Exception as e:
        out["skip_reason"] = f"{type(e).__name__}: {e}"
        return out

    # Mandatory before concluding: the spec RECOMMENDS dual-hosting legacy /sse beside a modern
    # /mcp, so a single-URL probe alone cannot tell "uses deprecated transport" from
    # "correctly following the blessed migration pattern".
    s = urlsplit(url)
    modern = f"{s.scheme}://{s.netloc}/mcp"
    if modern.rstrip("/") != url.rstrip("/"):
        out["modern_endpoint"] = modern
        try:    # a modern endpoint may speak either generation — try stateless discover first
            _, dbody = _discover(client, modern, None)
            if isinstance((dbody or {}).get("result"), dict):
                out["modern_detected"] = True
            else:
                _, body, sid = _initialize(client, modern, None)
                out["modern_detected"] = isinstance((body or {}).get("result"), dict)
                _delete_session(client, modern, None, sid, SPEC_VERSION)
        except Exception:
            out["modern_detected"] = False
    return out


# ── active probes (consent-gated) ─────────────────────────────────────────
def _probe_handshake(client, url, token, gen, *, version=None, origin=None):
    """One discovery round-trip in whichever generation the server speaks, for the active probes.
    Returns (response, has_result, sid). Stateless servers mint no session, so sid is None."""
    if gen == "stateless":
        r, body = _discover(client, url, token, version=version or MCP_SPEC_CURRENT, origin=origin)
        return r, isinstance((body or {}).get("result"), dict), None
    r, body, sid = _initialize(client, url, token, version=version or SPEC_VERSION, origin=origin)
    return r, isinstance((body or {}).get("result"), dict), sid


def _active_probes(client, url, token, negotiated, gen) -> dict:
    out = {"invalid_version": None, "origin": None, "sessions": None, "session_auth": None}

    # Legacy-transport concern only: an invalid/unsupported MCP-Protocol-Version header MUST get
    # 400. On the 2026-07-28 stateless core the version rides in _meta and a mismatch returns
    # UnsupportedProtocolVersionError instead, so the header probe is not the applicable mechanism.
    if gen != "stateless":
        try:
            r, _, sid = _initialize(client, url, token, version="9999-99-99")
            out["invalid_version"] = {"sent": "9999-99-99", "status": r.status_code}
            _delete_session(client, url, token, sid, negotiated)
        except Exception as e:
            out["invalid_version"] = {"sent": "9999-99-99", "error": f"{type(e).__name__}: {e}"}

    # Otherwise spec-conforming request carrying an attacker Origin — applies to both generations.
    try:
        r, has_result, sid = _probe_handshake(client, url, token, gen,
                                              origin="https://attacker.example")
        out["origin"] = {"sent": "https://attacker.example", "status": r.status_code,
                         "has_result": has_result}
        _delete_session(client, url, token, sid, negotiated)
    except Exception as e:
        out["origin"] = {"sent": "https://attacker.example", "error": f"{type(e).__name__}: {e}"}

    out["sessions"] = _session_samples(client, url, token, negotiated)
    if token:
        out["session_auth"] = _session_auth_probe(client, url, token, negotiated)
    return out


def _session_samples(client, url, token, negotiated) -> dict:
    samples, statuses = [], []
    for _ in range(SESSION_SAMPLES):
        ts = int(time.time())   # the second the id was minted — the derivability test needs it
        try:
            r, _, sid = _initialize(client, url, token)
        except Exception as e:
            statuses.append(type(e).__name__)
            break
        statuses.append(r.status_code)
        if r.status_code == 429:
            break                       # back off rather than hammer the target
        if sid:
            samples.append({"id": sid, "ts": ts})
        _delete_session(client, url, token, sid, negotiated)
    return {"requested": SESSION_SAMPLES, "samples": samples, "statuses": statuses}


def _session_auth_probe(client, url, token, negotiated) -> dict:
    """The negative control is what makes this sound: without it every unauthenticated server
    looks 'session-authenticated'."""
    out = {"session_id": None, "control_status": None, "replay_status": None}
    body = {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}}
    try:
        r, _, sid = _initialize(client, url, token)
        out["session_id"] = sid
        if not sid:
            return out
        c = client.post(url, json=body, headers=_headers(None, negotiated))
        out["control_status"] = c.status_code
        p = client.post(url, json=body, headers=_headers(None, negotiated, sid=sid))
        out["replay_status"] = p.status_code
        _delete_session(client, url, token, sid, negotiated)
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


# ── drift baseline ────────────────────────────────────────────────────────
def _sorted_required(node):
    if isinstance(node, dict):
        return {k: (sorted(v) if k == "required" and isinstance(v, list)
                    and all(isinstance(x, str) for x in v) else _sorted_required(v))
                for k, v in node.items()}
    if isinstance(node, list):
        return [_sorted_required(v) for v in node]
    return node


def _tools_hash(instructions, server_info, tools) -> str:
    """Canonical over the surface a rug pull would mutate. Semantic: tools sorted by name, keys
    sorted, `required` sorted — benign reordering must not move the hash. Recorded so a future
    stateful comparator has a baseline; no detector can fire on it point-in-time."""
    si = server_info or {}
    payload = {
        "instructions": instructions,
        "server": {"name": si.get("name"), "version": si.get("version")},
        "tools": sorted(
            [{k: _sorted_required(t.get(k)) for k in
              ("name", "title", "description", "inputSchema", "outputSchema", "annotations")}
             for t in tools],
            key=lambda t: t.get("name") or "",
        ),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


# ── collect ───────────────────────────────────────────────────────────────
@connector("mcp", fields=[
    ConnectorField("url", "MCP endpoint", required=True,
                   placeholder="https://mcp.example.com/mcp",
                   help="Streamable HTTP endpoint of the MCP server or gateway."),
    ConnectorField("token", "Bearer token", secret=True,
                   help="Only if the server requires auth. Passive checks by default — "
                        "active probes stay off unless enabled in config."),
])
def collect(config: dict) -> Collected:
    url = config["url"].rstrip("/") if config.get("url") else None
    if not url:
        raise SystemExit("mcp connector requires config['url'] (the Streamable HTTP endpoint)")
    token = config.get("token")
    active = bool(config.get("active_probes"))
    timeout = float(config.get("timeout", 10.0))
    source_zone = config.get("source_zone", "unspecified")

    s = urlsplit(url)
    host = s.hostname or ""
    port = s.port or (443 if s.scheme == "https" else 80)
    resolved_ip, ip_class = _resolve(host)

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        # Unauthenticated first — it is both its own posture signal and the mandatory gate for
        # the PRM and session-auth rules.
        unauth = _introspect(client, url, None)
        auth = _introspect(client, url, token) if token else None
        main = auth or unauth

        prm = _discover_prm(client, url, unauth.get("www_authenticate"))
        issuers = [i for i in ((prm.get("document") or {}).get("authorization_servers") or [])
                   if isinstance(i, str)]
        as_meta = [_discover_as(client, i) for i in issuers]
        legacy = _legacy_sse_probe(client, url, unauth, timeout)
        tls = _tls_probe(host, port, timeout, active) if s.scheme == "https" else {
            "negotiated": None, "cert_status": None, "cert_error": None, "floor": "UNTESTED"}
        probes = (_active_probes(client, url, token, main.get("protocol_version") or SPEC_VERSION,
                                 main.get("spec_generation"))
                  if active else None)

    tools = main.get("tools") or []
    server_ext = f"mcp-server-{url}"
    server_raw = {
        "url": url, "host": host, "port": port, "scheme": s.scheme,
        "transport": "streamable_http",
        "resolved_ip": resolved_ip, "ip_class": ip_class, "source_zone": source_zone,
        "client_name": CLIENT_INFO["name"],   # the session-derivability test rehashes it
        "protocol_version": main.get("protocol_version"),
        # Which generation the server actually spoke — the product covers both, and the lifecycle
        # rules key on this. session_id is the top-level protocol session (legacy only).
        "spec_generation": main.get("spec_generation"),
        "discovery_method": main.get("discovery_method"),
        "session_id": main.get("session_id"),
        "protocol_versions": main.get("protocol_versions"),
        "trace_context": {"echoed": bool(main.get("trace_echoed")),
                          "generation": main.get("spec_generation")},
        "server_info": main.get("server_info"), "capabilities": main.get("capabilities"),
        "instructions": main.get("instructions"),
        "authenticated_scan": bool(token), "active_probes": active,
        "unauth_probe": {k: unauth.get(k) for k in
                         ("status", "error", "www_authenticate", "has_result", "rpc_error",
                          "session_id", "protocol_version", "server_info",
                          "discovery_method", "spec_generation")}
                        | {"tool_count": len(unauth.get("tools") or [])},
        "auth_probe": ({k: auth.get(k) for k in ("status", "error", "has_result", "rpc_error")}
                       | {"tool_count": len(auth.get("tools") or [])}) if auth else None,
        "prm": prm, "prm_base": prm_base(prm["served_from"]) if prm.get("served_from") else None,
        "as_metadata": as_meta, "oauth_urls": _oauth_urls(prm, as_meta),
        "tls": tls, "legacy_sse": legacy, "probes": probes,
        "tool_count": len(tools), "tools_pages": main.get("pages"),
        "tools_cursor_drained": main.get("cursor_drained"),
        "tools_hash": _tools_hash(main.get("instructions"), main.get("server_info"), tools),
        "error": main.get("error"),
    }

    si = main.get("server_info") or {}
    resources = [Resource(
        kind="mcp_server",
        name=si.get("name") or host or url,
        ext_id=server_ext,
        namespace=host,
        labels={"scheme": s.scheme, "ip_class": ip_class,
                "protocol_version": main.get("protocol_version") or "",
                "server_version": si.get("version") or "",
                "spec_generation": main.get("spec_generation") or "",
                "discovery_method": main.get("discovery_method") or ""},
        raw=server_raw,
    )]
    edges = []
    for t in tools:
        name = t.get("name")
        if not isinstance(name, str):
            continue        # a nameless tool cannot be given a stable ext_id; skip, never guess
        tool_ext = f"mcp-tool-{url}#{name}"
        resources.append(Resource(
            kind="mcp_tool",
            name=name,
            ext_id=tool_ext,
            namespace=host,
            labels={"server": server_ext},
            # `tool` is the raw JSON-RPC object as it arrived — never sanitized, never NFKC'd:
            # normalizing here would delete the very codepoints the smuggling rules look for.
            raw={"tool": t, "endpoint": url, "server_ext_id": server_ext,
                 "protocol_version": main.get("protocol_version"),
                 "server_name": si.get("name")},
        ))
        edges.append(Edge(server_ext, tool_ext, "exposes"))

    return Collected(resources=resources, edges=edges)
