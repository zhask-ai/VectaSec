"""MCP rulepack — detectors over what connect/mcp.py read from a Streamable HTTP MCP server.

Two standing constraints from the rulepack that shape almost every rule here:

  • Authorization is OPTIONAL in MCP. Rules keyed on "no auth" are deployment-posture findings,
    never spec violations — evidence must never word them as "non-compliant".
  • Status accept-lists, never single-status matching. A server that rejects at the JSON-RPC
    layer answers HTTP 200 with an {"error":...} body; a correctly hardened one answers 421.
    Matching on one status flags the best-configured servers.

Every observation states a value read off the wire. Nothing here concludes.
"""
import hashlib
import ipaddress
import json
import re
from collections import Counter
from urllib.parse import urlsplit

from ..registry import detector
from ..contracts import Hit

_ABSENT = object()
SESSION_SUNSET = "2026-07-28"   # this revision removes MCP-Session-Id and the initialize handshake


# ── injection patterns ────────────────────────────────────────────────────
# Only the two CONFIRMED classes. The rulepack's signal classes (secret-bearing paths, exfil
# verb+sink, cross-tool references, length) detect vocabulary rather than malice and belong to
# the AI layer — reporting them here as CONFIRMED would make the rule net-noise.
_CLASS_A = re.compile(r"<\s*/?\s*(?:important|system|secret|instructions|admin)\s*>|<!--.*?-->",
                      re.I | re.S)
_CLASS_B_NARROW = re.compile(
    r"ignore\s+(?:all\s+)?previous\s+instructions"
    r"|do\s+not\s+(?:tell|mention|inform|reveal)\s+the\s+user"
    r"|without\s+(?:telling|informing)\s+the\s+user"
    r"|the\s+user\s+(?:will\s+not|cannot)\s+see",
    re.I,
)


def _injection_hits(text: str) -> list:
    """Offsets are into the RAW field: the patterns absorb whitespace with \\s+ rather than the
    scanner normalising the string first, because an offset computed over a normalised string is
    not reproducible against the field an analyst inspects."""
    out = []
    for cls, rx in (("a (pseudo-tag instruction block)", _CLASS_A),
                    ("b-narrow (concealment/override imperative)", _CLASS_B_NARROW)):
        for m in rx.finditer(text):
            out.append({"class": cls, "offset": m.start(), "excerpt": m.group(0)[:160]})
    return out


# ── codepoint scans ───────────────────────────────────────────────────────
def _tier1_hits(text: str) -> list:
    out = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if 0xE0000 <= cp <= 0xE007F:
            cls = "unicode-tags (ASCII smuggling range, deprecated since Unicode 5.1)"
        elif 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            cls = "bidi override/isolate"
        elif cp == 0x1B:
            cls = "ANSI/ESC control"
        elif cp in (0x200B, 0x2060, 0xFEFF) and i > 0:
            cls = "zero-width mid-string"     # a LEADING U+FEFF is a legitimate BOM
        else:
            continue
        out.append({"class": cls, "codepoint": f"U+{cp:04X}", "offset": i})
    return out


def _is_variation_selector(cp: int) -> bool:
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _tier2_hits(text: str) -> list:
    """Classes with documented legitimate uses: ZWJ in every emoji sequence, ZWNJ in required
    Persian orthography, PUA for Nerd Font glyphs. Presence is reportable at low; it is not
    evidence of smuggling."""
    out = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if cp == 0x200D:
            cls = "ZWJ (legitimate in emoji ZWJ sequences)"
        elif cp == 0x200C:
            cls = "ZWNJ (required Persian/Devanagari orthography)"
        elif 0xE000 <= cp <= 0xF8FF:
            cls = "private use area"
        else:
            continue
        out.append({"class": cls, "codepoint": f"U+{cp:04X}", "offset": i})

    run, start = 0, 0                    # variation selectors: flag only anomalous run length,
    for i, ch in enumerate(text + " "):  # never mere presence — U+FE0F is REQUIRED for ⚠️ ℹ️ ❗
        if _is_variation_selector(ord(ch)):
            start = i if run == 0 else start
            run += 1
            continue
        if run > 2:
            out.append({"class": f"variation-selector run of {run}", "codepoint": f"U+{ord(text[start]):04X}",
                        "offset": start})
        run = 0
    return out


# ── string walkers ────────────────────────────────────────────────────────
def _walk_all(node, path):
    """Every string in a JSON subtree, including dict KEYS — a property name is a live poisoning
    vector (CyberArk's PoC exfiltrated via a param renamed `content_from_reading_ssh_id_rsa`
    behind a clean description)."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}.{k} (key)", k
            yield from _walk_all(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_all(v, f"{path}[{i}]")


def _meta_strings(tool: dict):
    """Model- and approval-UI-facing metadata. Excludes the schemas: MCP.TOOL.SCHEMA_POISONING
    owns those, so one payload is not reported twice under two rule ids."""
    for f in ("description", "title"):
        if isinstance(tool.get(f), str):
            yield f, tool[f]
    ann = tool.get("annotations")
    if isinstance(ann, dict) and isinstance(ann.get("title"), str):
        yield "annotations.title", ann["title"]
    for f in ("_meta", "icons"):
        if tool.get(f) is not None:
            yield from _walk_all(tool[f], f)


def _schema_strings(schema, path):
    """(json_path, kind, value) for every model-visible string in a schema. Recursion through the
    default branch resolves allOf/anyOf/oneOf/items composition without a $ref resolver."""
    if isinstance(schema, dict):
        for k, v in schema.items():
            p = f"{path}.{k}"
            if k in ("properties", "patternProperties", "$defs", "definitions") and isinstance(v, dict):
                for key, sub in v.items():
                    yield f"{p}.{key}", "property key", key
                    yield from _schema_strings(sub, f"{p}.{key}")
            elif k == "required" and isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, str):
                        yield f"{p}[{i}]", "required entry", item
            elif k in ("description", "title", "pattern", "const", "default") and isinstance(v, str):
                yield p, k, v
            elif k in ("enum", "examples") and isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, str):
                        yield f"{p}[{i}]", k, item
            else:
                yield from _schema_strings(v, p)
    elif isinstance(schema, list):
        for i, v in enumerate(schema):
            yield from _schema_strings(v, f"{path}[{i}]")


def _canonical_len(node) -> int:
    try:
        return len(json.dumps(node, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    except (TypeError, ValueError):
        return -1


def _tool_ctx(resource):
    t = resource.raw.get("tool") or {}
    return (t, t.get("name"), resource.raw.get("endpoint"),
            resource.raw.get("protocol_version") or "unknown")


# ── shared network helpers ────────────────────────────────────────────────
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "::ffff:127.0.0.1"}


def _is_loopback_host(host) -> bool:
    h = (host or "").strip("[]").lower()
    if h in _LOOPBACK_HOSTS:
        return True
    try:
        a = ipaddress.ip_address(h)
    except ValueError:
        return False
    # ipaddress does NOT report the IPv4-mapped loopback ::ffff:127.0.0.1 as loopback.
    m = getattr(a, "ipv4_mapped", None)
    return a.is_loopback or bool(m and m.is_loopback)


def _tls_terminated_upstream(host, ip_class) -> bool:
    """RFC1918 / docker-network targets: TLS may be terminated at an ingress or mesh sidecar the
    scanner cannot see from the URL alone."""
    h = (host or "").lower()
    return ip_class == "private" or h == "host.docker.internal" or ("." not in h and h != "")


def _safe_split(u):
    """PRM and AS metadata are served BY THE TARGET: `resource`, `issuer` and every OAuth endpoint
    are strings a hostile — or merely broken — server chooses. urlsplit raises ValueError on some
    of them (an unclosed IPv6 bracket is enough), and scan.py swallows a detector exception into
    `detector_errors`, so a raise here is the rule silently switching itself off. Returns None
    instead; callers decide what an unparseable value means for their rule."""
    try:
        return urlsplit(u or "")
    except ValueError:
        return None


def _loose_eq(a: str, b: str) -> bool:
    """Spec: implementations SHOULD accept uppercase scheme and host for robustness."""
    sa, sb = _safe_split(a), _safe_split(b)
    if sa is None or sb is None:
        return False    # an unparseable identifier is not a case/trailing-slash delta
    def norm(s):
        return (s.scheme.lower(), s.netloc.lower(), s.path.rstrip("/"), s.query, s.fragment)
    return norm(sa) == norm(sb)


_SPEC_REVISION = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _sessions_removed(protocol_version) -> bool:
    """True only for a protocolVersion that PARSES as a spec revision date at or after the sunset.

    protocolVersion is whatever the target put in its InitializeResult — connect/mcp.py stores
    `result.get("protocolVersion")` verbatim and nothing validates its shape. A bare lexicographic
    `>= "2026-07-28"` therefore lets any string sorting above it ("v1", "draft", "latest",
    "unknown", "9") switch off all three MCP.SESSION rules, including the `high` auth-bypass rule
    MCP.SESSION.USED_FOR_AUTHENTICATION — a server suppresses its own findings with one string,
    and nothing is reported as not-assessable. A version we cannot parse is UNKNOWN, and the
    session rules read what is actually on the wire (whether MCP-Session-Id is present and
    whether it is accepted as a credential), which is the right signal whatever revision the
    server claims. So an unparseable version runs the rules rather than skipping them; each rule
    still self-gates on observed evidence, so a genuinely stateless server stays clean.

    Lexicographic compare is correct ONCE the shape is pinned: zero-padded ISO dates sort
    chronologically.
    """
    v = str(protocol_version or "").strip()
    return bool(_SPEC_REVISION.match(v)) and v >= SESSION_SUNSET


# ══════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════
@detector(kinds=["mcp_server"], rule_id="MCP.AUTH.UNAUTHENTICATED_ENDPOINT", severity="high",
          title="MCP server answers unauthenticated tool discovery")
def unauthenticated_endpoint(resource, ctx) -> list:
    raw = resource.raw
    probe = raw.get("unauth_probe") or {}
    if probe.get("status") != 200 or not probe.get("has_result"):
        return []
    url = raw.get("url")
    # No intent signal exists in the protocol: a public docs server and an open server exposing
    # delete_repo produce byte-identical evidence. Only an operator allowlist separates them.
    if url in (ctx.config.get("public_allowlist") or []):
        return []

    si = probe.get("server_info") or {}
    return [Hit(
        observation=(
            f"Unauthenticated POST initialize to {url} returned HTTP 200 with an InitializeResult "
            f"(serverInfo.name={si.get('name')!r}, protocolVersion={probe.get('protocol_version')!r}); "
            f"unauthenticated tools/list returned {probe.get('tool_count')} tool definitions. "
            f"No 401 challenge issued. Probed from {raw.get('source_zone')} to resolved IP "
            f"{raw.get('resolved_ip')} ({raw.get('ip_class')}); this establishes reachability from "
            f"that vantage point only."
        ),
        remediation=(
            "Per the transports spec Security Warning, servers SHOULD implement proper "
            "authentication for all connections, and when running locally SHOULD bind only to "
            "localhost (127.0.0.1) rather than all network interfaces. For a local server the "
            "spec's preferred hardening is the stdio transport, or if HTTP is required, require "
            "an authorization token, or use unix domain sockets or other Interprocess "
            "Communication (IPC) mechanisms with restricted access. If auth is adopted, "
            "authorization MUST be included in every HTTP request even within one logical "
            "session, and unauthenticated requests should receive 401 with "
            'WWW-Authenticate: Bearer resource_metadata="...". If this endpoint is intentionally '
            "public, add its URL to the connection's public_allowlist to suppress this rule."
        ),
        detail=(
            "Tier: unauthenticated tool DISCOVERY. This does not establish unauthenticated "
            "execution — auth at the tool-call layer with open discovery is spec-legal and "
            "actively requested by implementers. Confirmed unauthenticated execution is a "
            "separate auth-bypass finding requiring operator confirmation. The probe also cannot "
            "see the bind address, firewall, security group, or mesh policy: an authenticating "
            "gateway, mTLS, VPN or IP allowlist in front of this server is invisible from inside "
            "the trust boundary."
        ),
        source_ref={"api": f"POST {url} (JSON-RPC initialize, no Authorization header)"},
    )]


@detector(kinds=["mcp_server"], rule_id="MCP.AUTH.PRM_MISSING_OR_MISMATCHED", severity="medium",
          title="OAuth Protected Resource Metadata is missing or inconsistent")
def prm_missing_or_mismatched(resource, ctx) -> list:
    raw = resource.raw
    probe = raw.get("unauth_probe") or {}
    # Fire only when the server CLAIMS to be an OAuth protected resource. Authorization is
    # OPTIONAL in MCP — a server answering 2xx unauthenticated owes no PRM at all.
    if probe.get("status") not in (401, 403):
        return []

    prm = raw.get("prm") or {}
    www = probe.get("www_authenticate") or {}
    url = raw.get("url")
    tried = ", ".join(f"{c.get('url')} -> {c.get('status') or c.get('error')}"
                      for c in prm.get("candidates") or [])
    rem = (
        "Implement RFC 9728: serve a Protected Resource Metadata document whose `resource` equals "
        "the resource identifier implied by the well-known URL serving it, with a non-empty "
        "`authorization_servers` array, and advertise it via the `resource_metadata` parameter of "
        "WWW-Authenticate on 401. Spec: MCP servers MUST implement OAuth 2.0 Protected Resource "
        "Metadata (RFC9728) and the document MUST include the `authorization_servers` field "
        "containing at least one authorization server."
    )
    detail = (
        "Impact ceiling: this is a discovery/interop MUST violation, not an exploitable auth "
        "bypass. Token audience validation is enforced server-side and is unaffected by PRM "
        "absence."
    )

    if not prm.get("served_from"):
        hdr = ("lacked resource_metadata" if www else "absent")
        return [Hit(
            observation=(
                f"MCP server {url} returned {probe.get('status')} unauthenticated. Discovery: "
                f"WWW-Authenticate {hdr} (raw={www.get('raw')!r}); well-known GETs returned "
                f"[{tried}]. No PRM document was retrieved from the header parameter or either "
                f"well-known URI."
            ),
            remediation=rem, detail=detail,
            source_ref={"api": "/.well-known/oauth-protected-resource"},
        )]

    doc = prm.get("document") or {}
    base = raw.get("prm_base")
    served = prm.get("served_from")
    hits = []

    au = doc.get("authorization_servers")
    if not isinstance(au, list) or not au:
        hits.append(Hit(
            observation=(
                f"PRM served from {served} (implied resource identifier {base!r}) for MCP server "
                f"{url} declares authorization_servers={au!r}. The non-empty authorization_servers "
                f"requirement is MCP-specific (RFC 9728 §2 marks the field OPTIONAL)."
            ),
            remediation=rem, detail=detail,
            source_ref={"api": served, "config_key": "authorization_servers"},
        ))

    res = doc.get("resource")
    if not isinstance(res, str):
        hits.append(Hit(
            observation=(f"PRM served from {served} for MCP server {url} declares resource={res!r}; "
                         f"`resource` is REQUIRED per RFC 9728 §2."),
            remediation=rem, detail=detail,
            source_ref={"api": served, "config_key": "resource"},
        ))
    elif base and res != base:
        # RFC 9728 §3.3: the comparison base is derived from the URL that SERVED the document —
        # the identifier the well-known suffix was inserted into — NOT the MCP endpoint URL.
        cosmetic = _loose_eq(res, base)
        hits.append(Hit(
            observation=(
                f"PRM served from {served} (implied resource identifier {base!r}) for MCP server "
                f"{url} declares resource={res!r}, which is not byte-equal to the implied "
                f"identifier" + (" (differs only in scheme/host case or trailing slash)."
                                 if cosmetic else ".")
            ),
            severity="info" if cosmetic else None,
            remediation=rem,
            detail=(detail + " Spec: implementations SHOULD accept uppercase scheme and host "
                    "components for robustness, so a case/trailing-slash delta is informational.")
            if cosmetic else detail,
            source_ref={"api": served, "config_key": "resource"},
        ))
    return hits


@detector(kinds=["mcp_server"], rule_id="MCP.AUTH.PKCE_S256_NOT_OFFERED", severity="high",
          title="Authorization server advertises PKCE without S256")
def pkce_s256_not_offered(resource, ctx) -> list:
    hits = []
    for m in resource.raw.get("as_metadata") or []:
        doc = m.get("document")
        if not doc:
            continue
        ccms = doc.get("code_challenge_methods_supported")
        if not isinstance(ccms, list) or "S256" in ccms:
            continue
        hits.append(Hit(
            observation=(
                f"AS metadata at {m.get('metadata_url')} (resolved from candidate "
                f"{m.get('candidate_n')} of the spec discovery order) for issuer {m.get('issuer')} "
                f"advertises code_challenge_methods_supported={ccms!r}, which does not include "
                f'"S256".'
            ),
            remediation=('Support PKCE with S256 and publish code_challenge_methods_supported: '
                         '["S256"] in authorization server metadata. Spec: MCP clients MUST use '
                         "the S256 code challenge method when technically capable."),
            source_ref={"api": m.get("metadata_url"),
                        "config_key": "code_challenge_methods_supported"},
        ))
    return hits


_PKCE_OMITTER_HOSTS = {"login.microsoftonline.com", "sts.windows.net"}
_PKCE_OMITTER_SUFFIXES = (".ciamlogin.com", ".snowflakecomputing.com")


def _is_pkce_omitter(host) -> bool:
    h = (host or "").lower()
    return h in _PKCE_OMITTER_HOSTS or h.endswith(_PKCE_OMITTER_SUFFIXES)


@detector(kinds=["mcp_server"], rule_id="MCP.AUTH.PKCE_METHODS_NOT_ADVERTISED", severity="medium",
          title="Authorization server does not advertise code_challenge_methods_supported")
def pkce_methods_not_advertised(resource, ctx) -> list:
    hits = []
    for m in resource.raw.get("as_metadata") or []:
        doc = m.get("document")
        if not doc or "code_challenge_methods_supported" in doc:
            continue
        issuer = m.get("issuer")
        s = _safe_split(issuer)
        host = s.hostname if s else None     # unparseable issuer -> not an omitter -> no downgrade
        omitter = _is_pkce_omitter(host)
        obs = (
            f"AS metadata at {m.get('metadata_url')} for issuer {issuer} does not advertise "
            f"code_challenge_methods_supported (observed: ABSENT). Per MCP spec 2025-11-25, MCP "
            f"clients MUST refuse to proceed when this field is absent, so spec-compliant clients "
            f"will fail to connect. Absence does not prove the AS lacks S256 support — several "
            f"major providers support S256 without advertising it."
        )
        if omitter:
            obs += (f" Issuer host {host} is on the known-omitter list "
                    f"(verified to support S256 while omitting the field).")
        hits.append(Hit(
            observation=obs,
            severity="info" if omitter else None,
            remediation=('Publish code_challenge_methods_supported: ["S256"] in AS metadata. '
                         "OpenID providers must include the field explicitly to be MCP-compatible."),
            detail=("Conformance/interop, not a proven crypto weakness. Do not read this as the AS "
                    "lacking PKCE."),
            source_ref={"api": m.get("metadata_url"),
                        "config_key": "code_challenge_methods_supported"},
        ))
    return hits


@detector(kinds=["mcp_server"], rule_id="MCP.AUTH.AS_METADATA_UNDISCOVERABLE", severity="medium",
          title="Authorization server metadata is not discoverable")
def as_metadata_undiscoverable(resource, ctx) -> list:
    """Split out of the PKCE rules by their own text: when every candidate 404s, the fact is that
    metadata is undiscoverable — asserting anything about PKCE from it would be unfounded."""
    prm = resource.raw.get("prm") or {}
    hits = []
    for m in resource.raw.get("as_metadata") or []:
        if m.get("document") is not None:
            continue
        tried = ", ".join(f"{c.get('url')} -> {c.get('status') or c.get('error')}"
                          for c in m.get("candidates") or [])
        hits.append(Hit(
            observation=(
                f"Every authorization server metadata candidate in the MCP spec discovery order "
                f"failed for issuer {m.get('issuer')} declared in the PRM served from "
                f"{prm.get('served_from')}: [{tried}]. No AS metadata document was retrieved."
            ),
            remediation=("Serve OAuth 2.0 Authorization Server Metadata (RFC 8414) or OpenID "
                         "Provider Configuration at a well-known URI the MCP discovery order "
                         "reaches, so clients can resolve the issuer declared in the PRM."),
            source_ref={"api": "/.well-known/oauth-authorization-server"},
        ))
    return hits


_WILDCARD_EXACT = {"*", "all", "full", "full-access"}
_PREFIX_WILDCARD = re.compile(r"^[A-Za-z0-9_.-]+:\*$")


@detector(kinds=["mcp_server"], rule_id="MCP.AUTH.SCOPE_OVERBROAD", severity="low",
          title="Protected Resource Metadata advertises a wildcard or omnibus scope")
def scope_overbroad(resource, ctx) -> list:
    prm = resource.raw.get("prm") or {}
    scopes = (prm.get("document") or {}).get("scopes_supported")
    # scopes_supported is OPTIONAL per RFC 9728 §2 — if absent the rule MUST NOT fire.
    if not isinstance(scopes, list):
        return []
    bad = [s for s in scopes if isinstance(s, str) and (
        s.lower() in _WILDCARD_EXACT or _PREFIX_WILDCARD.match(s) or s.endswith(".*"))]
    if not bad:
        return []
    literal = any(s.lower() in _WILDCARD_EXACT for s in bad)
    return [Hit(
        observation=(
            f"PRM at {prm.get('served_from')} advertises scopes_supported={scopes!r}, including "
            f"wildcard/omnibus scope(s) {bad!r}, which MCP 2025-11-25 Security Best Practices "
            f"§Scope Minimization lists under Common Mistakes."
        ),
        severity="medium" if literal else None,   # per-match escalation on a literal */all/full-access
        remediation=(
            "Adopt a progressive least-privilege scope model: publish a minimal baseline scope set "
            "(e.g. mcp:tools-basic) covering only low-risk discovery/read operations in "
            "scopes_supported, and elevate incrementally via targeted "
            'WWW-Authenticate: Bearer error="insufficient_scope", scope="..." challenges on HTTP '
            "403 when a privileged tool is first called."
        ),
        detail=("§Scope Minimization carries no MUST/SHOULD server obligations — it is "
                "non-normative Common Mistakes guidance, and impact is conditional on a separate "
                "token compromise."),
        source_ref={"api": prm.get("served_from"), "config_key": "scopes_supported"},
    )]


# ══════════════════════════════════════════════════════════════════════════
# TRANSPORT
# ══════════════════════════════════════════════════════════════════════════
_BELOW_TLS12 = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_TLS_REMEDIATION = (
    "Serve the MCP endpoint and all OAuth endpoints over HTTPS with a valid certificate. Spec: "
    "all authorization server endpoints MUST be served over HTTPS, and all redirect URIs MUST be "
    "either localhost or use HTTPS; access tokens MUST NOT be included in the URI query string. "
    "OAuth 2.1 §1.5: when using https, TLS certificates MUST be checked according to RFC 9110. "
    "Separately, disable TLS below 1.2 per BCP 195/RFC 8996 — this one is not an MCP spec "
    "requirement."
)


@detector(kinds=["mcp_server"], rule_id="MCP.TRANSPORT.PLAINTEXT_HTTP", severity="high",
          title="MCP or OAuth endpoint transport is unprotected (plaintext HTTP, invalid certificate, or TLS below 1.2)")
def plaintext_http(resource, ctx) -> list:
    raw = resource.raw
    tls = raw.get("tls") or {}
    neg = tls.get("negotiated") or "NONE"
    floor = tls.get("floor") or "UNTESTED"
    hits = []

    # One hit per URL — the rule fires on any single match, so a combined evidence string would
    # over-assert about URLs that are fine.
    entries = [{"role": "MCP endpoint", "url": raw.get("url"), "host": raw.get("host"),
                "resolved_ip": raw.get("resolved_ip"), "ip_class": raw.get("ip_class")}]
    entries += raw.get("oauth_urls") or []
    seen = set()
    for e in entries:
        u = e.get("url")
        if not u or u in seen:
            continue
        seen.add(u)
        s = _safe_split(u)
        if s is None or s.scheme != "http":
            continue     # an unparseable URL is not evidence of plaintext — assert nothing
        host = e.get("host") or s.hostname
        if _is_loopback_host(host) or e.get("ip_class") == "loopback":
            continue
        hits.append(Hit(
            observation=(
                f"{e.get('role')} URL {u} uses scheme http:// with host {host} resolving to "
                f"non-loopback {e.get('resolved_ip')} ({e.get('ip_class')}). TLS: highest "
                f"negotiated {neg}, lowest accepted {floor}. Certificate: "
                f"{tls.get('cert_status') or 'NONE'}."
            ),
            severity="medium" if _tls_terminated_upstream(host, e.get("ip_class")) else None,
            remediation=_TLS_REMEDIATION,
            detail=("Bearer tokens travel in cleartext (CWE-319). Note there is no HTTPS MUST for "
                    "the MCP endpoint itself in the 2025-11-25 transports spec — the MUST binds "
                    "the OAuth/AS endpoints."),
            source_ref={"api": u, "config_key": "scheme"},
        ))

    if tls.get("cert_status") == "invalid":
        hits.append(Hit(
            observation=(
                f"MCP endpoint {raw.get('url')} presented a certificate that failed validation: "
                f"{tls.get('cert_error')!r}. TLS: highest negotiated {neg}, lowest accepted {floor}."
            ),
            severity="medium" if _tls_terminated_upstream(raw.get("host"), raw.get("ip_class")) else None,
            remediation=_TLS_REMEDIATION,
            source_ref={"api": raw.get("url"), "config_key": "tls.certificate"},
        ))

    observed_low = [v for v in (neg, floor) if v in _BELOW_TLS12]
    if observed_low:
        hits.append(Hit(
            observation=(
                f"MCP endpoint {raw.get('url')} TLS: highest negotiated {neg}, lowest accepted "
                f"{floor} — {observed_low[0]} is below TLS 1.2."
            ),
            remediation=_TLS_REMEDIATION,
            detail="Authority is BCP 195 / RFC 8996, not the MCP spec, which defers to OAuth 2.1 "
                   "§1.5 — and that section places TLS version identification out of scope.",
            source_ref={"api": raw.get("url"), "config_key": "tls.version"},
        ))
    return hits


@detector(kinds=["mcp_server"], rule_id="MCP.TRANSPORT.DEPRECATED_HTTP_SSE", severity="low",
          title="Server exposes the deprecated HTTP+SSE transport")
def deprecated_http_sse(resource, ctx) -> list:
    raw = resource.raw
    legacy = raw.get("legacy_sse") or {}
    url = raw.get("url")
    hits = []

    if legacy.get("first_event") == "endpoint":
        # The spec RECOMMENDS dual-hosting legacy /sse beside a modern /mcp during migration, so
        # a modern endpoint present means "legacy compat endpoint still exposed", not "server uses
        # the deprecated transport".
        modern = legacy.get("modern_detected")
        hits.append(Hit(
            observation=(
                f"GET {url} returned {legacy.get('content_type')!r} with first SSE event "
                f'name="endpoint" (data={legacy.get("endpoint_data")!r}), indicating the '
                f"deprecated HTTP+SSE transport; initialize reported protocolVersion="
                f"{raw.get('protocol_version')!r}. Modern Streamable HTTP "
                f"{'was' if modern else 'was not'} detected at {legacy.get('modern_endpoint')}."
            ),
            severity="info" if modern else None,
            remediation=(
                "Migrate to Streamable HTTP: expose a single MCP endpoint path supporting both "
                "POST and GET. HTTP+SSE has been Deprecated since revision 2025-03-26 and is "
                "registered as Deprecated under SEP-2596 — new implementations SHOULD NOT adopt "
                "it. The 2024-11-05 transport also predates any MCP authorization spec and "
                "therefore the RFC 9728 model. (Pinned to 2025-11-25: the 2026-07-28 revision "
                "removes the GET stream endpoint and protocol-level sessions and tells servers to "
                "return 405 to GET, so this remediation's mechanics change on that date.)"
            ),
            detail=("Legacy compat endpoint still exposed alongside working Streamable HTTP — the "
                    "blessed migration pattern, not a defect." if modern else
                    "Lifecycle/hygiene: HTTP+SSE is Deprecated, not Removed; no CVE, and the probe "
                    "proves no active exploit primitive."),
            source_ref={"api": f"GET {url} (Accept: text/event-stream)"},
        ))

    # Era-gated: this probe only works for 2025-03-26…2025-11-25. The 2026-07-28 revision removes
    # the initialize handshake and would silently break it.
    if raw.get("protocol_version") == "2024-11-05":
        hits.append(Hit(
            observation=(f"initialize at {url} negotiated protocolVersion=\"2024-11-05\", the "
                         f"revision that predates the MCP authorization spec."),
            severity="info",
            remediation="Upgrade the server to negotiate protocol revision 2025-11-25.",
            source_ref={"api": f"POST {url} (JSON-RPC initialize)",
                        "config_key": "protocolVersion"},
        ))
    return hits


@detector(kinds=["mcp_server"], rule_id="MCP.TRANSPORT.PROTOCOL_VERSION_UNVALIDATED",
          severity="low", title="Server does not reject an unsupported MCP-Protocol-Version")
def protocol_version_unvalidated(resource, ctx) -> list:
    iv = ((resource.raw.get("probes") or {}).get("invalid_version")) or {}
    status = iv.get("status")
    if status is None or status == 400:
        return []
    return [Hit(
        observation=(f"{resource.raw.get('url')} returned HTTP {status} for MCP-Protocol-Version: "
                     f"{iv.get('sent')}; spec requires 400 Bad Request."),
        remediation=("Reject unknown protocol revisions: if the server receives a request with an "
                     "invalid or unsupported MCP-Protocol-Version, it MUST respond with 400 Bad "
                     "Request."),
        source_ref={"api": f"POST {resource.raw.get('url')}",
                    "config_key": "MCP-Protocol-Version"},
    )]


@detector(kinds=["mcp_server"], rule_id="MCP.TRANSPORT.ORIGIN_UNVALIDATED", severity="medium",
          title="Server does not reject a foreign Origin header")
def origin_unvalidated(resource, ctx) -> list:
    raw = resource.raw
    o = ((raw.get("probes") or {}).get("origin")) or {}
    # PASS on 401/403/421/400-origin-error. FAIL only on 200 + a valid InitializeResult: the
    # Python SDK answers 421 when rebinding protection is correctly ENABLED, and an OAuth-
    # protected server answers 401 — status-only matching scores the safest configs worst.
    if not (o.get("status") == 200 and o.get("has_result")):
        return []

    ip_class = raw.get("ip_class")
    local = ip_class in ("loopback", "private")
    unauth_open = (raw.get("unauth_probe") or {}).get("status") == 200
    if local and unauth_open:
        sev = "high"          # the CVE-2025-49596 shape
    elif local:
        sev = None            # medium default
    else:
        sev = "info"          # maintainers: public servers are not affected by DNS rebinding

    return [Hit(
        observation=(
            f"POST {raw.get('url')} with Origin: {o.get('sent')} returned HTTP {o.get('status')} "
            f"with a valid InitializeResult; expected a rejection (401/403/421/400-origin-error). "
            f"Endpoint resolves to {raw.get('resolved_ip')} ({ip_class}) and "
            f"{'does not' if unauth_open else 'does'} enforce authentication."
        ),
        severity=sev,
        remediation=(
            "Validate the Origin header on all incoming connections against an allowlist. Spec "
            "(Streamable HTTP Security Warning): servers MUST validate the Origin header on all "
            "incoming connections to prevent DNS rebinding attacks, and if the Origin header is "
            "present and invalid, servers MUST respond with HTTP 403 Forbidden. TypeScript SDK: "
            "StreamableHTTPServerTransport({ enableDnsRebindingProtection: true, allowedHosts: "
            "[...], allowedOrigins: [...] }) or createMcpExpressApp(); upgrade to >=1.24.0. "
            "Python SDK: TransportSecuritySettings(enable_dns_rebinding_protection=True, "
            "allowed_hosts=[...], allowed_origins=[...]); upgrade to >=1.23.0 for FastMCP "
            "localhost auto-enable. Both SDKs still default the protection to false."
        ),
        detail=("DNS rebinding is a localhost threat model; MCP maintainers state public servers "
                "are not affected. A public server legitimately allowlisting browser origins "
                "correctly returns 200 to some foreign Origins."),
        source_ref={"api": f"POST {raw.get('url')}", "config_key": "Origin"},
    )]


# ══════════════════════════════════════════════════════════════════════════
# SESSION
# ══════════════════════════════════════════════════════════════════════════
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-([1-8])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
                      re.I)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_B62_RE = re.compile(r"^[0-9A-Za-z]+$")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def _derivable(sid: str, ts, client_name: str):
    """Fixed enumerated transforms only. The original 'derivable via a hash the scanner can
    reproduce' is unbounded; user id and email are unknown to a scanner, so only the client name
    and the unix second are testable."""
    low = sid.lower()
    seeds = [client_name] + ([str(ts), str(ts - 1), str(ts + 1)] if isinstance(ts, int) else [])
    for algo in ("md5", "sha1", "sha256", "sha512"):
        for seed in seeds:
            if seed and hashlib.new(algo, seed.encode()).hexdigest() == low:
                return f"{algo}({seed!r})"
    return None


def _session_id_verdict(samples: list, client_name: str):
    """Structural tests only -> (severity_override | 'fail' | None, reason).

    No entropy estimate is computed: a sample set of N bounds measurable distribution entropy at
    log2(N) bits, so a '122-bit entropy' claim from 10 samples is statistically incoherent."""
    ids = [s.get("id") for s in samples if s.get("id")]
    if not ids:
        return None, None

    for sid in ids:
        bad = [i for i, ch in enumerate(sid) if not 0x21 <= ord(ch) <= 0x7E]
        if bad:
            return "fail", (f"test 6 (charset): value {sid!r} carries a character outside visible "
                            f"ASCII 0x21-0x7E at offset {bad[0]}")

    if all(_JWT_RE.match(s) for s in ids):
        # JWTs are spec-blessed session IDs but are long, structured, carry client-derivable
        # claims and a monotonic `iat` — tests 1/2/5 would fire on a conformant server. Only the
        # signature's entropy is meaningful.
        sig = ids[0].rsplit(".", 1)[-1]
        if len(sig) < 22:
            return "fail", (f"test 3 (length floor): JWT signature segment is {len(sig)} chars, "
                            f"below the 22-char base62 floor (<122 bits)")
        return None, None

    uuids = [_UUID_RE.match(s) for s in ids]
    if all(uuids):
        vers = sorted({m.group(1) for m in uuids})
        if "1" in vers:
            return "fail", (f"test 4 (uuid version): sampled UUID versions {vers} include v1 "
                            f"(MAC address + timestamp, not random)")
        if vers == ["7"]:
            # v7 is timestamp-ordered BY DESIGN and carries 74 random bits per RFC 9562 — not
            # online-guessable. Lumping it with v1 would be wrong.
            return "info", ("values are UUIDv7: timestamp-ordered by design with 74 random bits. "
                            "RFC 9562 prefers UUIDv4 for security operations")
        return None, None   # UUIDv4 carries 122 bits and is the spec's own recommended answer

    if all(s.isdigit() for s in ids):
        nums = sorted(int(s) for s in ids)
        deltas = sorted({nums[i + 1] - nums[i] for i in range(len(nums) - 1)})
        return "fail", (f"test 1/2 (integer/counter): every sampled value parses as an integer; "
                        f"sorted deltas={deltas}")

    for s in samples:
        d = _derivable(s.get("id", ""), s.get("ts"), client_name)
        if d:
            return "fail", f"test 5 (derivable): value {s.get('id')!r} equals {d}"

    if all(_HEX_RE.match(s) for s in ids) and min(len(s) for s in ids) < 32:
        return "fail", (f"test 3 (length floor): shortest sampled value is "
                        f"{min(len(s) for s in ids)} hex chars, below the 32-hex floor (<122 bits)")
    if all(_B62_RE.match(s) for s in ids) and min(len(s) for s in ids) < 22:
        return "fail", (f"test 3 (length floor): shortest sampled value is "
                        f"{min(len(s) for s in ids)} base62 chars, below the 22-char floor "
                        f"(<122 bits)")
    return None, None


_SESSION_REMEDIATION = (
    "Generate session IDs with a cryptographically secure RNG. Spec: MCP servers MUST use secure, "
    "non-deterministic session IDs; generated session IDs (e.g. UUIDs) SHOULD use secure random "
    "number generators; avoid predictable or sequential session identifiers that could be guessed "
    "by an attacker. Transports §Session Management: the session ID SHOULD be globally unique and "
    "cryptographically secure (e.g. a securely generated UUID, a JWT, or a cryptographic hash). "
    "Bind session IDs to user-specific information using a key format like <user_id>:<session_id> "
    "so a guessed session ID cannot impersonate another user; rotate and expire session IDs. Note "
    "the 2026-07-28 revision removes MCP-Session-Id entirely in favour of a stateless core."
)


@detector(kinds=["mcp_server"], rule_id="MCP.SESSION.PREDICTABLE_ID", severity="medium",
          title="MCP-Session-Id values fail a structural randomness test")
def session_predictable_id(resource, ctx) -> list:
    raw = resource.raw
    pv = raw.get("protocol_version")
    if _sessions_removed(pv):
        return []      # >= 2026-07-28 removes MCP-Session-Id and the protocol-level session
    probes = (raw.get("probes") or {}).get("sessions") or {}
    samples = probes.get("samples") or []
    ids = [s.get("id") for s in samples if s.get("id")]
    if not ids:
        return []      # stateless server (sessionIdGenerator: undefined) — N/A skip, not a FAIL

    verdict, reason = _session_id_verdict(samples, raw.get("client_name") or "")
    if not verdict:
        return []
    sample = ids[:3]
    return [Hit(
        observation=(
            f"{len(ids)} initialize calls to {raw.get('url')} returned MCP-Session-Id values "
            f"{sample!r} (first {len(sample)} of {len(ids)}); {reason}. Negotiated "
            f"protocolVersion={pv!r}."
        ),
        severity="info" if verdict == "info" else None,
        remediation=_SESSION_REMEDIATION,
        detail=("Impact is contingent: the same page states MCP servers MUST NOT use sessions for "
                "authentication and MUST verify all inbound requests, so a guessed session ID "
                "alone should not authenticate on an otherwise-compliant server."),
        source_ref={"api": f"POST {raw.get('url')} (JSON-RPC initialize)",
                    "config_key": "MCP-Session-Id"},
    )]


@detector(kinds=["mcp_server"], rule_id="MCP.SESSION.ID_COLLISION", severity="high",
          title="MCP-Session-Id values collide across fresh sessions")
def session_id_collision(resource, ctx) -> list:
    raw = resource.raw
    if _sessions_removed(raw.get("protocol_version")):
        return []
    samples = ((raw.get("probes") or {}).get("sessions") or {}).get("samples") or []
    ids = [s.get("id") for s in samples if s.get("id")]
    dupes = {v: c for v, c in Counter(ids).items() if c > 1}
    if not dupes:
        return []
    v, c = next(iter(dupes.items()))
    return [Hit(
        observation=(f"{len(ids)} initialize calls to {raw.get('url')} returned a repeated "
                     f"MCP-Session-Id ({v!r} seen {c} times), indicating session collision."),
        remediation=_SESSION_REMEDIATION,
        detail="A collision/fixation bug with different impact from predictability.",
        source_ref={"api": f"POST {raw.get('url')} (JSON-RPC initialize)",
                    "config_key": "MCP-Session-Id"},
    )]


@detector(kinds=["mcp_server"], rule_id="MCP.SESSION.USED_FOR_AUTHENTICATION", severity="high",
          title="Session ID alone is accepted as the credential")
def session_used_for_authentication(resource, ctx) -> list:
    raw = resource.raw
    if _sessions_removed(raw.get("protocol_version")):
        return []
    sa = (raw.get("probes") or {}).get("session_auth") or {}
    replay, control = sa.get("replay_status"), sa.get("control_status")
    if replay is None or not 200 <= replay < 300:
        return []      # FAIL-on-2xx: 403 is a legitimate rejection, and 400 is spec-compliant
                       # for a missing session id
    if control is None or 200 <= control < 300:
        # The negative control is what makes this rule sound: without it every unauthenticated
        # server reads as "session-authenticated" — the dominant false positive.
        return []
    return [Hit(
        observation=(
            f"tools/list at {raw.get('url')} returned HTTP {replay} with "
            f"MCP-Session-Id={sa.get('session_id')!r} and no Authorization header, while the same "
            f"request without a session ID returned {control} — the session ID alone is being "
            f"accepted as the credential."
        ),
        remediation=(
            "Never treat the session as a credential. Spec: MCP servers that implement "
            "authorization MUST verify all inbound requests; MCP servers MUST NOT use sessions "
            "for authentication; and authorization MUST be included in every HTTP request from "
            "client to server, even if they are part of the same logical session. Validate the "
            "bearer token on every HTTP request including resumption GETs. The spec SHOULD-"
            "recommends binding session IDs to user-specific information (key format "
            "<user_id>:<session_id>) derived from the token rather than provided by the client."
        ),
        detail=("Residual caveats: transport-layer auth (mTLS/client-cert, cookie sessions) makes "
                "a tokenless request legitimately succeed, as does probing an origin directly "
                "behind a gateway that terminates auth."),
        source_ref={"api": f"POST {raw.get('url')} (JSON-RPC tools/list)",
                    "config_key": "MCP-Session-Id"},
    )]


# ══════════════════════════════════════════════════════════════════════════
# SERVER
# ══════════════════════════════════════════════════════════════════════════
_UNTRUSTED_METADATA_REMEDIATION = (
    "Treat server instructions as untrusted server-controlled input injected into the model's "
    "context at connection time, before any consent gate — the same line-jumping surface as tool "
    "descriptions. The spec's own doc comment on `instructions` says this information MAY be "
    "added to the system prompt, and the lifecycle spec makes initialization the first "
    "interaction between client and server, so the text lands in context before any tool is "
    "invoked. Strip, sandbox, or require human review of the field, and pin it as part of the "
    "server-config hash (Trail of Bits' context-protector compares server instructions, tool "
    "descriptions, and tool input schemas)."
)


@detector(kinds=["mcp_server"], rule_id="MCP.SERVER.INSTRUCTIONS_INJECTION", severity="high",
          title="Server instructions carry model-directed injection patterns")
def instructions_injection(resource, ctx) -> list:
    raw = resource.raw
    si = raw.get("server_info") or {}
    url, pv = raw.get("url"), raw.get("protocol_version")

    fields = []
    if isinstance(raw.get("instructions"), str):
        fields.append(("InitializeResult.instructions", raw["instructions"]))
    # serverInfo.description only exists from 2025-11-25 — its absence on a 2025-06-18 server is
    # not a finding and must not error.
    if isinstance(si.get("description"), str):
        fields.append(("serverInfo.description", si["description"]))

    hits = []
    for path, text in fields:
        for h in _injection_hits(text):
            hits.append(Hit(
                observation=(f"Server {url} (spec {pv!r}) {path} ({len(text)} chars) matched "
                             f"injection pattern class {h['class']} at raw offset {h['offset']}: "
                             f"{h['excerpt']!r}."),
                remediation=_UNTRUSTED_METADATA_REMEDIATION,
                source_ref={"api": f"POST {url} (JSON-RPC initialize)", "config_key": path},
            ))
        for h in _tier1_hits(text):
            hits.append(Hit(
                observation=(f"Server {url} (spec {pv!r}) {path} contains Tier-1 invisible/control "
                             f"class {h['class']}: codepoint {h['codepoint']} at offset "
                             f"{h['offset']} of {len(text)}."),
                remediation=_UNTRUSTED_METADATA_REMEDIATION,
                source_ref={"api": f"POST {url} (JSON-RPC initialize)", "config_key": path},
            ))
    return hits


# ══════════════════════════════════════════════════════════════════════════
# TOOL
# ══════════════════════════════════════════════════════════════════════════
_TOOL_POISON_REMEDIATION = (
    "Treat every tool description as untrusted input, not as trusted documentation. Spec: "
    "descriptions of tool behavior such as annotations should be considered untrusted, unless "
    "obtained from a trusted server (spec index, §Security and Trust & Safety > Tool Safety), and "
    "clients MUST consider tool annotations to be untrusted unless they come from trusted servers "
    "(server/tools, §Data Types > Tool). Because tool descriptions enter the model's context at "
    "tools/list time — before any tool is invoked — this bypasses MCP's invocation-consent "
    "control entirely. Quarantine the server, remove it from the agent's registry, and pin tool "
    "definitions after human review. Prefer servers from verified registry namespaces."
)


@detector(kinds=["mcp_tool"], rule_id="MCP.TOOL.DESCRIPTION_HIDDEN_INSTRUCTIONS", severity="high",
          title="Tool metadata carries model-directed injection patterns")
def tool_description_hidden_instructions(resource, ctx) -> list:
    tool, name, endpoint, pv = _tool_ctx(resource)
    desc = tool.get("description") if isinstance(tool.get("description"), str) else ""
    schema_len = _canonical_len(tool.get("inputSchema"))
    hits = []
    for path, text in _meta_strings(tool):
        for h in _injection_hits(text):
            hits.append(Hit(
                observation=(
                    f"Tool {name!r} on server {endpoint} (spec {pv}): field {path} matched "
                    f"poisoning pattern class {h['class']} at raw offset {h['offset']}: "
                    f"{h['excerpt']!r}. Description length {len(desc)} chars; inputSchema "
                    f"{schema_len} chars (canonical minified JSON)."
                ),
                remediation=_TOOL_POISON_REMEDIATION,
                detail=("CONFIRMED class. A pattern match is evidence of a poisoning ATTEMPT, not "
                        "of successful compromise; the deterministic layer catches the careless "
                        "attacker, not novel phrasing or non-English payloads."),
                source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)", "config_key": path},
            ))
    return hits


@detector(kinds=["mcp_tool"], rule_id="MCP.TOOL.DESCRIPTION_INVISIBLE_CHARS", severity="high",
          title="Tool metadata contains invisible or control characters")
def tool_description_invisible_chars(resource, ctx) -> list:
    tool, name, endpoint, pv = _tool_ctx(resource)
    # Scanned as it arrived off the wire: the connector never sanitizes or NFKC-normalises tool
    # metadata, because NFKC deletes several of these codepoints and would mask the finding.
    grouped = {}
    for path, text in _walk_all(tool, "tool"):
        for h in _tier1_hits(text):
            grouped.setdefault((path, h["class"]), []).append(h)
    hits = []
    for (path, cls), hs in grouped.items():
        hits.append(Hit(
            observation=(f"Tool {name!r} on server {endpoint} (spec {pv}): field {path} contains "
                         f"{len(hs)} codepoints in Tier-1 class {cls} (e.g. {hs[0]['codepoint']} "
                         f"at offset {hs[0]['offset']})."),
            remediation=(
                "Reject or strip invisible/control characters from all server-supplied metadata "
                "before it reaches the model or a human approval UI. Render ANSI escapes visibly "
                "rather than interpreting them (Trail of Bits' context-protector offers "
                "--visualize-ansi-codes) — hidden control characters let a malicious server show "
                "one thing to the reviewer and another to the model. Normalise to NFKC and "
                "enforce an allowlist of scripts for tool names. A server emitting any Tier-1 "
                "character in metadata should be treated as hostile."
            ),
            source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)", "config_key": path},
        ))
    return hits


@detector(kinds=["mcp_tool"], rule_id="MCP.TOOL.DESCRIPTION_UNUSUAL_UNICODE", severity="low",
          title="Tool metadata contains unusual but legitimately-used Unicode")
def tool_description_unusual_unicode(resource, ctx) -> list:
    tool, name, endpoint, pv = _tool_ctx(resource)
    grouped = {}
    for path, text in _walk_all(tool, "tool"):
        for h in _tier2_hits(text):
            grouped.setdefault((path, h["class"]), []).append(h)
    hits = []
    for (path, cls), hs in grouped.items():
        hits.append(Hit(
            observation=(f"Tool {name!r} on server {endpoint} (spec {pv}): field {path} contains "
                         f"{len(hs)} codepoints in Tier-2 class {cls} (e.g. {hs[0]['codepoint']} "
                         f"at offset {hs[0]['offset']})."),
            remediation=("Review the field. These classes all have documented legitimate uses — "
                         "confirm the characters are intentional (emoji, non-Latin orthography, "
                         "icon fonts) and strip them if not."),
            detail=("Reported low BY DESIGN: U+FE0F is required for emoji presentation of ⚠️ ℹ️ ❗, "
                    "U+200D appears in every emoji ZWJ sequence, U+200C is required Persian "
                    "orthography, and the PUA holds Nerd Font glyphs. Presence is not evidence of "
                    "smuggling."),
            source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)", "config_key": path},
        ))
    return hits


_JSON_SCHEMA_2020_12 = {
    "$schema", "$id", "$ref", "$defs", "$anchor", "$dynamicRef", "$dynamicAnchor", "$vocabulary",
    "$comment", "definitions", "type", "enum", "const", "multipleOf", "maximum",
    "exclusiveMaximum", "minimum", "exclusiveMinimum", "maxLength", "minLength", "pattern",
    "maxItems", "minItems", "uniqueItems", "maxContains", "minContains", "maxProperties",
    "minProperties", "required", "dependentRequired", "format", "contentEncoding",
    "contentMediaType", "contentSchema", "title", "description", "default", "deprecated",
    "readOnly", "writeOnly", "examples", "items", "prefixItems", "contains", "properties",
    "patternProperties", "additionalProperties", "propertyNames", "dependentSchemas", "if",
    "then", "else", "allOf", "anyOf", "oneOf", "not", "unevaluatedItems", "unevaluatedProperties",
}
_SCHEMA_KEY_ALLOW = {"x-mcp-header"}   # the spec blesses this one inside property schemas


def _declared_property_keys(node, acc: set) -> set:
    """Deliberately over-collects across the WHOLE tree ($defs included): legitimate orphans arise
    routinely from $ref/allOf/$defs composition (Pydantic inheritance emits exactly this), and a
    bare orphan is LEGAL — JSON Schema 2020-12 §6.5.3 constrains the instance, not the schema's
    own `properties`."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("properties", "patternProperties") and isinstance(v, dict):
                acc.update(v.keys())
            _declared_property_keys(v, acc)
    elif isinstance(node, list):
        for v in node:
            _declared_property_keys(v, acc)
    return acc


def _prose_shaped(s: str) -> bool:
    return bool(re.search(r"[\s.,;:!?]", s)) or len(s) > 64


def _walk_keywords(node, path, in_map=False):
    """(json_path, key, value) for keys outside the 2020-12 vocabulary. `in_map` tracks whether we
    are inside a properties/$defs map, where keys are property names rather than keywords."""
    if isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_keywords(v, f"{path}[{i}]")
        return
    if not isinstance(node, dict):
        return
    for k, v in node.items():
        p = f"{path}.{k}"
        if in_map:
            yield from _walk_keywords(v, p)
        elif k in ("properties", "patternProperties", "$defs", "definitions"):
            yield from _walk_keywords(v, p, in_map=True)
        elif k not in _JSON_SCHEMA_2020_12 and k not in _SCHEMA_KEY_ALLOW:
            yield p, k, v
        else:
            yield from _walk_keywords(v, p)


_SCHEMA_REMEDIATION = (
    "Scan the entire tool schema, not just the description field — the entire tool schema is part "
    "of the LLM's context window and thus part of its reasoning, and every part of it is a "
    "potential injection point (CyberArk, Full-Schema Poisoning). Validate inputSchema against "
    "the declared ($schema) or default (2020-12) dialect; do NOT reject unknown keywords, which "
    "would reject the spec-blessed x-mcp-header. Enforce that every `required` entry names a "
    "property declared in the resolved schema; strip or reject prose in default/const/examples. "
    "Pin the full schema after review and block on drift."
)


@detector(kinds=["mcp_tool"], rule_id="MCP.TOOL.SCHEMA_POISONING", severity="high",
          title="Tool input/output schema carries a poisoned element")
def tool_schema_poisoning(resource, ctx) -> list:
    """Deterministic sub-checks only. The rulepack's sub-check 1 (suspicious property key gated on
    'the tool's stated purpose is unrelated') is a semantic judgement and belongs to the AI layer —
    it is not implemented here rather than faked with substring matching, which fires on
    max_tokens, keywords, sort_key, environment, aws_region."""
    tool, name, endpoint, pv = _tool_ctx(resource)
    hits = []

    for field in ("inputSchema", "outputSchema"):
        schema = tool.get(field)
        if not isinstance(schema, dict):
            continue

        for path, kind, value in _schema_strings(schema, field):
            for h in _injection_hits(value):
                hits.append(Hit(
                    observation=(
                        f"Tool {name!r} on server {endpoint} (spec {pv}) {field} contains a "
                        f"poisoned element at JSON path {path}: {kind} = {value[:160]!r}; matched "
                        f"pattern class {h['class']} at raw offset {h['offset']}: "
                        f"{h['excerpt']!r}."
                    ),
                    remediation=_SCHEMA_REMEDIATION,
                    source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)",
                                "config_key": path},
                ))

        declared = _declared_property_keys(schema, set())
        orphans = [(p, v) for p, kind, v in _schema_strings(schema, field)
                   if kind == "required entry" and v not in declared and _prose_shaped(v)]
        if orphans:
            hits.append(Hit(
                observation=(
                    f"Tool {name!r} on server {endpoint} (spec {pv}) {field} lists prose-shaped "
                    f"entries in `required` that name no declared property anywhere in the "
                    f"resolved schema: {[v for _, v in orphans]!r} (at {[p for p, _ in orphans]!r})."
                ),
                remediation=_SCHEMA_REMEDIATION,
                detail=("Bare orphans are legal and are not reported — only prose-shaped ones, "
                        "which $ref/allOf/$defs composition never produces."),
                source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)",
                            "config_key": f"{field}.required"},
            ))

        for path, key, value in _walk_keywords(schema, field):
            # Presence of a non-standard keyword alone is overbroad — markdownDescription,
            # example, errorMessage, deprecationMessage and x-* extensions are all benign. Only a
            # long string value that ALSO matches an injection pattern is reportable.
            if not isinstance(value, str) or len(value) <= 40:
                continue
            for h in _injection_hits(value):
                hits.append(Hit(
                    observation=(
                        f"Tool {name!r} on server {endpoint} (spec {pv}) {field} carries "
                        f"non-standard keyword {key!r} at JSON path {path} with a "
                        f"{len(value)}-char string value matching pattern class {h['class']} at "
                        f"raw offset {h['offset']}: {h['excerpt']!r}."
                    ),
                    remediation=_SCHEMA_REMEDIATION,
                    source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)",
                                "config_key": path},
                ))
    return hits


@detector(kinds=["mcp_tool"], rule_id="MCP.TOOL.INPUTSCHEMA_INVALID", severity="low",
          title="Tool declares an invalid inputSchema")
def tool_inputschema_invalid(resource, ctx) -> list:
    tool, name, endpoint, pv = _tool_ctx(resource)
    schema = tool.get("inputSchema", _ABSENT)
    if isinstance(schema, dict):
        return []
    if schema is True:
        return []   # SEP-1613 (Final) lists `true` and `{}` as valid for no-param tools
    observed = "ABSENT" if schema is _ABSENT else repr(schema)
    return [Hit(
        observation=(f"Tool {name!r} on server {endpoint} (spec {pv}) declares "
                     f"inputSchema={observed}, which is not a valid JSON Schema object."),
        remediation=("Declare inputSchema as a valid JSON Schema object (spec: it MUST be a valid "
                     "JSON Schema object, not null). For a no-parameter tool use "
                     '{"type": "object", "properties": {}}.'),
        detail="A conformance bug, not an attack.",
        source_ref={"api": f"POST {endpoint} (JSON-RPC tools/list)", "config_key": "inputSchema"},
    )]
