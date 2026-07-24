"""Managed File Transfer / EDI connector — read-only posture for the appliance layer that
moved ~90M records in the Cl0p MOVEit campaign.

MFT/EDI is the highest-blast-radius omission in an integration-security tool: MOVEit Transfer,
GoAnywhere MFT, Cleo Harmony/VLTrader/LexiCom, IBM Sterling File Gateway and Axway SecureTransport
sit at the edge of the business moving partner data, and every one of them has shipped a
pre-auth RCE that a ransomware crew turned into a mass-exfiltration event. They are largely
CLOSED appliances, so collection is deliberately shallow-but-honest and STRICTLY READ-ONLY:

  (a) admin/API endpoint fingerprint + version banner over httpx GET where reachable — the
      version banner is what the version→CVE rules key on;
  (b) exposed-admin-console detection — is the management UI reachable without authentication;
  (c) AS2/SFTP auth-mode + cert hygiene + partner/transfer accounts WHERE a config/admin API is
      available (an operator-supplied `admin_export`, or a future per-product adapter). Absent
      that, the endpoint/account layer is simply empty and the server records
      `admin_api_readable=False` — a coverage gap the rulepack surfaces as not-assessable, never
      a clean pass.

Three disciplines carried over from the other connectors:

  • Secrets are used, never persisted. `admin_token` is a ConnectorField secret=True; it opens the
    admin API inside collect() and is never copied into any Resource. A partner/transfer account's
    STORED credential is reduced to METADATA only (present? / type / plaintext-capable?) — the
    value is never read, logged, or returned (same contract as connect/redis.py `requirepass`).
  • Per-target error isolation. One connection can name several appliances; each target is probed
    in its own try/except and an unreachable or unfingerprintable target records
    probe_outcome="error"/"unfingerprinted" instead of voiding the whole scan (same shape as
    connect/aws.py per-service isolation). detect/mft.py turns those into not-assessable findings.
  • DISTINCT kinds prefixed `mft_` (mft_server, mft_endpoint, mft_transfer_account) so no other
    rulepack ever runs against an MFT resource by accident — never the generic `server`/`user`.

The parse layer (fingerprint, parse_server, parse_endpoint, parse_transfer_account,
build_resources) is pure: plain-dict probe snapshots in, Resources out. Tests exercise detectors
against parse-layer output from golden fixture dicts shaped like the real admin-console/banner and
admin-API responses, so httpx (and a live appliance) stay out of the test suite.
"""
import re
import ssl
import socket
import time
from urllib.parse import urlsplit

import httpx

from ..contracts import Collected, Edge, Resource
from ..identity import _mk_credential, _mk_grant, _mk_identity, identity_extractor
from ..registry import ConnectorField, connector

_KNOWN_PRODUCTS = ("moveit", "goanywhere", "cleo", "sterling", "axway")

# Fingerprint signatures: substrings that identify each product in the banner/title/body/headers.
# Order matters only in that the first product with a match wins; the signatures are disjoint.
_PRODUCT_SIGNS = (
    ("moveit", ("moveit",)),
    ("goanywhere", ("goanywhere",)),
    ("cleo", ("cleo", "harmony", "vltrader", "lexicom", "versalex")),
    ("sterling", ("sterling file gateway", "myfilegateway", "sterling b2b", "filegateway")),
    ("axway", ("securetransport", "axway")),
)

# Well-known management/login paths per product — probed to learn whether the console is reachable
# and whether it is gated by authentication (mode (b)). Read-only GETs only.
_ADMIN_PATHS = {
    "moveit": ("/human.aspx", "/machine.aspx", "/webinterface", "/api/v1/token"),
    "goanywhere": ("/goanywhere/", "/goanywhere/auth/Login.xhtml", "/goanywhere/admin"),
    "cleo": ("/Harmony", "/VLTrader", "/"),
    "sterling": ("/myfilegateway", "/filegateway", "/dashboard"),
    "axway": ("/home", "/login"),
    "unknown": ("/",),
}

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){1,3})")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_LOGIN_MARKERS = ('type="password"', "type='password'", "sign on", "sign in",
                  "log in", "login", "j_username", "username")


def _truthy(v) -> bool:
    return str(v if v is not None else "").strip().lower() in ("1", "true", "yes", "on")


# ── pure fingerprint layer ────────────────────────────────────────────────────
def _extract_version(text: str):
    m = _VERSION_RE.search(str(text or ""))
    return m.group(1) if m else None


_PRODUCT_KEYS = dict(_PRODUCT_SIGNS)


def _extract_product_version(product: str, banner: str):
    """The version that follows the PRODUCT name in the banner — not the first dotted number,
    which is often the web-server version ('Microsoft-IIS/10.0 MOVEit Transfer 15.0.0' → 15.0.0,
    never 10.0). Falls back to the whole banner only when no product keyword is located."""
    banner = str(banner or "")
    low = banner.lower()
    positions = [low.find(k) + len(k) for k in _PRODUCT_KEYS.get(product, ()) if k in low]
    if positions:
        return _extract_version(banner[min(positions):])
    return _extract_version(banner)


def fingerprint(probe: dict) -> tuple:
    """(product, version, version_readable, signals). A config `product` hint wins when it names a
    known product; otherwise the product is inferred from substrings in the banner/title/body/
    headers/admin-paths. version is read from the banner segment that FOLLOWS the product name.
    Everything here is pure — no network."""
    hint = str(probe.get("product_hint") or "").strip().lower()
    hay = " ".join(str(probe.get(k) or "") for k in
                   ("banner", "title", "body_snippet", "server_header", "x_powered_by")).lower()
    paths = " ".join(str(p.get("path") or "") for p in (probe.get("admin_paths") or [])).lower()
    hay = f"{hay} {paths}"

    if hint in _KNOWN_PRODUCTS:
        product, signals = hint, [f"product hint={hint}"]
    else:
        product, signals = "unknown", []
        for name, keys in _PRODUCT_SIGNS:
            matched = [k for k in keys if k in hay]
            if matched:
                product, signals = name, [f"matched {m!r}" for m in matched]
                break

    version = _extract_product_version(product, probe.get("banner") or "")
    if version is None and product == "unknown":
        version = _extract_version(hay)
    return product, version, version is not None, signals


def _admin_console(probe: dict) -> dict:
    """Reduce the admin-path probes to the console posture. `any_exposed` is the load-bearing
    signal: a management path that answered HTTP 200 WITHOUT an authentication gate — the console
    served to anyone who can reach it. A 401/403/302-to-login proves the console exists but is
    gated (reachable, not exposed)."""
    paths = probe.get("admin_paths") or []
    reachable = [p for p in paths if p.get("status") in (200, 401, 403, 302)]
    exposed = [p for p in paths if p.get("status") == 200 and p.get("auth_required") is False]
    return {
        "probed": bool(paths),
        "reachable": [{"path": p.get("path"), "status": p.get("status")} for p in reachable],
        "exposed": [{"path": p.get("path"), "status": p.get("status")} for p in exposed],
        "any_exposed": bool(exposed),
    }


# ── pure parse layer: probe dicts → Resources ─────────────────────────────────
def parse_server(probe: dict) -> Resource:
    """One MFT appliance from its probe snapshot. probe_outcome is the honest anchor: 'error'
    when unreachable, 'unfingerprinted' when reachable but no product matched, 'ok' otherwise —
    detect/mft.py maps the first two to a not-assessable coverage gap."""
    url = probe.get("base_url") or ""
    host = probe.get("host") or (urlsplit(url).hostname if url else "") or url
    scheme = probe.get("scheme") or (urlsplit(url).scheme or "https")
    product, version, version_readable, signals = fingerprint(probe)
    console = _admin_console(probe)
    tls = probe.get("tls") or {"enabled": scheme == "https", "cert_status": None,
                               "expired": None, "negotiated": None}
    api = probe.get("admin_api") or {}
    reachable = bool(probe.get("reachable"))
    outcome = "error" if not reachable else ("unfingerprinted" if product == "unknown" else "ok")

    return Resource(
        kind="mft_server",
        name=f"{product}:{host}" if product != "unknown" else (host or url or "mft-server"),
        ext_id=f"mft-server-{url or host}",
        namespace=host or None,
        labels={"product": product, "version": version or "?", "scheme": scheme,
                "admin_exposed": "true" if console["any_exposed"] else "false"},
        raw={
            "product": product,
            "product_hint": str(probe.get("product_hint") or "") or None,
            "version": version,
            "version_readable": version_readable,
            "fingerprint_signals": signals,
            "base_url": url, "host": host, "scheme": scheme, "port": probe.get("port"),
            "banner": probe.get("banner"), "server_header": probe.get("server_header"),
            "http_status": probe.get("http_status"),
            "admin_console": console,
            "admin_console_exposed": console["any_exposed"],
            "tls": tls,
            "authenticated_scan": bool(probe.get("authenticated_scan")),
            "admin_api_readable": bool(api.get("readable")),
            "admin_api_reason": api.get("reason"),
            "default_admin_present": bool(api.get("default_admin_present")),
            "probe_outcome": outcome,
            "error": probe.get("error"),
        },
    )


_WEAK_HOSTKEY_ALGOS = {"ssh-dss", "ssh-dsa", "ssh-rsa"}   # DSA, and RSA under the SHA-1 scheme


def _weak_host_key(algo, bits):
    """True/False when determinable, None when neither algorithm nor bit-length is known (→ the
    detector answers not-assessable rather than reading absence as a strong host key)."""
    if algo is None and bits is None:
        return None
    a = str(algo or "").lower()
    if a in _WEAK_HOSTKEY_ALGOS:
        return True
    # The bit-length floor applies to RSA/DSA only; Ed25519 (256-bit) and ECDSA use short keys
    # by design and are NOT weak for their length.
    if ("rsa" in a or "dss" in a or "dsa" in a) and isinstance(bits, int) and 0 < bits < 2048:
        return True
    return False


def parse_endpoint(server_ext: str, host, ep: dict) -> Resource:
    """One AS2 or SFTP listener. AS2 fields are message-security modes (sign/encrypt/MDN); SFTP
    fields are auth modes + host-key hygiene. A field left None means the admin API did not report
    it — the rule answers 'unknown', never 'insecure'."""
    etype = str(ep.get("type") or "").lower()
    name = ep.get("name") or f"{etype or 'mft'}-listener"
    raw = {"endpoint_type": etype, "name": name, "server_ext": server_ext,
           "port": ep.get("port"), "host": host}
    if etype == "as2":
        raw.update(
            message_signing=ep.get("message_signing"),
            message_encryption=ep.get("message_encryption"),
            mdn_signed=ep.get("mdn_signed"),
            tls_required=ep.get("tls_required"),
        )
    elif etype == "sftp":
        algo, bits = ep.get("host_key_algorithm"), ep.get("host_key_bits")
        raw.update(
            password_auth_allowed=ep.get("password_auth_allowed"),
            public_key_auth=ep.get("public_key_auth"),
            host_key_algorithm=algo,
            host_key_bits=bits,
            weak_host_key=_weak_host_key(algo, bits),
        )
    return Resource(
        kind="mft_endpoint",
        name=f"{etype}:{name}" if etype else name,
        ext_id=f"{server_ext}/endpoint/{etype or 'x'}/{name}",
        namespace=host,
        labels={"endpoint_type": etype},
        raw=raw,
    )


def parse_transfer_account(server_ext: str, host, acct: dict) -> Resource:
    """One partner/transfer account. A stored credential is recorded as PRESENCE + type only —
    the connector never collected the value (credential-reduction contract)."""
    name = acct.get("username") or acct.get("name") or "account"
    partner = acct.get("partner_id") or acct.get("partner")
    return Resource(
        kind="mft_transfer_account",
        name=str(name),
        ext_id=f"{server_ext}/account/{name}",
        namespace=host,
        labels={"partner": str(partner or ""),
                "anonymous": "true" if acct.get("anonymous") else "false"},
        raw={
            "username": str(name),
            "partner_id": partner,
            "auth_type": acct.get("auth_type"),
            "credential_type": acct.get("credential_type"),
            "stored_credential_present": bool(acct.get("stored_credential_present")),
            "credential_plaintext_capable": acct.get("credential_plaintext_capable"),
            "anonymous": bool(acct.get("anonymous")),
            "is_default": bool(acct.get("is_default")),
            "enabled": acct.get("enabled", True),
            "endpoint": acct.get("endpoint"),   # the listener it transfers over, by name
            "server_ext": server_ext,
        },
    )


def build_resources(probes: list) -> Collected:
    """Pure normalisation: a list of probe snapshots → Collected. server --exposes--> endpoint,
    server --has_account--> account, account --transfers_over--> endpoint (when named)."""
    resources: list[Resource] = []
    edges: list[Edge] = []
    for probe in probes or []:
        server = parse_server(probe)
        resources.append(server)
        host = (server.raw or {}).get("host")
        api = probe.get("admin_api") or {}

        ep_by_name: dict = {}
        for ep in api.get("endpoints") or []:
            e = parse_endpoint(server.ext_id, host, ep)
            resources.append(e)
            edges.append(Edge(src_ext_id=server.ext_id, dst_ext_id=e.ext_id, kind="exposes"))
            ep_by_name[(e.raw or {}).get("name")] = e.ext_id

        for acct in api.get("transfer_accounts") or []:
            a = parse_transfer_account(server.ext_id, host, acct)
            resources.append(a)
            edges.append(Edge(src_ext_id=server.ext_id, dst_ext_id=a.ext_id, kind="has_account"))
            ep_ext = ep_by_name.get((a.raw or {}).get("endpoint"))
            if ep_ext:
                edges.append(Edge(src_ext_id=a.ext_id, dst_ext_id=ep_ext, kind="transfers_over"))
    return Collected(resources=resources, edges=edges)


# ── collection: httpx in, per-target isolation ────────────────────────────────
def _normalize_url(target: str) -> str:
    t = str(target or "").strip()
    if not t:
        return t
    if "://" not in t:
        t = "https://" + t
    return t.rstrip("/")


def _ua(token) -> dict:
    h = {"Accept": "text/html,application/json", "User-Agent": "vectasec-scanner/0.1"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _extract_title(body: str):
    m = _TITLE_RE.search(body or "")
    return m.group(1).strip() if m else None


def _banner(headers, title, body) -> str:
    server = (headers.get("server") if headers else None) or ""
    return " ".join(x for x in (server, title or "") if x).strip()


def _looks_like_login(body: str) -> bool:
    b = (body or "").lower()
    return any(m in b for m in _LOGIN_MARKERS)


def _probe_admin_paths(client, base_url: str, product: str, token) -> list:
    out = []
    for path in _ADMIN_PATHS.get(product, _ADMIN_PATHS["unknown"]):
        target = base_url + path
        try:
            r = client.get(target, headers=_ua(token))
        except Exception as e:
            out.append({"path": path, "status": None, "auth_required": None,
                        "error": f"{type(e).__name__}: {e}"})
            continue
        body = r.text[:2000]
        # 200 showing a login form is GATED (auth required); 200 with real admin/API content is
        # EXPOSED. Anything else (401/403/302-to-login) is gated by definition.
        if r.status_code == 200:
            auth_required = _looks_like_login(body)
        else:
            auth_required = True
        out.append({"path": path, "status": r.status_code, "auth_required": auth_required})
    return out


def _tls_summary_live(host: str, port: int, timeout: float) -> dict:
    """What a modern client negotiates + certificate validity/expiry. cert_status stays 'unknown'
    when the probe itself fails, which the TLS rule reads as not-assessable."""
    out = {"enabled": True, "cert_status": None, "cert_error": None,
           "negotiated": None, "not_after": None, "expired": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["negotiated"] = ss.version()
                cert = ss.getpeercert() or {}
                out["cert_status"] = "valid"
                na = cert.get("notAfter")
                if na:
                    out["not_after"] = na
                    try:
                        out["expired"] = ssl.cert_time_to_seconds(na) < time.time()
                    except Exception:
                        out["expired"] = None
    except ssl.SSLCertVerificationError as e:
        out["cert_status"] = "invalid"
        out["cert_error"] = str(e)
        if "expired" in str(e).lower():
            out["expired"] = True
        lax = ssl.create_default_context()
        lax.check_hostname = False
        lax.verify_mode = ssl.CERT_NONE
        try:   # re-handshake unverified only to learn the version; the verdict is already recorded
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with lax.wrap_socket(sock, server_hostname=host) as ss:
                    out["negotiated"] = ss.version()
        except Exception:
            pass
    except Exception as e:
        out["cert_status"] = "unknown"
        out["cert_error"] = f"{type(e).__name__}: {e}"
    return out


def _read_admin_api(base_url: str, token, product: str, config: dict) -> dict:
    """Mode (c): AS2/SFTP/account config, WHERE a config/admin API is available. These are closed
    appliances with product-specific admin APIs, so rather than assert an unverified API shape the
    connector reads an operator-supplied `admin_export` (documented shape below) and leaves a hook
    for future per-product adapters. Absent both, it honestly records that it could not read.

    admin_export shape (dict): keyed by base_url or product, or a bare dict with keys:
        {"default_admin_present": bool,
         "endpoints": [{type, name, ...}], "transfer_accounts": [{username, ...}]}
    """
    export = config.get("admin_export") or {}
    if isinstance(export, dict):
        data = export.get(base_url) or export.get(product)
        if data is None and ("endpoints" in export or "transfer_accounts" in export):
            data = export
        if isinstance(data, dict):
            return {"readable": True, "source": "operator_export",
                    "default_admin_present": bool(data.get("default_admin_present")),
                    "endpoints": data.get("endpoints") or [],
                    "transfer_accounts": data.get("transfer_accounts") or []}
    if token:
        return {"readable": False,
                "reason": (f"no built-in admin-API adapter for product {product!r}; supply "
                           "config['admin_export'] to assess AS2/SFTP/account config")}
    return {"readable": False, "reason": "no admin token or admin_export supplied"}


def _probe_target(client, url: str, token, product_hint: str, timeout: float, config: dict) -> dict:
    s = urlsplit(url)
    host = s.hostname or ""
    scheme = s.scheme or "https"
    port = s.port or (443 if scheme == "https" else 80)
    probe = {"base_url": url, "host": host, "scheme": scheme, "port": port,
             "reachable": False, "error": None, "product_hint": product_hint,
             "authenticated_scan": bool(token)}
    try:
        r = client.get(url, headers=_ua(token))
    except Exception as e:
        probe["error"] = f"{type(e).__name__}: {e}"
        return probe

    body = r.text[:4000]
    probe.update(
        reachable=True,
        http_status=r.status_code,
        server_header=r.headers.get("server"),
        x_powered_by=r.headers.get("x-powered-by"),
        title=_extract_title(body),
        body_snippet=body[:512],
    )
    probe["banner"] = _banner(r.headers, probe["title"], body)

    product, _, _, _ = fingerprint(probe)
    probe["admin_paths"] = _probe_admin_paths(client, url, product, token)
    probe["tls"] = (_tls_summary_live(host, port, timeout) if scheme == "https"
                    else {"enabled": False, "cert_status": None, "expired": None,
                          "negotiated": None})
    probe["admin_api"] = _read_admin_api(url, token, product, config)
    return probe


@connector("mft", fields=[
    ConnectorField("base_urls", "Base URLs", required=True,
                   placeholder="https://mft.example.com,https://as2.example.com",
                   help="Comma-separated admin/API base URLs of the MFT appliances (MOVEit, "
                        "GoAnywhere, Cleo, Sterling File Gateway, Axway SecureTransport). Every "
                        "call is a read-only GET — no transfers, no config writes."),
    ConnectorField("product", "Product hint", placeholder="moveit",
                   help="Optional: moveit|goanywhere|cleo|sterling|axway. Leave empty to "
                        "fingerprint from the server banner and login page."),
    ConnectorField("admin_token", "Admin API token", secret=True,
                   help="Only if reading AS2/SFTP + partner-account config via the appliance "
                        "admin API. Used to open the session, never persisted into any resource."),
    ConnectorField("verify_tls", "Verify TLS", placeholder="true",
                   help="'false' to accept a self-signed appliance certificate (the cert is still "
                        "assessed and reported); defaults to verifying."),
])
def collect(config: dict) -> Collected:
    raw_targets = (config.get("base_urls") or config.get("base_url")
                   or config.get("host") or "")
    targets = [_normalize_url(t) for t in
               re.split(r"[,\n]", str(raw_targets)) if str(t).strip()]
    if not targets:
        raise SystemExit("mft connector requires config['base_urls'] (comma-separated)")

    token = config.get("admin_token") or None
    product_hint = str(config.get("product") or "").strip().lower()
    verify_tls = _truthy(config.get("verify_tls", "true"))
    timeout = float(config.get("timeout") or 15)

    probes: list[dict] = []
    with httpx.Client(timeout=timeout, follow_redirects=True, verify=verify_tls) as client:
        for url in targets:
            try:
                probes.append(_probe_target(client, url, token, product_hint, timeout, config))
            except Exception as e:
                s = urlsplit(url)
                probes.append({"base_url": url, "host": s.hostname or url,
                               "scheme": s.scheme or "https",
                               "port": s.port or 443, "reachable": False,
                               "error": f"{type(e).__name__}: {e}",
                               "product_hint": product_hint,
                               "authenticated_scan": bool(token)})
    return build_resources(probes)


# ── NHI: partner/transfer accounts → identity, stored creds → credential, grants ──
@identity_extractor("mft")
def _from_mft(resources: list) -> tuple:
    """MFT non-human identities in the normalized model:

      mft_transfer_account   → identity — a partner account (has a partner_id) is EXTERNAL; a
                               plain transfer/service account is internal
      stored credential      → ONE credential per account (metadata only — type + present +
                               plaintext_capable; the connector never collected a value)
      per-endpoint grant     → one 'transfer' grant per account, targeting the listener it uses
                               (wildcard when the account is anonymous)

    Edges: credential --credential_of--> identity, grant --granted_to--> identity, and
    grant --grants_access--> the mft_endpoint when the account names one we collected.
    """
    out: list[Resource] = []
    edges: list[Edge] = []

    ep_ext_by_name: dict = {}
    for r in resources:
        if r.kind == "mft_endpoint":
            raw = r.raw or {}
            ep_ext_by_name[(raw.get("server_ext"), raw.get("name"))] = r.ext_id

    for r in resources:
        if r.kind != "mft_transfer_account":
            continue
        raw = r.raw or {}
        name = raw.get("username") or r.name
        external = bool(raw.get("partner_id"))
        itype = "partner_account" if external else "transfer_account"
        idr = _mk_identity(
            "mft", itype, name, external=external, source_ext=r.ext_id,
            tags=(["anonymous"] if raw.get("anonymous") else []),
            extra={"partner_id": raw.get("partner_id"), "server_ext": raw.get("server_ext"),
                   "anonymous": bool(raw.get("anonymous"))})
        out.append(idr)

        if raw.get("stored_credential_present"):
            ctype = raw.get("credential_type") or "password"
            cred = _mk_credential(
                "mft", idr.ext_id, ctype, name=f"{name}:{ctype}",
                hashing="unknown", present=True,
                plaintext=raw.get("credential_plaintext_capable"))
            out.append(cred)
            edges.append(Edge(src_ext_id=cred.ext_id, dst_ext_id=idr.ext_id,
                              kind="credential_of"))

        ep_name = raw.get("endpoint")
        ep_ext = ep_ext_by_name.get((raw.get("server_ext"), ep_name))
        target = f"endpoint:{ep_name}" if ep_name else f"server:{raw.get('server_ext')}"
        g = _mk_grant("mft", idr.ext_id, "transfer", target,
                      wildcard=bool(raw.get("anonymous")),
                      extra={"auth_type": raw.get("auth_type"), "endpoint": ep_name})
        out.append(g)
        edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
        if ep_ext:
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=ep_ext, kind="grants_access"))
    return out, edges
