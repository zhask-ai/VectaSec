"""Cross-fabric TLS / certificate-lifecycle sweep — the virtual cert asset every connector feeds.

Connectors already record what they observed about transport security and write it into the
resource: an MCP server carries a live handshake result (``raw.tls`` = negotiated version, cert
status/error, downgrade floor); an MFT appliance the same plus an ``expired`` flag; an Azure
namespace its ``minimum_tls_version`` floor; an MSK cluster its client-broker encryption mode; an
Apigee proxy its per-target ``ssl_enabled``/``protocols``; a k8s Ingress/Gateway its TLS blocks.
This pack reads those recorded facts — it never opens a socket — and grades them uniformly.

Rules (rule ids under ``TLS.*``):
  * TLS.CERT.EXPIRED     — the recorded cert is expired.
  * TLS.CERT.UNTRUSTED   — self-signed / untrusted chain / hostname mismatch (and the
                           not-assessable owner when a handshake was attempted but failed).
  * TLS.PROTOCOL.WEAK    — negotiated/floor/minimum protocol below TLS 1.2.
  * TLS.LISTENER.MISSING — an endpoint that should be TLS is served in plaintext.
  * TLS.MTLS.PERMISSIVE  — transit encryption accepts both TLS and plaintext (silent downgrade).

Honesty discipline (contracts.Hit): every observation states a value the connector RECORDED
("Azure reports minimumTlsVersion=1.0"), never a conclusion. Where a connector recorded no usable
cert/TLS data for a resource that should carry it, the finding is not-assessable — a coverage gap,
never an invented pass or fail. Each not-assessable case is owned by exactly one rule so a single
resource never files the same gap twice.

Not emitted by design: a weak-CIPHER rule. No connector currently records the negotiated cipher
suite, so such a rule could only ever return not-assessable on every TLS resource — noise, not
signal. It is documented here as a known coverage gap instead. Likewise cert 'expiring < 30 days'
is only computable where a connector records ``not_after``; today none expose enough for a reliable
day-count, so expiry grading is limited to the boolean ``expired`` an MFT probe already computes.
"""
from ..contracts import Hit
from ..registry import detector

# Protocol name → numeric rank. Anything below 1.2 is weak. Covers the shapes connectors emit:
# ssl.SSLSocket.version() ('TLSv1.2'), Azure ARM ('1.2' / 'TLS1_2'), Apigee protocol strings.
_TLS_NUM = {
    "sslv2": 0.2, "sslv3": 0.3,
    "tlsv1": 1.0, "tlsv1.0": 1.0, "tls1.0": 1.0, "1.0": 1.0,
    "tlsv1.1": 1.1, "tls1.1": 1.1, "1.1": 1.1,
    "tlsv1.2": 1.2, "tls1.2": 1.2, "1.2": 1.2,
    "tlsv1.3": 1.3, "tls1.3": 1.3, "1.3": 1.3,
}


def _tls_num(s):
    """Protocol string → number, or None when it isn't a recognised version token."""
    if s is None:
        return None
    key = str(s).strip().lower().replace(" ", "").replace("_", ".")
    return _TLS_NUM.get(key)


def _weak_proto(s) -> bool:
    n = _tls_num(s)
    return n is not None and n < 1.2


def _scheme(r) -> str:
    raw, labels = r.raw or {}, r.labels or {}
    return str(raw.get("scheme") or labels.get("scheme") or "").lower()


def _classify_cert_error(err) -> str:
    e = str(err or "").lower()
    if "expired" in e:
        return "expired"
    if "self-signed" in e or "self signed" in e:
        return "self_signed"
    if "hostname mismatch" in e or "doesn't match" in e or "does not match" in e \
            or "ip address mismatch" in e:
        return "hostname_mismatch"
    return "untrusted_chain"


def _cert_probe(r):
    """(is_tls_endpoint, cert_status, cert_error, expired) for a resource that records a cert
    handshake, or None for kinds that don't. cert_status ∈ {valid, invalid, unknown, None}."""
    raw = r.raw or {}
    if r.kind == "mcp_server":
        tls = raw.get("tls") or {}
        return (_scheme(r) == "https", tls.get("cert_status"), tls.get("cert_error"), None)
    if r.kind == "mft_server":
        tls = raw.get("tls") or {}
        https = bool(tls.get("enabled")) or _scheme(r) == "https"
        return (https, tls.get("cert_status"), tls.get("cert_error"), tls.get("expired"))
    return None


# ── TLS.CERT.EXPIRED ───────────────────────────────────────────────────────────
@detector(kinds=["mcp_server", "mft_server"], rule_id="TLS.CERT.EXPIRED", severity="high",
          title="TLS certificate is expired")
def cert_expired(r, ctx) -> list:
    probe = _cert_probe(r)
    if probe is None:
        return []
    is_tls, status, err, expired = probe
    if not is_tls:
        return []
    fired = expired is True or (status == "invalid" and _classify_cert_error(err) == "expired")
    if not fired:
        return []
    detail = "expired=true" if expired is True else f"cert_error={err!r}"
    return [Hit(
        observation=(f"{r.kind} '{r.name}' presented an expired TLS certificate "
                     f"({detail}); clients that verify certificates will refuse the connection"),
        remediation=("Renew and deploy the server certificate, and automate renewal so it cannot "
                     "lapse again. An expired cert either breaks clients or trains them to skip "
                     "verification — both are worse than the outage."),
        detail=detail,
        source_ref={"tls": "cert_status/expired"},
    )]


# ── TLS.CERT.UNTRUSTED ─────────────────────────────────────────────────────────
@detector(kinds=["mcp_server", "mft_server"], rule_id="TLS.CERT.UNTRUSTED", severity="medium",
          title="TLS certificate is self-signed or fails chain/hostname validation")
def cert_untrusted(r, ctx) -> list:
    probe = _cert_probe(r)
    if probe is None:
        return []
    is_tls, status, err, expired = probe
    if not is_tls:
        return []
    if status == "invalid" and expired is not True and _classify_cert_error(err) != "expired":
        cls = _classify_cert_error(err)
        kind_txt = {"self_signed": "a self-signed certificate",
                    "hostname_mismatch": "a certificate whose name does not match the host",
                    "untrusted_chain": "a certificate that does not chain to a trusted CA"}[cls]
        return [Hit(
            observation=(f"{r.kind} '{r.name}' presented {kind_txt}: certificate validation "
                         f"failed with {err!r}"),
            remediation=("Install a certificate issued by a CA the clients trust (or distribute the "
                         "internal CA to them). Self-signed or untrusted certs push operators toward "
                         "disabling verification, which removes the protection TLS exists to give."),
            detail=f"cert_status=invalid class={cls} cert_error={err!r}",
            source_ref={"tls": "cert_status/cert_error"},
        )]
    if status == "unknown":
        # A handshake was attempted but could not complete → we could not settle cert validity.
        return [Hit(
            observation=(f"{r.kind} '{r.name}' TLS handshake did not complete "
                         f"(cert_error={err!r}); certificate trust could not be determined"),
            remediation=("Confirm the endpoint is reachable over TLS and re-scan so certificate "
                         "validity can be assessed."),
            detail=f"cert_status=unknown cert_error={err!r}",
            assessable=False,
            assessment_reason="TLS handshake failed, so certificate trust was not settled",
            source_ref={"tls": "cert_status"},
        )]
    return []


# ── TLS.PROTOCOL.WEAK ──────────────────────────────────────────────────────────
@detector(kinds=["mcp_server", "mft_server", "azure_servicebus_namespace",
                 "azure_eventhub_namespace", "gcp_apigee_proxy"],
          rule_id="TLS.PROTOCOL.WEAK", severity="high",
          title="TLS endpoint permits a protocol below TLS 1.2")
def protocol_weak(r, ctx) -> list:
    raw = r.raw or {}
    kind = r.kind

    if kind in ("mcp_server", "mft_server"):
        tls = raw.get("tls") or {}
        negotiated, floor = tls.get("negotiated"), tls.get("floor")
        if _weak_proto(negotiated) or _weak_proto(floor):
            worst = negotiated if _weak_proto(negotiated) else floor
            return [Hit(
                observation=(f"{kind} '{r.name}' TLS is weak: recorded {worst!r}, below TLS 1.2"),
                remediation=("Disable SSLv3/TLS 1.0/1.1 and require TLS 1.2+ (prefer 1.3). Sub-1.2 "
                             "protocols have practical downgrade and decryption attacks."),
                detail=f"negotiated={negotiated!r} floor={floor!r}",
                source_ref={"tls": "negotiated/floor"},
            )]
        return []

    if kind in ("azure_servicebus_namespace", "azure_eventhub_namespace"):
        mtv = raw.get("minimum_tls_version")
        if mtv is None:
            return [Hit(
                observation=(f"{kind} '{r.name}' did not report a minimumTlsVersion, so its TLS "
                             f"floor could not be determined"),
                remediation=("Read the namespace's minimumTlsVersion and set it to 1.2 to confirm "
                             "the floor."),
                detail="minimum_tls_version=None",
                assessable=False,
                assessment_reason="minimumTlsVersion absent from the collected properties",
                source_ref={"config_key": "minimumTlsVersion"},
            )]
        if _weak_proto(mtv):
            return [Hit(
                observation=(f"{kind} '{r.name}' reports minimumTlsVersion={mtv!r}, so it still "
                             f"accepts connections below TLS 1.2"),
                remediation="Set the namespace minimumTlsVersion to 1.2.",
                detail=f"minimum_tls_version={mtv!r}",
                source_ref={"config_key": "minimumTlsVersion"},
            )]
        return []

    if kind == "gcp_apigee_proxy":
        if raw.get("targets_readable") is False:
            return []                                   # not-assessable is owned by LISTENER.MISSING
        weak = []
        for t in raw.get("targets") or []:
            bad = [p for p in (t.get("protocols") or []) if _weak_proto(p)]
            if bad:
                weak.append((t.get("name") or t.get("url"), bad))
        if weak:
            listed = "; ".join(f"{name}: {protos}" for name, protos in weak)
            return [Hit(
                observation=(f"Apigee proxy '{r.name}' has target endpoint(s) configured for a "
                             f"protocol below TLS 1.2 ({listed})"),
                remediation=("Restrict each TargetEndpoint sSLInfo.protocols to TLSv1.2/TLSv1.3."),
                detail=f"weak_targets={listed}",
                source_ref={"config_key": "sSLInfo.protocols"},
            )]
        return []
    return []


# ── TLS.LISTENER.MISSING ───────────────────────────────────────────────────────
@detector(kinds=["mcp_server", "mft_server", "aws_msk_cluster", "gcp_apigee_proxy",
                 "k8s_ingress", "k8s_gateway"],
          rule_id="TLS.LISTENER.MISSING", severity="medium",
          title="An endpoint that should use TLS is served in plaintext")
def listener_missing(r, ctx) -> list:
    raw, labels, kind = r.raw or {}, r.labels or {}, r.kind

    if kind == "mcp_server":
        if _scheme(r) == "https":
            return []
        return [Hit(
            observation=(f"MCP server '{r.name}' is served over plaintext HTTP (scheme={_scheme(r)!r}), "
                         f"so requests and any bearer token cross the network unencrypted"),
            remediation="Serve the MCP endpoint over HTTPS and redirect/deny plaintext HTTP.",
            detail=f"scheme={_scheme(r)!r}", severity="high",
            source_ref={"config_key": "scheme"},
        )]

    if kind == "mft_server":
        tls = raw.get("tls") or {}
        if tls.get("enabled") or _scheme(r) == "https":
            return []
        return [Hit(
            observation=(f"MFT appliance '{r.name}' admin/API endpoint is served over plaintext "
                         f"(tls.enabled={tls.get('enabled')!r}, scheme={_scheme(r)!r})"),
            remediation="Front the MFT admin/API surface with TLS and disable plaintext access.",
            detail=f"tls_enabled={tls.get('enabled')!r} scheme={_scheme(r)!r}", severity="high",
            source_ref={"config_key": "tls.enabled"},
        )]

    if kind == "aws_msk_cluster":
        mode = str(raw.get("encryption_in_transit_client_broker") or "").upper()
        if not mode:
            return [Hit(
                observation=(f"MSK cluster '{r.name}' did not report an in-transit client-broker "
                             f"encryption mode, so plaintext exposure could not be determined"),
                remediation="Read the cluster EncryptionInTransit.ClientBroker setting.",
                detail="encryption_in_transit_client_broker=None",
                assessable=False,
                assessment_reason="ClientBroker encryption mode absent from the collected cluster",
                source_ref={"api": "EncryptionInTransit.ClientBroker"},
            )]
        if mode == "PLAINTEXT":
            return [Hit(
                observation=(f"MSK cluster '{r.name}' client-broker encryption is PLAINTEXT, so "
                             f"producer/consumer traffic is unencrypted"),
                remediation="Set EncryptionInTransit.ClientBroker to TLS.",
                detail="encryption_in_transit_client_broker=PLAINTEXT", severity="high",
                source_ref={"api": "EncryptionInTransit.ClientBroker"},
            )]
        return []

    if kind == "gcp_apigee_proxy":
        if raw.get("targets_readable") is False:
            return [Hit(
                observation=(f"Apigee proxy '{r.name}' target endpoint configs were not readable, "
                             f"so backend TLS could not be determined"),
                remediation="Grant read access to the proxy's TargetEndpoint configuration and re-scan.",
                detail="targets_readable=false",
                assessable=False,
                assessment_reason="TargetEndpoint configs unreadable, so backend TLS is unknown",
                source_ref={"api": "TargetEndpoint"},
            )]
        plain = [(t.get("name") or t.get("url")) for t in (raw.get("targets") or [])
                 if t.get("ssl_enabled") is False]
        if plain:
            return [Hit(
                observation=(f"Apigee proxy '{r.name}' calls backend target(s) over plaintext HTTP "
                             f"(sSLInfo.enabled=false): {plain}"),
                remediation="Enable sSLInfo on each TargetEndpoint so backend calls use TLS.",
                detail=f"plaintext_targets={plain}",
                source_ref={"config_key": "sSLInfo.enabled"},
            )]
        return []

    if kind == "k8s_ingress":
        if str(labels.get("tls") or "").lower() == "false":
            return [Hit(
                observation=(f"Ingress '{r.name}' defines no spec.tls block, so it serves HTTP "
                             f"without TLS termination"),
                remediation="Add a spec.tls entry (and a certificate) so the ingress terminates TLS.",
                detail="labels.tls=false",
                source_ref={"config_key": "spec.tls"},
            )]
        return []

    if kind == "k8s_gateway":
        bad = [l for l in (raw.get("listeners") or [])
               if str(l.get("protocol") or "").upper() in ("HTTPS", "TLS") and not l.get("has_tls")]
        if bad:
            names = [l.get("name") for l in bad]
            return [Hit(
                observation=(f"Gateway '{r.name}' has HTTPS/TLS listener(s) with no TLS config "
                             f"(spec.listeners[].tls empty): {names}"),
                remediation="Populate each HTTPS/TLS listener's tls block (mode + certificateRefs).",
                detail=f"listeners_without_tls={names}",
                source_ref={"config_key": "spec.listeners.tls"},
            )]
        return []
    return []


# ── TLS.MTLS.PERMISSIVE ────────────────────────────────────────────────────────
@detector(kinds=["aws_msk_cluster"], rule_id="TLS.MTLS.PERMISSIVE", severity="medium",
          title="Transit encryption permits both TLS and plaintext (downgrade)")
def mtls_permissive(r, ctx) -> list:
    raw = r.raw or {}
    mode = str(raw.get("encryption_in_transit_client_broker") or "").upper()
    if not mode or mode in ("TLS", "PLAINTEXT"):
        # None → not-assessable is owned by TLS.LISTENER.MISSING; TLS/PLAINTEXT are unambiguous.
        return []
    if mode == "TLS_PLAINTEXT":
        return [Hit(
            observation=(f"MSK cluster '{r.name}' client-broker encryption is TLS_PLAINTEXT, so it "
                         f"accepts BOTH encrypted and plaintext clients — a client can silently use "
                         f"the plaintext path"),
            remediation="Set EncryptionInTransit.ClientBroker to TLS so plaintext clients are refused.",
            detail="encryption_in_transit_client_broker=TLS_PLAINTEXT",
            source_ref={"api": "EncryptionInTransit.ClientBroker"},
        )]
    return []
