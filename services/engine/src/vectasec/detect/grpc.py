"""gRPC rulepack — detectors over what connect/grpc.py read from a gRPC server.

Server reflection being DISABLED is the good outcome, so the reflection rules stay silent on a
hardened server and the auth rule instead records a coverage gap (it could not enumerate methods
to assess per-RPC auth) while noting that reflection-off is the recommended posture. Every
observation states a value read off the wire; nothing here concludes.
"""
from ..registry import detector
from ..contracts import Hit


def _reachable(raw) -> bool:
    """Did the target answer at the gRPC layer at all this scan? Used to separate 'hardened' from
    'unreachable' — an unreachable target must never read as a clean pass."""
    ref = raw.get("reflection") or {}
    return bool(ref.get("reached") or (raw.get("plaintext") or {}).get("reachable"))


@detector(kinds=["grpc_service"], rule_id="GRPC.REFLECTION.EXPOSED", severity="medium",
          title="gRPC server reflection is enabled")
def reflection_exposed(r, ctx) -> list:
    raw = r.raw or {}
    ref = raw.get("reflection") or {}
    if ref.get("enabled"):
        return [Hit(
            observation=f"gRPC server {raw.get('target')} answered server reflection, disclosing "
                        f"{raw.get('service_count')} service(s) and {raw.get('method_count')} "
                        f"method(s)",
            remediation="Disable server reflection in production builds (do not register the "
                        "reflection service, or gate it to internal networks). Reflection publishes "
                        "the complete service and method catalogue to any caller.",
            detail=f"service_count={raw.get('service_count')} method_count={raw.get('method_count')}",
            source_ref={"api": "grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"},
        )]
    # Reflection did not return a catalogue. If the server never answered at all, that is a
    # coverage gap; if it answered UNIMPLEMENTED, reflection is off — the good case, stay silent.
    if not _reachable(raw):
        return [Hit(
            observation=f"gRPC target {raw.get('target')} did not answer reflection or a plaintext "
                        f"probe (status {ref.get('status_code')}); reflection state undetermined",
            remediation="Confirm the target is reachable from the scanner and re-run.",
            detail=f"status_code={ref.get('status_code')} error={ref.get('error')}",
            assessable=False,
            assessment_reason="target did not answer at the gRPC layer",
            source_ref={"api": "ServerReflectionInfo"},
        )]
    return []


@detector(kinds=["grpc_service"], rule_id="GRPC.REFLECTION.UNAUTHENTICATED", severity="high",
          title="gRPC server reflection answers without authentication")
def reflection_unauthenticated(r, ctx) -> list:
    raw = r.raw or {}
    ref = raw.get("reflection") or {}
    if not ref.get("unauthenticated_ok"):
        return []
    return [Hit(
        observation=f"gRPC server {raw.get('target')} answered a reflection request with NO "
                    f"credentials, listing {raw.get('service_count')} service(s)",
        remediation="Require call credentials (per-RPC token/mTLS) before answering reflection, and "
                    "disable reflection in production. Unauthenticated reflection is a free map of "
                    "every RPC an attacker can then target.",
        detail=f"unauthenticated_ok=True service_count={raw.get('service_count')}",
        source_ref={"api": "ServerReflectionInfo (no metadata)"},
    )]


@detector(kinds=["grpc_service"], rule_id="GRPC.HEALTH.EXPOSED", severity="low",
          title="gRPC health service is exposed")
def health_exposed(r, ctx) -> list:
    raw = r.raw or {}
    ref = raw.get("reflection") or {}
    if not raw.get("health_service_present"):
        return []
    if ref.get("unauthenticated_ok"):
        detail = "reachable without credentials"
    else:
        detail = "present in the reflected service list"
    return [Hit(
        observation=f"gRPC server {raw.get('target')} exposes grpc.health.v1.Health ({detail})",
        remediation="Restrict the health-check service to internal callers (e.g. a separate "
                    "listener or network policy). An exposed health endpoint aids liveness probing "
                    "and target discovery by attackers.",
        detail="grpc.health.v1.Health present",
        severity="low",
        source_ref={"service": "grpc.health.v1.Health"},
    )]


@detector(kinds=["grpc_service"], rule_id="GRPC.TRANSPORT.PLAINTEXT", severity="high",
          title="gRPC server accepts plaintext (h2c) connections")
def transport_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    pt = raw.get("plaintext") or {}
    if pt.get("reachable") is None:
        return [Hit(
            observation=f"plaintext-transport probe of {raw.get('target')} was inconclusive "
                        f"(error: {pt.get('error')})",
            remediation="Confirm whether the server accepts cleartext h2c and enforce TLS if so.",
            detail=f"plaintext_status={pt.get('status_code')}",
            assessable=False,
            assessment_reason="plaintext probe did not complete",
            source_ref={"transport": "h2c"},
        )]
    if not pt.get("reachable"):
        return []
    if (raw.get("ip_class") or "") == "loopback":
        return []   # a loopback dev server over h2c is not a network exposure
    return [Hit(
        observation=f"gRPC server {raw.get('target')} answered a request over cleartext h2c "
                    f"(no TLS); host resolves to a {raw.get('ip_class')} address",
        remediation="Terminate gRPC over TLS only and refuse h2c. Over plaintext, every message and "
                    "any per-RPC bearer token crosses the network in the clear.",
        detail=f"plaintext_reachable=True status={pt.get('status_code')} tls_configured={raw.get('tls_configured')}",
        source_ref={"transport": "h2c (insecure channel)"},
    )]


@detector(kinds=["grpc_service"], rule_id="GRPC.TLS.CERT_INVALID", severity="medium",
          title="gRPC TLS certificate does not validate")
def tls_cert_invalid(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("tls_configured"):
        return []
    tls = raw.get("tls") or {}
    if tls.get("cert_status") == "valid":
        return []
    if tls.get("cert_status") == "invalid":
        return [Hit(
            observation=f"gRPC server {raw.get('target')} presented a TLS certificate that failed "
                        f"validation: {tls.get('cert_error')}",
            remediation="Install a certificate that chains to a trusted CA and matches the hostname. "
                        "An invalid/self-signed cert forces clients to disable verification, "
                        "reopening the door to man-in-the-middle.",
            detail=f"cert_status=invalid negotiated={tls.get('negotiated')}",
            source_ref={"transport": "TLS"},
        )]
    return [Hit(
        observation=f"gRPC server {raw.get('target')} TLS certificate validity could not be "
                    f"determined ({tls.get('cert_error')})",
        remediation="Confirm the TLS certificate chains to a trusted CA and matches the hostname.",
        detail=f"cert_status={tls.get('cert_status')}",
        assessable=False,
        assessment_reason="TLS handshake did not complete cleanly",
        source_ref={"transport": "TLS"},
    )]


@detector(kinds=["grpc_service"], rule_id="GRPC.AUTH.NO_PER_RPC_SIGNAL", severity="medium",
          title="gRPC per-RPC authentication could not be confirmed")
def no_per_rpc_signal(r, ctx) -> list:
    raw = r.raw or {}
    ref = raw.get("reflection") or {}
    # Positive finding: reflection answered with no credentials — at least that RPC has no auth.
    if ref.get("unauthenticated_ok"):
        return [Hit(
            observation=f"gRPC server {raw.get('target')} served a reflection RPC with no call "
                        f"credentials, so at least one RPC path enforces no per-call authentication",
            remediation="Enforce per-RPC authentication (token metadata or mTLS) via a server "
                        "interceptor on every service, and verify it on application methods — this "
                        "scan can only see that reflection itself was unauthenticated.",
            detail="reflection answered unauthenticated",
            source_ref={"api": "ServerReflectionInfo (no metadata)"},
        )]
    # Reflection is off (the recommended hardening) or required auth: we cannot enumerate methods to
    # test per-RPC auth. Record the coverage gap and note reflection-off is the good posture.
    if not _reachable(raw):
        return []   # unreachable target is handled by the reflection rule; avoid double-reporting
    return [Hit(
        observation=f"gRPC server {raw.get('target')} did not expose an unauthenticated reflection "
                    f"catalogue (reflection status {ref.get('status_code')}), so individual RPC "
                    f"methods could not be enumerated to test per-RPC authentication",
        remediation="No action if reflection is intentionally disabled — that is the recommended "
                    "hardening. Verify per-RPC auth is enforced by an interceptor through your own "
                    "integration tests, which this passive scan cannot substitute for.",
        detail=f"reflection_enabled={ref.get('enabled')} unauthenticated_ok={ref.get('unauthenticated_ok')}",
        assessable=False,
        assessment_reason="reflection disabled/authenticated — RPC methods not enumerable for a "
                          "per-RPC auth check (reflection-off is itself good posture)",
        source_ref={"api": "ServerReflectionInfo"},
    )]
