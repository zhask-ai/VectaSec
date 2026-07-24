"""gRPC connector — read-only server-reflection introspection + a TLS/plaintext transport probe.

gRPC is the RPC data plane between services, and its two classic exposures are (1) server
reflection left on, which hands any caller the full service+method catalogue, and (2) plaintext
h2c with no per-RPC auth. This connector asks the server to reflect (a read-only RPC — it never
invokes an application method) and probes the transport. Reflection being DISABLED is the good
outcome, and the connector records that honestly rather than treating it as a failure.

The parse layer `derive_service_facts(reflection)` is pure: a reflection result dict in, normalized
facts out (service/method counts, whether the health service is exposed). Tests feed a golden
service list to it and build `raw` dicts directly, so grpcio and a live server stay out of the
test suite.

Emits the DISTINCT kind `grpc_service` (the reflection-scanned target) so no other rulepack runs
against it by accident.

config: target 'host:port' (required), tls (toggle), token (secret), timeout, source_zone.
"""
import ipaddress
import socket
import ssl

from ..registry import ConnectorField, connector
from ..contracts import Resource, Collected

_HEALTH_SERVICE = "grpc.health.v1.Health"
_REFLECTION_SERVICES = ("grpc.reflection.v1.ServerReflection",
                        "grpc.reflection.v1alpha.ServerReflection")
_MAX_SERVICES_FOR_METHODS = 40   # cap the per-service descriptor fetches so a huge catalogue can't
                                 # turn one scan into hundreds of round-trips


# ── pure parse layer (tests feed a golden service list here) ───────────────
def derive_service_facts(reflection: dict) -> dict:
    """Normalize a reflection result into the facts the rules read. Pure."""
    services = [s for s in (reflection.get("services") or []) if isinstance(s, str)]
    methods = reflection.get("methods") or {}
    method_count = sum(len(v) for v in methods.values() if isinstance(v, list))
    app_services = [s for s in services
                    if s not in _REFLECTION_SERVICES and s != _HEALTH_SERVICE]
    return {
        "service_count": len(services),
        "app_service_count": len(app_services),
        "method_count": method_count,
        "health_service_present": _HEALTH_SERVICE in services,
        "reflection_service_present": any(s in _REFLECTION_SERVICES for s in services),
    }


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
    """Passive TLS probe (cert validity + negotiated version). gRPC-over-TLS presents its cert on
    the ordinary TLS handshake, so no ALPN negotiation is needed just to read validity."""
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


# ── reflection ─────────────────────────────────────────────────────────────
# Status codes that prove the server SPOKE gRPC (so the transport reached it), even though the
# specific call was refused — distinct from a transport/connection failure.
_SERVER_ANSWERED = {"OK", "UNIMPLEMENTED", "UNAUTHENTICATED", "PERMISSION_DENIED",
                    "INVALID_ARGUMENT", "FAILED_PRECONDITION"}


def _reflect(target, *, secure, metadata, timeout, with_methods=True) -> dict:
    """One reflection pass. Returns {reached, enabled, services, methods, status_code, error}.
    `reached` means the server answered at the gRPC layer at all (even UNIMPLEMENTED)."""
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

    out = {"reached": False, "enabled": False, "services": [], "methods": {},
           "status_code": None, "error": None}
    try:
        if secure:
            channel = grpc.secure_channel(target, grpc.ssl_channel_credentials())
        else:
            channel = grpc.insecure_channel(target)
        with channel:
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            req = reflection_pb2.ServerReflectionRequest(list_services="*")
            services = []
            for resp in stub.ServerReflectionInfo(iter([req]), timeout=timeout,
                                                  metadata=metadata or None):
                which = resp.WhichOneof("message_response")
                if which == "list_services_response":
                    out["reached"] = True
                    for s in resp.list_services_response.service:
                        services.append(s.name)
                elif which == "error_response":
                    out["reached"] = True
                    out["status_code"] = _status_name(resp.error_response.error_code)
                    out["error"] = resp.error_response.error_message
            if services:
                out["enabled"] = True
                out["status_code"] = out["status_code"] or "OK"
                out["services"] = services
                if with_methods:
                    out["methods"] = _reflect_methods(stub, services, timeout, metadata)
    except grpc.RpcError as e:
        code = e.code().name if e.code() else "UNKNOWN"
        out["status_code"] = code
        out["reached"] = code in _SERVER_ANSWERED
        out["error"] = f"{code}: {_details(e)}"
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def _reflect_methods(stub, services, timeout, metadata) -> dict:
    """Best-effort per-service method extraction from FileDescriptorProtos. Method disclosure is
    the sharpest reflection finding, but it is optional — any failure leaves methods empty."""
    import grpc
    from grpc_reflection.v1alpha import reflection_pb2
    from google.protobuf import descriptor_pb2

    methods: dict = {}
    for svc in services[:_MAX_SERVICES_FOR_METHODS]:
        if svc in _REFLECTION_SERVICES:
            continue
        try:
            req = reflection_pb2.ServerReflectionRequest(file_containing_symbol=svc)
            for resp in stub.ServerReflectionInfo(iter([req]), timeout=timeout,
                                                  metadata=metadata or None):
                if resp.WhichOneof("message_response") != "file_descriptor_response":
                    continue
                for blob in resp.file_descriptor_response.file_descriptor_proto:
                    fdp = descriptor_pb2.FileDescriptorProto()
                    fdp.ParseFromString(blob)
                    for s in fdp.service:
                        full = f"{fdp.package}.{s.name}" if fdp.package else s.name
                        if full == svc:
                            methods[svc] = [m.name for m in s.method]
        except (grpc.RpcError, Exception):
            continue
    return methods


_STATUS_NAMES = {0: "OK", 1: "CANCELLED", 2: "UNKNOWN", 3: "INVALID_ARGUMENT",
                 4: "DEADLINE_EXCEEDED", 5: "NOT_FOUND", 6: "ALREADY_EXISTS",
                 7: "PERMISSION_DENIED", 8: "RESOURCE_EXHAUSTED", 9: "FAILED_PRECONDITION",
                 10: "ABORTED", 11: "OUT_OF_RANGE", 12: "UNIMPLEMENTED", 13: "INTERNAL",
                 14: "UNAVAILABLE", 15: "DATA_LOSS", 16: "UNAUTHENTICATED"}


def _status_name(code_int) -> str:
    return _STATUS_NAMES.get(code_int, f"CODE_{code_int}")


def _details(e) -> str:
    try:
        return e.details() or ""
    except Exception:
        return str(e)


def _plaintext_probe(target, timeout) -> dict:
    """Does the server speak gRPC over cleartext h2c? A gRPC-level answer over an insecure channel
    (even UNIMPLEMENTED) proves plaintext is accepted; a transport failure means it is not."""
    ref = _reflect(target, secure=False, metadata=None, timeout=timeout, with_methods=False)
    return {"reachable": ref["reached"], "status_code": ref["status_code"], "error": ref["error"]}


# ── collect ────────────────────────────────────────────────────────────────
@connector("grpc", fields=[
    ConnectorField("target", "gRPC target", required=True, placeholder="api.example.com:443",
                   help="host:port of the gRPC server. Read-only — only server reflection is "
                        "called, never an application method."),
    ConnectorField("tls", "Use TLS", placeholder="true",
                   help="'true' to connect over TLS. The connector also checks whether plaintext "
                        "h2c is accepted regardless."),
    ConnectorField("token", "Bearer token", secret=True,
                   help="Only if the server requires per-RPC auth. Reflection is probed both with "
                        "and without it to measure unauthenticated reach."),
])
def collect(config: dict) -> Collected:
    target = (config.get("target") or "").strip()
    if not target:
        raise SystemExit("grpc connector requires config['target'] (host:port)")
    tls = str(config.get("tls", "")).strip().lower() in ("1", "true", "yes", "on")
    token = config.get("token") or None
    timeout = float(config.get("timeout") or 10.0)
    source_zone = config.get("source_zone", "unspecified")

    host, _, port_s = target.partition(":")
    port = int(port_s) if port_s.isdigit() else (443 if tls else 80)
    resolved_ip, ip_class = _resolve(host)
    token_md = [("authorization", f"Bearer {token}")] if token else None

    # Unauthenticated reflection is both a posture signal and the gate for the "no auth" rules.
    unauth = _reflect(target, secure=tls, metadata=None, timeout=timeout)
    auth = (_reflect(target, secure=tls, metadata=token_md, timeout=timeout) if token else None)
    main = auth if (auth and auth.get("enabled")) else unauth

    reflection = {
        "enabled": main.get("enabled"),
        "reached": main.get("reached"),
        "unauthenticated_ok": bool(unauth.get("enabled")),
        "authenticated_scan": bool(token),
        "services": main.get("services"),
        "methods": main.get("methods"),
        "status_code": main.get("status_code"),
        "error": main.get("error"),
        "unauth_status": unauth.get("status_code"),
    }
    facts = derive_service_facts(reflection)

    plaintext = _plaintext_probe(target, timeout)
    tls_probe = (_tls_probe(host, port, timeout) if tls
                 else {"negotiated": None, "cert_status": None, "cert_error": None})

    raw = {
        "target": target, "host": host, "port": port,
        "tls_configured": tls, "resolved_ip": resolved_ip, "ip_class": ip_class,
        "source_zone": source_zone,
        "reflection": reflection,
        **facts,
        "plaintext": plaintext,
        "tls": tls_probe,
    }

    resource = Resource(
        kind="grpc_service",
        name=target,
        ext_id=f"grpc-{target}",
        namespace=host,
        labels={"tls": "true" if tls else "false", "ip_class": ip_class,
                "reflection": "on" if reflection["enabled"] else "off",
                "service_count": str(facts["service_count"])},
        raw=raw,
    )
    return Collected(resources=[resource], edges=[])
