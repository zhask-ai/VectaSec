"""Discovery rulepack — judging what the sweep found on the wire.

These rules are unusual in one respect: their evidence was gathered WITHOUT credentials, which
makes it unusually damning. "The broker told us its version before we authenticated" is a mild
observation; "the broker ran our command before we authenticated" is an incident. So severity
here keys off what the service was willing to do for a total stranger.

Every observation quotes a string the probe actually read off the wire (`raw.evidence`), so the
immutable ledger records the handshake, not our interpretation of it. The probes never send a
credential, so no finding here can be an artefact of us guessing a password.
"""
from ..contracts import Hit
from ..registry import detector

# Products where answering an unauthenticated client is a serious exposure rather than a
# designed-in public health endpoint. Vault's sys/health and an OpenAPI document are meant to
# be readable; a Redis that runs commands for anyone is not.
_ANON_IS_EXPOSURE = {
    "redis": ("critical", "anyone who can reach this port can run Redis commands, read every "
                          "key and rewrite the dataset"),
    "memcached": ("high", "anyone who can reach this port can read and evict cache entries"),
    "elasticsearch": ("critical", "anyone who can reach this port can read and modify every "
                                  "index"),
    "opensearch": ("critical", "anyone who can reach this port can read and modify every index"),
    "consul": ("critical", "the agent API exposes the service catalogue and, without ACLs, "
                           "the ability to register and deregister services"),
    "etcd": ("critical", "etcd holds cluster state and, in a Kubernetes estate, every Secret"),
    "zookeeper": ("high", "the ensemble's administrative surface answers unauthenticated "
                          "four-letter commands"),
    "mqtt": ("high", "the broker admits anonymous clients, which can subscribe to topics and "
                     "publish messages"),
    "rabbitmq": ("critical", "the management API answers without credentials, exposing vhosts, "
                             "users and queue contents"),
}


def _evidence(r) -> str:
    """The probe's own words, joined. These are wire facts, never conclusions."""
    return "; ".join((r.raw or {}).get("evidence") or []) or "(no evidence recorded)"


def _signals(r) -> dict:
    return (r.raw or {}).get("signals") or {}


def _ref(r, **extra) -> dict:
    raw = r.raw or {}
    return {"host": raw.get("host"), "port": raw.get("port"), "product": raw.get("product"),
            "discovered_by": "network-probe", **extra}


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.ACCESS.UNAUTHENTICATED",
          severity="critical", title="Service answered a command without authentication")
def unauthenticated_access(r, ctx) -> list:
    """The probe sent no credential. If the service acted anyway, so can anyone else."""
    raw = r.raw or {}
    product = raw.get("product") or ""
    sig = _signals(r)

    exposure = _ANON_IS_EXPOSURE.get(product)
    if not exposure:
        return []

    # `auth_required` absent means the probe could not settle the question for this product —
    # a half-completed handshake, a timeout mid-probe. The old `return []` said "checked,
    # nothing wrong" about a service we failed to interrogate, on the one rule in this pack
    # whose whole job is finding open doors.
    if "auth_required" not in sig and "anonymous_accepted" not in sig:
        return [Hit(
            observation=(f"{product} at {raw.get('host')}:{raw.get('port')} was identified, but "
                         f"the probe could not determine whether it requires authentication"),
            detail="The service answered enough to be fingerprinted but not enough to settle "
                   "whether it admits unauthenticated clients.",
            remediation=f"Add {raw.get('host')}:{raw.get('port')} as a monitored connection so "
                        "its own rulepack can read the authentication configuration directly.",
            assessable=False,
            assessment_reason="the probe could not determine the authentication requirement",
            source_ref=_ref(r, signal="auth_indeterminate"),
        )]
    answered_anonymously = (sig.get("anonymous_accepted") is True
                            or sig.get("auth_required") is False)
    if not answered_anonymously:
        return []

    severity, consequence = exposure
    return [Hit(
        observation=_evidence(r),
        detail=f"No username or password was sent by the scanner — {consequence}.",
        remediation=(f"Require authentication on {raw.get('host')}:{raw.get('port')} and put the "
                     "port behind a network boundary that only its clients can cross. If this "
                     "service is not meant to exist, decommission it — it is currently reachable."),
        severity=severity,
        source_ref=_ref(r, signal="anonymous_access"),
    )]


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.ADMIN_API.EXPOSED",
          severity="critical", title="Administrative API reachable on the network")
def admin_api_exposed(r, ctx) -> list:
    """A gateway's Admin API can rewrite every route in the estate. It belongs on loopback."""
    if not _signals(r).get("admin_api_open"):
        return []
    raw = r.raw or {}
    return [Hit(
        observation=_evidence(r),
        detail="The Kong Admin API can create, modify and delete routes, services, consumers "
               "and plugins. Reaching it is equivalent to controlling every API the gateway "
               "fronts, including disabling authentication on them.",
        remediation="Bind the Admin API to loopback (admin_listen = 127.0.0.1:8001) or put it "
                    "behind mTLS and an allowlist. Never expose it on a routable address.",
        source_ref=_ref(r, signal="admin_api_open"),
    )]


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.TRANSPORT.PLAINTEXT",
          severity="high", title="Discovered service speaks plaintext")
def plaintext_transport(r, ctx) -> list:
    """Credentials and payloads on the wire in the clear, observed rather than inferred."""
    raw = r.raw or {}
    if raw.get("transport") != "plaintext":
        return []
    # An MQTT probe on the TLS port that fell back is already reported as tls; a descriptor
    # found over http is covered here too.
    product = raw.get("product") or "service"
    return [Hit(
        observation=f"the {product} at {raw.get('host')}:{raw.get('port')} completed its "
                    f"protocol handshake over an unencrypted connection",
        detail="Anything this service's clients send — credentials, message payloads, tokens — "
               "is readable by anyone on the path.",
        remediation=f"Enable TLS on {product} and move clients to the encrypted listener, then "
                    "close the plaintext port.",
        source_ref=_ref(r, signal="plaintext_transport"),
    )]


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.TLS.UNTRUSTED_CERTIFICATE",
          severity="medium", title="TLS certificate does not validate")
def untrusted_certificate(r, ctx) -> list:
    err = _signals(r).get("tls_cert_error")
    if not err:
        return []
    raw = r.raw or {}
    return [Hit(
        observation=f"the TLS certificate served by {raw.get('host')}:{raw.get('port')} failed "
                    f"verification against the system trust store ({err})",
        detail="Clients that reach this service must either disable verification — which "
               "removes the protection TLS exists to provide — or fail to connect.",
        remediation="Serve a certificate issued by a CA the clients trust, matching the "
                    "hostname clients use, and renew it before expiry.",
        source_ref=_ref(r, signal="tls_cert_error"),
    )]


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.DISCLOSURE.PREAUTH_VERSION",
          severity="low", title="Product version disclosed before authentication")
def preauth_version_disclosure(r, ctx) -> list:
    """Low severity on its own, and deliberately so — but this is the signal that lets an
    attacker (and this product's own CVE pack) map the service to known vulnerabilities."""
    raw = r.raw or {}
    version = raw.get("version")
    if not version or raw.get("version_inferred"):
        return []
    return [Hit(
        observation=f"{raw.get('product')} at {raw.get('host')}:{raw.get('port')} disclosed "
                    f"version {version!r} to an unauthenticated connection",
        detail="A pre-auth version string lets anyone match this service against published "
               "CVEs without touching it again. It is rarely the vulnerability itself; it is "
               "how the vulnerable ones get found.",
        remediation="Where the product allows it, suppress version banners on pre-auth "
                    "responses. The durable fix is to keep the version patched, since the "
                    "banner only matters when it names something exploitable.",
        source_ref=_ref(r, signal="preauth_version", version=version),
    )]


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.API.NO_DECLARED_SECURITY",
          severity="high", title="OpenAPI document declares no authentication")
def openapi_no_security(r, ctx) -> list:
    sig = _signals(r)
    if sig.get("descriptor") != "openapi":
        return []
    if sig.get("declares_security"):
        return []
    raw = r.raw or {}
    paths = sig.get("path_count") or 0
    return [Hit(
        observation=f"the OpenAPI document served at {raw.get('host')}:{raw.get('port')} "
                    f"declares {paths} paths and no `security` requirement or "
                    "`securitySchemes` component",
        detail="The specification is what clients, gateways and code generators trust. One "
               "that declares no authentication either describes an unauthenticated API, or "
               "describes an authenticated one inaccurately — both are worth settling.",
        remediation="Declare the API's real authentication in `components.securitySchemes` and "
                    "apply it with a top-level `security` requirement. If the API genuinely "
                    "has no authentication, that is the finding to fix first.",
        source_ref=_ref(r, signal="openapi_no_security"),
    )]


@detector(kinds=["discovered_service"], rule_id="DISCOVERY.MCP.UNMANAGED_SURFACE",
          severity="medium", title="MCP endpoint found on the network")
def mcp_surface(r, ctx) -> list:
    """An MCP server is a tool surface an AI agent can be steered into calling. Finding one by
    sweep — rather than in the inventory — means nobody is watching what it exposes."""
    if _signals(r).get("descriptor") != "mcp":
        return []
    raw = r.raw or {}
    return [Hit(
        observation=_evidence(r),
        detail="MCP servers expose tools that an AI agent may invoke, which makes their tool "
               "metadata an injection surface and their permissions an identity problem. This "
               "one was found by probing, so it is not currently a monitored connection.",
        remediation=f"Add {raw.get('host')}:{raw.get('port')} as an MCP connection so its tools, "
                    "auth posture and transport are scanned by the MCP rulepack — or take it "
                    "off the network if it is not meant to be reachable.",
        source_ref=_ref(r, signal="mcp_endpoint"),
    )]


@detector(kinds=["discovery_sweep"], rule_id="DISCOVERY.SCOPE.TARGETS_REFUSED",
          severity="medium", title="Part of the declared discovery scope was not probed")
def scope_refused(r, ctx) -> list:
    """A coverage gap, filed honestly. A sweep that quietly dropped half its scope would
    otherwise render as a clean estate — the most dangerous possible lie in this product."""
    refusals = (r.raw or {}).get("refusals") or []
    if not refusals:
        return []
    listed = "; ".join(str(x) for x in refusals[:5])
    more = f" (+{len(refusals) - 5} more)" if len(refusals) > 5 else ""
    return [Hit(
        observation=f"{len(refusals)} declared target(s) were refused by the scope guardrails "
                    f"and never probed: {listed}{more}",
        detail="These addresses were not scanned, so nothing is known about them. This is a "
               "gap in coverage, not evidence that they are clean.",
        remediation="Narrow oversized ranges, correct malformed targets, and — only where you "
                    "are authorized to scan the addresses — set allow_public to include public "
                    "ranges. Then re-run discovery.",
        assessable=False,
        assessment_reason="the targets were never contacted, so their posture is unknown",
        source_ref={"refusals": refusals[:20], "signal": "scope_refused"},
    )]


@detector(kinds=["discovery_sweep"], rule_id="DISCOVERY.SCOPE.NOTHING_PROBED",
          severity="medium", title="Discovery ran with nothing in scope")
def nothing_probed(r, ctx) -> list:
    raw = r.raw or {}
    if int(raw.get("targets_probed") or 0) > 0:
        return []
    return [Hit(
        observation="the discovery sweep resolved zero probeable targets from its declared "
                    f"scope ({len(raw.get('declared_targets') or [])} target expression(s) given)",
        detail="No host was contacted, so this scan says nothing about the estate.",
        remediation="Give discovery at least one host, host:port or CIDR to probe, and check "
                    "the refusal list for targets that were rejected.",
        assessable=False,
        assessment_reason="no target was contacted, so no posture was observed",
        source_ref={"signal": "empty_scope"},
    )]
