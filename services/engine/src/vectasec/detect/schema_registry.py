"""Schema Registry rulepack — read-only REST posture.

Runs on the DISTINCT `schema_registry` kind. The registry is the schema contract layer every
producer/consumer trusts, and it is routinely deployed anonymous and on plaintext HTTP. Findings
cite what the REST API returned (the compatibility level, whether an unauthenticated read
succeeded, the URL scheme). Write-openness is never asserted — the connector issues no writes —
so it is reported as a coverage gap where relevant.
"""
from ..contracts import Hit
from ..registry import detector


@detector(kinds=["schema_registry"], rule_id="SCHEMA_REGISTRY.AUTH.ANONYMOUS", severity="high",
          title="Schema Registry is readable without authentication")
def auth_anonymous(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("anonymous_readable"):
        return []
    mode = raw.get("mode")
    return [Hit(
        observation=(
            f"schema registry at {raw.get('base_url')} served /subjects to a client sending NO "
            f"credentials, so the schema store is anonymously readable. Every registered subject "
            f"and schema — which encode topic names, field structures and often PII field labels — "
            f"is exposed to anyone who can reach the endpoint. Registry mode is {mode!r}."),
        remediation=(
            "Put the Schema Registry behind authentication (Basic auth, mTLS, or an authenticating "
            "proxy) and enforce authorization on the /subjects and /config endpoints. Restrict the "
            "registry port to trusted clients. If the registry is also in READWRITE mode, an "
            "unauthenticated client may be able to register or evolve schemas, which can break "
            "every consumer — verify write protection directly."),
        detail=(
            "Read exposure is proven (an anonymous GET succeeded). WRITE exposure is NOT tested — "
            "this scanner never issues POST/PUT/DELETE — so whether an anonymous client can also "
            "register schemas is a coverage gap to confirm out of band; mode=" + f"{mode!r}."),
        severity="high",
        source_ref={"probe": "anonymous /subjects", "mode": mode},
    )]


@detector(kinds=["schema_registry"], rule_id="SCHEMA_REGISTRY.TLS.DISABLED", severity="medium",
          title="Schema Registry is served over plaintext HTTP")
def tls_disabled(resource, ctx):
    raw = resource.raw or {}
    if raw.get("over_tls"):
        return []
    return [Hit(
        observation=(
            f"schema registry at {raw.get('base_url')} is reached over plaintext HTTP (no TLS), so "
            f"schemas and any Basic-auth credentials sent to it cross the network unencrypted and "
            f"are interceptable."),
        remediation=(
            "Serve the registry over HTTPS with a valid certificate (listeners=https://…, "
            "ssl.keystore.*) and redirect or disable the HTTP listener. If a terminating proxy "
            "provides TLS, point the scan at the HTTPS endpoint."),
        detail=("Determined from the URL scheme. A TLS-terminating proxy in front of an HTTP "
                "origin is a real exception — scan the public HTTPS URL to reflect true exposure."),
        source_ref={"scheme": "http"},
    )]


@detector(kinds=["schema_registry"], rule_id="SCHEMA_REGISTRY.COMPAT.OPEN", severity="low",
          title="Schema Registry global compatibility level is NONE — no schema-evolution safety")
def compat_open(resource, ctx):
    raw = resource.raw or {}
    compat = raw.get("compatibility_level")
    if compat is None:
        if not raw.get("config_readable"):
            return [Hit(
                observation=(f"schema registry at {raw.get('base_url')}: /config was not readable, "
                             f"so the global compatibility level could not be determined."),
                remediation=("Grant the scan read access to /config, or confirm the global "
                             "compatibility level directly (GET /config)."),
                detail="Coverage gap: /config unreadable (authentication required).",
                assessable=False,
                assessment_reason="/config unreadable, global compatibility level undetermined",
                source_ref={"endpoint": "/config"},
            )]
        return []
    if compat != "NONE":
        return []
    return [Hit(
        observation=(
            f"schema registry at {raw.get('base_url')}: the global compatibility level is NONE, so "
            f"the registry accepts any schema change — including breaking ones — without an "
            f"evolution check. A malformed or incompatible schema can be registered and break "
            f"every consumer of the affected subject."),
        remediation=(
            "Set the global compatibility level to BACKWARD (the common default) or FULL via "
            "PUT /config, and override per subject only where a looser policy is justified. NONE "
            "disables the safety Schema Registry exists to provide."),
        detail=("Integrity/availability risk, not a direct access-control exposure — hence low. "
                "NONE is sometimes set deliberately during a bulk import (mode=IMPORT); confirm it "
                "is not left on afterwards."),
        source_ref={"config_key": "compatibilityLevel", "value": "NONE"},
    )]
