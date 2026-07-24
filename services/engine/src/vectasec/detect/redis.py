"""Redis detectors — the highest-signal, config-time checks from the broker-hardening research.

Redis ships open by design (no auth, protected-mode as the only guard), so the P0 checks are about
what was NOT turned on. Rules run on the DISTINCT `redis_server`/`redis_user` kinds this connector
emits, so they never collide with the Kafka/Kong `broker` or RabbitMQ `user` packs.
"""
from ..contracts import Hit
from ..registry import detector

# RediShell — CVE-2025-49844, a CVSS 10.0 Lua use-after-free RCE (Wiz, Oct 2025). Patched per
# series; a version at or above its series floor is safe, below it is vulnerable.
_REDISHELL_FIXED = {(6, 2): 20, (7, 2): 11, (7, 4): 6, (8, 0): 4, (8, 2): 2}


def _parse_version(v):
    try:
        parts = [int(x) for x in str(v).split(".")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts)
    except (ValueError, TypeError):
        return None


def _redishell_vulnerable(v: str):
    """True/False if determinable, None if the version can't be parsed (→ not assessable)."""
    parsed = _parse_version(v)
    if parsed is None:
        return None
    major, minor, patch = parsed
    floor = _REDISHELL_FIXED.get((major, minor))
    if floor is None:
        # A series we don't have a floor for (e.g. very old 5.x, or a newer series): unknown.
        return None
    return patch < floor


def _default_user_nopass(ctx) -> bool:
    for u in ctx.of_kind("redis_user"):
        if (u.raw or {}).get("username") == "default":
            return bool((u.raw or {}).get("nopass"))
    # No ACL user list readable at all → Redis <6 or ACL disabled; default is historically nopass.
    return not ctx.of_kind("redis_user")


@detector(kinds=["redis_server"], rule_id="REDIS.AUTH.NO_PASSWORD", severity="critical",
          title="Redis accepts unauthenticated connections")
def no_password(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("has_requirepass") or not _default_user_nopass(ctx):
        return []
    return [Hit(
        observation=("redis has no `requirepass` set and its default user has `nopass`, so any "
                     "client that can reach the port has full access"),
        remediation=("Set a strong `requirepass`, or define ACL users with passwords and remove "
                     "`nopass` from the default user. Unauthenticated Redis is remote code and "
                     "data access to anyone who can open the socket."),
        detail="has_requirepass=False default_user=nopass",
        source_ref={"config": "requirepass", "acl": "default nopass"},
    )]


@detector(kinds=["redis_server"], rule_id="REDIS.NETWORK.PROTECTED_MODE_OFF", severity="high",
          title="Redis protected-mode is disabled")
def protected_mode_off(r, ctx) -> list:
    if str((r.raw or {}).get("protected_mode") or "").lower() != "no":
        return []
    return [Hit(
        observation="redis config `protected-mode` is `no`, removing the last guard against "
                    "unauthenticated access from non-loopback clients",
        remediation="Set `protected-mode yes` (and configure auth + `bind`). protected-mode is the "
                    "safety net that stops an unauthenticated, externally-bound Redis being wide open.",
        detail="protected-mode=no",
        source_ref={"config": "protected-mode"},
    )]


@detector(kinds=["redis_server"], rule_id="REDIS.NETWORK.BIND_ALL", severity="medium",
          title="Redis binds to all network interfaces")
def bind_all(r, ctx) -> list:
    bind = str((r.raw or {}).get("bind") or "").strip()
    # Empty bind == all interfaces (Redis default when the directive is commented out).
    if bind and "0.0.0.0" not in bind and "*" not in bind and "::" not in bind:
        return []
    return [Hit(
        observation=f"redis `bind` is '{bind or '(unset — all interfaces)'}', so the server "
                    f"listens on every interface rather than a private one",
        remediation="Bind Redis to the specific private interface it should serve, and firewall the "
                    "port. Combined with weak auth, an all-interfaces bind is internet-exposed Redis.",
        detail=f"bind={bind or '(unset)'}",
        source_ref={"config": "bind"},
    )]


@detector(kinds=["redis_server"], rule_id="REDIS.TLS.DISABLED", severity="medium",
          title="Redis has no TLS listener")
def tls_disabled(r, ctx) -> list:
    tls_port = str((r.raw or {}).get("tls_port") or "0").strip()
    if tls_port and tls_port != "0":
        return []
    return [Hit(
        observation="redis `tls-port` is 0, so client and replication traffic (including AUTH "
                    "passwords) crosses the network in plaintext",
        remediation="Enable a `tls-port` with a server certificate and require TLS for clients and "
                    "replicas. Without it, the AUTH password and every value are sniffable.",
        detail=f"tls_port={tls_port}",
        source_ref={"config": "tls-port"},
    )]


@detector(kinds=["redis_server"], rule_id="REDIS.VERSION.RCE_CVE", severity="high",
          title="Redis version is affected by the RediShell RCE (CVE-2025-49844)")
def rce_cve(r, ctx) -> list:
    version = (r.raw or {}).get("redis_version")
    vulnerable = _redishell_vulnerable(version)
    if vulnerable is False:
        return []
    if vulnerable is None:
        # Version unreadable or an unmapped series — a coverage gap, not a clean pass.
        return [Hit(
            observation=f"redis reports version '{version}'; this scanner has no RediShell patch "
                        f"floor for that series, so exposure to CVE-2025-49844 was not determined",
            remediation="Confirm the running version against the Redis advisory for CVE-2025-49844 "
                        "and patch to a fixed release (≥6.2.20 / 7.2.11 / 7.4.6 / 8.0.4 / 8.2.2).",
            detail=f"redis_version={version}",
            assessable=False,
            assessment_reason="version string not parseable to a known RediShell-patched series",
            source_ref={"info": "redis_version"},
        )]
    return [Hit(
        observation=f"redis version {version} predates the RediShell patch for its series "
                    f"(CVE-2025-49844, CVSS 10.0 Lua use-after-free RCE)",
        remediation="Upgrade to a fixed release (≥6.2.20 / 7.2.11 / 7.4.6 / 8.0.4 / 8.2.2). As a "
                    "compensating control, restrict EVAL/FUNCTION via ACL until patched.",
        detail=f"redis_version={version}",
        source_ref={"info": "redis_version", "cve": "CVE-2025-49844"},
    )]


@detector(kinds=["redis_user"], rule_id="REDIS.USER.NOPASS", severity="high",
          title="Redis ACL user has no password")
def user_nopass(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("nopass") or not raw.get("enabled"):
        return []
    return [Hit(
        observation=f"redis ACL user '{raw.get('username')}' is enabled with `nopass` — it "
                    f"authenticates with no credential",
        remediation="Give the user a password (or disable it). A `nopass` ACL user is a credential-"
                    "free door into whatever keys and commands its rules allow.",
        detail=f"username={raw.get('username')} keys={raw.get('keys')} commands={raw.get('commands')}",
        source_ref={"acl_user": raw.get("username")},
    )]
