"""Memcached rulepack — config-time posture over what connect/memcached.py collected.

Every rule reads REAL evidence from the `stats settings` reply (or the connection target) and
cites it. Rules run on the DISTINCT `memcached_server` kind. Memcached ships unauthenticated with
UDP historically on, so the P0 checks are about what was NOT turned off. When the setting a rule
needs was not in the reply (an older build, or SASL refused the ASCII command), the rule returns
assessable=False — a coverage gap, never a silent pass.
"""
from ..contracts import Hit
from ..registry import detector


@detector(kinds=["memcached_server"], rule_id="MEMCACHED.AUTH.NO_SASL", severity="high",
          title="Memcached has no SASL authentication")
def no_sasl(r, ctx) -> list:
    raw = r.raw or {}
    val = raw.get("auth_enabled_sasl")
    if val is None:
        if not raw.get("settings_readable"):
            return [Hit(
                observation=("`stats settings` was not readable, so whether SASL authentication "
                             "is enabled could not be determined (an enforced SASL setup can "
                             "itself refuse the ASCII command)"),
                remediation="Confirm the server is reachable and, if SASL is enforced, verify it "
                            "out of band; otherwise re-run the scan.",
                detail="auth_enabled_sasl=absent settings_readable=False",
                assessable=False,
                assessment_reason="stats settings did not return auth_enabled_sasl",
                source_ref={"command": "stats settings", "field": "auth_enabled_sasl"},
            )]
        return [Hit(
            observation=("`stats settings` did not report `auth_enabled_sasl`, so SASL "
                         "authentication status could not be determined on this build"),
            remediation="Verify the memcached build and whether it was started with `-S` (SASL).",
            detail="auth_enabled_sasl=absent",
            assessable=False,
            assessment_reason="auth_enabled_sasl not present in stats settings",
            source_ref={"command": "stats settings", "field": "auth_enabled_sasl"},
        )]
    if str(val).lower() in ("yes", "1", "true", "on"):
        return []
    loopback = raw.get("target_is_loopback")
    return [Hit(
        observation=(f"memcached reports `auth_enabled_sasl {val}` — no SASL authentication is "
                     f"configured, so any client that can open the socket has full "
                     f"read/write/flush access to the cache"
                     + ("" if loopback else " (and the reached host is not loopback)")),
        severity="high",
        remediation=("Start memcached with SASL enabled (`-S`, binary protocol) and require "
                     "authentication, or — since SASL is coarse — firewall the port to only the "
                     "application hosts and never expose it to untrusted networks."),
        detail=f"auth_enabled_sasl={val} target_is_loopback={loopback}",
        source_ref={"command": "stats settings", "field": "auth_enabled_sasl"},
    )]


@detector(kinds=["memcached_server"], rule_id="MEMCACHED.NETWORK.UDP_ENABLED", severity="high",
          title="Memcached UDP listener is enabled")
def udp_enabled(r, ctx) -> list:
    raw = r.raw or {}
    udpport = raw.get("udpport")
    if udpport is None:
        if not raw.get("settings_readable"):
            return [Hit(
                observation="`stats settings` was not readable, so whether the UDP listener is "
                            "enabled could not be determined",
                remediation="Confirm the server is reachable and re-run the scan.",
                detail="udpport=absent settings_readable=False",
                assessable=False,
                assessment_reason="stats settings did not return udpport",
                source_ref={"command": "stats settings", "field": "udpport"},
            )]
        return []
    try:
        port = int(udpport)
    except (ValueError, TypeError):
        return []
    if port == 0:
        return []
    return [Hit(
        observation=(f"memcached reports `udpport {port}` — the UDP listener is enabled. UDP "
                     f"memcached is spoofable and was the vector for record-setting reflection/"
                     f"amplification DDoS attacks, and it accepts commands with no handshake"),
        remediation=("Disable UDP: start memcached with `-U 0`. UDP has been off by default "
                     "since 1.5.6; there is almost never a reason to run it, and it turns the "
                     "cache into a DDoS amplifier."),
        detail=f"udpport={port}",
        source_ref={"command": "stats settings", "field": "udpport"},
    )]


@detector(kinds=["memcached_server"], rule_id="MEMCACHED.NETWORK.NON_LOOPBACK_BIND",
          severity="medium", title="Memcached is reachable on a non-loopback interface")
def non_loopback_bind(r, ctx) -> list:
    raw = r.raw or {}
    loopback = raw.get("target_is_loopback")
    if loopback is None:
        return [Hit(
            observation=(f"the memcached host '{raw.get('host')}' could not be resolved, so "
                         f"whether it is bound only to loopback could not be determined"),
            remediation="Confirm the intended bind address and firewall for the cache port.",
            detail=f"host={raw.get('host')} target_is_loopback=unknown",
            assessable=False,
            assessment_reason="target host did not resolve to any address",
            source_ref={"target": raw.get("host")},
        )]
    if loopback:
        return []
    return [Hit(
        observation=(f"memcached answered at non-loopback host '{raw.get('host')}:"
                     f"{raw.get('port')}' — it is listening on a network-reachable interface. "
                     f"Combined with unauthenticated access, that is a directly exposed cache"),
        remediation=("Bind memcached to the private interface it must serve (`-l "
                     "<private-ip>`, or `-l 127.0.0.1` if only local) and firewall the port. An "
                     "all-interfaces bind plus no SASL is internet-exposed memcached."),
        detail=f"host={raw.get('host')} port={raw.get('port')} target_is_loopback=False",
        source_ref={"target": f"{raw.get('host')}:{raw.get('port')}"},
    )]


@detector(kinds=["memcached_server"], rule_id="MEMCACHED.SERVER.NOT_ASSESSED", severity="info",
          title="Memcached settings could not be read")
def server_not_assessed(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("settings_readable"):
        return []
    outcomes = raw.get("endpoint_outcomes") or {}
    return [Hit(
        observation=(f"`stats settings` did not return a settings block "
                     f"(outcomes={outcomes}), so the server's posture could not be assessed"),
        remediation=("Confirm the engine can reach the memcached port and that the server "
                     "responds to the ASCII `stats settings` command; if SASL is enforced it may "
                     "refuse ASCII commands, which itself indicates authentication is on."),
        detail=f"settings_readable=False outcomes={outcomes}",
        assessable=False,
        assessment_reason="stats settings returned no data",
        source_ref={"command": "stats settings"},
    )]
