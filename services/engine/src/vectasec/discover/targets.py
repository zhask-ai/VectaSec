"""Scope resolution for network discovery — the guardrail layer, deliberately its own module.

A posture scanner that probes networks is one config typo away from being a scanning weapon
pointed at somebody else's infrastructure. So scope is resolved here, once, by pure functions
with no sockets in sight, and every probe in `discover/probes.py` receives only what this
module has already approved. The rules, in order of importance:

  1. NOTHING IMPLICIT. There is no "scan my network" mode. The operator names hosts or CIDRs;
     an empty target list resolves to an empty sweep, never to a default range.
  2. PRIVATE BY DEFAULT. A target outside RFC1918 / loopback / link-local / CGNAT / unique-local
     is REFUSED unless the operator sets `allow_public: true`, which exists so the refusal is a
     deliberate, auditable decision rather than an accident. Scanning the public internet is a
     thing you must say out loud.
  3. BOUNDED. `MAX_HOSTS` caps the expansion of any one scan. A /16 is 65k hosts; a fat-fingered
     mask must fail loudly at parse time, not melt a network at 3am and get us subpoenaed.
  4. HONEST REFUSALS. Every rejection returns a human-readable reason that names the target and
     the rule it broke. The connector surfaces these — a silently-dropped target is a coverage
     gap the operator thinks they do not have.

Nothing here authenticates, writes, or exploits. See `probes.py` for the equally strict rules
that govern what a probe may send once a target is approved.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# The hard ceiling on hosts one discovery scan may expand to. A /22 (1024 addresses) is a
# generous single subnet; anything larger is a scope decision that deserves several scans and
# several deliberate approvals rather than one heroic sweep.
MAX_HOSTS = 1024

# Ports we REFUSE to contact, even when explicitly named. This list is not about politeness;
# each entry is a documented way to cause harm by connecting at all:
#
#   9100-9107 — raw print (JetDirect). These ports print whatever bytes reach them. This is
#               the ONLY hardcoded exclusion Nmap ships in nmap-service-probes
#               (`Exclude T:9100-9107`), and it is there because probing them emits paper.
#   1414-1416 — IBM MQ. The queue manager treats any non-MQ bytes as a corrupt client and
#               writes an AMQ9207E plus an FFST/FDC diagnostic file; at many sites those
#               auto-open a support ticket. IBM shipped APAR IT30348 (the
#               AMQ_NO_BAD_COMMS_DATA_FDCS env var) specifically to mute scanner noise. We
#               cannot speak MQ's handshake without being a real client, so the honest
#               choice is not to knock.
#   515, 631  — LPD and IPP: printers again.
#
# A refused port is reported in `Scope.refusals`, so declining to scan is visible rather than
# silently narrowing the sweep.
EXCLUDED_PORTS: frozenset[int] = frozenset(
    set(range(9100, 9108)) | {1414, 1415, 1416, 515, 631}
)

# Ports probed when a target names no port of its own. Kept to the middleware surface this
# product understands — a general-purpose port sweep is somebody else's tool, and every extra
# port is another connection to somebody's fragile legacy broker.
DEFAULT_PORTS: tuple[int, ...] = (
    1883,   # MQTT
    2181,   # ZooKeeper
    2379,   # etcd
    4222,   # NATS
    5432,   # PgBouncer / Postgres wire
    5672,   # AMQP (RabbitMQ)
    6379,   # Redis
    6650,   # Pulsar binary
    8001,   # Kong admin
    8080,   # HTTP admin surfaces (Keycloak, Pulsar admin, ActiveMQ console)
    8161,   # ActiveMQ web console
    8200,   # Vault
    8500,   # Consul
    8883,   # MQTT over TLS
    9000,   # misc HTTP admin
    9092,   # Kafka
    9200,   # Elasticsearch
    11211,  # Memcached
    15672,  # RabbitMQ management
    61616,  # ActiveMQ OpenWire
)

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
                          r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


@dataclass(frozen=True)
class Target:
    """One approved (host, port) to probe.

    `source` is the operator's original string, kept so a finding can say which line of their
    config produced it. `explicit` marks a port the operator named THEMSELVES rather than one
    that came from the default set — which the sweep treats as a licence to work harder to
    identify it, because shadow middleware is precisely what does not sit on a standard port.
    """
    host: str
    port: int
    source: str
    explicit: bool = False


@dataclass
class Scope:
    """The result of resolving an operator's target list: what will be probed, and every
    refusal with its reason. Both halves are surfaced — see the module docstring."""
    targets: list[Target] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)

    @property
    def hosts(self) -> set[str]:
        return {t.host for t in self.targets}


def _is_private(host: str) -> bool | None:
    """True/False for a literal IP; None for a hostname (we do NOT resolve here).

    Resolution is deliberately not done in the guardrail: a DNS lookup is a network call, it
    can change between check and connect (rebinding), and a scanner that decides scope from a
    name the target controls has no scope at all. Hostnames are instead governed by the
    `allow_public` flag alone — the operator vouches for them explicitly.
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def _split_host_port(raw: str) -> tuple[str, int | None]:
    """`host`, `host:port`, `[v6]:port`, `[v6]`, `cidr` → (host-or-cidr, port|None).

    IPv6 must be bracketed to carry a port, exactly as in a URL — otherwise `::1:6379` is
    ambiguous and would silently probe the wrong thing.
    """
    s = raw.strip()
    if s.startswith("["):
        end = s.find("]")
        if end == -1:
            raise ValueError("unterminated '[' in IPv6 target")
        host = s[1:end]
        rest = s[end + 1:]
        if rest.startswith(":"):
            return host, int(rest[1:])
        return host, None
    # A bare IPv6 address has several colons; only a single colon means host:port.
    if s.count(":") == 1:
        host, _, port = s.partition(":")
        return host, int(port)
    return s, None


def resolve_scope(targets, ports=None, allow_public: bool = False,
                  max_hosts: int = MAX_HOSTS) -> Scope:
    """Expand the operator's target list into approved (host, port) pairs.

    `targets` accepts hosts, `host:port`, and CIDRs. `ports` overrides DEFAULT_PORTS for
    targets that carry no port of their own. Refusals never raise — they are collected, so one
    bad line does not void a scan the operator otherwise scoped correctly.
    """
    scope = Scope()
    port_list = tuple(ports) if ports else DEFAULT_PORTS
    if not port_list:
        scope.refusals.append("no ports to probe: `ports` was set to an empty list")
        return scope

    seen: set[tuple[str, int]] = set()
    for raw in targets or []:
        raw = str(raw or "").strip()
        if not raw:
            continue

        try:
            host_part, explicit_port = _split_host_port(raw)
        except ValueError as e:
            scope.refusals.append(f"{raw!r}: {e}")
            continue

        if explicit_port is not None and not (1 <= explicit_port <= 65535):
            scope.refusals.append(f"{raw!r}: port {explicit_port} is out of range")
            continue

        # ── CIDR ──────────────────────────────────────────────────────────
        if "/" in host_part:
            try:
                net = ipaddress.ip_network(host_part, strict=False)
            except ValueError as e:
                scope.refusals.append(f"{raw!r}: not a valid CIDR ({e})")
                continue
            if not (net.is_private or net.is_loopback or net.is_link_local) and not allow_public:
                scope.refusals.append(
                    f"{raw!r}: refused — public address space. Scanning hosts you do not own is "
                    "not something this tool does by accident: set allow_public=true to declare "
                    "you are authorized to scan this range.")
                continue
            addresses = list(net.hosts()) or [net.network_address]
            if len(addresses) > max_hosts:
                scope.refusals.append(
                    f"{raw!r}: refused — expands to {len(addresses)} hosts, over the {max_hosts} "
                    "cap. Split it into smaller ranges so the scope stays something a human "
                    "reviewed.")
                continue
            candidates = [str(a) for a in addresses]
        # ── single host or IP ─────────────────────────────────────────────
        else:
            private = _is_private(host_part)
            if private is None and not _HOSTNAME_RE.match(host_part):
                scope.refusals.append(f"{raw!r}: not a valid host, IP or CIDR")
                continue
            if private is False and not allow_public:
                scope.refusals.append(
                    f"{raw!r}: refused — public IP. Set allow_public=true to declare you are "
                    "authorized to scan it.")
                continue
            candidates = [host_part]

        is_explicit = explicit_port is not None
        target_ports = (explicit_port,) if is_explicit else port_list
        for host in candidates:
            for port in target_ports:
                key = (host, port)
                if key in seen:
                    continue
                seen.add(key)
                if port in EXCLUDED_PORTS:
                    # Refused even when named explicitly: connecting IS the harm here. See
                    # EXCLUDED_PORTS for the per-port reason.
                    if is_explicit:
                        scope.refusals.append(
                            f"{raw!r}: refused — port {port} is on the do-not-contact list "
                            "(raw print, or a broker that logs a diagnostic file for any "
                            "unrecognised bytes). Connecting to it is itself the harm.")
                    continue
                scope.targets.append(
                    Target(host=host, port=port, source=raw, explicit=is_explicit))

    if len(scope.hosts) > max_hosts:
        # Reachable by summing several in-cap targets. The cap is on the scan, not the line.
        scope.refusals.append(
            f"refused — the targets together expand to {len(scope.hosts)} hosts, over the "
            f"{max_hosts} cap. Nothing was probed; narrow the scope.")
        scope.targets = []
    return scope
