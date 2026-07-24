"""Memcached connector — read-only over the ASCII text protocol (stdlib socket).

Memcached has no read API to speak of and no config endpoint: its posture lives in two
unauthenticated text commands this connector sends and nothing else (both are read-only —
neither mutates cache state):

  version         the server version banner ("VERSION 1.6.21")
  stats settings  the effective runtime settings — the security-relevant ones being
                  `auth_enabled_sasl` (is SASL on?), `udpport` (is the UDP amplification
                  listener on?), `tcpport`, `maxbytes`

Memcached is UNAUTHENTICATED by design: unless it was started with SASL (`-S`), any client that
can open the socket has full read/write/flush access. That is the point of the SASL check — and
of recording whether the host we reached is loopback: a non-loopback memcached with SASL off is
the classic exposed-cache / UDP-amplification finding.

No credential material exists to reduce (there are no users on the ASCII path); nothing secret is
read or stored. Kind is DISTINCT (`memcached_server`).

Split for offline testing: the two parsers are pure (text in, dict/str out), so the golden
`stats settings` fixture drives the detectors with no live socket.
"""
import ipaddress
import socket

from ..contracts import Collected, Resource
from ..registry import ConnectorField, connector


# ── pure parse layer (protocol text in, data out) ─────────────────────────────
def _parse_version(text: str):
    """The version string from a `version` reply line ('VERSION 1.6.21' -> '1.6.21')."""
    for line in (text or "").splitlines():
        line = line.strip()
        if line.upper().startswith("VERSION "):
            return line.split(None, 1)[1].strip()
    return None


def _parse_stats_settings(text: str) -> dict:
    """`stats settings` reply → {key: value}. Each data line is 'STAT <key> <value>'; the block
    terminates with 'END'. Values stay strings — the detectors interpret them."""
    out: dict = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line == "END":
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2 and parts[0] == "STAT":
            out[parts[1]] = parts[2] if len(parts) == 3 else ""
    return out


def _host_is_loopback(host: str):
    """True/False/None — whether the target host resolves only to loopback addresses. None when
    it cannot be resolved (recorded as 'unknown', never guessed)."""
    if not host:
        return None
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    addrs = []
    for i in infos:
        try:
            addrs.append(ipaddress.ip_address(i[4][0]))
        except ValueError:
            continue
    return all(a.is_loopback for a in addrs) if addrs else None


def _build_resources(host: str, port: int, *, version, settings: dict,
                     settings_readable: bool, target_is_loopback, outcomes: dict) -> Collected:
    settings = settings or {}
    udpport = settings.get("udpport")
    resource = Resource(
        kind="memcached_server",
        name=f"{host}:{port}",
        ext_id=f"memcached-{host}:{port}",
        labels={"version": str(version or "?")},
        raw={
            "host": host,
            "port": port,
            "version": version,
            "target_is_loopback": target_is_loopback,
            "settings_readable": settings_readable,
            "auth_enabled_sasl": settings.get("auth_enabled_sasl"),
            "udpport": udpport,
            "tcpport": settings.get("tcpport"),
            "maxbytes": settings.get("maxbytes"),
            "maxconns": settings.get("maxconns"),
            "num_threads": settings.get("num_threads"),
            "settings": settings,
            "endpoint_outcomes": outcomes or {},
        },
    )
    return Collected(resources=[resource], edges=[])


# ── socket I/O ────────────────────────────────────────────────────────────────
def _command(sock, line: bytes, terminators) -> str:
    """Send one text command, read until a line equals a terminator (END / ERROR / VERSION …)."""
    sock.sendall(line)
    chunks: list[bytes] = []
    sock.settimeout(sock.gettimeout())
    while True:
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        joined = b"".join(chunks)
        # stop as soon as a whole line matching a terminator has arrived
        text = joined.decode("utf-8", "replace")
        stripped = [l.strip() for l in text.splitlines()]
        if any(any(s == t or s.startswith(t + " ") for t in terminators) for s in stripped):
            if joined.endswith(b"\r\n") or joined.endswith(b"\n"):
                break
    return b"".join(chunks).decode("utf-8", "replace")


@connector("memcached", fields=[
    ConnectorField("host", "Host", required=True, placeholder="localhost",
                   help="Hostname/IP the engine or worker can reach. Read-only — sends only "
                        "`version` and `stats settings`, no key access."),
    ConnectorField("port", "Port", placeholder="11211"),
])
def collect(config: dict) -> Collected:
    host = (config.get("host") or "").strip()
    if not host:
        raise SystemExit("memcached connector requires config['host']")
    port = int(config.get("port") or 11211)
    timeout = float(config.get("timeout") or 10)

    target_is_loopback = _host_is_loopback(host)
    version = None
    settings: dict = {}
    settings_readable = False
    outcomes: dict = {}

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError as e:
        outcomes["connect"] = f"error: {type(e).__name__}: {e}"
        return _build_resources(host, port, version=None, settings={}, settings_readable=False,
                                target_is_loopback=target_is_loopback, outcomes=outcomes)

    try:
        with sock:
            try:
                version = _parse_version(_command(sock, b"version\r\n", ("VERSION", "ERROR")))
                outcomes["version"] = "ok" if version else "error"
            except OSError as e:
                outcomes["version"] = f"error: {type(e).__name__}: {e}"
            try:
                raw = _command(sock, b"stats settings\r\n", ("END", "ERROR", "CLIENT_ERROR"))
                settings = _parse_stats_settings(raw)
                settings_readable = bool(settings)
                outcomes["stats_settings"] = "ok" if settings else "error"
            except OSError as e:
                outcomes["stats_settings"] = f"error: {type(e).__name__}: {e}"
    except OSError as e:
        outcomes.setdefault("session", f"error: {type(e).__name__}: {e}")

    return _build_resources(host, port, version=version, settings=settings,
                            settings_readable=settings_readable,
                            target_is_loopback=target_is_loopback, outcomes=outcomes)
