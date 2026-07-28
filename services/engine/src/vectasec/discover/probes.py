"""Read-only protocol fingerprints for the middleware surface.

What a probe may do, and it is a short list: open a TCP connection, send the bytes a normal
client sends BEFORE it authenticates, read one response, and hang up. That is enough, because
most middleware announces itself in the pre-auth handshake — RabbitMQ puts its version in
Connection.Start, NATS sends INFO unprompted, Elasticsearch answers `GET /` — and the whole
point of this module is to learn what is out there without holding anybody's credentials.

What a probe must NEVER do:
  * authenticate, or attempt to. No credential is sent, guessed, defaulted or sprayed. When a
    service demands auth, the refusal IS the finding ("auth required" is a good answer) and we
    stop there. A scanner that tries `guest/guest` is a brute-forcer with a nice UI.
  * write, publish, enqueue, delete, or run any command that mutates state. Reads only, and
    only reads that a health check would make.
  * follow redirects to a host outside the approved scope, or resolve its way out of scope.
  * amplify. Memcached and friends are DDoS reflectors; probes send one small request and read
    a bounded reply.

Honesty discipline (mirrors contracts.Hit): a probe reports what it READ. Where a version can
only be *inferred* — Kafka's ApiVersions exposes a capability matrix, not a version string —
the result is flagged `version_inferred` and the evidence says how it was derived. We would
rather say "Kafka ≥ 3.x, inferred from supported API keys" than invent a version nobody can
check against the wire.
"""
from __future__ import annotations

import json
import re
import socket
import ssl
import struct
from dataclasses import dataclass, field

# Bounded reads everywhere: a probe must not be talked into buffering a hostile stream.
MAX_READ = 65536
DEFAULT_TIMEOUT = 3.0


@dataclass
class ProbeResult:
    """One identified service. `evidence` entries are facts read from the wire, phrased so a
    detector can quote them straight into an immutable observation."""
    product: str
    version: str | None = None
    version_inferred: bool = False
    transport: str = "plaintext"          # plaintext | tls
    evidence: list[str] = field(default_factory=list)
    signals: dict = field(default_factory=dict)   # auth_required, sealed, tls_required, …
    raw: dict = field(default_factory=dict)


# ── socket helpers ─────────────────────────────────────────────────────────
def _connect(host: str, port: int, timeout: float, tls: bool = False):
    """A plain or TLS socket, or None. TLS verification is deliberately OFF: we are identifying
    what is listening, and a self-signed or expired certificate is a FINDING to record (see
    `tls_cert_error` in signals), not a reason to go blind to the service behind it."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except (OSError, ValueError):
        return None
    if not tls:
        return sock
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except (ssl.SSLError, OSError):
        try:
            sock.close()
        except OSError:
            pass
        return None


def _read(sock, n: int = MAX_READ) -> bytes:
    try:
        return sock.recv(min(n, MAX_READ)) or b""
    except (OSError, ssl.SSLError):
        return b""


def _close(sock) -> None:
    try:
        sock.close()
    except (OSError, ssl.SSLError):
        pass


# ── NATS ───────────────────────────────────────────────────────────────────
def probe_nats(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult | None:
    """The politest probe there is: NATS sends `INFO {json}` on connect. We send NOTHING."""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        data = _read(sock)
    finally:
        _close(sock)
    if not data.startswith(b"INFO "):
        return None
    try:
        info = json.loads(data[5:].split(b"\r\n", 1)[0].decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None

    version = info.get("version")
    auth = bool(info.get("auth_required"))
    tls_required = bool(info.get("tls_required"))
    ev = [f"NATS server announced version {version!r} in its unsolicited INFO on connect"]
    ev.append(f"INFO advertises auth_required={str(auth).lower()}")
    if tls_required:
        ev.append("INFO advertises tls_required=true")
    return ProbeResult(
        product="nats", version=version, evidence=ev,
        signals={"auth_required": auth, "tls_required": tls_required,
                 "server_id": info.get("server_id"), "jetstream": bool(info.get("jetstream"))},
        raw={"info": {k: info.get(k) for k in
                      ("server_id", "version", "go", "auth_required", "tls_required",
                       "jetstream", "max_payload", "proto", "cluster")}},
    )


# ── Redis ──────────────────────────────────────────────────────────────────
_REDIS_VERSION_RE = re.compile(rb"redis_version:([^\r\n]+)")


def probe_redis(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult | None:
    """PING, then (only if PING was answered without auth) `INFO server`.

    A `-NOAUTH` reply is a GOOD outcome: it proves a password is set, and we stop. A `+PONG`
    from an unauthenticated socket is itself the serious finding — anyone who can reach the
    port can run commands — so INFO is read to name the version that exposure applies to.
    """
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(b"PING\r\n")
        reply = _read(sock, 256)
        if not reply:
            return None

        if reply.startswith(b"-NOAUTH") or b"NOAUTH" in reply or b"operation not permitted" in reply:
            return ProbeResult(
                product="redis", version=None,
                evidence=["Redis replied -NOAUTH to an unauthenticated PING "
                          "(a password is required — no credential was sent)"],
                signals={"auth_required": True},
                raw={"ping_reply": reply[:120].decode("utf-8", "replace")},
            )
        if not reply.startswith(b"+PONG"):
            return None

        sock.sendall(b"INFO server\r\n")
        info = _read(sock)
    finally:
        _close(sock)

    m = _REDIS_VERSION_RE.search(info)
    version = m.group(1).decode("utf-8", "replace").strip() if m else None
    ev = ["Redis answered PING with +PONG on an unauthenticated connection "
          "(no password was sent, and none was demanded)"]
    if version:
        ev.append(f"`INFO server` reported redis_version:{version} to the same "
                  "unauthenticated connection")
    return ProbeResult(
        product="redis", version=version,
        evidence=ev, signals={"auth_required": False},
        raw={"info_server": info[:2000].decode("utf-8", "replace")},
    )


# ── AMQP 0-9-1 (RabbitMQ and friends) ──────────────────────────────────────
def _amqp_field_table(buf: bytes, off: int) -> tuple[dict, int]:
    """Parse an AMQP 0-9-1 field table into a flat dict of the scalar entries we care about.

    Only the value types RabbitMQ actually uses in server-properties are decoded (longstr,
    bool, nested table, signed ints); anything else aborts the parse for that entry rather than
    guessing at a length and walking off into the weeds.
    """
    out: dict = {}
    if off + 4 > len(buf):
        return out, off
    (size,) = struct.unpack_from(">I", buf, off)
    off += 4
    end = min(off + size, len(buf))
    while off < end:
        if off + 1 > end:
            break
        name_len = buf[off]
        off += 1
        name = buf[off:off + name_len].decode("utf-8", "replace")
        off += name_len
        if off >= end:
            break
        typ = buf[off:off + 1]
        off += 1
        if typ == b"S":                                    # long string
            if off + 4 > end:
                break
            (ln,) = struct.unpack_from(">I", buf, off)
            off += 4
            out[name] = buf[off:off + ln].decode("utf-8", "replace")
            off += ln
        elif typ == b"t":                                  # boolean
            out[name] = bool(buf[off])
            off += 1
        elif typ == b"F":                                  # nested table
            nested, off = _amqp_field_table(buf, off)
            out[name] = nested
        elif typ in (b"I", b"i"):                          # 32-bit int
            (out[name],) = struct.unpack_from(">i", buf, off)
            off += 4
        else:
            break                                          # unknown type: stop, do not guess
    return out, end


def probe_amqp(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult | None:
    """Send the AMQP 0-9-1 protocol header and read Connection.Start.

    The broker's server-properties — product, version, cluster_name, capabilities — arrive
    BEFORE any credential is exchanged. We read them and hang up without sending
    Connection.StartOk, which is where authentication would have begun.
    """
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(b"AMQP\x00\x00\x09\x01")
        data = _read(sock)
    finally:
        _close(sock)
    if not data or data[:1] != b"\x01":
        # A version mismatch makes the broker reply with its own header ("AMQP" + version).
        if data[:4] == b"AMQP":
            return ProbeResult(
                product="amqp", version=None,
                evidence=["the service answered the AMQP 0-9-1 protocol header with an AMQP "
                          "version header of its own (speaks AMQP, different version)"],
                raw={"header_reply": data[:16].hex()},
            )
        return None

    # frame: type(1) channel(2) size(4) | payload: class(2) method(2) major(1) minor(1) table…
    props: dict = {}
    try:
        if data[7:11] == b"\x00\x0a\x00\x0a":
            props, _ = _amqp_field_table(data, 13)
    except (struct.error, IndexError):
        props = {}

    product = str(props.get("product") or "amqp")
    version = props.get("version")
    key = "rabbitmq" if "rabbit" in product.lower() else product.lower().replace(" ", "-")
    ev = [f"AMQP Connection.Start advertised product={product!r}"
          + (f" version={version!r}" if version else "")
          + " before any credential was exchanged"]
    if props.get("cluster_name"):
        ev.append(f"Connection.Start advertised cluster_name={props['cluster_name']!r}")
    mechanisms = None
    # Connection.Start carries `mechanisms` (a longstr) after server-properties; surfacing it
    # tells an operator whether PLAIN is on the table at all.
    m = re.search(rb"(?:PLAIN|AMQPLAIN|EXTERNAL)(?:[ A-Z\-_]*)", data)
    if m:
        mechanisms = m.group(0).decode("ascii", "replace").strip()
        ev.append(f"Connection.Start offered SASL mechanisms {mechanisms!r}")
    return ProbeResult(
        product=key, version=version if isinstance(version, str) else None,
        evidence=ev,
        signals={"auth_required": True, "mechanisms": mechanisms},
        raw={"server_properties": {k: v for k, v in props.items() if not isinstance(v, dict)}},
    )


# ── Kafka ──────────────────────────────────────────────────────────────────
# ApiKey → the Kafka release that introduced it. ApiVersions (key 18) is answerable BEFORE
# authentication on purpose: a client must negotiate the protocol before it can SASL. So the
# capability matrix is readable pre-auth, and the highest key present puts a FLOOR under the
# broker version. This is a floor, never an exact version — see `version_inferred`.
_KAFKA_APIKEY_FLOOR = (
    (68, "3.7"),   # ConsumerGroupHeartbeat (KIP-848, 3.7)
    (66, "3.5"),   # ListClientMetricsResources era
    (60, "3.3"),   # DescribeCluster/metadata quorum era
    (50, "2.7"),   # DescribeUserScramCredentials
    (42, "2.4"),   # DeleteGroups/alter-partition era
    (32, "2.0"),   # DescribeConfigs/AlterConfigs GA
    (18, "0.10"),  # ApiVersions itself
)


def probe_kafka(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult | None:
    """ApiVersions v0 — the one request every Kafka broker answers before authentication."""
    client_id = b"vectasec-discovery"
    body = struct.pack(">hhi", 18, 0, 1) + struct.pack(">h", len(client_id)) + client_id
    frame = struct.pack(">i", len(body)) + body

    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(frame)
        head = _read(sock, 8)
        if len(head) < 8:
            return None
        (size,) = struct.unpack_from(">i", head, 0)
        (correlation,) = struct.unpack_from(">i", head, 4)
        if correlation != 1 or not (0 < size < MAX_READ):
            return None
        rest = b""
        while len(rest) < size - 4:
            chunk = _read(sock, size - 4 - len(rest))
            if not chunk:
                break
            rest += chunk
    except (struct.error, OSError):
        return None
    finally:
        _close(sock)

    if len(rest) < 6:
        return None
    (error_code,) = struct.unpack_from(">h", rest, 0)
    (n_apis,) = struct.unpack_from(">i", rest, 2)
    if not (0 <= n_apis <= 200):
        return None
    keys: list[int] = []
    off = 6
    for _ in range(n_apis):
        if off + 6 > len(rest):
            break
        (api_key,) = struct.unpack_from(">h", rest, off)
        keys.append(api_key)
        off += 6

    if not keys:
        return None
    top = max(keys)
    floor = next((v for k, v in _KAFKA_APIKEY_FLOOR if top >= k), None)
    ev = [f"the service answered a Kafka ApiVersions request pre-authentication with "
          f"{len(keys)} supported API keys (error_code={error_code})"]
    if floor:
        ev.append(f"the highest supported API key is {top}, which was introduced in Kafka "
                  f"{floor} — so the broker is at least {floor} (inferred from the capability "
                  "matrix; ApiVersions carries no version string)")
    return ProbeResult(
        product="kafka", version=floor, version_inferred=bool(floor),
        evidence=ev,
        signals={"api_keys": len(keys), "max_api_key": top,
                 "answers_preauth": True, "error_code": error_code},
        raw={"max_api_key": top, "api_key_count": len(keys)},
    )


# ── MQTT ───────────────────────────────────────────────────────────────────
def probe_mqtt(host: str, port: int, timeout: float = DEFAULT_TIMEOUT,
               tls: bool = False) -> ProbeResult | None:
    """A CONNECT with NO credentials, to learn whether the broker accepts anonymous clients.

    This sends no username and no password — it is not an authentication attempt and cannot
    be a guess. CONNACK 0 means the broker admitted an anonymous client, which is the finding;
    CONNACK 4/5 means it demanded credentials, which is the healthy answer. We DISCONNECT
    immediately either way and never subscribe or publish.
    """
    client_id = b"vectasec-discovery"
    payload = struct.pack(">H", len(client_id)) + client_id
    var_header = b"\x00\x04MQTT" + b"\x04" + b"\x02" + struct.pack(">H", 10)  # v3.1.1, clean session
    body = var_header + payload
    packet = b"\x10" + bytes([len(body)]) + body

    sock = _connect(host, port, timeout, tls=tls)
    if sock is None:
        return None
    try:
        sock.sendall(packet)
        data = _read(sock, 16)
        try:
            sock.sendall(b"\xe0\x00")   # DISCONNECT — leave the broker tidy
        except OSError:
            pass
    finally:
        _close(sock)

    if len(data) < 4 or data[0] != 0x20:
        return None
    code = data[3]
    accepted = code == 0
    meanings = {0: "connection accepted", 1: "unacceptable protocol version",
                2: "identifier rejected", 3: "server unavailable",
                4: "bad user name or password", 5: "not authorized"}
    ev = [f"MQTT broker answered a credential-less CONNECT with CONNACK code {code} "
          f"({meanings.get(code, 'unknown')})"]
    if accepted:
        ev.append("the broker admitted an anonymous client: no username or password was sent")
    return ProbeResult(
        product="mqtt", version=None,
        transport="tls" if tls else "plaintext",
        evidence=ev,
        signals={"anonymous_accepted": accepted, "connack_code": code,
                 "auth_required": not accepted},
        raw={"connack": data[:4].hex()},
    )


# ── Memcached ──────────────────────────────────────────────────────────────
def probe_memcached(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult | None:
    """`version\\r\\n` — one small request, one small reply. Deliberately NOT `stats`, which is
    the command every memcached UDP amplification attack abuses."""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(b"version\r\n")
        data = _read(sock, 128)
    finally:
        _close(sock)
    if not data.startswith(b"VERSION"):
        return None
    version = data[8:].decode("utf-8", "replace").strip()
    return ProbeResult(
        product="memcached", version=version or None,
        evidence=[f"memcached answered `version` with {version!r} on an unauthenticated "
                  "connection (memcached has no authentication unless SASL is enabled)"],
        signals={"auth_required": False},
        raw={"version_reply": data[:64].decode("utf-8", "replace").strip()},
    )


# ── ZooKeeper ──────────────────────────────────────────────────────────────
def probe_zookeeper(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult | None:
    """The `srvr` four-letter word. Modern ZooKeeper whitelists these off by default, so a
    refusal is a healthy answer and an answer is itself worth reporting."""
    sock = _connect(host, port, timeout)
    if sock is None:
        return None
    try:
        sock.sendall(b"srvr")
        data = _read(sock, 2048)
    finally:
        _close(sock)
    if not data:
        return None
    text = data.decode("utf-8", "replace")
    if "not executed because it is not in the whitelist" in text:
        return ProbeResult(
            product="zookeeper", version=None,
            evidence=["ZooKeeper refused the `srvr` four-letter word: it is not in "
                      "4lw.commands.whitelist (the hardened default)"],
            signals={"four_letter_words_restricted": True},
            raw={"reply": text[:200]},
        )
    m = re.search(r"Zookeeper version:\s*([^\s,]+)", text)
    if not m:
        return None
    version = m.group(1)
    return ProbeResult(
        product="zookeeper", version=version,
        evidence=[f"ZooKeeper answered the unauthenticated `srvr` four-letter word with "
                  f"version {version!r}"],
        signals={"four_letter_words_restricted": False, "auth_required": False},
        raw={"srvr": text[:800]},
    )
