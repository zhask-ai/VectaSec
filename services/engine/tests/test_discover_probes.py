"""Protocol fingerprint parsing, against golden bytes. No sockets are opened.

The fixtures are real wire captures in miniature: an AMQP Connection.Start field table, a Kafka
ApiVersions v0 response, a NATS INFO line, Redis inline replies, an MQTT CONNACK. Parsing them
offline is the only way to test the interesting half of a probe — a live test would prove that
somebody's local RabbitMQ was up, which is not a property of this code.

Two behaviours matter beyond "did it parse":
  * NO CREDENTIAL IS EVER SENT. `test_*_sends_only_*` asserts on the exact bytes written, so a
    future edit that adds an auth step to "improve detection" fails here rather than turning
    this product into a credential sprayer.
  * INFERENCE IS LABELLED. Kafka's version is derived from a capability matrix, so it must come
    back with version_inferred=True — an exact-looking version we cannot actually read is a lie
    the CVE pack would then act on.
"""
import json
import struct

import pytest

from vectasec.discover import probes as P


class FakeSocket:
    """Replays scripted responses and records everything written."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.closed = False

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        return self.replies.pop(0) if self.replies else b""

    def close(self):
        self.closed = True


@pytest.fixture
def fake_conn(monkeypatch):
    """Installs a fake `_connect`. Returns a setter; the handle exposes the last socket."""
    class Handle:
        sock = None
        refuse = False

    h = Handle()

    def factory(replies):
        def _connect(host, port, timeout, tls=False):
            if h.refuse:
                return None
            h.sock = FakeSocket(replies)
            return h.sock
        monkeypatch.setattr(P, "_connect", _connect)
        return h

    return factory


# ═══ NATS: the probe that sends nothing at all ═════════════════════════════
NATS_INFO = (b'INFO {"server_id":"NAAB","version":"2.10.22","go":"go1.22","auth_required":true,'
             b'"tls_required":false,"jetstream":true,"max_payload":1048576}\r\n')


def test_nats_reads_version_and_sends_nothing(fake_conn):
    h = fake_conn([NATS_INFO])
    r = P.probe_nats("h", 4222)
    assert r.product == "nats" and r.version == "2.10.22"
    assert r.signals["auth_required"] is True
    assert h.sock.sent == [], "the NATS probe must send NOTHING — the server speaks first"
    assert h.sock.closed


def test_nats_ignores_a_service_that_is_not_nats(fake_conn):
    fake_conn([b"HTTP/1.1 200 OK\r\n\r\n"])
    assert P.probe_nats("h", 4222) is None


def test_a_refused_connection_is_not_an_error(fake_conn):
    h = fake_conn([NATS_INFO])
    h.refuse = True
    assert P.probe_nats("h", 4222) is None


# ═══ Redis ═════════════════════════════════════════════════════════════════
def test_redis_noauth_reply_is_recorded_as_healthy_and_stops_there(fake_conn):
    """A password-protected Redis is the GOOD case: one PING, no INFO, no credential."""
    h = fake_conn([b"-NOAUTH Authentication required.\r\n"])
    r = P.probe_redis("h", 6379)
    assert r.signals["auth_required"] is True and r.version is None
    assert h.sock.sent == [b"PING\r\n"], "must not probe further once auth is demanded"


def test_redis_unauthenticated_pong_reads_the_version(fake_conn):
    h = fake_conn([b"+PONG\r\n", b"# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n"])
    r = P.probe_redis("h", 6379)
    assert r.version == "7.2.4" and r.signals["auth_required"] is False
    assert h.sock.sent == [b"PING\r\n", b"INFO server\r\n"]
    assert "no password was sent" in " ".join(r.evidence)


def test_redis_probe_never_sends_a_credential_or_a_write(fake_conn):
    h = fake_conn([b"+PONG\r\n", b"redis_version:7.2.4\r\n"])
    P.probe_redis("h", 6379)
    blob = b" ".join(h.sock.sent).upper()
    for forbidden in (b"AUTH", b"SET ", b"DEL ", b"FLUSH", b"CONFIG SET"):
        assert forbidden not in blob


# ═══ AMQP: pre-auth version leak, and no StartOk ═══════════════════════════
def _amqp_short(name: str) -> bytes:
    return bytes([len(name)]) + name.encode()


def _amqp_longstr(value: str) -> bytes:
    return b"S" + struct.pack(">I", len(value)) + value.encode()


def _amqp_connection_start(product="RabbitMQ", version="3.13.7", cluster="rabbit@node") -> bytes:
    table = (_amqp_short("product") + _amqp_longstr(product)
             + _amqp_short("version") + _amqp_longstr(version)
             + _amqp_short("cluster_name") + _amqp_longstr(cluster))
    payload = (b"\x00\x0a\x00\x0a" + b"\x00\x09"
               + struct.pack(">I", len(table)) + table
               + struct.pack(">I", len("PLAIN AMQPLAIN")) + b"PLAIN AMQPLAIN")
    return b"\x01\x00\x00" + struct.pack(">I", len(payload)) + payload + b"\xce"


def test_amqp_reads_product_and_version_before_authenticating(fake_conn):
    h = fake_conn([_amqp_connection_start()])
    r = P.probe_amqp("h", 5672)
    assert r.product == "rabbitmq" and r.version == "3.13.7"
    assert "before any credential was exchanged" in " ".join(r.evidence)


def test_amqp_sends_only_the_protocol_header_and_never_start_ok(fake_conn):
    """Connection.StartOk is where a client sends its SASL response. We must never get there."""
    h = fake_conn([_amqp_connection_start()])
    P.probe_amqp("h", 5672)
    assert h.sock.sent == [b"AMQP\x00\x00\x09\x01"]


def test_amqp_reports_the_cluster_name_when_the_broker_offers_it(fake_conn):
    fake_conn([_amqp_connection_start(cluster="rabbit@prod-1")])
    r = P.probe_amqp("h", 5672)
    assert any("rabbit@prod-1" in e for e in r.evidence)


def test_amqp_version_mismatch_still_identifies_the_protocol(fake_conn):
    fake_conn([b"AMQP\x00\x00\x0a\x00"])
    r = P.probe_amqp("h", 5672)
    assert r.product == "amqp" and r.version is None


def test_a_truncated_amqp_frame_does_not_raise(fake_conn):
    fake_conn([b"\x01\x00\x00\x00\x00\x00\x05\x00\x0a"])
    P.probe_amqp("h", 5672)     # must not raise


# ═══ Kafka: inference must be labelled as inference ════════════════════════
def _kafka_apiversions(max_key: int, error_code: int = 0) -> bytes:
    keys = list(range(0, max_key + 1))
    body = struct.pack(">i", 1) + struct.pack(">h", error_code) + struct.pack(">i", len(keys))
    for k in keys:
        body += struct.pack(">hhh", k, 0, 9)
    return struct.pack(">i", len(body)) + body


def test_kafka_infers_a_version_floor_and_says_that_it_inferred_it(fake_conn):
    frame = _kafka_apiversions(81)
    fake_conn([frame[:8], frame[8:]])
    r = P.probe_kafka("h", 9092)
    assert r.product == "kafka"
    assert r.version_inferred is True, "ApiVersions carries no version string — never claim one"
    assert r.version == "3.7"
    assert "inferred" in " ".join(r.evidence)


def test_kafka_probe_sends_one_apiversions_request_and_no_sasl(fake_conn):
    frame = _kafka_apiversions(60)
    h = fake_conn([frame[:8], frame[8:]])
    P.probe_kafka("h", 9092)
    assert len(h.sock.sent) == 1
    api_key = struct.unpack_from(">h", h.sock.sent[0], 4)[0]
    assert api_key == 18, "ApiVersions only; SaslHandshake (17) would begin authentication"


def test_kafka_ignores_a_reply_whose_correlation_id_does_not_match(fake_conn):
    """A mismatched correlation id means we are not talking to Kafka — or not to our own
    request. Either way, parsing it as a capability matrix would invent an estate."""
    body = struct.pack(">i", 999) + struct.pack(">h", 0) + struct.pack(">i", 0)
    frame = struct.pack(">i", len(body)) + body
    fake_conn([frame[:8], frame[8:]])
    assert P.probe_kafka("h", 9092) is None


def test_kafka_with_no_api_keys_is_not_identified(fake_conn):
    frame = _kafka_apiversions(-1)   # zero keys
    fake_conn([frame[:8], frame[8:]])
    assert P.probe_kafka("h", 9092) is None


# ═══ MQTT: a credential-less CONNECT, and the CONNACK is the answer ════════
def test_mqtt_anonymous_accepted_is_flagged(fake_conn):
    h = fake_conn([b"\x20\x02\x00\x00"])
    r = P.probe_mqtt("h", 1883)
    assert r.signals["anonymous_accepted"] is True
    assert r.signals["auth_required"] is False
    assert "admitted an anonymous client" in " ".join(r.evidence)


def test_mqtt_not_authorized_is_the_healthy_answer(fake_conn):
    fake_conn([b"\x20\x02\x00\x05"])
    r = P.probe_mqtt("h", 1883)
    assert r.signals["anonymous_accepted"] is False
    assert r.signals["auth_required"] is True


def test_mqtt_connect_carries_no_username_or_password_flags(fake_conn):
    """Bits 6 and 7 of the CONNECT flags byte are username/password. Both must be zero — a set
    bit would mean the probe is attempting authentication."""
    h = fake_conn([b"\x20\x02\x00\x00"])
    P.probe_mqtt("h", 1883)
    connect = h.sock.sent[0]
    flags = connect[9]
    assert flags & 0x80 == 0, "username flag set — the probe must never authenticate"
    assert flags & 0x40 == 0, "password flag set — the probe must never authenticate"


def test_mqtt_disconnects_cleanly_rather_than_holding_the_session(fake_conn):
    h = fake_conn([b"\x20\x02\x00\x00"])
    P.probe_mqtt("h", 1883)
    assert h.sock.sent[-1] == b"\xe0\x00"


# ═══ memcached and ZooKeeper ═══════════════════════════════════════════════
def test_memcached_version_is_read_with_the_non_amplifying_command(fake_conn):
    h = fake_conn([b"VERSION 1.6.21\r\n"])
    r = P.probe_memcached("h", 11211)
    assert r.version == "1.6.21"
    assert h.sock.sent == [b"version\r\n"]
    assert b"stats" not in b" ".join(h.sock.sent), "`stats` is the amplification command"


def test_zookeeper_whitelist_refusal_is_reported_as_the_hardened_state(fake_conn):
    fake_conn([b"srvr is not executed because it is not in the whitelist.\n"])
    r = P.probe_zookeeper("h", 2181)
    assert r.signals["four_letter_words_restricted"] is True
    assert r.version is None


def test_zookeeper_answering_four_letter_words_yields_a_version(fake_conn):
    fake_conn([b"Zookeeper version: 3.8.4-abc, built on 01/01/2024\nLatency min/avg/max: 0/0/0\n"])
    r = P.probe_zookeeper("h", 2181)
    assert r.version == "3.8.4-abc"
    assert r.signals["four_letter_words_restricted"] is False
