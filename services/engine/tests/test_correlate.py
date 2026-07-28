"""Estate correlation: is this discovered service one we already monitor?

The rule this module protects is asymmetric. A false NEGATIVE (missing a shadow broker) costs
one finding. A false POSITIVE — telling a team that the broker they are already scanning is
"unmonitored" — costs the rule its credibility, and a muted rule finds nothing forever. So most
of these tests are about NOT crying wolf: the same broker reached on a different listener, a
config shape we do not parse, a connection type that could not possibly monitor that product.

`covers()` is deliberately three-valued. True and False are conclusions; None means the config
named no endpoint we understand, and the caller must file that as an unresolved question rather
than as a shadow system.
"""
import pytest

from vectasec.correlate import connection_endpoints, covers


# ═══ endpoint extraction ═══════════════════════════════════════════════════
@pytest.mark.parametrize("config,expected", [
    ({"bootstrap": "localhost:9092"}, {("localhost", 9092)}),
    ({"url": "http://localhost:15672"}, {("localhost", 15672)}),
    ({"url": "https://kafka.internal:9093/path?x=1"}, {("kafka.internal", 9093)}),
    ({"host": "10.0.0.5", "port": "6379"}, {("10.0.0.5", 6379)}),
    ({"bootstrap": "a.internal:9092,b.internal:9092"},
     {("a.internal", 9092), ("b.internal", 9092)}),
    ({"url": "amqps://user:secret@rabbit.internal:5671"}, {("rabbit.internal", 5671)}),
    ({"nothing": "useful"}, set()),
])
def test_endpoints_are_extracted_from_the_shapes_connectors_actually_use(config, expected):
    assert connection_endpoints(config) == expected


def test_a_password_in_a_url_never_becomes_a_hostname():
    """`user:pass@host` must yield the host. Parsing it as a host would put a credential into
    a finding's evidence, which is the one place it must never appear."""
    endpoints = connection_endpoints({"url": "amqp://admin:hunter2@rabbit.internal:5672"})
    assert endpoints == {("rabbit.internal", 5672)}
    assert not any("hunter2" in h for h, _ in endpoints)


def test_loopback_spellings_are_one_host():
    assert connection_endpoints({"host": "127.0.0.1"}) == {("localhost", None)}
    assert connection_endpoints({"host": "0.0.0.0"}) == {("localhost", None)}


def test_a_split_host_and_port_are_re_paired():
    """Read separately, host+port yields (host, None) — a port-agnostic match that would let
    one Redis vouch for a different Redis on the next port."""
    assert connection_endpoints({"host": "localhost", "port": "6379"}) == {("localhost", 6379)}


# ═══ coverage decisions ════════════════════════════════════════════════════
def test_the_exact_endpoint_is_covered():
    assert covers("kafka", {"bootstrap": "localhost:9092"}, "kafka", "127.0.0.1", 9092) is True


def test_a_second_listener_of_the_SAME_broker_is_covered():
    """The RabbitMQ connector talks to the management API; the AMQP port is the same broker.
    Reporting 5672 as an unmonitored system because the config named 15672 is the false
    positive that would get this rule muted."""
    conf = {"url": "http://localhost:15672"}
    assert covers("rabbitmq", conf, "rabbitmq", "127.0.0.1", 5672) is True
    assert covers("rabbitmq", conf, "rabbitmq", "127.0.0.1", 15672) is True


def test_kafkas_tls_listener_is_the_same_broker():
    assert covers("kafka", {"bootstrap": "localhost:9092"}, "kafka", "127.0.0.1", 9093) is True


def test_a_SECOND_instance_of_the_same_product_is_NOT_covered():
    """Two Redis instances on one host really are two systems. Collapsing them by product
    would hide the unmonitored one — the exact thing this capability exists to find."""
    assert covers("redis", {"host": "localhost", "port": "6379"},
                  "redis", "127.0.0.1", 6380) is False


def test_a_different_host_is_never_covered():
    assert covers("kafka", {"bootstrap": "localhost:9092"}, "kafka", "10.0.0.9", 9092) is False


def test_a_connection_cannot_cover_a_product_it_does_not_speak():
    """A Redis connection on host X says nothing about the Kafka broker on host X."""
    assert covers("redis", {"host": "localhost", "port": "6379"},
                  "kafka", "127.0.0.1", 9092) is False


def test_an_unparseable_config_is_UNKNOWN_not_uncovered():
    """Three-valued on purpose: None must never be collapsed to False by a caller."""
    assert covers("mcp", {"note": "nothing parseable"}, "mcp", "10.0.0.9", 3000) is None


def test_a_config_with_no_port_matches_the_host_rather_than_guessing_a_default():
    assert covers("redis", {"host": "10.0.0.5"}, "redis", "10.0.0.5", 6379) is True


def test_an_unknown_connector_type_still_matches_on_endpoint():
    """A type absent from the product map is not a reason to refuse a clean host:port match —
    it would manufacture shadow findings for every connector added after this file."""
    assert covers("brand-new-thing", {"url": "http://10.0.0.5:1234"},
                  "brand-new-thing", "10.0.0.5", 1234) is True
