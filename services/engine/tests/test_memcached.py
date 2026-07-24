"""Memcached connector + rulepack. Offline: no socket, no live memcached.

The two protocol parsers are pure, so a golden `stats settings` text block drives the detectors.
Every rule gets FIRE / DOES-NOT-FIRE / (where relevant) NOT-ASSESSABLE.
"""
from vectasec.connect.memcached import (_build_resources, _parse_stats_settings,
                                        _parse_version)
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.memcached  # noqa: F401 — registers the rulepack

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("MEMCACHED.")}

EXPECTED_RULES = {
    "MEMCACHED.AUTH.NO_SASL", "MEMCACHED.NETWORK.UDP_ENABLED",
    "MEMCACHED.NETWORK.NON_LOOPBACK_BIND", "MEMCACHED.SERVER.NOT_ASSESSED",
}

# Golden `stats settings` reply — an exposed, unauthenticated, UDP-on server.
STATS_INSECURE = """STAT maxbytes 67108864
STAT maxconns 1024
STAT tcpport 11211
STAT udpport 11211
STAT verbosity 0
STAT num_threads 4
STAT auth_enabled_sasl no
END
"""

STATS_SECURE = """STAT maxbytes 67108864
STAT tcpport 11211
STAT udpport 0
STAT auth_enabled_sasl yes
END
"""


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def server(*, host="cache.internal", port=11211, version="1.6.21",
           stats_text=STATS_INSECURE, settings_readable=True, target_is_loopback=False,
           outcomes=None):
    settings = _parse_stats_settings(stats_text) if stats_text is not None else {}
    col = _build_resources(host, port, version=version, settings=settings,
                           settings_readable=settings_readable if stats_text is not None else False,
                           target_is_loopback=target_is_loopback,
                           outcomes=outcomes or {"version": "ok", "stats_settings": "ok"})
    return col.resources[0]


def fire(rule_id, resource, ctx=None):
    d = RULES[rule_id]
    assert resource.kind in d.kinds
    return d.fn(resource, ctx or _ctx([resource])) or []


# ── pack shape + parsers ────────────────────────────────────────────────────--
def test_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_parsers():
    assert _parse_version("VERSION 1.6.21\r\n") == "1.6.21"
    assert _parse_version("ERROR\r\n") is None
    s = _parse_stats_settings(STATS_INSECURE)
    assert s["auth_enabled_sasl"] == "no" and s["udpport"] == "11211" and s["tcpport"] == "11211"


# ── MEMCACHED.AUTH.NO_SASL ──────────────────────────────────────────────────--
def test_no_sasl_fire_and_pass():
    assert len(fire("MEMCACHED.AUTH.NO_SASL", server(stats_text=STATS_INSECURE))) == 1
    assert fire("MEMCACHED.AUTH.NO_SASL", server(stats_text=STATS_SECURE)) == []


def test_no_sasl_not_assessable_when_setting_absent():
    text = "STAT tcpport 11211\nSTAT udpport 0\nEND\n"
    hits = fire("MEMCACHED.AUTH.NO_SASL", server(stats_text=text))
    assert len(hits) == 1 and hits[0].assessable is False


def test_no_sasl_not_assessable_when_unreadable():
    hits = fire("MEMCACHED.AUTH.NO_SASL", server(stats_text=None))
    assert len(hits) == 1 and hits[0].assessable is False


# ── MEMCACHED.NETWORK.UDP_ENABLED ──────────────────────────────────────────--
def test_udp_fire_and_pass():
    assert len(fire("MEMCACHED.NETWORK.UDP_ENABLED", server(stats_text=STATS_INSECURE))) == 1
    assert fire("MEMCACHED.NETWORK.UDP_ENABLED", server(stats_text=STATS_SECURE)) == []


def test_udp_not_assessable_when_absent_and_unreadable():
    hits = fire("MEMCACHED.NETWORK.UDP_ENABLED", server(stats_text=None))
    assert len(hits) == 1 and hits[0].assessable is False


# ── MEMCACHED.NETWORK.NON_LOOPBACK_BIND ────────────────────────────────────--
def test_non_loopback_fire_pass_and_gap():
    assert len(fire("MEMCACHED.NETWORK.NON_LOOPBACK_BIND",
                    server(target_is_loopback=False))) == 1
    assert fire("MEMCACHED.NETWORK.NON_LOOPBACK_BIND", server(target_is_loopback=True)) == []
    gap = fire("MEMCACHED.NETWORK.NON_LOOPBACK_BIND", server(target_is_loopback=None))
    assert len(gap) == 1 and gap[0].assessable is False


# ── MEMCACHED.SERVER.NOT_ASSESSED ──────────────────────────────────────────--
def test_server_not_assessed_gap_and_quiet():
    gap = fire("MEMCACHED.SERVER.NOT_ASSESSED",
               server(stats_text=None, outcomes={"connect": "error: boom"}))
    assert len(gap) == 1 and gap[0].assessable is False
    assert fire("MEMCACHED.SERVER.NOT_ASSESSED", server(stats_text=STATS_INSECURE)) == []
