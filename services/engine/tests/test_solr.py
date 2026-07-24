"""Apache Solr connector + rulepack. Offline: no httpx, no live Solr.

Golden snapshot dicts (shaped as connect/solr.py assembles from its admin-endpoint envelopes)
feed the connector's OWN pure _build_resources, so the detectors run against exactly what the
connector emits. Every rule gets FIRE / DOES-NOT-FIRE / (where relevant) NOT-ASSESSABLE.
"""
from vectasec.connect.solr import _build_resources, _parse_version
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.solr  # noqa: F401 — registers the rulepack
from vectasec.detect.solr import _authbypass_vulnerable

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("SOLR.")}

EXPECTED_RULES = {
    "SOLR.AUTH.NO_PLUGIN", "SOLR.AUTHZ.NO_PLUGIN", "SOLR.ADMIN.UNAUTHENTICATED",
    "SOLR.AUTH.BLOCK_UNKNOWN_FALSE", "SOLR.NETWORK.NO_TLS", "SOLR.VERSION.AUTH_BYPASS_CVE",
}


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=resources)


def server(**snap):
    base = {
        "base_url": "https://solr:8983", "scheme": "https",
        "system": {"lucene": {"solr-spec-version": "9.7.0"}, "mode": "solrcloud"},
        "system_readable": True,
        "authentication": {"authentication": {"class": "solr.BasicAuthPlugin",
                                              "blockUnknown": True}},
        "authentication_readable": True,
        "authorization": {"authorization": {"class": "solr.RuleBasedAuthorizationPlugin"}},
        "authorization_readable": True,
        "anon_admin_status": 401,
        "endpoint_outcomes": {"system": "ok", "authentication": "ok", "authorization": "ok"},
    }
    base.update(snap)
    return next(r for r in _build_resources(base).resources if r.kind == "solr_server")


def fire(rule_id, resource, ctx=None):
    d = RULES[rule_id]
    assert resource.kind in d.kinds
    return d.fn(resource, ctx or _ctx([resource])) or []


# ── pack shape ────────────────────────────────────────────────────────────────
def test_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


# ── version helpers + CVE ranges (verified against the Apache advisory) ───────--
def test_parse_version():
    assert _parse_version("9.4.0") == (9, 4, 0)
    assert _parse_version("8.11") == (8, 11, 0)
    assert _parse_version("nightly") is None


def test_authbypass_ranges_match_advisory():
    assert _authbypass_vulnerable("8.11.3") is True     # < 8.11.4
    assert _authbypass_vulnerable("8.11.4") is False    # fixed
    assert _authbypass_vulnerable("9.6.1") is True      # < 9.7.0
    assert _authbypass_vulnerable("9.7.0") is False     # fixed
    assert _authbypass_vulnerable("5.2.0") is False     # below the affected floor
    assert _authbypass_vulnerable("weird") is None      # unparseable → not assessable


# ── SOLR.AUTH.NO_PLUGIN ─────────────────────────────────────────────────────--
def test_no_auth_plugin_fires_when_absent():
    hits = fire("SOLR.AUTH.NO_PLUGIN",
                server(authentication={"authentication": {"class": None}}))
    assert len(hits) == 1 and hits[0].assessable


def test_no_auth_plugin_quiet_when_present():
    assert fire("SOLR.AUTH.NO_PLUGIN", server()) == []


def test_no_auth_plugin_not_assessable_when_unreadable():
    hits = fire("SOLR.AUTH.NO_PLUGIN", server(authentication={}, authentication_readable=False))
    assert len(hits) == 1 and hits[0].assessable is False


# ── SOLR.AUTHZ.NO_PLUGIN ────────────────────────────────────────────────────--
def test_no_authz_plugin_fire_pass_and_gap():
    assert len(fire("SOLR.AUTHZ.NO_PLUGIN",
                    server(authorization={"authorization": {"class": None}}))) == 1
    assert fire("SOLR.AUTHZ.NO_PLUGIN", server()) == []
    gap = fire("SOLR.AUTHZ.NO_PLUGIN", server(authorization={}, authorization_readable=False))
    assert len(gap) == 1 and gap[0].assessable is False


# ── SOLR.ADMIN.UNAUTHENTICATED ─────────────────────────────────────────────--
def test_admin_unauth_fires_on_200():
    hits = fire("SOLR.ADMIN.UNAUTHENTICATED", server(anon_admin_status=200))
    assert len(hits) == 1 and hits[0].assessable


def test_admin_unauth_quiet_on_401():
    assert fire("SOLR.ADMIN.UNAUTHENTICATED", server(anon_admin_status=401)) == []


def test_admin_unauth_not_assessable_on_error():
    hits = fire("SOLR.ADMIN.UNAUTHENTICATED", server(anon_admin_status=None))
    assert len(hits) == 1 and hits[0].assessable is False


# ── SOLR.AUTH.BLOCK_UNKNOWN_FALSE ──────────────────────────────────────────--
def test_block_unknown_false_fire_and_pass():
    hits = fire("SOLR.AUTH.BLOCK_UNKNOWN_FALSE", server(
        authentication={"authentication": {"class": "solr.BasicAuthPlugin",
                                           "blockUnknown": False}}))
    assert len(hits) == 1
    assert fire("SOLR.AUTH.BLOCK_UNKNOWN_FALSE", server()) == []   # blockUnknown True
    # no plugin at all → this rule is silent (NO_PLUGIN owns it)
    assert fire("SOLR.AUTH.BLOCK_UNKNOWN_FALSE",
                server(authentication={"authentication": {"class": None,
                                                          "blockUnknown": False}})) == []


# ── SOLR.NETWORK.NO_TLS ─────────────────────────────────────────────────────--
def test_no_tls_fire_and_pass():
    assert len(fire("SOLR.NETWORK.NO_TLS", server(scheme="http"))) == 1
    assert fire("SOLR.NETWORK.NO_TLS", server(scheme="https")) == []


# ── SOLR.VERSION.AUTH_BYPASS_CVE ───────────────────────────────────────────--
def test_version_cve_fire_pass_and_not_assessable():
    hits = fire("SOLR.VERSION.AUTH_BYPASS_CVE",
                server(system={"lucene": {"solr-spec-version": "9.4.0"}}))
    assert len(hits) == 1 and hits[0].assessable and "CVE-2024-45216" in str(hits[0].source_ref)
    assert fire("SOLR.VERSION.AUTH_BYPASS_CVE",
                server(system={"lucene": {"solr-spec-version": "9.7.0"}})) == []
    gap = fire("SOLR.VERSION.AUTH_BYPASS_CVE",
               server(system={"lucene": {"solr-spec-version": "dev"}}))
    assert len(gap) == 1 and gap[0].assessable is False
