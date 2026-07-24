"""Flink connector + rulepack — offline. Detectors run on parse_cluster() output from golden
REST dicts (/overview + /jobmanager/config).
"""
from vectasec.contracts import ScanContext
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.flink import parse_cluster
import vectasec.detect.flink as rp

BASE = "http://flink:8081"


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def _jm(**kv):
    return [{"key": k, "value": v} for k, v in kv.items()]


def cluster(*, version="1.14.0", jm=None, tls_url=False, anonymous_readable=False,
            config_readable=True):
    overview = {"flink-version": version, "taskmanagers": 2, "slots-total": 8, "jobs-running": 1}
    jm_config = jm if jm is not None else _jm(**{"web.submit.enable": "true",
                                                 "security.ssl.rest.enabled": "false"})
    return parse_cluster(BASE, overview, jm_config, tls_url=tls_url,
                         anonymous_readable=anonymous_readable, config_readable=config_readable)


def test_connector_registered_and_secret_marked():
    assert "flink" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["flink"]}
    assert fields["password"].secret and fields["url"].required


# ── FLINK.REST.UNAUTHENTICATED ─────────────────────────────────────────────────
def test_rest_unauthenticated_fires_critical():
    c = cluster(anonymous_readable=True)
    hits = rp.rest_unauthenticated(c, _ctx([c]))
    assert len(hits) == 1 and "job submission" in hits[0].observation


def test_rest_authenticated_does_not_fire():
    assert rp.rest_unauthenticated(cluster(anonymous_readable=False), _ctx([])) == []


# ── FLINK.WEB.SUBMIT_ENABLED ───────────────────────────────────────────────────
def test_web_submit_enabled_fires_medium_when_authenticated():
    c = cluster(anonymous_readable=False, jm=_jm(**{"web.submit.enable": "true"}))
    hits = rp.web_submit_enabled(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].severity == "medium"


def test_web_submit_escalates_to_high_when_anonymous():
    c = cluster(anonymous_readable=True, jm=_jm(**{"web.submit.enable": "true"}))
    hits = rp.web_submit_enabled(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].severity == "high"


def test_web_submit_default_true_when_config_readable_but_absent():
    """web.submit.enable defaults to true in Flink — a readable config that omits it still fires."""
    c = cluster(jm=_jm(**{"rest.address": "0.0.0.0"}))
    assert len(rp.web_submit_enabled(c, _ctx([c]))) == 1


def test_web_submit_does_not_fire_when_disabled():
    c = cluster(jm=_jm(**{"web.submit.enable": "false"}))
    assert rp.web_submit_enabled(c, _ctx([c])) == []


def test_web_submit_not_assessable_when_config_unreadable():
    c = cluster(config_readable=False)
    hits = rp.web_submit_enabled(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].assessable is False


# ── FLINK.TLS.DISABLED ─────────────────────────────────────────────────────────
def test_tls_disabled_fires_on_http_without_ssl_rest():
    c = cluster(tls_url=False, jm=_jm(**{"security.ssl.rest.enabled": "false"}))
    assert len(rp.tls_disabled(c, _ctx([c]))) == 1


def test_tls_silent_when_ssl_rest_enabled():
    c = cluster(tls_url=False, jm=_jm(**{"security.ssl.rest.enabled": "true"}))
    assert rp.tls_disabled(c, _ctx([c])) == []


def test_tls_silent_on_https():
    assert rp.tls_disabled(cluster(tls_url=True), _ctx([])) == []


# ── FLINK.VERSION.PATH_TRAVERSAL_CVE (+ not-assessable) ────────────────────────
def test_traversal_cve_fires_in_range():
    c = cluster(version="1.11.1")
    hits = rp.version_path_traversal_cve(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].assessable is True
    assert "CVE-2020-17518" in hits[0].observation


def test_traversal_cve_silent_when_patched():
    assert rp.version_path_traversal_cve(cluster(version="1.11.3"), _ctx([])) == []


def test_traversal_cve_silent_on_newer_line():
    assert rp.version_path_traversal_cve(cluster(version="1.18.0"), _ctx([])) == []


def test_traversal_cve_not_assessable_on_unparseable_version():
    c = cluster(version=None)
    hits = rp.version_path_traversal_cve(c, _ctx([c]))
    assert len(hits) == 1 and hits[0].assessable is False
