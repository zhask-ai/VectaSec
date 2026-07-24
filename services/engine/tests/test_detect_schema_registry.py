"""Schema Registry connector + rulepack — offline. Detectors run on parse_registry() output
from golden REST response dicts.
"""
from vectasec.contracts import ScanContext
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.schema_registry import parse_registry
import vectasec.detect.schema_registry as rp


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def registry(*, compat="BACKWARD", mode="READWRITE", subjects=("orders-value",), tls_url=False,
             anonymous_readable=False, config_readable=True):
    return parse_registry(
        "http://schema-registry:8081",
        config_resp=({"compatibilityLevel": compat} if compat is not None else None),
        mode_resp={"mode": mode}, subjects=list(subjects) if subjects is not None else None,
        tls_url=tls_url, anonymous_readable=anonymous_readable, config_readable=config_readable)


def test_connector_registered_and_secret_marked():
    assert "schema_registry" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["schema_registry"]}
    assert fields["password"].secret and fields["url"].required


# ── SCHEMA_REGISTRY.AUTH.ANONYMOUS ─────────────────────────────────────────────
def test_anonymous_read_fires():
    r = registry(anonymous_readable=True)
    hits = rp.auth_anonymous(r, _ctx([r]))
    assert len(hits) == 1 and "anonymously readable" in hits[0].observation
    assert "WRITE exposure is NOT tested" in hits[0].detail   # honest coverage note


def test_authenticated_read_does_not_fire():
    assert rp.auth_anonymous(registry(anonymous_readable=False), _ctx([])) == []


# ── SCHEMA_REGISTRY.TLS.DISABLED ───────────────────────────────────────────────
def test_http_fires_tls():
    r = registry(tls_url=False)
    assert len(rp.tls_disabled(r, _ctx([r]))) == 1


def test_https_does_not_fire_tls():
    r = registry(tls_url=True)
    assert rp.tls_disabled(r, _ctx([r])) == []


# ── SCHEMA_REGISTRY.COMPAT.OPEN (+ not-assessable) ─────────────────────────────
def test_compat_none_fires():
    r = registry(compat="NONE")
    hits = rp.compat_open(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].assessable is True and "NONE" in hits[0].observation


def test_compat_backward_does_not_fire():
    assert rp.compat_open(registry(compat="BACKWARD"), _ctx([])) == []


def test_compat_full_does_not_fire():
    assert rp.compat_open(registry(compat="FULL"), _ctx([])) == []


def test_compat_not_assessable_when_config_unreadable():
    r = registry(compat=None, config_readable=False)
    hits = rp.compat_open(r, _ctx([r]))
    assert len(hits) == 1 and hits[0].assessable is False


def test_compat_readable_but_absent_is_silent():
    """config readable but no compatibility level echoed -> nothing to assert, not a finding."""
    r = registry(compat=None, config_readable=True)
    assert rp.compat_open(r, _ctx([r])) == []
