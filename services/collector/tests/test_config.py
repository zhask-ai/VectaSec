"""load_config() — where a typo must not become a security downgrade.

`VECTASEC_VERIFY_TLS` defaults to ON, which means a flag parser that reads anything it does not
recognise as False is not merely lax: it lets an operator turn certificate verification OFF by
misspelling the value that was supposed to keep it on. The connection in question carries the
tenant service token, so these tests pin the parser to fail loudly instead.
"""
import json
import pathlib

import pytest

from collector.config import load_config

TARGETS = {"targets": [{"name": "t1", "type": "kafka",
                        "config": {"bootstrap": "kafka.internal:9092"}}]}


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch):
    (tmp_path / "targets.json").write_text(json.dumps(TARGETS))
    monkeypatch.setenv("VECTASEC_CONTROL_PLANE_URL", "https://cp.example")
    monkeypatch.setenv("VECTASEC_ENROLL_TOKEN", "enroll-token-abcdefgh")
    monkeypatch.setenv("VECTASEC_TARGETS_FILE", str(tmp_path / "targets.json"))
    monkeypatch.setenv("VECTASEC_STATE_DIR", str(tmp_path / "state"))
    for k in ("VECTASEC_VERIFY_TLS", "VECTASEC_CA_BUNDLE",
              "VECTASEC_ALLOW_INSECURE_CONTROL_PLANE"):
        monkeypatch.delenv(k, raising=False)
    return monkeypatch


def test_tls_verification_is_on_when_the_flag_is_unset(env):
    assert load_config().verify_tls is True


@pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "on"])
def test_the_documented_true_values_keep_verification_on(env, raw):
    env.setenv("VECTASEC_VERIFY_TLS", raw)
    assert load_config().verify_tls is True


@pytest.mark.parametrize("raw", ["false", "FALSE", "0", "no", "off"])
def test_the_documented_false_values_still_turn_verification_off(env, raw):
    """The escape hatch has to keep working, or this is a fix that broke local dev."""
    env.setenv("VECTASEC_VERIFY_TLS", raw)
    assert load_config().verify_tls is False


@pytest.mark.parametrize("raw", ["enabled", "enable", "y", "tru", "verify", "asdf"])
def test_an_unparseable_flag_stops_the_collector_rather_than_disabling_tls(env, raw):
    """The regression. Every one of these used to yield verify_tls=False silently, i.e.
    httpx.Client(verify=False), i.e. any certificate accepted for the control plane."""
    env.setenv("VECTASEC_VERIFY_TLS", raw)
    with pytest.raises(SystemExit) as e:
        load_config()
    assert "is not a boolean" in str(e.value)


def test_a_ca_bundle_still_short_circuits_the_flag(env, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    env.setenv("VECTASEC_CA_BUNDLE", str(ca))
    assert load_config().verify_tls == str(ca)


def test_an_unparseable_insecure_flag_does_not_read_as_permission(env):
    """The other _flag call site. `ALLOW_INSECURE=maybe` is not consent to plaintext, and it is
    not a clean 'no' either — it is a mistake, and the collector says so."""
    env.setenv("VECTASEC_CONTROL_PLANE_URL", "http://cp.internal")
    env.setenv("VECTASEC_ALLOW_INSECURE_CONTROL_PLANE", "maybe")
    with pytest.raises(SystemExit) as e:
        load_config()
    assert "is not a boolean" in str(e.value)
