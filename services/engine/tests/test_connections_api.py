"""The connect surface: connector field specs, config validation, the /connectors
catalogue, and the CLI's flag→config assembly.

Offline on purpose (no DB, no target): these are the contracts the console form and the
CLI both build on, so they are pinned exactly. The DB-touching endpoints
(POST /connections, …/test, …/scan, DELETE) are exercised by the live end-to-end path.
"""
import argparse

import pytest
from fastapi.testclient import TestClient

from vectasec.api.main import app
from vectasec.cli import config_from_args
from vectasec.registry import CONNECTORS, CONNECTOR_FIELDS, validate_config
import vectasec.connect    # noqa: F401 — auto-register
import vectasec.detect     # noqa: F401


# ── Field specs ────────────────────────────────────────────────────────────
def test_every_connector_declares_fields():
    """A connector without a field spec renders an empty connect form — a system nobody can
    connect from the console. The spec is part of shipping a connector."""
    for type_ in CONNECTORS:
        assert CONNECTOR_FIELDS.get(type_), f"{type_} declares no connect fields"


@pytest.mark.parametrize("type_,required", [
    ("kafka", {"bootstrap"}),
    ("kong", {"url"}),
    ("rabbitmq", {"url", "username", "password"}),
    ("mcp", {"url"}),
])
def test_required_fields_match_connector_hard_requirements(type_, required):
    """The declared REQUIRED set must cover what the collect fn hard-requires (KeyError /
    SystemExit without it) — otherwise the form submits configs that fail later inside a
    queued job nobody is watching."""
    declared = {f.key for f in CONNECTOR_FIELDS[type_] if f.required}
    assert declared == required


def test_secret_fields_are_marked():
    """Credentials must render as password inputs. A miss here echoes a secret on screen."""
    secret = {(t, f.key) for t, fs in CONNECTOR_FIELDS.items() for f in fs if f.secret}
    assert ("rabbitmq", "password") in secret
    assert ("kong", "admin_token") in secret
    assert ("mcp", "token") in secret


# ── validate_config ────────────────────────────────────────────────────────
def test_validate_config_missing_required():
    problems = validate_config("kafka", {})
    assert problems and "bootstrap" in problems[0]


def test_validate_config_blank_counts_as_missing():
    assert validate_config("kafka", {"bootstrap": "   "})
    assert validate_config("rabbitmq", {"url": "http://x", "username": "", "password": "p"})


def test_validate_config_ok_and_extra_keys_pass():
    assert validate_config("kafka", {"bootstrap": "b:9092", "timeout": "30"}) == []
    assert validate_config("mcp", {"url": "https://x/mcp"}) == []


def test_validate_config_unknown_type():
    problems = validate_config("istio", {})
    assert problems and "no connector" in problems[0]


# ── GET /connectors (offline endpoint) ─────────────────────────────────────
# Auth default is deny (see test_api_auth.py); these catalogue tests opt into the explicit
# dev header-trust gate because what they pin is the /connectors payload, not the auth.
def test_connectors_catalogue_shape(monkeypatch):
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", "1")
    client = TestClient(app)
    res = client.get("/connectors")
    assert res.status_code == 200
    catalogue = {c["type"]: c for c in res.json()["connectors"]}

    assert set(catalogue) == set(CONNECTORS)
    for type_, entry in catalogue.items():
        assert entry["rules"] > 0, f"{type_} claims zero detectors"
        keys = {f["key"] for f in entry["fields"]}
        assert keys == {f.key for f in CONNECTOR_FIELDS[type_]}
        for f in entry["fields"]:
            assert set(f) == {"key", "label", "required", "secret", "placeholder", "help"}


def test_connectors_rule_counts_match_registry(monkeypatch):
    """The picker says "N checks"; N must be the registry's truth, not a hardcode."""
    from vectasec.api.main import rule_owner
    from vectasec.registry import DETECTORS
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", "1")
    client = TestClient(app)
    for entry in client.get("/connectors").json()["connectors"]:
        expected = sum(1 for d in DETECTORS if rule_owner(d.rule_id) == entry["type"])
        assert entry["rules"] == expected


def test_no_rule_is_counted_for_two_connectors(monkeypatch):
    """The catalogue's counts must partition the registry, not overlap it. DISCOVERY.MCP.* is
    the shape that breaks a naive "match either segment" attribution: it would be counted for
    both `discovery` and `mcp`, so both pickers would overstate their coverage."""
    from vectasec.registry import DETECTORS
    monkeypatch.setenv("VECTASEC_DEV_TRUST_HEADERS", "1")
    client = TestClient(app)
    total_claimed = sum(e["rules"] for e in client.get("/connectors").json()["connectors"])
    assert total_claimed <= len(DETECTORS), "a rule is being counted under two connectors"


def test_capability_prefixed_rules_are_attributed_to_their_connector():
    """SUPPLY.IAC.* leads with the capability, not the connector. Without the fallback the iac
    connector advertises "0 checks" in the console's picker while shipping a full rulepack."""
    from vectasec.api.main import rule_owner
    assert rule_owner("SUPPLY.IAC.LITERAL_SECRET") == "iac"
    assert rule_owner("KAFKA.ACL.WILDCARD") == "kafka"
    assert rule_owner("DISCOVERY.MCP.UNMANAGED_SURFACE") == "discovery"


# ── CLI flag → config assembly ─────────────────────────────────────────────
def _ns(**kw):
    ns = argparse.Namespace(bootstrap=None, url=None, token=None, admin_token=None,
                            username=None, password=None, set=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_config_from_args_named_flags():
    cfg = config_from_args(_ns(url="http://localhost:15672", username="svc", password="p"))
    assert cfg == {"url": "http://localhost:15672", "username": "svc", "password": "p"}


def test_config_from_args_set_pairs():
    cfg = config_from_args(_ns(bootstrap="b:9092", set=["timeout=30", "verify_tls=false"]))
    assert cfg == {"bootstrap": "b:9092", "timeout": "30", "verify_tls": "false"}


def test_config_from_args_set_value_may_contain_equals():
    cfg = config_from_args(_ns(set=["token=abc=def=="]))
    assert cfg == {"token": "abc=def=="}


def test_config_from_args_rejects_malformed_set():
    with pytest.raises(SystemExit):
        config_from_args(_ns(set=["timeout"]))


def test_config_from_args_empty():
    assert config_from_args(_ns()) == {}
