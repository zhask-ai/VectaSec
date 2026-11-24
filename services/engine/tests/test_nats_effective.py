"""NATS effective permissions (connect/nats.nats_effective_grants, NATS.PERMISSION.*)."""
from vectasec.connect.nats import nats_effective_grants
from vectasec.contracts import Resource
from vectasec import detect as _detect  # noqa: F401
from vectasec.registry import DETECTORS

RULE = next(d for d in DETECTORS if d.rule_id == "NATS.PERMISSION.EMPTY_LIST_UNRESTRICTED")


def g(perms):
    return {(d, s, w) for d, s, w, _ in nats_effective_grants(perms)}


def test_documented_traps_are_unrestricted():
    assert g({}) == {("all", ">", True)}
    assert ("publish", ">", True) in g({"publish": []}), "an empty list is no list"
    assert ("publish", ">", True) in g({"publish": {"allow": []}})
    assert ("publish", ">", True) in g({"publish": {"deny": ["secret.>"]}}), "deny-only allows the rest"
    assert ("publish", ">", True) in g({"subscribe": {"allow": ["orders.*"]}}), "a missing direction is open"


def test_allow_lists_and_deny_precedence():
    out = g({"publish": {"allow": ["orders.created", "audit.>"], "deny": ["orders.created"]},
             "subscribe": ["_INBOX.>"]})
    assert out == {("publish", "audit.>", True), ("subscribe", "_INBOX.>", True)}
    reasons = [r for *_, r in nats_effective_grants({"publish": {"deny": ["a"]}}) if r]
    assert any("deny-only" in r for r in reasons)


def test_empty_list_detector():
    acct = Resource(kind="nats_account", name="APP", ext_id="a", raw={"name": "APP", "users": [
        {"user": "svc", "permissions": {"publish": [], "subscribe": {"allow": ["x"]}}},
        {"user": "ok", "permissions": {"publish": {"deny": [">"]}}},
        {"user": "none", "permissions": {}}]})

    class Ctx:
        resources = []
    hits = RULE.fn(acct, Ctx)
    assert len(hits) == 1 and "APP/svc" in hits[0].observation and 'deny: [">"]' in hits[0].remediation
