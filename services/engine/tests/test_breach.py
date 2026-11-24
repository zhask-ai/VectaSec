"""Breach-day mode (breach.py): an advisory matched to stored inventory, no network call.

Pinned: version ranges (and that a mistyped one raises), unknown ≠ not affected, an inferred
version is unknown, aliases, discovered-but-unconnected systems are listed, held third-party
credentials are listed only for the matched tool, rotation order and its reasons, the empty
result says what it does not cover, and the output is deterministic.
"""
import pytest

from vectasec import breach


def conn(cid, type_, name=None):
    return {"id": cid, "name": name or f"{type_} prod", "type": type_, "last_scanned_at": "2026-11-20T08:00:00+00:00"}


def res(kind, name, cid, ctype, labels=None, raw=None, stale=False):
    return {"id": name, "kind": kind, "name": name, "ext_id": name, "labels": labels or {},
            "raw": raw or {}, "connection_id": cid, "connection_type": ctype, "stale": stale}


def row(system, identity, **kw):
    base = {"system": system, "identity": identity, "identity_type": "service_account", "owner": "",
            "credential_types": "api_key", "last_used_at": "unknown", "grants": 1,
            "wildcard_grants": 0, "highest_sensitivity": "", "external": "false"}
    return {**base, **kw}


@pytest.mark.parametrize("spec,version,want", [
    ("<1.121.0", "1.120.4", "affected"), ("<1.121.0", "1.121.0", "not_affected"),
    (">=7.0, <7.2.5", "7.2.4", "affected"), (">=7.0, <7.2.5", "6.2.14", "not_affected"),
    (">=7.0,<7.2.5", "7.2.5", "not_affected"), ("=2.4.1", "v2.4.1-alpine", "affected"),
    ("<2", None, "unknown"), ("", "1.0.0", "affected"), ("", None, "unknown"),
])
def test_version_status(spec, version, want):
    assert breach.version_status(version, False, breach.parse_spec(spec)) == want


def test_inferred_version_is_unknown_and_bad_spec_raises():
    assert breach.version_status("3.6.0", True, breach.parse_spec("<3.7")) == "unknown"
    with pytest.raises(ValueError):
        breach.parse_spec("<latest")


def test_vulnerability_brief_affected_unknown_and_not_affected():
    conns = [conn("c1", "n8n", "n8n prod"), conn("c2", "n8n", "n8n staging"), conn("c3", "n8n", "n8n lab"),
             conn("c4", "redis")]
    resources = [
        res("n8n_instance", "prod", "c1", "n8n", {"version": "1.119.0"}),
        res("n8n_instance", "staging", "c2", "n8n", {"version": "1.122.1"}),
        res("n8n_workflow", "wf", "c3", "n8n"),
        res("n8n_credential", "Slack bot", "c1", "n8n", {"credential_type": "slackApi"}),
        res("redis_server", "cache", "c4", "redis", {"version": "1.0.0"}),
    ]
    b = breach.build_brief({"product": "n8n", "affected": "<1.121.0"}, conns, resources, [])
    by = {s["name"]: s["status"] for s in b["systems"]}
    assert by == {"n8n prod": "affected", "n8n lab": "unknown", "n8n staging": "not_affected"}
    assert [s["name"] for s in b["systems"]][0] == "n8n prod", "affected first"
    assert b["counts"] == {"affected": 1, "unknown": 1, "not_affected": 1}
    assert [h["name"] for h in b["held"]] == ["Slack bot"] and b["held"][0]["for"] == "slackApi"
    assert "unknown versions as affected" in " ".join(b["steps"])


def test_discovered_but_not_connected_is_listed():
    resources = [res("discovered_service", "10.0.0.9:6379", "d1", "discovery",
                     {"product": "redis", "version": "7.2.4"})]
    b = breach.build_brief({"product": "Redis", "affected": "<7.2.5"}, [conn("d1", "discovery")], resources, [])
    assert b["systems"][0]["source"] == "discovered, not connected" and b["systems"][0]["status"] == "affected"


def test_alias_and_stale_resources():
    conns = [conn("c1", "msk", "events")]
    resources = [res("broker", "b1", "c1", "msk", {"version": "3.5.1"}, stale=True)]
    b = breach.build_brief({"product": "kafka"}, conns, resources, [])
    assert [s["name"] for s in b["systems"]] == ["events"] and b["systems"][0]["versions"] == []


def test_rotation_order_and_reasons():
    rows = [row("kong", "low-risk"),
            row("kong", "pii-reader", highest_sensitivity="restricted", last_used_at="2026-11-20T00:00:00+00:00"),
            row("kong", "partner", external="true", wildcard_grants=2),
            row("kong", "ghost", last_used_at="never"),
            row("redis", "other-system", wildcard_grants=9)]
    b = breach.build_brief({"product": "kong", "kind": "vendor_breach"}, [conn("c1", "kong")], [], rows)
    assert [r["identity"] for r in b["rotate"]] == ["partner", "pii-reader", "ghost", "low-risk"]
    assert [r["order"] for r in b["rotate"]] == [1, 2, 3, 4]
    assert "has wildcard grants" in b["rotate"][0]["why"] and "external party" in b["rotate"][0]["why"]
    assert any("revoke instead" in w for w in b["rotate"][2]["why"])
    assert "DESTINATION" not in " ".join(b["steps"]), "no held credentials, so no such step"
    assert "refresh token" in " ".join(b["steps"])


def test_nothing_found_says_what_it_does_not_cover():
    b = breach.build_brief({"product": "langflow"}, [conn("c1", "redis")], [], [row("redis", "x")])
    assert b["systems"] == [] and b["rotate"] == []
    assert "only what VectaSec can see" in b["headline"]
    assert "not connected to" in b["steps"][0]


def test_deterministic_and_markdown():
    args = ({"product": "n8n", "affected": "<1.121.0", "title": "n8n RCE", "reference": "https://example.org/a"},
            [conn("c1", "n8n")], [res("n8n_instance", "p", "c1", "n8n", {"version": "1.0.0"}),
                                  res("n8n_credential", "A | B", "c1", "n8n", {"credential_type": "x"})],
            [row("n8n", "owner@corp.io")])
    a, b = breach.build_brief(*args), breach.build_brief(*args)
    assert a == b
    md = breach.to_markdown({**a, "generated_at": "2026-11-23T10:00:00+00:00"})
    assert "# Breach-day brief: n8n RCE" in md and "A \\| B" in md and "no system was contacted" in md
