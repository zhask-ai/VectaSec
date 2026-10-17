"""Zapier connector parse layer + assembly, offline. The golden fixture is shaped per the Zapier
Workflow API docs (Get Zaps [v2] with expand, Get Authentications, User profile); every Resource
here is produced by the connector's OWN parse layer so a shape drift fails here, not in production.
"""
import json
import pathlib

from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.zapier import (
    assemble, build_account, parse_authentication, parse_zap, _paginate, _pages,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "zapier_responses.json").read_text())
BASE = "https://api.zapier.com"


def zaps_raw():
    return [z for page in FIX["zaps"] for z in page["data"]]


def auths_raw():
    return [a for page in FIX["authentications"].values() for a in page["data"]]


def ok_outcomes():
    return {"profile": {"outcome": "ok"}, "zaps": {"outcome": "ok", "count": 8},
            "authentications": {"outcome": "ok", "count": 6}}


def collected(**over):
    kw = dict(account_id="123456", profile=FIX["profile"][0], zaps_raw=zaps_raw(),
              auths_raw=auths_raw(), outcomes=ok_outcomes())
    kw.update(over)
    return assemble(BASE, **kw)


def by_kind(col, kind):
    return [r for r in col.resources if r.kind == kind]


# ── registration / fields ─────────────────────────────────────────────────────
def test_connector_registered_with_exact_fields():
    assert "zapier" in CONNECTORS
    fields = [(f.key, f.required, f.secret) for f in CONNECTOR_FIELDS["zapier"]]
    assert fields == [("base_url", False, False), ("access_token", True, True),
                      ("account_id", False, False)]


# ── parse_zap ─────────────────────────────────────────────────────────────────
def test_webhook_zap_becomes_zap_plus_trigger_with_uses_edges():
    z = next(z for z in zaps_raw() if z["id"] == "zap-hook-prod")
    rs, es = parse_zap(z)
    kinds = [r.kind for r in rs]
    assert kinds == ["zapier_zap", "zapier_webhook_trigger"]
    zap, hook = rs
    assert zap.ext_id == "zapier-zap-zap-hook-prod"
    assert zap.raw["has_webhook_trigger"] is True and zap.raw["has_anonymous_trigger"] is True
    assert zap.raw["connection_ids"] == ["auth-pg"]
    assert zap.raw["apps"] == ["PostgreSQLAPI", "WebHookAPI"]
    assert [w["app"] for w in zap.raw["production_writes"]] == ["PostgreSQLAPI"]
    assert zap.labels["anonymous_trigger"] == "true" and zap.labels["enabled"] == "true"
    assert hook.raw["authentication"] == "none" and hook.raw["action_key"] == "catch_hook"
    assert hook.labels["writes_to_production"] == "true"
    assert ("zapier-zap-zap-hook-prod", "zapier-connection-auth-pg", "uses") in \
        {(e.src_ext_id, e.dst_ext_id, e.kind) for e in es}
    assert any(e.kind == "triggers" and e.src_ext_id == hook.ext_id for e in es)


def test_app_triggered_zap_has_no_webhook_resource_and_no_production_write_flag():
    z = next(z for z in zaps_raw() if z["id"] == "zap-sf-1")
    rs, _ = parse_zap(z)
    assert [r.kind for r in rs] == ["zapier_zap"]
    zap = rs[0]
    assert zap.raw["has_anonymous_trigger"] is False
    # Slack (not Slack admin) is not production-shaped
    assert zap.raw["production_writes"] == []
    assert zap.raw["connection_ids"] == ["auth-sf", "auth-slack"]


def test_unexpanded_steps_are_recorded_not_guessed():
    z = next(z for z in zaps_raw() if z["id"] == "zap-unexpanded")
    rs, _ = parse_zap(z)
    zap = rs[0]
    assert zap.raw["steps_unexpanded"] == [1]
    assert zap.raw["actions"][0]["app"] == "?" and zap.raw["actions"][0]["action_key"] is None
    assert zap.raw["connection_ids"] == ["auth-expired"]


def test_no_step_data_leaks_into_the_zap_resource():
    """Step `inputs` can carry customer data (table names are fine, row payloads are not); the
    resource keeps structure, never the inputs."""
    z = next(z for z in zaps_raw() if z["id"] == "zap-hook-prod")
    rs, _ = parse_zap(z)
    assert "inputs" not in json.dumps(rs[0].raw)


# ── parse_authentication ──────────────────────────────────────────────────────
def test_authentication_is_metadata_only_with_owner_and_usage():
    a = next(a for a in auths_raw() if a["id"] == "auth-slack")
    zaps = [parse_zap(z)[0][0].raw for z in zaps_raw()]
    used = [z for z in zaps if "auth-slack" in z["connection_ids"]]
    r = parse_authentication(a, used, owner={"email": "ada.ops@example.com", "id": 1})
    assert r.kind == "zapier_connection" and r.ext_id == "zapier-connection-auth-slack"
    assert r.labels == {"app": "app-slack", "used_by_count": "5", "expired": "false",
                        "owner": "ada.ops@example.com"}
    assert r.raw["used_by_zaps"] == ["zap-hook-paused", "zap-sf-1", "zap-sf-2", "zap-sf-3", "zap-sf-4"]
    assert r.raw["used_by_enabled_zaps"] == ["zap-sf-1", "zap-sf-2", "zap-sf-3"]
    assert r.raw["used_by_anonymous_trigger_zaps"] == ["zap-hook-paused"]
    assert {(x["app"], x["action_key"]) for x in r.raw["actions"]} == {("SlackAPI", "channel_message")}
    assert r.raw["owner_readable"] is True
    # never a token / secret field
    assert not {"token", "access_token", "refresh_token", "secret", "api_key"} & set(r.raw)


def test_authentication_with_expanded_app_object():
    a = next(a for a in auths_raw() if a["id"] == "auth-expired")
    r = parse_authentication(a, [], owner=None, owner_readable=False)
    assert r.raw["app"] == {"id": "app-github", "key": "GitHubAPI", "title": "GitHub"}
    assert r.labels["app"] == "GitHubAPI" and r.labels["expired"] == "true"
    assert r.raw["auth_type"] == "api_key" and r.raw["owner_readable"] is False


# ── assemble: the wiring collect() performs ───────────────────────────────────
def test_assemble_produces_account_zaps_connections_and_edges():
    col = collected()
    assert len(by_kind(col, "zapier_account")) == 1
    assert len(by_kind(col, "zapier_zap")) == 8
    assert len(by_kind(col, "zapier_webhook_trigger")) == 4
    conns = {r.raw["id"]: r for r in by_kind(col, "zapier_connection")}
    # 5 from the per-app listing + the orphan one no Zap uses
    assert set(conns) == {"auth-pg", "auth-sheets", "auth-slack", "auth-slack-orphan", "auth-sf",
                          "auth-expired"}
    assert conns["auth-slack-orphan"].raw["used_by_zaps"] == []
    assert conns["auth-pg"].raw["owner"]["email"] == "ada.ops@example.com"
    # a bare app id from /v2/authentications is named from the expanded Zap steps
    assert conns["auth-pg"].raw["app"] == {"id": "app-postgres", "key": "PostgreSQLAPI",
                                           "title": "PostgreSQL"}
    assert conns["auth-pg"].labels["app"] == "PostgreSQLAPI"
    kinds = {e.kind for e in col.edges}
    assert kinds == {"uses", "triggers", "owns", "holds"}
    acct = by_kind(col, "zapier_account")[0]
    assert acct.name == "123456" and acct.raw["zap_count"] == 8 and acct.raw["connection_count"] == 6
    assert acct.labels["zaps_readable"] == "true"


def test_connection_only_referenced_by_a_zap_is_still_a_resource():
    """A Zap can reference an authentication the per-app listing did not return (shared with the
    user, not owned). It must still exist as a node, with what the Zap told us."""
    col = collected(auths_raw=[a for a in auths_raw() if a["id"] != "auth-pg"])
    pg = next(r for r in by_kind(col, "zapier_connection") if r.raw["id"] == "auth-pg")
    assert pg.raw["used_by_zaps"] == ["zap-hook-prod"]


def test_unreadable_profile_marks_owner_not_readable():
    outcomes = ok_outcomes()
    outcomes["profile"] = {"outcome": "forbidden", "status": 403, "error": "HTTP 403"}
    col = collected(profile=None, outcomes=outcomes)
    for c in by_kind(col, "zapier_connection"):
        assert c.raw["owner"] is None and c.raw["owner_readable"] is False


def test_account_records_unreadable_endpoints_not_empty_inventory():
    outcomes = {"profile": {"outcome": "ok"},
                "zaps": {"outcome": "forbidden", "status": 403, "error": "HTTP 403"},
                "authentications": {"outcome": "skipped", "error": "zaps unreadable"}}
    acct = build_account(BASE, profile=FIX["profile"][0], account_id=None, outcomes=outcomes,
                         zap_count=0, connection_count=0)
    assert acct.labels["zaps_readable"] == "false"
    assert acct.raw["collection"]["zaps"]["outcome"] == "forbidden"
    assert acct.name == "ada.ops@example.com"


def test_access_token_never_lands_in_a_resource():
    col = collected()
    blob = json.dumps([r.raw for r in col.resources]) + json.dumps([r.labels for r in col.resources])
    assert "Bearer" not in blob and "access_token" not in blob


# ── pagination helpers ────────────────────────────────────────────────────────
def test_pages_accepts_array_and_object_bodies():
    assert _pages({"data": [1]}) == [{"data": [1]}]
    assert _pages([{"data": [1]}, {"data": [2]}]) == [{"data": [1]}, {"data": [2]}]
    assert _pages("nope") == []


class _Resp:
    def __init__(self, body):
        self._b = body
        self.status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._b


class _Client:
    """Serves two pages by offset; a third request would be a bug (the loop must stop on count)."""
    def __init__(self):
        self.calls = []

    def get(self, url, params=None):
        self.calls.append(params["offset"])
        off = params["offset"]
        if off == 0:
            return _Resp([{"links": {"next": "x"}, "meta": {"count": 3, "offset": 0, "limit": 2},
                           "data": [{"id": 1}, {"id": 2}]}])
        if off == 2:
            return _Resp([{"links": {"next": None}, "meta": {"count": 3, "offset": 2, "limit": 2},
                           "data": [{"id": 3}]}])
        raise AssertionError("paginated past meta.count")


def test_paginate_walks_by_offset_to_count():
    c = _Client()
    out = _paginate(c, "https://api.zapier.com/v2/zaps", {"expand": "steps.action"}, limit=2)
    assert [o["id"] for o in out] == [1, 2, 3]
    assert c.calls == [0, 2]
