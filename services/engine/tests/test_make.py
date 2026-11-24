"""Make connector + rulepack, offline. Bodies are shaped per the Make API v2 docs
(GET /organizations, /teams, /scenarios, /connections, /hooks)."""
from datetime import datetime, timezone

import httpx

from vectasec.contracts import ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
from vectasec.connect import make as m
import vectasec.detect.make  # noqa: F401  (registers the rulepack)

BASE = "https://eu1.make.com/api/v2"
NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)
RULES = {x.rule_id: x for x in DETECTORS if x.rule_id.startswith("MAKE.")}

ME = {"id": 1, "name": "Ops", "email": "ops@acme.io"}
ORGS = [{"id": 10, "name": "Acme", "tfaEnforced": False, "ssoType": None, "teams": [{"id": 20, "name": "Ops"}]}]
TEAMS = {10: [{"id": 20, "name": "Ops", "organizationId": 10}]}
SCEN = {20: [
    {"id": 100, "name": "Leads to CRM", "teamId": 20, "isActive": True, "isPaused": False, "hookId": 300,
     "createdByUser": {"id": 5, "name": "Ann", "email": "Ann@acme.io"},
     "updatedByUser": {"id": 6, "name": "Bob", "email": "bob@acme.io"}, "usedPackages": ["gateway", "hubspot"]},
    {"id": 101, "name": "Old export", "teamId": 20, "isActive": False, "hookId": 301,
     "createdByUser": {"id": 5, "email": "ann@acme.io"}},
]}
CONNS = {20: [
    {"id": 200, "name": "My Gmail", "accountLabel": "Gmail", "packageName": "google-email",
     "metadata": {"value": "ann.home@gmail.com", "type": "email"}, "teamId": 20,
     "scenarioUsages": [{"id": 100, "name": "Leads to CRM"}], "hookUsages": []},
    {"id": 201, "name": "HubSpot", "accountLabel": "HubSpot", "metadata": {"value": "crm@acme.io", "type": "email"},
     "teamId": 20, "scenarioUsages": [], "hookUsages": []},
    {"id": 202, "name": "Slack old", "accountLabel": "Slack", "teamId": 20, "expire": "2025-01-01T00:00:00Z",
     "scenarioUsages": [], "hookUsages": []},
    {"id": 203, "name": "No usage cols", "accountLabel": "Sheets", "teamId": 20},
]}
HOOKS = {20: [
    {"id": 300, "name": "Lead form", "teamId": 20, "typeName": "gateway-webhook", "enabled": True, "gone": False,
     "url": "https://hook.eu1.make.com/abcSECRETpath", "scenarioId": 100},
    {"id": 301, "name": "Export", "teamId": 20, "typeName": "gateway-webhook", "enabled": True,
     "url": "https://hook.eu1.make.com/zzz", "scenarioId": 101},
    {"id": 302, "name": "Mailhook", "teamId": 20, "typeName": "gateway-mailhook", "enabled": True,
     "url": "x@hook.eu1.make.com", "scenarioId": 100},
]}
OK = {k: {"outcome": "ok"} for k in ("me", "organizations", "teams", "scenarios", "connections", "hooks")}


def col(**over):
    kw = dict(me=ME, orgs=ORGS, teams=TEAMS, scenarios=SCEN, connections=CONNS, hooks=HOOKS, outcomes=OK, now=NOW)
    kw.update(over)
    return m.assemble(BASE, **kw)


COL = col()


def res(kind, ident, c=COL):
    return next(r for r in c.resources if r.kind == kind and r.raw.get("id") == ident)


def fire(rule, r, c=COL):
    return RULES[rule].fn(r, ScanContext(connection_id="c", tenant_id="t", resources=list(c.resources), config={}))


def test_registered_with_secret_token():
    assert "make" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["make"]}
    assert fields["api_token"].secret and fields["api_token"].required
    assert set(RULES) == {"MAKE.CONNECTION.PERSONAL_ACCOUNT", "MAKE.CONNECTION.UNUSED",
                          "MAKE.HOOK.ACTIVE_PUBLIC_WEBHOOK", "MAKE.ORG.TFA_NOT_ENFORCED",
                          "MAKE.ACCOUNT.NOT_ASSESSED"}


def test_assemble_shapes_and_edges():
    kinds = {r.kind for r in COL.resources}
    assert kinds == {"make_account", "make_organization", "make_team", "make_scenario", "make_connection", "make_hook"}
    s = res("make_scenario", 100)
    assert s.raw["created_by"] == "ann@acme.io" and s.raw["updated_by"] == "bob@acme.io" and s.raw["active"]
    assert ("make-scenario-100", "make-connection-200", "uses_connection") in {
        (e.src_ext_id, e.dst_ext_id, e.kind) for e in COL.edges}
    # A webhook URL path is the credential: only the host is stored.
    h = res("make_hook", 300)
    assert h.raw["url_host"] == "hook.eu1.make.com"
    assert "abcSECRETpath" not in repr([r.raw for r in COL.resources])


def test_personal_account_fires_only_on_webmail():
    hit = fire("MAKE.CONNECTION.PERSONAL_ACCOUNT", res("make_connection", 200))[0]
    assert "ann.home@gmail.com" in hit.observation and "1 scenario" in hit.observation
    assert fire("MAKE.CONNECTION.PERSONAL_ACCOUNT", res("make_connection", 201)) == []


def test_unused_fires_only_when_usage_was_read_and_not_expired():
    assert fire("MAKE.CONNECTION.UNUSED", res("make_connection", 201))
    assert fire("MAKE.CONNECTION.UNUSED", res("make_connection", 200)) == []
    assert fire("MAKE.CONNECTION.UNUSED", res("make_connection", 202)) == []   # expired
    assert fire("MAKE.CONNECTION.UNUSED", res("make_connection", 203)) == []   # usage unknown


def test_public_webhook_only_for_enabled_webhook_on_active_scenario():
    assert fire("MAKE.HOOK.ACTIVE_PUBLIC_WEBHOOK", res("make_hook", 300))
    assert fire("MAKE.HOOK.ACTIVE_PUBLIC_WEBHOOK", res("make_hook", 301)) == []   # scenario inactive
    assert fire("MAKE.HOOK.ACTIVE_PUBLIC_WEBHOOK", res("make_hook", 302)) == []   # mailhook


def test_tfa_rule_needs_explicit_false():
    assert fire("MAKE.ORG.TFA_NOT_ENFORCED", res("make_organization", 10))
    c = col(orgs=[{**ORGS[0], "tfaEnforced": True}])
    assert fire("MAKE.ORG.TFA_NOT_ENFORCED", res("make_organization", 10, c), c) == []
    c = col(orgs=[{k: v for k, v in ORGS[0].items() if k != "tfaEnforced"}])
    assert fire("MAKE.ORG.TFA_NOT_ENFORCED", res("make_organization", 10, c), c) == []


def test_not_assessed_on_forbidden_endpoint():
    acct = next(r for r in COL.resources if r.kind == "make_account")
    assert fire("MAKE.ACCOUNT.NOT_ASSESSED", acct) == []
    c = col(outcomes={**OK, "connections": {"outcome": "forbidden", "status": 403, "error": "HTTP 403"}})
    acct = next(r for r in c.resources if r.kind == "make_account")
    hit = fire("MAKE.ACCOUNT.NOT_ASSESSED", acct, c)[0]
    assert hit.assessable is False and "connections" in hit.observation


def test_identity_extractor_carries_account_email_as_owner():
    ids, _ = IDENTITY_EXTRACTORS["make"](list(COL.resources))
    conn = [i for i in ids if i.kind == "identity" and i.raw.get("connection_id") == 200]
    assert conn and conn[0].labels.get("owner_label") == "ann.home@gmail.com"


def test_collect_reads_every_endpoint_with_token_header(monkeypatch):
    seen = []

    def handler(req: httpx.Request):
        seen.append(req)
        assert req.headers["Authorization"] == "Token t0k"
        p = req.url.path.removeprefix("/api/v2")
        body = {"/users/me": {"authUser": ME}, "/organizations": {"organizations": ORGS},
                "/teams": {"teams": TEAMS[10]}, "/scenarios": {"scenarios": SCEN[20]},
                "/connections": {"connections": CONNS[20]}, "/hooks": {"hooks": HOOKS[20]}}[p]
        return httpx.Response(200, json=body)

    real = httpx.Client
    monkeypatch.setattr(m.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    out = m.collect({"api_token": "t0k", "zone": "eu1"})
    assert {r.kind for r in out.resources} >= {"make_scenario", "make_connection", "make_hook"}
    assert all(r.method == "GET" for r in seen)
    acct = next(r for r in out.resources if r.kind == "make_account")
    assert all(v["outcome"] == "ok" for v in acct.raw["collection"].values())
