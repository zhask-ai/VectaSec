"""LiteLLM connector + rulepack, offline. Bodies are shaped per the LiteLLM proxy source
(key_management_endpoints, internal_user_endpoints, team_endpoints, model/info)."""
from datetime import datetime, timezone

import httpx

from vectasec.contracts import ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS, DETECTORS
from vectasec.connect import litellm as L
import vectasec.detect.litellm as D

BASE = "https://llm.acme.io"
NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)
RULES = {x.rule_id: x for x in DETECTORS if x.rule_id.startswith("LITELLM.")}

KEYS = [
    {"token": "a" * 64, "key_alias": "billing-app", "key_name": "sk-...a1b2", "user_id": "u1", "team_id": "t1",
     "models": ["gpt-4o-mini"], "max_budget": 50, "expires": "2027-01-01T00:00:00Z",
     "created_at": "2026-10-01T00:00:00Z", "last_active": "2026-11-20T00:00:00Z", "spend": 3.2},
    {"token": "b" * 64, "key_alias": "old-script", "key_name": "sk-...c3d4", "models": [],
     "created_at": "2025-01-01T00:00:00Z", "last_active": None, "created_by": "admin", "spend": 0},
    {"token": "c" * 64, "key_alias": "team-key", "key_name": "sk-...e5f6", "team_id": "t1", "models": [],
     "created_at": "2026-11-01T00:00:00Z", "last_active": "2026-11-23T00:00:00Z"},
    {"token": "d" * 64, "key_alias": "blocked", "models": [], "blocked": True},
]
USERS = [{"user_id": "u1", "user_email": "ann@acme.io", "user_role": "internal_user"}]
TEAMS = [{"team_id": "t1", "team_alias": "payments", "models": ["gpt-4o-mini"], "max_budget": 500,
          "members_with_roles": [{"user_id": "u1", "user_email": "ann@acme.io", "role": "admin"}],
          "keys": [{"token": "leak-me"}]}]
MODELS = [{"model_name": "gpt-4o-mini", "litellm_params": {"model": "openai/gpt-4o-mini",
                                                            "api_base": "https://api.openai.com/v1"}}]
OK = {k: {"outcome": "ok"} for k in ("keys", "users", "teams", "models")}
PROBES = {"version": "1.83.5", "version_source": "/health/readiness", "no_auth": False,
          "default_key_accepted": False}


def col(**over):
    kw = dict(probes=PROBES, keys=KEYS, users=USERS, teams=TEAMS, models=MODELS, outcomes=OK, now=NOW)
    kw.update(over)
    return L.assemble(BASE, **kw)


COL = col()


def get(kind, name, c=COL):
    return next(r for r in c.resources if r.kind == kind and r.name == name)


def proxy(c=COL):
    return next(r for r in c.resources if r.kind == "litellm_proxy")


def fire(rule, r, c=COL, **config):
    return RULES[rule].fn(r, ScanContext(connection_id="c", tenant_id="t", resources=list(c.resources), config=config))


def test_registered():
    assert "litellm" in CONNECTORS
    f = {x.key: x for x in CONNECTOR_FIELDS["litellm"]}
    assert f["api_key"].secret and f["base_url"].required
    assert len(RULES) == 10


def test_assemble_keeps_no_secrets_and_owner_from_user_list():
    blob = repr([r.raw for r in COL.resources])
    assert "leak-me" not in blob and "a" * 64 not in blob
    assert get("litellm_key", "billing-app").raw["owner"] == "ann@acme.io"
    assert get("litellm_model", "gpt-4o-mini").raw["provider"] == "openai"


def test_auth_rules():
    assert fire("LITELLM.AUTH.NO_MASTER_KEY", proxy()) == []
    c = col(probes={**PROBES, "no_auth": True})
    assert fire("LITELLM.AUTH.NO_MASTER_KEY", proxy(c), c)
    c = col(probes={**PROBES, "default_key_accepted": True})
    assert "sk-1234" in fire("LITELLM.AUTH.DEFAULT_MASTER_KEY", proxy(c), c)[0].observation


def test_version_rules():
    hit = fire("LITELLM.VERSION.KNOWN_CVE", proxy())[0]
    assert "CVE-2026-42208" in hit.observation and hit.severity == "critical"
    c = col(probes={**PROBES, "version": "1.110.2"})
    assert fire("LITELLM.VERSION.KNOWN_CVE", proxy(c), c) == []
    c = col(probes={**PROBES, "version": None})
    assert fire("LITELLM.VERSION.KNOWN_CVE", proxy(c), c)[0].assessable is False
    c = col(probes={**PROBES, "version": "1.82.7"})
    assert fire("LITELLM.VERSION.MALICIOUS_RELEASE", proxy(c), c)
    assert fire("LITELLM.VERSION.MALICIOUS_RELEASE", proxy()) == []
    # Range-bounded advisory: CVE-2026-42271 starts at 1.74.2.
    assert "CVE-2026-42271" not in [a[0] for a in D.affected("1.70.0")]


def test_key_rules():
    good, old, team, blocked = (get("litellm_key", n) for n in ("billing-app", "old-script", "team-key", "blocked"))
    for rule in ("LITELLM.KEY.NO_BUDGET", "LITELLM.KEY.NO_EXPIRY", "LITELLM.KEY.ALL_MODELS",
                 "LITELLM.KEY.NO_OWNER", "LITELLM.KEY.UNUSED"):
        assert fire(rule, good) == [], rule
        assert fire(rule, blocked) == [], rule
        assert fire(rule, old), rule
    # The team caps budget and models, so the team key is not flagged for those.
    assert fire("LITELLM.KEY.NO_BUDGET", team) == []
    assert fire("LITELLM.KEY.ALL_MODELS", team) == []
    assert fire("LITELLM.KEY.NO_OWNER", team) == []


def test_not_assessed():
    assert fire("LITELLM.PROXY.NOT_ASSESSED", proxy()) == []
    c = col(outcomes={**OK, "keys": {"outcome": "forbidden", "error": "HTTP 403"}})
    assert fire("LITELLM.PROXY.NOT_ASSESSED", proxy(c), c)[0].assessable is False


def test_identity_grants():
    out, edges = IDENTITY_EXTRACTORS["litellm"](list(COL.resources))
    grants = [g for g in out if g.kind == "grant"]
    assert any(g.labels["target"] == "model:*" and g.labels["wildcard"] == "true" for g in grants)
    assert any(r.kind == "identity" and r.labels.get("owner_label") == "ann@acme.io" for r in out)


def test_collect_probes_and_reads(monkeypatch):
    calls = []

    def handler(req: httpx.Request):
        auth = req.headers.get("Authorization")
        calls.append((req.method, req.url.path, auth))
        p = req.url.path
        if p == "/health/readiness":
            return httpx.Response(200, json={"status": "healthy", "litellm_version": "1.84.1"})
        if auth is None:
            return httpx.Response(401, json={"error": "no key"})
        if auth == "Bearer sk-1234":
            return httpx.Response(401, json={"error": "bad key"})
        body = {"/key/list": {"keys": KEYS, "total_pages": 1}, "/user/list": {"users": USERS},
                "/team/list": TEAMS, "/model/info": {"data": MODELS}}[p]
        return httpx.Response(200, json=body)

    real = httpx.Client
    monkeypatch.setattr(L.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    out = L.collect({"base_url": BASE, "api_key": "sk-admin"})
    p = next(r for r in out.resources if r.kind == "litellm_proxy")
    assert p.raw["version"] == "1.84.1" and not p.raw["no_auth"] and not p.raw["default_key_accepted"]
    assert all(m == "GET" for m, _, _ in calls)
    assert all(v["outcome"] == "ok" for v in p.raw["collection"].values())
