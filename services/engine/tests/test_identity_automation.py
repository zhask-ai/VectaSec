"""The "Belongs to an automation or agent" label: identities, credentials and grants from the
automation systems (n8n, Zapier, Workato, Boomi, MuleSoft, MCP, Airflow) carry automation=true in
labels AND raw; broker/gateway principals (Kafka, RabbitMQ, Kong, Redis) carry false. Grant labels
also carry `target`, so the Access page renders "can <action> <target>" without reading raw.
Plus the Zapier extractor end to end from the golden fixture.
"""
import json
import pathlib

from vectasec.contracts import Collected, Resource
from vectasec.identity import (
    AUTOMATION_SYSTEMS, IDENTITY_EXTRACTORS, _mk_credential, _mk_grant, _mk_identity,
    derive_identities,
)
import vectasec.connect.n8n  # noqa: F401 — registers the n8n extractor
import vectasec.connect.zapier  # noqa: F401 — registers the zapier extractor
from vectasec.connect.n8n import parse_credential as n8n_credential
from vectasec.connect.zapier import assemble

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "zapier_responses.json").read_text())


def test_automation_systems_set():
    assert AUTOMATION_SYSTEMS == {"n8n", "zapier", "make", "workato", "boomi", "mulesoft", "mcp", "airflow"}


def test_builders_label_automation_by_system():
    for system in ("n8n", "zapier", "mcp", "workato", "boomi", "mulesoft", "airflow"):
        i = _mk_identity(system, "x", "name")
        assert i.labels["automation"] == "true" and i.raw["automation"] is True, system
        assert _mk_credential(system, i.ext_id, "api_key", name="n").labels["automation"] == "true"
        assert _mk_grant(system, i.ext_id, "read", "t").labels["automation"] == "true"
    for system in ("kafka", "rabbitmq", "kong", "redis"):
        i = _mk_identity(system, "x", "name")
        assert i.labels["automation"] == "false" and i.raw["automation"] is False, system
        assert _mk_credential(system, i.ext_id, "password", name="n").labels["automation"] == "false"
        assert _mk_grant(system, i.ext_id, "read", "t").labels["automation"] == "false"


def test_automation_tag_flips_a_non_automation_system_identity():
    i = _mk_identity("kafka", "service_account", "User:n8n-bot", tags=["automation"])
    assert i.labels["automation"] == "true" and i.raw["automation"] is True


def test_grant_labels_carry_target():
    g = _mk_grant("kafka", "identity:kafka:alice", "read", "topic:payments")
    assert g.labels["target"] == "topic:payments" and g.raw["target"] == "topic:payments"
    assert _mk_grant("mcp", "identity:mcp:c", "scope", "").labels["target"] == ""


# ── through the real extractors ───────────────────────────────────────────────
def test_n8n_and_mcp_identities_are_automation():
    cred = n8n_credential({"id": "c1", "name": "Slack", "type": "slackApi"}, ["wf-1"], False)
    col = derive_identities("n8n", Collected(resources=[cred]))
    ids = [r for r in col.resources if r.kind == "identity"]
    assert ids and all(r.labels["automation"] == "true" for r in ids)
    grants = [r for r in col.resources if r.kind == "grant"]
    assert grants and all(g.labels["automation"] == "true" and g.labels["target"] == "n8n-workflow-wf-1"
                          for g in grants)

    mcp = Resource(kind="mcp_server", name="s", ext_id="mcp-s",
                   raw={"issuer": "https://idp", "client_name": "agent",
                        "as_metadata": {"scopes_supported": ["read", "*"]}})
    col = derive_identities("mcp", Collected(resources=[mcp]))
    assert all(r.labels["automation"] == "true" for r in col.resources
               if r.kind in ("identity", "grant"))
    star = next(r for r in col.resources if r.kind == "grant" and r.labels["target"] == "*")
    assert star.labels["wildcard"] == "true"


def test_kafka_and_rabbitmq_identities_are_not_automation():
    broker = Resource(kind="broker", name="b", ext_id="broker-1", raw={"acls": {"bindings": [
        {"restype": "TOPIC", "name": "payments", "pattern": "LITERAL", "principal": "User:svc",
         "operation": "WRITE", "permission_type": "ALLOW"}]}})
    col = derive_identities("kafka", Collected(resources=[broker]))
    nhi = [r for r in col.resources if r.kind in ("identity", "credential", "grant")]
    assert nhi and all(r.labels["automation"] == "false" for r in nhi)
    g = next(r for r in col.resources if r.kind == "grant")
    assert g.labels["target"] == "topic:payments"

    user = Resource(kind="user", name="app", ext_id="user-app",
                    raw={"name": "app", "tags": [], "has_internal_password": True,
                         "hashing_algorithm": "sha256"})
    col = derive_identities("rabbitmq", Collected(resources=[user]))
    nhi = [r for r in col.resources if r.kind in ("identity", "credential", "grant")]
    assert len(nhi) == 2 and all(r.labels["automation"] == "false" for r in nhi)


# ── Zapier extractor ──────────────────────────────────────────────────────────
def _zapier():
    col = assemble("https://api.zapier.com", account_id="1", profile=FIX["profile"][0],
                   zaps_raw=[z for p in FIX["zaps"] for z in p["data"]],
                   auths_raw=[a for p in FIX["authentications"].values() for a in p["data"]],
                   outcomes={"profile": {"outcome": "ok"}, "zaps": {"outcome": "ok"},
                             "authentications": {"outcome": "ok"}})
    return derive_identities("zapier", col)


def test_zapier_extractor_registered():
    assert "zapier" in IDENTITY_EXTRACTORS


def test_each_zapier_connection_becomes_an_automation_identity_with_credential_metadata():
    col = _zapier()
    conns = [r for r in col.resources if r.kind == "zapier_connection"]
    ids = [r for r in col.resources if r.kind == "identity"]
    assert len(ids) == len(conns) == 6
    for i in ids:
        assert i.labels == {"identity_type": "automation_connection", "system": "zapier",
                            "external": "true", "automation": "true"}
        assert i.raw["owner_email"] == "ada.ops@example.com"
    creds = {c.labels["owner"]: c for c in col.resources if c.kind == "credential"}
    assert len(creds) == 6
    for c in creds.values():
        assert c.raw["present"] is True and c.raw["plaintext"] is False
        assert c.labels["automation"] == "true"
        assert not {"token", "access_token", "refresh_token", "value"} & set(c.raw)
        assert any(e.kind == "credential_of" and e.src_ext_id == c.ext_id for e in col.edges)


def test_zapier_credential_type_follows_auth_type_and_never_guesses():
    col = _zapier()
    by_name = {c.name: c for c in col.resources if c.kind == "credential"}
    sf = next(c for n, c in by_name.items() if n.startswith("SalesforceAPI:"))
    gh = next(c for n, c in by_name.items() if n.startswith("GitHubAPI:"))
    pg = next(c for n, c in by_name.items() if n.startswith("PostgreSQLAPI:"))
    assert sf.raw["credential_type"] == "oauth2" and sf.raw["auth_type_known"] is True
    assert gh.raw["credential_type"] == "api_key" and gh.raw["is_expired"] is True
    # the current API schema carries no auth type → recorded as unknown, not guessed as oauth2
    assert pg.raw["credential_type"] == "app_connection" and pg.raw["auth_type_known"] is False
    assert pg.raw["reachable_anonymously"] is True       # used by the webhook-triggered Zap


def test_zapier_grants_are_one_per_app_action_with_target_and_zap_edges():
    col = _zapier()
    slack_id = next(r for r in col.resources if r.kind == "identity"
                    and r.name.startswith("SlackAPI:Slack acme"))
    grants = [g for g in col.resources if g.kind == "grant" and g.labels["identity"] == slack_id.ext_id]
    assert len(grants) == 1                       # same action across 5 Zaps → merged
    g = grants[0]
    assert g.labels["action"] == "SlackAPI.channel_message" and g.labels["target"] == "SlackAPI"
    assert g.labels["automation"] == "true"
    assert sorted(g.raw["zap_ids"]) == ["zap-hook-paused", "zap-sf-1", "zap-sf-2", "zap-sf-3", "zap-sf-4"]
    targets = {e.dst_ext_id for e in col.edges if e.kind == "grants_access" and e.src_ext_id == g.ext_id}
    assert targets == {f"zapier-zap-{z}" for z in g.raw["zap_ids"]}
    assert any(e.kind == "granted_to" and e.src_ext_id == g.ext_id and e.dst_ext_id == slack_id.ext_id
               for e in col.edges)

    pg_grant = next(g for g in col.resources if g.kind == "grant"
                    and g.labels["action"] == "PostgreSQLAPI.new_row")
    assert pg_grant.raw["production_write"] is True and pg_grant.labels["target"] == "PostgreSQLAPI"


def test_orphan_connection_has_identity_and_credential_but_no_grants():
    col = _zapier()
    orphan = next(r for r in col.resources if r.kind == "identity" and "old-workspace" in r.name)
    assert not [g for g in col.resources if g.kind == "grant" and g.labels["identity"] == orphan.ext_id]
    cred = next(c for c in col.resources if c.kind == "credential" and c.labels["owner"] == orphan.ext_id)
    assert cred.raw["count"] == 0
