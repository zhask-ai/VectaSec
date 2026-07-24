"""Unit tests for the AWS connector's parse layer and NHI extraction. Offline: no boto3
client is ever constructed, no AWS account is touched.

The baseline is the golden fixture in fixtures/aws_responses.json — response dicts shaped
exactly as boto3 returns them (Policy/RedrivePolicy/EventPattern re-serialized to JSON
strings here, because that is how boto3 delivers them). The parse layer is the seam the
detector tests build on, so a shape drift between connector and rulepack fails HERE first.
"""
import json
import pathlib

from vectasec.contracts import Collected, Resource
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.aws import (
    arn_account, has_wildcard_action, is_public_statement, parse_api_v1, parse_api_v2,
    parse_bus, parse_msk_cluster, parse_queue, parse_rule, parse_subscription, parse_topic,
    policy_statements, principal_entries,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "aws_responses.json").read_text()
)
REGION = "us-east-1"

_JSON_STRING_ATTRS = ("Policy", "RedrivePolicy", "EventPattern")


def as_boto(d: dict) -> dict:
    """Fixture dict → the exact boto3 shape: policy-ish documents become JSON strings."""
    out = dict(d)
    for k in _JSON_STRING_ATTRS:
        if isinstance(out.get(k), dict):
            out[k] = json.dumps(out[k])
    return out


def account_resource() -> Resource:
    """The aws_account resource exactly as collect() emits it."""
    ident = FIX["caller_identity"]
    return Resource(
        kind="aws_account", name=ident["Account"], ext_id=f"aws-account-{ident['Account']}",
        labels={"service": "sts", "auth_method": "assume_role"},
        raw={"account_id": ident["Account"], "caller_arn": ident["Arn"],
             "auth_method": "assume_role", "regions": [REGION], "collection": {}},
    )


def queue(name: str, attrs="fixture") -> Resource:
    a = as_boto(FIX["sqs"]["attributes"][name]) if attrs == "fixture" else attrs
    url = f"https://sqs.{REGION}.amazonaws.com/111111111111/{name}"
    return parse_queue(REGION, url, a)


def topic(name: str) -> Resource:
    a = as_boto(FIX["sns"]["attributes"][name])
    return parse_topic(REGION, a["TopicArn"], a)


def bus(name: str) -> Resource:
    b = next(x for x in FIX["events"]["buses"] if x["Name"] == name)
    return parse_bus(REGION, b, json.dumps(FIX["events"]["bus_policies"][name]))


def msk(name: str) -> Resource:
    c = next(x for x in FIX["msk"]["clusters"] if x["ClusterName"] == name)
    return parse_msk_cluster(REGION, c)


# ── registration + form fields ────────────────────────────────────────────────
def test_connector_registered():
    assert "aws" in CONNECTORS


def test_secret_fields_are_marked_secret():
    fields = {f.key: f for f in CONNECTOR_FIELDS["aws"]}
    assert fields["secret_access_key"].secret and fields["session_token"].secret
    # the rest of the auth surface is not secret material
    assert not fields["role_arn"].secret and not fields["profile"].secret
    assert fields["regions"].required
    # role/profile/keys are alternatives, so none of them may be required
    assert not any(fields[k].required for k in
                   ("role_arn", "external_id", "profile", "access_key_id", "secret_access_key"))


# ── policy helpers ────────────────────────────────────────────────────────────
def test_policy_statements_tolerates_single_statement_and_garbage():
    assert policy_statements({"Statement": {"Effect": "Allow"}}) == [{"Effect": "Allow"}]
    assert policy_statements(None) == []
    assert policy_statements({"Statement": "oops"}) == []


def test_principal_star_forms_are_equivalent():
    assert principal_entries({"Principal": "*"}) == ["*"]
    assert principal_entries({"Principal": {"AWS": "*"}}) == ["*"]
    assert principal_entries({"Principal": {"AWS": ["a", "b"]}}) == ["a", "b"]


def test_condition_defuses_public():
    stmt = {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage"}
    assert is_public_statement(stmt)
    assert not is_public_statement({**stmt, "Condition": {"ArnEquals": {"aws:SourceArn": "x"}}})
    assert not is_public_statement({**stmt, "Effect": "Deny"})


def test_wildcard_actions():
    assert has_wildcard_action({"Action": "sqs:*"})
    assert has_wildcard_action({"Action": ["sqs:SendMessage", "*"]})
    assert not has_wildcard_action({"Action": "sqs:SendMessage"})


def test_arn_account():
    assert arn_account("arn:aws:sqs:us-east-1:111111111111:orders") == "111111111111"
    assert arn_account("not-an-arn") == ""


# ── SQS ───────────────────────────────────────────────────────────────────────
def test_parse_queue_public():
    r = queue("orders")
    assert r.kind == "aws_sqs_queue"
    assert r.ext_id == "arn:aws:sqs:us-east-1:111111111111:orders"
    assert r.raw["attributes_readable"] is True
    assert r.raw["policy"]["Statement"][0]["Principal"] == "*"   # JSON string was parsed
    assert r.raw["sqs_managed_sse_enabled"] is None              # attribute absent ≠ false
    assert r.raw["redrive_policy"] is None
    assert r.raw["account"] == "111111111111"


def test_parse_queue_clean():
    r = queue("payments")
    assert r.raw["sqs_managed_sse_enabled"] is True
    assert r.raw["redrive_policy"]["maxReceiveCount"] == "5"
    assert r.raw["policy"]["Statement"][0]["Condition"]


def test_parse_queue_attributes_denied():
    r = queue("orders", attrs=None)
    assert r.raw["attributes_readable"] is False
    assert r.raw["policy"] is None
    assert r.ext_id == f"sqs-{REGION}-orders"    # no ARN readable → synthesized, stable


# ── SNS ───────────────────────────────────────────────────────────────────────
def test_parse_topic_and_subscription():
    t = topic("alerts")
    assert t.kind == "aws_sns_topic" and t.ext_id.endswith(":alerts")
    assert t.raw["kms_master_key_id"] is None
    assert t.raw["policy"]["Statement"][0]["Action"] == "sns:*"

    subs = [parse_subscription(REGION, s) for s in FIX["sns"]["subscriptions"]["alerts"]]
    assert subs[0].kind == "aws_sns_subscription"
    assert subs[0].raw["protocol"] == "http" and subs[0].raw["pending"] is False
    # PendingConfirmation has no ARN: ext_id is synthesized and unique within the topic
    assert subs[1].raw["pending"] is True
    assert subs[1].ext_id != subs[0].ext_id and "pending" in subs[1].ext_id


# ── EventBridge ───────────────────────────────────────────────────────────────
def test_parse_bus_policy_string():
    b = bus("default")
    assert b.kind == "aws_event_bus"
    assert is_public_statement(policy_statements(b.raw["policy"])[0])


def test_parse_rule_targets_and_edges():
    b = bus("default")
    rule = as_boto(FIX["events"]["rules"]["default"][0])
    targets = FIX["events"]["targets"]["forward-orders"]
    resources, edges = parse_rule(REGION, b.ext_id, rule, targets)

    rule_res = resources[0]
    assert rule_res.kind == "aws_event_rule"
    assert rule_res.raw["event_pattern"] == {"source": ["app.orders"]}
    assert len(rule_res.raw["targets"]) == 2
    # Input payload templates are data, not posture — never collected
    assert all("Input" not in t and "input" not in t for t in rule_res.raw["targets"])

    target_res = [r for r in resources if r.kind == "aws_event_target"]
    assert len(target_res) == 2
    kinds = {(e.src_ext_id, e.dst_ext_id, e.kind) for e in edges}
    assert (b.ext_id, rule_res.ext_id, "routes_to") in kinds
    for t in target_res:
        assert (rule_res.ext_id, t.ext_id, "targets") in kinds


# ── MSK ───────────────────────────────────────────────────────────────────────
def test_parse_msk_wide_open():
    r = msk("wide-open")
    assert r.kind == "aws_msk_cluster"
    raw = r.raw
    assert raw["client_auth_unauthenticated"] is True
    assert raw["encryption_in_transit_client_broker"] == "TLS_PLAINTEXT"
    assert raw["encryption_in_transit_in_cluster"] is False
    assert raw["public_access_type"] == "SERVICE_PROVIDED_EIPS"
    assert raw["enhanced_monitoring"] == "DEFAULT"


def test_parse_msk_hardened():
    raw = msk("hardened").raw
    assert raw["client_auth_unauthenticated"] is False
    assert raw["client_auth_sasl_iam"] is True
    assert raw["encryption_in_transit_client_broker"] == "TLS"
    assert raw["public_access_type"] == "DISABLED"


def test_parse_msk_serverless_is_iam_tls_by_service():
    raw = msk("on-demand").raw
    assert raw["cluster_type"] == "SERVERLESS"
    assert raw["client_auth_sasl_iam"] is True
    assert raw["client_auth_unauthenticated"] is False
    assert raw["encryption_in_transit_client_broker"] == "TLS"


# ── API Gateway ───────────────────────────────────────────────────────────────
def test_parse_api_v1_routes_stages_edges():
    fx = FIX["apigw_v1"]
    resources, edges = parse_api_v1(REGION, fx["api"], fx["stages"], fx["authorizers"],
                                    fx["resources"])
    api = resources[0]
    assert api.kind == "aws_api" and api.raw["api_version"] == "v1"
    routes = {(r["method"], r["path"]): r for r in api.raw["routes"]}
    assert routes[("GET", "/public")]["authorization_type"] == "NONE"
    assert routes[("POST", "/orders")]["authorizer_id"] == "auth1"
    assert routes[("GET", "/metrics")]["api_key_required"] is True
    # embed=['methods'] not honoured → recorded unreadable, never defaulted to NONE
    assert routes[("GET", "/opaque")]["details_readable"] is False
    assert routes[("GET", "/opaque")]["authorization_type"] is None

    stages = {r.name: r for r in resources if r.kind == "aws_api_stage"}
    assert stages["prod"].raw["access_log_enabled"] is False
    assert stages["prod"].raw["waf_supported"] is True
    assert stages["hardened"].raw["execution_logging_level"] == "INFO"
    assert stages["hardened"].raw["web_acl_arn"]
    assert {(e.src_ext_id, e.dst_ext_id, e.kind) for e in edges} == {
        (api.ext_id, s.ext_id, "exposes") for s in stages.values()}


def test_parse_api_v2_route_keys_and_waf_unsupported():
    fx = FIX["apigw_v2"]
    resources, edges = parse_api_v2(REGION, fx["api"], fx["stages"], fx["routes"],
                                    fx["authorizers"])
    api = resources[0]
    assert api.raw["api_version"] == "v2" and api.raw["protocol"] == "HTTP"
    routes = {r["path"]: r for r in api.raw["routes"]}
    assert routes["$default"]["method"] == "ANY"
    assert routes["/pets"]["method"] == "GET"
    assert routes["/pets"]["authorization_type"] == "JWT"

    stage = next(r for r in resources if r.kind == "aws_api_stage")
    assert stage.raw["waf_supported"] is False       # WAF cannot attach to HTTP APIs
    assert any(e.kind == "exposes" for e in edges)


# ── NHI extraction ────────────────────────────────────────────────────────────
def _kinds(resources):
    out: dict[str, int] = {}
    for r in resources:
        out[r.kind] = out.get(r.kind, 0) + 1
    return out


def _derived():
    base = [account_resource(), queue("orders"), queue("payments"),
            topic("alerts"), topic("billing"), bus("default"), bus("partner")]
    return derive_identities("aws", Collected(resources=list(base)))


def test_aws_has_an_extractor():
    assert "aws" in IDENTITY_EXTRACTORS


def test_wildcard_principal_is_one_identity_flagged_in_labels():
    col = _derived()
    identities = [r for r in col.resources if r.kind == "identity"]
    stars = [i for i in identities if i.raw["principal"] == "*"]
    # orders queue + alerts topic + default bus all grant "*" — ONE deduped identity
    assert len(stars) == 1
    star = stars[0]
    assert star.labels["identity_type"] == "wildcard"      # the label flag
    assert star.labels["external"] == "true"
    assert "wildcard_principal" in star.raw["tags"]
    # …holding a grant on each of the three public resources
    targets = {g.raw["target"] for g in col.resources
               if g.kind == "grant" and g.raw["identity_ext_id"] == star.ext_id}
    assert {"arn:aws:sqs:us-east-1:111111111111:orders",
            "arn:aws:sns:us-east-1:111111111111:alerts",
            "arn:aws:events:us-east-1:111111111111:event-bus/default"} <= targets


def test_cross_account_principal_is_external_own_account_is_not():
    col = _derived()
    by_name = {r.raw["principal"]: r for r in col.resources if r.kind == "identity"}
    assert by_name["arn:aws:iam::222222222222:root"].raw["external"] is True
    # billing topic names the bare account id "111111111111" — normalized to the root ARN
    assert by_name["arn:aws:iam::111111111111:root"].raw["external"] is False
    assert by_name["sns.amazonaws.com"].labels["identity_type"] == "service_principal"
    assert by_name["sns.amazonaws.com"].raw["external"] is False


def test_grants_carry_wildcard_flag_and_both_edges():
    col = _derived()
    grants = [r for r in col.resources if r.kind == "grant"]
    assert grants, "policies must produce grants"
    # sqs:* / sns:* / events:* actions are wildcard; sqs:SendMessage is not
    assert any(g.raw["wildcard"] for g in grants)
    scoped = [g for g in grants if g.raw["action"] == "sqs:sendmessage"]
    assert scoped and not scoped[0].raw["wildcard"] and scoped[0].raw["conditioned"] is True

    edge_kinds = {(e.src_ext_id, e.kind, e.dst_ext_id) for e in col.edges}
    for g in grants:
        assert (g.ext_id, "granted_to", g.raw["identity_ext_id"]) in edge_kinds
        assert (g.ext_id, "grants_access", g.raw["target"]) in edge_kinds


def test_no_credentials_and_no_duplicate_grants():
    col = _derived()
    # resource policies expose no secret material — absence, not silence
    assert _kinds(col.resources).get("credential") is None
    grant_ids = [r.ext_id for r in col.resources if r.kind == "grant"]
    assert len(grant_ids) == len(set(grant_ids))


def test_deny_statements_grant_nothing():
    q = queue("orders")
    q.raw["policy"] = {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "sqs:*"}]}
    col = derive_identities("aws", Collected(resources=[account_resource(), q]))
    assert _kinds(col.resources).get("identity") is None
    assert _kinds(col.resources).get("grant") is None
