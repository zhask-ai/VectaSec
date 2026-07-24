"""Unit tests for the AWS rulepack. Offline: no boto3, no AWS account, no network.

Every rule gets a FIRE case and a DOES-NOT-FIRE case. Resources are built by feeding the
golden boto3-response fixtures (fixtures/aws_responses.json) through the connector's OWN
parse layer, so the detectors here run against exactly the shapes connect/aws.py emits —
a hand-written dict cannot drift past this suite.
"""
import copy
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.aws  # noqa: F401  — import registers the rulepack
from vectasec.connect.aws import (
    parse_api_v1, parse_api_v2, parse_bus, parse_msk_cluster, parse_queue, parse_rule,
    parse_subscription, parse_topic,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "aws_responses.json").read_text()
)
REGION = "us-east-1"

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("AWS.")}

# Every rule_id the pack is expected to ship. Kept explicit so silently dropping a detector
# fails a test rather than quietly shrinking coverage.
EXPECTED_RULES = {
    "AWS.SQS.QUEUE_POLICY_PUBLIC",
    "AWS.SQS.POLICY_WILDCARD_ACTION",
    "AWS.SQS.ENCRYPTION_AT_REST_OFF",
    "AWS.SQS.NO_DEAD_LETTER_QUEUE",
    "AWS.SNS.TOPIC_POLICY_PUBLIC",
    "AWS.SNS.POLICY_WILDCARD_ACTION",
    "AWS.SNS.ENCRYPTION_AT_REST_OFF",
    "AWS.SNS.SUBSCRIPTION_PLAINTEXT_HTTP",
    "AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC",
    "AWS.EVENTBRIDGE.BUS_POLICY_WILDCARD_ACTION",
    "AWS.EVENTBRIDGE.CROSS_ACCOUNT_TARGET",
    "AWS.MSK.UNAUTHENTICATED_ACCESS",
    "AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT",
    "AWS.MSK.INTERBROKER_PLAINTEXT",
    "AWS.MSK.PUBLIC_ACCESS_ENABLED",
    "AWS.MSK.ENHANCED_MONITORING_DEFAULT",
    "AWS.APIGW.ROUTE_NO_AUTHORIZER",
    "AWS.APIGW.ROUTE_API_KEY_ONLY",
    "AWS.APIGW.STAGE_LOGGING_DISABLED",
    "AWS.APIGW.STAGE_NO_WAF",
    "AWS.ACCOUNT.SERVICE_NOT_ASSESSED",
}


# ── builders: fixture → parse layer → Resource ────────────────────────────────
_JSON_STRING_ATTRS = ("Policy", "RedrivePolicy", "EventPattern")


def as_boto(d: dict) -> dict:
    out = dict(d)
    for k in _JSON_STRING_ATTRS:
        if isinstance(out.get(k), dict):
            out[k] = json.dumps(out[k])
    return out


def queue(name: str, attrs="fixture") -> Resource:
    a = as_boto(FIX["sqs"]["attributes"][name]) if attrs == "fixture" else attrs
    return parse_queue(REGION, f"https://sqs.{REGION}.amazonaws.com/111111111111/{name}", a)


def topic(name: str, attrs="fixture") -> Resource:
    a = as_boto(FIX["sns"]["attributes"][name]) if attrs == "fixture" else attrs
    arn = a["TopicArn"] if a else f"arn:aws:sns:{REGION}:111111111111:{name}"
    return parse_topic(REGION, arn, a)


def bus(name: str) -> Resource:
    b = next(x for x in FIX["events"]["buses"] if x["Name"] == name)
    return parse_bus(REGION, b, json.dumps(FIX["events"]["bus_policies"][name]))


def event_rule() -> Resource:
    b = bus("default")
    rule = as_boto(FIX["events"]["rules"]["default"][0])
    resources, _ = parse_rule(REGION, b.ext_id, rule,
                              FIX["events"]["targets"]["forward-orders"])
    return resources[0]


def msk(name: str) -> Resource:
    c = next(x for x in FIX["msk"]["clusters"] if x["ClusterName"] == name)
    return parse_msk_cluster(REGION, c)


def api_v1() -> list:
    fx = FIX["apigw_v1"]
    resources, _ = parse_api_v1(REGION, fx["api"], fx["stages"], fx["authorizers"],
                                fx["resources"])
    return resources


def api_v2() -> list:
    fx = FIX["apigw_v2"]
    resources, _ = parse_api_v2(REGION, fx["api"], fx["stages"], fx["routes"],
                                fx["authorizers"])
    return resources


def account(collection=None) -> Resource:
    ident = FIX["caller_identity"]
    return Resource(
        kind="aws_account", name=ident["Account"], ext_id=f"aws-account-{ident['Account']}",
        labels={"service": "sts", "auth_method": "assume_role"},
        raw={"account_id": ident["Account"], "caller_arn": ident["Arn"],
             "auth_method": "assume_role", "regions": [REGION],
             "collection": collection or {}},
    )


def scan(*resources) -> ScanContext:
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def fire(rule_id, resource, ctx=None) -> list:
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


def sev(hits, rule_id) -> list:
    base = RULES[rule_id].severity
    return [h.severity or base for h in hits]


# ── pack shape ────────────────────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_aws_kinds():
    for d in RULES.values():
        assert all(k.startswith("aws_") for k in d.kinds), d.rule_id


# ── SQS ───────────────────────────────────────────────────────────────────────
def test_sqs_public_policy_fires_and_cites_statement():
    hits = fire("AWS.SQS.QUEUE_POLICY_PUBLIC", queue("orders"))
    assert len(hits) == 1 and hits[0].assessable
    assert "AllowEveryone" in hits[0].observation and "Condition" in hits[0].observation
    assert sev(hits, "AWS.SQS.QUEUE_POLICY_PUBLIC") == ["critical"]


def test_sqs_public_policy_quiet_on_conditioned_policy():
    assert fire("AWS.SQS.QUEUE_POLICY_PUBLIC", queue("payments")) == []


def test_sqs_public_policy_not_assessable_when_attributes_denied():
    hits = fire("AWS.SQS.QUEUE_POLICY_PUBLIC", queue("orders", attrs=None))
    assert len(hits) == 1 and hits[0].assessable is False
    assert "AccessDenied" in hits[0].assessment_reason


def test_sqs_wildcard_action_fires_alongside_public():
    hits = fire("AWS.SQS.POLICY_WILDCARD_ACTION", queue("orders"))
    assert len(hits) == 1 and "sqs:*" in hits[0].observation
    assert fire("AWS.SQS.POLICY_WILDCARD_ACTION", queue("payments")) == []
    # unreadable attributes: the gap is filed once (by the public rule), not restated here
    assert fire("AWS.SQS.POLICY_WILDCARD_ACTION", queue("orders", attrs=None)) == []


def test_sqs_encryption_off_fires_and_sse_on_passes():
    hits = fire("AWS.SQS.ENCRYPTION_AT_REST_OFF", queue("orders"))
    assert len(hits) == 1 and "SqsManagedSseEnabled" in hits[0].observation
    assert fire("AWS.SQS.ENCRYPTION_AT_REST_OFF", queue("payments")) == []
    kms = queue("orders")
    kms.raw["kms_master_key_id"] = "alias/custom"
    assert fire("AWS.SQS.ENCRYPTION_AT_REST_OFF", kms) == []


def test_sqs_no_dlq_low_when_shared_info_when_private():
    hits = fire("AWS.SQS.NO_DEAD_LETTER_QUEUE", queue("orders"))     # has a resource policy
    assert sev(hits, "AWS.SQS.NO_DEAD_LETTER_QUEUE") == ["low"]
    private = queue("orders")
    private.raw["policy"] = None
    assert sev(fire("AWS.SQS.NO_DEAD_LETTER_QUEUE", private),
               "AWS.SQS.NO_DEAD_LETTER_QUEUE") == ["info"]
    assert fire("AWS.SQS.NO_DEAD_LETTER_QUEUE", queue("payments")) == []   # has RedrivePolicy


def test_sqs_no_dlq_skips_queues_that_are_dlqs():
    dlq = parse_queue(REGION, f"https://sqs.{REGION}.amazonaws.com/111111111111/payments-dlq",
                      {"QueueArn": f"arn:aws:sqs:{REGION}:111111111111:payments-dlq"})
    assert fire("AWS.SQS.NO_DEAD_LETTER_QUEUE", dlq) == []


# ── SNS ───────────────────────────────────────────────────────────────────────
def test_sns_public_policy_fire_and_pass():
    hits = fire("AWS.SNS.TOPIC_POLICY_PUBLIC", topic("alerts"))
    assert len(hits) == 1 and "OpenTopic" in hits[0].observation
    assert fire("AWS.SNS.TOPIC_POLICY_PUBLIC", topic("billing")) == []


def test_sns_public_policy_not_assessable_when_attributes_denied():
    hits = fire("AWS.SNS.TOPIC_POLICY_PUBLIC", topic("alerts", attrs=None))
    assert len(hits) == 1 and hits[0].assessable is False


def test_sns_wildcard_action_fire_and_pass():
    assert len(fire("AWS.SNS.POLICY_WILDCARD_ACTION", topic("alerts"))) == 1
    assert fire("AWS.SNS.POLICY_WILDCARD_ACTION", topic("billing")) == []


def test_sns_encryption_fire_and_pass():
    hits = fire("AWS.SNS.ENCRYPTION_AT_REST_OFF", topic("alerts"))
    assert len(hits) == 1 and "KmsMasterKeyId" in hits[0].observation
    assert fire("AWS.SNS.ENCRYPTION_AT_REST_OFF", topic("billing")) == []


def test_sns_http_subscription_fires_https_and_sqs_pass():
    subs = [parse_subscription(REGION, s) for s in FIX["sns"]["subscriptions"]["alerts"]]
    http, https_pending = subs
    hits = fire("AWS.SNS.SUBSCRIPTION_PLAINTEXT_HTTP", http)
    assert len(hits) == 1 and "http://hooks.example.com/ingest" in hits[0].observation
    assert fire("AWS.SNS.SUBSCRIPTION_PLAINTEXT_HTTP", https_pending) == []
    sqs_sub = parse_subscription(REGION, FIX["sns"]["subscriptions"]["billing"][0])
    assert fire("AWS.SNS.SUBSCRIPTION_PLAINTEXT_HTTP", sqs_sub) == []


# ── EventBridge ───────────────────────────────────────────────────────────────
def test_bus_public_policy_fire_and_pass():
    hits = fire("AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC", bus("default"))
    assert len(hits) == 1 and "AllowAnySender" in hits[0].observation
    assert fire("AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC", bus("partner")) == []


def test_bus_wildcard_action_fire_and_pass():
    # partner bus grants events:* to a specific account — wildcard fires, public does not
    hits = fire("AWS.EVENTBRIDGE.BUS_POLICY_WILDCARD_ACTION", bus("partner"))
    assert len(hits) == 1 and "events:*" in hits[0].observation
    # default bus is public but its action list is exact — wildcard stays quiet
    assert fire("AWS.EVENTBRIDGE.BUS_POLICY_WILDCARD_ACTION", bus("default")) == []


def test_cross_account_target_fires_only_for_foreign_account():
    r = event_rule()
    hits = fire("AWS.EVENTBRIDGE.CROSS_ACCOUNT_TARGET", r)
    assert len(hits) == 1
    assert "222222222222" in hits[0].observation and "to-partner-bus" in hits[0].detail
    same_account = copy.deepcopy(r)
    same_account.raw["targets"] = [t for t in same_account.raw["targets"]
                                   if "222222222222" not in str(t["arn"])]
    assert fire("AWS.EVENTBRIDGE.CROSS_ACCOUNT_TARGET", same_account) == []


# ── MSK ───────────────────────────────────────────────────────────────────────
def test_msk_unauthenticated_escalates_to_critical_when_public():
    hits = fire("AWS.MSK.UNAUTHENTICATED_ACCESS", msk("wide-open"))
    assert sev(hits, "AWS.MSK.UNAUTHENTICATED_ACCESS") == ["critical"]
    private = msk("wide-open")
    private.raw["public_access_type"] = "DISABLED"
    assert sev(fire("AWS.MSK.UNAUTHENTICATED_ACCESS", private),
               "AWS.MSK.UNAUTHENTICATED_ACCESS") == ["high"]
    assert fire("AWS.MSK.UNAUTHENTICATED_ACCESS", msk("hardened")) == []


def test_msk_client_plaintext_fire_and_pass():
    hits = fire("AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT", msk("wide-open"))
    assert len(hits) == 1 and "TLS_PLAINTEXT" in hits[0].observation
    assert fire("AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT", msk("hardened")) == []
    assert fire("AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT", msk("on-demand")) == []


def test_msk_interbroker_plaintext_fire_and_pass():
    assert len(fire("AWS.MSK.INTERBROKER_PLAINTEXT", msk("wide-open"))) == 1
    assert fire("AWS.MSK.INTERBROKER_PLAINTEXT", msk("hardened")) == []
    # serverless clusters have no broker replication surface to configure
    assert fire("AWS.MSK.INTERBROKER_PLAINTEXT", msk("on-demand")) == []


def test_msk_public_access_fire_and_pass():
    hits = fire("AWS.MSK.PUBLIC_ACCESS_ENABLED", msk("wide-open"))
    assert len(hits) == 1 and "SERVICE_PROVIDED_EIPS" in hits[0].observation
    assert fire("AWS.MSK.PUBLIC_ACCESS_ENABLED", msk("hardened")) == []


def test_msk_monitoring_default_fire_and_pass():
    assert len(fire("AWS.MSK.ENHANCED_MONITORING_DEFAULT", msk("wide-open"))) == 1
    assert fire("AWS.MSK.ENHANCED_MONITORING_DEFAULT", msk("hardened")) == []
    assert fire("AWS.MSK.ENHANCED_MONITORING_DEFAULT", msk("on-demand")) == []


# ── API Gateway ───────────────────────────────────────────────────────────────
def test_apigw_v1_no_authorizer_fires_per_open_route_skips_options():
    api = api_v1()[0]
    hits = fire("AWS.APIGW.ROUTE_NO_AUTHORIZER", api)
    assessable = [h for h in hits if h.assessable]
    # GET /public is the only open route: POST /orders has an authorizer, GET /metrics is
    # api-key-only (a different rule), OPTIONS is CORS preflight
    assert len(assessable) == 1 and "GET /public" in assessable[0].observation
    # the unreadable method (/opaque) is a coverage gap, never reported as unauthenticated
    gaps = [h for h in hits if not h.assessable]
    assert len(gaps) == 1 and "/opaque" in gaps[0].observation


def test_apigw_v2_default_route_fires_jwt_route_passes():
    api = api_v2()[0]
    hits = fire("AWS.APIGW.ROUTE_NO_AUTHORIZER", api)
    assert len(hits) == 1 and "$default" in hits[0].observation
    secured = copy.deepcopy(api)
    for r in secured.raw["routes"]:
        r["authorization_type"] = "JWT"
    assert fire("AWS.APIGW.ROUTE_NO_AUTHORIZER", secured) == []


def test_apigw_api_key_only_fire_and_pass():
    api = api_v1()[0]
    hits = fire("AWS.APIGW.ROUTE_API_KEY_ONLY", api)
    assert len(hits) == 1 and "GET /metrics" in hits[0].observation
    assert fire("AWS.APIGW.ROUTE_API_KEY_ONLY", api_v2()[0]) == []


def test_apigw_stage_logging_fire_and_pass():
    stages = {r.name: r for r in api_v1() if r.kind == "aws_api_stage"}
    hits = fire("AWS.APIGW.STAGE_LOGGING_DISABLED", stages["prod"])
    assert len(hits) == 1 and "OFF" in hits[0].observation
    assert fire("AWS.APIGW.STAGE_LOGGING_DISABLED", stages["hardened"]) == []
    # v2 stage with no access log destination fires too
    v2_stage = next(r for r in api_v2() if r.kind == "aws_api_stage")
    assert len(fire("AWS.APIGW.STAGE_LOGGING_DISABLED", v2_stage)) == 1


def test_apigw_no_waf_fires_on_rest_only():
    stages = {r.name: r for r in api_v1() if r.kind == "aws_api_stage"}
    assert len(fire("AWS.APIGW.STAGE_NO_WAF", stages["prod"])) == 1
    assert fire("AWS.APIGW.STAGE_NO_WAF", stages["hardened"]) == []
    # WAF cannot associate with HTTP APIs — flagging one would be unactionable
    v2_stage = next(r for r in api_v2() if r.kind == "aws_api_stage")
    assert fire("AWS.APIGW.STAGE_NO_WAF", v2_stage) == []


# ── account coverage gaps ─────────────────────────────────────────────────────
def test_denied_service_is_not_assessable_never_a_pass():
    acct = account(collection={
        "sqs:us-east-1": {"outcome": "ok", "error": None, "resources": 2},
        "msk:us-east-1": {"outcome": "access_denied", "error": "AccessDeniedException"},
        "events:us-east-1": {"outcome": "error", "error": "EndpointConnectionError: boom"},
    })
    hits = fire("AWS.ACCOUNT.SERVICE_NOT_ASSESSED", acct)
    # only the DENIED service is a permissions coverage gap; ok and transport errors are not
    assert len(hits) == 1
    assert hits[0].assessable is False and "msk" in hits[0].observation
    assert "AccessDeniedException" in hits[0].assessment_reason


def test_clean_collection_reports_nothing():
    acct = account(collection={"sqs:us-east-1": {"outcome": "ok", "error": None}})
    assert fire("AWS.ACCOUNT.SERVICE_NOT_ASSESSED", acct) == []
