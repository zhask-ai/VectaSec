"""The fix library (remediation.py). Pure, offline.

What is pinned and why:
  • Every exact key names a REGISTERED detector and every prefix key covers at least one —
    a fix for a rule that cannot fire is dead weight at best and, at worst, a command a
    customer runs against the wrong thing.
  • Lookup is compliance/map.py's rule: exact beats longest prefix.
  • Templating fills only what the resource actually carries and leaves visible placeholders
    otherwise — a fabricated ARN in a copy-paste command is worse than a blank.
  • Every snippet has a body and every Fix says what the rescan will check.
"""
import pytest

import vectasec.detect  # noqa: F401 — auto-register the rulepack
from vectasec import remediation as rem
from vectasec.registry import DETECTORS

RULE_IDS = {d.rule_id for d in DETECTORS}


# ═══ Library hygiene ═══════════════════════════════════════════════════════
def test_every_exact_key_names_a_registered_detector():
    missing = sorted(k for k in rem.FIX_LIBRARY if not k.endswith(".") and k not in RULE_IDS)
    assert not missing, f"fixes for rules that do not exist: {missing}"


def test_every_prefix_key_covers_at_least_one_detector():
    assert rem.PREFIX_KEYS, "the library is expected to carry at least one family key"
    dead = [k for k in rem.PREFIX_KEYS if not any(r.startswith(k) for r in RULE_IDS)]
    assert not dead, f"prefix keys that match no rule: {dead}"


@pytest.mark.parametrize("key", sorted(rem.FIX_LIBRARY))
def test_fix_is_complete(key):
    fix = rem.FIX_LIBRARY[key]
    assert fix.summary.strip()
    assert fix.steps and all(s.strip() for s in fix.steps)
    assert fix.snippets, f"{key} has no snippet — that is prose, not a fix"
    for s in fix.snippets:
        assert s.kind in ("cli", "terraform", "helm", "console", "config", "sql")
        assert s.title.strip() and s.body.strip(), f"{key}: empty snippet {s.title!r}"
    assert "rescan" in fix.verify_hint.lower(), f"{key}: verify_hint must say what the rescan checks"


REQUIRED = [
    "KAFKA.ACL.WILDCARD_PRINCIPAL", "KAFKA.ACL.WILDCARD_RESOURCE_ALL_OPERATIONS",
    "KAFKA.ACL.PREFIXED_OVERBROAD", "KAFKA.ACL.ANONYMOUS_PRINCIPAL", "KAFKA.AUTHZ.NO_AUTHORIZER",
    "KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL", "KAFKA.LISTENER.PLAINTEXT",
    "KAFKA.LISTENER.SASL_PLAINTEXT", "KAFKA.TOPIC.AUTO_CREATE_ENABLED",
    "KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED",
    "RABBITMQ.USER.DEFAULT_GUEST_PRESENT", "RABBITMQ.USER.GUEST_DEFAULT_PASSWORD_REMOTE",
    "RABBITMQ.USER.GUEST_REMOTE_LOGIN", "RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED",
    "RABBITMQ.LISTENER.AMQP_PLAINTEXT", "RABBITMQ.MGMT.HTTP_API_NO_TLS",
    "RABBITMQ.PERMISSION.WILDCARD_ALL", "RABBITMQ.PERMISSION.CONFIGURE_WILDCARD",
    "RABBITMQ.USER.ADMIN_TAG_SPRAWL",
    "REDIS.AUTH.NO_PASSWORD", "REDIS.TLS.DISABLED", "REDIS.USER.NOPASS",
    "REDIS.NETWORK.BIND_ALL", "REDIS.NETWORK.PROTECTED_MODE_OFF",
    "KONG.ADMIN.UNAUTHENTICATED", "KONG.ADMIN.LISTEN_WILDCARD", "KONG.ROUTE.NO_AUTH_PLUGIN",
    "KONG.ROUTE.HTTP_PROTOCOL_ALLOWED", "KONG.ROUTE.NO_RATE_LIMITING",
    "KONG.CONSUMER.NO_CREDENTIALS",
    "AWS.SQS.QUEUE_POLICY_PUBLIC", "AWS.SNS.TOPIC_POLICY_PUBLIC",
    "AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC", "AWS.SQS.POLICY_WILDCARD_ACTION",
    "AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT", "AWS.MSK.UNAUTHENTICATED_ACCESS",
    "AWS.MSK.PUBLIC_ACCESS_ENABLED", "AWS.APIGW.ROUTE_NO_AUTHORIZER",
    "AWS.SQS.ENCRYPTION_AT_REST_OFF",
    "K8S.MESH.MTLS_NOT_STRICT", "K8S.MESH.AUTHZ_ALLOW_ALL", "K8S.RBAC.SA_CLUSTER_ADMIN",
    "K8S.SA.DEFAULT_BOUND", "K8S.INGRESS.NO_TLS", "K8S.NETPOL.NO_DEFAULT_DENY",
    "MCP.AUTH.UNAUTHENTICATED_ENDPOINT", "MCP.TRANSPORT.PLAINTEXT_HTTP",
    "N8N.WORKFLOW.UNAUTHENTICATED_WEBHOOK",
    "CREDENTIAL.LIFECYCLE.NEVER_USED", "CREDENTIAL.LIFECYCLE.ROTATION_STALE",
    "CREDENTIAL.LIFECYCLE.DEFAULT_ACTIVE",
]


@pytest.mark.parametrize("rule_id", REQUIRED)
def test_required_rules_have_a_fix_and_exist(rule_id):
    assert rule_id in RULE_IDS, f"{rule_id} is not a registered detector"
    assert rem.fix_for(rule_id) is not None


# ═══ Lookup: exact beats longest prefix ════════════════════════════════════
def test_unknown_rule_is_none():
    assert rem.fix_for("NOPE.NOT.A_RULE") is None
    assert rem.lookup("RABBITMQ") is None          # no key, and prefixes need the dot


def test_prefix_key_resolves_family_members():
    key, fix = rem.lookup("RABBITMQ.PERMISSION.WILDCARD_ALL")
    assert key == "RABBITMQ.PERMISSION."
    assert fix is rem.FIX_LIBRARY["RABBITMQ.PERMISSION."]


def test_exact_key_beats_a_prefix(monkeypatch):
    exact = rem.FIX_LIBRARY["KAFKA.LISTENER.PLAINTEXT"]
    monkeypatch.setitem(rem.FIX_LIBRARY, "KAFKA.LISTENER.", rem.FIX_LIBRARY["KAFKA.LISTENER.SASL_PLAINTEXT"])
    key, fix = rem.lookup("KAFKA.LISTENER.PLAINTEXT")
    assert key == "KAFKA.LISTENER.PLAINTEXT" and fix is exact


def test_longest_prefix_wins(monkeypatch):
    short = rem.FIX_LIBRARY["RABBITMQ.PERMISSION."]
    longer = rem.FIX_LIBRARY["REDIS.AUTH.NO_PASSWORD"]
    monkeypatch.setitem(rem.FIX_LIBRARY, "RABBITMQ.", short)
    monkeypatch.setitem(rem.FIX_LIBRARY, "RABBITMQ.PERMISSION.SUB.", longer)
    key, fix = rem.lookup("RABBITMQ.PERMISSION.SUB.ANYTHING")
    assert key == "RABBITMQ.PERMISSION.SUB." and fix is longer
    # a key without the trailing dot is an exact key, never a prefix
    monkeypatch.setitem(rem.FIX_LIBRARY, "RABBITMQ.PERMISSION.SUB.ANY", longer)
    assert rem.lookup("RABBITMQ.PERMISSION.SUB.ANYTHING")[0] == "RABBITMQ.PERMISSION.SUB."


# ═══ Templating ════════════════════════════════════════════════════════════
def test_without_labels_placeholders_stay_visible():
    fix = rem.fix_for("AWS.SQS.QUEUE_POLICY_PUBLIC")
    body = fix.snippets[0].body
    assert "<QUEUE_URL>" in body and "<REGION>" in body
    assert "<ACCOUNT_ID>" in body


def test_with_labels_the_resource_specifics_are_filled_in():
    fix = rem.fix_for(
        "AWS.SQS.QUEUE_POLICY_PUBLIC",
        {"region": "eu-west-1", "service": "sqs"},
        {"queue_url": "https://sqs.eu-west-1.amazonaws.com/123456789012/orders",
         "queue_arn": "arn:aws:sqs:eu-west-1:123456789012:orders", "account": "123456789012"},
        name="orders", ext_id="arn:aws:sqs:eu-west-1:123456789012:orders", namespace="eu-west-1",
    )
    cli = fix.snippets[0].body
    assert "--queue-url https://sqs.eu-west-1.amazonaws.com/123456789012/orders" in cli
    assert "--region eu-west-1" in cli
    assert '"Resource": "arn:aws:sqs:eu-west-1:123456789012:orders"' in cli
    assert "<QUEUE_URL>" not in cli and "<REGION>" not in cli
    # the role name is not something the scan knows — it must remain a visible blank
    assert "<PRODUCER_ROLE>" in cli
    tf = next(s for s in fix.snippets if s.kind == "terraform").body
    assert 'queue_url = "https://sqs.eu-west-1.amazonaws.com/123456789012/orders"' in tf


def test_templating_never_mutates_the_library():
    before = rem.FIX_LIBRARY["KONG.ROUTE.NO_AUTH_PLUGIN"].snippets[0].body
    rem.fix_for("KONG.ROUTE.NO_AUTH_PLUGIN", {"protocols": "http,https"}, {},
                name="checkout", ext_id="kong-route-abc-123")
    assert rem.FIX_LIBRARY["KONG.ROUTE.NO_AUTH_PLUGIN"].snippets[0].body == before


def test_kong_route_id_is_taken_from_the_ext_id():
    fix = rem.fix_for("KONG.ROUTE.NO_AUTH_PLUGIN", {}, {}, name="checkout",
                      ext_id="kong-route-7d1e3f2a")
    assert "/routes/7d1e3f2a/plugins" in fix.snippets[0].body
    assert "route <ROUTE_ID>" not in fix.verify_hint and "7d1e3f2a" in fix.verify_hint


def test_rabbitmq_permission_templates_user_and_vhost():
    fix = rem.fix_for("RABBITMQ.PERMISSION.WILDCARD_ALL", {"user": "app", "vhost": "/"}, {})
    assert "set_permissions -p '/' 'app'" in fix.snippets[0].body
    assert "/api/permissions/%2F/app" in fix.snippets[1].body


def test_k8s_namespace_and_name_come_from_raw():
    fix = rem.fix_for("K8S.INGRESS.NO_TLS", {}, {"name": "web", "namespace": "shop", "tls": None},
                      name="web", namespace="shop")
    yaml = fix.snippets[0].body
    assert "name: web" in yaml and "namespace: shop" in yaml
    assert "Ingress `web` in shop" in fix.verify_hint


def test_credential_fix_branches_on_system():
    aws = rem.fix_for("CREDENTIAL.LIFECYCLE.NEVER_USED",
                      {"system": "aws", "credential_type": "access_key",
                       "owner": "identity:aws:deploy-bot"}, {"system": "aws"})
    assert all("aws iam" in s.body for s in aws.snippets)
    assert "--user-name deploy-bot" in aws.snippets[0].body
    assert "update-access-key" in aws.snippets[0].body and "--status Inactive" in aws.snippets[0].body
    assert "delete-access-key" in aws.snippets[0].body

    rmq = rem.fix_for("CREDENTIAL.LIFECYCLE.DEFAULT_ACTIVE",
                      {"system": "rabbitmq", "owner": "identity:rabbitmq:guest"}, {})
    assert len(rmq.snippets) == 1 and "rabbitmqctl" in rmq.snippets[0].body
    assert "'guest'" in rmq.snippets[0].body

    kafka = rem.fix_for("CREDENTIAL.LIFECYCLE.ROTATION_STALE", {"system": "kafka"}, {})
    assert "kafka-configs.sh" in kafka.snippets[0].body and "--delete-config 'SCRAM-SHA-512'" in kafka.snippets[0].body
    kong = rem.fix_for("CREDENTIAL.LIFECYCLE.ROTATION_STALE", {"system": "kong"}, {})
    assert "key-auth/<CREDENTIAL_ID>" in kong.snippets[0].body
    k8s = rem.fix_for("CREDENTIAL.LIFECYCLE.NEVER_USED", {"system": "k8s"}, {})
    assert "kubectl delete secret" in k8s.snippets[0].body

    # unknown system: every branch is offered rather than none
    generic = rem.fix_for("CREDENTIAL.LIFECYCLE.NEVER_USED", {"system": "solace"}, {})
    assert len(generic.snippets) > 1


def test_to_dict_shape():
    d = rem.fix_for("REDIS.AUTH.NO_PASSWORD").to_dict()
    assert set(d) == {"summary", "steps", "snippets", "verify_hint", "read_only_note"}
    assert set(d["snippets"][0]) == {"kind", "title", "body"}
    assert d["read_only_note"]


# ═══ coverage() ════════════════════════════════════════════════════════════
def test_coverage_shape_and_bounds():
    cov = rem.coverage()
    assert set(cov) == {"rules_with_fix", "rules_total"}
    assert cov["rules_total"] == len(RULE_IDS)
    assert len(REQUIRED) <= cov["rules_with_fix"] <= cov["rules_total"]


def test_coverage_counts_against_the_registry_it_is_given():
    class D:
        def __init__(self, rid):
            self.rule_id = rid
    cov = rem.coverage([D("REDIS.AUTH.NO_PASSWORD"), D("RABBITMQ.PERMISSION.WILDCARD_ALL"),
                        D("NOPE.X"), D("REDIS.AUTH.NO_PASSWORD")])
    assert cov == {"rules_with_fix": 2, "rules_total": 3}
