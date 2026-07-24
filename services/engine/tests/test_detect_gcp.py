"""Unit tests for the GCP rulepack and NHI extraction. Offline: no httpx client is ever
constructed, no project is touched, no JWT is ever signed.

Every rule gets a FIRE case and a DOES-NOT-FIRE case. Resources are built by feeding the
golden REST-response fixtures (fixtures/gcp_responses.json) through the connector's OWN
parse layer, so the detectors here run against exactly the shapes connect/gcp.py emits —
a hand-written dict cannot drift past this suite.
"""
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS
from vectasec.registry import CONNECTOR_FIELDS, DETECTORS
import vectasec.detect.gcp  # noqa: F401  — import registers the rulepack
from vectasec.connect.gcp import (
    parse_apigee_org, parse_apigee_proxy, parse_project, parse_pubsub_subscription,
    parse_pubsub_topic,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "gcp_responses.json").read_text()
)
PROJECT = FIX["project"]

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("GCP.")}

# Every rule_id the pack is expected to ship. Kept explicit so silently dropping a detector
# fails a test rather than quietly shrinking coverage.
EXPECTED_RULES = {
    "GCP.PUBSUB.TOPIC_IAM_PUBLIC",
    "GCP.PUBSUB.SUBSCRIPTION_IAM_PUBLIC",
    "GCP.PUBSUB.BROAD_ROLE_BINDING",
    "GCP.PUBSUB.IAM_NOT_READABLE",
    "GCP.PUBSUB.TOPIC_NO_CMEK",
    "GCP.PUBSUB.PUSH_ENDPOINT_NOT_HTTPS",
    "GCP.PUBSUB.PUSH_NO_AUTH",
    "GCP.PUBSUB.SUBSCRIPTION_NO_DEAD_LETTER",
    "GCP.APIGEE.TARGET_NO_TLS",
    "GCP.APIGEE.TARGET_LEGACY_TLS",
    "GCP.PROJECT.AUDIT_LOGGING_DISABLED",
    "GCP.PROJECT.SERVICE_NOT_ASSESSED",
}


# ── builders: fixture → parse layer → Resource ────────────────────────────────
def topic(name: str, policy="fixture") -> Resource:
    t = next(x for x in FIX["topics"] if x["name"].endswith(f"/{name}"))
    p = FIX["topic_policies"][name] if policy == "fixture" else policy
    return parse_pubsub_topic(PROJECT, t, p)


def sub(name: str, policy="fixture") -> Resource:
    s = next(x for x in FIX["subscriptions"] if x["name"].endswith(f"/{name}"))
    p = FIX["subscription_policies"][name] if policy == "fixture" else policy
    return parse_pubsub_subscription(PROJECT, s, p)


def proxy(name: str, targets="fixture") -> Resource:
    deps = [d for d in FIX["apigee"]["deployments"] if d["apiProxy"] == name]
    t = FIX["apigee"]["targets"].get(name) if targets == "fixture" else targets
    return parse_apigee_proxy(PROJECT, name, deps, t)


def project(iam="fixture", collection=None) -> Resource:
    p = FIX["project_policy"] if iam == "fixture" else iam
    return parse_project(PROJECT, p, collection or {}, "service_account_key")


def scan(*resources) -> ScanContext:
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def fire(rule_id, resource, ctx=None) -> list:
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


# ── pack shape ────────────────────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_gcp_kinds():
    for d in RULES.values():
        assert all(k.startswith("gcp_") for k in d.kinds), d.rule_id


def test_connector_declares_secret_fields():
    fields = {f.key: f for f in CONNECTOR_FIELDS["gcp"]}
    assert fields["service_account_key"].secret is True
    assert fields["access_token"].secret is True


# ── Pub/Sub IAM ───────────────────────────────────────────────────────────────
def test_topic_public_binding_fires_critical_and_cites_role():
    hits = fire("GCP.PUBSUB.TOPIC_IAM_PUBLIC", topic("orders"))
    assert len(hits) == 1
    assert "allUsers" in hits[0].observation and "roles/pubsub.publisher" in hits[0].observation
    assert RULES["GCP.PUBSUB.TOPIC_IAM_PUBLIC"].severity == "critical"
    assert fire("GCP.PUBSUB.TOPIC_IAM_PUBLIC", topic("payments")) == []


def test_subscription_public_binding_fires_and_scoped_passes():
    hits = fire("GCP.PUBSUB.SUBSCRIPTION_IAM_PUBLIC", sub("orders-push"))
    assert len(hits) == 1 and "allAuthenticatedUsers" in hits[0].observation
    assert "Google-authenticated" in hits[0].observation
    assert fire("GCP.PUBSUB.SUBSCRIPTION_IAM_PUBLIC", sub("orders-push-secure")) == []


def test_broad_role_fires_for_concrete_principal_not_wildcard():
    # orders binds roles/editor to a service account AND roles/pubsub.publisher to allUsers:
    # the broad-role rule reports only the editor binding (wildcard is the critical rule's)
    hits = fire("GCP.PUBSUB.BROAD_ROLE_BINDING", topic("orders"))
    assert len(hits) == 1
    assert "roles/editor" in hits[0].observation
    assert "legacy-app@acme-prod.iam.gserviceaccount.com" in hits[0].observation
    assert "allUsers" not in hits[0].detail
    assert fire("GCP.PUBSUB.BROAD_ROLE_BINDING", topic("payments")) == []
    assert fire("GCP.PUBSUB.BROAD_ROLE_BINDING", sub("orders-push-secure")) == []


def test_iam_not_readable_is_a_coverage_gap_not_a_pass():
    gap = topic("orders", policy=None)
    for rule in ("GCP.PUBSUB.TOPIC_IAM_PUBLIC", "GCP.PUBSUB.BROAD_ROLE_BINDING"):
        assert fire(rule, gap) == []   # silence, because the gap rule files the finding
    hits = fire("GCP.PUBSUB.IAM_NOT_READABLE", gap)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "getIamPolicy" in hits[0].assessment_reason
    assert fire("GCP.PUBSUB.IAM_NOT_READABLE", topic("orders")) == []
    # empty bindings but readable is a real (clean) answer, not a gap
    assert fire("GCP.PUBSUB.IAM_NOT_READABLE", sub("payments-pull")) == []


# ── Pub/Sub configuration ─────────────────────────────────────────────────────
def test_topic_no_cmek_fire_and_pass():
    hits = fire("GCP.PUBSUB.TOPIC_NO_CMEK", topic("orders"))
    assert len(hits) == 1 and "kmsKeyName" in hits[0].observation
    assert fire("GCP.PUBSUB.TOPIC_NO_CMEK", topic("payments")) == []


def test_push_plaintext_fires_https_and_pull_pass():
    hits = fire("GCP.PUBSUB.PUSH_ENDPOINT_NOT_HTTPS", sub("orders-push"))
    assert len(hits) == 1 and "http://hooks.example.com/ingest" in hits[0].observation
    assert fire("GCP.PUBSUB.PUSH_ENDPOINT_NOT_HTTPS", sub("orders-push-secure")) == []
    assert fire("GCP.PUBSUB.PUSH_ENDPOINT_NOT_HTTPS", sub("payments-pull")) == []


def test_push_no_auth_fires_oidc_and_pull_pass():
    hits = fire("GCP.PUBSUB.PUSH_NO_AUTH", sub("orders-push"))
    assert len(hits) == 1 and "oidcToken" in hits[0].observation
    assert fire("GCP.PUBSUB.PUSH_NO_AUTH", sub("orders-push-secure")) == []
    assert fire("GCP.PUBSUB.PUSH_NO_AUTH", sub("payments-pull")) == []


def test_no_dead_letter_low_when_push_info_when_pull_and_dlq_passes():
    hits = fire("GCP.PUBSUB.SUBSCRIPTION_NO_DEAD_LETTER", sub("orders-push"))
    assert [h.severity or RULES["GCP.PUBSUB.SUBSCRIPTION_NO_DEAD_LETTER"].severity
            for h in hits] == ["low"]
    pull = sub("payments-pull")
    pull.raw["dead_letter_topic"] = None
    hits = fire("GCP.PUBSUB.SUBSCRIPTION_NO_DEAD_LETTER", pull)
    assert [h.severity for h in hits] == ["info"]
    assert fire("GCP.PUBSUB.SUBSCRIPTION_NO_DEAD_LETTER", sub("orders-push-secure")) == []


# ── Apigee ────────────────────────────────────────────────────────────────────
def test_apigee_no_tls_fires_and_https_target_passes():
    hits = fire("GCP.APIGEE.TARGET_NO_TLS", proxy("orders-proxy"))
    assert len(hits) == 1 and hits[0].assessable
    assert "http://internal-api.example.com" in hits[0].observation
    assert fire("GCP.APIGEE.TARGET_NO_TLS", proxy("secure-proxy")) == []


def test_apigee_legacy_tls_fires_on_protocol_list():
    hits = fire("GCP.APIGEE.TARGET_LEGACY_TLS", proxy("secure-proxy"))
    assert len(hits) == 1 and "TLSv1.1" in hits[0].observation
    assert fire("GCP.APIGEE.TARGET_LEGACY_TLS", proxy("orders-proxy")) == []


def test_apigee_undeployed_proxy_is_silent():
    parked = proxy("parked-proxy", targets=None)
    assert fire("GCP.APIGEE.TARGET_NO_TLS", parked) == []
    assert fire("GCP.APIGEE.TARGET_LEGACY_TLS", parked) == []


def test_apigee_unreadable_targets_not_assessable_filed_once():
    gap = proxy("orders-proxy", targets=None)
    hits = fire("GCP.APIGEE.TARGET_NO_TLS", gap)
    assert len(hits) == 1 and hits[0].assessable is False
    # the legacy-TLS rule stays quiet: the gap is filed once, by TARGET_NO_TLS
    assert fire("GCP.APIGEE.TARGET_LEGACY_TLS", gap) == []


# ── project posture ───────────────────────────────────────────────────────────
def test_audit_logging_missing_fires_and_configured_passes():
    hits = fire("GCP.PROJECT.AUDIT_LOGGING_DISABLED", project())
    assert len(hits) == 1 and "auditConfig" in hits[0].observation
    audited = project(iam=FIX["project_policy_audited"])
    assert fire("GCP.PROJECT.AUDIT_LOGGING_DISABLED", audited) == []


def test_audit_logging_unreadable_policy_not_assessable():
    hits = fire("GCP.PROJECT.AUDIT_LOGGING_DISABLED", project(iam=None))
    assert len(hits) == 1 and hits[0].assessable is False


def test_denied_and_disabled_services_are_gaps_never_passes():
    p = project(collection={
        "pubsub": {"outcome": "ok", "error": None, "resources": 5},
        "apigee": {"outcome": "api_disabled", "error": "http_403 SERVICE_DISABLED"},
        "resourcemanager": {"outcome": "access_denied", "error": "http_403"},
    })
    hits = fire("GCP.PROJECT.SERVICE_NOT_ASSESSED", p)
    assert len(hits) == 2 and all(h.assessable is False for h in hits)
    by_service = {h.source_ref["service"]: h for h in hits}
    assert "not enabled" in by_service["apigee"].observation
    assert "was denied" in by_service["resourcemanager"].observation


def test_clean_collection_reports_nothing():
    p = project(collection={"pubsub": {"outcome": "ok", "error": None}})
    assert fire("GCP.PROJECT.SERVICE_NOT_ASSESSED", p) == []


# ── NHI derivation ────────────────────────────────────────────────────────────
def _derive(*resources):
    return IDENTITY_EXTRACTORS["gcp"](list(resources))


def test_wildcard_members_become_wildcard_identities():
    out, _ = _derive(topic("orders"), sub("orders-push"))
    wild = {i.name for i in out if i.kind == "identity"
            and i.labels["identity_type"] == "wildcard"}
    assert wild == {"allUsers", "allAuthenticatedUsers"}
    for i in out:
        if i.kind == "identity" and i.labels["identity_type"] == "wildcard":
            assert i.raw["external"] is True and "wildcard_principal" in i.raw["tags"]


def test_grants_per_member_role_resource_with_edges():
    t = topic("orders")
    out, edges = _derive(t)
    grants = [g for g in out if g.kind == "grant"]
    # orders: allUsers→publisher, legacy-app→editor = 2 grants
    assert len(grants) == 2
    editor = next(g for g in grants if g.raw["action"] == "roles/editor")
    assert editor.raw["wildcard"] is True          # broad role → wildcard-flagged
    assert editor.raw["target"] == t.ext_id
    pub = next(g for g in grants if g.raw["action"] == "roles/pubsub.publisher")
    assert pub.raw["wildcard"] is True             # allUsers member → wildcard-flagged
    for g in grants:
        kinds = {e.kind for e in edges if e.src_ext_id == g.ext_id}
        assert kinds == {"granted_to", "grants_access"}


def test_narrow_binding_to_service_account_is_not_wildcard():
    out, _ = _derive(topic("payments"))
    grants = [g for g in out if g.kind == "grant"]
    assert len(grants) == 2 and all(g.raw["wildcard"] is False for g in grants)
    idents = [i for i in out if i.kind == "identity"]
    assert all(i.labels["identity_type"] == "service_account" for i in idents)
    assert all(i.raw["external"] is False for i in idents)


def test_identities_dedupe_across_resources():
    # legacy-app appears in both the orders topic policy and the project policy
    out, _ = _derive(topic("orders"), project())
    legacy = [i for i in out if i.kind == "identity"
              and i.name.startswith("serviceAccount:legacy-app")]
    assert len(legacy) == 1
    grants = [g for g in out if g.kind == "grant"
              and g.raw["identity_ext_id"] == legacy[0].ext_id]
    assert len(grants) == 2   # one per (role, resource)


def test_no_credentials_emitted_and_unreadable_policy_derives_nothing():
    out, edges = _derive(topic("orders", policy=None), sub("payments-pull"))
    # IAM bindings expose no credential material — absence, not silence
    assert [r for r in out if r.kind == "credential"] == []
    # unreadable policy + empty bindings → no identities at all
    assert [r for r in out if r.kind == "identity"] == []
