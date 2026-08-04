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
import vectasec.connect.gcp as connect_gcp
import vectasec.detect.gcp  # noqa: F401  — import registers the rulepack
from vectasec.connect.gcp import (
    _Denied, parse_apigee_org, parse_apigee_proxy, parse_project, parse_pubsub_subscription,
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


def proxy(name: str, targets="fixture", deployments="fixture",
          unreadable_targets=()) -> Resource:
    deps = ([d for d in FIX["apigee"]["deployments"] if d["apiProxy"] == name]
            if deployments == "fixture" else deployments)
    t = FIX["apigee"]["targets"].get(name) if targets == "fixture" else targets
    return parse_apigee_proxy(PROJECT, name, deps, t,
                              unreadable_targets=unreadable_targets)


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


def test_apigee_one_unreadable_target_clears_the_flag_and_keeps_its_siblings():
    """Dropping an unreadable target while leaving targets_readable True is the worst shape
    available: the detector believes the list is complete, so a target whose config was
    refused simply vanishes. The flag must fall, and the targets that WERE read must still be
    assessed — a refused sibling cannot suppress a plaintext backend sitting in the list."""
    partial = proxy("orders-proxy", unreadable_targets=["billing-backend"])
    assert partial.raw["targets_readable"] is False
    hits = fire("GCP.APIGEE.TARGET_NO_TLS", partial)
    gaps = [h for h in hits if not h.assessable]
    real = [h for h in hits if h.assessable]
    assert len(gaps) == 1 and "billing-backend" in gaps[0].observation
    assert len(real) == 1 and "http://internal-api.example.com" in real[0].observation


def test_apigee_unreadable_deployments_do_not_read_as_an_undeployed_proxy():
    """deployments=[] is what a parked proxy looks like, and parked proxies are skipped — so
    a denied deployments list would silently retire the whole Apigee surface."""
    unknown = proxy("orders-proxy", targets=None, deployments=None)
    assert unknown.labels["deployed"] == "unknown"
    hits = fire("GCP.APIGEE.TARGET_NO_TLS", unknown)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "deployment state" in hits[0].observation
    # filed once: the targets gap is subsumed and the legacy-TLS rule stays quiet
    assert "targets_readable" not in hits[0].detail
    assert fire("GCP.APIGEE.TARGET_LEGACY_TLS", unknown) == []


def test_apigee_org_records_whether_the_proxy_list_was_readable():
    assert parse_apigee_org(FIX["apigee"]["org"], []).raw["proxies_readable"] is True
    denied = parse_apigee_org(FIX["apigee"]["org"], None, proxies_readable=False)
    assert denied.raw["proxies_readable"] is False
    assert denied.raw["envgroups_readable"] is False


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


def test_denied_child_read_under_an_ok_service_is_a_coverage_gap():
    """The surface listed fine, so outcome stays 'ok' — but children under it were never
    collected and left no resource behind to carry the gap. Reporting nothing here is exactly
    how a partial collection scores as full coverage."""
    p = project(collection={
        "pubsub": {"outcome": "ok", "error": None, "resources": 5},
        "apigee": {"outcome": "ok", "error": None, "resources": 1,
                   "child_gaps": [{"parent": "organization acme-prod",
                                   "child": "apis (proxy list)", "error": "http_403"}]},
    })
    hits = fire("GCP.PROJECT.SERVICE_NOT_ASSESSED", p)
    assert len(hits) == 1 and hits[0].assessable is False
    assert hits[0].source_ref["service"] == "apigee"
    assert "apis (proxy list) of organization acme-prod" in hits[0].observation


# ── collection: a denied CHILD read inside a surface that listed fine ─────────
# httpx never appears here either: _gget is the seam, so a stub keyed on the URL path drives
# the real except branches offline.
def _apigee_gget(deny=()):
    fx = FIX["apigee"]

    def _get(_client, _headers, url, params=None):
        path = url.split(f"/organizations/{PROJECT}", 1)[-1].lstrip("/")
        if path in deny:
            raise _Denied(403, "IAM_PERMISSION_DENIED")
        if not path:
            return fx["org"]
        if path == "envgroups":
            return {"environmentGroups": fx["envgroups"]}
        if path == "apis":
            return {"proxies": fx["proxies"]}
        if path == "deployments":
            return {"deployments": fx["deployments"]}
        parts = path.split("/")        # apis/<proxy>/revisions/<rev>/targets[/<name>]
        details = fx["targets"].get(parts[1]) or []
        if len(parts) == 5:
            return [d["name"] for d in details]
        return next(d for d in details if d["name"] == parts[5])
    return _get


def _collect_apigee(monkeypatch, deny=()):
    monkeypatch.setattr(connect_gcp, "_gget", _apigee_gget(deny))
    return connect_gcp._collect_apigee(None, {}, PROJECT)


def test_collect_apigee_fully_readable_records_no_gap(monkeypatch):
    resources, _edges, gaps = _collect_apigee(monkeypatch)
    assert gaps == []
    proxies = {r.name: r for r in resources if r.kind == "gcp_apigee_proxy"}
    assert set(proxies) == {"orders-proxy", "secure-proxy", "parked-proxy"}
    assert proxies["orders-proxy"].raw["targets_readable"] is True
    assert proxies["orders-proxy"].labels["deployed"] == "true"
    assert proxies["parked-proxy"].labels["deployed"] == "false"


def test_collect_apigee_denied_proxy_list_and_envgroups_are_recorded(monkeypatch):
    resources, _edges, gaps = _collect_apigee(monkeypatch, deny={"apis", "envgroups"})
    org = next(r for r in resources if r.kind == "gcp_apigee_org")
    assert org.raw["proxies_readable"] is False and org.raw["envgroups_readable"] is False
    # not one proxy resource exists, so every Apigee proxy rule is silent for want of a subject
    assert [r for r in resources if r.kind == "gcp_apigee_proxy"] == []
    assert {g["child"] for g in gaps} == {"apis (proxy list)", "envgroups"}


def test_collect_apigee_denied_deployments_leave_every_proxy_unknown(monkeypatch):
    resources, _edges, gaps = _collect_apigee(monkeypatch, deny={"deployments"})
    proxies = [r for r in resources if r.kind == "gcp_apigee_proxy"]
    assert proxies and all(p.raw["deployments_readable"] is False for p in proxies)
    assert all(p.labels["deployed"] == "unknown" for p in proxies)
    # filed once, per proxy, by GCP.APIGEE.TARGET_NO_TLS — not restated at project scope
    assert gaps == []


def test_collect_apigee_one_denied_target_config_is_named_not_dropped(monkeypatch):
    resources, _edges, _gaps = _collect_apigee(
        monkeypatch, deny={"apis/orders-proxy/revisions/3/targets/default"})
    orders = next(r for r in resources if r.name == "orders-proxy")
    assert orders.raw["targets_readable"] is False
    assert orders.raw["unreadable_targets"] == ["default"]
    # the sibling proxy is untouched by its neighbour's denial
    secure = next(r for r in resources if r.name == "secure-proxy")
    assert secure.raw["targets_readable"] is True and len(secure.raw["targets"]) == 1


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
