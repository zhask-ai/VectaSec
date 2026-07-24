"""Unit tests for the Azure rulepack and NHI extraction. Offline: no httpx client is ever
constructed, no tenant is touched.

Every rule gets a FIRE case and a DOES-NOT-FIRE case. Resources are built by feeding the
golden ARM-response fixtures (fixtures/azure_responses.json) through the connector's OWN
parse layer, so the detectors here run against exactly the shapes connect/azure.py emits —
a hand-written dict cannot drift past this suite.
"""
import copy
import json
import pathlib

from vectasec.contracts import Resource, ScanContext
from vectasec.identity import IDENTITY_EXTRACTORS
from vectasec.registry import CONNECTOR_FIELDS, DETECTORS
import vectasec.detect.azure  # noqa: F401  — import registers the rulepack
from vectasec.connect.azure import (
    parse_apim, parse_apim_api, parse_capture_storage, parse_eh_namespace, parse_event_hub,
    parse_logic_app, parse_sb_namespace, parse_sb_queue, parse_sb_topic,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "azure_responses.json").read_text()
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("AZURE.")}

# Every rule_id the pack is expected to ship. Kept explicit so silently dropping a detector
# fails a test rather than quietly shrinking coverage.
EXPECTED_RULES = {
    "AZURE.SERVICEBUS.PUBLIC_NETWORK_ACCESS",
    "AZURE.SERVICEBUS.LOCAL_AUTH_ENABLED",
    "AZURE.SERVICEBUS.TLS_MIN_LEGACY",
    "AZURE.SERVICEBUS.MANAGE_SAS_RULE",
    "AZURE.SERVICEBUS.QUEUE_NO_DEAD_LETTERING",
    "AZURE.EVENTHUB.PUBLIC_NETWORK_ACCESS",
    "AZURE.EVENTHUB.LOCAL_AUTH_ENABLED",
    "AZURE.EVENTHUB.TLS_MIN_LEGACY",
    "AZURE.EVENTHUB.MANAGE_SAS_RULE",
    "AZURE.EVENTHUB.CAPTURE_PUBLIC_STORAGE",
    "AZURE.APIM.LEGACY_TLS_CIPHERS",
    "AZURE.APIM.API_SUBSCRIPTION_KEY_ONLY",
    "AZURE.APIM.PUBLIC_NO_NETWORK_RESTRICTIONS",
    "AZURE.LOGICAPP.HTTP_TRIGGER_OPEN",
    "AZURE.LOGICAPP.WORKFLOW_DISABLED",
    "AZURE.SUBSCRIPTION.SERVICE_NOT_ASSESSED",
}


# ── builders: fixture → parse layer → Resource ────────────────────────────────
def sb_ns(name: str, rules="fixture") -> Resource:
    ns = next(x for x in FIX["servicebus"]["namespaces"] if x["name"] == name)
    r = FIX["servicebus"]["authorization_rules"][name] if rules == "fixture" else rules
    return parse_sb_namespace(ns, r)


def eh_ns(name: str, rules="fixture") -> Resource:
    ns = next(x for x in FIX["eventhub"]["namespaces"] if x["name"] == name)
    r = FIX["eventhub"]["authorization_rules"][name] if rules == "fixture" else rules
    return parse_eh_namespace(ns, r)


def sb_queue(ns_name: str, q_name: str) -> Resource:
    ns = sb_ns(ns_name)
    q = next(x for x in FIX["servicebus"]["queues"][ns_name] if x["name"] == q_name)
    return parse_sb_queue(ns.ext_id, q)


def event_hub(ns_name: str, hub_name: str, storage="fixture") -> Resource:
    ns = eh_ns(ns_name)
    hub = next(x for x in FIX["eventhub"]["hubs"][ns_name] if x["name"] == hub_name)
    capture = (hub["properties"].get("captureDescription") or {})
    capture_storage = None
    if capture.get("enabled"):
        if storage == "fixture":
            capture_storage = parse_capture_storage(
                FIX["eventhub"]["storage_accounts"]["capturesa"])
        else:
            capture_storage = storage
    groups = FIX["eventhub"]["consumer_groups"].get(hub_name)
    return parse_event_hub(ns.ext_id, hub, groups, capture_storage)


def apim(name: str) -> Resource:
    svc = next(x for x in FIX["apim"]["services"] if x["name"] == name)
    return parse_apim(svc, FIX["apim"]["named_values"][name], FIX["apim"]["subscriptions"][name])


def apim_api(svc_name: str, api_name: str) -> Resource:
    svc = apim(svc_name)
    api = next(x for x in FIX["apim"]["apis"][svc_name] if x["name"] == api_name)
    return parse_apim_api(svc.ext_id, api)


def logic(name: str) -> Resource:
    wf = next(x for x in FIX["logic"]["workflows"] if x["name"] == name)
    return parse_logic_app(wf)


def subscription(collection=None) -> Resource:
    return Resource(
        kind="azure_subscription", name=FIX["subscription_id"],
        ext_id=f"azure-sub-{FIX['subscription_id']}",
        labels={"service": "arm"},
        raw={"subscription_id": FIX["subscription_id"], "tenant_id": "t-1",
             "client_id": FIX["client_id"], "collection": collection or {}},
    )


def scan(*resources) -> ScanContext:
    return ScanContext(connection_id="conn-1", tenant_id="tenant-1", resources=list(resources))


def fire(rule_id, resource, ctx=None) -> list:
    d = RULES[rule_id]
    assert resource.kind in d.kinds, f"{rule_id} does not apply to kind={resource.kind}"
    return d.fn(resource, ctx or scan(resource)) or []


# ── pack shape ────────────────────────────────────────────────────────────────
def test_expected_rules_all_registered():
    assert set(RULES) == EXPECTED_RULES


def test_rules_only_run_on_azure_kinds():
    for d in RULES.values():
        assert all(k.startswith("azure_") for k in d.kinds), d.rule_id


def test_connector_declares_secret_field():
    fields = {f.key: f for f in CONNECTOR_FIELDS["azure"]}
    assert fields["client_secret"].secret is True
    assert all(fields[k].required for k in ("tenant_id", "client_id", "client_secret",
                                            "subscription_id"))


# ── namespace posture (Service Bus + Event Hubs share the surface) ────────────
def test_sb_public_network_fires_and_disabled_passes():
    hits = fire("AZURE.SERVICEBUS.PUBLIC_NETWORK_ACCESS", sb_ns("sb-open"))
    assert len(hits) == 1 and "publicNetworkAccess" in hits[0].observation
    assert "no private-endpoint path" in hits[0].observation
    assert fire("AZURE.SERVICEBUS.PUBLIC_NETWORK_ACCESS", sb_ns("sb-hardened")) == []


def test_eh_public_network_fires_and_disabled_passes():
    assert len(fire("AZURE.EVENTHUB.PUBLIC_NETWORK_ACCESS", eh_ns("eh-open"))) == 1
    assert fire("AZURE.EVENTHUB.PUBLIC_NETWORK_ACCESS", eh_ns("eh-hardened")) == []


def test_local_auth_fires_and_aad_only_passes():
    hits = fire("AZURE.SERVICEBUS.LOCAL_AUTH_ENABLED", sb_ns("sb-open"))
    assert len(hits) == 1 and "disableLocalAuth" in hits[0].observation
    assert fire("AZURE.SERVICEBUS.LOCAL_AUTH_ENABLED", sb_ns("sb-hardened")) == []
    assert len(fire("AZURE.EVENTHUB.LOCAL_AUTH_ENABLED", eh_ns("eh-open"))) == 1
    assert fire("AZURE.EVENTHUB.LOCAL_AUTH_ENABLED", eh_ns("eh-hardened")) == []


def test_tls_legacy_fires_12_and_absent_pass():
    hits = fire("AZURE.SERVICEBUS.TLS_MIN_LEGACY", sb_ns("sb-open"))
    assert len(hits) == 1 and "'1.1'" in hits[0].observation
    assert fire("AZURE.SERVICEBUS.TLS_MIN_LEGACY", sb_ns("sb-hardened")) == []
    assert len(fire("AZURE.EVENTHUB.TLS_MIN_LEGACY", eh_ns("eh-open"))) == 1
    # absent minimumTlsVersion means the platform default (1.2) — not a defect
    unset = sb_ns("sb-hardened")
    unset.raw["minimum_tls_version"] = None
    assert fire("AZURE.SERVICEBUS.TLS_MIN_LEGACY", unset) == []


def test_manage_sas_rule_fires_on_root_key_only():
    hits = fire("AZURE.SERVICEBUS.MANAGE_SAS_RULE", sb_ns("sb-open"))
    assert len(hits) == 1 and "RootManageSharedAccessKey" in hits[0].observation
    assert "wildcard-equivalent" in hits[0].observation
    # send-only / listen-only rules never fire
    assert fire("AZURE.SERVICEBUS.MANAGE_SAS_RULE", sb_ns("sb-hardened")) == []
    assert len(fire("AZURE.EVENTHUB.MANAGE_SAS_RULE", eh_ns("eh-open"))) == 1
    assert fire("AZURE.EVENTHUB.MANAGE_SAS_RULE", eh_ns("eh-hardened")) == []


def test_manage_sas_rule_not_assessable_when_rules_denied():
    hits = fire("AZURE.SERVICEBUS.MANAGE_SAS_RULE", sb_ns("sb-open", rules=None))
    assert len(hits) == 1 and hits[0].assessable is False
    assert "401/403" in hits[0].assessment_reason


# ── Service Bus entities ──────────────────────────────────────────────────────
def test_queue_dead_lettering_fire_and_pass():
    hits = fire("AZURE.SERVICEBUS.QUEUE_NO_DEAD_LETTERING", sb_queue("sb-open", "orders"))
    assert len(hits) == 1 and "deadLetteringOnMessageExpiration" in hits[0].observation
    assert fire("AZURE.SERVICEBUS.QUEUE_NO_DEAD_LETTERING",
                sb_queue("sb-hardened", "payments")) == []


# ── Event Hubs capture ────────────────────────────────────────────────────────
def test_capture_public_storage_fires():
    hits = fire("AZURE.EVENTHUB.CAPTURE_PUBLIC_STORAGE", event_hub("eh-open", "telemetry"))
    assert len(hits) == 1 and hits[0].assessable
    assert "allowBlobPublicAccess=True" in hits[0].observation
    assert "capturesa" in hits[0].observation


def test_capture_locked_storage_and_capture_off_pass():
    locked = event_hub("eh-open", "telemetry",
                       storage=parse_capture_storage(
                           FIX["eventhub"]["storage_accounts"]["lockedsa"]))
    assert fire("AZURE.EVENTHUB.CAPTURE_PUBLIC_STORAGE", locked) == []
    assert fire("AZURE.EVENTHUB.CAPTURE_PUBLIC_STORAGE", event_hub("eh-hardened", "audit")) == []


def test_capture_storage_unreadable_is_not_assessable():
    gap = event_hub("eh-open", "telemetry", storage=parse_capture_storage(None))
    hits = fire("AZURE.EVENTHUB.CAPTURE_PUBLIC_STORAGE", gap)
    assert len(hits) == 1 and hits[0].assessable is False
    assert "denied or failed" in hits[0].assessment_reason


# ── API Management ────────────────────────────────────────────────────────────
def test_apim_legacy_tls_fires_only_enabled_toggles():
    hits = fire("AZURE.APIM.LEGACY_TLS_CIPHERS", apim("apim-legacy"))
    assert len(hits) == 1
    # Tls10 and TripleDes are "True"; Tls11 and the backend toggle are "False" and must
    # not be cited
    assert "Protocols.Tls10" in hits[0].observation
    assert "TripleDes168" in hits[0].observation
    assert "Tls11" not in hits[0].detail
    assert fire("AZURE.APIM.LEGACY_TLS_CIPHERS", apim("apim-hardened")) == []


def test_apim_api_key_only_fires_and_oauth_passes():
    hits = fire("AZURE.APIM.API_SUBSCRIPTION_KEY_ONLY", apim_api("apim-legacy", "orders-api"))
    assert len(hits) == 1 and "subscriptionRequired" in hits[0].observation
    assert fire("AZURE.APIM.API_SUBSCRIPTION_KEY_ONLY",
                apim_api("apim-legacy", "secure-api")) == []
    # an open API (no subscription requirement) is out of this rule's scope
    open_api = apim_api("apim-legacy", "orders-api")
    open_api.raw["subscription_required"] = False
    assert fire("AZURE.APIM.API_SUBSCRIPTION_KEY_ONLY", open_api) == []


def test_apim_public_no_restrictions_fires_and_vnet_passes():
    hits = fire("AZURE.APIM.PUBLIC_NO_NETWORK_RESTRICTIONS", apim("apim-legacy"))
    assert len(hits) == 1 and "virtualNetworkType 'None'" in hits[0].observation
    # apim-hardened is public too, but VNet-injected (Internal) — a network boundary exists
    assert fire("AZURE.APIM.PUBLIC_NO_NETWORK_RESTRICTIONS", apim("apim-hardened")) == []


# ── Logic Apps ────────────────────────────────────────────────────────────────
def test_logic_http_trigger_open_fires_and_restricted_passes():
    hits = fire("AZURE.LOGICAPP.HTTP_TRIGGER_OPEN", logic("wf-open"))
    assert len(hits) == 1 and "manual (Request)" in hits[0].observation
    assert fire("AZURE.LOGICAPP.HTTP_TRIGGER_OPEN", logic("wf-restricted")) == []
    # a disabled workflow's callback URL is inert — not this rule's finding
    assert fire("AZURE.LOGICAPP.HTTP_TRIGGER_OPEN", logic("wf-disabled")) == []


def test_logic_http_trigger_not_assessable_when_definition_unreadable():
    # the connector falls back to the list-shape (no definition) when the GET fails
    wf = next(x for x in FIX["logic"]["workflows"] if x["name"] == "wf-open")
    stripped = copy.deepcopy(wf)
    del stripped["properties"]["definition"]
    hits = fire("AZURE.LOGICAPP.HTTP_TRIGGER_OPEN", parse_logic_app(stripped))
    assert len(hits) == 1 and hits[0].assessable is False


def test_logic_disabled_workflow_fires_info_enabled_passes():
    hits = fire("AZURE.LOGICAPP.WORKFLOW_DISABLED", logic("wf-disabled"))
    assert len(hits) == 1 and RULES["AZURE.LOGICAPP.WORKFLOW_DISABLED"].severity == "info"
    assert fire("AZURE.LOGICAPP.WORKFLOW_DISABLED", logic("wf-open")) == []


# ── subscription coverage gaps ────────────────────────────────────────────────
def test_denied_service_is_not_assessable_never_a_pass():
    sub = subscription(collection={
        "servicebus": {"outcome": "ok", "error": None, "resources": 4},
        "apim": {"outcome": "access_denied", "error": "http_403"},
        "logic": {"outcome": "error", "error": "ConnectError: boom"},
    })
    hits = fire("AZURE.SUBSCRIPTION.SERVICE_NOT_ASSESSED", sub)
    # only the DENIED service is a permissions coverage gap; ok and transport errors are not
    assert len(hits) == 1
    assert hits[0].assessable is False and "apim" in hits[0].observation
    assert "http_403" in hits[0].assessment_reason


def test_clean_collection_reports_nothing():
    sub = subscription(collection={"servicebus": {"outcome": "ok", "error": None}})
    assert fire("AZURE.SUBSCRIPTION.SERVICE_NOT_ASSESSED", sub) == []


# ── NHI derivation ────────────────────────────────────────────────────────────
def _derive(*resources):
    return IDENTITY_EXTRACTORS["azure"](list(resources))


def test_sas_rules_become_identities_with_credentials_and_grants():
    out, edges = _derive(sb_ns("sb-open"))
    identities = [r for r in out if r.kind == "identity"]
    creds = [r for r in out if r.kind == "credential"]
    grants = [r for r in out if r.kind == "grant"]
    assert {i.name for i in identities} == {"sb-open/RootManageSharedAccessKey",
                                            "sb-open/producer-send"}
    # every SAS rule has two live keys by construction — metadata only, never a value
    assert len(creds) == 2 and all(c.raw["count"] == 2 for c in creds)
    assert all("plaintext" in c.raw and not isinstance(c.raw.get("plaintext"), str)
               for c in creds)
    # Root rule: three rights → three grants; producer-send: one
    assert len(grants) == 4


def test_manage_rule_is_wildcard_flagged():
    out, _ = _derive(sb_ns("sb-open"))
    root = next(i for i in out if i.kind == "identity" and "RootManage" in i.name)
    assert "wildcard_equivalent" in root.raw["tags"]
    manage_grant = next(g for g in out if g.kind == "grant"
                        and g.raw["identity_ext_id"] == root.ext_id
                        and g.raw["action"] == "manage")
    assert manage_grant.raw["wildcard"] is True
    send_grant = next(g for g in out if g.kind == "grant"
                      and g.raw["identity_ext_id"] == root.ext_id
                      and g.raw["action"] == "send")
    assert send_grant.raw["wildcard"] is False


def test_grant_edges_link_identity_and_namespace():
    ns = eh_ns("eh-open")
    out, edges = _derive(ns)
    grant = next(g for g in out if g.kind == "grant" and g.raw["action"] == "manage")
    kinds = {(e.kind, e.dst_ext_id) for e in edges if e.src_ext_id == grant.ext_id}
    assert ("grants_access", ns.ext_id) in kinds
    idr = next(i for i in out if i.kind == "identity")
    assert ("granted_to", idr.ext_id) in kinds


def test_apim_subscriptions_become_identities_with_key_metadata():
    out, edges = _derive(apim("apim-legacy"))
    idr = next(i for i in out if i.kind == "identity")
    assert idr.labels["identity_type"] == "apim_subscription"
    assert idr.name == "apim-legacy/CI pipeline"
    cred = next(c for c in out if c.kind == "credential")
    assert cred.raw["credential_type"] == "subscription_key" and cred.raw["count"] == 2
    grant = next(g for g in out if g.kind == "grant")
    # /apis scope = every API on the gateway → wildcard-flagged
    assert grant.raw["wildcard"] is True and grant.raw["target"] == "/apis"


def test_unreadable_rules_and_hardened_apim_derive_nothing():
    out, edges = _derive(sb_ns("sb-open", rules=None), apim("apim-hardened"))
    assert out == [] and edges == []


def test_no_secret_material_in_any_derived_resource():
    out, _ = _derive(sb_ns("sb-open"), eh_ns("eh-open"), apim("apim-legacy"))
    for r in out:
        blob = json.dumps(r.raw).lower()
        assert "primarykey" not in blob and "secondarykey" not in blob
        assert "connectionstring" not in blob
