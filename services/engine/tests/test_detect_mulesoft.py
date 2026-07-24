"""Offline unit tests for the MuleSoft Anypoint connector parse layer + rulepack.

No httpx, no live org: Resources come from the connector's OWN parse layer (parse_api,
parse_connected_app) fed golden Anypoint JSON. Every detector gets a fire and a no-fire case; the
policy-based rules additionally prove they DECLINE (not_assessable) when the policy list was
unreadable rather than reading absence as 'no policy'.
"""
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.mulesoft  # noqa: F401
from vectasec.connect.mulesoft import parse_api, parse_connected_app
from vectasec.detect.mulesoft import (
    api_deprecated, app_overprivileged, insecure_transport, no_auth_policy,
    no_client_id_enforcement, no_rate_limiting, policies_unreadable, policy_disabled,
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("MULESOFT.")}

EXPECTED_RULES = {
    "MULESOFT.API.POLICIES_UNREADABLE",
    "MULESOFT.API.NO_AUTH_POLICY",
    "MULESOFT.API.NO_CLIENT_ID_ENFORCEMENT",
    "MULESOFT.API.NO_RATE_LIMITING",
    "MULESOFT.API.INSECURE_TRANSPORT",
    "MULESOFT.API.POLICY_DISABLED",
    "MULESOFT.API.DEPRECATED",
    "MULESOFT.APP.OVERPRIVILEGED_SCOPES",
}

ORG = "org-guid"
ENV = "Production"


def pol(asset, *, disabled=False):
    return {"assetId": asset, "disabled": disabled, "configurationData": {}}


def api(*, policies=(), readable=True, uri="https://orders.internal:8082/api", deprecated=False,
        label="orders-api-prod"):
    raw = {"id": 42, "instanceLabel": label, "assetId": "orders-api", "stage": "release",
           "technology": "mule4", "endpoint": {"uri": uri, "isCloudHub": False},
           "deprecated": deprecated}
    return parse_api(ORG, ENV, raw, list(policies) if policies is not None else None, readable)


def app(*, scopes=("read:apis",), name="ci-deployer", cid="app-1", grant_types=("client_credentials",)):
    return parse_connected_app({"client_id": cid, "client_name": name, "scopes": list(scopes),
                                "grant_types": list(grant_types), "enabled": True})


def ctx(*resources):
    return ScanContext(connection_id="c1", tenant_id="t1", resources=list(resources), config={})


def one(hits):
    assert len(hits) == 1, f"expected 1 hit, got {len(hits)}"
    return hits[0]


def fire(fn, res, *others):
    return fn(res, ctx(res, *others))


def test_all_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_connector_registered_with_secret_fields():
    from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
    assert "mulesoft" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["mulesoft"]}
    assert fields["client_secret"].secret is True and fields["access_token"].secret is True
    assert fields["org_id"].required is True


# ══ MULE.API.POLICIES_UNREADABLE ══════════════════════════════════════════
def test_policies_unreadable_is_not_assessable():
    h = one(fire(policies_unreadable, api(policies=None, readable=False)))
    assert h.assessable is False


def test_policies_unreadable_does_not_fire_when_readable():
    assert fire(policies_unreadable, api(policies=[pol("client-id-enforcement")])) == []


def test_policy_rules_decline_when_policies_unreadable():
    # The whole point of the coverage gap: policy-based rules must not FAIL on an unread list.
    a = api(policies=None, readable=False)
    assert no_auth_policy(a, ctx(a)) == []
    assert no_rate_limiting(a, ctx(a)) == []
    assert no_client_id_enforcement(a, ctx(a)) == []


# ══ MULE.API.NO_AUTH_POLICY ═══════════════════════════════════════════════
def test_no_auth_policy_fires_with_no_policies():
    h = one(fire(no_auth_policy, api(policies=[])))
    assert h.severity is None and RULES["MULESOFT.API.NO_AUTH_POLICY"].severity == "high"
    assert "no enforcing authentication policy" in h.observation


def test_no_auth_policy_does_not_fire_with_client_id_enforcement():
    assert fire(no_auth_policy, api(policies=[pol("client-id-enforcement")])) == []


def test_no_auth_policy_does_not_fire_with_jwt_validation():
    assert fire(no_auth_policy, api(policies=[pol("jwt-validation")])) == []


def test_no_auth_policy_fires_when_only_auth_policy_is_disabled():
    # A disabled policy does not enforce, so it does not count as authentication.
    assert len(fire(no_auth_policy, api(policies=[pol("jwt-validation", disabled=True)]))) == 1


# ══ MULE.API.NO_CLIENT_ID_ENFORCEMENT ═════════════════════════════════════
def test_no_client_id_enforcement_fires_when_only_jwt():
    h = one(fire(no_client_id_enforcement, api(policies=[pol("jwt-validation")])))
    assert "no client-id-enforcement" in h.observation


def test_no_client_id_enforcement_does_not_fire_with_client_id():
    assert fire(no_client_id_enforcement,
                api(policies=[pol("client-id-enforcement"), pol("jwt-validation")])) == []


def test_no_client_id_enforcement_does_not_fire_when_no_auth_at_all():
    # NO_AUTH_POLICY owns the "nothing at all" case; this rule must stay quiet to avoid double-firing.
    assert fire(no_client_id_enforcement, api(policies=[])) == []


# ══ MULE.API.NO_RATE_LIMITING ═════════════════════════════════════════════
def test_no_rate_limiting_fires():
    h = one(fire(no_rate_limiting, api(policies=[pol("client-id-enforcement")])))
    assert "no" in h.observation and "rate-limiting" in h.observation


def test_no_rate_limiting_does_not_fire_with_rate_limiting_sla():
    assert fire(no_rate_limiting,
                api(policies=[pol("client-id-enforcement"), pol("rate-limiting-sla")])) == []


# ══ MULE.API.INSECURE_TRANSPORT ═══════════════════════════════════════════
def test_insecure_transport_fires_on_http():
    h = one(fire(insecure_transport, api(uri="http://orders.internal:8081/api")))
    assert "cleartext" in h.observation


def test_insecure_transport_does_not_fire_on_https():
    assert fire(insecure_transport, api(uri="https://orders.internal:8082/api")) == []


# ══ MULE.API.POLICY_DISABLED ══════════════════════════════════════════════
def test_policy_disabled_fires_on_disabled_auth_policy():
    h = one(fire(policy_disabled, api(policies=[pol("jwt-validation", disabled=True)])))
    assert "disabled=true" in h.observation
    assert "jwt-validation" in h.observation


def test_policy_disabled_does_not_fire_when_all_enabled():
    assert fire(policy_disabled, api(policies=[pol("jwt-validation")])) == []


# ══ MULE.API.DEPRECATED ═══════════════════════════════════════════════════
def test_api_deprecated_fires():
    h = one(fire(api_deprecated, api(deprecated=True)))
    assert h.severity is None and RULES["MULESOFT.API.DEPRECATED"].severity == "low"


def test_api_deprecated_does_not_fire():
    assert fire(api_deprecated, api(deprecated=False)) == []


# ══ MULE.APP.OVERPRIVILEGED_SCOPES ════════════════════════════════════════
def test_app_overprivileged_fires_on_broad_scope():
    h = one(fire(app_overprivileged, app(scopes=["read:apis", "org-admin"])))
    assert "org-admin" in h.observation


def test_app_overprivileged_does_not_fire_on_narrow_scopes():
    assert fire(app_overprivileged, app(scopes=["read:apis", "view:environment"])) == []
