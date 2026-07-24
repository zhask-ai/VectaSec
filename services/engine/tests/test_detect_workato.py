"""Offline unit tests for the Workato connector parse layer + rulepack. No httpx, no live workspace:
Resources come from the connector's OWN parse layer fed golden Workato JSON."""
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.workato  # noqa: F401
from vectasec.connect.workato import (
    parse_api_client, parse_api_endpoint, parse_connection,
)
from vectasec.detect.workato import (
    admin_no_ip_allowlist, connection_shared, connection_unauthorized,
    endpoint_no_access_profile, no_ip_allowlist, role_unreadable,
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("WORKATO.")}

EXPECTED_RULES = {
    "WORKATO.APICLIENT.ROLE_UNREADABLE",
    "WORKATO.APICLIENT.ADMIN_NO_IP_ALLOWLIST",
    "WORKATO.APICLIENT.NO_IP_ALLOWLIST",
    "WORKATO.ENDPOINT.NO_ACCESS_PROFILE",
    "WORKATO.CONNECTION.SHARED_ORG_WIDE",
    "WORKATO.CONNECTION.UNAUTHORIZED",
}

_UNSET = object()


def api_client(*, role="Analyst", allowlist=()):
    obj = {"id": 7, "name": "ci-token", "ip_allowlist": list(allowlist)}
    if role is not _UNSET:
        obj["role_name"] = role
    return parse_api_client(obj)


def endpoint(*, active=True, profiles=()):
    return parse_api_endpoint({"id": 9, "name": "orders", "base_path": "/orders",
                               "active": active, "access_profile_ids": list(profiles)})


def connection(*, shared=False, authorized=True, provider="salesforce"):
    return parse_connection({"id": 3, "name": "SFDC", "provider": provider,
                             "authorized": authorized, "shared": shared})


def ctx(*resources):
    return ScanContext(connection_id="c1", tenant_id="t1", resources=list(resources), config={})


def one(hits):
    assert len(hits) == 1, f"expected 1 hit, got {len(hits)}"
    return hits[0]


def fire(fn, res, *others):
    return fn(res, ctx(res, *others))


def test_all_expected_rules_registered():
    assert set(RULES) == EXPECTED_RULES


def test_connector_registered_with_secret_token():
    from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
    assert "workato" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["workato"]}
    assert fields["api_token"].secret is True and fields["api_token"].required is True


# ══ WORKATO.APICLIENT.ROLE_UNREADABLE ═════════════════════════════════════
def test_role_unreadable_is_not_assessable():
    # Give it an allowlist so only the role-unreadable rule is in play.
    h = one(fire(role_unreadable, api_client(role=_UNSET, allowlist=["10.0.0.0/8"])))
    assert h.assessable is False


def test_role_unreadable_does_not_fire_when_readable():
    assert fire(role_unreadable, api_client(role="Admin")) == []


def test_admin_rule_declines_when_role_unreadable():
    c = api_client(role=_UNSET, allowlist=[])
    assert admin_no_ip_allowlist(c, ctx(c)) == []


# ══ WORKATO.APICLIENT.ADMIN_NO_IP_ALLOWLIST ═══════════════════════════════
def test_admin_no_ip_allowlist_fires():
    h = one(fire(admin_no_ip_allowlist, api_client(role="Admin", allowlist=[])))
    assert h.severity is None and RULES[
        "WORKATO.APICLIENT.ADMIN_NO_IP_ALLOWLIST"].severity == "high"
    assert "empty IP allowlist" in h.observation


def test_admin_no_ip_allowlist_does_not_fire_with_allowlist():
    assert fire(admin_no_ip_allowlist, api_client(role="Admin", allowlist=["1.2.3.4"])) == []


def test_admin_no_ip_allowlist_does_not_fire_for_non_admin():
    assert fire(admin_no_ip_allowlist, api_client(role="Analyst", allowlist=[])) == []


# ══ WORKATO.APICLIENT.NO_IP_ALLOWLIST ═════════════════════════════════════
def test_no_ip_allowlist_fires_for_non_admin_without_allowlist():
    h = one(fire(no_ip_allowlist, api_client(role="Analyst", allowlist=[])))
    assert "usable from any source address" in h.observation


def test_no_ip_allowlist_does_not_double_report_admin_clients():
    # Admin clients belong to the higher-severity ADMIN_NO_IP_ALLOWLIST rule.
    assert fire(no_ip_allowlist, api_client(role="Admin", allowlist=[])) == []


def test_no_ip_allowlist_does_not_fire_with_allowlist():
    assert fire(no_ip_allowlist, api_client(role="Analyst", allowlist=["10.0.0.0/8"])) == []


# ══ WORKATO.ENDPOINT.NO_ACCESS_PROFILE ════════════════════════════════════
def test_endpoint_no_access_profile_fires_on_active_ungated():
    h = one(fire(endpoint_no_access_profile, endpoint(active=True, profiles=[])))
    assert "no access profile" in h.observation


def test_endpoint_no_access_profile_does_not_fire_with_a_profile():
    assert fire(endpoint_no_access_profile, endpoint(active=True, profiles=[101])) == []


def test_endpoint_no_access_profile_does_not_fire_when_inactive():
    assert fire(endpoint_no_access_profile, endpoint(active=False, profiles=[])) == []


# ══ WORKATO.CONNECTION.SHARED_ORG_WIDE ════════════════════════════════════
def test_connection_shared_fires():
    h = one(fire(connection_shared, connection(shared=True)))
    assert h.severity is None and RULES["WORKATO.CONNECTION.SHARED_ORG_WIDE"].severity == "medium"
    assert "shared workspace-wide" in h.observation


def test_connection_shared_does_not_fire_when_folder_scoped():
    assert fire(connection_shared, connection(shared=False)) == []


# ══ WORKATO.CONNECTION.UNAUTHORIZED ═══════════════════════════════════════
def test_connection_unauthorized_fires():
    h = one(fire(connection_unauthorized, connection(authorized=False)))
    assert "unauthorized state" in h.observation


def test_connection_unauthorized_does_not_fire_when_authorized():
    assert fire(connection_unauthorized, connection(authorized=True)) == []
