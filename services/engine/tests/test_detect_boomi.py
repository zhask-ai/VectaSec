"""Offline unit tests for the Boomi connector parse layer + rulepack. No httpx, no live account:
Resources come from the connector's OWN parse layer fed golden AtomSphere JSON."""
from vectasec.contracts import ScanContext
from vectasec.registry import DETECTORS
import vectasec.detect.boomi  # noqa: F401
from vectasec.connect.boomi import parse_api, parse_connection, parse_role
from vectasec.detect.boomi import (
    auth_unreadable, connection_reused, no_authentication, no_tls, role_overprivileged, weak_auth,
)

RULES = {d.rule_id: d for d in DETECTORS if d.rule_id.startswith("BOOMI.")}

EXPECTED_RULES = {
    "BOOMI.API.AUTH_UNREADABLE",
    "BOOMI.API.NO_AUTHENTICATION",
    "BOOMI.API.WEAK_AUTH",
    "BOOMI.API.NO_TLS",
    "BOOMI.CONNECTION.REUSED_ACROSS_ENVIRONMENTS",
    "BOOMI.ROLE.OVER_PRIVILEGED",
}


def api(*, auth="apikey", https=True, url="https://gw.boomi/ws/rest/orders", env="Production"):
    obj = {"id": "api-1", "name": "Orders API", "environmentName": env,
           "httpsRequired": https, "publicUrl": url}
    if auth is not _MISSING:
        obj["authenticationType"] = auth
    return parse_api(obj)


_MISSING = object()


def connection(*, envs=("env-prod",), ctype="database", name="Prod DB"):
    return parse_connection({"id": "conn-1", "name": name, "connectorType": ctype,
                             "environments": list(envs)})


def role(*, privileges=("BUILD_READ_AND_WRITE",), name="Builder"):
    return parse_role({"id": "role-1", "name": name, "privileges": list(privileges)})


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
    assert "boomi" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["boomi"]}
    assert fields["token"].secret is True
    assert fields["account_id"].required is True and fields["username"].required is True


# ══ BOOMI.API.AUTH_UNREADABLE ═════════════════════════════════════════════
def test_auth_unreadable_is_not_assessable():
    h = one(fire(auth_unreadable, api(auth=_MISSING)))
    assert h.assessable is False


def test_auth_unreadable_does_not_fire_when_readable():
    assert fire(auth_unreadable, api(auth="none")) == []


def test_auth_rules_decline_when_unreadable():
    a = api(auth=_MISSING)
    assert no_authentication(a, ctx(a)) == []
    assert weak_auth(a, ctx(a)) == []


# ══ BOOMI.API.NO_AUTHENTICATION ═══════════════════════════════════════════
def test_no_authentication_fires_on_authtype_none():
    h = one(fire(no_authentication, api(auth="none")))
    assert h.severity is None and RULES["BOOMI.API.NO_AUTHENTICATION"].severity == "high"
    assert "authenticationType='none'" in h.observation


def test_no_authentication_does_not_fire_when_apikey():
    assert fire(no_authentication, api(auth="apikey")) == []


# ══ BOOMI.API.WEAK_AUTH ═══════════════════════════════════════════════════
def test_weak_auth_fires_on_basic():
    h = one(fire(weak_auth, api(auth="basic")))
    assert "authenticationType='basic'" in h.observation


def test_weak_auth_does_not_fire_on_oauth():
    assert fire(weak_auth, api(auth="oauth2")) == []


# ══ BOOMI.API.NO_TLS ══════════════════════════════════════════════════════
def test_no_tls_fires_when_https_not_required():
    h = one(fire(no_tls, api(https=False, url="http://gw.boomi/ws/rest/orders")))
    assert "cleartext" in h.observation


def test_no_tls_does_not_fire_when_https_required():
    assert fire(no_tls, api(https=True)) == []


def test_no_tls_infers_https_from_url_when_flag_absent():
    # parse_api derives https_required from the url scheme when httpsRequired is not supplied.
    a = parse_api({"id": "a", "name": "n", "authenticationType": "apikey",
                   "publicUrl": "https://gw/x"})
    assert no_tls(a, ctx(a)) == []


# ══ BOOMI.CONNECTION.REUSED_ACROSS_ENVIRONMENTS ═══════════════════════════
def test_connection_reused_fires_across_two_environments():
    h = one(fire(connection_reused, connection(envs=["env-prod", "env-dev"])))
    assert h.severity is None and RULES[
        "BOOMI.CONNECTION.REUSED_ACROSS_ENVIRONMENTS"].severity == "medium"
    assert "2 environments" in h.observation


def test_connection_reused_does_not_fire_single_environment():
    assert fire(connection_reused, connection(envs=["env-prod"])) == []


# ══ BOOMI.ROLE.OVER_PRIVILEGED ════════════════════════════════════════════
def test_role_overprivileged_fires_on_admin_privilege():
    h = one(fire(role_overprivileged,
                 role(privileges=["BUILD_READ_AND_WRITE", "ACCOUNT_ADMINISTRATION"],
                      name="Administrator")))
    assert "ACCOUNT_ADMINISTRATION" in h.observation


def test_role_overprivileged_does_not_fire_on_scoped_role():
    assert fire(role_overprivileged, role(privileges=["BUILD_READ", "DEPLOY_READ"])) == []
