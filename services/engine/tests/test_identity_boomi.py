"""NHI derivation for Boomi — account users → identities, role assignments → grants (wildcard for
account-admin roles), Connection components → integration-credential metadata. Built from the
connector's own parse layer."""
from vectasec.contracts import Collected, Resource
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
import vectasec.connect.boomi  # noqa: F401  — registers the "boomi" extractor
from vectasec.connect.boomi import parse_account_user, parse_connection, parse_role


def _collected():
    account = Resource(kind="boomi_account", name="acct-1", ext_id="boomi-account-acct-1",
                       labels={}, raw={"account_id": "acct-1"})
    admin_role = parse_role({"id": "role-admin", "name": "Administrator",
                             "privileges": ["ACCOUNT_ADMINISTRATION", "BUILD_READ_AND_WRITE"]})
    scoped_role = parse_role({"id": "role-build", "name": "Builder",
                              "privileges": ["BUILD_READ"]})
    admin_user = parse_account_user({"userId": "alice@example.com", "roleId": "role-admin",
                                     "roleName": "Administrator", "accountId": "acct-1"})
    build_user = parse_account_user({"userId": "bob@example.com", "roleId": "role-build",
                                     "roleName": "Builder", "accountId": "acct-1"})
    conn = parse_connection({"id": "conn-1", "name": "Prod DB", "connectorType": "database",
                             "environments": ["env-prod", "env-dev"]})
    return Collected(resources=[account, admin_role, scoped_role, admin_user, build_user, conn],
                     edges=[])


def _derived():
    return derive_identities("boomi", _collected())


def test_extractor_registered():
    assert "boomi" in IDENTITY_EXTRACTORS


def test_account_users_become_identities():
    col = _derived()
    ids = {r.name for r in col.resources if r.kind == "identity"
           and r.labels["identity_type"] == "user"}
    assert ids == {"alice@example.com", "bob@example.com"}


def test_role_assignment_becomes_grant_wildcard_for_admin_only():
    col = _derived()
    grants = {g.labels["identity"]: g for g in col.resources if g.kind == "grant"}
    alice = next(g for g in col.resources if g.kind == "grant"
                 and g.raw["action"] == "Administrator")
    bob = next(g for g in col.resources if g.kind == "grant" and g.raw["action"] == "Builder")
    assert alice.raw["wildcard"] is True          # ACCOUNT_ADMINISTRATION → wildcard
    assert bob.raw["wildcard"] is False
    for g in (alice, bob):
        assert any(e.kind == "granted_to" and e.src_ext_id == g.ext_id for e in col.edges)


def test_connection_becomes_integration_credential_metadata_only():
    col = _derived()
    cred = next(r for r in col.resources if r.kind == "credential")
    assert cred.raw["credential_type"] == "connection_secret"
    assert cred.raw["plaintext"] is False
    assert cred.raw["count"] == 2                  # spans two environments
    assert cred.raw["environments"] == ["env-prod", "env-dev"]
    assert any(e.kind == "credential_of" and e.src_ext_id == cred.ext_id for e in col.edges)
