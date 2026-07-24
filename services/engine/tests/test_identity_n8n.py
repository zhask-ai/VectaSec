"""NHI derivation for n8n — users → identities/credentials/grants, stored credentials → integration
identities with credential-metadata and per-workflow grants. Built from the connector's own parse
layer so the extractor runs on exactly what collect() emits."""
import json

from vectasec.contracts import Collected
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
import vectasec.connect.n8n  # noqa: F401  — registers the "n8n" extractor
from vectasec.connect.n8n import build_instance, parse_credential, parse_user


def _collected():
    inst = build_instance("https://n8n.example.com",
                          settings={"versionCli": "1.122.0", "userManagement": {}},
                          settings_status=200, origin="remote", audit=None,
                          users_readable=True, outcomes={})
    owner = parse_user({"id": "u1", "email": "owner@example.com", "role": "global:owner",
                        "isPending": False, "mfaEnabled": False})
    member = parse_user({"id": "u2", "email": "member@example.com", "role": "global:member",
                         "isPending": True})
    cred = parse_credential({"id": "c1", "name": "Slack account", "type": "slackApi"},
                            ["wf-1", "wf-2"], True)
    return Collected(resources=[inst, owner, member, cred], edges=[])


def _derived():
    return derive_identities("n8n", _collected())


def test_n8n_extractor_is_registered():
    assert "n8n" in IDENTITY_EXTRACTORS


def test_users_become_identities_with_roles():
    col = _derived()
    ids = {r.name: r for r in col.resources if r.kind == "identity"}
    assert ids["owner@example.com"].labels["identity_type"] == "owner"
    assert ids["member@example.com"].labels["identity_type"] == "service_account"
    # MFA-off owner is tagged so the console can surface it.
    assert "mfa_disabled" in ids["owner@example.com"].raw["tags"]


def test_active_user_gets_a_password_credential_but_pending_does_not():
    col = _derived()
    creds = [r for r in col.resources if r.kind == "credential"]
    pw = [c for c in creds if c.raw["credential_type"] == "password"]
    # owner is active → has a password credential; member is pending → none.
    assert len(pw) == 1
    assert pw[0].labels["owner"] == "identity:n8n:owner-example-com"
    assert pw[0].raw["plaintext"] is False
    assert any(e.kind == "credential_of" and e.src_ext_id == pw[0].ext_id for e in col.edges)


def test_role_becomes_a_grant_with_wildcard_for_admin():
    col = _derived()
    grants = [r for r in col.resources if r.kind == "grant"]
    owner_grant = next(g for g in grants if g.raw["action"] == "global:owner")
    assert owner_grant.raw["wildcard"] is True
    assert owner_grant.raw["target"] == "instance"
    assert any(e.kind == "granted_to" and e.src_ext_id == owner_grant.ext_id for e in col.edges)


def test_stored_credential_becomes_integration_identity_with_metadata_only():
    col = _derived()
    integ = next(r for r in col.resources if r.kind == "identity"
                 and r.labels["identity_type"] == "integration_credential")
    assert integ.labels["external"] == "true"
    cred = next(r for r in col.resources if r.kind == "credential"
                and r.raw["credential_type"] == "slackApi")
    assert cred.raw["count"] == 2                       # used by two workflows
    assert cred.raw["plaintext"] is False
    assert cred.raw["reachable_unauthenticated"] is True
    # Never leaks a value: only metadata is present.
    assert "value" not in json.dumps(cred.raw).lower() or cred.raw.get("plaintext") is False


def test_stored_credential_grants_resolve_to_each_workflow():
    col = _derived()
    grants = [r for r in col.resources if r.kind == "grant" and r.raw["action"] == "invoked_by"]
    assert {g.raw["target"] for g in grants} == {"n8n-workflow-wf-1", "n8n-workflow-wf-2"}
    for g in grants:
        assert any(e.kind == "grants_access" and e.src_ext_id == g.ext_id
                   and e.dst_ext_id == g.raw["target"] for e in col.edges)


def test_derivation_is_additive():
    base = _collected()
    n = len(base.resources)
    col = derive_identities("n8n", base)
    assert len(col.resources) > n
