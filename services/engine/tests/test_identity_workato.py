"""NHI derivation for Workato — API clients → machine identities with token metadata + role grants,
connections → integration-credential metadata. Built from the connector's own parse layer."""
from vectasec.contracts import Collected, Resource
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
import vectasec.connect.workato  # noqa: F401  — registers the "workato" extractor
from vectasec.connect.workato import parse_api_client, parse_connection


def _collected():
    ws = Resource(kind="workato_workspace", name="ws", ext_id="workato-workspace-us",
                  labels={}, raw={"data_center": "us"})
    admin = parse_api_client({"id": 1, "name": "admin-token", "role_name": "Admin",
                              "ip_allowlist": []})
    scoped = parse_api_client({"id": 2, "name": "recipe-token", "role_name": "Recipe Runner",
                               "ip_allowlist": ["10.0.0.0/8"]})
    conn = parse_connection({"id": 3, "name": "SFDC", "provider": "salesforce",
                             "authorized": True, "shared": True})
    return Collected(resources=[ws, admin, scoped, conn], edges=[])


def _derived():
    return derive_identities("workato", _collected())


def test_extractor_registered():
    assert "workato" in IDENTITY_EXTRACTORS


def test_api_clients_become_machine_identities_with_token_credentials():
    col = _derived()
    idents = {r.name: r for r in col.resources if r.kind == "identity"
              and r.labels["identity_type"] == "api_client"}
    assert set(idents) == {"admin-token", "recipe-token"}
    # The admin client with no allowlist is tagged so the console can surface it.
    assert "no_ip_allowlist" in idents["admin-token"].raw["tags"]
    assert "no_ip_allowlist" not in idents["recipe-token"].raw["tags"]
    tokens = [c for c in col.resources if c.kind == "credential"
              and c.raw["credential_type"] == "api_token"]
    assert len(tokens) == 2
    assert all(c.raw["plaintext"] is False for c in tokens)


def test_admin_role_becomes_wildcard_grant():
    col = _derived()
    admin_grant = next(g for g in col.resources if g.kind == "grant" and g.raw["action"] == "Admin")
    scoped_grant = next(g for g in col.resources if g.kind == "grant"
                        and g.raw["action"] == "Recipe Runner")
    assert admin_grant.raw["wildcard"] is True
    assert scoped_grant.raw["wildcard"] is False
    assert any(e.kind == "grants_access" and e.src_ext_id == admin_grant.ext_id for e in col.edges)


def test_connection_becomes_integration_credential_metadata_only():
    col = _derived()
    cred = next(r for r in col.resources if r.kind == "credential"
                and r.raw["credential_type"] == "connection_secret")
    assert cred.raw["plaintext"] is False
    assert cred.raw["shared_org_wide"] is True
    assert any(e.kind == "credential_of" and e.src_ext_id == cred.ext_id for e in col.edges)
