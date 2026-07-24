"""NHI derivation for MuleSoft — Connected Apps → OAuth client identities, client-secret metadata,
and one grant per scope (broad scopes flagged wildcard). Built from the connector's own parse layer."""
from vectasec.contracts import Collected
from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
import vectasec.connect.mulesoft  # noqa: F401  — registers the "mulesoft" extractor
from vectasec.connect.mulesoft import parse_connected_app


def _derived(scopes=("read:apis", "org-admin")):
    app = parse_connected_app({"client_id": "app-1", "client_name": "ci-deployer",
                               "scopes": list(scopes), "grant_types": ["client_credentials"]})
    return derive_identities("mulesoft", Collected(resources=[app], edges=[]))


def test_extractor_registered():
    assert "mulesoft" in IDENTITY_EXTRACTORS


def test_connected_app_becomes_external_oauth_identity():
    col = _derived()
    idr = next(r for r in col.resources if r.kind == "identity")
    assert idr.labels["identity_type"] == "oauth_client"
    assert idr.labels["external"] == "true"
    assert idr.raw["client_id"] == "app-1"


def test_client_secret_is_credential_metadata_only():
    col = _derived()
    cred = next(r for r in col.resources if r.kind == "credential")
    assert cred.raw["credential_type"] == "client_secret"
    assert cred.raw["plaintext"] is False
    assert any(e.kind == "credential_of" and e.src_ext_id == cred.ext_id for e in col.edges)


def test_scopes_become_grants_with_broad_marked_wildcard():
    col = _derived()
    grants = {g.raw["target"]: g for g in col.resources if g.kind == "grant"}
    assert grants["read:apis"].raw["wildcard"] is False
    assert grants["org-admin"].raw["wildcard"] is True
    for g in grants.values():
        assert any(e.kind == "granted_to" and e.src_ext_id == g.ext_id for e in col.edges)
