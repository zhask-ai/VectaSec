"""NHI derivation for Kubernetes — ServiceAccounts → identity, token secrets → credential
(metadata only), role bindings → grants, with the owner/identity labels the /identities
console view groups on.

Reuses the golden snapshot fixtures from test_detect_k8s so the extractor is exercised on
exactly what the connector emits, not on hand-massaged resources.
"""
import json

from test_detect_k8s import TOKEN_B64, build, rbac_bad

from vectasec.identity import IDENTITY_EXTRACTORS, derive_identities
import vectasec.connect.k8s  # noqa: F401  — registers the "k8s" extractor


def _derived():
    return derive_identities("k8s", build(rbac_bad()))


def test_k8s_extractor_is_registered():
    assert "k8s" in IDENTITY_EXTRACTORS


def test_service_accounts_become_identities():
    col = _derived()
    ids = [r for r in col.resources if r.kind == "identity"]
    assert sorted(i.name for i in ids) == ["app/default", "ci/deployer"]
    for i in ids:
        assert i.labels["system"] == "k8s"
        assert i.labels["identity_type"] == "service_account"
        assert i.raw["source_ext_id"].startswith("k8s-sa-")


def test_token_secret_becomes_credential_metadata_only():
    col = _derived()
    creds = [r for r in col.resources if r.kind == "credential"]
    assert len(creds) == 1
    c = creds[0]
    assert c.raw["credential_type"] == "sa_token" and c.raw["count"] == 1
    assert c.raw["secret_names"] == ["deployer-token-abc12"]
    assert c.labels["owner"] == "identity:k8s:ci-deployer"     # console groups on this label
    assert TOKEN_B64 not in json.dumps({"raw": c.raw, "labels": c.labels})
    # credential --credential_of--> identity edge resolves
    assert any(e.kind == "credential_of" and e.src_ext_id == c.ext_id
               and e.dst_ext_id == "identity:k8s:ci-deployer" for e in col.edges)


def test_bindings_become_grants_with_wildcard_and_edges():
    col = _derived()
    grants = [r for r in col.resources if r.kind == "grant"]
    # ci-admin → deployer (cluster-admin, cluster scope) and default-editor → app/default;
    # bob-super and anon-view have no ServiceAccount subject, so no grant.
    assert len(grants) == 2
    admin = next(g for g in grants if g.raw["action"] == "cluster-admin")
    assert admin.raw["wildcard"] is True and admin.raw["target"] == "cluster"
    assert admin.labels["identity"] == "identity:k8s:ci-deployer"
    editor = next(g for g in grants if g.raw["action"] == "editor")
    assert editor.raw["wildcard"] is False and editor.raw["target"] == "namespace:app"
    assert editor.labels["identity"] == "identity:k8s:app-default"
    for g in grants:
        assert any(e.kind == "granted_to" and e.src_ext_id == g.ext_id
                   and e.dst_ext_id == g.labels["identity"] for e in col.edges)


def test_derivation_is_additive_and_edges_resolve():
    base = build(rbac_bad())
    n_resources, n_edges = len(base.resources), len(base.edges)
    col = derive_identities("k8s", base)
    assert len(col.resources) > n_resources and len(col.edges) > n_edges
    ext_ids = {r.ext_id for r in col.resources}
    for e in col.edges:
        assert e.src_ext_id in ext_ids and e.dst_ext_id in ext_ids, (e.src_ext_id, e.dst_ext_id)
