"""Confluent Cloud connector + rulepack — offline. No httpx client is ever built, no Confluent
org is touched. The parse layer is the seam: detectors run on parse-layer output from golden
response dicts shaped exactly as the Confluent REST v2 API returns them.
"""
from datetime import datetime, timedelta, timezone

from vectasec.contracts import ScanContext
from vectasec.identity import derive_identities
from vectasec.contracts import Collected
from vectasec.registry import CONNECTOR_FIELDS, CONNECTORS
from vectasec.connect.confluent import (
    parse_api_key, parse_environment, parse_network, parse_role_binding, parse_service_account,
)
import vectasec.detect.confluent as rp


def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def _recent_iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── golden response dicts ──────────────────────────────────────────────────────
SA = {"id": "sa-abc123", "display_name": "connect-worker", "metadata": {"created_at": "2023-01-01T00:00:00Z"}}
ORG_ADMIN_RB = {"id": "rb-1", "principal": "User:sa-abc123", "role_name": "OrganizationAdmin",
                "crn_pattern": "crn://confluent.cloud/organization=11aa"}
ENV_ADMIN_RB = {"id": "rb-2", "principal": "User:sa-def456", "role_name": "EnvironmentAdmin",
                "crn_pattern": "crn://confluent.cloud/organization=11aa/environment=env-x"}
READER_RB = {"id": "rb-3", "principal": "User:sa-abc123", "role_name": "DeveloperRead",
             "crn_pattern": "crn://confluent.cloud/.../topic=orders"}
CLOUD_KEY = {"id": "CLOUDKEY1", "spec": {"display_name": "org-automation",
             "owner": {"id": "sa-abc123", "kind": "ServiceAccount"}, "resource": None},
             "metadata": {"created_at": "2023-01-01T00:00:00Z"}}
CLUSTER_KEY = {"id": "CKEY2", "spec": {"display_name": "app-key",
               "owner": {"id": "sa-def456", "kind": "ServiceAccount"},
               "resource": {"id": "lkc-123", "kind": "Cluster"}},
               "metadata": {"created_at": _recent_iso(10)}}
USER_KEY = {"id": "UKEY3", "spec": {"display_name": "alice-personal",
            "owner": {"id": "u-999", "kind": "User"},
            "resource": {"id": "lkc-123", "kind": "Cluster"}},
            "metadata": {"created_at": _recent_iso(5)}}
PUBLIC_NET = {"id": "n-pub", "spec": {"display_name": "public-net", "cloud": "AWS",
              "region": "us-east-1", "connection_types": ["PUBLIC"], "environment": {"id": "env-x"}}}
PRIVATE_NET = {"id": "n-priv", "spec": {"display_name": "pl-net", "cloud": "AWS",
               "connection_types": ["PRIVATELINK"], "environment": {"id": "env-x"}}}


# ── registration ───────────────────────────────────────────────────────────────
def test_connector_registered_and_secret_marked():
    assert "confluent" in CONNECTORS
    fields = {f.key: f for f in CONNECTOR_FIELDS["confluent"]}
    assert fields["api_secret"].secret and fields["api_key"].required


# ── CONFLUENT.RBAC.ORG_ADMIN ───────────────────────────────────────────────────
def test_org_admin_fires():
    rb = parse_role_binding(ORG_ADMIN_RB)
    hits = rp.rbac_org_admin(rb, _ctx([rb]))
    assert len(hits) == 1 and hits[0].severity is None  # decorator default high
    assert "OrganizationAdmin" in hits[0].observation


def test_org_admin_does_not_fire_for_other_roles():
    rb = parse_role_binding(ENV_ADMIN_RB)
    assert rp.rbac_org_admin(rb, _ctx([rb])) == []


# ── CONFLUENT.RBAC.BROAD_ADMIN ─────────────────────────────────────────────────
def test_broad_admin_fires_on_environment_admin():
    rb = parse_role_binding(ENV_ADMIN_RB)
    assert len(rp.rbac_broad_admin(rb, _ctx([rb]))) == 1


def test_broad_admin_does_not_fire_on_developer_read():
    rb = parse_role_binding(READER_RB)
    assert rp.rbac_broad_admin(rb, _ctx([rb])) == []


def test_org_admin_is_not_double_counted_as_broad_admin():
    rb = parse_role_binding(ORG_ADMIN_RB)
    assert rp.rbac_broad_admin(rb, _ctx([rb])) == []   # OrganizationAdmin has its own rule


# ── CONFLUENT.APIKEY.CLOUD_SCOPED ──────────────────────────────────────────────
def test_cloud_scoped_key_fires():
    k = parse_api_key(CLOUD_KEY)
    hits = rp.apikey_cloud_scoped(k, _ctx([k]))
    assert len(hits) == 1 and "Cloud API key" in hits[0].observation


def test_resource_scoped_key_does_not_fire_cloud_scoped():
    k = parse_api_key(CLUSTER_KEY)
    assert rp.apikey_cloud_scoped(k, _ctx([k])) == []


# ── CONFLUENT.APIKEY.USER_OWNED ────────────────────────────────────────────────
def test_user_owned_key_fires():
    k = parse_api_key(USER_KEY)
    assert len(rp.apikey_user_owned(k, _ctx([k]))) == 1


def test_service_account_key_does_not_fire_user_owned():
    k = parse_api_key(CLUSTER_KEY)
    assert rp.apikey_user_owned(k, _ctx([k])) == []


# ── CONFLUENT.APIKEY.STALE (+ not-assessable) ──────────────────────────────────
def test_stale_key_fires_when_old():
    k = parse_api_key(CLOUD_KEY)          # created 2023 -> well over a year old
    hits = rp.apikey_stale(k, _ctx([k]))
    assert len(hits) == 1 and hits[0].assessable is True and "never expire" in hits[0].observation


def test_recent_key_does_not_fire_stale():
    k = parse_api_key(CLUSTER_KEY)        # created 10 days ago
    assert rp.apikey_stale(k, _ctx([k])) == []


def test_stale_not_assessable_without_created_at():
    k = parse_api_key({"id": "K", "spec": {"display_name": "x",
                       "owner": {"id": "sa-1", "kind": "ServiceAccount"}, "resource": None}})
    hits = rp.apikey_stale(k, _ctx([k]))
    assert len(hits) == 1 and hits[0].assessable is False and hits[0].assessment_reason


# ── CONFLUENT.NETWORK.PUBLIC ───────────────────────────────────────────────────
def test_public_network_fires():
    n = parse_network(PUBLIC_NET)
    hits = rp.network_public(n, _ctx([n]))
    assert len(hits) == 1 and "PUBLIC" in hits[0].observation


def test_private_network_does_not_fire():
    n = parse_network(PRIVATE_NET)
    assert rp.network_public(n, _ctx([n])) == []


# ── NHI ────────────────────────────────────────────────────────────────────────
def test_nhi_service_accounts_api_keys_and_role_bindings():
    resources = [parse_service_account(SA), parse_api_key(CLOUD_KEY), parse_api_key(USER_KEY),
                 parse_role_binding(ORG_ADMIN_RB)]
    col = derive_identities("confluent", Collected(resources=list(resources)))
    kinds = {}
    for r in col.resources:
        kinds[r.kind] = kinds.get(r.kind, 0) + 1
    assert kinds.get("identity", 0) >= 2          # sa-abc123 (SA + owner) deduped, u-999 (user)
    assert kinds.get("credential", 0) == 2        # one per API key
    assert kinds.get("grant", 0) == 1             # the org-admin role binding
    # the API-key credential records presence but never a secret value
    creds = [r for r in col.resources if r.kind == "credential"]
    assert all(c.raw.get("plaintext") is None for c in creds)
    # user-owned key produces an external "user" identity
    users = [r for r in col.resources if r.kind == "identity"
             and r.raw.get("identity_type") == "user"]
    assert users and users[0].raw.get("external") is True


def test_parse_environment_is_context_only():
    e = parse_environment({"id": "env-x", "display_name": "prod"})
    assert e.kind == "confluent_environment" and e.raw["environment_id"] == "env-x"
