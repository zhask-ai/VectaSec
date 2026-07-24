"""Confluent Cloud rulepack — read-only control-plane posture.

Runs on the DISTINCT confluent_* kinds the connector emits, so no Kafka rule ever fires against a
Confluent resource. Findings cite exactly what the Confluent REST v2 API returned — role names,
API-key scope/owner/age, network connection types — never a value the API withheld (the per-key
secret is never in the data at all).
"""
from datetime import datetime, timezone

from ..contracts import Hit
from ..registry import detector

# Roles that grant admin/owner breadth. OrganizationAdmin is org-wide superuser (its own rule);
# the rest are broad but scoped, handled together.
_BROAD_ADMIN_ROLES = {"EnvironmentAdmin", "CloudClusterAdmin", "ResourceOwner"}

_STALE_DAYS = 365


def _age_days(created_at):
    """Age in days of an ISO-8601 timestamp, or None when absent/unparseable."""
    if not created_at:
        return None
    s = str(created_at).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


@detector(kinds=["confluent_role_binding"], rule_id="CONFLUENT.RBAC.ORG_ADMIN", severity="high",
          title="RBAC role binding grants OrganizationAdmin (org-wide superuser)")
def rbac_org_admin(resource, ctx):
    raw = resource.raw or {}
    if raw.get("role_name") != "OrganizationAdmin":
        return []
    return [Hit(
        observation=(
            f"Confluent role binding {raw.get('role_binding_id')} grants OrganizationAdmin to "
            f"{raw.get('principal')!r} over {raw.get('crn_pattern')!r}. OrganizationAdmin is the "
            f"organization-wide superuser role: full control of every environment, cluster, "
            f"service account, API key and role binding in the org."
        ),
        remediation=(
            "Grant OrganizationAdmin to as few principals as possible and never to a workload "
            "service account used by an application. Prefer environment- or cluster-scoped roles "
            "(EnvironmentAdmin, CloudClusterAdmin) or fine-grained roles (DeveloperRead / "
            "DeveloperWrite / ResourceOwner on a specific CRN) for day-to-day access."
        ),
        detail=("Highest-privilege Confluent Cloud role. Human break-glass admins holding it is "
                "expected; a service account or a broad list of principals holding it is the "
                "concern."),
        source_ref={"role": "OrganizationAdmin", "principal": raw.get("principal"),
                    "crn_pattern": raw.get("crn_pattern")},
    )]


@detector(kinds=["confluent_role_binding"], rule_id="CONFLUENT.RBAC.BROAD_ADMIN", severity="medium",
          title="RBAC role binding grants broad admin/owner over an environment, cluster or CRN")
def rbac_broad_admin(resource, ctx):
    raw = resource.raw or {}
    role = raw.get("role_name")
    if role not in _BROAD_ADMIN_ROLES:
        return []
    return [Hit(
        observation=(
            f"Confluent role binding {raw.get('role_binding_id')} grants {role} to "
            f"{raw.get('principal')!r} over {raw.get('crn_pattern')!r}. {role} confers "
            f"administrative or ownership control over everything matched by that CRN pattern, "
            f"including the ability to manage access and delete resources."
        ),
        remediation=(
            "Confirm this principal needs admin/owner breadth over the whole CRN pattern. Where it "
            "only needs data access, replace it with DeveloperRead/DeveloperWrite on the specific "
            "topic/cluster CRN. Scope the crn_pattern as narrowly as the workload allows."
        ),
        detail=("Broad but scoped, so medium rather than high. Operator and platform-team "
                "bindings legitimately carry these roles; the signal is breadth and principal "
                "count, which need ownership context to judge."),
        source_ref={"role": role, "principal": raw.get("principal"),
                    "crn_pattern": raw.get("crn_pattern")},
    )]


@detector(kinds=["confluent_api_key"], rule_id="CONFLUENT.APIKEY.CLOUD_SCOPED", severity="high",
          title="Cloud (org-scoped) API key — can manage the whole organization")
def apikey_cloud_scoped(resource, ctx):
    raw = resource.raw or {}
    if not raw.get("cloud_scoped"):
        return []
    return [Hit(
        observation=(
            f"Confluent API key {raw.get('api_key_id')} ({raw.get('display_name')!r}) is a Cloud "
            f"API key — its spec.resource is null, so it is not bound to a single Kafka cluster or "
            f"Schema Registry but authenticates to the org-level control plane. Its owner is "
            f"{raw.get('owner_kind')} {raw.get('owner_id')!r}. A Cloud key can call the IAM, "
            f"networking and environment APIs subject only to the owner's role bindings."
        ),
        remediation=(
            "Use resource-scoped API keys (bound to a specific cluster/registry) for applications; "
            "reserve Cloud API keys for control-plane automation owned by a dedicated service "
            "account with least-privilege role bindings. Rotate Cloud keys regularly and store the "
            "secret in a secrets manager."
        ),
        detail=("A Cloud key's actual power is the intersection of the key and its owner's role "
                "bindings — pair this with the role-binding findings for the same owner."),
        source_ref={"api_key_id": raw.get("api_key_id"), "scope": "cloud",
                    "owner_id": raw.get("owner_id")},
    )]


@detector(kinds=["confluent_api_key"], rule_id="CONFLUENT.APIKEY.USER_OWNED", severity="medium",
          title="API key owned by a user account rather than a service account")
def apikey_user_owned(resource, ctx):
    raw = resource.raw or {}
    if str(raw.get("owner_kind")) != "User":
        return []
    return [Hit(
        observation=(
            f"Confluent API key {raw.get('api_key_id')} ({raw.get('display_name')!r}) is owned by "
            f"a User account ({raw.get('owner_id')!r}), not a service account. User-owned API keys "
            f"inherit the human's role bindings and stop working when the person is deactivated, "
            f"and they are hard to attribute to a specific workload."
        ),
        remediation=(
            "Reissue this key under a dedicated service account with least-privilege role "
            "bindings, migrate the application to it, then delete the user-owned key. Confluent "
            "recommends service accounts for all programmatic access."
        ),
        detail=("Governance and lifecycle risk more than a direct exposure — a user key is as "
                "privileged as the human, which is usually more than the workload needs."),
        source_ref={"api_key_id": raw.get("api_key_id"), "owner_kind": "User",
                    "owner_id": raw.get("owner_id")},
    )]


@detector(kinds=["confluent_api_key"], rule_id="CONFLUENT.APIKEY.STALE", severity="low",
          title="API key is old and Confluent API keys do not expire — rotate")
def apikey_stale(resource, ctx):
    raw = resource.raw or {}
    created = raw.get("created_at")
    age = _age_days(created)
    if age is None:
        # No usable created_at, and the LIST API exposes no last-used timestamp, so neither age
        # nor actual usage can be assessed read-only.
        return [Hit(
            observation=(
                f"Confluent API key {raw.get('api_key_id')} ({raw.get('display_name')!r}) has no "
                f"parseable metadata.created_at, and the /iam/v2/api-keys API exposes no last-used "
                f"timestamp, so neither its age nor whether it is still in use could be determined."
            ),
            remediation=(
                "Confirm this key is still needed and rotate it on a schedule. Confluent Cloud API "
                "keys do not expire; establish a rotation and unused-key cleanup process out of "
                "band (audit-log or usage telemetry), which this read-only scan cannot see."
            ),
            detail="Coverage gap: created_at unreadable and no usage signal in the REST list API.",
            assessable=False,
            assessment_reason="created_at unparseable and the API exposes no last-used timestamp",
            source_ref={"api_key_id": raw.get("api_key_id")},
        )]
    if age < _STALE_DAYS:
        return []
    return [Hit(
        observation=(
            f"Confluent API key {raw.get('api_key_id')} ({raw.get('display_name')!r}) was created "
            f"{age} days ago (created_at={created!r}). Confluent Cloud API keys never expire, so an "
            f"old, un-rotated key is a long-lived static credential."
        ),
        remediation=(
            "Rotate this API key and adopt a rotation schedule (create the new key, migrate the "
            "workload, delete the old key). Store the secret in a secrets manager and review "
            "whether the key is still used at all."
        ),
        detail=(f"Age threshold is {_STALE_DAYS} days — a hygiene heuristic, not a Confluent "
                f"limit. Actual usage cannot be seen read-only, so an old key may still be active "
                f"or already abandoned."),
        source_ref={"api_key_id": raw.get("api_key_id"), "age_days": age},
    )]


@detector(kinds=["confluent_network"], rule_id="CONFLUENT.NETWORK.PUBLIC", severity="medium",
          title="Confluent network reachable over the public internet")
def network_public(resource, ctx):
    raw = resource.raw or {}
    conn = raw.get("connection_types") or []
    if "PUBLIC" not in conn:
        return []
    return [Hit(
        observation=(
            f"Confluent network {raw.get('network_id')} ({raw.get('display_name')!r}, "
            f"cloud={raw.get('cloud')}, region={raw.get('region')}) advertises connection type(s) "
            f"{conn}, which includes PUBLIC — clusters on this network expose their bootstrap "
            f"endpoint to the public internet, gated only by SASL/mTLS authentication and ACLs."
        ),
        remediation=(
            "For production workloads use PrivateLink, VPC/VNet peering or Transit Gateway so the "
            "bootstrap endpoint is not internet-reachable. If PUBLIC is required, ensure strong "
            "authentication, tight ACLs/RBAC, and IP filtering are in place."
        ),
        detail=("Confluent Cloud always enforces TLS + authentication on public endpoints, so this "
                "is defense-in-depth/exposure-reduction, not an open door — hence medium. A "
                "deliberately public dev cluster is a suppression candidate."),
        source_ref={"network_id": raw.get("network_id"), "connection_types": conn},
    )]
