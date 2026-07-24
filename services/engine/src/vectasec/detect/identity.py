"""Non-Human Identity (NHI) detectors — the cross-cutting hygiene pack.

These run on the NORMALIZED identity/credential/grant kinds that identity.py derives from every
connector, so one rule covers Kafka principals, Kong consumers, RabbitMQ users and MCP OAuth
clients at once. They are organized against the OWASP Non-Human Identities Top 10 (2025), the
category spine for this whole area — the same framework the market (Astrix/Entro/Oasis/
GitGuardian) governs to, anchored by the Salesloft Drift → Gainsight OAuth-token breach.

These are ADDITIVE to the per-connector packs, not a re-run of them: a per-connector rule reads
one system's config in its own terms; these read the unified NHI model, so they express things no
single connector can — a wildcard grant generalized across systems, a privileged-NHI inventory,
a credential-storage coverage gap. They fingerprint on the derived (grant/credential/identity)
ext_ids, which never collide with a connector rule's, so no finding is double-counted.
"""
from ..contracts import Hit
from ..registry import detector

# Identity names that denote a shared, default, or anonymous principal — the ones a human
# never should, but always does, leave enabled. Matched case-insensitively on the last path
# segment so "User:guest" and "guest" both hit.
_DEFAULT_NAMES = {"guest", "anonymous", "default", "admin", "administrator", "root", "public",
                  "test", "demo", "nobody"}

_WEAK_HASH = {"md5", "sha1"}


def _leaf(name: str) -> str:
    # "User:alice" -> "alice", "oauth:client-x" -> "client-x"; a principal's type prefix is
    # not part of the name we match defaults against.
    return (name or "").split(":")[-1].strip().lower()


# ── NHI5: Overprivileged — the wildcard grant ─────────────────────────────────
@detector(kinds=["grant"], rule_id="NHI.GRANT.WILDCARD", severity="high",
          title="Non-human identity holds a wildcard authorization")
def grant_wildcard(r, ctx) -> list:
    """A grant whose target or action is a wildcard hands the identity blanket access — the
    single most common over-privilege in the integration layer (Kafka `User:*`/topic `*`/ALL,
    RabbitMQ `.*` permission regex, an MCP `*` scope). Deny grants are not over-privilege, so
    only `allow` fires."""
    raw = r.raw or {}
    if not raw.get("wildcard") or raw.get("permission", "allow") != "allow":
        return []
    action = raw.get("action", "?")
    target = raw.get("target", "?")
    system = raw.get("system", "?")
    detail = raw.get("pattern") or raw.get("scope") or ""
    return [Hit(
        observation=(f"{system} grant gives '{action}' on '{target}' with a wildcard scope "
                     f"({detail or 'wildcard target/action'}) to identity {raw.get('identity_ext_id')}"),
        remediation=("Replace the wildcard with the specific resources this identity needs "
                     "(least privilege). A wildcard grant means a compromise of this one "
                     "credential reaches every resource the wildcard covers."),
        detail=f"action={action} target={target} pattern={detail}",
        source_ref={"kind": "grant", "system": system, "action": action, "target": target},
    )]


# ── Default / shared / anonymous identity ─────────────────────────────────────
@detector(kinds=["identity"], rule_id="NHI.IDENTITY.SHARED_DEFAULT", severity="medium",
          title="Default, shared, or anonymous non-human identity is present")
def identity_shared_default(r, ctx) -> list:
    """A default/shared identity (guest, admin, anonymous, default) breaks accountability: its
    actions cannot be attributed, and its credential is usually well-known. This is the NHI
    inventory lens — it fires wherever such an identity exists in ANY system, so a security team
    can see them all in one place, distinct from a single connector's default-user rule."""
    name = r.name or ""
    if _leaf(name) not in _DEFAULT_NAMES:
        return []
    system = (r.labels or {}).get("system", "?")
    itype = (r.raw or {}).get("identity_type", "identity")
    return [Hit(
        observation=f"{system} has a {itype} named '{name}', a default/shared/anonymous principal",
        remediation=("Remove or rename default identities and give each application its own "
                     "named identity with its own credential and least-privilege grants, so "
                     "actions are attributable and one leak does not implicate every app."),
        detail=f"identity_type={itype} system={system}",
        source_ref={"kind": "identity", "system": system, "name": name},
    )]


# ── NHI4: Insecure authentication — weak credential storage ───────────────────
@detector(kinds=["credential"], rule_id="NHI.CREDENTIAL.WEAK_HASH", severity="medium",
          title="Credential stored with a weak password hash")
def credential_weak_hash(r, ctx) -> list:
    """A credential hashed with MD5 or SHA-1 is recoverable from a database leak — the hash is
    the credential. Fires on the normalized credential regardless of which system stored it."""
    raw = r.raw or {}
    hashing = (raw.get("hashing") or "").lower()
    if hashing not in _WEAK_HASH:
        return []
    system = raw.get("system", "?")
    return [Hit(
        observation=f"{system} credential '{r.name}' is stored with the weak hash algorithm '{hashing}'",
        remediation=("Move to a modern password hash (bcrypt/argon2) or, better, to certificate "
                     "or federated authentication so there is no reversible secret at rest."),
        detail=f"hashing={hashing} type={raw.get('credential_type')}",
        source_ref={"kind": "credential", "system": system, "hashing": hashing},
    )]


# ── Credential storage the scanner cannot verify — the third outcome ──────────
@detector(kinds=["credential"], rule_id="NHI.CREDENTIAL.STORAGE_UNVERIFIED", severity="info",
          title="Credential present but its storage strength could not be verified")
def credential_storage_unverified(r, ctx) -> list:
    """Some systems expose that a credential EXISTS but not how it is stored. Kong key-auth API
    keys are the case that matters: Kong stores them in cleartext by DEFAULT, but the Admin API
    returns only counts, so this scanner cannot read whether key hashing was enabled. That is a
    coverage GAP, not a finding — assessable=False — so it is surfaced honestly (never as a pass,
    never as a vulnerability) and prompts a manual check rather than a claim the evidence can't
    carry."""
    raw = r.raw or {}
    if raw.get("credential_type") != "api_key" or raw.get("system") != "kong":
        return []
    n = raw.get("count", 1)
    return [Hit(
        observation=(f"kong identity holds {n} key-auth API key(s); the Admin API returns counts, "
                     f"not storage mode, so this scan cannot read whether key hashing is enabled"),
        remediation=("Verify `key-auth` is configured with `hash_secret: true`; Kong stores API "
                     "keys in cleartext by default, which makes a database read a credential theft."),
        detail=f"count={n}",
        assessable=False,
        assessment_reason="Kong Admin API exposes credential counts only, not hashing configuration",
        source_ref={"kind": "credential", "system": "kong", "credential_type": "api_key"},
    )]
