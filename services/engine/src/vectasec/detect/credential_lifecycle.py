"""Credential-lifecycle telemetry pack — the CREDENTIAL.LIFECYCLE.* rules.

These run on the NORMALIZED `credential`/`identity` kinds that identity.py derives from every
connector, so one rule reasons about a Confluent API key, a Kong key-auth key, an Azure SAS key
and a RabbitMQ password in the same terms. Where the per-connector packs answer "is THIS system
configured badly", this pack answers the cross-system lifecycle question the NHI inventory exists
to make actionable: *is this non-human credential long-lived, unrotated, non-expiring, shared,
default, or attached to an orphaned principal* — the exact class of failure behind the Salesloft
Drift → Gainsight OAuth-token breach (a static, never-expiring, never-rotated integration token).

ADDITIVE, NOT A RE-RUN. Like the NHI pack (detect/identity.py), these fingerprint on the derived
credential/identity ext_ids, which never collide with a connector rule's ext_id — so a finding
here is never a double-count of, say, CONFLUENT.APIKEY.STALE. The connector rule speaks Confluent's
terms; this one speaks the unified lifecycle terms and covers systems that have no equivalent rule.
They do NOT touch hashing (that is NHI.CREDENTIAL.WEAK_HASH) or identity NAMES (that is
NHI.IDENTITY.SHARED_DEFAULT); each rule below keys on a distinct lifecycle fact.

────────────────────────────────────────────────────────────────────────────────────────────────
HONESTY — what is provable TODAY vs what awaits connector enrichment.

Most rotation / last-used telemetry is NOT collected by the connectors yet. Where the signal is
absent, the rule fires the THIRD outcome (Hit.assessable=False → "Not assessed", mapped to
'unknown', never 'fail'), with an observation naming the exact gap. It never invents staleness.

  PROVABLE TODAY (a rule can fire an assessed finding from real connector data):
    • CREDENTIAL.LIFECYCLE.ROTATION_STALE   — where a creation/rotation timestamp is recorded:
                                              confluent `api_key` (created_at), k8s `sa_token`
                                              (oldest_created).
    • CREDENTIAL.LIFECYCLE.STATIC_NO_ROTATION — structural, from the credential TYPE alone:
                                              api_key/api_token/sas_key/subscription_key/sa_token/
                                              access_key are static bearer secrets that never
                                              self-expire (confluent, kong, azure, k8s, workato…).
                                              The Drift/Gainsight pattern. No timestamp needed.
    • CREDENTIAL.LIFECYCLE.SHARED           — for shared-by-construction key types (azure sas_key,
                                              azure subscription_key) or an explicit `shared` flag.
    • CREDENTIAL.LIFECYCLE.DEFAULT_ACTIVE   — where is_default is recorded: rabbitmq default user
                                              password (default_password_confirmed).
    • CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY — the disabled-principal-still-granted case, from an
                                              explicit `enabled=False` signal (redis ACL users).
    • CREDENTIAL.LIFECYCLE.NO_EXPIRY        — where an expiry/TTL value is recorded and is
                                              unbounded or excessive (fire path is future-proofed;
                                              see below).

  AWAITS CONNECTOR ENRICHMENT (rule exists and is honest; today it can only NOT-ASSESS, or its
  assessed path is exercised by synthetic fixtures until a connector records the field):
    • CREDENTIAL.LIFECYCLE.NEVER_USED       — NO connector exposes a last-authentication time for a
                                              credential today, so every real credential is
                                              not_assessable. The fire path (recorded last-used that
                                              is null/stale → orphaned-NHI candidate) is ready for
                                              the first connector that records last_used_at.
    • CREDENTIAL.LIFECYCLE.ROTATION_STALE   — not_assessable for every credential whose connector
                                              records no creation/rotation timestamp (all but the
                                              two named above).
    • CREDENTIAL.LIFECYCLE.NO_EXPIRY        — not_assessable for rotatable-secret types
                                              (oauth_secret/client_secret/secret_id/password/…)
                                              whose connector does not expose the TTL/expiry policy
                                              (e.g. vault secret_id carries a secret_id_ttl the NHI
                                              layer does not yet propagate).
    • CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY — not_assessable for a granted identity with no
                                              readable credential and no activity/ownership signal
                                              (e.g. Kafka principals — AdminClient exposes no secret
                                              and no last-use), because orphanhood cannot be proven
                                              without a last-activity signal.

  OUT OF SCOPE (noted, never guessed): value-level credential REUSE across systems. No secret
  material is ever collected, so CREDENTIAL.LIFECYCLE.SHARED reasons only from structural markers
  (shared-by-design key types, an explicit shared flag); it never correlates secret values.
"""
from datetime import datetime, timezone

from ..contracts import Hit
from ..registry import detector

# ── thresholds (hygiene heuristics, not vendor limits) ────────────────────────
_STALE_DAYS = 365      # a credential unrotated for a year is long-lived (matches CONFLUENT.APIKEY.STALE)
_IDLE_DAYS = 90        # a credential unused for a quarter is an orphaned-NHI candidate
_EXCESSIVE_DAYS = 365  # an expiry window longer than this is effectively non-expiring

# Credential TYPES that are static long-lived bearer secrets by construction: the same secret stays
# valid until a human manually revokes/replaces it — there is no expiry and no automatic rotation.
# This is a property of the type, provable without any timestamp, so STATIC_NO_ROTATION fires on it.
_STATIC_BEARER = {"api_key", "api_token", "sas_key", "subscription_key", "sa_token", "access_key"}

# Credential TYPES whose systems DO support an expiry/rotation policy that the connectors do not yet
# expose. For these, an absent expiry field is a COVERAGE GAP (not_assessable), not a clean pass.
_ROTATABLE = {"oauth_secret", "client_secret", "secret_id", "connection_secret", "password",
              "oauth2", "jwt"}

# Key TYPES that are, by construction, a single secret handed to many callers.
_SHARED_KEY_TYPES = {"sas_key", "subscription_key"}

# raw fields a connector might record for each lifecycle signal (first present wins).
_CREATED_KEYS = ("rotated_at", "created_at", "created", "oldest_created")
_LAST_USED_KEYS = ("last_authenticated_at", "last_used_at", "last_auth", "last_used")


def _age_days(value):
    """Age in days of an ISO-8601 timestamp, or None when absent/unparseable."""
    if not value:
        return None
    s = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def _first_present(raw: dict, keys) -> tuple:
    """(key, value) for the first key that EXISTS in raw (even if its value is None/''), else
    (None, None). Presence of the key — not truthiness — is what distinguishes 'the connector
    recorded this signal' from 'the connector never collected it'."""
    for k in keys:
        if k in raw:
            return k, raw.get(k)
    return None, None


# ── Rotation age — provable where a creation/rotation timestamp is recorded ────
@detector(kinds=["credential"], rule_id="CREDENTIAL.LIFECYCLE.ROTATION_STALE", severity="medium",
          title="Non-human credential is long-lived and appears unrotated")
def rotation_stale(r, ctx) -> list:
    """A credential last created/rotated more than a year ago is a long-lived static secret — the
    longer it lives the larger its blast radius when leaked. Provable only where the connector
    recorded a creation/rotation timestamp; absent that, this is a coverage gap, never a guess."""
    raw = r.raw or {}
    if not raw.get("present", True):
        return []
    system = raw.get("system", "?")
    ctype = raw.get("credential_type", "credential")
    key, value = _first_present(raw, _CREATED_KEYS)

    if key is None:
        return [Hit(
            observation=(f"{system} credential '{r.name}' ({ctype}) records no creation or rotation "
                         f"timestamp; this connector does not expose one, so its rotation age "
                         f"cannot be determined"),
            remediation=("Track credential creation/rotation dates (in the source system or a "
                         "secrets manager) so long-lived, unrotated non-human credentials can be "
                         "found and rotated on a schedule."),
            detail=f"type={ctype} system={system} rotation_timestamp=absent",
            assessable=False,
            assessment_reason=f"{system} exposes no creation/rotation timestamp for this credential",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]

    age = _age_days(value)
    if age is None:
        return [Hit(
            observation=(f"{system} credential '{r.name}' records {key}={value!r}, which is not a "
                         f"parseable timestamp, so its rotation age could not be determined"),
            remediation="Confirm the credential's creation date in the source system and rotate it "
                        "if it predates your rotation policy.",
            detail=f"type={ctype} {key}={value!r}",
            assessable=False,
            assessment_reason=f"{key} present but not parseable as a timestamp",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]

    if age < _STALE_DAYS:
        return []
    return [Hit(
        observation=(f"{system} credential '{r.name}' ({ctype}) was created/rotated {age} days ago "
                     f"({key}={value!r}), older than the {_STALE_DAYS}-day rotation threshold"),
        remediation=("Rotate this credential and put it on a rotation schedule; a static secret that "
                     "has lived this long is the pattern behind the Drift/Gainsight token breach."),
        detail=f"type={ctype} age_days={age} threshold={_STALE_DAYS} {key}={value!r}",
        source_ref={"kind": "credential", "system": system, "credential_type": ctype,
                    "age_days": age},
    )]


# ── Last used / never used — the orphaned-NHI question (awaits enrichment) ─────
@detector(kinds=["credential"], rule_id="CREDENTIAL.LIFECYCLE.NEVER_USED", severity="medium",
          title="Non-human credential appears never used or long dormant")
def never_used(r, ctx) -> list:
    """A credential that has never authenticated, or not for a quarter, is an orphaned-NHI
    candidate: an unused key that only adds attack surface. NO connector records a last-auth time
    for a credential today, so this is honestly not_assessable until one does; the assessed path is
    ready for the first connector that records last_used_at."""
    raw = r.raw or {}
    if not raw.get("present", True):
        return []
    system = raw.get("system", "?")
    ctype = raw.get("credential_type", "credential")
    key, value = _first_present(raw, _LAST_USED_KEYS)

    if key is None:
        return [Hit(
            observation=(f"{system} credential '{r.name}' ({ctype}) has no last-authentication time; "
                         f"this connector exposes none, so whether the non-human identity behind it "
                         f"is dormant or orphaned cannot be determined"),
            remediation=("Collect last-used/last-auth telemetry for this credential (source-system "
                         "audit log or usage API) so unused non-human identities can be found and "
                         "decommissioned."),
            detail=f"type={ctype} system={system} last_used=absent",
            assessable=False,
            assessment_reason=f"{system} exposes no last-authentication time for this credential",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]

    # The signal IS recorded. Null/empty → the credential exists but has never authenticated.
    if not value:
        return [Hit(
            observation=(f"{system} credential '{r.name}' ({ctype}) records {key} as empty — it "
                         f"exists but has never authenticated"),
            remediation="Remove this never-used credential (and its identity if it has no other "
                        "credential); an unused key is pure attack surface.",
            detail=f"type={ctype} {key}=never",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]

    age = _age_days(value)
    if age is None:
        return [Hit(
            observation=(f"{system} credential '{r.name}' records {key}={value!r}, which is not a "
                         f"parseable timestamp, so its idle time could not be determined"),
            remediation="Confirm the credential's last use in the source system and decommission it "
                        "if it is no longer needed.",
            detail=f"type={ctype} {key}={value!r}",
            assessable=False,
            assessment_reason=f"{key} present but not parseable as a timestamp",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]

    if age < _IDLE_DAYS:
        return []
    return [Hit(
        observation=(f"{system} credential '{r.name}' ({ctype}) last authenticated {age} days ago "
                     f"({key}={value!r}), past the {_IDLE_DAYS}-day idle threshold"),
        remediation="Decommission this dormant credential (and its identity if unused elsewhere); a "
                    "long-idle non-human credential is a likely orphan.",
        detail=f"type={ctype} idle_days={age} threshold={_IDLE_DAYS} {key}={value!r}",
        source_ref={"kind": "credential", "system": system, "credential_type": ctype,
                    "idle_days": age},
    )]


# ── Static long-lived token with no rotation mechanism — structural, provable ──
@detector(kinds=["credential"], rule_id="CREDENTIAL.LIFECYCLE.STATIC_NO_ROTATION", severity="medium",
          title="Static bearer credential has no expiry or automatic rotation")
def static_no_rotation(r, ctx) -> list:
    """API keys, SAS keys, service-account token secrets and the like are static bearer secrets:
    the same value stays valid until a human revokes it, with no built-in expiry and no automatic
    rotation. That is the credential class behind the Drift/Gainsight breach. This is a property of
    the credential TYPE, so it is provable structurally — no timestamp required."""
    raw = r.raw or {}
    ctype = raw.get("credential_type", "")
    if ctype not in _STATIC_BEARER or not raw.get("present", True):
        return []
    system = raw.get("system", "?")
    n = raw.get("count", 1)
    return [Hit(
        observation=(f"{system} credential '{r.name}' is a {ctype} — a static bearer secret that "
                     f"does not self-expire and is not automatically rotated; it stays valid until "
                     f"manually revoked"),
        remediation=("Put this credential on an enforced rotation schedule, scope it tightly, and "
                     "prefer short-lived/federated credentials (OIDC workload identity, STS) where "
                     "the system supports them. Static non-expiring tokens are the Drift/Gainsight "
                     "breach pattern."),
        detail=f"type={ctype} system={system} count={n}",
        source_ref={"kind": "credential", "system": system, "credential_type": ctype},
    )]


# ── Missing / excessive expiry — recorded TTL fires; rotatable-without-TTL not-assessed ──
@detector(kinds=["credential"], rule_id="CREDENTIAL.LIFECYCLE.NO_EXPIRY", severity="medium",
          title="Non-human credential has no or an excessive expiry")
def no_expiry(r, ctx) -> list:
    """Where a connector records an expiry/TTL, flag it when it is unbounded (0 / never) or longer
    than a year — an effectively non-expiring secret. Where a rotatable-secret type records NO
    expiry, that is a coverage gap (the policy exists in the system but this connector does not
    expose it), surfaced honestly rather than passed. Static bearer types are handled by
    STATIC_NO_ROTATION, so this rule stays silent for them to avoid a duplicate finding."""
    raw = r.raw or {}
    if not raw.get("present", True):
        return []
    system = raw.get("system", "?")
    ctype = raw.get("credential_type", "credential")

    # Recorded expiry telemetry (future-proofed; no connector emits these yet).
    if "ttl_seconds" in raw or "max_age_days" in raw or "expires_at" in raw:
        if "ttl_seconds" in raw:
            ttl = raw.get("ttl_seconds")
            unbounded = not ttl or int(ttl) <= 0
            excessive = (not unbounded) and int(ttl) > _EXCESSIVE_DAYS * 86400
            shown = f"ttl_seconds={ttl}"
        elif "max_age_days" in raw:
            days = raw.get("max_age_days")
            unbounded = not days or int(days) <= 0
            excessive = (not unbounded) and int(days) > _EXCESSIVE_DAYS
            shown = f"max_age_days={days}"
        else:
            exp = raw.get("expires_at")
            if not exp:                                  # key present but empty → never expires
                unbounded, excessive, shown = True, False, "expires_at=never"
            else:
                age = _age_days(exp)                     # negative age → future expiry
                remaining = -age if age is not None else None
                unbounded = False
                excessive = remaining is not None and remaining > _EXCESSIVE_DAYS
                shown = f"expires_at={exp!r}"
        if not (unbounded or excessive):
            return []
        why = "no expiry (unbounded)" if unbounded else f"an expiry window over {_EXCESSIVE_DAYS} days"
        return [Hit(
            observation=(f"{system} credential '{r.name}' ({ctype}) is configured with {why} "
                         f"({shown}), so a leaked value stays usable indefinitely"),
            remediation="Set a short, finite TTL and rotate before it expires; unbounded credential "
                        "lifetimes turn a one-time leak into permanent access.",
            detail=f"type={ctype} {shown}",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]

    # No expiry telemetry recorded. Only the rotatable types (where an expiry policy really exists)
    # are a coverage gap; static bearer types are the STATIC_NO_ROTATION rule's job.
    if ctype in _ROTATABLE:
        return [Hit(
            observation=(f"{system} credential '{r.name}' ({ctype}) exposes no expiry or TTL; this "
                         f"connector does not report the credential's rotation/expiry policy, so "
                         f"whether it is set to expire cannot be determined"),
            remediation="Confirm an expiry/rotation policy is configured for this credential in its "
                        "source system, and collect it so this can be assessed automatically.",
            detail=f"type={ctype} system={system} expiry=unknown",
            assessable=False,
            assessment_reason=f"{system} does not expose an expiry/TTL for this {ctype}",
            source_ref={"kind": "credential", "system": system, "credential_type": ctype},
        )]
    return []


# ── Shared credential — structural markers only (no value correlation) ─────────
@detector(kinds=["credential"], rule_id="CREDENTIAL.LIFECYCLE.SHARED", severity="medium",
          title="Credential is shared by construction across callers")
def shared_credential(r, ctx) -> list:
    """Some credentials are, by construction, one secret handed to many callers — an Azure SAS
    policy key or an APIM subscription key. A shared credential breaks attribution and widens the
    blast radius. Fires only on a structural marker (a shared-by-design key type or an explicit
    `shared` flag); value-level reuse across systems is out of scope because no secret is
    collected, so silence here means 'no shared marker', never a proof of non-sharing."""
    raw = r.raw or {}
    if not raw.get("present", True):
        return []
    ctype = raw.get("credential_type", "credential")
    system = raw.get("system", "?")
    shared_flag = bool(raw.get("shared"))
    if not (shared_flag or ctype in _SHARED_KEY_TYPES):
        return []
    why = ("is flagged shared" if shared_flag
           else f"is a {ctype}, a single key issued to every caller of its resource")
    return [Hit(
        observation=(f"{system} credential '{r.name}' {why}, so its use cannot be attributed to a "
                     f"single consumer and any one holder's compromise exposes all of them"),
        remediation=("Issue a distinct credential per consumer (per-consumer SAS rule / APIM "
                     "subscription) so access is attributable and revocable one caller at a time."),
        detail=f"type={ctype} system={system} shared={'flag' if shared_flag else 'by-type'}",
        source_ref={"kind": "credential", "system": system, "credential_type": ctype},
    )]


# ── Default / bootstrap credential still active ───────────────────────────────
@detector(kinds=["credential"], rule_id="CREDENTIAL.LIFECYCLE.DEFAULT_ACTIVE", severity="high",
          title="Default or bootstrap credential is still active")
def default_active(r, ctx) -> list:
    """A shipped default/bootstrap credential that is still present and unchanged (e.g. the
    RabbitMQ default user's confirmed default password) is a well-known secret an attacker can try
    first. This keys on the recorded is_default flag — distinct from the weak-hash rule (which keys
    on the storage algorithm) and the shared-default IDENTITY rule (which keys on the principal
    name)."""
    raw = r.raw or {}
    is_default = raw.get("is_default")
    if is_default is None:
        is_default = (r.labels or {}).get("default") == "true"
    if not is_default or not raw.get("present", True):
        return []
    system = raw.get("system", "?")
    ctype = raw.get("credential_type", "credential")
    return [Hit(
        observation=(f"{system} credential '{r.name}' ({ctype}) is a default/bootstrap credential "
                     f"that is still present and unchanged"),
        remediation=("Replace the default credential with a unique secret (or delete the default "
                     "identity entirely); shipped defaults are the first thing an attacker tries."),
        detail=f"type={ctype} system={system} is_default=true",
        source_ref={"kind": "credential", "system": system, "credential_type": ctype},
    )]


# ── Orphaned identity — granted but disabled, or ungoverned ───────────────────
@detector(kinds=["identity"], rule_id="CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY", severity="medium",
          title="Non-human identity holds grants but shows no owner or activity signal")
def orphaned_identity(r, ctx) -> list:
    """An identity that still holds authorizations but has been offboarded — or that nobody owns and
    that shows no sign of use — is an orphaned principal: standing access with no accountable owner.
    The disabled-but-still-granted case is provable today (an explicit enabled=False, e.g. a Redis
    ACL user). The general orphan case needs a last-activity signal we do not have, so it is
    surfaced as a coverage gap rather than asserted."""
    raw = r.raw or {}
    grants = [g for g in ctx.of_kind("grant") if (g.raw or {}).get("identity_ext_id") == r.ext_id]
    if not grants:
        return []                      # no standing access → not an over-authorized orphan
    system = (raw.get("system") or (r.labels or {}).get("system") or "?")
    itype = raw.get("identity_type", "identity")
    creds = [c for c in ctx.of_kind("credential")
             if (c.raw or {}).get("owner_ext_id") == r.ext_id]

    # Provable: a disabled principal that still carries authorizations — an offboarding gap.
    if raw.get("enabled") is False:
        return [Hit(
            observation=(f"{system} identity '{r.name}' ({itype}) is disabled but still holds "
                         f"{len(grants)} grant(s); its access was not removed when it was disabled"),
            remediation=("Remove the grants of a disabled identity (or delete it); a disabled "
                         "principal that keeps its authorizations is standing access waiting to be "
                         "re-enabled."),
            detail=f"type={itype} system={system} grants={len(grants)} enabled=false",
            source_ref={"kind": "identity", "system": system, "identity": r.ext_id},
        )]

    # No readable credential and no activity/ownership signal → orphanhood cannot be proven.
    if not creds:
        return [Hit(
            observation=(f"{system} identity '{r.name}' ({itype}) holds {len(grants)} grant(s) but "
                         f"exposes no credential and no last-activity or ownership signal, so "
                         f"whether it is an orphaned principal cannot be determined"),
            remediation=("Record an owner and last-activity for each non-human identity so granted "
                         "principals that are no longer used can be found and decommissioned."),
            detail=f"type={itype} system={system} grants={len(grants)} credential=absent",
            assessable=False,
            assessment_reason=(f"{system} exposes no credential, last-activity, or owner for this "
                               f"granted identity"),
            source_ref={"kind": "identity", "system": system, "identity": r.ext_id},
        )]
    return []
