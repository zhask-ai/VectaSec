"""Offline unit tests for the credential-lifecycle rulepack (CREDENTIAL.LIFECYCLE.*).

Detectors run on the NORMALIZED identity/credential kinds. Fixtures are built either by hand in
the exact shape identity.py's _mk_credential/_mk_identity produce, or by running the real
extractors over connector-shaped resources — so the tests double as proof that the lifecycle
signals the module claims are "provable today" really do survive derivation.

Every rule gets a fires-on-bad AND a silent-on-good pair, and every rule whose signal can be
absent gets the third case: telemetry absent → not_assessable (assessable is False). Timestamps
are built relative to now (400 days ago = stale, 5 days ago = fresh) so the suite never rots on a
calendar date.
"""
from datetime import datetime, timedelta, timezone

from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.identity import (
    _mk_credential, _mk_grant, _mk_identity, derive_identities,
)
import vectasec.detect.credential_lifecycle as lc


# ── helpers ────────────────────────────────────────────────────────────────────
def _ctx(resources):
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iso_future(days_ahead: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days_ahead)).strftime("%Y-%m-%dT%H:%M:%SZ")


def cred(ctype="api_key", system="acme", *, present=True, **extra) -> Resource:
    """A normalized credential exactly as _mk_credential builds it, plus any extra raw fields a
    connector may have carried through (created_at, last_used_at, ttl_seconds, …)."""
    owner = f"identity:{system}:svc"
    c = _mk_credential(system, owner, ctype, name=f"svc:{ctype}", present=present)
    c.raw.update(extra)
    return c


def only(hits):
    assert len(hits) == 1, f"expected exactly one hit, got {len(hits)}"
    return hits[0]


# ── ROTATION_STALE ──────────────────────────────────────────────────────────────
def test_rotation_stale_fires_on_old_recorded_timestamp():
    h = only(lc.rotation_stale(cred(created_at=_iso(400)), _ctx([])))
    assert h.assessable is True
    assert "400 days ago" in h.observation

def test_rotation_stale_silent_when_recently_rotated():
    assert lc.rotation_stale(cred(created_at=_iso(5)), _ctx([])) == []

def test_rotation_stale_not_assessable_when_no_timestamp_recorded():
    h = only(lc.rotation_stale(cred("password", "rabbitmq"), _ctx([])))
    assert h.assessable is False
    assert "no creation or rotation timestamp" in h.observation

def test_rotation_stale_not_assessable_on_unparseable_timestamp():
    h = only(lc.rotation_stale(cred(created_at="last-tuesday"), _ctx([])))
    assert h.assessable is False
    assert "not a parseable timestamp" in h.observation

def test_rotation_stale_reads_k8s_oldest_created_alias():
    h = only(lc.rotation_stale(cred("sa_token", "k8s", oldest_created=_iso(500)), _ctx([])))
    assert h.assessable is True and "500 days ago" in h.observation


# ── NEVER_USED (awaits enrichment: real creds are always not_assessable) ─────────
def test_never_used_not_assessable_today():
    h = only(lc.never_used(cred("api_key", "confluent"), _ctx([])))
    assert h.assessable is False
    assert "no last-authentication time" in h.observation

def test_never_used_fires_when_last_used_is_empty():
    h = only(lc.never_used(cred(last_used_at=""), _ctx([])))
    assert h.assessable is True and "never authenticated" in h.observation

def test_never_used_fires_on_long_dormant():
    h = only(lc.never_used(cred(last_authenticated_at=_iso(120)), _ctx([])))
    assert h.assessable is True and "120 days ago" in h.observation

def test_never_used_silent_when_recently_used():
    assert lc.never_used(cred(last_used_at=_iso(3)), _ctx([])) == []


# ── STATIC_NO_ROTATION (structural, provable today) ──────────────────────────────
def test_static_no_rotation_fires_on_api_key():
    h = only(lc.static_no_rotation(cred("api_key", "kong"), _ctx([])))
    assert h.assessable is True and "static bearer secret" in h.observation

def test_static_no_rotation_silent_on_password():
    assert lc.static_no_rotation(cred("password", "rabbitmq"), _ctx([])) == []

def test_static_no_rotation_covers_sas_and_sa_token():
    assert lc.static_no_rotation(cred("sas_key", "azure"), _ctx([]))
    assert lc.static_no_rotation(cred("sa_token", "k8s"), _ctx([]))


# ── NO_EXPIRY ────────────────────────────────────────────────────────────────────
def test_no_expiry_fires_on_zero_ttl():
    h = only(lc.no_expiry(cred("secret_id", "vault", ttl_seconds=0), _ctx([])))
    assert h.assessable is True and "no expiry (unbounded)" in h.observation

def test_no_expiry_fires_on_excessive_max_age():
    h = only(lc.no_expiry(cred("client_secret", "keycloak", max_age_days=1000), _ctx([])))
    assert h.assessable is True and "over 365 days" in h.observation

def test_no_expiry_fires_on_far_future_expires_at():
    h = only(lc.no_expiry(cred("oauth_secret", "mcp", expires_at=_iso_future(800)), _ctx([])))
    assert h.assessable is True

def test_no_expiry_silent_on_reasonable_ttl():
    assert lc.no_expiry(cred("secret_id", "vault", ttl_seconds=3600), _ctx([])) == []

def test_no_expiry_not_assessable_for_rotatable_without_ttl():
    h = only(lc.no_expiry(cred("password", "pgbouncer"), _ctx([])))
    assert h.assessable is False and "no expiry or TTL" in h.observation

def test_no_expiry_silent_for_static_type_without_ttl():
    # api_key has no expiry, but STATIC_NO_ROTATION owns that finding — no double-count here.
    assert lc.no_expiry(cred("api_key", "confluent"), _ctx([])) == []


# ── SHARED ───────────────────────────────────────────────────────────────────────
def test_shared_fires_on_sas_key_type():
    h = only(lc.shared_credential(cred("sas_key", "azure"), _ctx([])))
    assert "single key issued to every caller" in h.observation

def test_shared_fires_on_explicit_flag():
    assert lc.shared_credential(cred("password", "acme", shared=True), _ctx([]))

def test_shared_silent_on_ordinary_credential():
    assert lc.shared_credential(cred("password", "rabbitmq"), _ctx([])) == []


# ── DEFAULT_ACTIVE ───────────────────────────────────────────────────────────────
def test_default_active_fires_on_is_default_flag():
    c = _mk_credential("rabbitmq", "identity:rabbitmq:guest", "password",
                       name="guest:password", is_default=True)
    h = only(lc.default_active(c, _ctx([])))
    assert h.severity is None and "default/bootstrap credential" in h.observation

def test_default_active_reads_label_when_raw_missing():
    c = cred("password", "acme")
    c.raw.pop("is_default", None)
    c.labels["default"] = "true"
    assert lc.default_active(c, _ctx([]))

def test_default_active_silent_on_nondefault():
    assert lc.default_active(cred("password", "rabbitmq"), _ctx([])) == []


# ── ORPHANED_IDENTITY (ctx-aware) ────────────────────────────────────────────────
def _identity(system="redis", *, enabled=None, name="svc"):
    idr = _mk_identity(system, "service_account", name, extra={} if enabled is None else {"enabled": enabled})
    return idr

def _grant_for(idr, system="redis"):
    return _mk_grant(system, idr.ext_id, "acl", "keys=~* commands=+@all", wildcard=True)

def test_orphaned_identity_silent_without_grants():
    idr = _identity(enabled=False)
    assert lc.orphaned_identity(idr, _ctx([idr])) == []

def test_orphaned_identity_fires_when_disabled_but_granted():
    idr = _identity(enabled=False)
    g = _grant_for(idr)
    h = only(lc.orphaned_identity(idr, _ctx([idr, g])))
    assert h.assessable is True and "disabled but still holds" in h.observation

def test_orphaned_identity_not_assessable_when_granted_but_no_credential():
    # A Kafka-style principal: grants exist, no credential readable, no enabled/owner signal.
    idr = _mk_identity("kafka", "service_account", "User:alice")
    g = _mk_grant("kafka", idr.ext_id, "read", "topic:payments")
    h = only(lc.orphaned_identity(idr, _ctx([idr, g])))
    assert h.assessable is False and "cannot be determined" in h.observation

def test_orphaned_identity_silent_when_granted_and_credentialed():
    idr = _identity(enabled=True)
    g = _grant_for(idr)
    c = _mk_credential("redis", idr.ext_id, "password", name="svc:password")
    assert lc.orphaned_identity(idr, _ctx([idr, g, c])) == []


# ── end-to-end through the real extractors: "provable today" holds after derivation ──
def test_confluent_api_key_yields_rotation_and_static_findings():
    key = Resource(kind="confluent_api_key", name="api-key-1", ext_id="ck-1", raw={
        "api_key_id": "KEY123", "owner_id": "sa-1", "created_at": _iso(500),
        "cloud_scoped": False, "resource_kind": "cluster"})
    col = derive_identities("confluent", Collected(resources=[key]))
    creds = [r for r in col.resources if r.kind == "credential"]
    assert len(creds) == 1
    c, ctx = creds[0], _ctx(col.resources)
    assert lc.rotation_stale(c, ctx)[0].assessable is True         # created_at survived derivation
    assert lc.static_no_rotation(c, ctx)[0].assessable is True     # api_key type is static
    assert lc.never_used(c, ctx)[0].assessable is False            # no last-used telemetry

def test_rabbitmq_default_password_is_flagged_default_active():
    user = Resource(kind="user", name="guest", ext_id="user-guest", raw={
        "name": "guest", "tags": [], "hashing_algorithm": "sha256",
        "has_internal_password": True, "default_password_confirmed": True})
    col = derive_identities("rabbitmq", Collected(resources=[user]))
    c = next(r for r in col.resources if r.kind == "credential")
    assert lc.default_active(c, _ctx(col.resources))               # is_default survived derivation

def test_redis_disabled_user_with_grant_is_orphaned():
    u = Resource(kind="redis_user", name="stale", ext_id="redis-user-stale", raw={
        "username": "stale", "enabled": False, "nopass": True, "keys": "~*", "commands": "+@all"})
    col = derive_identities("redis", Collected(resources=[u]))
    idr = next(r for r in col.resources if r.kind == "identity")
    h = only(lc.orphaned_identity(idr, _ctx(col.resources)))
    assert h.assessable is True and "disabled" in h.observation


# ── catalogue hygiene ────────────────────────────────────────────────────────────
def test_rule_ids_are_unique_and_namespaced():
    from vectasec.registry import DETECTORS
    lifecycle = [d for d in DETECTORS if d.rule_id.startswith("CREDENTIAL.LIFECYCLE.")]
    ids = [d.rule_id for d in lifecycle]
    assert len(ids) == len(set(ids)), "duplicate CREDENTIAL.LIFECYCLE rule_id"
    assert len(ids) == 7
    # The prefix must not collide with any connector type (like NHI./CVE.), so it can never be
    # captured by a per-connector suppression scope or mapping.
    assert all(d.kinds and set(d.kinds) <= {"credential", "identity"} for d in lifecycle)
