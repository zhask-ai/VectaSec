"""FastAPI service: actions + scan orchestration.

    uv run python -m vectasec.api.main        # or: uvicorn vectasec.api.main:app

Division of labour with the console: the console READS Supabase directly (PostgREST + RLS),
so this service has no list endpoints. Everything here either changes state or starts work,
and both need what RLS cannot give: an authenticated actor and an audit trail.

Two rules this file lives by:

  • The engine connects with a BYPASSRLS role, so tenant isolation is NOT free here the way
    it is in the browser. Every statement filters `tenant_id` explicitly. A missing
    `and tenant_id = %s` in this file is a cross-tenant leak, not a bug.
  • Every mutation writes its audit_log row in the SAME transaction as the change. An action
    that committed without its audit row is an action nobody can account for.

Handlers are sync `def` on purpose: psycopg blocks, and FastAPI runs sync handlers in a
threadpool, so blocking here costs a worker thread rather than stalling the event loop.
"""
import hmac as _hmac
import json
import logging
import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Literal, Optional

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Header, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from ..config import load_env, settings
from ..db import connect
from ..registry import CONNECTORS, CONNECTOR_FIELDS, DETECTORS, validate_config
from ..scan import run_scan, ensure_connection_with_creds   # reused so a queued scan points at
                                                            # the same connection row the worker
                                                            # will land on — not a second one
from .. import connect as _connect_pkg   # noqa: F401 — import triggers connector auto-registration
from .. import detect as _detect_pkg     # noqa: F401 — import triggers detector auto-registration

log = logging.getLogger("vectasec.api")

QUEUE = "vectasec_scans"                 # created in 20260717000002_platform_schema.sql


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    _warn_if_header_trust_enabled()
    yield


app = FastAPI(title="VectaSec engine", version="0.0.1", lifespan=_lifespan)

# The console is a browser app on another origin, so it cannot call this service at all
# without CORS. Origins are an allowlist, never "*": this API takes actions.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in
                   os.environ.get("ENGINE_CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()],
    allow_credentials=False,             # auth travels in headers, not cookies — no CSRF surface
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Identity ──────────────────────────────────────────────────────────────
class Principal(BaseModel):
    tenant_id: str
    actor: str
    # Which auth path admitted the request ("service" | "jwt" | "dev") and, when already
    # known (the JWT path resolves membership anyway), the actor's tenant_members.role.
    # The service path resolves the role lazily, at mutation time (_require_rank).
    #
    # NO DEFAULT, deliberately. This used to default to "dev" — the one value for which
    # _require_rank returns unconditionally — so any Principal constructed without naming its
    # auth path was a silent, complete RBAC bypass. One such construction already existed
    # (the audit-only actor below). A required field makes that class of mistake a startup
    # error instead of a privilege escalation nobody notices.
    via: str
    role: Optional[str] = None


# Dev header-trust is OFF, unconditionally, unless VECTASEC_DEV_TRUST_HEADERS is EXPLICITLY set
# truthy. There is no localhost carve-out any more: an unset environment means a verified token
# (Supabase JWT or the engine service token) is the ONLY way to authenticate, on every bind.
# Read at request time, not import time, so a process cannot capture a stale default.
def _dev_trust_headers() -> bool:
    return os.environ.get("VECTASEC_DEV_TRUST_HEADERS", "").strip().lower() in (
        "1", "true", "yes", "on")


def _warn_if_header_trust_enabled() -> None:
    """The loud half of the gate: enabling header trust must be impossible to miss."""
    if _dev_trust_headers():
        log.warning("=" * 76)
        log.warning("SECURITY: VECTASEC_DEV_TRUST_HEADERS is ENABLED.")
        log.warning("Self-asserted X-VectaSec-Tenant / X-VectaSec-Actor headers are TRUSTED:")
        log.warning("any caller that can reach this port can name any tenant and any actor.")
        log.warning("This is a single-operator DEV convenience only. Unset it (the default is")
        log.warning("OFF) before this engine is reachable by anything you do not control.")
        log.warning("=" * 76)


def _engine_token() -> str:
    """Optional shared-secret bearer token for trusted server-to-server callers (the console's
    server side). Transitional: it authenticates the CALLING SERVICE, which is then trusted to
    assert the acting user/tenant it has itself verified (apps/web verifies both via Supabase
    before ever calling here). Scope it with VECTASEC_ENGINE_TOKEN_TENANT to pin the token to
    one tenant."""
    return os.environ.get("VECTASEC_ENGINE_TOKEN", "").strip()


def _tenant_for_user(user_id: str, requested: Optional[str]) -> tuple[str, Optional[str]]:
    """Resolve (tenant, role) for a verified user from tenant_members.

    The tenant is NEVER taken from the request — it is looked up from membership. If the user
    asked for a specific tenant (X-VectaSec-Tenant), honour it only if they actually belong to
    it; otherwise use their (single) membership. A user in no tenant is 403, not defaulted.
    The role rides along because the same query answers both questions, and every mutation
    will need it (_require_rank).
    """
    with _db() as conn, conn.cursor() as cur:
        cur.execute("select tenant_id::text, role from tenant_members where user_id = %s",
                    (user_id,))
        member_of = {r[0]: r[1] for r in cur.fetchall()}
        cur.execute("select 1 from super_admins where user_id = %s", (user_id,))
        is_super = cur.fetchone() is not None
    if not member_of and not is_super:
        raise HTTPException(403, "authenticated user belongs to no tenant")
    if requested:
        if requested not in member_of:
            # Platform operators act as admin in any tenant — the row in super_admins is the
            # privilege (granted by the operator, never writable from the browser role). This
            # branch is only reached on the JWT path, where the ENGINE verified the subject.
            if is_super:
                # The tenant must exist. Without this a typo'd or invented uuid is accepted as
                # a legitimate operating context: reads return empty (reassuringly), writes
                # fail deep in a foreign-key error instead of a clean 404, and the audit log
                # records admin actions against a tenant that was never real.
                with _db() as conn, conn.cursor() as cur:
                    cur.execute("select 1 from tenants where id = %s", (requested,))
                    if not cur.fetchone():
                        raise HTTPException(404, "no such tenant")
                return requested, "admin"
            raise HTTPException(403, "not a member of the requested tenant")
        return requested, member_of[requested]
    if not member_of:
        raise HTTPException(400, "super admin with no membership: specify X-VectaSec-Tenant")
    if len(member_of) > 1:
        raise HTTPException(400, "user belongs to multiple tenants; specify X-VectaSec-Tenant")
    tenant = next(iter(member_of))
    return tenant, member_of[tenant]


def principal(
    authorization: Optional[str] = Header(None),
    x_vectasec_tenant: Optional[str] = Header(None),
    x_vectasec_actor: Optional[str] = Header(None),
) -> Principal:
    """Who is calling. Verified tokens only, by default — nothing self-asserted is trusted.

    Path 1 — `Authorization: Bearer <engine-token>` (checked first, constant-time): the shared
    service secret in VECTASEC_ENGINE_TOKEN, for trusted server-to-server callers (the console's
    server side). The tenant comes from VECTASEC_ENGINE_TOKEN_TENANT when that scope is set
    (a mismatched X-VectaSec-Tenant is refused); otherwise from X-VectaSec-Tenant — asserted by
    the authenticated SERVICE, which verifies the user and derives the tenant under RLS before
    calling (apps/web/lib/{engine,tenant}.ts). The actor is X-VectaSec-Actor, the service's
    server-confirmed user id. Unset VECTASEC_ENGINE_TOKEN disables this path entirely.

    Path 2 — `Authorization: Bearer <supabase-jwt>`: the signature is verified against the
    project's public JWKS (auth.verify_supabase_jwt), the actor is the token's `sub`, and the
    tenant is resolved from tenant_members for that user. The request cannot name a tenant the
    user does not belong to.

    Path 3 — the bare X-VectaSec-* headers: self-asserted, accepted ONLY when
    VECTASEC_DEV_TRUST_HEADERS is explicitly enabled (default OFF, always — see
    _dev_trust_headers and the startup warning). Without it, no Authorization header is 401.
    """
    if x_vectasec_tenant:
        try:
            uuid.UUID(x_vectasec_tenant)
        except ValueError:
            raise HTTPException(400, "X-VectaSec-Tenant must be a uuid")

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()

        engine_token = _engine_token()
        if engine_token and _hmac.compare_digest(token.encode(), engine_token.encode()):
            scoped = os.environ.get("VECTASEC_ENGINE_TOKEN_TENANT", "").strip()
            if scoped:
                if x_vectasec_tenant and x_vectasec_tenant != scoped:
                    raise HTTPException(403, "engine token is not scoped to the requested tenant")
                tenant = scoped
            elif x_vectasec_tenant:
                tenant = x_vectasec_tenant
            else:
                raise HTTPException(400, "engine-token calls must name a tenant "
                                          "(X-VectaSec-Tenant or VECTASEC_ENGINE_TOKEN_TENANT)")
            try:
                uuid.UUID(tenant)
            except ValueError:
                raise HTTPException(400, "tenant must be a uuid")
            return Principal(tenant_id=tenant, actor=(x_vectasec_actor or "").strip(),
                             via="service")

        try:
            from .auth import verify_supabase_jwt
            claims = verify_supabase_jwt(token)
        except Exception as e:
            raise HTTPException(401, f"invalid token: {type(e).__name__}") from e
        user_id = str(claims.get("sub") or "")
        if not user_id:
            raise HTTPException(401, "token has no subject")
        tenant, role = _tenant_for_user(user_id, x_vectasec_tenant)
        return Principal(tenant_id=tenant, actor=user_id, via="jwt", role=role)

    if not _dev_trust_headers():
        raise HTTPException(401, "authentication required: a Supabase JWT or the engine service "
                                 "token (dev header-trust is disabled by default)")

    tenant = (x_vectasec_tenant or settings.demo_tenant).strip()
    try:
        uuid.UUID(tenant)
    except ValueError:
        raise HTTPException(400, "X-VectaSec-Tenant must be a uuid")
    return Principal(tenant_id=tenant, actor=(x_vectasec_actor or "").strip(), via="dev")


def acting(p: Principal = Depends(principal)) -> Principal:
    """Principal for mutating endpoints — the actor is mandatory.

    An audit row with no actor documents nothing, so an unattributed write is refused rather
    than recorded anonymously.
    """
    if not p.actor:
        raise HTTPException(401, "X-VectaSec-Actor is required for actions (it is written to the audit log)")
    return p


# ── RBAC ──────────────────────────────────────────────────────────────────
# tenant_members.role is the authority. The live values are the console's MemberRole set
# (owner|admin|analyst|viewer, apps/web/lib/types.ts); 'editor' is accepted as a synonym of
# analyst so the API reads naturally. Three tiers of capability:
#   viewer (rank 1)         — read-only: every GET, nothing else
#   editor/analyst (rank 2) — scans, triage, suppressions, connections, attestations
#   admin/owner (rank 3)    — everything, incl. integrations, routing rules and members
ROLE_RANK = {"viewer": 1, "analyst": 2, "editor": 2, "admin": 3, "owner": 3}
_TIER_NAME = {2: "editor", 3: "admin"}


def _role_for_actor(tenant_id: str, actor: str) -> Optional[str]:
    """The actor's tenant_members.role, or None (not a uuid / not a member).

    Used on the SERVICE path: the console authenticated with the shared engine token and
    named its server-verified user in X-VectaSec-Actor — the console is trusted to name the
    actor, but the ENGINE decides what that actor may do, from the membership table."""
    try:
        user_id = str(uuid.UUID(actor))
    except (ValueError, AttributeError, TypeError):
        return None
    with _db() as conn, conn.cursor() as cur:
        cur.execute("select role from tenant_members where tenant_id = %s and user_id = %s",
                    (tenant_id, user_id))
        row = cur.fetchone()
        if row:
            return row[0]

        # Platform operators. This function runs ONLY on the service-token path, where `actor`
        # is the self-asserted X-VectaSec-Actor header — the engine has verified the CALLING
        # SERVICE, not the user it names. Honouring super_admins here therefore turns one
        # shared env-var secret into cross-tenant admin: a token holder asserts any super
        # admin's uuid (they are not secret — GET /members returns them) and gains member,
        # integration and connection control in EVERY tenant.
        #
        # So it is off unless an operator explicitly turns it on. The trade is deliberate: the
        # operator console's act-on-behalf loses its cross-tenant reach in a default install,
        # and in exchange a leaked engine token stays bounded by tenant_members — which is
        # what it was before super admins existed. The durable fix is per-user JWTs on console
        # calls (STATUS.md gap 2), after which the JWT path below carries this natively.
        if _allow_service_superadmin():
            cur.execute("select 1 from super_admins where user_id = %s", (user_id,))
            if cur.fetchone():
                return "admin"
    return None


def _allow_service_superadmin() -> bool:
    """Opt-in for super-admin elevation on the SERVICE-token path. Default off — see
    _role_for_actor for why this is not a knob to enable casually."""
    return os.environ.get("VECTASEC_ALLOW_SERVICE_SUPERADMIN", "").strip().lower() in (
        "1", "true", "yes")


def _is_super_admin(user_id: str) -> bool:
    with _db() as conn, conn.cursor() as cur:
        cur.execute("select 1 from super_admins where user_id = %s", (user_id,))
        return cur.fetchone() is not None


# ── Error text that is safe to persist and return ─────────────────────────
# Connector exceptions carry whatever the underlying client library felt like saying, and those
# libraries are invoked with VAULTED CREDENTIALS. psycopg echoes a malformed DSN verbatim
# (`postgresql://user:pass@host`), httpx can include a URL with userinfo, and several SDKs put
# the endpoint and token fragment in the message. That text was going into `audit_log.detail`
# and `notification_deliveries.error` — both readable by every tenant member, including VIEWERS.
#
# `notify._post` already keeps URLs out of its error text and the action-layer migration's own
# comment says these columns are "never a secret/URL value". This makes that true here too.
_SECRET_PATTERNS = [
    # scheme://user:pass@host  → keep the shape, drop the credential
    (re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),
    # Bearer FIRST. `Authorization: Bearer <jwt>` otherwise matches the key=value rule below,
    # which consumes only the word "Bearer" as the value and leaves the token in the clear —
    # verified: it leaked the JWT until this pair was reordered.
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"), "bearer <redacted>"),
    # password / token / secret / api-key = value
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization)"
                r"\s*[=:]\s*\S+"), r"\1=<redacted>"),
]

_ERROR_MAX = 300


def safe_error(e: BaseException) -> str:
    """A message safe to store and return: type name, redacted text, bounded length.

    The type name is always exact — that is the part an operator debugs with — while the free
    text is scrubbed and truncated. The full exception still reaches the server log, where the
    audience is the operator rather than every viewer in the tenant.
    """
    text = str(e)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > _ERROR_MAX:
        text = text[:_ERROR_MAX] + "… (truncated)"
    return f"{type(e).__name__}: {text}" if text else type(e).__name__


def _require_rank(p: Principal, min_rank: int) -> Principal:
    """Enforce the role matrix on an acting principal. Dev header-trust is exempt: that mode
    already trusts self-asserted headers wholesale (single-operator opt-in), so a role check
    against a made-up actor would be theatre, not security."""
    if p.via == "dev":
        return p
    if p.via not in ("service", "jwt"):
        # An unrecognised auth path grants nothing. Fail closed: the alternative is that a new
        # path added later inherits whatever the last `if` happened to allow.
        raise HTTPException(403, f"authentication path {p.via!r} cannot perform actions")
    role = p.role if p.role is not None else _role_for_actor(p.tenant_id, p.actor)
    p.role = role
    if ROLE_RANK.get(role or "", 0) < min_rank:
        raise HTTPException(
            403, f"this action requires the {_TIER_NAME[min_rank]} role or above "
                 f"(actor's role: {role or 'not a member'})")
    return p


def editing(p: Principal = Depends(acting)) -> Principal:
    """Acting principal with at least the editor tier (scans/triage/suppressions/connections)."""
    return _require_rank(p, 2)


def admin(p: Principal = Depends(acting)) -> Principal:
    """Acting principal with the admin tier (integrations, routing rules, members)."""
    return _require_rank(p, 3)


def would_drop_last_admin(members: list[tuple[str, str]], target_user: str,
                          new_role: Optional[str]) -> bool:
    """Would changing target_user to new_role (None = removal) leave the tenant with no
    admin-tier member? Pure — the members list is [(user_id, role)]. A tenant nobody can
    administer is a locked room, so this is checked before every demotion/removal."""
    admins = {u for u, r in members if ROLE_RANK.get(r, 0) >= 3}
    if target_user not in admins:
        return False
    if new_role is not None and ROLE_RANK.get(new_role, 0) >= 3:
        return False
    return admins == {target_user}


def _db() -> psycopg.Connection:
    """One connection per request.

    db.connect() is CLI-first: it raises SystemExit when DATABASE_URL is unset, and SystemExit
    is not an Exception — unhandled it takes down the request in a way no client can read.
    Both it and an unreachable database mean the same thing to a caller: try later.
    """
    try:
        return connect()
    except SystemExit as e:
        raise HTTPException(503, str(e)) from e
    except psycopg.OperationalError as e:
        raise HTTPException(503, f"database unavailable: {e}") from e


def _audit(cur, p: Principal, action: str, target: Optional[str], detail: dict) -> None:
    """Append to the audit log. Always called inside the caller's transaction — an audit row
    that can be lost while the action it records commits is worse than none."""
    cur.execute(
        """insert into audit_log (tenant_id, actor, action, target, detail)
           values (%s,%s,%s,%s,%s)""",
        (p.tenant_id, p.actor, action, target, json.dumps(detail, default=str)),
    )


# ── Health ────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> dict:
    """Deliberately 200 even when the database is down: `db` carries the truth, and a health
    check that refuses to answer cannot tell an operator which half is broken."""
    db_ok = False
    try:
        with _db() as conn, conn.cursor() as cur:
            cur.execute("select 1")
            db_ok = cur.fetchone() == (1,)
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "db": db_ok,
        "detectors": len(DETECTORS),
        "connectors": sorted(CONNECTORS),
    }


# ── Scans ─────────────────────────────────────────────────────────────────
def _enqueue_scan(cur, tenant: str, connection_id: str, type_: str, config: dict,
                  name: str, requested_by: str) -> tuple[str, int]:
    """Insert a 'queued' scans row and its pgmq job in the caller's transaction.

    One helper, two callers (POST /scans and POST /connections/{id}/scan), so the job payload
    can never drift from the shape worker.parse_job validates. pgmq is a table: the message
    becomes visible at COMMIT, so a worker can never pull a job whose scan row does not exist.
    """
    cur.execute(
        """insert into scans (tenant_id, connection_id, status)
           values (%s,%s,'queued') returning id""",
        (tenant, connection_id),
    )
    scan_id = cur.fetchone()[0]
    job = {"scan_id": str(scan_id), "type": type_, "config": config,
           "tenant_id": tenant, "name": name, "requested_by": requested_by}
    cur.execute("select * from pgmq.send(%s, %s::jsonb)", (QUEUE, json.dumps(job)))
    msg_id = cur.fetchone()[0]
    return str(scan_id), msg_id


class ScanRequest(BaseModel):
    type: str
    config: dict = Field(default_factory=dict)
    tenant_id: Optional[uuid.UUID] = None
    name: Optional[str] = None           # connection name; defaults like the CLI's
    inline: bool = False


@app.post("/scans", status_code=202)
def create_scan(req: ScanRequest, p: Principal = Depends(editing)) -> dict:
    """Start a scan. Queued by default — `vectasec worker` drains the queue and adopts the
    row (worker.py); `inline: true` runs it in this request instead (dev and demo path).
    """
    if req.type not in CONNECTORS:
        raise HTTPException(400, f"no connector for type {req.type!r} (have: {sorted(CONNECTORS)})")
    # The principal's tenant is authoritative (membership-derived on the JWT path, service-
    # asserted on the token path). A body tenant_id may only AGREE with it — anything else is
    # a cross-tenant write. Dev header-trust keeps the old permissive behaviour.
    if req.tenant_id and str(req.tenant_id) != p.tenant_id and p.via != "dev":
        raise HTTPException(403, "body tenant_id does not match the authenticated tenant")
    tenant = str(req.tenant_id) if req.tenant_id else p.tenant_id
    # Audit-only: never passed to _require_rank. `via` is explicit because the field is
    # now required, and "audit" is deliberately a path with no rank of its own.
    actor = Principal(tenant_id=tenant, actor=p.actor, via="audit")

    # Resolved HERE, not left to run_scan's fallback, so the queued connection row and the
    # worker's eventual run_scan(connection_name=...) agree by construction rather than by two
    # copies of the same rule staying in sync.
    name = req.name or req.config.get("bootstrap") or req.config.get("url") or req.type

    if req.inline:
        stats = run_scan(req.type, req.config, tenant_id=tenant, connection_name=name)
        with _db() as conn, conn.cursor() as cur:
            # run_scan writes its own 'scan.completed' as the engine; this row records who asked.
            _audit(cur, actor, "scan.requested", stats["scan_id"],
                   {"type": req.type, "name": name, "mode": "inline", "stats": stats})
            conn.commit()
        return {"scan_id": stats["scan_id"], "mode": "inline", "status": "done", "stats": stats}

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            # Secret fields go to Vault with the connection row; the QUEUE payload carries the
            # public config only — pgmq (and its archive) is a table, and a job that carried a
            # password would persist it forever. The worker's run_scan resolves creds_ref.
            connection_id, public_config, _ref = ensure_connection_with_creds(
                cur, tenant, req.type, name, req.config)
            scan_id, msg_id = _enqueue_scan(cur, tenant, connection_id, req.type,
                                            public_config, name, p.actor)
            _audit(cur, actor, "scan.requested", scan_id,
                   {"type": req.type, "name": name, "mode": "queued", "msg_id": msg_id})
        conn.commit()

    return {"scan_id": scan_id, "mode": "queued", "status": "queued",
            "msg_id": msg_id, "connection_id": str(connection_id)}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: uuid.UUID, p: Principal = Depends(principal)) -> dict:
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """select s.status, s.started_at, s.finished_at, s.stats, c.type, c.name
               from scans s left join connections c on c.id = s.connection_id
               where s.tenant_id = %s and s.id = %s""",
            (p.tenant_id, str(scan_id)),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "no such scan")
    return {"scan_id": str(scan_id), "status": row[0], "started_at": row[1], "finished_at": row[2],
            "stats": row[3], "connection": {"type": row[4], "name": row[5]}}


# ── Connections ───────────────────────────────────────────────────────────
# The console's connect-and-scan surface. Reads of the connections LIST stay in the console
# (PostgREST + RLS, config never selected); everything here changes state or starts work, so
# it lives behind an authenticated actor + audit row like every other action.

@app.get("/connectors")
def connectors(p: Principal = Depends(principal)) -> dict:
    """The connector catalogue: what can be connected and what a human must supply to
    connect it. Driven by the registry, so a dropped-in connector file shows up here — and
    in the console's form — with no list to edit. `rules` counts the detectors whose
    rule_id prefix belongs to the type, because "20 checks" is what the form's picker says."""
    out = []
    for type_ in sorted(CONNECTORS):
        rules = sum(1 for d in DETECTORS if d.rule_id.split(".")[0].lower() == type_)
        out.append({
            "type": type_,
            "rules": rules,
            "fields": [f.to_dict() for f in CONNECTOR_FIELDS.get(type_, [])],
        })
    return {"connectors": out}


class ConnectionRequest(BaseModel):
    type: str
    name: str = Field(min_length=1)
    config: dict = Field(default_factory=dict)
    mode: Literal["cloud", "collector"] = "cloud"

    @field_validator("name")
    @classmethod
    def _name_trimmed(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        return v


@app.post("/connections", status_code=201)
def create_connection(req: ConnectionRequest, p: Principal = Depends(editing)) -> dict:
    """Create (or update the config of) a connection without scanning it.

    Validation happens HERE, at the moment a human is looking at a form, not later inside a
    queued job nobody is watching. Declared-secret fields are split out of the config and
    stored in Supabase Vault (creds_ref); connections.config keeps metadata only. The audit
    row records config KEYS only — config values carry credentials and must never enter the
    append-only log."""
    problems = validate_config(req.type, req.config)
    if problems:
        raise HTTPException(400, "; ".join(problems))

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select id from connections where tenant_id=%s and type=%s and name=%s",
                (p.tenant_id, req.type, req.name),
            )
            existed = cur.fetchone() is not None
            connection_id, public_config, _ref = ensure_connection_with_creds(
                cur, p.tenant_id, req.type, req.name, req.config, mode=req.mode)
            _audit(cur, p, "connection.updated" if existed else "connection.created",
                   str(connection_id),
                   {"type": req.type, "name": req.name, "mode": req.mode,
                    "config_keys": sorted(req.config),
                    "secret_keys_vaulted": sorted(set(req.config) - set(public_config))})
        conn.commit()

    return {"connection_id": str(connection_id), "type": req.type, "name": req.name,
            "created": not existed}


@app.post("/connections/{connection_id}/test")
def test_connection(connection_id: uuid.UUID, p: Principal = Depends(editing)) -> dict:
    """Run the connector's collect against the stored config and report what came back.

    Read-only against the target, same code path a real scan uses — so "test passed" means
    the scan will actually work, not that a TCP port answered. Persists nothing from the
    collect; only connections.status is updated so the console can show reachability. 200
    either way: the test *ran*; `ok` says what it found."""
    from ..creds import resolve_secrets, runtime_config

    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "select type, name, config, creds_ref from connections where id=%s and tenant_id=%s",
            (str(connection_id), p.tenant_id),
        )
        row = cur.fetchone()
        # Vaulted credentials are resolved HERE, into this request's memory only — the merged
        # config is handed to the connector and never persisted or echoed anywhere.
        config = runtime_config(row[2] or {}, resolve_secrets(cur, row[3])) if row else {}
    if not row:
        raise HTTPException(404, "no such connection")
    type_, name = row[0], row[1]
    if type_ not in CONNECTORS:
        raise HTTPException(400, f"no connector loaded for type {type_!r}")

    # SystemExit included: connectors raise it for config errors (their CLI heritage), and
    # it is not an Exception — uncaught it would take the request handler down with it.
    try:
        collected = CONNECTORS[type_](config)
        kinds: dict[str, int] = {}
        for r in collected.resources:
            kinds[r.kind] = kinds.get(r.kind, 0) + 1
        result = {"ok": True, "resources": len(collected.resources), "kinds": kinds}
        status = "active"
    except (Exception, SystemExit) as e:
        result = {"ok": False, "error": safe_error(e)}
        status = "error"

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("update connections set status=%s where id=%s and tenant_id=%s",
                        (status, str(connection_id), p.tenant_id))
            _audit(cur, p, "connection.tested", str(connection_id),
                   {"type": type_, "name": name, **result})
        conn.commit()

    return {"connection_id": str(connection_id), "type": type_, "name": name, **result}


@app.post("/connections/{connection_id}/scan", status_code=202)
def scan_connection(connection_id: uuid.UUID, p: Principal = Depends(editing)) -> dict:
    """Queue a scan of an EXISTING connection from its stored config.

    This is the console's "Scan now": the browser sends only the connection id it can
    already see under RLS — the config, credentials included, never round-trips through
    the client. Cloud connections go onto pgmq for `vectasec worker`; collector
    connections only get the queued scans row, which the enrolled collector claims via
    GET /collector/jobs (pushing them onto pgmq would hand a cloud worker a job whose
    target it cannot reach and whose credentials it does not have)."""
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select type, name, config, mode from connections where id=%s and tenant_id=%s",
                (str(connection_id), p.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such connection")
            type_, name, config, mode = row[0], row[1], row[2] or {}, row[3]
            if type_ not in CONNECTORS:
                raise HTTPException(400, f"no connector loaded for type {type_!r}")

            if mode == "collector":
                cur.execute(
                    """insert into scans (tenant_id, connection_id, status)
                       values (%s,%s,'queued') returning id""",
                    (p.tenant_id, str(connection_id)),
                )
                scan_id, msg_id = str(cur.fetchone()[0]), None
            else:
                scan_id, msg_id = _enqueue_scan(cur, p.tenant_id, str(connection_id),
                                                type_, config, name, p.actor)
            _audit(cur, p, "scan.requested", scan_id,
                   {"type": type_, "name": name, "mode": mode, "msg_id": msg_id,
                    "via": "connection"})
        conn.commit()

    return {"scan_id": scan_id, "connection_id": str(connection_id), "status": "queued",
            "mode": mode, "msg_id": msg_id}


@app.delete("/connections/{connection_id}")
def delete_connection(connection_id: uuid.UUID, p: Principal = Depends(editing)) -> dict:
    """Remove a connection and everything collected through it.

    The cascade is the schema's: resources (and their edges, findings, observations) go
    with the connection; scans rows survive with connection_id nulled — scan history is
    an audit artefact and outlives the thing scanned. The audit row records the counts
    BEFORE the delete so what was removed is on the record."""
    from ..creds import delete_secret

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select type, name, creds_ref from connections where id=%s and tenant_id=%s",
                (str(connection_id), p.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such connection")
            type_, name, creds_ref = row

            cur.execute("select count(*) from resources where connection_id=%s", (str(connection_id),))
            n_resources = cur.fetchone()[0]
            cur.execute(
                """select count(*) from findings f
                   join resources r on r.id = f.resource_id
                   where r.connection_id = %s""",
                (str(connection_id),),
            )
            n_findings = cur.fetchone()[0]

            _audit(cur, p, "connection.deleted", str(connection_id),
                   {"type": type_, "name": name, "resources": n_resources,
                    "findings": n_findings, "creds_vaulted": creds_ref is not None})
            cur.execute("delete from connections where id=%s and tenant_id=%s",
                        (str(connection_id), p.tenant_id))
            # The Vault secret goes with its connection — an orphaned credential is pure risk.
            delete_secret(cur, creds_ref)
        conn.commit()

    return {"deleted": True, "connection_id": str(connection_id), "type": type_,
            "name": name, "resources": n_resources, "findings": n_findings}


class ConnectionPatch(BaseModel):
    # None is meaningful (unschedule), so "was the field sent at all" is model_fields_set.
    scan_interval_minutes: Optional[int] = None

    @field_validator("scan_interval_minutes")
    @classmethod
    def _interval_sane(cls, v: Optional[int]) -> Optional[int]:
        # 5 minutes to 7 days — below 5 the scheduler would queue faster than most scans
        # finish; the DB check constraint only enforces > 0, so the real floor lives here.
        if v is not None and not (5 <= v <= 10080):
            raise ValueError("scan_interval_minutes must be null (unscheduled) or 5..10080")
        return v


@app.patch("/connections/{connection_id}")
def patch_connection(connection_id: uuid.UUID, req: ConnectionPatch,
                     p: Principal = Depends(editing)) -> dict:
    """Update a connection's schedule knob (20260723000001: queue_due_scans() consumes it).

    scan_interval_minutes: null turns the schedule off; 5..10080 sets the cadence in minutes.
    Deliberately narrow — config/credential changes go through POST /connections, which owns
    the Vault split."""
    if "scan_interval_minutes" not in req.model_fields_set:
        raise HTTPException(400, "nothing to update: pass scan_interval_minutes (int or null)")

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """select type, name, scan_interval_minutes from connections
                   where id = %s and tenant_id = %s for update""",
                (str(connection_id), p.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such connection")
            type_, name, previous = row
            cur.execute(
                "update connections set scan_interval_minutes = %s where id = %s and tenant_id = %s",
                (req.scan_interval_minutes, str(connection_id), p.tenant_id),
            )
            _audit(cur, p, "connection.updated", str(connection_id),
                   {"type": type_, "name": name,
                    "scan_interval_minutes": {"from": previous, "to": req.scan_interval_minutes}})
        conn.commit()

    return {"connection_id": str(connection_id), "type": type_, "name": name,
            "scan_interval_minutes": req.scan_interval_minutes, "previous": previous}


# ── Findings workflow ─────────────────────────────────────────────────────
# 'suppressed' is deliberately not settable here: a suppression carries a reason and an
# expiry and is applied by the scan loop, so it goes through POST /suppressions. Letting it
# be set as a plain status would create exceptions nobody can audit or expire.
FindingStatus = Literal["open", "triaged", "in_progress", "resolved", "accepted"]


class StatusRequest(BaseModel):
    status: FindingStatus
    note: str = ""


@app.post("/findings/{finding_id}/status")
def set_status(finding_id: uuid.UUID, req: StatusRequest, p: Principal = Depends(editing)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            # Locked: two analysts triaging the same finding must not interleave into an audit
            # trail that records a transition that never happened.
            cur.execute(
                "select status from findings where tenant_id = %s and id = %s for update",
                (p.tenant_id, str(finding_id)),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such finding")
            previous = row[0]

            cur.execute(
                "update findings set status = %s where tenant_id = %s and id = %s",
                (req.status, p.tenant_id, str(finding_id)),
            )
            # The note lives only here. It explains a state *change*, so it belongs in the
            # append-only trail — a column on findings would be overwritten by the next change.
            _audit(cur, p, "finding.status", str(finding_id),
                   {"from": previous, "to": req.status, "note": req.note})
        conn.commit()
    return {"finding_id": str(finding_id), "status": req.status, "previous": previous}


class AssignRequest(BaseModel):
    assignee: Optional[uuid.UUID] = None   # null unassigns


@app.post("/findings/{finding_id}/assign")
def assign(finding_id: uuid.UUID, req: AssignRequest, p: Principal = Depends(editing)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select assignee from findings where tenant_id = %s and id = %s for update",
                (p.tenant_id, str(finding_id)),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such finding")
            previous = row[0]

            cur.execute(
                "update findings set assignee = %s where tenant_id = %s and id = %s",
                (req.assignee, p.tenant_id, str(finding_id)),
            )
            _audit(cur, p, "finding.assigned", str(finding_id),
                   {"from": previous, "to": req.assignee})
        conn.commit()
    return {"finding_id": str(finding_id), "assignee": req.assignee, "previous": previous}


@app.post("/findings/{finding_id}/triage")
def triage(finding_id: uuid.UUID, force: bool = Query(False, description="bypass the fingerprint cache"),
           p: Principal = Depends(editing)) -> dict:
    """Grounded AI triage. The citations ARE the product: every claim in `triage` is backed by
    an observation returned in `citations`, quoted exactly as it was read from the target."""
    from ..ai import triage_finding

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("select 1 from findings where tenant_id = %s and id = %s",
                        (p.tenant_id, str(finding_id)))
            if not cur.fetchone():
                raise HTTPException(404, "no such finding")

            # The caller owns the transaction (ai.triage_finding's contract): the ai_output and
            # its evidence links must commit together or the citation gate cannot do its job.
            t = triage_finding(cur, p.tenant_id, str(finding_id), force=force)
            if t is None:
                # The finding exists but has no observations. A finding with no evidence is a
                # rumour, and the AI layer will not speak about it — say so rather than invent.
                raise HTTPException(422, "finding has no observations; nothing to ground a triage on")

            cur.execute(
                """select id, claim, source_ref, observed_at from observations
                   where tenant_id = %s and id = any(%s) order by observed_at""",
                (p.tenant_id, list(t.cited_observation_ids)),
            )
            citations = [{"observation_id": str(r[0]), "claim": r[1], "source_ref": r[2],
                          "observed_at": r[3]} for r in cur.fetchall()]

            _audit(cur, p, "finding.triaged", str(finding_id),
                   {"model": t.model, "priority": t.priority, "grounded": t.grounded,
                    "model_priority": getattr(t, "model_priority", None),
                    "priority_floor_applied": getattr(t, "priority_floor_applied", False),
                    "citations": len(citations), "forced": force})

        # The citation gate is a DEFERRED constraint trigger: an ai_output with no linked
        # observation fails at COMMIT, not at INSERT. This is where ungrounded output dies, so
        # the failure is reported rather than swallowed into a half-written triage.
        try:
            conn.commit()
        except psycopg.errors.DatabaseError as e:
            raise HTTPException(500, f"triage rejected by the database: {e}") from e

    return {
        "finding_id": str(finding_id),
        "triage": {"summary": t.summary, "business_risk": t.business_risk,
                   "exploitability": t.exploitability, "priority": t.priority,
                   "confidence": t.confidence,
                   # Provenance for decision 2: when the model's priority was raised to the rule's
                   # severity floor, the console shows it honestly rather than passing off the
                   # clamped value as the model's own judgement.
                   "model_priority": getattr(t, "model_priority", None),
                   "priority_floor_applied": getattr(t, "priority_floor_applied", False)},
        "model": t.model,
        "grounded": t.grounded,
        "citations": citations,
    }


# ── Suppressions ──────────────────────────────────────────────────────────
# What the scan loop actually understands (scan._is_suppressed): {} is tenant-wide, otherwise
# ext_id or kind. Anything else is rejected — an unknown key would match nothing and quietly
# produce a suppression the user believes is in force.
SCOPE_KEYS = {"ext_id", "kind"}


class SuppressionRequest(BaseModel):
    rule_id: str = Field(min_length=1)
    scope: dict = Field(default_factory=dict)
    reason: str
    expires_at: Optional[datetime] = None

    @field_validator("reason")
    @classmethod
    def _reason_required(cls, v: str) -> str:
        # An exception without a stated reason is not an exception, it is a hole in the scan
        # that no one can review later. min_length would have accepted "   ".
        if not v.strip():
            raise ValueError("reason is required: a suppression nobody explained cannot be reviewed")
        return v.strip()

    @field_validator("scope")
    @classmethod
    def _known_scope(cls, v: dict) -> dict:
        unknown = set(v) - SCOPE_KEYS
        if unknown:
            raise ValueError(f"unsupported scope keys {sorted(unknown)}; the scanner matches on "
                             f"{sorted(SCOPE_KEYS)} (or {{}} for tenant-wide)")
        return v


@app.post("/suppressions", status_code=201)
def create_suppression(req: SuppressionRequest, p: Principal = Depends(editing)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            # created_by is a uuid column but the actor header may be an email or a service
            # name; the audit row below records the actor verbatim either way.
            try:
                created_by = str(uuid.UUID(p.actor))
            except ValueError:
                created_by = None

            cur.execute(
                """insert into suppressions (tenant_id, rule_id, scope, reason, expires_at, created_by)
                   values (%s,%s,%s,%s,%s,%s) returning id, created_at""",
                (p.tenant_id, req.rule_id, json.dumps(req.scope), req.reason,
                 req.expires_at, created_by),
            )
            sid, created_at = cur.fetchone()
            _audit(cur, p, "suppression.created", str(sid),
                   {"rule_id": req.rule_id, "scope": req.scope, "reason": req.reason,
                    "expires_at": req.expires_at})
        conn.commit()

    return {
        "id": str(sid), "rule_id": req.rule_id, "scope": req.scope, "reason": req.reason,
        "expires_at": req.expires_at, "created_at": created_at,
        # Honest about when this bites: the scan loop applies suppressions, so findings that are
        # already open keep their status until the next scan re-evaluates them.
        "applies_at_next_scan": True,
    }


# ── Compliance ────────────────────────────────────────────────────────────
@app.get("/compliance/{framework}")
def compliance(framework: str, p: Principal = Depends(principal)) -> dict:
    """Controls + status for one framework.

    An unknown framework returns an empty list rather than 404: until the mapping module seeds
    and evaluates the catalogue, "framework we don't map" and "not evaluated yet" are the same
    row-count from here, and inventing a 404 would assert a distinction we cannot make.
    """
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """select control_id, title, requirement, status, failing_finding_ids,
                      unknown_finding_ids, evaluated_at
               from controls where tenant_id = %s and framework = %s order by control_id""",
            (p.tenant_id, framework),
        )
        rows = cur.fetchall()

    controls = [{"control_id": r[0], "title": r[1], "requirement": r[2], "status": r[3],
                 "failing_finding_ids": r[4] or [], "failing": len(r[4] or []),
                 # not_assessable findings that map here — a coverage gap, surfaced separately so a
                 # buyer can see "we could not check" distinct from "we checked and it failed".
                 "unknown_finding_ids": r[5] or [], "unknown": len(r[5] or []),
                 "evaluated_at": r[6]} for r in rows]
    summary: dict[str, int] = {}
    for c in controls:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    return {"framework": framework, "count": len(controls), "summary": summary, "controls": controls}


class AttestRequest(BaseModel):
    scope: str = Field(min_length=1)     # what was attested, over which systems/period — required
    note: Optional[str] = None
    expires_at: Optional[datetime] = None

    @field_validator("scope")
    @classmethod
    def _scope_required(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("attestation requires a scope: what was attested, and over what")
        return v.strip()


@app.post("/compliance/{framework}/{control_id}/attest", status_code=201)
def attest_control(framework: str, control_id: str, req: AttestRequest,
                   p: Principal = Depends(editing)) -> dict:
    """A human signs that a control is met. This is the ONLY path to a compliance `pass`, and a
    live assessed failing finding still overrides it (compliance.map: fail beats attestation). The
    attestation, the recomputed controls, and the audit row all land in one transaction."""
    from ..compliance import map as compliance

    try:
        created_by = str(uuid.UUID(p.actor))   # attested_by is a uuid (auth.users id)
    except ValueError:
        raise HTTPException(400, "attestation actor must be a user uuid (sign in as a real user)")

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            try:
                result = compliance.attest(
                    cur, p.tenant_id, framework, control_id, created_by, req.scope,
                    note=req.note, expires_at=req.expires_at,
                )
            except ValueError as e:
                raise HTTPException(400, str(e)) from e
            _audit(cur, p, "compliance.attested", f"{framework}:{control_id}",
                   {"scope": req.scope, "note": req.note, "expires_at": req.expires_at,
                    "resulting_status": result.get("status")})
        conn.commit()
    return result


# ── Reporting / evidence export ────────────────────────────────────────────
# The generation core is report.py (pure, deterministic, no clock); these endpoints load the
# tenant's findings + controls + posture and hand them off. Read-only: any tenant member can
# export the data they can already see. generated_at is stamped here (the API layer owns the clock).
# Reports are viewer-tier and read whole tables. Unbounded, one caller loops them and pulls the
# entire estate into engine memory per request. The cap is generous enough that a real report is
# never silently truncated in practice, and truncation is REPORTED rather than hidden — a
# security report that quietly drops findings is worse than one that refuses.
REPORT_MAX_FINDINGS = 20000
REPORT_MAX_CONTROLS = 5000


def _load_report_data(cur, tenant_id: str):
    from .. import report
    cur.execute(
        """select f.rule_id, f.severity, f.status, f.title, f.remediation, f.detail,
                  f.first_seen, r.name, c.type
             from findings f
             left join resources r on r.id = f.resource_id
             left join connections c on c.id = r.connection_id
            where f.tenant_id = %s
            order by f.severity, f.rule_id
            limit %s""",
        (tenant_id, REPORT_MAX_FINDINGS + 1),
    )
    findings = [
        {"rule_id": row[0], "severity": row[1], "status": row[2], "title": row[3],
         "remediation": row[4] or "", "observation": row[5] or "", "detail": row[5] or "",
         "first_seen": row[6].isoformat() if row[6] else "",
         "resource": row[7] or "", "system": row[8] or "", "connector": row[8] or ""}
        for row in cur.fetchall()
    ]
    if len(findings) > REPORT_MAX_FINDINGS:
        findings = findings[:REPORT_MAX_FINDINGS]
        raise HTTPException(
            413, f"this tenant has more than {REPORT_MAX_FINDINGS} findings, which is more than "
                 "one report can carry. Narrow the scope (per-connection export) rather than "
                 "receiving a silently truncated document.")
    cur.execute(
        """select framework, control_id, title, requirement, status
             from controls where tenant_id = %s order by framework, control_id
             limit %s""",
        (tenant_id, REPORT_MAX_CONTROLS),
    )
    controls = [{"framework": row[0], "control_id": row[1], "title": row[2],
                 "requirement": row[3], "status": row[4]} for row in cur.fetchall()]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f["status"] == "open" and f["severity"] in counts:
            counts[f["severity"]] += 1
    posture = report.posture_from_counts(counts)
    posture["counts"] = counts
    cur.execute("select name from tenants where id = %s", (tenant_id,))
    trow = cur.fetchone()
    tenant_name = trow[0] if trow else "VectaSec tenant"
    return findings, controls, posture, tenant_name


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@app.get("/reports/oscal")
def report_oscal(p: Principal = Depends(principal)) -> dict:
    """OSCAL 1.1 Assessment Results for the tenant (JSON)."""
    from .. import report
    with _db() as conn, conn.cursor() as cur:
        findings, controls, posture, tenant_name = _load_report_data(cur, p.tenant_id)
    return report.to_oscal_assessment_results(
        findings, controls, posture, tenant_name=tenant_name, generated_at=_now_iso())


@app.get("/reports/csv")
def report_csv(p: Principal = Depends(principal)) -> Response:
    """All findings as a CSV download."""
    from .. import report
    with _db() as conn, conn.cursor() as cur:
        findings, _c, _po, _tn = _load_report_data(cur, p.tenant_id)
    return Response(
        content=report.to_findings_csv(findings), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="vectasec-findings.csv"'})


@app.get("/reports/summary")
def report_summary(p: Principal = Depends(principal)) -> Response:
    """Executive summary report (Markdown download)."""
    from .. import report
    with _db() as conn, conn.cursor() as cur:
        findings, controls, posture, tenant_name = _load_report_data(cur, p.tenant_id)
    md = report.to_executive_summary_markdown(
        findings, controls, posture, tenant_name=tenant_name, generated_at=_now_iso())
    return Response(
        content=md, media_type="text/markdown",
        headers={"Content-Disposition": 'attachment; filename="vectasec-report.md"'})


@app.get("/reports/sbom")
def report_sbom(p: Principal = Depends(principal)) -> Response:
    """CycloneDX 1.6 SBOM of the running estate.

    Unlike a build SBOM this is read from the systems themselves, which is why the lifecycle
    phase matters: `operations` when every component's version came from a connector that
    authenticated, `discovery` when any of it came from an unauthenticated network sweep. We
    report the weaker of the two rather than the flattering one — a document that claims
    `operations` over probe-derived data misrepresents how it was obtained.
    """
    from .. import sbom
    with _db() as conn, conn.cursor() as cur:
        cur.execute("select name from tenants where id = %s", (p.tenant_id,))
        row = cur.fetchone()
        tenant_name = row[0] if row else "estate"
        cur.execute(
            # Select ONLY the raw keys the SBOM reads. `r.raw` is a full jsonb blob per
            # resource — probe banners, signals, config echoes — and pulling the whole estate's
            # worth into Python to extract a version string is both a memory problem and an
            # unnecessary handling of data the document never contains.
            """select r.kind, r.name, r.ext_id, r.labels,
                      jsonb_build_object(
                        'product', r.raw->'product', 'version', r.raw->'version',
                        'version_inferred', r.raw->'version_inferred',
                        'redis_version', r.raw->'redis_version',
                        'rabbitmq_version', r.raw->'rabbitmq_version',
                        'broker_version', r.raw->'broker_version',
                        'kafka_version', r.raw->'kafka_version',
                        'etcdserver', r.raw->'etcdserver',
                        'host', r.raw->'host', 'port', r.raw->'port',
                        'transport', r.raw->'transport') as raw,
                      c.type, r.connection_id
                 from resources r join connections c on c.id = r.connection_id
                where r.tenant_id = %s and coalesce(r.stale, false) = false
                limit %s""",
            (p.tenant_id, REPORT_MAX_FINDINGS),
        )
        rows = cur.fetchall()
        cur.execute(
            "select id::text from scans where tenant_id = %s and status = 'done'",
            (p.tenant_id,),
        )
        scan_ids = [s[0] for s in cur.fetchall()]

    resources = [{"kind": k, "name": n, "ext_id": e, "labels": lab, "raw": raw,
                  "connection_type": t} for k, n, e, lab, raw, t, _cid in rows]
    # Any probe-derived component downgrades the whole document to `discovery`.
    authenticated = not any(r["kind"] == "discovered_service" for r in resources)

    doc = sbom.to_cyclonedx(
        resources, tenant_name=tenant_name, tenant_id=str(p.tenant_id),
        scan_ids=scan_ids, timestamp=_now_iso(), authenticated=authenticated)
    return Response(
        content=json.dumps(doc, indent=2),
        media_type="application/vnd.cyclonedx+json; version=1.6",
        headers={"Content-Disposition": 'attachment; filename="vectasec-sbom.cdx.json"'})


# ── Graph ─────────────────────────────────────────────────────────────────
@app.get("/graph/blast-radius/{resource_id}")
def blast_radius(resource_id: uuid.UUID, depth: int = Query(4, ge=1, le=10),
                 directed: bool = Query(False, description="follow edges src→dst only"),
                 p: Principal = Depends(principal)) -> dict:
    """What a compromise of this resource reaches. Undirected by default: a broker→topic 'hosts'
    edge means an attacker on either end learns the other, so posture reachability is symmetric.

    The walk is graph.blast_radius (ONE implementation, per-path cycle guard + depth bound) — this
    endpoint used to reimplement it inline with only a depth guard, which on a cyclic estate
    (broker → topic → mirror → broker) reported the root as its own blast radius. This layer only
    enriches the walk's nodes with their open findings and the edges between them.
    """
    from ..graph import blast_radius as walk

    with _db() as conn, conn.cursor() as cur:
        result = walk(cur, p.tenant_id, str(resource_id), max_depth=depth, directed=directed)
        if not result["found"]:
            raise HTTPException(404, "no such resource")

        ids = [n["id"] for n in result["nodes"]]

        per_resource: dict = {}
        totals: dict[str, int] = {}
        edges: list = []
        if ids:
            # Open findings only: a resolved or suppressed finding is not blast radius.
            cur.execute(
                """select resource_id::text, severity, count(*) from findings
                   where tenant_id = %s and resource_id = any(%s)
                     and status not in ('resolved','suppressed')
                   group by resource_id, severity""",
                (p.tenant_id, ids),
            )
            for rid, sev, n in cur.fetchall():
                per_resource.setdefault(rid, {})[sev] = n
                totals[sev] = totals.get(sev, 0) + n

            cur.execute(
                """select src_resource_id::text, dst_resource_id::text, kind from edges
                   where tenant_id = %s and src_resource_id = any(%s) and dst_resource_id = any(%s)""",
                (p.tenant_id, ids, ids),
            )
            edges = [{"src": a, "dst": b, "kind": k} for a, b, k in cur.fetchall()]

    root = result["root"]
    nodes = [{"resource_id": n["id"], "kind": n["kind"], "name": n["name"], "ext_id": n["ext_id"],
              "stale": n["stale"], "depth": n["depth"], "path": n["path"],
              "via_edge_kind": n["via_edge_kind"], "findings": per_resource.get(n["id"], {})}
             for n in result["nodes"]]
    return {
        "root": {"resource_id": root["id"], "kind": root["kind"], "name": root["name"],
                 "ext_id": root["ext_id"], "findings": per_resource.get(root["id"], {})},
        "max_depth": result["max_depth"],
        "directed": result["directed"],
        # The frontier was still expanding when the depth bound stopped it: the blast radius is at
        # least this, and the console must not present it as complete.
        "depth_bounded": result["depth_bounded"],
        "nodes": nodes,          # reachable set, EXCLUDING the root (root is reported separately)
        "edges": edges,
        "totals": {"resources": len(nodes), "findings_by_severity": totals},
    }


# ── Integrations (the action layer's destinations) ──────────────────────────
# Admin surface: who we notify is a tenant-governance decision, like who is a member.
# Secret-shaped config fields (webhook/Slack/SIEM URLs, Jira tokens, HMAC secrets) never land
# in integrations.config — notify.split_integration_config sends them to Vault, exactly as
# connection credentials are handled, and audit rows record config KEYS only.

class IntegrationRequest(BaseModel):
    type: str
    name: str = Field(min_length=1)
    config: dict = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name_trimmed(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name is required")
        return v


@app.get("/integrations")
def list_integrations(p: Principal = Depends(principal)) -> dict:
    """The tenant's destinations, public config only. `has_credentials` says a Vault secret
    exists without saying what is in it; `secret_keys` is the TYPE's declared secret fields so
    the console knows which form inputs to render as passwords."""
    from ..notify import INTEGRATION_SECRET_KEYS

    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """select id::text, type, name, config, enabled, created_at, creds_ref is not null
               from integrations where tenant_id = %s order by created_at""",
            (p.tenant_id,),
        )
        rows = cur.fetchall()
    return {"integrations": [
        {"id": r[0], "type": r[1], "name": r[2], "config": r[3] or {}, "enabled": r[4],
         "created_at": r[5], "has_credentials": r[6],
         "secret_keys": list(INTEGRATION_SECRET_KEYS.get(r[1], ()))}
        for r in rows]}


@app.post("/integrations", status_code=201)
def upsert_integration(req: IntegrationRequest, p: Principal = Depends(admin)) -> dict:
    """Create (or update, matched on tenant+type+name) a destination. On update, absent/empty
    secret fields mean "unchanged" — the stored Vault secret is merged over, so re-saving a
    Slack integration does not require re-pasting the webhook URL."""
    from ..notify import (split_integration_config, store_integration_secrets,
                          validate_integration_config)
    from ..creds import resolve_secrets

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select id::text, creds_ref from integrations where tenant_id=%s and type=%s and name=%s",
                (p.tenant_id, req.type, req.name),
            )
            row = cur.fetchone()
            existing_id, existing_ref = (row[0], row[1]) if row else (None, None)

            stored_keys = tuple(resolve_secrets(cur, existing_ref)) if existing_ref else ()
            problems = validate_integration_config(req.type, req.config, stored_keys)
            if problems:
                raise HTTPException(400, "; ".join(problems))

            public, secrets = split_integration_config(req.type, req.config)
            if existing_id:
                cur.execute(
                    "update integrations set config=%s, enabled=%s where id=%s",
                    (json.dumps(public), req.enabled, existing_id),
                )
                integration_id = existing_id
            else:
                cur.execute(
                    """insert into integrations (tenant_id, type, name, config, enabled)
                       values (%s,%s,%s,%s,%s) returning id::text""",
                    (p.tenant_id, req.type, req.name, json.dumps(public), req.enabled),
                )
                integration_id = cur.fetchone()[0]

            if secrets:
                ref = store_integration_secrets(cur, integration_id, secrets, existing_ref)
                if ref != existing_ref:
                    cur.execute("update integrations set creds_ref=%s where id=%s",
                                (ref, integration_id))

            _audit(cur, p, "integration.updated" if existing_id else "integration.created",
                   integration_id,
                   {"type": req.type, "name": req.name, "enabled": req.enabled,
                    "config_keys": sorted(public), "secret_keys_vaulted": sorted(secrets)})
        conn.commit()

    return {"integration_id": integration_id, "type": req.type, "name": req.name,
            "created": existing_id is None}


@app.delete("/integrations/{integration_id}")
def delete_integration(integration_id: uuid.UUID, p: Principal = Depends(admin)) -> dict:
    """Remove a destination. Its routing rules cascade with it (FK), and the Vault secret goes
    in the same transaction — an orphaned webhook URL is a live credential nobody owns."""
    from ..creds import delete_secret

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select type, name, creds_ref from integrations where id=%s and tenant_id=%s",
                (str(integration_id), p.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such integration")
            type_, name, creds_ref = row
            cur.execute("select count(*) from routing_rules where integration_id=%s",
                        (str(integration_id),))
            n_rules = cur.fetchone()[0]
            _audit(cur, p, "integration.deleted", str(integration_id),
                   {"type": type_, "name": name, "routing_rules": n_rules,
                    "creds_vaulted": creds_ref is not None})
            cur.execute("delete from integrations where id=%s and tenant_id=%s",
                        (str(integration_id), p.tenant_id))
            delete_secret(cur, creds_ref)
        conn.commit()

    return {"deleted": True, "integration_id": str(integration_id), "type": type_,
            "name": name, "routing_rules_removed": n_rules}


@app.post("/integrations/{integration_id}/test")
def test_integration(integration_id: uuid.UUID, p: Principal = Depends(admin)) -> dict:
    """Send a real test message through the stored destination — the same sender a scan would
    use, so "test passed" means notifications will actually arrive. 200 either way; `ok` says
    what happened, and the attempt lands in notification_deliveries like any delivery."""
    from ..creds import resolve_secrets, runtime_config
    from ..notify import deliver

    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "select type, name, config, creds_ref from integrations where id=%s and tenant_id=%s",
            (str(integration_id), p.tenant_id),
        )
        row = cur.fetchone()
        # Merged in this request's memory only, exactly like connection credentials.
        merged = runtime_config(row[2] or {}, resolve_secrets(cur, row[3])) if row else {}
    if not row:
        raise HTTPException(404, "no such integration")
    type_, name = row[0], row[1]

    event = {
        "kind": "test", "tenant_id": p.tenant_id, "scan_id": None,
        "connection": {"type": "vectasec", "name": "test"},
        "findings": [{
            "id": "00000000-0000-0000-0000-000000000000",
            "rule_id": "VECTASEC.TEST", "title": "Test notification from VectaSec",
            "severity": "info", "detail": "If you can read this, the integration works.",
            "resource_name": "test", "resource_kind": "test", "resource_ext_id": "test",
        }],
        "error": None,
    }
    try:
        deliver(type_, merged, event)
        result: dict = {"ok": True}
    except Exception as e:
        result = {"ok": False, "error": safe_error(e)}

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """insert into notification_deliveries
                     (tenant_id, integration_id, event, findings_count, status, error)
                   values (%s,%s,'test',1,%s,%s)""",
                (p.tenant_id, str(integration_id),
                 "sent" if result["ok"] else "error", result.get("error")),
            )
            _audit(cur, p, "integration.tested", str(integration_id),
                   {"type": type_, "name": name, **result})
        conn.commit()

    return {"integration_id": str(integration_id), "type": type_, "name": name, **result}


# ── Routing rules (which findings go to which destination) ───────────────────
ROUTING_MATCH_KEYS = {"min_severity", "connector_types", "rule_prefixes", "notify_on"}
_SEVERITIES = ("info", "low", "medium", "high", "critical")


class RoutingRuleRequest(BaseModel):
    integration_id: uuid.UUID
    match: dict = Field(default_factory=dict)     # {} routes everything
    name: Optional[str] = None
    enabled: bool = True

    @field_validator("match")
    @classmethod
    def _known_match(cls, v: dict) -> dict:
        unknown = set(v) - ROUTING_MATCH_KEYS
        if unknown:
            raise ValueError(f"unsupported match keys {sorted(unknown)}; the router evaluates "
                             f"{sorted(ROUTING_MATCH_KEYS)} (or {{}} to route everything)")
        sev = v.get("min_severity")
        if sev is not None and sev not in _SEVERITIES:
            raise ValueError(f"min_severity must be one of {_SEVERITIES}")
        for key in ("connector_types", "rule_prefixes", "notify_on"):
            if key in v and not (isinstance(v[key], list)
                                 and all(isinstance(x, str) for x in v[key])):
                raise ValueError(f"{key} must be a list of strings")
        bad = set(v.get("notify_on") or []) - {"new_findings", "scan_failed"}
        if bad:
            raise ValueError(f"notify_on entries {sorted(bad)} unknown; "
                             "use new_findings and/or scan_failed")
        return v


@app.get("/routing-rules")
def list_routing_rules(p: Principal = Depends(principal)) -> dict:
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """select r.id::text, r.name, r.match, r.enabled, r.created_at,
                      r.integration_id::text, i.type, i.name
               from routing_rules r left join integrations i on i.id = r.integration_id
               where r.tenant_id = %s order by r.created_at""",
            (p.tenant_id,),
        )
        rows = cur.fetchall()
    return {"routing_rules": [
        {"id": r[0], "name": r[1], "match": r[2] or {}, "enabled": r[3], "created_at": r[4],
         "integration": {"id": r[5], "type": r[6], "name": r[7]}}
        for r in rows]}


@app.post("/routing-rules", status_code=201)
def create_routing_rule(req: RoutingRuleRequest, p: Principal = Depends(admin)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            # The destination must be THIS tenant's — a rule pointing at another tenant's
            # integration would exfiltrate findings across the boundary.
            cur.execute("select type, name from integrations where id=%s and tenant_id=%s",
                        (str(req.integration_id), p.tenant_id))
            dest = cur.fetchone()
            if not dest:
                raise HTTPException(404, "no such integration for this tenant")
            cur.execute(
                """insert into routing_rules (tenant_id, integration_id, match, name, enabled)
                   values (%s,%s,%s,%s,%s) returning id::text""",
                (p.tenant_id, str(req.integration_id), json.dumps(req.match),
                 req.name, req.enabled),
            )
            rule_id = cur.fetchone()[0]
            _audit(cur, p, "routing_rule.created", rule_id,
                   {"integration_id": str(req.integration_id),
                    "integration": f"{dest[0]}/{dest[1]}", "match": req.match,
                    "name": req.name, "enabled": req.enabled})
        conn.commit()
    return {"routing_rule_id": rule_id,
            "integration": {"id": str(req.integration_id), "type": dest[0], "name": dest[1]}}


@app.delete("/routing-rules/{rule_id}")
def delete_routing_rule(rule_id: uuid.UUID, p: Principal = Depends(admin)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select match, integration_id::text from routing_rules where id=%s and tenant_id=%s",
                (str(rule_id), p.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such routing rule")
            _audit(cur, p, "routing_rule.deleted", str(rule_id),
                   {"match": row[0], "integration_id": row[1]})
            cur.execute("delete from routing_rules where id=%s and tenant_id=%s",
                        (str(rule_id), p.tenant_id))
        conn.commit()
    return {"deleted": True, "routing_rule_id": str(rule_id)}


# ── Members ──────────────────────────────────────────────────────────────────
VALID_ROLES = tuple(sorted(ROLE_RANK))    # analyst|admin|editor|owner|viewer


class MemberAddRequest(BaseModel):
    email: str = Field(min_length=3)
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def _known_role(cls, v: str) -> str:
        if v not in ROLE_RANK:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v

    @field_validator("email")
    @classmethod
    def _email_shaped(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("email must be an email address")
        return v


class MemberPatchRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def _known_role(cls, v: str) -> str:
        if v not in ROLE_RANK:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v


@app.get("/members")
def list_members(p: Principal = Depends(principal)) -> dict:
    """Who belongs to the tenant. Readable by any member (the browser's RLS only shows a user
    their OWN membership row, so the console needs the engine for the team list)."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """select m.user_id::text, u.email, m.role, m.created_at
               from tenant_members m left join auth.users u on u.id = m.user_id
               where m.tenant_id = %s order by m.created_at""",
            (p.tenant_id,),
        )
        rows = cur.fetchall()
    return {"members": [{"user_id": r[0], "email": r[1], "role": r[2], "created_at": r[3]}
                        for r in rows]}


# Invites send real email from the customer's domain to an address the caller chooses. Without a
# cap, `POST /members` is an open relay for one message per request and a way to enumerate which
# addresses already have accounts. The window is per tenant, counted from the audit log so it
# survives a restart and needs no new table.
_INVITE_WINDOW_MINUTES = 60
_INVITE_MAX_PER_WINDOW = 20


def _invite_budget_remaining(cur, tenant_id: str) -> int:
    cur.execute(
        """select count(*) from audit_log
            where tenant_id = %s and action = 'member.added'
              and created_at > now() - make_interval(mins => %s)""",
        (tenant_id, _INVITE_WINDOW_MINUTES),
    )
    used = int((cur.fetchone() or [0])[0])
    return max(0, _INVITE_MAX_PER_WINDOW - used)


def _invite_user(email: str) -> Optional[str]:
    """Create the auth user via GoTrue's admin invite (sends the invite email). Returns the
    new user id, or None when the engine has no service-role key to do it with."""
    service_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    base = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    if not service_key or not base:
        return None
    import httpx
    res = httpx.post(f"{base}/auth/v1/invite", json={"email": email}, timeout=10.0,
                     headers={"apikey": service_key, "Authorization": f"Bearer {service_key}"})
    if res.status_code >= 300:
        raise HTTPException(502, f"invite failed: GoTrue HTTP {res.status_code}: {res.text[:200]}")
    user_id = (res.json() or {}).get("id")
    if not user_id:
        raise HTTPException(502, "invite failed: GoTrue returned no user id")
    return str(user_id)


@app.post("/members", status_code=201)
def add_member(req: MemberAddRequest, p: Principal = Depends(admin)) -> dict:
    """Add an existing auth user to the tenant by email. If no auth user exists and the engine
    holds SUPABASE_SERVICE_ROLE_KEY, the user is invited via GoTrue admin (they get an email);
    otherwise the caller is told the user must sign up first."""
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("select id::text from auth.users where lower(email) = %s", (req.email,))
            row = cur.fetchone()
            invited = False
            if row:
                user_id = row[0]
            else:
                # Rate-limit BEFORE sending: this path mails an address the caller chose, from
                # the customer's domain. Unbounded, it is a spam relay with an audit trail.
                if _invite_budget_remaining(cur, p.tenant_id) <= 0:
                    raise HTTPException(
                        429, f"invite limit reached ({_INVITE_MAX_PER_WINDOW} per "
                             f"{_INVITE_WINDOW_MINUTES} minutes for this tenant). Existing "
                             "members can still be added once they have signed up.")
                user_id = _invite_user(req.email)
                if user_id is None:
                    # Deliberately NOT "no user with email x@y": that distinguishes a registered
                    # address from an unregistered one, which is an account-existence oracle any
                    # tenant admin could iterate. The remedy is identical either way, so the
                    # message can be too.
                    raise HTTPException(
                        400, "this address could not be added. If they have not signed up yet, "
                             "enable invites by setting SUPABASE_SERVICE_ROLE_KEY on the engine; "
                             "otherwise ask them to sign up first.")
                invited = True

            cur.execute("select 1 from tenant_members where tenant_id=%s and user_id=%s",
                        (p.tenant_id, user_id))
            if cur.fetchone():
                raise HTTPException(409, "already a member of this tenant (use PATCH to change the role)")

            cur.execute(
                "insert into tenant_members (tenant_id, user_id, role) values (%s,%s,%s)",
                (p.tenant_id, user_id, req.role),
            )
            _audit(cur, p, "member.added", user_id,
                   {"email": req.email, "role": req.role, "invited": invited})
        conn.commit()

    return {"user_id": user_id, "email": req.email, "role": req.role, "invited": invited}


@app.patch("/members/{user_id}")
def change_member_role(user_id: uuid.UUID, req: MemberPatchRequest,
                       p: Principal = Depends(admin)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            # The whole membership, locked: the last-admin decision must see a consistent set.
            cur.execute(
                "select user_id::text, role from tenant_members where tenant_id=%s for update",
                (p.tenant_id,),
            )
            members = cur.fetchall()
            current = {u: r for u, r in members}
            if str(user_id) not in current:
                raise HTTPException(404, "no such member")
            if would_drop_last_admin(members, str(user_id), req.role):
                raise HTTPException(400, "cannot demote the last admin: a tenant nobody can "
                                         "administer is locked; promote someone else first")
            previous = current[str(user_id)]
            cur.execute(
                "update tenant_members set role=%s where tenant_id=%s and user_id=%s",
                (req.role, p.tenant_id, str(user_id)),
            )
            _audit(cur, p, "member.role_changed", str(user_id),
                   {"from": previous, "to": req.role})
        conn.commit()
    return {"user_id": str(user_id), "role": req.role, "previous": previous}


@app.delete("/members/{user_id}")
def remove_member(user_id: uuid.UUID, p: Principal = Depends(admin)) -> dict:
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select user_id::text, role from tenant_members where tenant_id=%s for update",
                (p.tenant_id,),
            )
            members = cur.fetchall()
            current = {u: r for u, r in members}
            if str(user_id) not in current:
                raise HTTPException(404, "no such member")
            if would_drop_last_admin(members, str(user_id), None):
                raise HTTPException(400, "cannot remove the last admin: promote someone else first")
            cur.execute("delete from tenant_members where tenant_id=%s and user_id=%s",
                        (p.tenant_id, str(user_id)))
            _audit(cur, p, "member.removed", str(user_id), {"role": current[str(user_id)]})
        conn.commit()
    return {"removed": True, "user_id": str(user_id), "role": current[str(user_id)]}


# ── Collector control plane ─────────────────────────────────────────────────
# The customer-side Collector's ONLY outbound endpoints. It authenticates with a short-lived,
# tenant-scoped bearer token minted at /enroll (auth.mint_collector_token — stateless HMAC, not a
# Supabase user JWT). It never opens an inbound port; every exchange here is the Collector calling
# us. Credentials for the customer's systems stay in the Collector and never reach these handlers —
# /results receives normalized findings + resource METADATA only, never Resource.raw.
import hashlib as _hashlib


class EnrollRequest(BaseModel):
    enrollment_token: str = Field(min_length=1)
    name: Optional[str] = None
    version: Optional[str] = None


@app.post("/collector/enroll")
def collector_enroll(req: EnrollRequest) -> dict:
    """Trade a long-lived enrollment token for a short-lived tenant-scoped service token.

    The enrollment token is matched by its sha256 against collectors.enroll_token_hash — the raw
    token is never stored here or by the collector. A bad token is 401 with no detail (no oracle).
    """
    token_hash = _hashlib.sha256(req.enrollment_token.encode()).hexdigest()
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select id, tenant_id from collectors where enroll_token_hash = %s for update",
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(401, "enrollment rejected")
            collector_id, tenant_id = str(row[0]), str(row[1])
            cur.execute(
                """update collectors set status='active', last_heartbeat=now(),
                          name=coalesce(%s, name), version=coalesce(%s, version)
                   where id=%s""",
                (req.name, req.version, collector_id),
            )
            cur.execute(
                """insert into audit_log (tenant_id, actor, action, target, detail)
                   values (%s,%s,'collector.enrolled',%s,%s)""",
                (tenant_id, f"collector:{collector_id}", collector_id,
                 json.dumps({"name": req.name, "version": req.version})),
            )
        conn.commit()

    from .auth import mint_collector_token
    token, expires_in = mint_collector_token(tenant_id, collector_id)
    return {"collector_id": collector_id, "tenant_id": tenant_id,
            "token": token, "expires_in": expires_in}


def collector_principal(authorization: Optional[str] = Header(None)) -> dict:
    """Verify a collector service token. Returns {'tenant_id', 'collector_id'} or 401."""
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "collector token required")
    from .auth import verify_collector_token
    claims = verify_collector_token(authorization[7:].strip())
    if not claims:
        raise HTTPException(401, "invalid or expired collector token")
    return claims


class HeartbeatRequest(BaseModel):
    collector_id: Optional[str] = None
    version: Optional[str] = None
    status: str = "active"
    # target names/types may be sent; recorded, but never used to tell the collector where to go.
    targets: Optional[list] = None


@app.post("/collector/heartbeat")
def collector_heartbeat(req: HeartbeatRequest, c: dict = Depends(collector_principal)) -> dict:
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """update collectors set last_heartbeat=now(), status=%s, version=coalesce(%s, version)
               where id=%s and tenant_id=%s""",
            (req.status, req.version, c["collector_id"], c["tenant_id"]),
        )
        conn.commit()
    return {"ok": True}


@app.get("/collector/jobs")
def collector_jobs(c: dict = Depends(collector_principal),
                   max_jobs: int = Query(5, ge=1, le=50)) -> dict:
    """Hand out queued scans for THIS collector's connections. A job is a reference to a locally
    configured target by NAME — never a host or a credential (the collector refuses config-shaped
    job fields anyway). Claimed scans move queued→running so two polls don't double-run one.
    """
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                """select s.id, s.connection_id, conn.name
                     from scans s join connections conn on conn.id = s.connection_id
                    where s.tenant_id = %s and s.status = 'queued'
                      and conn.mode = 'collector' and conn.collector_id = %s
                    order by s.started_at
                    limit %s
                    for update of s skip locked""",
                (c["tenant_id"], c["collector_id"], max_jobs),
            )
            rows = cur.fetchall()
            jobs = []
            for scan_id, connection_id, name in rows:
                cur.execute("update scans set status='running', started_at=now() where id=%s", (scan_id,))
                jobs.append({"job_id": str(scan_id), "connection_id": str(connection_id), "target": name})
        conn.commit()
    return {"jobs": jobs}


@app.post("/collector/results")
def collector_results(payload: dict, c: dict = Depends(collector_principal)) -> dict:
    """Persist a scan the collector ran locally. The job_id is the scan_id it claimed. On a
    collector-side error we mark the scan failed rather than persisting a half-result."""
    from ..scan import persist_pushed

    job_id = str(payload.get("job_id") or "")
    connection_id = str(payload.get("connection_id") or "")
    if not job_id or not connection_id:
        raise HTTPException(400, "results must carry job_id and connection_id")

    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            # The scan must belong to this collector's tenant and connection — a collector cannot
            # push results for a scan that isn't its own.
            cur.execute(
                """select 1 from scans s join connections conn on conn.id = s.connection_id
                   where s.id=%s and s.tenant_id=%s and conn.id=%s and conn.collector_id=%s""",
                (job_id, c["tenant_id"], connection_id, c["collector_id"]),
            )
            if not cur.fetchone():
                raise HTTPException(404, "no such job for this collector")

        if payload.get("status") == "error":
            with conn.cursor() as cur:
                cur.execute(
                    "update scans set status='error', finished_at=now(), stats=%s where id=%s",
                    (json.dumps({"error": payload.get("error"), "via": "collector"}), job_id),
                )
            conn.commit()
            return {"ok": True, "status": "error"}

        stats = persist_pushed(conn, c["tenant_id"], connection_id, job_id, payload)
    return {"ok": True, "status": "done", "stats": {k: stats[k] for k in
            ("resources", "edges", "findings", "observations") if k in stats}}


def main() -> None:
    import uvicorn

    # Here and not at import, so that importing vectasec has no environmental side effect for the
    # collector, which reads its own security posture out of os.environ. See config.py.
    load_env()

    # localhost by default: this process holds a BYPASSRLS database connection, so a small
    # attack surface is still the right default even now that every request requires a verified
    # token (see `principal`). Containers set ENGINE_HOST=0.0.0.0 deliberately.
    uvicorn.run(app, host=os.environ.get("ENGINE_HOST", "127.0.0.1"), port=settings.engine_port)


if __name__ == "__main__":
    main()
