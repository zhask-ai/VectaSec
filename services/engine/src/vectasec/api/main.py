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
import json
import os
import uuid
from datetime import datetime
from typing import Literal, Optional

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from ..config import load_env, settings
from ..db import connect
from ..registry import CONNECTORS, CONNECTOR_FIELDS, DETECTORS, validate_config
from ..scan import run_scan, _ensure_connection   # _ensure_connection: reused so a queued scan
                                                  # points at the same connection row the worker
                                                  # will land on — not a second one
from .. import connect as _connect_pkg   # noqa: F401 — import triggers connector auto-registration
from .. import detect as _detect_pkg     # noqa: F401 — import triggers detector auto-registration

QUEUE = "vectasec_scans"                 # created in 20260717000002_platform_schema.sql

app = FastAPI(title="VectaSec engine", version="0.0.1")

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


# Dev header-trust is OFF unless explicitly enabled. Default on for localhost single-host dev so
# the CLI/demo keep working; a container that binds 0.0.0.0 must leave this unset, and then a
# real Supabase JWT is the ONLY way to authenticate.
_DEV_TRUST_HEADERS = os.environ.get("VECTASEC_DEV_TRUST_HEADERS", "1").strip() not in ("", "0", "false")


def _tenant_for_user(user_id: str, requested: Optional[str]) -> str:
    """Resolve the authoritative tenant for a verified user from tenant_members.

    The tenant is NEVER taken from the request — it is looked up from membership. If the user
    asked for a specific tenant (X-VectaSec-Tenant), honour it only if they actually belong to
    it; otherwise use their (single) membership. A user in no tenant is 403, not defaulted.
    """
    with _db() as conn, conn.cursor() as cur:
        cur.execute("select tenant_id::text from tenant_members where user_id = %s", (user_id,))
        member_of = {r[0] for r in cur.fetchall()}
    if not member_of:
        raise HTTPException(403, "authenticated user belongs to no tenant")
    if requested:
        if requested not in member_of:
            raise HTTPException(403, "not a member of the requested tenant")
        return requested
    if len(member_of) > 1:
        raise HTTPException(400, "user belongs to multiple tenants; specify X-VectaSec-Tenant")
    return next(iter(member_of))


def principal(
    authorization: Optional[str] = Header(None),
    x_vectasec_tenant: Optional[str] = Header(None),
    x_vectasec_actor: Optional[str] = Header(None),
) -> Principal:
    """Who is calling. A verified Supabase JWT is authoritative; the dev headers are a gated
    fallback, never trusted on their own in production.

    Path 1 — `Authorization: Bearer <supabase-jwt>`: the signature is verified against the
    project's public JWKS (auth.verify_supabase_jwt), the actor is the token's `sub`, and the
    tenant is resolved from tenant_members for that user. The request cannot name a tenant the
    user does not belong to. This is the real path.

    Path 2 — the X-VectaSec-* headers: self-asserted, so accepted ONLY when
    VECTASEC_DEV_TRUST_HEADERS is enabled (default on for localhost dev, off the moment a
    container binds a public interface). Without it, and without a valid JWT, the request is 401.
    """
    if x_vectasec_tenant:
        try:
            uuid.UUID(x_vectasec_tenant)
        except ValueError:
            raise HTTPException(400, "X-VectaSec-Tenant must be a uuid")

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        try:
            from .auth import verify_supabase_jwt
            claims = verify_supabase_jwt(token)
        except Exception as e:
            raise HTTPException(401, f"invalid token: {type(e).__name__}") from e
        user_id = str(claims.get("sub") or "")
        if not user_id:
            raise HTTPException(401, "token has no subject")
        tenant = _tenant_for_user(user_id, x_vectasec_tenant)
        return Principal(tenant_id=tenant, actor=user_id)

    if not _DEV_TRUST_HEADERS:
        raise HTTPException(401, "a verified Supabase JWT is required (dev header-trust is disabled)")

    tenant = (x_vectasec_tenant or settings.demo_tenant).strip()
    try:
        uuid.UUID(tenant)
    except ValueError:
        raise HTTPException(400, "X-VectaSec-Tenant must be a uuid")
    return Principal(tenant_id=tenant, actor=(x_vectasec_actor or "").strip())


def acting(p: Principal = Depends(principal)) -> Principal:
    """Principal for mutating endpoints — the actor is mandatory.

    An audit row with no actor documents nothing, so an unattributed write is refused rather
    than recorded anonymously.
    """
    if not p.actor:
        raise HTTPException(401, "X-VectaSec-Actor is required for actions (it is written to the audit log)")
    return p


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
def create_scan(req: ScanRequest, p: Principal = Depends(acting)) -> dict:
    """Start a scan. Queued by default — `vectasec worker` drains the queue and adopts the
    row (worker.py); `inline: true` runs it in this request instead (dev and demo path).
    """
    if req.type not in CONNECTORS:
        raise HTTPException(400, f"no connector for type {req.type!r} (have: {sorted(CONNECTORS)})")
    # TODO(auth): once the JWT lands, the token's tenant is authoritative and a body tenant_id
    # is only honourable after a membership check.
    tenant = str(req.tenant_id) if req.tenant_id else p.tenant_id
    actor = Principal(tenant_id=tenant, actor=p.actor)

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
            connection_id = _ensure_connection(cur, tenant, req.type, name, req.config)
            scan_id, msg_id = _enqueue_scan(cur, tenant, connection_id, req.type,
                                            req.config, name, p.actor)
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
def create_connection(req: ConnectionRequest, p: Principal = Depends(acting)) -> dict:
    """Create (or update the config of) a connection without scanning it.

    Validation happens HERE, at the moment a human is looking at a form, not later inside a
    queued job nobody is watching. The audit row records config KEYS only — config values
    carry credentials and must never enter the append-only log."""
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
            connection_id = _ensure_connection(cur, p.tenant_id, req.type, req.name,
                                               req.config, mode=req.mode)
            _audit(cur, p, "connection.updated" if existed else "connection.created",
                   str(connection_id),
                   {"type": req.type, "name": req.name, "mode": req.mode,
                    "config_keys": sorted(req.config)})
        conn.commit()

    return {"connection_id": str(connection_id), "type": req.type, "name": req.name,
            "created": not existed}


@app.post("/connections/{connection_id}/test")
def test_connection(connection_id: uuid.UUID, p: Principal = Depends(acting)) -> dict:
    """Run the connector's collect against the stored config and report what came back.

    Read-only against the target, same code path a real scan uses — so "test passed" means
    the scan will actually work, not that a TCP port answered. Persists nothing from the
    collect; only connections.status is updated so the console can show reachability. 200
    either way: the test *ran*; `ok` says what it found."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "select type, name, config from connections where id=%s and tenant_id=%s",
            (str(connection_id), p.tenant_id),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "no such connection")
    type_, name, config = row[0], row[1], row[2] or {}
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
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
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
def scan_connection(connection_id: uuid.UUID, p: Principal = Depends(acting)) -> dict:
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
def delete_connection(connection_id: uuid.UUID, p: Principal = Depends(acting)) -> dict:
    """Remove a connection and everything collected through it.

    The cascade is the schema's: resources (and their edges, findings, observations) go
    with the connection; scans rows survive with connection_id nulled — scan history is
    an audit artefact and outlives the thing scanned. The audit row records the counts
    BEFORE the delete so what was removed is on the record."""
    with _db() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute(
                "select type, name from connections where id=%s and tenant_id=%s",
                (str(connection_id), p.tenant_id),
            )
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such connection")
            type_, name = row

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
                    "findings": n_findings})
            cur.execute("delete from connections where id=%s and tenant_id=%s",
                        (str(connection_id), p.tenant_id))
        conn.commit()

    return {"deleted": True, "connection_id": str(connection_id), "type": type_,
            "name": name, "resources": n_resources, "findings": n_findings}


# ── Findings workflow ─────────────────────────────────────────────────────
# 'suppressed' is deliberately not settable here: a suppression carries a reason and an
# expiry and is applied by the scan loop, so it goes through POST /suppressions. Letting it
# be set as a plain status would create exceptions nobody can audit or expire.
FindingStatus = Literal["open", "triaged", "in_progress", "resolved", "accepted"]


class StatusRequest(BaseModel):
    status: FindingStatus
    note: str = ""


@app.post("/findings/{finding_id}/status")
def set_status(finding_id: uuid.UUID, req: StatusRequest, p: Principal = Depends(acting)) -> dict:
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
def assign(finding_id: uuid.UUID, req: AssignRequest, p: Principal = Depends(acting)) -> dict:
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
           p: Principal = Depends(acting)) -> dict:
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
def create_suppression(req: SuppressionRequest, p: Principal = Depends(acting)) -> dict:
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
                   p: Principal = Depends(acting)) -> dict:
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

    # localhost by default: this process holds a BYPASSRLS database connection and its auth is
    # a self-asserted header (see `principal`), so it must not be reachable off-box until both
    # of those change. Containers set ENGINE_HOST=0.0.0.0 deliberately.
    uvicorn.run(app, host=os.environ.get("ENGINE_HOST", "127.0.0.1"), port=settings.engine_port)


if __name__ == "__main__":
    main()
