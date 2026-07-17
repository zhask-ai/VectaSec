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
from ..registry import CONNECTORS, DETECTORS
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


def principal(
    x_vectasec_tenant: Optional[str] = Header(None),
    x_vectasec_actor: Optional[str] = Header(None),
) -> Principal:
    """Who is calling.

    TODO(auth): a real deployment MUST verify a Supabase JWT here — validate the signature
    against the project JWKS, take the tenant from the token's membership claims, and ignore
    these headers entirely. As written they are self-asserted: any caller can name any tenant
    and any actor. This is a development stand-in, which is also why the server binds to
    localhost by default (see `main`). Do not expose this to an untrusted network.
    """
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
class ScanRequest(BaseModel):
    type: str
    config: dict = Field(default_factory=dict)
    tenant_id: Optional[uuid.UUID] = None
    name: Optional[str] = None           # connection name; defaults like the CLI's
    inline: bool = False


@app.post("/scans", status_code=202)
def create_scan(req: ScanRequest, p: Principal = Depends(acting)) -> dict:
    """Start a scan. Queued by default (the Collector/worker pulls it); `inline: true` runs it
    in this request, which is the dev and demo path.

    NOTE: no worker consumes the queue yet, so a queued scan stays `queued` until one exists.
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
            cur.execute(
                """insert into scans (tenant_id, connection_id, status)
                   values (%s,%s,'queued') returning id""",
                (tenant, connection_id),
            )
            scan_id = cur.fetchone()[0]

            # Enqueued in the same transaction as the scan row it refers to: pgmq is a table, so
            # the message only becomes visible at COMMIT and a worker can never pull a job whose
            # scan row does not exist yet.
            # TODO(worker): the worker must adopt this scan_id — run_scan currently opens its own
            # scans row, so until it accepts one this row is a placeholder that stays 'queued'.
            job = {"scan_id": str(scan_id), "type": req.type, "config": req.config,
                   "tenant_id": tenant, "name": name, "requested_by": p.actor}
            cur.execute("select * from pgmq.send(%s, %s::jsonb)", (QUEUE, json.dumps(job)))
            msg_id = cur.fetchone()[0]

            _audit(cur, actor, "scan.requested", str(scan_id),
                   {"type": req.type, "name": name, "mode": "queued", "msg_id": msg_id})
        conn.commit()

    return {"scan_id": str(scan_id), "mode": "queued", "status": "queued",
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
                   "confidence": t.confidence},
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
            """select control_id, title, requirement, status, failing_finding_ids, evaluated_at
               from controls where tenant_id = %s and framework = %s order by control_id""",
            (p.tenant_id, framework),
        )
        rows = cur.fetchall()

    controls = [{"control_id": r[0], "title": r[1], "requirement": r[2], "status": r[3],
                 "failing_finding_ids": r[4] or [], "failing": len(r[4] or []),
                 "evaluated_at": r[5]} for r in rows]
    summary: dict[str, int] = {}
    for c in controls:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    return {"framework": framework, "count": len(controls), "summary": summary, "controls": controls}


# ── Graph ─────────────────────────────────────────────────────────────────
@app.get("/graph/blast-radius/{resource_id}")
def blast_radius(resource_id: uuid.UUID, depth: int = Query(4, ge=1, le=10),
                 p: Principal = Depends(principal)) -> dict:
    """What is reachable DOWNSTREAM of this resource — "what does an attacker who owns this
    get to next". The reverse question (what reaches this) is a different walk, not this one.
    """
    with _db() as conn, conn.cursor() as cur:
        cur.execute("select kind, name, ext_id from resources where tenant_id = %s and id = %s",
                    (p.tenant_id, str(resource_id)))
        root = cur.fetchone()
        if not root:
            raise HTTPException(404, "no such resource")

        # The depth cap is not a UI nicety: integration graphs contain cycles (a mesh routes
        # A→B→A), and `union all` would walk one forever without the `depth <` guard. min(depth)
        # then collapses the repeats back to one row per resource.
        cur.execute(
            """with recursive reach as (
                 select r.id, 0 as depth
                   from resources r
                  where r.tenant_id = %(tenant)s and r.id = %(root)s
                 union all
                 select e.dst_resource_id, reach.depth + 1
                   from edges e join reach on reach.id = e.src_resource_id
                  where e.tenant_id = %(tenant)s and reach.depth < %(max)s
               )
               select r.id, r.kind, r.name, r.ext_id, r.stale, min(reach.depth)
                 from reach join resources r on r.id = reach.id
                where r.tenant_id = %(tenant)s
                group by r.id, r.kind, r.name, r.ext_id, r.stale
                order by 6, 2, 3""",
            {"tenant": p.tenant_id, "root": str(resource_id), "max": depth},
        )
        rows = cur.fetchall()
        ids = [r[0] for r in rows]

        # Open findings only: a resolved or suppressed finding is not blast radius.
        cur.execute(
            """select resource_id, severity, count(*) from findings
               where tenant_id = %s and resource_id = any(%s)
                 and status not in ('resolved','suppressed')
               group by resource_id, severity""",
            (p.tenant_id, ids),
        )
        per_resource: dict = {}
        totals: dict[str, int] = {}
        for rid, sev, n in cur.fetchall():
            per_resource.setdefault(rid, {})[sev] = n
            totals[sev] = totals.get(sev, 0) + n

        cur.execute(
            """select src_resource_id, dst_resource_id, kind from edges
               where tenant_id = %s and src_resource_id = any(%s) and dst_resource_id = any(%s)""",
            (p.tenant_id, ids, ids),
        )
        edges = [{"src": str(a), "dst": str(b), "kind": k} for a, b, k in cur.fetchall()]

    nodes = [{"resource_id": str(r[0]), "kind": r[1], "name": r[2], "ext_id": r[3],
              "stale": r[4], "depth": r[5], "findings": per_resource.get(r[0], {})}
             for r in rows]
    return {
        "root": {"resource_id": str(resource_id), "kind": root[0], "name": root[1], "ext_id": root[2]},
        "max_depth": depth,
        "nodes": nodes,          # includes the root at depth 0
        "edges": edges,
        "totals": {"resources": len(nodes), "findings_by_severity": totals},
    }


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
