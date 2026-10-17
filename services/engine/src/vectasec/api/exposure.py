"""Exposure scan API — the free external scan behind an ownership gate.

Built as a router factory rather than a module that imports `main`: `build_router` receives
main.py's `principal` / `editing` dependencies, its `_db` connection factory and `_audit`, so
this module has no import-time coupling to the app and the tests can hand it fakes.

Flow: POST /exposure/targets (get a token) -> publish the TXT record -> POST .../verify ->
POST .../scan (202, runs in a background thread with its own connection) -> GET /exposure/scans/{id}.
The console reads exposure_targets / exposure_scans directly under RLS; every write is here.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import exposure as X

log = logging.getLogger("vectasec.api.exposure")

MAX_RUNNING_PER_TENANT = 1
MAX_SCANS_PER_DAY = 10
SCAN_TIME_BUDGET_S = 60.0

TargetKind = Literal["domain", "ip", "cidr"]


class TargetRequest(BaseModel):
    kind: TargetKind
    value: str = Field(min_length=1, max_length=253)


def _iso(v) -> Optional[str]:
    if v is None:
        return None
    return v.isoformat() if isinstance(v, datetime) else str(v)


def _load_target(cur, tenant_id: str, target_id: str) -> dict:
    cur.execute(
        """select kind, value, token, verified_at, verify_method
             from exposure_targets where tenant_id = %s and id = %s""",
        (tenant_id, target_id),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "no such exposure target")
    return {"id": target_id, "kind": row[0], "value": row[1], "token": row[2],
            "verified_at": row[3], "verify_method": row[4]}


def build_router(principal: Callable, editing: Callable, db: Callable, audit: Callable, *,
                 resolver: Optional[X.Resolver] = None, runner: Optional[Callable] = None,
                 spawn: Optional[Callable[[Callable[[], None]], None]] = None,
                 time_budget_s: float = SCAN_TIME_BUDGET_S) -> APIRouter:
    """`principal` / `editing` are FastAPI dependency callables yielding an object with
    `.tenant_id` and `.actor`; `db()` returns a psycopg-style connection usable as a context
    manager; `audit(cur, p, action, target, detail)` appends to the audit log.

    `resolver`, `runner` (defaults to `exposure.run_exposure_scan`) and `spawn` (defaults to a
    daemon thread) are injection points for tests."""
    router = APIRouter(prefix="/exposure", tags=["exposure"])
    run = runner or X.run_exposure_scan

    def _spawn(fn: Callable[[], None]) -> None:
        if spawn is not None:
            spawn(fn)
            return
        threading.Thread(target=fn, name="exposure-scan", daemon=True).start()

    # ── Targets ───────────────────────────────────────────────────────────
    @router.post("/targets", status_code=201)
    def create_target(req: TargetRequest, p=Depends(editing)) -> dict:
        try:
            value = (X.normalize_domain(req.value) if req.kind == "domain"
                     else X.normalize_ip_or_cidr(req.kind, req.value))
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

        token = X.issue_token()
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                # Idempotent on (tenant, kind, value): a re-submit returns the existing row and
                # ITS token, so a user who lost the TXT value gets the same one back rather than
                # a second record to publish. The no-op update makes RETURNING fire on conflict;
                # xmax = 0 distinguishes a fresh insert from the existing row.
                cur.execute(
                    """insert into exposure_targets (tenant_id, kind, value, token, created_by)
                       values (%s,%s,%s,%s,%s)
                       on conflict (tenant_id, kind, value) do update set value = excluded.value
                       returning id, token, verified_at, (xmax = 0) as inserted""",
                    (p.tenant_id, req.kind, value, token, p.actor),
                )
                row = cur.fetchone()
                target_id, token, verified_at, inserted = str(row[0]), row[1], row[2], bool(row[3])
                if inserted:
                    audit(cur, p, "exposure.target_created", target_id,
                          {"kind": req.kind, "value": value})
            conn.commit()
        return {"target_id": target_id, "kind": req.kind, "value": value, "token": token,
                "txt_record": X.txt_record_for(token),
                "txt_names": [value, f"{X.VERIFY_SUBDOMAIN}.{value}"] if req.kind == "domain" else [],
                "verified": verified_at is not None}

    @router.post("/targets/{target_id}/verify")
    def verify_target(target_id: uuid.UUID, p=Depends(editing)) -> dict:
        tid = str(target_id)
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                t = _load_target(cur, p.tenant_id, tid)
                if t["kind"] == "domain":
                    checked = X.domain_lookups(t["value"])
                    ok, detail = X.verify_domain(t["value"], t["token"], resolver)
                    method = "dns_txt" if ok else None
                else:
                    cur.execute(
                        """select value from exposure_targets
                            where tenant_id = %s and kind = 'domain' and verified_at is not null""",
                        (p.tenant_id,),
                    )
                    domains = [r[0] for r in cur.fetchall()]
                    checked = [f"PTR/A {t['value']}"] + [f"A/AAAA {d}" for d in domains]
                    ok, detail = X.verify_ip(t["value"], domains, resolver)
                    method = detail if ok else None
                if ok:
                    cur.execute(
                        """update exposure_targets set verified_at = now(), verify_method = %s
                            where tenant_id = %s and id = %s""",
                        (method, p.tenant_id, tid),
                    )
                audit(cur, p, "exposure.target_verified" if ok else "exposure.target_verify_failed",
                      tid, {"kind": t["kind"], "value": t["value"], "method": method, "detail": detail})
            conn.commit()
        return {"target_id": tid, "verified": ok, "method": method, "checked": checked,
                "detail": detail}

    @router.get("/targets")
    def list_targets(p=Depends(principal)) -> dict:
        with db() as conn, conn.cursor() as cur:
            cur.execute(
                """select t.id, t.kind, t.value, t.verified_at, t.verify_method, t.created_at,
                          s.id, s.status, s.started_at, s.finished_at, s.report->>'headline'
                     from exposure_targets t
                     left join lateral (
                        select id, status, started_at, finished_at, report
                          from exposure_scans where target_id = t.id
                         order by started_at desc nulls last limit 1) s on true
                    where t.tenant_id = %s
                    order by t.created_at desc""",
                (p.tenant_id,),
            )
            rows = cur.fetchall()
        return {"targets": [{
            "target_id": str(r[0]), "kind": r[1], "value": r[2],
            "verified": r[3] is not None, "verified_at": _iso(r[3]), "verify_method": r[4],
            "created_at": _iso(r[5]),
            "latest_scan": None if r[6] is None else {
                "scan_id": str(r[6]), "status": r[7], "started_at": _iso(r[8]),
                "finished_at": _iso(r[9]), "headline": r[10]},
        } for r in rows]}

    # ── Scans ─────────────────────────────────────────────────────────────
    def _finish(scan_id: str, tenant_id: str, status: str, report: dict, error: Optional[str]):
        """Write the outcome from the background thread with its OWN connection: the request
        that started the scan has long since returned and closed its connection."""
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                cur.execute(
                    """update exposure_scans
                          set status = %s, finished_at = now(), report = %s::jsonb, error = %s
                        where id = %s and tenant_id = %s""",
                    (status, json.dumps(report, default=str), error, scan_id, tenant_id),
                )
            conn.commit()

    def _run_scan(scan_id: str, tenant_id: str, kind: str, value: str) -> None:
        try:
            hosts = X.expand_targets(kind, value, resolver)
            if not hosts:
                report = {"targets_probed": 0, "hosts": [], "services": [], "refusals": [
                    f"{value} resolved to no addresses — nothing to probe"],
                    "headline": "The target resolved to no addresses, so nothing was probed.",
                    "generated_at": datetime.now(timezone.utc).isoformat()}
            else:
                report = run(hosts, time_budget_s=time_budget_s)
            _finish(scan_id, tenant_id, "done", report, None)
        except Exception as e:                                   # noqa: BLE001 - must land in the row
            log.exception("exposure scan %s failed", scan_id)
            try:
                _finish(scan_id, tenant_id, "error", {}, f"{type(e).__name__}: {e}"[:500])
            except Exception:                                    # noqa: BLE001
                log.exception("exposure scan %s: could not record the error", scan_id)

    @router.post("/targets/{target_id}/scan", status_code=202)
    def start_scan(target_id: uuid.UUID, p=Depends(editing)) -> dict:
        tid = str(target_id)
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                t = _load_target(cur, p.tenant_id, tid)
                # The ownership gate. Not a soft warning: an unverified target is somebody
                # else's infrastructure until proven otherwise.
                if t["verified_at"] is None:
                    raise HTTPException(
                        403, "target is not verified — publish the TXT record and call "
                             "/verify first; the exposure scan only probes what you have proven you own")
                cur.execute(
                    """select count(*) filter (where status in ('queued','running')),
                              count(*) filter (where started_at > now() - interval '1 day')
                         from exposure_scans where tenant_id = %s""",
                    (p.tenant_id,),
                )
                running, today = (cur.fetchone() or (0, 0))
                if int(running or 0) >= MAX_RUNNING_PER_TENANT:
                    raise HTTPException(429, "a scan is already running for this organisation — "
                                             "wait for it to finish")
                if int(today or 0) >= MAX_SCANS_PER_DAY:
                    raise HTTPException(429, f"the free scan allows {MAX_SCANS_PER_DAY} runs per "
                                             "day per organisation — try again tomorrow")
                cur.execute(
                    """insert into exposure_scans (tenant_id, target_id, status, started_at)
                       values (%s,%s,'running',now()) returning id""",
                    (p.tenant_id, tid),
                )
                scan_id = str(cur.fetchone()[0])
                audit(cur, p, "exposure.scan_started", scan_id,
                      {"target_id": tid, "kind": t["kind"], "value": t["value"]})
            conn.commit()

        tenant_id, kind, value = p.tenant_id, t["kind"], t["value"]
        _spawn(lambda: _run_scan(scan_id, tenant_id, kind, value))
        return {"scan_id": scan_id, "status": "running", "target_id": tid}

    @router.get("/scans/{scan_id}")
    def get_scan(scan_id: uuid.UUID, p=Depends(principal)) -> dict:
        with db() as conn, conn.cursor() as cur:
            cur.execute(
                """select s.target_id, s.status, s.started_at, s.finished_at, s.report, s.error,
                          t.kind, t.value
                     from exposure_scans s join exposure_targets t on t.id = s.target_id
                    where s.tenant_id = %s and s.id = %s""",
                (p.tenant_id, str(scan_id)),
            )
            row = cur.fetchone()
        if not row:
            raise HTTPException(404, "no such exposure scan")
        return {"scan_id": str(scan_id), "target_id": str(row[0]), "status": row[1],
                "started_at": _iso(row[2]), "finished_at": _iso(row[3]),
                "report": row[4] or {}, "error": row[5],
                "target": {"kind": row[6], "value": row[7]}}

    return router
