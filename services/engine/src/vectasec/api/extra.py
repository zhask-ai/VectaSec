"""Extra API surface: the auditor access register and the weekly digest.

Built as an APIRouter factory so this module imports nothing from main.py — main.py passes its
own `principal` / `editing` dependencies, its `_db` connection factory and `_audit` writer, and
mounts the result with one `app.include_router(build_router(...))` line.

    from .extra import build_router
    app.include_router(build_router(principal, editing, _db, audit=_audit))

Endpoints:
  GET  /reports/access-register?format=csv|md   → file download (vectasec-access-register.csv|.md)
  GET  /timeline/as-of?at=2026-10-03            → the estate as recorded on that date     (principal)
  GET  /reports/changes?format=csv|md|json&since&until&days  → access and change report  (principal)
  GET  /findings/{id}/proof                     → proof support, action text, attempts    (principal)
  POST /findings/{id}/prove                     → run the read-only proof now             (editing)
  POST /breach-briefs                           → match an advisory to the inventory     (editing)
  GET  /reports/breach-brief?id=                → a stored brief as Markdown             (principal)
  GET  /people                                  → people named as owners in the inventory (principal)
  GET  /people/report?person=&format=json|md    → the Leaver report for one person        (principal)
  GET  /findings/{id}/impact                    → what a fix would touch, and a runbook  (principal)
  GET  /access/least-privilege                  → grants vs observed use, dry-run diff   (principal)
  GET  /benchmark                               → per-system benchmark scorecard         (principal)
  GET  /reports/benchmark?system=&blank=        → one benchmark as Markdown              (principal)
  POST /canaries, POST /canaries/{id}/revoke    → mint (URL shown once) / revoke a canary (editing)
  ANY  /c/{token}                               → PUBLIC canary endpoint; always the same 404
  GET  /access/flows                            → toxic flows, agent reach, data map     (principal)
  POST /assistant/ask                           → cited answer to a plain-language question (principal)
  GET  /assistant/explain-changes?days=         → cited reading of recorded changes       (principal)
  POST /assistant/review/{resource_id}          → AI suggestions, each quote-verified     (editing)
  GET  /access/who-can/{resource_id}            → effective access by the system's rules (principal)
  GET  /access/usage/{resource_id}?format=      → who was seen using it, and when        (principal)
  POST /access/owner                            → confirm an identity's owner, stamp verified (editing)
  POST /digests/run                             → {"id", "digest", "delivered_to"}      (editing)
  GET  /digests                                 → {"digests": [...last 12]}             (principal)
"""
from datetime import datetime, timezone
from typing import Callable, Optional

from fastapi import APIRouter, Depends, Query, Request, Response

# Bound so one tenant with a huge estate cannot make the API assemble an unbounded document.
# The document says when it was cut rather than silently truncating.
ACCESS_REGISTER_MAX_IDENTITIES = 5000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rows(cur, sql: str, params: tuple) -> list[dict]:
    cur.execute(sql, params)
    return [{"id": r[0], "ext_id": r[1], "name": r[2], "labels": r[3] or {}, "raw": r[4] or {}}
            for r in cur.fetchall()]


def load_access_register(cur, tenant_id: str, *, generated_at: str) -> tuple[list[dict], dict, str]:
    """(rows, coverage, tenant_name) for the tenant. Identities are bounded; credentials and
    grants are loaded for the identities that made the cut."""
    from .. import report
    from ..runtime_evidence import RUNTIME_SOURCES

    identities = _rows(cur,
        """select id::text, ext_id, name, labels, raw from resources
            where tenant_id = %s and kind = 'identity'
            order by labels->>'system', name, ext_id limit %s""",
        (tenant_id, ACCESS_REGISTER_MAX_IDENTITIES + 1))
    truncated = len(identities) > ACCESS_REGISTER_MAX_IDENTITIES
    identities = identities[:ACCESS_REGISTER_MAX_IDENTITIES]
    credentials = _rows(cur,
        """select id::text, ext_id, name, labels, raw from resources
            where tenant_id = %s and kind = 'credential'""", (tenant_id,))
    grants = _rows(cur,
        """select id::text, ext_id, name, labels, raw from resources
            where tenant_id = %s and kind = 'grant'""", (tenant_id,))

    cur.execute(
        """select f.rule_id, f.status, f.assessment, f.resource_id::text, r.ext_id
             from findings f join resources r on r.id = f.resource_id
            where f.tenant_id = %s and f.status = 'open'
              and r.kind in ('identity', 'credential', 'grant')
              and (f.rule_id like 'CREDENTIAL.LIFECYCLE.%%' or f.rule_id like 'NHI.%%')""",
        (tenant_id,),
    )
    findings = [{"rule_id": r[0], "status": r[1], "assessment": r[2], "resource_id": r[3],
                 "resource_ext_id": r[4]} for r in cur.fetchall()]

    cur.execute(
        """select principal, source, max(last_seen) from runtime_evidence
            where tenant_id = %s and principal is not null group by principal, source""",
        (tenant_id,),
    )
    runtime: dict = {}
    for principal, source, last_seen in cur.fetchall():
        value = last_seen.isoformat() if hasattr(last_seen, "isoformat") else str(last_seen)
        prev = runtime.get(principal)
        if prev is None or value > prev["last_seen"]:
            runtime[principal] = {"last_seen": value, "source": f"runtime_evidence:{source}"}

    cur.execute(
        """select ext_id, name, labels->>'data_sensitivity' from resources
            where tenant_id = %s and labels ? 'data_sensitivity'""",
        (tenant_id,),
    )
    sensitivity: dict = {}
    for ext_id, name, sens in cur.fetchall():
        if sens:
            sensitivity[ext_id] = sens
            sensitivity.setdefault(name, sens)

    cur.execute("select name from tenants where id = %s", (tenant_id,))
    trow = cur.fetchone()
    tenant_name = trow[0] if trow else "VectaSec tenant"

    # Human-confirmed owners win over inferred ones (table added 2026-11-24; absent on older DBs).
    confirmed: dict = {}
    cur.execute("savepoint owners")
    try:
        cur.execute("select identity_ext_id, owner, verified_at from identity_owners where tenant_id = %s",
                    (tenant_id,))
        confirmed = {r[0]: (r[1], r[2]) for r in cur.fetchall() or []}
        cur.execute("release savepoint owners")
    except Exception:
        cur.execute("rollback to savepoint owners")
    for ident in identities:
        hit = confirmed.get(ident["ext_id"])
        if hit:
            ident["labels"] = {**ident["labels"], "owner_label": hit[0],
                               "owner_verified_at": hit[1].isoformat() if hasattr(hit[1], "isoformat") else str(hit[1])}

    rows = report.to_access_register_rows(
        identities, credentials, grants, runtime_last_seen=runtime, generated_at=generated_at,
        findings=findings, target_sensitivity=sensitivity, cde_systems=None)
    # Connector types that can read a last-used signal: runtime-evidence sources plus AWS
    # (Access Advisor / GetAccessKeyLastUsed / RoleLastUsed, connect/aws.py).
    capable = set(RUNTIME_SOURCES) | {"aws"}
    coverage = report.access_register_coverage(
        rows, last_used_capable=capable, truncated=truncated, limit=ACCESS_REGISTER_MAX_IDENTITIES)
    return rows, coverage, tenant_name


def build_router(principal: Callable, editing: Callable, db: Callable,
                 audit: Optional[Callable] = None) -> APIRouter:
    router = APIRouter()

    @router.get("/reports/access-register")
    def report_access_register(
        format: str = Query("csv", pattern="^(csv|md)$"),
        p=Depends(principal),
    ) -> Response:
        """The auditor access register: one row per non-human identity with owner, last-used
        (unknown ≠ never ≠ dated), grants, verdicts and the controls it is evidence for."""
        from .. import report
        generated_at = _now_iso()
        with db() as conn, conn.cursor() as cur:
            rows, coverage, tenant_name = load_access_register(cur, p.tenant_id, generated_at=generated_at)
        if format == "md":
            body = report.to_access_register_markdown(
                rows, tenant_name=tenant_name, generated_at=generated_at, coverage=coverage)
            return Response(content=body, media_type="text/markdown",
                            headers={"Content-Disposition":
                                     'attachment; filename="vectasec-access-register.md"'})
        body = report.to_access_register_csv(rows)
        if coverage.get("truncated"):
            body += (f"# truncated at {ACCESS_REGISTER_MAX_IDENTITIES} identities; "
                     "the tenant has more than one export carries\n")
        return Response(content=body, media_type="text/csv",
                        headers={"Content-Disposition":
                                 'attachment; filename="vectasec-access-register.csv"'})

    def _window(since: Optional[str], until: Optional[str], days: int):
        """(since, until) as aware datetimes; a bad date is a 422, not a 500."""
        from datetime import timedelta
        from fastapi import HTTPException
        from ..timemachine import _dt
        try:
            end = _dt(until) if until else datetime.now(timezone.utc)
            start = _dt(since) if since else end - timedelta(days=days)
        except ValueError:
            raise HTTPException(422, "since / until must be ISO dates, e.g. 2026-10-03")
        if start >= end:
            raise HTTPException(422, "since must be before until")
        return start, end

    @router.get("/timeline/as-of")
    def timeline_as_of(at: str = Query(..., description="ISO date or datetime (UTC)"),
                       p=Depends(principal)) -> dict:
        """The estate as the scans had recorded it at `at`: posture, open findings, inventory
        size, and what has changed since. A date-only value means the END of that day."""
        from datetime import timedelta
        from fastapi import HTTPException
        from .. import timemachine
        try:
            when = timemachine._dt(at)
        except ValueError:
            raise HTTPException(422, "at must be an ISO date, e.g. 2026-10-03")
        if len(at.strip()) <= 10:
            when = when + timedelta(days=1) - timedelta(seconds=1)
        when = min(when, datetime.now(timezone.utc))
        with db() as conn, conn.cursor() as cur:
            return timemachine.as_of(cur, p.tenant_id, when)

    @router.get("/reports/changes")
    def report_changes(
        format: str = Query("md", pattern="^(csv|md|json)$"),
        since: Optional[str] = Query(None),
        until: Optional[str] = Query(None),
        days: int = Query(30, ge=1, le=366),
        p=Depends(principal),
    ) -> Response:
        """The access and change report: configuration changes between scans, findings opened
        and finding status changes, for a window (default the last 30 days)."""
        import json as _json
        from .. import timemachine
        start, end = _window(since, until, days)
        with db() as conn, conn.cursor() as cur:
            rep = timemachine.change_report(cur, p.tenant_id, start, end)
        if format == "json":
            return Response(content=_json.dumps(rep, default=str), media_type="application/json")
        if format == "csv":
            return Response(content=timemachine.to_changes_csv(rep), media_type="text/csv",
                            headers={"Content-Disposition":
                                     'attachment; filename="vectasec-change-report.csv"'})
        return Response(content=timemachine.to_changes_markdown(rep, generated_at=_now_iso()),
                        media_type="text/markdown",
                        headers={"Content-Disposition":
                                 'attachment; filename="vectasec-change-report.md"'})

    @router.get("/findings/{finding_id}/proof")
    def finding_proof(finding_id: str, p=Depends(principal)) -> dict:
        """Whether this finding has a safe proof, the exact action it would take, and the
        attempts made so far (newest first)."""
        from fastapi import HTTPException
        from .. import proof
        try:
            import uuid as _uuid
            fid = str(_uuid.UUID(finding_id))
        except ValueError:
            raise HTTPException(404, "no such finding")
        with db() as conn, conn.cursor() as cur:
            cur.execute("select rule_id from findings where tenant_id = %s and id = %s",
                        (p.tenant_id, fid))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such finding")
            try:
                attempts = proof.list_proofs(cur, p.tenant_id, fid)
                available = True
            except Exception:                   # table not migrated yet: the panel hides itself
                attempts, available = [], False
        return {"finding_id": fid, "rule_id": row[0], "available": available,
                "supported": proof.supported(row[0]), "action": proof.describe(row[0]),
                "proofs": attempts}

    @router.post("/findings/{finding_id}/prove")
    def prove_finding(finding_id: str, p=Depends(editing)) -> dict:
        """Run the proof now: ONE read-only, pre-authentication action against the finding's
        own target. No credential is sent, nothing is written, and the target cannot be chosen
        by the caller. The attempt is stored and audited whatever its verdict."""
        from fastapi import HTTPException
        from .. import proof
        try:
            import uuid as _uuid
            fid = str(_uuid.UUID(finding_id))
        except ValueError:
            raise HTTPException(404, "no such finding")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                result = proof.prove_finding(cur, p.tenant_id, fid, getattr(p, "actor", None))
                if result is None:
                    raise HTTPException(404, "no such finding")
                if audit is not None:
                    audit(cur, p, "finding.proof", fid,
                          {"proof_id": result["id"], "verdict": result["verdict"],
                           "target": result["target"], "rule_id": result["rule_id"]})
            conn.commit()
        return result

    @router.post("/breach-briefs")
    def create_breach_brief(body: dict, p=Depends(editing)) -> dict:
        """Match an advisory or vendor breach to the stored inventory now. No system is
        contacted. Body: {product, kind?: vulnerability|vendor_breach, affected?, title?,
        reference?}. The brief is stored as given on the day."""
        from fastapi import HTTPException
        from .. import breach
        product = str(body.get("product") or "").strip()
        if not product or len(product) > 100:
            raise HTTPException(422, "product is required (for example: n8n, redis, kong)")
        kind = str(body.get("kind") or "vulnerability")
        if kind not in ("vulnerability", "vendor_breach"):
            raise HTTPException(422, "kind must be vulnerability or vendor_breach")
        reference = str(body.get("reference") or "").strip()
        if reference and not reference.lower().startswith(("https://", "http://")):
            raise HTTPException(422, "reference must be an http(s) link")
        advisory = {"product": product, "kind": kind, "reference": reference,
                    "affected": str(body.get("affected") or "").strip(),
                    "title": str(body.get("title") or "").strip()}
        try:
            breach.parse_spec(advisory["affected"])
        except ValueError as e:
            raise HTTPException(422, f"affected versions: {e}. Example: <1.121.0 or >=7.0, <7.2.5")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                brief = breach.create_brief(cur, p.tenant_id, advisory,
                                            getattr(p, "actor", None), _now_iso())
                if audit is not None:
                    audit(cur, p, "breach_brief.created", brief["id"],
                          {"product": product, "kind": kind, "counts": brief["counts"],
                           "rotate": brief["rotate_total"], "held": len(brief["held"])})
            conn.commit()
        return brief

    @router.get("/reports/breach-brief")
    def report_breach_brief(id: str = Query(...), p=Depends(principal)) -> Response:
        """A stored brief as Markdown."""
        from fastapi import HTTPException
        from .. import breach
        import uuid as _uuid
        try:
            bid = str(_uuid.UUID(id))
        except ValueError:
            raise HTTPException(404, "no such brief")
        with db() as conn, conn.cursor() as cur:
            cur.execute("select summary from breach_briefs where tenant_id = %s and id = %s",
                        (p.tenant_id, bid))
            row = cur.fetchone()
        if not row:
            raise HTTPException(404, "no such brief")
        return Response(content=breach.to_markdown(row[0]), media_type="text/markdown",
                        headers={"Content-Disposition":
                                 'attachment; filename="vectasec-breach-brief.md"'})

    @router.get("/people")
    def people(p=Depends(principal)) -> dict:
        """People the inventory names as owner, creator or account holder, most first."""
        from .. import leaver
        with db() as conn, conn.cursor() as cur:
            resources, _edges, _conns = leaver.load(cur, p.tenant_id)
        return {"people": leaver.list_people(resources)[:500]}

    @router.get("/people/report")
    def people_report(person: str = Query(..., min_length=1, max_length=200),
                      format: str = Query("json", pattern="^(json|md)$"),
                      p=Depends(principal)):
        """The Leaver report for one person: their accounts, what they own, and what keeps
        running on their authority. Exact match on the name or email; nothing is changed."""
        from .. import leaver
        with db() as conn, conn.cursor() as cur:
            resources, edges, conns = leaver.load(cur, p.tenant_id)
        rep = leaver.build_report(person, resources, edges, conns)
        if format == "md":
            return Response(content=leaver.to_markdown(rep, _now_iso()), media_type="text/markdown",
                            headers={"Content-Disposition":
                                     'attachment; filename="vectasec-leaver-report.md"'})
        return rep

    @router.get("/findings/{finding_id}/impact")
    def finding_impact(finding_id: str, p=Depends(principal)) -> dict:
        """What a fix would touch: who was seen using the resource, what depends on it, what
        else the fix closes, and a runbook. From stored scans; nothing is contacted."""
        from fastapi import HTTPException
        from .. import impact
        import uuid as _uuid
        try:
            fid = str(_uuid.UUID(finding_id))
        except ValueError:
            raise HTTPException(404, "no such finding")
        with db() as conn, conn.cursor() as cur:
            out = impact.fix_preview(cur, p.tenant_id, fid)
        if out is None:
            raise HTTPException(404, "no such finding")
        return out

    @router.get("/access/least-privilege")
    def least_privilege(p=Depends(principal)) -> dict:
        """Per identity: grants versus observed use, as a dry-run diff. Nothing is applied."""
        from .. import impact
        with db() as conn, conn.cursor() as cur:
            return impact.recommend(cur, p.tenant_id)

    @router.get("/benchmark")
    def benchmark_scorecard(p=Depends(principal)) -> dict:
        """This tenant's result against the VectaSec Integration-Layer Benchmark, per system,
        without the per-control catalogue (use /reports/benchmark for the document)."""
        from .. import benchmark
        with db() as conn, conn.cursor() as cur:
            card = benchmark.load_scorecard(cur, p.tenant_id)
        return {"version": card["version"],
                "systems": [{k: v for k, v in s.items() if k != "results"} for s in card["systems"]]}

    @router.get("/reports/benchmark")
    def report_benchmark(system: str = Query(..., pattern="^[a-z0-9_]{1,32}$"),
                         blank: bool = Query(False), p=Depends(principal)) -> Response:
        """One system's benchmark as Markdown: filled in with this tenant's results, or the
        blank public document with blank=true."""
        from fastapi import HTTPException
        from .. import benchmark
        with db() as conn, conn.cursor() as cur:
            card = benchmark.load_scorecard(cur, p.tenant_id)
        bench = card["catalogue"].get(system)
        if not bench:
            raise HTTPException(404, "no benchmark for that system")
        results = None if blank else next(s for s in card["systems"] if s["key"] == system)
        return Response(content=benchmark.to_markdown(bench, results, generated_at=_now_iso()),
                        media_type="text/markdown",
                        headers={"Content-Disposition":
                                 f'attachment; filename="vectasec-benchmark-{system}.md"'})

    @router.post("/canaries")
    def create_canary(body: dict, p=Depends(editing)) -> dict:
        """Mint a canary. The URL is returned ONCE and never stored (only its hash is)."""
        from fastapi import HTTPException
        from .. import canary
        name = str(body.get("name") or "").strip()
        if not name:
            raise HTTPException(422, "give the canary a name you will recognise in an alert")
        finding_id = body.get("finding_id") or None
        if finding_id:
            import uuid as _uuid
            try:
                finding_id = str(_uuid.UUID(str(finding_id)))
            except ValueError:
                raise HTTPException(422, "finding_id is not a uuid")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                if finding_id:
                    cur.execute("select 1 from findings where tenant_id = %s and id = %s",
                                (p.tenant_id, finding_id))
                    if not cur.fetchone():
                        raise HTTPException(404, "no such finding")
                out = canary.mint(cur, p.tenant_id, name, str(body.get("placed_in") or "").strip(),
                                  finding_id, getattr(p, "actor", None))
                if audit is not None:
                    audit(cur, p, "canary.created", out["id"], {"name": out["name"]})
            conn.commit()
        return out

    @router.post("/canaries/{canary_id}/revoke")
    def revoke_canary(canary_id: str, p=Depends(editing)) -> dict:
        from fastapi import HTTPException
        from .. import canary
        import uuid as _uuid
        try:
            cid = str(_uuid.UUID(canary_id))
        except ValueError:
            raise HTTPException(404, "no such canary")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                if not canary.revoke(cur, p.tenant_id, cid):
                    raise HTTPException(404, "no such live canary")
                if audit is not None:
                    audit(cur, p, "canary.revoked", cid, {})
            conn.commit()
        return {"id": cid, "revoked": True}

    @router.api_route("/c/{token}", methods=["GET", "POST", "PUT", "HEAD"], include_in_schema=False)
    def canary_hit(token: str, request: Request) -> Response:
        """PUBLIC, unauthenticated. Every caller gets the same 404 whether or not the token is
        a live canary: the endpoint must not confirm that anything was tripped. Bodies and
        headers are never read or stored."""
        import json as _json
        from .. import canary
        try:
            fwd = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
            ip = fwd or (request.client.host if request.client else None)
            with db() as conn:
                conn.autocommit = False
                with conn.cursor() as cur:
                    hit = canary.record_hit(cur, token, source_ip=ip,
                                            user_agent=request.headers.get("user-agent"),
                                            method=request.method,
                                            query_len=len(request.url.query or ""))
                conn.commit()
                if hit and hit.get("alert"):
                    with conn.cursor() as cur:
                        canary.send_alerts(cur, hit)
                    conn.commit()
        except Exception:                       # noqa: BLE001 - never leak a failure to the caller
            pass
        return Response(content=_json.dumps(canary.PUBLIC_RESPONSE, separators=(",", ":")), status_code=404,
                        media_type="application/json")

    @router.get("/access/flows")
    def data_and_agents(p=Depends(principal)) -> dict:
        """Toxic flows across automations, what MCP servers can reach, and the sensitive-data
        map. Stored scans only; every row says whether it is declared or inferred."""
        from .. import flows
        with db() as conn, conn.cursor() as cur:
            return flows.load(cur, p.tenant_id)

    @router.post("/assistant/ask")
    def assistant_ask(body: dict, p=Depends(principal)) -> dict:
        """Answer a plain-language question from stored facts, with citations. The model may
        only use numbered facts the engine supplies; an uncited answer is discarded and a plain
        search of the same facts is returned instead. Read-only."""
        from fastapi import HTTPException
        from .. import assistant
        question = str(body.get("question") or "").strip()
        if len(question) < 3:
            raise HTTPException(422, "ask a question")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                out = assistant.ask(cur, p.tenant_id, question)
                if audit is not None:
                    audit(cur, p, "assistant.ask", None,
                          {"chars": len(question), "ai_used": out["ai_used"], "model": out["model"],
                           "facts": out["facts_considered"]})
            conn.commit()
        return out

    @router.get("/assistant/explain-changes")
    def assistant_explain_changes(days: int = Query(7, ge=1, le=90), p=Depends(principal)) -> dict:
        """A plain-language reading of recorded configuration changes, cited to the changes."""
        from .. import assistant
        with db() as conn, conn.cursor() as cur:
            return assistant.explain_changes(cur, p.tenant_id, days)

    @router.post("/assistant/review/{resource_id}")
    def assistant_review(resource_id: str, p=Depends(editing)) -> dict:
        """AI review of one resource's stored configuration. Each suggestion must quote a value
        the engine can find at the stated path, or it is dropped. Suggestions are never findings."""
        from fastapi import HTTPException
        from .. import assistant
        import uuid as _uuid
        try:
            rid = str(_uuid.UUID(resource_id))
        except ValueError:
            raise HTTPException(404, "no such resource")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                out = assistant.review_resource(cur, p.tenant_id, rid)
                if out is None:
                    raise HTTPException(404, "no such resource")
                if audit is not None:
                    audit(cur, p, "assistant.review", rid,
                          {"ai_used": out["ai_used"], "model": out["model"],
                           "kept": len(out["suggestions"]), "discarded": out["discarded"]})
            conn.commit()
        return out

    @router.get("/assistant/status")
    def assistant_status(p=Depends(principal)) -> dict:
        from .. import ai_core
        return {"ai_available": ai_core.available()}

    @router.get("/access/who-can/{resource_id}")
    def who_can(resource_id: str, p=Depends(principal)) -> dict:
        """Effective access for one resource, evaluated with the system's own rules (Kafka ACL
        evaluation, RabbitMQ permission regexes, Redis ACL rules). From stored scans only."""
        from fastapi import HTTPException
        from .. import effective
        import uuid as _uuid
        try:
            rid = str(_uuid.UUID(resource_id))
        except ValueError:
            raise HTTPException(404, "no such resource")
        with db() as conn, conn.cursor() as cur:
            cur.execute("select kind, name, raw, labels, connection_id from resources "
                        "where tenant_id = %s and id = %s", (p.tenant_id, rid))
            row = cur.fetchone()
            if not row:
                raise HTTPException(404, "no such resource")
            kind, name, raw, labels, cid = row
            cur.execute("select kind, name, raw, labels from resources where tenant_id = %s and "
                        "connection_id = %s and not stale and kind = any(%s)",
                        (p.tenant_id, cid, ["broker", "permission", "user", "redis_user"]))
            siblings = [{"kind": r[0], "name": r[1], "raw": r[2] or {}, "labels": r[3] or {}}
                        for r in cur.fetchall() or []]
        out = effective.who_can({"kind": kind, "name": name, "raw": raw or {}, "labels": labels or {}}, siblings)
        return {"supported": out is not None, **(out or {})}

    @router.get("/access/usage/{resource_id}")
    def usage(resource_id: str, format: str = Query("json", pattern="^(json|csv)$"),
              p=Depends(principal)):
        """Who was seen using one resource, and when (runtime evidence). CSV for auditors."""
        from fastapi import HTTPException
        from .. import impact
        import uuid as _uuid
        try:
            rid = str(_uuid.UUID(resource_id))
        except ValueError:
            raise HTTPException(404, "no such resource")
        with db() as conn, conn.cursor() as cur:
            out = impact.usage_history(cur, p.tenant_id, rid)
        if out is None:
            raise HTTPException(404, "no such resource")
        if format == "csv":
            import csv, io
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            w.writerow(["resource", "principal", "peer_host", "first_seen", "last_seen",
                        "scans_that_saw_it", "source"])
            for r in out["rows"]:
                w.writerow([out["resource"]["name"], r["principal"], r["peer_host"], r["first_seen"],
                            r["last_seen"], r["observed_scans"], r["source"]])
            buf.write(f"# observed since {out['observation_started_at'] or 'never'}; {out['note']}\n")
            return Response(content=buf.getvalue(), media_type="text/csv",
                            headers={"Content-Disposition": 'attachment; filename="vectasec-usage.csv"'})
        return out

    @router.post("/access/owner")
    def confirm_owner(body: dict, p=Depends(editing)) -> dict:
        """Confirm (or change) who owns a machine identity, stamping 'last verified' now.
        Body: {resource_id, owner, note?}. Re-confirming the same owner just refreshes the date."""
        from fastapi import HTTPException
        import json as _json
        import uuid as _uuid
        owner = " ".join(str(body.get("owner") or "").split())
        note = " ".join(str(body.get("note") or "").split())[:300]
        if not owner or len(owner) > 200:
            raise HTTPException(422, "name the owner: a person's email or a team name")
        try:
            rid = str(_uuid.UUID(str(body.get("resource_id") or "")))
        except ValueError:
            raise HTTPException(404, "no such identity")
        with db() as conn:
            conn.autocommit = False
            with conn.cursor() as cur:
                cur.execute("select ext_id, name from resources where tenant_id = %s and id = %s "
                            "and kind = 'identity'", (p.tenant_id, rid))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(404, "no such identity")
                ext_id, name = row
                cur.execute("select owner from identity_owners where tenant_id = %s and identity_ext_id = %s",
                            (p.tenant_id, ext_id))
                prev = cur.fetchone()
                cur.execute(
                    """insert into identity_owners (tenant_id, identity_ext_id, owner, note, verified_by)
                       values (%s,%s,%s,%s,%s)
                       on conflict (tenant_id, identity_ext_id) do update
                         set owner = excluded.owner, note = excluded.note,
                             verified_by = excluded.verified_by, verified_at = now()
                       returning verified_at""",
                    (p.tenant_id, ext_id, owner, note, getattr(p, "actor", None)))
                verified_at = cur.fetchone()[0]
                if audit is not None:
                    audit(cur, p, "access.owner_confirmed", rid,
                          {"identity": name, "owner": owner, "previous": prev[0] if prev else None,
                           "note": note})
            conn.commit()
        return {"identity": name, "owner": owner, "previous": prev[0] if prev else None,
                "verified_at": verified_at.isoformat()}

    @router.post("/digests/run")
    def run_digest(p=Depends(editing)) -> dict:
        """Compose and deliver the weekly digest for the caller's tenant now (window: since the
        last digest, else seven days). Returns the summary and every delivery attempt."""
        from ..digest import send_digest
        with db() as conn:
            conn.autocommit = False
            result = send_digest(conn, p.tenant_id)
            if audit is not None:
                with conn.cursor() as cur:
                    audit(cur, p, "digest.run", result.get("id"),
                          {"period_start": result["digest"].get("period_start"),
                           "period_end": result["digest"].get("period_end"),
                           "delivered_to": [{k: v for k, v in d.items() if k != "error"}
                                            for d in result["delivered_to"]]})
                conn.commit()
        return result

    @router.get("/digests")
    def list_digests_endpoint(p=Depends(principal)) -> dict:
        """The last 12 digest runs for the tenant."""
        from ..digest import list_digests
        with db() as conn, conn.cursor() as cur:
            rows = list_digests(cur, p.tenant_id, limit=12)
        return {"digests": rows}

    return router
