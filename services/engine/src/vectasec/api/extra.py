"""Extra API surface: the auditor access register and the weekly digest.

Built as an APIRouter factory so this module imports nothing from main.py — main.py passes its
own `principal` / `editing` dependencies, its `_db` connection factory and `_audit` writer, and
mounts the result with one `app.include_router(build_router(...))` line.

    from .extra import build_router
    app.include_router(build_router(principal, editing, _db, audit=_audit))

Endpoints:
  GET  /reports/access-register?format=csv|md   → file download (vectasec-access-register.csv|.md)
  POST /digests/run                             → {"id", "digest", "delivered_to"}      (editing)
  GET  /digests                                 → {"digests": [...last 12]}             (principal)
"""
from datetime import datetime, timezone
from typing import Callable, Optional

from fastapi import APIRouter, Depends, Query, Response

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
