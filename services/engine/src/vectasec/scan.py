"""The scan loop: collect → detect → persist.

This is the spine. Everything else (connectors, detectors, AI, compliance) plugs into it.

Design rules that are not negotiable:
  • A finding is identified by a *fingerprint*, not a row id — so the same real-world issue
    seen across 100 scans stays ONE finding with a stable history, and human triage state
    (status/assignee/due_at) survives re-scanning. Re-scanning must never resurrect a
    finding a human already resolved into a fresh row.
  • Every finding writes its triggering evidence to `observations` in the SAME transaction.
    A finding without evidence is a rumour.
  • The RESULT of a scan is one transaction: resources, edges, findings, observations and
    stats all land together, because a half-written scan would show a security team an
    incomplete picture, which is worse than showing them an error. The `connections` and
    `scans('running')` rows are committed BEFORE that, on purpose — they are bookkeeping,
    not results, and holding them open across the collect took a row lock on the connection
    for as long as the target took to answer. The cost of that split is honest and recorded
    in docs/STATUS.md: a crash mid-collect now leaves a durable 'running' row, and nothing
    reaps it yet.
"""
import hashlib
import json
import time
from typing import Optional

from .config import settings
from .contracts import Collected, ScanContext
from .registry import CONNECTORS, DETECTORS
from . import connect as _connect   # noqa: F401  — import triggers connector auto-registration
from . import detect as _detect     # noqa: F401  — import triggers detector auto-registration


def fingerprint(tenant_id: str, connection_id: str, rule_id: str, ext_id: str) -> str:
    """Stable identity of a finding across scans.

    Deliberately excludes the scan id and the resource's DB uuid (which changes if a
    resource is deleted and recollected) — it is keyed on what a human would call "the
    same problem on the same thing".

    connection_id IS included, and must be: `Resource.ext_id` is only unique *within a
    connection* (contracts.py), so without it one tenant's prod and staging Kafka clusters
    both emit `topic-payments` / `broker-1`, and RabbitMQ emits the literal `cluster` for
    every connection. `findings` is UNIQUE (tenant_id, fingerprint), so those collapse into
    ONE row and the staging scan silently overwrites the production finding. connection_id
    is resolved from (tenant, type, name) and is stable across scans, so the cross-scan
    stability the rest of this docstring promises is preserved.
    """
    return hashlib.sha256(
        f"{tenant_id}|{connection_id}|{rule_id}|{ext_id}".encode()
    ).hexdigest()[:32]


_RANK = ["info", "low", "medium", "high", "critical"]


def representative(hits: list, default_severity: str):
    """Pick the ONE Hit whose severity/remediation/detail a group of Hits is filed under.

    A detector may return several Hits for one resource (one per listener, one per OAuth URL),
    but fingerprint() is keyed on (tenant, connection, rule, resource) with no per-Hit
    discriminator — so every Hit in that group collapses into ONE findings row. The upsert does
    `severity = excluded.severity`, so before this existed the row kept whatever the LAST Hit in
    list order happened to say. That is not a cosmetic ordering wart on a security product:

      • detect/mcp.py plaintext_http yields the MCP endpoint first and the OAuth URLs after it, so
        a public plaintext-HTTP endpoint (high) followed by a private-IP token endpoint (medium)
        filed the whole finding at medium — a public endpoint carrying bearer tokens in cleartext,
        recorded one tier below the truth.
      • prm_missing_or_mismatched yields an empty-authorization_servers MUST violation (medium)
        then a cosmetic trailing-slash delta (info): the finding was stored at info WITH the
        cosmetic hit's detail text, so the stored explanation actively contradicted the defect.

    Worst-severity wins, and the representative carries its OWN remediation and detail, so the
    prose the customer reads always belongs to the Hit the severity came from. Ties keep the
    earliest Hit, making the result independent of list order. Every Hit still writes its own
    observation to the ledger — no evidence is dropped, only the summary row is chosen.

    A Hit with severity=None means "use the rule's declared severity" (contracts.Hit), so it is
    resolved against `default_severity` BEFORE ranking — a mixed None/explicit group is exactly
    the case detect/kafka.py's `_uniform` bails out of, and it is the common one.
    """
    def rank(sev) -> int:
        try:
            return _RANK.index(sev)
        except ValueError:
            return -1   # an unrecognised severity never silently outranks a known one
    best = hits[0]
    best_sev = hits[0].severity or default_severity
    for h in hits[1:]:
        sev = h.severity or default_severity
        if rank(sev) > rank(best_sev):
            best, best_sev = h, sev
    return best, best_sev


def _ensure_connection(cur, tenant_id: str, type_: str, name: str, config: dict) -> str:
    cur.execute(
        "select id from connections where tenant_id=%s and type=%s and name=%s",
        (tenant_id, type_, name),
    )
    row = cur.fetchone()
    if row:
        cur.execute("update connections set config=%s where id=%s", (json.dumps(config), row[0]))
        return row[0]
    cur.execute(
        """insert into connections (tenant_id, type, name, mode, config)
           values (%s,%s,%s,'cloud',%s) returning id""",
        (tenant_id, type_, name, json.dumps(config)),
    )
    return cur.fetchone()[0]


def _persist_resources(cur, tenant_id: str, connection_id: str, collected: Collected) -> dict:
    """Upsert resources, mark vanished ones stale, return ext_id -> resource uuid."""
    ext_to_id: dict[str, str] = {}
    seen: list[str] = []

    for r in collected.resources:
        cur.execute(
            """insert into resources (tenant_id, connection_id, kind, name, namespace, ext_id, labels, raw)
               values (%s,%s,%s,%s,%s,%s,%s,%s)
               on conflict (connection_id, ext_id) do update
                 set last_seen = now(),
                     labels    = excluded.labels,
                     raw       = excluded.raw,
                     name      = excluded.name,
                     stale     = false
               returning id""",
            (tenant_id, connection_id, r.kind, r.name, r.namespace, r.ext_id,
             json.dumps(r.labels), json.dumps(r.raw)),
        )
        rid = cur.fetchone()[0]
        ext_to_id[r.ext_id] = rid
        seen.append(r.ext_id)

    # Anything previously collected but absent now is stale, not deleted: an asset that
    # disappears is itself a signal, and deleting it would destroy finding history.
    if seen:
        cur.execute(
            "update resources set stale = true where connection_id = %s and not (ext_id = any(%s))",
            (connection_id, seen),
        )
    return ext_to_id


def _persist_edges(cur, tenant_id: str, connection_id: str, collected: Collected, ext_to_id: dict) -> int:
    cur.execute(
        """delete from edges where src_resource_id in (
             select id from resources where connection_id = %s)""",
        (connection_id,),
    )
    n = 0
    for e in collected.edges:
        src, dst = ext_to_id.get(e.src_ext_id), ext_to_id.get(e.dst_ext_id)
        if not src or not dst:
            continue  # an edge to something we didn't collect is dropped, not guessed at
        cur.execute(
            """insert into edges (tenant_id, src_resource_id, dst_resource_id, kind, labels)
               values (%s,%s,%s,%s,%s)""",
            (tenant_id, src, dst, e.kind, json.dumps(e.labels)),
        )
        n += 1
    return n


def _active_suppressions(cur, tenant_id: str) -> list[dict]:
    cur.execute(
        """select rule_id, scope from suppressions
           where tenant_id = %s and (expires_at is null or expires_at > now())""",
        (tenant_id,),
    )
    # The scope is handed over VERBATIM — `r[1] or {}` would coerce a jsonb `[]` into the
    # tenant-wide `{}` right here, before _is_suppressed ever gets to reject it.
    return [{"rule_id": r[0], "scope": r[1]} for r in cur.fetchall()]


def _is_suppressed(supps: list[dict], rule_id: str, resource) -> bool:
    for s in supps:
        if s["rule_id"] != rule_id:
            continue
        raw = s["scope"]
        # An ABSENT scope (SQL NULL / {}) is the documented tenant-wide form. Any other
        # non-object jsonb — an array, a string, a number — is an unevaluable scope, and an
        # unevaluable scope must FAIL CLOSED: `[] or {}` used to fall through to the
        # tenant-wide branch and silence the rule across the whole tenant, and a jsonb string
        # used to raise AttributeError out of the scan loop. Neither is a scope anyone wrote
        # on purpose. Skipping leaves the finding open, which is the safe direction.
        if raw is None:
            scope: dict = {}
        elif isinstance(raw, dict):
            scope = raw
        else:
            continue
        if not scope:
            return True                                        # tenant-wide
        if scope.get("ext_id") == resource.ext_id:
            return True
        if scope.get("kind") == resource.kind:
            return True
    return False


def _mark_scan_error(conn, scan_id: str, e: BaseException) -> None:
    """Record a scan as failed, on a transaction of its own.

    The caller's transaction may be ABORTED (a UniqueViolation poisons it — every subsequent
    statement raises InFailedSqlTransaction), so roll back first and write the error row on a
    fresh transaction. Without this, a persist/detect failure rolls the `scans` row back with
    it and a scan that fails every night leaves no trace in the database at all.
    """
    conn.rollback()
    with conn.cursor() as cur:
        cur.execute(
            "update scans set status='error', finished_at=now(), stats=%s where id=%s",
            (json.dumps({"error": f"{type(e).__name__}: {e}"}), scan_id),
        )
    conn.commit()


def run_scan(type_: str, config: dict, tenant_id: Optional[str] = None,
             connection_name: Optional[str] = None) -> dict:
    """Run one scan end to end. Returns stats."""
    from .db import connect

    tenant_id = tenant_id or settings.demo_tenant
    if type_ not in CONNECTORS:
        raise SystemExit(f"no connector registered for type {type_!r} (have: {sorted(CONNECTORS)})")

    name = connection_name or config.get("bootstrap") or config.get("url") or type_
    t0 = time.time()

    with connect() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            connection_id = _ensure_connection(cur, tenant_id, type_, name, config)
            cur.execute(
                """insert into scans (tenant_id, connection_id, status)
                   values (%s,%s,'running') returning id""",
                (tenant_id, connection_id),
            )
            scan_id = cur.fetchone()[0]

        # COMMIT the connection + scans('running') rows before collecting. This is what makes
        # the claim below true: _ensure_connection's UPDATE takes an exclusive row lock on the
        # connections row, so holding it open across the collect meant a slow or down target
        # blocked every concurrent scan of that connection for the whole collect, kept the
        # session idle-in-transaction, and made 'running' a status no reader could ever
        # observe. The scan is still atomic where atomicity matters: resources, edges,
        # findings, observations and stats all land in the single transaction below.
        conn.commit()

        # Collect OUTSIDE the write transaction: a target that is slow or down must fail the
        # scan cleanly, not hold a write lock.
        try:
            collected: Collected = CONNECTORS[type_](config)
        except Exception as e:
            _mark_scan_error(conn, scan_id, e)
            raise

        try:
            stats = _persist_scan(conn, tenant_id, connection_id, scan_id, config, collected, t0)
        except Exception as e:
            # Everything from here on used to run with the scans row still uncommitted, so ANY
            # persist/detect failure rolled the scan record away and left no in-product signal
            # that scanning had stopped. Only the connector was ever recorded as an error.
            _mark_scan_error(conn, scan_id, e)
            raise

    stats["scan_id"] = str(scan_id)
    stats["connection_id"] = str(connection_id)
    return stats


def _persist_scan(conn, tenant_id: str, connection_id: str, scan_id: str,
                  config: dict, collected: Collected, t0: float) -> dict:
    """The single write transaction: resources, edges, findings, evidence, stats."""
    with conn.cursor() as cur:
        ext_to_id = _persist_resources(cur, tenant_id, connection_id, collected)
        n_edges = _persist_edges(cur, tenant_id, connection_id, collected, ext_to_id)

        ctx = ScanContext(connection_id=connection_id, tenant_id=tenant_id,
                          resources=collected.resources, config=config)
        supps = _active_suppressions(cur, tenant_id)

        n_findings = n_obs = n_suppressed = 0
        errors: list[str] = []

        for d in DETECTORS:
            for r in collected.resources:
                if r.kind not in d.kinds:
                    continue
                try:
                    hits = d.fn(r, ctx) or []
                except Exception as e:
                    # One broken detector must not void an entire scan — record and continue.
                    errors.append(f"{d.rule_id} on {r.ext_id}: {type(e).__name__}: {e}")
                    continue

                if not hits:
                    continue

                # Every Hit in this group shares one fingerprint and therefore ONE findings row.
                # Resolve the row's severity/remediation/detail up front instead of letting the
                # last Hit in list order overwrite the others — see representative().
                fp = fingerprint(tenant_id, connection_id, d.rule_id, r.ext_id)
                suppressed = _is_suppressed(supps, d.rule_id, r)
                rep, severity = representative(hits, d.severity)

                cur.execute(
                    """insert into findings
                         (tenant_id, scan_id, resource_id, rule_id, fingerprint,
                          title, severity, status, remediation, detail)
                       values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       on conflict (tenant_id, fingerprint) do update
                         set last_seen   = now(),
                             scan_id     = excluded.scan_id,
                             severity    = excluded.severity,
                             remediation = excluded.remediation,
                             detail      = excluded.detail,
                             resource_id = excluded.resource_id,
                             -- Suppression state is RE-EVALUATED every scan. Status used
                             -- to be written on INSERT only, which runs exactly once in a
                             -- finding's life — so `expires_at` was a no-op for any
                             -- finding that already existed and a 30-day exception became
                             -- a permanent one. Flips suppressed<->open as suppressions
                             -- come and go, and never touches a status a HUMAN set
                             -- (resolved/triaged/in_progress/accepted).
                             status = case
                               when excluded.status = 'suppressed' then 'suppressed'
                               when findings.status = 'suppressed' then 'open'
                               else findings.status
                             end
                       returning id""",
                    (tenant_id, scan_id, ext_to_id.get(r.ext_id), d.rule_id, fp,
                     d.title, severity, "suppressed" if suppressed else "open",
                     rep.remediation, rep.detail),
                )
                finding_id = cur.fetchone()[0]
                # Counts one findings ROW per (rule, resource), which is what the console shows.
                # It used to count Hits, so a rule that fired on 3 listeners of one broker
                # reported 3 findings against the 1 row it actually wrote.
                n_findings += 1
                n_suppressed += 1 if suppressed else 0

                # The evidence ledger entries — written in the same transaction as the
                # finding they justify, so a finding can never exist uncited. EVERY Hit files
                # its own observation, including the ones the representative outranked.
                for h in hits:
                    cur.execute(
                        """insert into observations (tenant_id, finding_id, resource_id, claim, source_ref)
                           values (%s,%s,%s,%s,%s)""",
                        (tenant_id, finding_id, ext_to_id.get(r.ext_id), h.observation,
                         json.dumps({**h.source_ref, "rule_id": d.rule_id,
                                     "resource": r.ext_id, "scan_id": str(scan_id)})),
                    )
                    n_obs += 1

        stats = {
            "resources": len(collected.resources),
            "edges": n_edges,
            "findings": n_findings,
            "suppressed": n_suppressed,
            "observations": n_obs,
            "detectors_run": len(DETECTORS),
            "duration_ms": int((time.time() - t0) * 1000),
        }
        if errors:
            stats["detector_errors"] = errors

        cur.execute(
            "update scans set status='done', finished_at=now(), stats=%s where id=%s",
            (json.dumps(stats), scan_id),
        )
        cur.execute("update connections set last_scanned_at=now() where id=%s", (connection_id,))
        cur.execute(
            """insert into audit_log (tenant_id, actor, action, target, detail)
               values (%s,'engine','scan.completed',%s,%s)""",
            (tenant_id, str(scan_id), json.dumps(stats)),
        )
    conn.commit()
    return stats
