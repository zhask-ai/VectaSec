"""The scan queue worker — the other end of `POST /scans` (STATUS.md gaps 0 and 2).

`POST /scans` (api/main.py) inserts a `scans` row as `'queued'` and, in the *same* transaction,
enqueues a job onto the `pgmq` queue `vectasec_scans`. Nothing consumed that queue, so every
queued scan stayed `queued` forever (gap 2). This module is the consumer.

Two properties this file exists to guarantee:

  • **The queued row is adopted, never orphaned.** The job carries the `scan_id` of the row the
    API already created; we hand it to `run_scan(..., scan_id=...)`, which transitions THAT row
    `queued → running → done`. If the worker opened its own scan row instead, the API's queued
    row would linger as a permanent placeholder — the exact orphan gap 2 warns about.

  • **A crash never wedges the pipeline, and a poison message never loops forever.**
    `pgmq.read` claims a message with a visibility timeout (`vt`): the message is invisible to
    other consumers for `vt` seconds, and becomes visible again if we neither archive nor delete
    it — so a worker that dies mid-scan simply loses its claim and the job is redelivered (at
    least once; run_scan is idempotent by fingerprint, which is what makes that safe — see
    docs/research/supabase-hardening.md §7.5). A job that fails *deterministically* would be
    redelivered forever, so we cap attempts at `MAX_READS` using pgmq's own `read_ct` and archive
    the message once it is exhausted.

And the reaper (gap 0): a scan that is SIGKILL/OOM/evicted mid-collect leaves a durable
`running` row that no in-process handler will ever transition — `run_scan` commits the
`running` row before collecting, on purpose (scan.py). `reap_stuck_scans` ages those out. It is
the worker's job because the worker owns a scan's lifecycle and lease window.

Entry point: `vectasec worker` (cli.py). `load_env()` is called there, not here.
"""
import json
import logging
import time
from typing import NamedTuple, Optional

from .scan import run_scan   # module-level so it is monkeypatchable in tests

log = logging.getLogger(__name__)

# Mirrors api/main.py's QUEUE. Duplicated deliberately: importing api/main pulls in FastAPI and
# uvicorn for a single string, and the worker must not depend on the web layer. If one changes,
# the other must — both name the pgmq queue created in 20260717000002_platform_schema.sql.
QUEUE = "vectasec_scans"

DEFAULT_VT = 600            # visibility timeout (s). > worst-case scan, per hardening doc §7.5.
DEFAULT_QTY = 5             # messages claimed per read.
DEFAULT_POLL_INTERVAL = 5.0  # seconds to sleep when a poll comes back empty.
MAX_READS = 5              # a message read this many times is treated as poison and archived.

# The reaper's marker, written into stats so the console shows WHY a scan ended without a worker.
REAP_ERROR = json.dumps({"error": "reaped: no worker completed within the lease window"})

# pgmq.read returns SETOF pgmq.message_record (msg_id, read_ct, enqueued_at, vt, message, headers);
# we only need the first two and the payload. The 3-arg form resolves — `conditional` defaults.
_READ_SQL = "select msg_id, read_ct, message from pgmq.read(%s, %s, %s)"
_ARCHIVE_SQL = "select pgmq.archive(%s, %s)"

# gap 0's reaper, verbatim intent: only 'running' rows older than the lease window, error marker
# MERGED into existing stats (`||`) rather than overwriting whatever the collector recorded.
_REAP_SQL = """
    update scans
       set status = 'error',
           finished_at = now(),
           stats = coalesce(stats, '{}'::jsonb) || %s::jsonb
     where status = 'running'
       and started_at < now() - interval '1 hour'
    returning id
"""


class InvalidJob(Exception):
    """A queue message that is not the shape POST /scans enqueues. Never becomes valid on
    retry, so a message that raises this is archived immediately rather than redelivered."""


class ClaimedMessage(NamedTuple):
    msg_id: int
    read_ct: int
    message: object   # jsonb payload — a dict once parsed


class Job(NamedTuple):
    """The subset of a queue message the worker acts on, validated. `requested_by` is carried
    for logging only — run_scan does not take it."""
    scan_id: str
    type_: str
    config: dict
    tenant_id: str
    connection_name: Optional[str]
    requested_by: Optional[str]


# ── Pure logic (unit-tested; no DB, no queue) ─────────────────────────────────
def parse_job(message: object) -> Job:
    """Validate one queue payload against the shape POST /scans writes and extract run_scan args.

    Required: scan_id (the row to adopt), type (the connector), tenant_id (scopes the adopt —
    run_scan's UPDATE is `where id=%s and tenant_id=%s`, so a wrong/missing tenant makes the row
    un-adoptable). `config` defaults to {} and `name` is optional: POST /scans always sends both,
    and when `name` is absent run_scan derives it exactly as POST /scans would
    (name or config['bootstrap'] or config['url'] or type), so they still resolve the same
    connection row.
    """
    if isinstance(message, (str, bytes, bytearray)):
        try:
            message = json.loads(message)
        except (ValueError, TypeError) as e:
            raise InvalidJob(f"message is not valid JSON: {e}")
    if not isinstance(message, dict):
        raise InvalidJob(f"message is not a JSON object: {type(message).__name__}")

    missing = [f for f in ("scan_id", "type", "tenant_id") if not message.get(f)]
    if missing:
        raise InvalidJob(f"message missing required field(s): {missing}")

    config = message.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        raise InvalidJob(f"config must be an object, got {type(config).__name__}")

    name = message.get("name")
    return Job(
        scan_id=str(message["scan_id"]),
        type_=str(message["type"]),
        config=config,
        tenant_id=str(message["tenant_id"]),
        connection_name=str(name) if name else None,
        requested_by=(str(message["requested_by"]) if message.get("requested_by") else None),
    )


def is_poison(read_ct: int, max_reads: int = MAX_READS) -> bool:
    """After a failed attempt, whether to give up on the message (archive) rather than leave it
    for redelivery. pgmq returns the post-increment read_ct (first delivery == 1), so
    `read_ct >= max_reads` caps total attempts at max_reads."""
    return read_ct >= max_reads


# ── DB helpers (thin; the worker connection drives pgmq + the reaper) ──────────
def _commit_if_needed(conn) -> None:
    # The worker runs its connection autocommit=True, so each pgmq call is its own atomic op and
    # a claimed message's invisibility persists immediately. Kept tolerant so a non-autocommit
    # connection (e.g. a test fake) still commits.
    if not getattr(conn, "autocommit", False):
        conn.commit()


def read_batch(conn, vt: int = DEFAULT_VT, qty: int = DEFAULT_QTY) -> list[ClaimedMessage]:
    with conn.cursor() as cur:
        cur.execute(_READ_SQL, (QUEUE, vt, qty))
        rows = cur.fetchall()
    _commit_if_needed(conn)
    return [ClaimedMessage(msg_id=r[0], read_ct=r[1], message=r[2]) for r in rows]


def archive(conn, msg_id: int) -> None:
    """Archive (not delete): pgmq.a_vectasec_scans is a durable record of what was scanned and
    when, which feeds the audit/compliance story (hardening doc §7.5)."""
    with conn.cursor() as cur:
        cur.execute(_ARCHIVE_SQL, (QUEUE, msg_id))
    _commit_if_needed(conn)


def _safe_archive(conn, msg_id: int) -> bool:
    """Archive, never raising. A failed archive is not fatal: the message simply keeps its claim,
    reappears after vt, and is reprocessed — run_scan is idempotent (fingerprint dedup), so a
    re-run is harmless. What must not happen is a failed archive taking down the loop."""
    try:
        archive(conn, msg_id)
        return True
    except Exception:
        log.exception("msg %s: archive failed; it will be redelivered after vt", msg_id)
        return False


def reap_stuck_scans(conn) -> int:
    """Age out scans stuck in 'running' past the lease window (gap 0). Returns the count reaped.

    A crash between run_scan's `commit` of the 'running' row and its final 'done'/'error' write
    leaves a row no in-process handler will transition. This is the only thing that does.
    """
    with conn.cursor() as cur:
        cur.execute(_REAP_SQL, (REAP_ERROR,))
        reaped = cur.fetchall()
    _commit_if_needed(conn)
    n = len(reaped)
    if n:
        log.warning("reaped %d stuck 'running' scan(s) past the lease window", n)
    return n


# ── One message ───────────────────────────────────────────────────────────────
def process_message(conn, msg: ClaimedMessage, max_reads: int = MAX_READS) -> str:
    """Run one scan from one claimed message. Returns an outcome tag for logging/tests.

    Never raises: one bad message must not kill the loop, so every failure mode ends in a return.
    On success the message is archived; on a malformed payload it is archived immediately (it
    will never become valid); on a scan failure it is left for redelivery until read_ct exhausts
    `max_reads`, then archived as poison. run_scan records the scans row's own error state via
    its _mark_scan_error — the worker owns only queue hygiene here.
    """
    try:
        job = parse_job(msg.message)
    except InvalidJob as e:
        log.error("msg %s: invalid job, archiving (unrunnable): %s", msg.msg_id, e)
        _safe_archive(conn, msg.msg_id)
        return "invalid"

    try:
        # SystemExit is run_scan's domain error (no such connector / scan not found for tenant)
        # and is NOT an Exception — catch it explicitly so it cannot escape and stop the worker.
        stats = run_scan(job.type_, job.config, tenant_id=job.tenant_id,
                         connection_name=job.connection_name, scan_id=job.scan_id)
    except (Exception, SystemExit) as e:
        if is_poison(msg.read_ct, max_reads):
            log.error("msg %s scan %s: failed %d time(s), archiving as poison: %s",
                      msg.msg_id, job.scan_id, msg.read_ct, e)
            _safe_archive(conn, msg.msg_id)
            return "poison"
        log.warning("msg %s scan %s: failed (attempt %d/%d), leaving for redelivery: %s",
                    msg.msg_id, job.scan_id, msg.read_ct, max_reads, e)
        return "retry"

    _safe_archive(conn, msg.msg_id)
    log.info("msg %s scan %s: done — %s findings, %s resources, %sms",
             msg.msg_id, job.scan_id, stats.get("findings"), stats.get("resources"),
             stats.get("duration_ms"))
    return "done"


# ── The loop ──────────────────────────────────────────────────────────────────
def run_worker(*, once: bool = False, reap_only: bool = False,
               vt: int = DEFAULT_VT, qty: int = DEFAULT_QTY,
               poll_interval: float = DEFAULT_POLL_INTERVAL,
               max_reads: int = MAX_READS) -> None:
    """Drain `vectasec_scans` until stopped.

    once      — drain everything currently visible, then return (for tests/CI).
    reap_only — run the stuck-scan reaper once and return; touch no queue message.

    The reaper runs once per loop iteration (gap 0). Between empty polls the loop sleeps.
    """
    from .db import connect

    with connect() as conn:
        conn.autocommit = True

        if reap_only:
            reap_stuck_scans(conn)
            return

        log.info("worker started: queue=%s vt=%ss qty=%d poll=%ss max_reads=%d%s",
                 QUEUE, vt, qty, poll_interval, max_reads, " (once)" if once else "")
        try:
            while True:
                reap_stuck_scans(conn)

                batch = read_batch(conn, vt, qty)
                if not batch:
                    if once:
                        log.info("queue drained; exiting (--once)")
                        return
                    time.sleep(poll_interval)
                    continue

                for msg in batch:
                    # process_message is written not to raise, but the loop guards it anyway:
                    # one surprising message must never stop the worker (the whole point of the
                    # queue is that failures are isolated and redelivered).
                    try:
                        process_message(conn, msg, max_reads)
                    except Exception:
                        log.exception("msg %s: unexpected error; leaving for redelivery", msg.msg_id)
                # loop straight back to drain the next batch without sleeping.
        except KeyboardInterrupt:
            log.info("worker stopping (interrupted)")
