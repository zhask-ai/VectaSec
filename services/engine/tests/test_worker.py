"""Unit tests for the scan queue worker. Offline: no DB, no live queue, no target.

The worker is the consumer half of `POST /scans` (STATUS.md gaps 0, 2). The three decisions
worth pinning, because a wrong one silently breaks the scan pipeline rather than erroring loudly:

  • parse_job() — it must read EXACTLY the message shape api/main.py enqueues. A field the API
    sends that the worker ignores (or requires and the API omits) means every queued scan fails
    or adopts the wrong row. Pinned against that literal shape here.
  • is_poison() — the retry cap. Too eager and a transient target blip discards a real scan; too
    lax and a deterministically-broken job is redelivered forever, pinning a worker on it.
  • reap_stuck_scans() — the SQL that ages out crashed 'running' scans. It must touch ONLY
    'running' rows past the lease window and MERGE its marker into stats, never overwrite them.

The DB is a fake cursor/conn that records what was executed; run_scan is monkeypatched. Nothing
here stands up Postgres or pgmq.
"""
import json

import pytest

from vectasec import worker
from vectasec.worker import (
    InvalidJob,
    Job,
    ClaimedMessage,
    MAX_READS,
    REAP_ERROR,
    is_poison,
    parse_job,
    process_message,
    reap_stuck_scans,
)

TENANT = "00000000-0000-0000-0000-000000000001"
SCAN_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def api_message(**overrides) -> dict:
    """The exact shape api/main.py's POST /scans puts on the queue (lines 191-192):

        {"scan_id": str, "type": str, "config": dict,
         "tenant_id": str, "name": str, "requested_by": str}
    """
    msg = {
        "scan_id": SCAN_ID,
        "type": "kafka",
        "config": {"bootstrap": "localhost:9092"},
        "tenant_id": TENANT,
        "name": "localhost:9092",
        "requested_by": "tester@example.com",
    }
    msg.update(overrides)
    return msg


# ═══ parse_job ════════════════════════════════════════════════════════════════
def test_parse_job_reads_the_api_message_shape():
    """A well-formed message maps 1:1 onto run_scan's parameters."""
    job = parse_job(api_message())
    assert isinstance(job, Job)
    assert job.scan_id == SCAN_ID
    assert job.type_ == "kafka"
    assert job.config == {"bootstrap": "localhost:9092"}
    assert job.tenant_id == TENANT
    assert job.connection_name == "localhost:9092"
    assert job.requested_by == "tester@example.com"


def test_parse_job_accepts_a_json_string_payload():
    """pgmq/psycopg hands back a parsed dict, but a str payload must not crash the worker."""
    job = parse_job(json.dumps(api_message()))
    assert job.scan_id == SCAN_ID
    assert job.type_ == "kafka"


@pytest.mark.parametrize("drop", ["scan_id", "type", "tenant_id"])
def test_parse_job_requires_the_adoptable_fields(drop):
    """scan_id (the row to adopt), type (the connector) and tenant_id (which scopes run_scan's
    adopt UPDATE) are all mandatory — without them the queued row cannot be adopted at all."""
    msg = api_message()
    del msg[drop]
    with pytest.raises(InvalidJob) as e:
        parse_job(msg)
    assert drop in str(e.value)


@pytest.mark.parametrize("blank", ["", None])
def test_parse_job_rejects_blank_required_fields(blank):
    with pytest.raises(InvalidJob):
        parse_job(api_message(scan_id=blank))


def test_parse_job_defaults_absent_config_to_empty_dict():
    """config is recoverable — POST /scans always sends it, but an absent one is {} not a crash."""
    msg = api_message()
    del msg["config"]
    assert parse_job(msg).config == {}


def test_parse_job_defaults_null_config_to_empty_dict():
    assert parse_job(api_message(config=None)).config == {}


def test_parse_job_rejects_non_object_config():
    with pytest.raises(InvalidJob):
        parse_job(api_message(config=["not", "an", "object"]))


def test_parse_job_name_is_optional():
    """When name is absent, run_scan derives it exactly as POST /scans would, so the worker
    passes None through rather than guessing — see parse_job's docstring."""
    msg = api_message()
    del msg["name"]
    assert parse_job(msg).connection_name is None


def test_parse_job_requested_by_is_optional():
    msg = api_message()
    del msg["requested_by"]
    assert parse_job(msg).requested_by is None


@pytest.mark.parametrize("bad", ["not json {", "[1,2,3]", "42", '"a string"'])
def test_parse_job_rejects_non_object_payloads(bad):
    with pytest.raises(InvalidJob):
        parse_job(bad)


def test_parse_job_rejects_non_dict_non_str():
    with pytest.raises(InvalidJob):
        parse_job(12345)


# ═══ is_poison (the retry cap) ════════════════════════════════════════════════
def test_is_poison_boundary_is_at_max_reads():
    """pgmq returns the post-increment read_ct (first delivery == 1), so the message is attempted
    exactly MAX_READS times and archived on the MAX_READS-th failure."""
    assert MAX_READS == 5
    assert is_poison(1) is False
    assert is_poison(4) is False
    assert is_poison(5) is True       # the cap the task specifies: read_ct >= 5
    assert is_poison(6) is True


def test_is_poison_respects_a_custom_cap():
    assert is_poison(2, max_reads=3) is False
    assert is_poison(3, max_reads=3) is True


# ═══ reap_stuck_scans (the SQL) ═══════════════════════════════════════════════
class FakeCursor:
    """Records executed (sql, params) and replays canned results positionally."""

    def __init__(self, results=None):
        self.executed: list = []
        self._results = list(results or [])
        self._last: list = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        self._last = self._results.pop(0) if self._results else []

    def fetchall(self):
        return self._last

    def fetchone(self):
        return self._last[0] if self._last else None


class FakeConn:
    def __init__(self, results=None, autocommit=True):
        self.autocommit = autocommit
        self.cur = FakeCursor(results)
        self.commits = 0

    def cursor(self):
        return self.cur

    def commit(self):
        self.commits += 1


def test_reap_targets_only_stale_running_rows_and_merges_stats():
    """The reap UPDATE must: set status='error', filter status='running' AND started_at past the
    one-hour lease window, and MERGE (`||`) its marker into existing stats rather than clobber."""
    conn = FakeConn(results=[[("id-1",), ("id-2",)]])   # RETURNING two reaped rows

    n = reap_stuck_scans(conn)

    assert n == 2, "returns the count of rows reaped (RETURNING length)"
    sql, params = conn.cur.executed[0]
    low = " ".join(sql.split()).lower()
    assert "update scans" in low
    assert "status = 'error'" in low
    assert "finished_at = now()" in low
    assert "where status = 'running'" in low
    assert "started_at < now() - interval '1 hour'" in low
    assert "coalesce(stats, '{}'::jsonb) ||" in low, "must merge, not overwrite, existing stats"
    assert params == (REAP_ERROR,)


def test_reap_marker_is_a_reaped_error_object():
    payload = json.loads(REAP_ERROR)
    assert "reaped" in payload["error"]


def test_reap_returns_zero_when_nothing_is_stuck():
    conn = FakeConn(results=[[]])
    assert reap_stuck_scans(conn) == 0


def test_reap_commits_when_connection_is_not_autocommit():
    conn = FakeConn(results=[[("id-1",)]], autocommit=False)
    reap_stuck_scans(conn)
    assert conn.commits == 1, "a non-autocommit connection must be committed explicitly"


# ═══ process_message (archive-on-success / poison / retry, run_scan stubbed) ═══
def _msg(read_ct=1, message=None):
    return ClaimedMessage(msg_id=99, read_ct=read_ct, message=message or api_message())


def test_process_message_success_adopts_scan_and_archives(monkeypatch):
    """The happy path: run_scan is called with the queued scan_id (adoption, not a new row), and
    the message is archived exactly once on success."""
    calls = {}

    def fake_run_scan(type_, config, tenant_id=None, connection_name=None, scan_id=None):
        calls.update(type_=type_, config=config, tenant_id=tenant_id,
                     connection_name=connection_name, scan_id=scan_id)
        return {"findings": 7, "resources": 3, "duration_ms": 12}

    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    archived = []
    monkeypatch.setattr(worker, "archive", lambda conn, msg_id: archived.append(msg_id))

    outcome = process_message(FakeConn(), _msg())

    assert outcome == "done"
    assert calls["scan_id"] == SCAN_ID, "the queued row must be ADOPTED, not orphaned"
    assert calls["type_"] == "kafka"
    assert calls["tenant_id"] == TENANT
    assert calls["connection_name"] == "localhost:9092"
    assert archived == [99]


def test_process_message_invalid_payload_is_archived_immediately(monkeypatch):
    """A malformed message never becomes valid, so it is archived at once — not retried, and
    run_scan is never called."""
    called = False

    def fake_run_scan(*a, **k):
        nonlocal called
        called = True

    monkeypatch.setattr(worker, "run_scan", fake_run_scan)
    archived = []
    monkeypatch.setattr(worker, "archive", lambda conn, msg_id: archived.append(msg_id))

    outcome = process_message(FakeConn(), _msg(message={"type": "kafka"}))  # no scan_id/tenant

    assert outcome == "invalid"
    assert called is False
    assert archived == [99]


def test_process_message_failure_below_cap_is_left_for_redelivery(monkeypatch):
    """A failing scan under the cap is NOT archived: leaving it lets vt expire and pgmq redeliver
    it. run_scan's own _mark_scan_error records the scans row; the worker only decides queue fate."""
    def boom(*a, **k):
        raise RuntimeError("target unreachable")

    monkeypatch.setattr(worker, "run_scan", boom)
    archived = []
    monkeypatch.setattr(worker, "archive", lambda conn, msg_id: archived.append(msg_id))

    outcome = process_message(FakeConn(), _msg(read_ct=1))

    assert outcome == "retry"
    assert archived == [], "must leave the message for redelivery, not archive it"


def test_process_message_failure_at_cap_is_archived_as_poison(monkeypatch):
    """At read_ct == MAX_READS a persistently-failing job is archived so it cannot loop forever."""
    monkeypatch.setattr(worker, "run_scan",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("still broken")))
    archived = []
    monkeypatch.setattr(worker, "archive", lambda conn, msg_id: archived.append(msg_id))

    outcome = process_message(FakeConn(), _msg(read_ct=MAX_READS))

    assert outcome == "poison"
    assert archived == [99]


def test_process_message_swallows_systemexit_from_run_scan(monkeypatch):
    """run_scan raises SystemExit for 'no such connector' / 'scan not found for tenant'. SystemExit
    is NOT an Exception, so if the worker did not catch it explicitly it would kill the loop."""
    def sysexit(*a, **k):
        raise SystemExit("no connector registered for type 'bogus'")

    monkeypatch.setattr(worker, "run_scan", sysexit)
    monkeypatch.setattr(worker, "archive", lambda conn, msg_id: None)

    # Must return an outcome, not propagate SystemExit.
    outcome = process_message(FakeConn(), _msg(read_ct=1))
    assert outcome == "retry"


def test_process_message_never_raises_even_when_archive_fails(monkeypatch):
    """A failed archive on the SUCCESS path must not propagate: the scan completed, and the
    message will simply be redelivered and re-archived (run_scan is idempotent). If this raised,
    it would take down the loop even though the scan itself succeeded."""
    monkeypatch.setattr(worker, "run_scan", lambda *a, **k: {"findings": 0, "resources": 1})

    def bad_archive(conn, msg_id):
        raise RuntimeError("queue write failed")

    monkeypatch.setattr(worker, "archive", bad_archive)

    # Must not raise despite archive throwing on the happy path.
    outcome = process_message(FakeConn(), _msg(read_ct=1))
    assert outcome == "done"
