"""The Time machine (timemachine.py): configuration history from scan snapshots.

Offline, with scripted cursors (the suite's pattern). What is pinned:

  • diff: only real configuration differences are reported; telemetry keys and pure list
    reorders are not; `updated_at` IS (it can be the only evidence a workflow was edited);
    secret-looking values are masked on both sides; long values are truncated.
  • record: a connection's first scan is a baseline and writes nothing; after that, added /
    modified / removed / returned each write one row with the window (prev_seen_at); a stale
    resource that stays absent is not "removed" twice; runtime kinds are ignored.
  • collector path compares labels only (raw never leaves the customer's network).
  • both persist paths in scan.py record changes inside the scan, and a failure in the Time
    machine never voids the scan.
  • as-of status replay from the audit trail.
  • the report says what it cannot prove, and its CSV header is stable.
"""
import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest

from vectasec import timemachine as tm
from vectasec.contracts import Collected, Resource
from vectasec import scan as scan_mod
from vectasec.scan import _persist_scan, persist_pushed

TENANT = "00000000-0000-0000-0000-000000000001"
CONN = "11111111-1111-1111-1111-111111111111"
SCAN = "33333333-3333-3333-3333-333333333333"
T0 = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)


# ═══ diff ══════════════════════════════════════════════════════════════════
def test_diff_reports_changed_added_and_removed_fields():
    out = tm.diff_resource({}, {"auth": "sasl", "tls": True, "old": 1},
                           {}, {"auth": "none", "tls": True, "new": 2})
    assert {(f["path"], json.dumps(f["before"]), json.dumps(f["after"])) for f in out} == {
        ("auth", '"sasl"', '"none"'), ("old", "1", "null"), ("new", "null", "2")}


def test_diff_nested_paths_and_label_prefix():
    out = tm.diff_resource({"exposure": "internal"}, {"listeners": {"ext": {"port": 9092}}},
                           {"exposure": "internet"}, {"listeners": {"ext": {"port": 9093}}})
    assert sorted(f["path"] for f in out) == ["labels.exposure", "listeners.ext.port"]


@pytest.mark.parametrize("key", [
    "last_used_at", "last_seen", "connection_count", "live_client_count", "uptime",
    "messages_ready", "earliest_connected_at", "consumers", "mem_used", "age_days",
    "expires_in_days", "message_stats", "runtime_client_count", "publish_rate",
])
def test_telemetry_keys_are_not_changes(key):
    assert tm.diff_resource({}, {key: 1, "a": 1}, {}, {key: 2, "a": 1}) == []


@pytest.mark.parametrize("key", [
    "updated_at", "modified_at", "last_modified", "last_rotated", "rate_limit", "max_age",
    "max_connections", "partition_count", "timeout_seconds", "memory_limit", "retention_bytes",
])
def test_configuration_keys_are_kept(key):
    out = tm.diff_resource({}, {key: 1}, {}, {key: 2})
    assert [f["path"] for f in out] == [key]


def test_list_reorder_is_not_a_change_but_membership_is():
    assert tm.diff_resource({}, {"scopes": ["a", "b"]}, {}, {"scopes": ["b", "a"]}) == []
    out = tm.diff_resource({}, {"scopes": ["a", "b"]}, {}, {"scopes": ["b", "c"]})
    assert out == [{"path": "scopes", "op": "set", "before": ["a"], "after": ["c"]}]


def test_list_of_named_dicts_is_compared_by_name_not_position():
    old = {"plugins": [{"name": "cors", "enabled": True}, {"name": "key-auth", "enabled": True}]}
    new = {"plugins": [{"name": "key-auth", "enabled": False}, {"name": "cors", "enabled": True}]}
    out = tm.diff_resource({}, old, {}, new)
    assert out == [{"path": "plugins.key-auth.enabled", "before": True, "after": False}]


def test_secret_looking_values_are_masked_on_both_sides():
    out = tm.diff_resource({}, {"api_key": "AAAA", "password": None},
                           {}, {"api_key": "BBBB", "password": None})
    assert len(out) == 1 and out[0]["path"] == "api_key"
    assert "AAAA" not in json.dumps(out) and "BBBB" not in json.dumps(out)
    assert out[0]["before"] != out[0]["after"], "a rotated secret must still read as a change"
    # A null under a secret-looking key is evidence, not a secret: shown as is.
    out = tm.diff_resource({}, {"password": None}, {}, {"password": "hunter2"})
    assert out == [{"path": "password", "before": None, "after": tm.REDACTED}]
    nested = tm.diff_resource({}, {"cfg": {"a": 1}}, {}, {"cfg": [{"token": "zzz"}]})
    assert "zzz" not in json.dumps(nested)


def test_long_values_are_truncated():
    out = tm.diff_resource({}, {"policy": "x" * 1000}, {}, {"policy": "y" * 1000})
    assert len(out[0]["before"]) < 300 and out[0]["before"].endswith("(truncated)")


def test_collector_path_compares_labels_only():
    out = tm.diff_resource({"tls": "true"}, {"a": 1}, {"tls": "false"}, {"a": 2},
                           compare_raw=False)
    assert [f["path"] for f in out] == ["labels.tls"]


# ═══ record_changes ════════════════════════════════════════════════════════
class _Cur:
    def __init__(self, log, previous_rows=(), fail_on=None):
        self.log, self.previous_rows, self.fail_on = log, list(previous_rows), fail_on
        self._one, self._all, self.n = None, [], 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.log.append((s, params))
        if self.fail_on and self.fail_on in s:
            raise RuntimeError("boom")
        self._one, self._all = None, []
        if s.startswith("select ext_id, id, kind, name, labels, raw, stale, last_seen"):
            self._all = list(self.previous_rows)
        elif "returning id" in s:
            self.n += 1
            self._one = (f"id-{self.n}",)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


def _prev(ext_id, kind="topic", labels=None, raw=None, stale=False, last_seen=T0):
    return {ext_id: {"id": f"rid-{ext_id}", "kind": kind, "name": ext_id, "labels": labels or {},
                     "raw": raw or {}, "stale": stale, "last_seen": last_seen}}


def _res(ext_id, kind="topic", labels=None, raw=None):
    return Resource(kind=kind, name=ext_id, ext_id=ext_id, labels=labels or {}, raw=raw or {})


def _changes(log):
    return [p for s, p in log if s.startswith("insert into resource_changes")]


def _record(previous, current, **kw):
    log = []
    stats = tm.record_changes(_Cur(log), TENANT, CONN, SCAN, previous, current,
                              {r.ext_id: f"rid-{r.ext_id}" for r in current}, **kw)
    return stats, _changes(log)


def test_first_scan_is_a_baseline_and_writes_nothing():
    stats, rows = _record({}, [_res("a"), _res("b")])
    assert rows == [] and stats["baseline"] is True


def test_added_modified_removed_and_unchanged():
    previous = {**_prev("same", raw={"x": 1}), **_prev("mod", raw={"auth": "sasl"}),
                **_prev("gone")}
    stats, rows = _record(previous, [_res("same", raw={"x": 1}),
                                     _res("mod", raw={"auth": "none"}), _res("new")])
    by = {r[6]: r for r in rows}          # ext_id -> params
    assert set(by) == {"mod", "new", "gone"}
    assert by["mod"][7] == "modified" and json.loads(by["mod"][8]) == [
        {"path": "auth", "before": "sasl", "after": "none"}]
    assert by["mod"][9] == 1 and by["mod"][11] == T0, "the window opens at the previous sighting"
    assert by["new"][7] == "added" and by["new"][11] == T0
    assert by["gone"][7] == "removed" and by["gone"][2] == "rid-gone"
    assert stats == {"added": 1, "removed": 1, "modified": 1, "returned": 0}


def test_stale_resource_is_not_removed_twice_and_returns_once():
    previous = _prev("ghost", stale=True)
    stats, rows = _record(previous, [_res("other")])
    assert [r[7] for r in rows] == ["added"], "already-stale and still absent: no second 'removed'"
    stats, rows = _record(previous, [_res("ghost")])
    assert [r[7] for r in rows] == ["returned"] and stats["returned"] == 1


def test_telemetry_only_difference_writes_nothing():
    previous = _prev("q", raw={"messages_ready": 1, "durable": True})
    stats, rows = _record(previous, [_res("q", raw={"messages_ready": 900, "durable": True})])
    assert rows == [] and stats["modified"] == 0


def test_runtime_kinds_are_ignored_both_ways():
    previous = {**_prev("c1", kind="runtime_client"), **_prev("t")}
    stats, rows = _record(previous, [_res("t"), _res("c2", kind="runtime_client")])
    assert rows == []


def test_field_cap_keeps_the_true_count():
    previous = _prev("big", raw={f"k{i}": 0 for i in range(100)})
    _, rows = _record(previous, [_res("big", raw={f"k{i}": 1 for i in range(100)})])
    assert len(json.loads(rows[0][8])) == tm.MAX_FIELDS and rows[0][9] == 100


def test_actor_only_where_the_system_exposes_one():
    previous = {**_prev("wf", raw={"active": False}), **_prev("acl", raw={"op": "read"})}
    _, rows = _record(previous, [
        _res("wf", raw={"active": True, "updated_by": {"email": "dev@corp.io"}}),
        _res("acl", raw={"op": "all"})])
    by = {r[6]: r for r in rows}
    assert by["wf"][10] == "dev@corp.io" and by["acl"][10] is None


# ═══ Through the scan paths ════════════════════════════════════════════════
class _Conn:
    def __init__(self, previous_rows=(), fail_on=None):
        self.log, self.committed = [], 0
        self._prev, self._fail = previous_rows, fail_on

    def cursor(self):
        return _Cur(self.log, self._prev, self._fail)

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    from vectasec.compliance import map as compliance
    monkeypatch.setattr(compliance, "evaluate", lambda cur, tenant: {})
    monkeypatch.setattr(scan_mod, "DETECTORS", [])


PREV_ROWS = [("orders", "rid-orders", "topic", "orders", {}, {"acl": "team"}, False, T0)]


def test_local_scan_records_changes_and_reports_them_in_stats():
    conn = _Conn(PREV_ROWS)
    collected = Collected(resources=[_res("orders", raw={"acl": "*"})], edges=[])
    stats = _persist_scan(conn, TENANT, CONN, SCAN, {}, collected, 0.0)
    rows = _changes(conn.log)
    assert [r[7] for r in rows] == ["modified"]
    assert stats["changes"]["modified"] == 1 and conn.committed == 1
    order = [s.split(" ")[0:3] for s, _ in conn.log]
    first_select = next(i for i, (s, _) in enumerate(conn.log) if s.startswith("select ext_id, id"))
    first_upsert = next(i for i, (s, _) in enumerate(conn.log) if s.startswith("insert into resources"))
    assert first_select < first_upsert, "the 'before' must be read before the upsert overwrites it"
    assert order


def test_pushed_scan_records_label_changes_only():
    prev = [("orders", "rid-orders", "topic", "orders", {"tls": "true"}, {}, False, T0)]
    conn = _Conn(prev)
    payload = {"resources": [{"kind": "topic", "name": "orders", "ext_id": "orders",
                              "labels": {"tls": "false"}}], "edges": [], "findings": []}
    stats = persist_pushed(conn, TENANT, CONN, SCAN, payload)
    rows = _changes(conn.log)
    assert len(rows) == 1 and json.loads(rows[0][8])[0]["path"] == "labels.tls"
    assert stats["changes"]["modified"] == 1


def test_a_time_machine_failure_never_voids_the_scan():
    conn = _Conn(PREV_ROWS, fail_on="insert into resource_changes")
    collected = Collected(resources=[_res("orders", raw={"acl": "*"})], edges=[])
    stats = _persist_scan(conn, TENANT, CONN, SCAN, {}, collected, 0.0)
    assert "changes_error" in stats and conn.committed == 1
    assert any(s == "rollback to savepoint tm_record" for s, _ in conn.log)
    assert any(s.startswith("update scans set status='done'") for s, _ in conn.log)


def test_unreadable_previous_state_records_nothing_and_still_scans():
    conn = _Conn(fail_on="select ext_id, id, kind, name, labels, raw, stale, last_seen")
    stats = _persist_scan(conn, TENANT, CONN, SCAN, {},
                          Collected(resources=[_res("orders")], edges=[]), 0.0)
    assert stats["changes_error"] and _changes(conn.log) == [] and conn.committed == 1


# ═══ as-of status replay ═══════════════════════════════════════════════════
def test_status_replay():
    at = T0
    before, after = T0 - timedelta(days=2), T0 + timedelta(days=2)
    # Never touched: what it is now is what it was.
    assert tm._status_at("open", [], at) == "open"
    # Resolved after the date: it was still open on the date.
    assert tm._status_at("resolved", [(after, "finding.status", {"from": "open", "to": "resolved"})], at) == "open"
    # Resolved before the date.
    assert tm._status_at("resolved", [(before, "finding.status", {"from": "open", "to": "resolved"})], at) == "resolved"
    # Verified by a rescan after the date: the audit row names the status it had.
    assert tm._status_at("resolved", [(after, "finding.verified", {"previous_status": "triaged"})], at) == "triaged"
    assert tm._status_at("resolved", [(before, "finding.verified", {"previous_status": "open"})], at) == "resolved"
    # Resolved then reopened, both before: the later one decides.
    ev = [(before, "finding.status", {"from": "open", "to": "resolved"}),
          (before + timedelta(hours=1), "finding.status", {"from": "resolved", "to": "open"})]
    assert tm._status_at("open", ev, at) == "open"


# ═══ report rendering ══════════════════════════════════════════════════════
def _report(changes, truncated=False):
    return {"tenant": "Acme", "since": "2026-10-01T00:00:00+00:00", "until": "2026-11-01T00:00:00+00:00",
            "changes": changes, "counts": {"added": 0, "removed": 0, "modified": len(changes), "returned": 0},
            "truncated": truncated, "findings_opened": [], "status_changes": [], "scans": []}


CHANGE = {"observed_at": "2026-10-20T08:00:00+00:00", "prev_seen_at": "2026-10-19T08:00:00+00:00",
          "system": "n8n", "connection": "prod n8n", "kind": "n8n_workflow", "name": "sync | crm",
          "ext_id": "wf:1", "change": "modified", "field_count": 2, "actor": None,
          "fields": [{"path": "active", "before": False, "after": True},
                     {"path": "labels.webhook", "before": None, "after": "public"}]}


def test_csv_is_one_row_per_field_with_a_stable_header():
    rows = list(csv.reader(io.StringIO(tm.to_changes_csv(_report([CHANGE])))))
    assert rows[0] == ["observed_at", "previous_scan_at", "system", "connection", "kind",
                       "resource", "change", "field", "before", "after", "changed_by"]
    assert len(rows) == 3 and rows[1][7:10] == ["active", "false", "true"]
    assert rows[2][8] == "(not set)" and rows[1][10] == "not exposed by the system"


def test_csv_change_without_fields_is_still_a_row():
    rows = list(csv.reader(io.StringIO(tm.to_changes_csv(
        _report([{**CHANGE, "change": "removed", "fields": [], "field_count": 0}])))))
    assert len(rows) == 2 and rows[1][6] == "removed"


def test_markdown_states_its_limits_and_escapes_tables():
    md = tm.to_changes_markdown(_report([CHANGE]), generated_at="2026-11-01T09:00:00+00:00")
    assert tm.SCOPE_NOTE in md and "not the system's own audit log" in md
    assert "No scan completed in this window" in md, "an empty window must not read as 'nothing changed'"
    assert "### Modified: sync | crm" in md and "| `active` | false | true |" in md
    assert "Changed by: not exposed by the system" in md
    assert tm.to_changes_markdown(_report([CHANGE]), generated_at="x") == \
        tm.to_changes_markdown(_report([CHANGE]), generated_at="x")


def test_author_field_alone_is_not_a_change():
    assert tm.diff_resource({}, {"a": 1, "updated_by": "x"}, {}, {"a": 1}) == []


def test_absent_and_empty_are_the_same_configuration():
    assert tm.diff_resource({}, {"a": 1}, {}, {"a": 1, "principals": []}) == []
    assert tm.diff_resource({}, {"tags": None, "note": ""}, {}, {"tags": {}, "note": None}) == []
    assert tm.diff_resource({}, {"principals": []}, {}, {"principals": ["svc"]}) != []
    assert tm.diff_resource({}, {"enabled": False}, {}, {"enabled": None}) != [], "False is a value, not empty"


def test_a_label_vectasec_starts_computing_is_not_a_change():
    assert tm.diff_resource({"system": "kafka"}, {}, {"system": "kafka", "automation": "false"}, {}) == []
    assert tm.diff_resource({"a": "1"}, {}, {"a": "2"}, {}) != [], "a label that changes value still counts"
    assert tm.diff_resource({}, {"principal": "x"}, {}, {"principal": "x", "automation": False}, derived_raw=True) == []
    assert tm.diff_resource({}, {"acl": "x"}, {}, {"acl": "x", "new_setting": True}) != [], "the system's own config still counts"
