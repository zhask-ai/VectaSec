"""The Verify loop: POST /findings/{id}/verify marks a finding, the next successful scan of
its connection settles it (scan._settle_verifications), GET /findings/{id}/fix shows the fix.

Offline, with scripted cursors (the suite's pattern: tests/test_scan.py's _FakeConn for the
persist path, tests/test_rbac.py's _patch_conn_db for endpoints). What is pinned:

  • verify-requested + NOT re-emitted  -> resolved, verified_at, verified_scan_id, audit
    'finding.verified', stats["verified"] == 1.
  • verify-requested + re-emitted      -> status untouched, request cleared, audit
    'finding.verify_failed', stats["verify_failed"] == 1.
  • never requested + vanished          -> nothing happens. The settle query itself filters on
    verify_requested_at, so the existing "stale, not resolved" behaviour is preserved by
    construction, and no UPDATE of findings.status is ever issued for such rows.
  • a failed persist never reaches the settle step.
  • both persist paths (local and collector-pushed) run the same settle.
  • GET /fix: fix for a known rule, null fix + free text for an unknown one.
  • POST /verify: 202 with the queued scan; 409 with the in-flight scan id and NO update.
"""
import json

import pytest
from fastapi.testclient import TestClient

from vectasec.api import main as api_main
from vectasec.api.main import app
from vectasec.contracts import Collected, Hit, Resource
from vectasec.registry import DetectorDef
from vectasec import scan as scan_mod
from vectasec.scan import _persist_scan, _settle_verifications, fingerprint, persist_pushed

TENANT = "00000000-0000-0000-0000-000000000001"
CONN = "11111111-1111-1111-1111-111111111111"
SCAN = "33333333-3333-3333-3333-333333333333"
FINDING = "44444444-4444-4444-4444-444444444444"
EDITOR = "00000000-0000-0000-0000-0000000000a2"
VIEWER = "00000000-0000-0000-0000-0000000000a1"
RULE = "KAFKA.LISTENER.PLAINTEXT"


# ═══ A scripted connection for the persist paths ══════════════════════════
class _Cur:
    def __init__(self, state):
        self.s = state
        self._one = None
        self._all = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.s["log"].append((s, params))
        if self.s.get("fail_on") and self.s["fail_on"] in s:
            raise RuntimeError("boom")
        self._one, self._all = None, []
        if "from findings f join resources r" in s and "verify_requested_at is not null" in s:
            self._all = list(self.s["pending"])
        elif "returning id" in s:
            self.s["n"] += 1
            self._one = (f"id-{self.s['n']}",)

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class _Conn:
    def __init__(self, pending=(), fail_on=None):
        self.state = {"log": [], "pending": list(pending), "n": 0, "fail_on": fail_on}
        self.committed = 0

    def cursor(self):
        return _Cur(self.state)

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass

    @property
    def log(self):
        return self.state["log"]


def _status_updates(log):
    return [(s, p) for s, p in log if s.startswith("update findings") and "status = 'resolved'" in s]


def _clear_only_updates(log):
    return [(s, p) for s, p in log
            if s.startswith("update findings set verify_requested_at = null")]


def _audits(log, action):
    """(tenant, action, target, detail) param tuples; the actor 'engine' is inline in the SQL."""
    out = []
    for s, p in log:
        if s.startswith("insert into audit_log") and p and action in p:
            assert "'engine'" in s, "the scan loop audits as the engine, never as a user"
            out.append(p)
    return out


@pytest.fixture(autouse=True)
def _no_compliance(monkeypatch):
    """compliance.evaluate is SQL-heavy and not under test here."""
    from vectasec.compliance import map as compliance
    monkeypatch.setattr(compliance, "evaluate", lambda cur, tenant: {})


def _detector_emitting(rule_id=RULE):
    return DetectorDef(("broker",), rule_id, "high", "t", lambda r, ctx: [Hit(observation="obs")])


def _collected():
    return Collected(resources=[Resource(kind="broker", name="b1", ext_id="b1")])


# ═══ _settle_verifications, directly ══════════════════════════════════════
def test_requested_and_gone_is_resolved_with_the_proving_scan():
    gone = fingerprint(TENANT, CONN, "KAFKA.AUTHZ.NO_AUTHORIZER", "b1")
    conn = _Conn(pending=[("f1", gone, "KAFKA.AUTHZ.NO_AUTHORIZER", "open", EDITOR)])
    with conn.cursor() as cur:
        stats = _settle_verifications(cur, TENANT, CONN, SCAN, emitted={"other"})
    assert stats == {"verified": 1, "verify_failed": 0}
    ups = _status_updates(conn.log)
    assert len(ups) == 1
    s, p = ups[0]
    assert "verified_at = now()" in s and "verified_scan_id = %s" in s and "verify_requested_at = null" in s
    assert p == (SCAN, "f1", TENANT)
    aud = _audits(conn.log, "finding.verified")
    assert len(aud) == 1 and aud[0][1] == "finding.verified" and aud[0][2] == "f1"
    detail = json.loads(aud[0][3])
    assert detail["scan_id"] == SCAN and detail["previous_status"] == "open"
    assert detail["requested_by"] == EDITOR


def test_requested_and_still_emitted_clears_the_request_but_keeps_status():
    fp = fingerprint(TENANT, CONN, RULE, "b1")
    conn = _Conn(pending=[("f1", fp, RULE, "in_progress", None)])
    with conn.cursor() as cur:
        stats = _settle_verifications(cur, TENANT, CONN, SCAN, emitted={fp})
    assert stats == {"verified": 0, "verify_failed": 1}
    assert _status_updates(conn.log) == []
    clears = _clear_only_updates(conn.log)
    assert len(clears) == 1 and clears[0][1] == ("f1", TENANT)
    assert "status" not in clears[0][0]
    aud = _audits(conn.log, "finding.verify_failed")
    assert len(aud) == 1 and json.loads(aud[0][3])["previous_status"] == "in_progress"
    assert _audits(conn.log, "finding.verified") == []


def test_the_pending_query_only_selects_requested_unremediated_findings():
    """The 'never auto-resolve' guarantee lives in the WHERE clause: a vanished finding nobody
    asked about is never even read, let alone updated."""
    conn = _Conn()
    with conn.cursor() as cur:
        stats = _settle_verifications(cur, TENANT, CONN, SCAN, emitted=set())
    assert stats == {"verified": 0, "verify_failed": 0}
    sel, params = conn.log[0]
    assert "verify_requested_at is not null" in sel
    assert "f.status = any(%s)" in sel
    assert params[2] == ["open", "triaged", "in_progress", "accepted"]
    assert "r.connection_id = %s" in sel and params[1] == CONN
    assert len(conn.log) == 1, "no pending rows -> no writes at all"


# ═══ Through _persist_scan (local path) ═══════════════════════════════════
def test_persist_scan_resolves_a_requested_finding_the_detectors_no_longer_emit(monkeypatch):
    monkeypatch.setattr(scan_mod, "DETECTORS", [_detector_emitting(RULE)])
    gone = fingerprint(TENANT, CONN, "KAFKA.AUTHZ.NO_AUTHORIZER", "b1")
    conn = _Conn(pending=[("f-old", gone, "KAFKA.AUTHZ.NO_AUTHORIZER", "triaged", EDITOR)])
    stats = _persist_scan(conn, TENANT, CONN, SCAN, {}, _collected(), t0=0.0)
    assert stats["findings"] == 1 and stats["verified"] == 1 and stats["verify_failed"] == 0
    assert len(_status_updates(conn.log)) == 1
    assert _audits(conn.log, "finding.verified")
    # the settle ran inside the transaction, before the scan row went 'done' and before COMMIT
    idx_settle = next(i for i, (s, _) in enumerate(conn.log) if "status = 'resolved'" in s)
    idx_done = next(i for i, (s, _) in enumerate(conn.log) if s.startswith("update scans set status='done'"))
    assert idx_settle < idx_done
    assert conn.committed == 1
    # ...and the recorded stats carry the counts
    done_stats = json.loads(next(p for s, p in conn.log if s.startswith("update scans set status='done'"))[0])
    assert done_stats["verified"] == 1 and done_stats["verify_failed"] == 0


def test_persist_scan_fails_verification_of_a_finding_that_is_re_emitted(monkeypatch):
    monkeypatch.setattr(scan_mod, "DETECTORS", [_detector_emitting(RULE)])
    fp = fingerprint(TENANT, CONN, RULE, "b1")
    conn = _Conn(pending=[("f-same", fp, RULE, "open", EDITOR)])
    stats = _persist_scan(conn, TENANT, CONN, SCAN, {}, _collected(), t0=0.0)
    assert stats["verified"] == 0 and stats["verify_failed"] == 1
    assert _status_updates(conn.log) == []
    assert len(_clear_only_updates(conn.log)) == 1
    assert _audits(conn.log, "finding.verify_failed")


def test_persist_scan_leaves_never_requested_vanished_findings_alone(monkeypatch):
    """A fingerprint that stopped being emitted and was never verify-requested: the existing
    behaviour (resource stale=true, finding untouched) must not change."""
    monkeypatch.setattr(scan_mod, "DETECTORS", [])            # nothing emitted at all
    conn = _Conn(pending=[])                                   # nothing requested
    stats = _persist_scan(conn, TENANT, CONN, SCAN, {}, _collected(), t0=0.0)
    assert stats["findings"] == 0 and stats["verified"] == 0 and stats["verify_failed"] == 0
    assert not any(s.startswith("update findings") for s, _ in conn.log)
    assert any(s.startswith("update resources set stale = true") for s, _ in conn.log)
    assert not any("finding." in (p[1] if p and len(p) > 1 else "") for s, p in conn.log
                   if s.startswith("insert into audit_log"))


def test_a_failed_persist_never_reaches_the_settle_step(monkeypatch):
    monkeypatch.setattr(scan_mod, "DETECTORS", [_detector_emitting(RULE)])
    gone = fingerprint(TENANT, CONN, "KAFKA.AUTHZ.NO_AUTHORIZER", "b1")
    conn = _Conn(pending=[("f-old", gone, "KAFKA.AUTHZ.NO_AUTHORIZER", "open", EDITOR)],
                 fail_on="insert into findings")
    with pytest.raises(RuntimeError):
        _persist_scan(conn, TENANT, CONN, SCAN, {}, _collected(), t0=0.0)
    assert _status_updates(conn.log) == []
    assert not any("verify_requested_at is not null" in s for s, _ in conn.log)
    assert conn.committed == 0


# ═══ Through persist_pushed (collector path) ══════════════════════════════
def _payload(rule_id=RULE):
    return {
        "resources": [{"kind": "broker", "name": "b1", "ext_id": "b1", "labels": {}}],
        "edges": [],
        "findings": [{"rule_id": rule_id, "fingerprint": fingerprint(TENANT, CONN, rule_id, "b1"),
                      "resource_ext_id": "b1", "title": "t", "severity": "high",
                      "remediation": "", "detail": "", "observation": "obs", "source_ref": {}}],
        "stats": {},
    }


def test_persist_pushed_resolves_like_the_local_path():
    gone = fingerprint(TENANT, CONN, "KAFKA.AUTHZ.NO_AUTHORIZER", "b1")
    conn = _Conn(pending=[("f-old", gone, "KAFKA.AUTHZ.NO_AUTHORIZER", "accepted", None)])
    stats = persist_pushed(conn, TENANT, CONN, SCAN, _payload())
    assert stats["verified"] == 1 and stats["verify_failed"] == 0
    assert len(_status_updates(conn.log)) == 1
    assert json.loads(_audits(conn.log, "finding.verified")[0][3])["previous_status"] == "accepted"


def test_persist_pushed_fails_verification_when_the_collector_re_emits():
    fp = fingerprint(TENANT, CONN, RULE, "b1")
    conn = _Conn(pending=[("f-same", fp, RULE, "open", None)])
    stats = persist_pushed(conn, TENANT, CONN, SCAN, _payload(RULE))
    assert stats["verified"] == 0 and stats["verify_failed"] == 1
    assert _status_updates(conn.log) == []
    assert _audits(conn.log, "finding.verify_failed")


# ═══ API ══════════════════════════════════════════════════════════════════
ROLES = {VIEWER: "viewer", EDITOR: "analyst"}


@pytest.fixture(autouse=True)
def _service_auth(monkeypatch):
    monkeypatch.setenv("VECTASEC_ENGINE_TOKEN", "svc-secret")
    monkeypatch.delenv("VECTASEC_DEV_TRUST_HEADERS", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(api_main, "_role_for_actor", lambda tenant, actor: ROLES.get(actor))


def h(actor: str) -> dict:
    return {"Authorization": "Bearer svc-secret",
            "X-VectaSec-Tenant": TENANT, "X-VectaSec-Actor": actor}


client = TestClient(app)


def _api_db(monkeypatch, *, finding_row=None, connection_row=None, inflight=None):
    state = {"updates": [], "audits": [], "scans": [], "pgmq": [], "committed": False}

    class Cur:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def execute(self, sql, params=()):
            s = " ".join(sql.split())
            self._one = None
            if s.startswith("select f.rule_id, f.remediation"):
                self._one = finding_row
            elif s.startswith("select f.status, r.connection_id"):
                assert "for update of f" in s
                self._one = finding_row
            elif s.startswith("select type, name, config, mode from connections"):
                self._one = connection_row
            elif s.startswith("select id from scans where") and "status in ('queued','running')" in s:
                self._one = inflight
            elif s.startswith("update findings set verify_requested_at = now()"):
                state["updates"].append(params)
            elif s.startswith("insert into scans"):
                state["scans"].append(params)
                self._one = ("55555555-5555-5555-5555-555555555555",)
            elif "pgmq.send" in s:
                state["pgmq"].append(json.loads(params[1]))
                self._one = (42,)
            elif s.startswith("insert into audit_log"):
                state["audits"].append(params)
            else:
                raise AssertionError(f"unexpected SQL: {s}")

        def fetchone(self):
            return self._one

    class Conn:
        autocommit = False

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def cursor(self):
            return Cur()

        def commit(self):
            state["committed"] = True

    monkeypatch.setattr(api_main, "_db", lambda: Conn())
    return state


def test_get_fix_returns_a_templated_fix_for_a_known_rule(monkeypatch):
    _api_db(monkeypatch, finding_row=(
        "KONG.ROUTE.NO_AUTH_PLUGIN", "Attach an auth plugin.", None, None, None,
        {"protocols": "http,https"}, {}, "checkout", "kong-route-abc123", None))
    res = client.get(f"/findings/{FINDING}/fix", headers=h(VIEWER))
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["finding_id"] == FINDING and body["rule_id"] == "KONG.ROUTE.NO_AUTH_PLUGIN"
    assert body["remediation"] == "Attach an auth plugin."
    assert body["fix"]["summary"]
    assert "/routes/abc123/plugins" in body["fix"]["snippets"][0]["body"]
    assert body["verify"] == {"requested_at": None, "verified_at": None, "verified_scan_id": None}


def test_get_fix_returns_null_fix_and_the_free_text_for_an_unknown_rule(monkeypatch):
    _api_db(monkeypatch, finding_row=(
        "SOLACE.SOMETHING.UNMAPPED", "Do the thing by hand.", "2026-10-17T10:00:00+00:00",
        None, None, {}, {}, "x", "x", None))
    res = client.get(f"/findings/{FINDING}/fix", headers=h(VIEWER))
    assert res.status_code == 200
    body = res.json()
    assert body["fix"] is None
    assert body["remediation"] == "Do the thing by hand."
    assert body["verify"]["requested_at"] == "2026-10-17T10:00:00+00:00"


def test_get_fix_404_for_an_unknown_finding(monkeypatch):
    _api_db(monkeypatch, finding_row=None)
    assert client.get(f"/findings/{FINDING}/fix", headers=h(VIEWER)).status_code == 404


def test_post_verify_queues_a_scan_and_marks_the_finding(monkeypatch):
    state = _api_db(monkeypatch, finding_row=("open", CONN),
                    connection_row=("kafka", "prod", {"bootstrap": "b:9092"}, "cloud"),
                    inflight=None)
    res = client.post(f"/findings/{FINDING}/verify", headers=h(EDITOR))
    assert res.status_code == 202, res.text
    assert res.json() == {"finding_id": FINDING, "connection_id": CONN,
                          "scan_id": "55555555-5555-5555-5555-555555555555"}
    assert len(state["updates"]) == 1
    requested_by, fid, tenant = state["updates"][0]
    assert str(requested_by) == EDITOR and fid == FINDING and tenant == TENANT
    # queued exactly like POST /connections/{id}/scan: scans row + pgmq job in worker shape
    assert state["scans"] == [(TENANT, CONN)]
    job = state["pgmq"][0]
    assert job["scan_id"] == "55555555-5555-5555-5555-555555555555"
    assert job["type"] == "kafka" and job["config"] == {"bootstrap": "b:9092"}
    assert job["tenant_id"] == TENANT and job["name"] == "prod"
    actions = [a[2] for a in state["audits"]]
    assert actions == ["finding.verify_requested"]
    assert state["committed"]


def test_post_verify_409_when_a_scan_is_already_in_flight(monkeypatch):
    state = _api_db(monkeypatch, finding_row=("open", CONN),
                    connection_row=("kafka", "prod", {}, "cloud"),
                    inflight=("66666666-6666-6666-6666-666666666666",))
    res = client.post(f"/findings/{FINDING}/verify", headers=h(EDITOR))
    assert res.status_code == 409
    detail = res.json()["detail"]
    assert detail["scan_id"] == "66666666-6666-6666-6666-666666666666"
    assert detail["connection_id"] == CONN
    assert state["updates"] == [] and state["scans"] == [] and state["audits"] == []
    assert not state["committed"]


def test_post_verify_404_when_the_resource_is_gone(monkeypatch):
    state = _api_db(monkeypatch, finding_row=("open", None))
    res = client.post(f"/findings/{FINDING}/verify", headers=h(EDITOR))
    assert res.status_code == 404 and state["updates"] == []


def test_post_verify_collector_connection_gets_a_queued_row_but_no_pgmq_job(monkeypatch):
    state = _api_db(monkeypatch, finding_row=("open", CONN),
                    connection_row=("kafka", "prod", {}, "collector"), inflight=None)
    res = client.post(f"/findings/{FINDING}/verify", headers=h(EDITOR))
    assert res.status_code == 202
    assert state["scans"] == [(TENANT, CONN)] and state["pgmq"] == []


def test_post_verify_requires_an_editing_role(monkeypatch):
    _api_db(monkeypatch, finding_row=("open", CONN))
    assert client.post(f"/findings/{FINDING}/verify", headers=h(VIEWER)).status_code == 403
