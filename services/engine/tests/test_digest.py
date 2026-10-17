"""Weekly digest (vectasec.digest): compose from canned rows, deterministic renderers, and the
send path's per-destination isolation. The fake cursor dispatches on the `/* digest:<section> */`
tag each statement starts with, so the test speaks the module's own contract, not SQL."""
import json
from datetime import datetime, timezone

import pytest

from vectasec import digest as dg
from vectasec import notify
from vectasec.digest import compose_digest, render_digest_slack, render_digest_text, send_digest

TENANT = "00000000-0000-0000-0000-000000000001"
SINCE = datetime(2026, 10, 10, 8, 0, tzinfo=timezone.utc)
UNTIL = datetime(2026, 10, 17, 8, 0, tzinfo=timezone.utc)


class FakeCursor:
    """Returns canned rows per digest section; records every (tag, params) it saw."""

    def __init__(self, db):
        self.db = db
        self._one, self._all = None, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        s = " ".join(sql.split())
        tag = s.split("*/")[0].replace("/*", "").strip().split(":", 1)[1] if s.startswith("/*") else s
        self.db.calls.append((tag, params))
        rows = self.db.rows.get(tag)
        if tag == "insert":
            self.db.inserted.append(params)
            self._one = ("digest-1",)
        elif tag in ("scans", "posture_latest", "posture_baseline", "posture_earliest",
                     "unknowns", "last_period_end"):
            self._one = rows
        else:
            self._all = rows or []

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class FakeConn:
    autocommit = False

    def __init__(self, rows):
        self.rows, self.calls, self.inserted = rows, [], []
        self.committed = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        pass


def canned():
    return {
        # severity, rule_id, title, resource name, assessment
        "new_findings": [
            ("critical", "KAFKA.LISTENER.PLAINTEXT", "Broker listener is PLAINTEXT", "broker-1", "assessed"),
            ("high", "NHI.GRANT.WILDCARD", "Wildcard grant", "etl-role", "assessed"),
            ("low", "KONG.PLUGIN.X", "Plugin", "route-a", "assessed"),
            ("medium", "CREDENTIAL.LIFECYCLE.ROTATION_STALE", "Rotation unknown", "k1", "not_assessable"),
        ],
        # target, rule_id, title, at
        "fixed": [
            ("f-9", "RABBITMQ.DEFAULT_USER", "guest present", datetime(2026, 10, 12, tzinfo=timezone.utc)),
            ("f-9", "RABBITMQ.DEFAULT_USER", "guest present", datetime(2026, 10, 11, tzinfo=timezone.utc)),
            ("f-8", "KONG.AUTH.MISSING", "route unauthenticated", datetime(2026, 10, 11, tzinfo=timezone.utc)),
        ],
        # name, system, credential_type
        "new_credentials": [("deploy:access_key", "aws", "access_key"), ("svc:key-auth", "kong", "key-auth"),
                            ("svc2:key-auth", "kong", "key-auth")],
        "newly_exposed": [("high", "ATTACKPATH.EXPOSED_NHI_SENSITIVE", "Exposed NHI reaches payments", "etl-role")],
        "newly_unused": [("medium", "CREDENTIAL.LIFECYCLE.NEVER_USED", "Key never used", "deploy-key")],
        "scans": (14, 2),
        "posture_latest": (72, datetime(2026, 10, 16, tzinfo=timezone.utc)),
        "posture_baseline": (65, datetime(2026, 10, 9, tzinfo=timezone.utc)),
        "unknowns": (11,),
    }


# ── compose ────────────────────────────────────────────────────────────────
def test_compose_builds_every_section_from_the_window():
    conn = FakeConn(canned())
    d = compose_digest(conn.cursor(), TENANT, SINCE, UNTIL)

    assert d["period_start"] == SINCE.isoformat() and d["period_end"] == UNTIL.isoformat()
    assert d["new_findings"]["total"] == 3                      # the not_assessable one is excluded
    assert d["new_findings"]["by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert [t["rule_id"] for t in d["new_findings"]["top"]] == [
        "KAFKA.LISTENER.PLAINTEXT", "NHI.GRANT.WILDCARD", "KONG.PLUGIN.X"]
    assert d["fixed"]["total"] == 2                             # f-9 counted once
    assert [t["finding_id"] for t in d["fixed"]["top"]] == ["f-9", "f-8"]
    assert d["new_credentials"] == {
        "total": 3, "by_system": {"aws": 1, "kong": 2},
        "sample": [{"name": "deploy:access_key", "system": "aws", "credential_type": "access_key"},
                   {"name": "svc:key-auth", "system": "kong", "credential_type": "key-auth"},
                   {"name": "svc2:key-auth", "system": "kong", "credential_type": "key-auth"}]}
    assert d["newly_exposed"]["total"] == 1 and d["newly_exposed"]["top"][0]["resource"] == "etl-role"
    assert d["newly_unused"]["total"] == 1
    assert d["scans"] == {"total": 14, "failed": 2}
    assert d["posture"]["score"] == 72 and d["posture"]["previous_score"] == 65 and d["posture"]["delta"] == 7
    assert d["unknowns"] == {"not_assessable_open": 11, "new_not_assessable": 1}
    # every windowed query got the tenant and the window
    windowed = [p for tag, p in conn.calls if tag in ("new_findings", "fixed", "new_credentials",
                                                      "newly_exposed", "newly_unused", "scans")]
    assert windowed and all(p == (TENANT, SINCE, UNTIL) for p in windowed)
    # json-serialisable as it lands in digests.summary
    json.dumps(d)


def test_compose_without_snapshots_or_baseline_is_honest():
    rows = canned()
    rows["posture_latest"] = None
    rows["posture_baseline"] = None
    rows["posture_earliest"] = None
    d = compose_digest(FakeConn(rows).cursor(), TENANT, SINCE, UNTIL)
    assert d["posture"] == {"score": None, "taken_at": "", "previous_score": None,
                            "previous_taken_at": "", "delta": None}
    assert "no posture snapshot yet" in render_digest_text(d)


def test_compose_falls_back_to_the_earliest_in_window_snapshot_as_baseline():
    rows = canned()
    rows["posture_baseline"] = None
    rows["posture_earliest"] = (60, datetime(2026, 10, 11, tzinfo=timezone.utc))
    conn = FakeConn(rows)
    d = compose_digest(conn.cursor(), TENANT, SINCE, UNTIL)
    assert d["posture"]["previous_score"] == 60 and d["posture"]["delta"] == 12
    assert "posture_earliest" in [t for t, _ in conn.calls]


def test_compose_accepts_iso_strings_for_the_window():
    d = compose_digest(FakeConn(canned()).cursor(), TENANT, "2026-10-10T08:00:00Z", "2026-10-17T08:00:00Z")
    assert d["period_start"] == SINCE.isoformat()


# ── renderers ──────────────────────────────────────────────────────────────
def test_renderers_are_deterministic_and_cover_the_sections():
    d = compose_digest(FakeConn(canned()).cursor(), TENANT, SINCE, UNTIL)
    t1, t2 = render_digest_text(d), render_digest_text(json.loads(json.dumps(d)))
    assert t1 == t2
    assert t1.splitlines()[0] == "VectaSec weekly digest 2026-10-10 → 2026-10-17"
    assert "Posture: 72/100 (+7 vs 65, improved)" in t1
    assert "Scans: 14 run, 2 failed" in t1
    assert "New findings: 3 (1 critical, 1 high, 1 low)" in t1
    assert "Fixed: 2 finding(s) moved to resolved" in t1
    assert "New credentials: 3 (1 aws, 2 kong)" in t1
    assert "Newly exposed: 1 attack path(s)" in t1
    assert "Newly unused: 1 credential(s)" in t1
    assert "Unknowns: 11 open finding(s) are coverage gaps (not assessable), 1 new this week" in t1

    s1, s2 = render_digest_slack(d), render_digest_slack(json.loads(json.dumps(d)))
    assert s1 == s2
    assert s1["text"] == t1
    assert s1["blocks"][0] == {"type": "header", "text": {"type": "plain_text",
                                                          "text": "VectaSec weekly digest 2026-10-10 → 2026-10-17"}}
    titles = [b["text"]["text"].splitlines()[0] for b in s1["blocks"] if b["type"] == "section" and "text" in b]
    assert titles == ["*Top new findings*", "*Fixed*", "*New credentials*", "*Newly exposed*", "*Newly unused*"]
    assert s1["blocks"][-1]["type"] == "context" and "Unknown is not unused" in s1["blocks"][-1]["elements"][0]["text"]
    json.dumps(s1)


def test_render_declined_posture_and_empty_lists():
    d = {"period_start": "2026-10-10", "period_end": "2026-10-17",
         "posture": {"score": 50, "previous_score": 58, "delta": -8},
         "new_findings": {"total": 0, "by_severity": {}, "top": []}, "fixed": {"total": 0, "top": []},
         "new_credentials": {"total": 0, "by_system": {}, "sample": []},
         "newly_exposed": {"total": 0, "top": []}, "newly_unused": {"total": 0, "top": []},
         "scans": {"total": 0, "failed": 0}, "unknowns": {}}
    text = render_digest_text(d)
    assert "Posture: 50/100 (-8 vs 58, declined)" in text
    assert "New findings: 0 (none)" in text
    blocks = render_digest_slack(d)["blocks"]
    assert [b["type"] for b in blocks] == ["header", "section", "context"]


# ── send ───────────────────────────────────────────────────────────────────
def rule(rule_id, itype, match=None, config=None, name=None):
    return (rule_id, match or {}, f"i-{rule_id}", itype, name or itype, config or {}, None)


def test_send_digest_routes_only_rules_naming_weekly_digest_and_records_failures(monkeypatch):
    got = []
    monkeypatch.setitem(notify.SENDERS, "slack",
                        lambda cfg, ev, client=None: (_ for _ in ()).throw(RuntimeError("hook dead")))
    monkeypatch.setitem(notify.SENDERS, "webhook", lambda cfg, ev, client=None: got.append(ev))
    monkeypatch.setitem(notify.SENDERS, "jira", lambda cfg, ev, client=None: got.append(("jira", ev)))
    monkeypatch.setattr(dg, "resolve_secrets", lambda cur, ref: {})

    rows = canned()
    rows["last_period_end"] = (SINCE,)
    rows["rules"] = [
        rule("r1", "slack", match={"notify_on": ["weekly_digest"]}, config={"webhook_url": "https://x"}),
        rule("r2", "webhook", match={"notify_on": ["new_findings", "weekly_digest"]}, config={"url": "https://y"}),
        rule("r3", "webhook", match={}, config={"url": "https://z"}),             # defaults: not the digest
        rule("r4", "jira", match={"notify_on": ["weekly_digest"]}),                # type not a digest destination
        rule("r5", "webhook", match={"notify_on": ["weekly_digest"]}, config={"url": "https://y"}),
    ]
    # r5 shares integration i-r5 ≠ i-r2, so it is a second destination; make it the same hook:
    rows["rules"][4] = ("r5", {"notify_on": ["weekly_digest"]}, "i-r2", "webhook", "webhook", {"url": "https://y"}, None)
    conn = FakeConn(rows)

    out = send_digest(conn, TENANT, until=UNTIL)

    assert out["id"] == "digest-1"
    assert out["digest"]["period_start"] == SINCE.isoformat()       # cursor from the last digest
    assert [(d["rule_id"], d["status"]) for d in out["delivered_to"]] == [("r1", "error"), ("r2", "sent")]
    assert "hook dead" in out["delivered_to"][0]["error"]
    assert out["delivered_to"][1]["error"] is None
    assert len(got) == 1 and got[0]["kind"] == "weekly_digest" and got[0]["digest"] is out["digest"]
    assert conn.committed
    # the digests row carries the window, the attempts (failure included) and the summary
    tenant, since, until, delivered_json, summary_json = conn.inserted[0]
    assert (tenant, since, until) == (TENANT, SINCE, UNTIL)
    assert [d["status"] for d in json.loads(delivered_json)] == ["error", "sent"]
    assert json.loads(summary_json)["scans"] == {"total": 14, "failed": 2}


def test_send_digest_defaults_to_seven_days_when_no_digest_exists(monkeypatch):
    monkeypatch.setattr(dg, "resolve_secrets", lambda cur, ref: {})
    rows = canned()
    rows["last_period_end"] = (None,)
    rows["rules"] = []
    out = send_digest(FakeConn(rows), TENANT, until=UNTIL)
    assert out["digest"]["period_start"] == SINCE.isoformat()
    assert out["delivered_to"] == []


def test_rule_wants_accepts_weekly_digest_only_when_named():
    assert notify.rule_wants({"notify_on": ["weekly_digest"]}, "weekly_digest")
    assert not notify.rule_wants({}, "weekly_digest")
    assert notify.rule_wants({}, "new_findings") and notify.rule_wants({}, "scan_failed")
    assert not notify.rule_wants({"notify_on": ["weekly_digest"]}, "new_findings")
    assert not notify.rule_wants({"notify_on": ["bogus"]}, "bogus")
    assert notify.DEFAULT_EVENTS == ("new_findings", "scan_failed")
    assert "weekly_digest" in notify.EVENT_KINDS


@pytest.mark.parametrize("sender", ["slack", "teams", "webhook"])
def test_builtin_senders_render_a_weekly_digest_event(sender):
    import httpx
    seen = []
    client = httpx.Client(transport=httpx.MockTransport(
        lambda req: (seen.append(req), httpx.Response(200, json={}))[1]))
    d = compose_digest(FakeConn(canned()).cursor(), TENANT, SINCE, UNTIL)
    ev = {"kind": "weekly_digest", "tenant_id": TENANT, "scan_id": None,
          "connection": {"type": "vectasec", "name": "weekly-digest"}, "findings": [],
          "error": None, "digest": d}
    cfg = {"webhook_url": "https://hooks.example/x", "url": "https://hooks.example/x"}
    notify.SENDERS[sender](cfg, ev, client=client)
    body = json.loads(seen[0].content)
    if sender == "slack":
        assert body["blocks"][0]["type"] == "header" and "weekly digest" in body["text"]
    elif sender == "teams":
        assert "VectaSec weekly digest" in body["attachments"][0]["content"]["body"][0]["text"]
    else:
        assert body["event"] == "weekly_digest" and body["digest"]["scans"] == {"total": 14, "failed": 2}
