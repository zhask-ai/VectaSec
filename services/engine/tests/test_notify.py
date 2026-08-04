"""The action layer (notify.py): senders, routing semantics, and the two promises that make
notifications safe to bolt onto a security scanner:

  • **Error isolation.** One dead destination must neither fail the scan (notify_scan never
    raises) nor silence the destinations next to it (per-rule try/except, every attempt
    bookkept in notification_deliveries).
  • **Honest "new".** Rules are evaluated only against findings CREATED by the scan that just
    finished — `scan_id = this scan AND first_seen >= its started_at` — so a re-scan that
    re-sees 50 old findings notifies about none of them.

All HTTP goes through httpx.MockTransport (no network); email through a scripted smtplib.SMTP.
The DB is a fake cursor speaking exactly the SQL shapes _notify_scan emits.
"""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

import httpx
import pytest

from vectasec import notify
from vectasec.notify import (
    NotifyError,
    deliver,
    match_findings,
    notify_scan,
    ocsf_detection_finding,
    rule_wants,
    send_jira,
    send_siem,
    send_slack,
    send_teams,
    send_webhook,
    split_integration_config,
    validate_integration_config,
)

TENANT = "00000000-0000-0000-0000-000000000001"
SCAN = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def finding(**over) -> dict:
    f = {"id": "f-1", "rule_id": "KAFKA.TOPIC.PUBLIC", "title": "Topic world-readable",
         "severity": "high", "detail": "anyone can read payments",
         "resource_name": "payments", "resource_kind": "topic", "resource_ext_id": "topic-payments"}
    f.update(over)
    return f


def event(**over) -> dict:
    e = {"kind": "new_findings", "tenant_id": TENANT, "scan_id": SCAN,
         "connection": {"type": "kafka", "name": "prod"},
         "findings": [finding()], "error": None}
    e.update(over)
    return e


def capture_client(status_code: int = 200):
    """(client, seen): an httpx client whose transport records every request."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status_code, json={"id": "10001"})

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


# ═══ Senders ══════════════════════════════════════════════════════════════════
def test_slack_posts_summary_to_the_webhook_url():
    client, seen = capture_client()
    send_slack({"webhook_url": "https://hooks.slack.com/services/T/B/x"}, event(), client=client)
    assert len(seen) == 1
    assert str(seen[0].url) == "https://hooks.slack.com/services/T/B/x"
    body = json.loads(seen[0].content)
    assert "1 new finding(s)" in body["text"] and "kafka/prod" in body["text"]
    assert "KAFKA.TOPIC.PUBLIC" in body["text"]


def test_slack_without_url_is_a_notify_error():
    with pytest.raises(NotifyError):
        send_slack({}, event(), client=capture_client()[0])


def test_slack_http_error_is_a_notify_error_not_a_crash():
    client, _ = capture_client(500)
    with pytest.raises(NotifyError) as e:
        send_slack({"webhook_url": "https://hooks.slack.com/x"}, event(), client=client)
    assert "500" in str(e.value)
    # The URL is a credential; the error text must not leak it.
    assert "hooks.slack.com" not in str(e.value)


def test_teams_posts_an_adaptive_card_message_envelope():
    """Teams incoming webhooks (Workflows trigger or legacy connector) both accept the
    message envelope with an Adaptive Card attachment — assert exactly that shape."""
    client, seen = capture_client(202)     # Workflows answers 202 Accepted
    send_teams({"webhook_url": "https://prod-1.westus.logic.azure.com/workflows/x"},
               event(), client=client)
    assert len(seen) == 1
    body = json.loads(seen[0].content)
    assert body["type"] == "message"
    att = body["attachments"][0]
    assert att["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = att["content"]
    assert card["type"] == "AdaptiveCard" and card["version"] == "1.4"
    texts = " ".join(b["text"] for b in card["body"] if b["type"] == "TextBlock")
    assert "1 new finding(s)" in texts and "kafka/prod" in texts
    assert "KAFKA.TOPIC.PUBLIC" in texts


def test_teams_without_url_is_a_notify_error():
    with pytest.raises(NotifyError):
        send_teams({}, event(), client=capture_client()[0])


def test_teams_http_error_names_the_type_not_the_url():
    client, _ = capture_client(400)
    with pytest.raises(NotifyError) as e:
        send_teams({"webhook_url": "https://prod-1.westus.logic.azure.com/workflows/x"},
                   event(), client=client)
    assert "teams" in str(e.value) and "400" in str(e.value)
    assert "logic.azure.com" not in str(e.value)


def test_webhook_posts_the_event_body_unsigned_by_default():
    client, seen = capture_client()
    send_webhook({"url": "https://sink.example/hook"}, event(), client=client)
    body = json.loads(seen[0].content)
    assert body["source"] == "vectasec"
    assert body["event"] == "new_findings"
    assert body["scan_id"] == SCAN
    assert body["findings"][0]["rule_id"] == "KAFKA.TOPIC.PUBLIC"
    assert "X-VectaSec-Signature" not in seen[0].headers


def test_webhook_hmac_signature_verifies_against_the_delivered_body():
    client, seen = capture_client()
    send_webhook({"url": "https://sink.example/hook", "hmac_secret": "s3cret"},
                 event(), client=client)
    sig = seen[0].headers["X-VectaSec-Signature"]
    assert sig.startswith("sha256=")
    expected = hmac.new(b"s3cret", seen[0].content, hashlib.sha256).hexdigest()
    assert sig == f"sha256={expected}"    # a receiver can verify exactly this way


def test_jira_creates_a_v3_issue_with_project_and_type_from_config():
    client, seen = capture_client(201)
    send_jira({"base_url": "https://corp.atlassian.net/", "project_key": "SEC",
               "email": "bot@corp.io", "api_token": "tok", "issue_type": "Bug"},
              event(), client=client)
    req = seen[0]
    assert str(req.url) == "https://corp.atlassian.net/rest/api/3/issue"
    assert req.headers["Authorization"] == "Basic " + base64.b64encode(b"bot@corp.io:tok").decode()
    body = json.loads(req.content)
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["issuetype"]["name"] == "Bug"
    assert "1 new finding(s)" in body["fields"]["summary"]
    assert body["fields"]["description"]["type"] == "doc"   # ADF, required by v3


def test_jira_missing_config_is_a_notify_error():
    with pytest.raises(NotifyError):
        send_jira({"base_url": "https://x", "project_key": "SEC"}, event(),
                  client=capture_client()[0])


def test_siem_exports_ocsf_detection_findings():
    client, seen = capture_client()
    send_siem({"url": "https://siem.example/ingest"},
              event(findings=[finding(), finding(id="f-2", severity="critical")]),
              client=client)
    payload = json.loads(seen[0].content)
    assert isinstance(payload, list) and len(payload) == 2
    for o in payload:
        assert o["class_uid"] == 2004 and o["class_name"] == "Detection Finding"
        assert o["category_uid"] == 2 and o["type_uid"] == 200401
        assert o["activity_id"] == 1
        assert o["metadata"]["product"]["name"] == "VectaSec"
        assert o["finding_info"]["types"] == ["KAFKA.TOPIC.PUBLIC"]
        assert o["resources"][0]["uid"] == "topic-payments"
    assert payload[0]["severity_id"] == 4 and payload[1]["severity_id"] == 5


def test_siem_bearer_token_when_configured():
    client, seen = capture_client()
    send_siem({"url": "https://siem.example/ingest", "token": "abc"}, event(), client=client)
    assert seen[0].headers["Authorization"] == "Bearer abc"


@pytest.mark.parametrize("sev,sid", [("info", 1), ("low", 2), ("medium", 3),
                                     ("high", 4), ("critical", 5), ("bogus", 0)])
def test_ocsf_severity_mapping(sev, sid):
    o = ocsf_detection_finding(finding(severity=sev), event())
    assert o["severity_id"] == sid


def test_ocsf_carries_scan_context_in_unmapped():
    o = ocsf_detection_finding(finding(), event())
    assert o["unmapped"] == {"tenant_id": TENANT, "scan_id": SCAN,
                             "connection": {"type": "kafka", "name": "prod"}}


class FakeSMTP:
    """Scripted smtplib.SMTP: records the session instead of talking to a server."""
    instances: list = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.tls = False
        self.login_args = None
        self.messages = []
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        self.tls = True

    def login(self, u, p):
        self.login_args = (u, p)

    def send_message(self, msg):
        self.messages.append(msg)


def test_email_sends_over_smtp_env(monkeypatch):
    import smtplib
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_HOST", "smtp.example")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("SMTP_USERNAME", "mailer")
    monkeypatch.setenv("SMTP_PASSWORD", "pw")
    monkeypatch.setenv("SMTP_FROM", "alerts@vectasec.io")

    notify.send_email({"to": "a@corp.io, b@corp.io"}, event())

    s = FakeSMTP.instances[0]
    assert (s.host, s.port, s.tls, s.login_args) == ("smtp.example", 2525, True, ("mailer", "pw"))
    msg = s.messages[0]
    assert msg["To"] == "a@corp.io, b@corp.io"
    assert msg["From"] == "alerts@vectasec.io"
    assert "new finding" in msg["Subject"]


def test_email_accepts_a_list_of_recipients(monkeypatch):
    import smtplib
    FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_HOST", "smtp.example")
    notify.send_email({"to": ["a@corp.io", "b@corp.io"]}, event(kind="scan_failed", findings=[]))
    assert FakeSMTP.instances[0].messages[0]["To"] == "a@corp.io, b@corp.io"


def test_email_without_smtp_host_is_a_notify_error(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    with pytest.raises(NotifyError):
        notify.send_email({"to": "a@corp.io"}, event())


def test_deliver_unknown_type_is_a_notify_error():
    with pytest.raises(NotifyError):
        deliver("carrier-pigeon", {}, event())


# ═══ Integration config contract ═════════════════════════════════════════════
def test_validate_unknown_type():
    problems = validate_integration_config("carrier-pigeon", {})
    assert problems and "unknown integration type" in problems[0]


@pytest.mark.parametrize("type_,config,missing", [
    ("slack", {}, "webhook_url"),
    ("teams", {}, "webhook_url"),
    ("webhook", {}, "url"),
    ("email", {}, "to"),
    ("jira", {"base_url": "https://x"}, "project_key"),
    ("siem", {}, "url"),
])
def test_validate_missing_required(type_, config, missing):
    problems = validate_integration_config(type_, config)
    assert any(missing in p for p in problems)


def test_validate_update_passes_with_stored_secret_keys():
    """Re-saving without retyping the secret: the vaulted key satisfies the requirement."""
    assert validate_integration_config("slack", {}, stored_secret_keys=("webhook_url",)) == []
    assert validate_integration_config(
        "jira", {"base_url": "https://x", "project_key": "SEC", "email": "e@x"},
        stored_secret_keys=("api_token",)) == []


def test_split_moves_declared_secrets_out_of_config():
    public, secrets = split_integration_config(
        "jira", {"base_url": "https://x", "project_key": "SEC", "email": "e@x",
                 "api_token": "tok"})
    assert public == {"base_url": "https://x", "project_key": "SEC", "email": "e@x"}
    assert secrets == {"api_token": "tok"}


def test_split_drops_empty_secret_values():
    """Empty secret on a resubmitted form means "unchanged", not "store empty string"."""
    public, secrets = split_integration_config("slack", {"webhook_url": ""})
    assert public == {} and secrets == {}


# ═══ Routing semantics (pure) ════════════════════════════════════════════════
FINDINGS = [finding(id="c", rule_id="KAFKA.A", severity="critical"),
            finding(id="h", rule_id="KAFKA.B", severity="high"),
            finding(id="m", rule_id="KONG.C", severity="medium"),
            finding(id="l", rule_id="KONG.D", severity="low")]


def test_empty_match_routes_everything():
    assert match_findings({}, "kafka", FINDINGS) == FINDINGS


def test_min_severity_is_an_inclusive_floor():
    got = match_findings({"min_severity": "high"}, "kafka", FINDINGS)
    assert [f["id"] for f in got] == ["c", "h"]


def test_connector_type_filter_gates_the_whole_scan():
    assert match_findings({"connector_types": ["kong"]}, "kafka", FINDINGS) == []
    assert match_findings({"connector_types": ["kafka", "kong"]}, "kafka", FINDINGS) == FINDINGS


def test_rule_prefix_filter():
    got = match_findings({"rule_prefixes": ["KONG."]}, "kafka", FINDINGS)
    assert [f["id"] for f in got] == ["m", "l"]


def test_filters_compose():
    got = match_findings({"rule_prefixes": ["KONG."], "min_severity": "medium"},
                         "kafka", FINDINGS)
    assert [f["id"] for f in got] == ["m"]


def test_rule_wants_defaults_to_both_scan_events():
    assert rule_wants({}, "new_findings") and rule_wants({}, "scan_failed")
    assert not rule_wants({}, "test")     # test messages never go through rules


def test_rule_wants_respects_explicit_notify_on():
    assert rule_wants({"notify_on": ["scan_failed"]}, "scan_failed")
    assert not rule_wants({"notify_on": ["scan_failed"]}, "new_findings")


# ═══ notify_scan against a fake DB ═══════════════════════════════════════════
STARTED = datetime(2026, 7, 23, 12, 0, tzinfo=timezone.utc)


class FakeCursor:
    def __init__(self, db):
        self.db = db
        self._one, self._all = None, []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        s = " ".join(sql.split()).lower()
        if s.startswith("select s.status"):
            self._one = self.db.scan_row
        elif s.startswith("select r.id::text, r.match"):
            self._all = self.db.rules
        elif s.startswith("select f.id::text"):
            self.db.findings_sql, self.db.findings_params = s, params
            self._all = self.db.finding_rows
        elif s.startswith("insert into notification_deliveries"):
            self.db.deliveries.append(params)
        else:
            raise AssertionError(f"unexpected SQL: {s}")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class FakeConn:
    autocommit = False

    def __init__(self, scan_row, rules, finding_rows=()):
        self.scan_row, self.rules, self.finding_rows = scan_row, list(rules), list(finding_rows)
        self.deliveries: list = []
        self.committed = self.rolled_back = False
        self.findings_sql, self.findings_params = "", ()

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


# (id, rule_id, title, severity, detail, resource name, kind, ext_id) — _new_findings's shape
FINDING_ROWS = [("f-1", "KAFKA.A", "t1", "critical", "d1", "payments", "topic", "topic-payments"),
                ("f-2", "KAFKA.B", "t2", "low", "d2", "logs", "topic", "topic-logs")]


def rule(rule_id, itype, match=None, config=None, name=None):
    return (rule_id, match or {}, f"i-{rule_id}", itype, name or itype, config or {}, None)


def test_notify_scan_routes_new_findings_and_isolates_failures(monkeypatch):
    """One dead Slack must not silence the webhook next to it — and BOTH attempts must be
    bookkept, the failure with its error and the success as sent."""
    sent = []
    monkeypatch.setitem(notify.SENDERS, "slack",
                        lambda cfg, ev, client=None: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setitem(notify.SENDERS, "webhook",
                        lambda cfg, ev, client=None: sent.append((cfg, ev)))

    conn = FakeConn(("done", STARTED, {}, "kafka", "prod"),
                    [rule("r1", "slack", config={"webhook_url": "https://x"}),
                     rule("r2", "webhook", config={"url": "https://y"})],
                    FINDING_ROWS)
    out = notify_scan(conn, TENANT, SCAN)

    assert [d["status"] for d in out] == ["error", "sent"]
    assert conn.committed
    # Bookkeeping: (tenant, integration, rule, scan, event, count, status, error)
    assert len(conn.deliveries) == 2
    t, iid, rid, sid, ev, n, status, err = conn.deliveries[0]
    assert (iid, rid, ev, n, status) == ("i-r1", "r1", "new_findings", 2, "error")
    assert "boom" in err
    assert conn.deliveries[1][6] == "sent" and conn.deliveries[1][7] is None
    # The surviving destination got the real findings.
    assert len(sent) == 1 and [f["id"] for f in sent[0][1]["findings"]] == ["f-1", "f-2"]


def test_notify_scan_applies_the_rule_match_per_destination(monkeypatch):
    got = {}
    monkeypatch.setitem(notify.SENDERS, "slack",
                        lambda cfg, ev, client=None: got.setdefault("slack", ev))
    monkeypatch.setitem(notify.SENDERS, "webhook",
                        lambda cfg, ev, client=None: got.setdefault("webhook", ev))

    conn = FakeConn(("done", STARTED, {}, "kafka", "prod"),
                    [rule("r1", "slack", match={"min_severity": "high"}),
                     rule("r2", "webhook", match={"connector_types": ["kong"]})],
                    FINDING_ROWS)
    out = notify_scan(conn, TENANT, SCAN)

    # Slack gets only the critical finding; the kong-scoped webhook rule matches nothing and
    # is skipped entirely — no delivery row for a rule that selected zero findings.
    assert [f["id"] for f in got["slack"]["findings"]] == ["f-1"]
    assert "webhook" not in got
    assert len(out) == 1 and out[0]["findings"] == 1
    assert len(conn.deliveries) == 1


def test_notify_scan_new_is_first_seen_within_this_scan(monkeypatch):
    """The honesty pin: the findings query must scope BOTH by scan_id and by first_seen >=
    the scan's started_at — scan_id alone re-notifies every re-seen old finding."""
    monkeypatch.setitem(notify.SENDERS, "slack", lambda cfg, ev, client=None: None)
    conn = FakeConn(("done", STARTED, {}, "kafka", "prod"), [rule("r1", "slack")], FINDING_ROWS)
    notify_scan(conn, TENANT, SCAN)
    assert "f.scan_id = %s" in conn.findings_sql
    assert "f.first_seen >= %s" in conn.findings_sql
    assert conn.findings_params == (TENANT, SCAN, STARTED)
    assert "f.status = 'open'" in conn.findings_sql   # born-suppressed findings stay silent


def test_notify_scan_failure_event_routes_to_scan_failed_rules(monkeypatch):
    got = {}
    monkeypatch.setitem(notify.SENDERS, "slack",
                        lambda cfg, ev, client=None: got.setdefault("slack", ev))
    monkeypatch.setitem(notify.SENDERS, "webhook",
                        lambda cfg, ev, client=None: got.setdefault("webhook", ev))

    conn = FakeConn(("error", STARTED, {"error": "SystemExit: no such connector"}, "kafka", "prod"),
                    [rule("r1", "slack"),                                     # default: both events
                     rule("r2", "webhook", match={"notify_on": ["new_findings"]})])
    out = notify_scan(conn, TENANT, SCAN)

    assert got["slack"]["kind"] == "scan_failed"
    assert got["slack"]["error"] == "SystemExit: no such connector"
    assert got["slack"]["findings"] == []
    assert "webhook" not in got                       # opted out of scan_failed
    assert len(out) == 1 and conn.deliveries[0][4] == "scan_failed" and conn.deliveries[0][5] == 0


def test_notify_scan_says_nothing_for_running_or_unknown_scans():
    conn = FakeConn(("running", STARTED, {}, "kafka", "prod"), [rule("r1", "slack")])
    assert notify_scan(conn, TENANT, SCAN) == []
    conn2 = FakeConn(None, [rule("r1", "slack")])
    assert notify_scan(conn2, TENANT, SCAN) == []
    assert conn.deliveries == [] and conn2.deliveries == []


def test_notify_scan_never_raises():
    """The pipeline promise: a routing crash is logged and swallowed, the scan stays done."""
    class ExplodingConn:
        autocommit = False

        def cursor(self):
            raise RuntimeError("db went away")

        def rollback(self):
            pass

    assert notify_scan(ExplodingConn(), TENANT, SCAN) == []


def test_notify_scan_no_rules_is_a_cheap_noop():
    conn = FakeConn(("done", STARTED, {}, "kafka", "prod"), [])
    assert notify_scan(conn, TENANT, SCAN) == []
    assert conn.findings_sql == ""        # the findings query never even ran
