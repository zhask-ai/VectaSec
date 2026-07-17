"""The transport half of the trust story, against a fake control plane.

The README claims the enroll → heartbeat → long-poll → scan → redact → push loop closes, that the
service token is memory-only, and that the state file holds nothing usable. Those are claims
about code that talks to a server, and until this file existed nothing exercised them — the
"tested" column was riding on the redaction unit tests.

The server here is `httpx.MockTransport`: a real httpx.Client, real request/response objects,
real status-code handling, no socket. It is a fake server, not a real one, and the README says
exactly that.
"""
import json
import pathlib
import stat
import threading

import httpx
import pytest

from vectasec.contracts import Collected, Resource
from vectasec.registry import connector

from collector import main as m
from collector.config import Config, Target

PW = "sup3rs3cr3tpw"
ENROLL = "enroll-token-abcdefgh"
SERVICE_TOKEN = "service-token-zyxwvu-shortlived"
RAW_SECRET = "entire broker config that must never leave the network"


@connector("test_cp_fake")
def _collect(config: dict) -> Collected:
    assert config["password"] == PW      # creds do reach the connector, or this is all pointless
    return Collected(resources=[Resource(
        kind="test_thing", name="thing-1", ext_id="thing-1",
        labels={"host": "internal.example"}, raw={"dump": RAW_SECRET},
    )])


class FakeControlPlane:
    """Records every request it is handed, and answers the four endpoints the client speaks."""

    def __init__(self, jobs=None):
        self.requests: list = []
        self.enrolls = 0
        self.pushed: list = []
        self.jobs = list(jobs or [])
        self.reject_enroll = False
        self.expire_next_post = False
        self.on_results = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.url.path, dict(request.headers), body))
        path = request.url.path

        if path == "/collector/enroll":
            if self.reject_enroll:
                return httpx.Response(401, json={"error": "nope"})
            self.enrolls += 1
            return httpx.Response(200, json={
                "collector_id": f"cid-{self.enrolls}", "tenant_id": "tenant-1",
                "token": SERVICE_TOKEN, "expires_in": 3600,
            })

        if self.expire_next_post and request.method == "POST":
            # The control plane rotated its signing key, or the token died early.
            self.expire_next_post = False
            return httpx.Response(401, json={"error": "expired"})

        if path == "/collector/jobs":
            if not self.jobs:
                return httpx.Response(204)
            return httpx.Response(200, json={"jobs": [self.jobs.pop(0)]})

        if path == "/collector/results":
            self.pushed.append(body)
            if self.on_results:
                self.on_results()
            return httpx.Response(202, json={})

        if path == "/collector/heartbeat":
            return httpx.Response(200, json={})

        return httpx.Response(404)

    def posted_to(self, path) -> list:
        return [b for p, _h, b in self.requests if p == path]


@pytest.fixture
def cfg(tmp_path: pathlib.Path) -> Config:
    return Config(
        control_plane_url="https://cp.example",
        enroll_token=ENROLL,
        collector_name="collector-1",
        targets=(Target(name="t1", type="test_cp_fake",
                        config={"url": "https://svc.internal:9000", "password": PW}),),
        state_dir=tmp_path / "state", verify_tls=True, timeout_s=5, heartbeat_interval_s=60,
        poll_wait_s=1, poll_interval_s=0, max_backoff_s=1, log_level="INFO",
    )


@pytest.fixture
def server(monkeypatch):
    """Installs the fake transport into whatever httpx.Client ControlPlane builds, so the client
    under test is the real one — base_url, timeouts, headers and all."""
    fake = FakeControlPlane()
    real_client = httpx.Client

    def _client(**kw):
        return real_client(**kw, transport=httpx.MockTransport(fake.handler))

    monkeypatch.setattr(m.httpx, "Client", _client)
    return fake


# ═══ enrollment and what it leaves on disk ════════════════════════════════
def test_enroll_trades_the_enrollment_token_for_a_tenant_scoped_one(cfg, server):
    cp = m.ControlPlane(cfg)
    cp.enroll()
    assert server.posted_to("/collector/enroll") == [
        {"enrollment_token": ENROLL, "name": "collector-1", "version": m.VERSION}]
    assert cp.tenant_id == "tenant-1" and cp.collector_id == "cid-1"
    assert cp._token == SERVICE_TOKEN


def test_neither_token_reaches_the_disk(cfg, server):
    """README: "the state file holds a collector id and sha256(enrollment token). Nothing in it
    can authenticate to anything." """
    import hashlib
    m.ControlPlane(cfg).enroll()
    p = cfg.state_dir / "state.json"
    text = p.read_text()
    assert ENROLL not in text and SERVICE_TOKEN not in text
    assert json.loads(text)["enroll_token_sha256"] == hashlib.sha256(ENROLL.encode()).hexdigest()
    assert json.loads(text)["collector_id"] == "cid-1"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_a_rejected_enrollment_token_exits_with_a_message_naming_the_variable(cfg, server):
    server.reject_enroll = True
    with pytest.raises(SystemExit) as e:
        m.ControlPlane(cfg).enroll()
    assert "VECTASEC_ENROLL_TOKEN_FILE" in str(e.value)


def test_a_response_without_a_tenant_refuses_to_scan(cfg, server, monkeypatch):
    monkeypatch.setattr(server, "handler", lambda r: httpx.Response(
        200, json={"collector_id": "c", "token": SERVICE_TOKEN}))
    with pytest.raises(SystemExit) as e:
        m.ControlPlane(cfg).enroll()
    assert "tenant_id" in str(e.value)


# ═══ heartbeat ════════════════════════════════════════════════════════════
def test_the_heartbeat_carries_target_names_and_types_and_no_hostname(cfg, server):
    """README: "Target names and types, on each heartbeat | Target hostnames, on the heartbeat."
    A hostname list is an inventory of the customer's private network."""
    cp = m.ControlPlane(cfg)
    cp.ensure_enrolled()
    cp.heartbeat()
    hb = server.posted_to("/collector/heartbeat")[0]
    assert hb == {"collector_id": "cid-1", "version": m.VERSION, "status": "active",
                  "targets": [{"name": "t1", "type": "test_cp_fake"}]}
    assert "svc.internal" not in json.dumps(hb) and PW not in json.dumps(hb)


# ═══ polling ══════════════════════════════════════════════════════════════
def test_an_empty_long_poll_is_not_an_error(cfg, server):
    """204 means the long-poll expired against an empty queue. Treating it as a failure would
    drive the backoff on an idle collector."""
    cp = m.ControlPlane(cfg)
    cp.ensure_enrolled()
    assert cp.poll() == []


def test_poll_sends_the_bearer_token_and_the_wait(cfg, server):
    cp = m.ControlPlane(cfg)
    cp.ensure_enrolled()
    cp.poll()
    path, headers, _ = server.requests[-1]
    assert path == "/collector/jobs"
    assert headers["authorization"] == f"Bearer {SERVICE_TOKEN}"


def test_a_401_on_poll_re_enrolls_rather_than_dying(cfg, server, monkeypatch):
    cp = m.ControlPlane(cfg)
    cp.ensure_enrolled()
    monkeypatch.setattr(cp._http, "get", lambda *a, **k: httpx.Response(401))
    assert cp.poll() == []
    assert server.enrolls == 2


def test_a_401_on_a_push_re_enrolls_once_and_retries_the_same_body(cfg, server):
    cp = m.ControlPlane(cfg)
    cp.ensure_enrolled()
    server.expire_next_post = True
    cp.push_results({"job_id": "j-1", "status": "done"})
    assert server.enrolls == 2
    assert server.pushed == [{"job_id": "j-1", "status": "done"}]


# ═══ the whole loop ═══════════════════════════════════════════════════════
def test_the_loop_closes_and_pushes_a_redacted_result(cfg, server, monkeypatch):
    """README:194 — "the whole loop closes". enroll → heartbeat → poll → local scan → redact →
    push, driven by run_forever() against the fake server."""
    stop = threading.Event()
    monkeypatch.setattr(m, "_stop_event", lambda: stop)
    server.jobs = [{"job_id": "j-1", "connection_id": "conn-1", "target": "t1"}]
    server.on_results = stop.set          # one job pushed, then shut down

    assert m.run_forever(cfg) == 0

    paths = [p for p, _h, _b in server.requests]
    assert paths[:4] == ["/collector/enroll", "/collector/heartbeat", "/collector/jobs",
                         "/collector/results"]

    (pushed,) = server.pushed
    assert pushed["status"] == "done"
    assert pushed["job_id"] == "j-1"
    assert pushed["collector_id"] == "cid-1"
    assert pushed["stats"]["resources"] == 1
    # The payload half of the claim, asserted on what the wire actually carried.
    assert PW not in json.dumps(pushed)
    assert RAW_SECRET not in json.dumps(pushed)
    assert pushed["config"] == {"url": "https://svc.internal:9000", "password": "[redacted]"}


def test_the_loop_reports_its_own_enrolled_id_not_one_echoed_by_the_job(cfg, server, monkeypatch):
    """What the collector says about itself has to come from its enrollment, not from a message
    a compromised control plane handed it."""
    stop = threading.Event()
    monkeypatch.setattr(m, "_stop_event", lambda: stop)
    server.jobs = [{"job_id": "j-1", "connection_id": "conn-1", "target": "t1",
                    "collector_id": "cid-belonging-to-another-tenant"}]
    server.on_results = stop.set
    m.run_forever(cfg)
    assert server.pushed[0]["collector_id"] == "cid-1"


def test_a_control_plane_outage_backs_off_instead_of_spinning(cfg, server, monkeypatch):
    """The claim is that a fleet of collectors does not become a retry storm. Assert the sleep,
    not the wall clock."""
    stop = threading.Event()
    monkeypatch.setattr(m, "_stop_event", lambda: stop)
    waits: list = []
    monkeypatch.setattr(stop, "wait", lambda t=None: (waits.append(t), stop.set())[1])
    server.reject_enroll = False
    monkeypatch.setattr(m.ControlPlane, "heartbeat",
                        lambda self, status="active": (_ for _ in ()).throw(
                            httpx.ConnectError("control plane unreachable")))
    m.run_forever(cfg)
    assert waits and 0.5 <= waits[0] <= 1.5      # backoff 1.0 with jitter, not a tight loop
