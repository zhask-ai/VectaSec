"""What run_job() puts on the wire — the other half of the trust claim.

These lock in two properties that a future connector author cannot be relied on to remember:
Resource.raw has no route out, and a job cannot tell the collector where to connect.
"""
import pathlib

import pytest

from vectasec.contracts import Collected, Resource
from vectasec.registry import CONNECTORS, connector

from collector.config import Config, Target
from collector.main import run_job
from collector.redact import redact

PW = "sup3rs3cr3tpw"
RAW_SECRET = "entire broker config that must never leave the network"


@connector("test_fake")
def _collect(config: dict) -> Collected:
    # A kind no rulepack claims, so this test stays about the payload rather than about whichever
    # rules happen to be registered.
    return Collected(resources=[Resource(
        kind="test_thing", name="thing-1", ext_id="thing-1",
        labels={"host": "internal.example"},
        raw={"config": {"dump": RAW_SECRET}, "password_seen": config["password"]},
    )])


@pytest.fixture
def cfg(tmp_path: pathlib.Path) -> Config:
    return Config(
        control_plane_url="https://cp.example",
        enroll_token="enroll-token-abcdefgh",
        collector_name="test",
        targets=(Target(name="t1", type="test_fake",
                        config={"url": "https://svc.internal:9000", "password": PW}),),
        state_dir=tmp_path, verify_tls=True, timeout_s=5, heartbeat_interval_s=60,
        poll_wait_s=25, poll_interval_s=5, max_backoff_s=300, log_level="INFO",
    )


def _payload(cfg: Config, job: dict) -> dict:
    return redact(run_job(job, cfg, tenant_id="tenant-1"), cfg.secret_values())


def test_resource_raw_has_no_route_out(cfg):
    out = _payload(cfg, {"job_id": "j", "connection_id": "c", "target": "t1"})
    assert out["status"] == "done"
    assert RAW_SECRET not in str(out)
    assert PW not in str(out)
    # Metadata does leave, and the README says so plainly — the console is unusable without it.
    assert out["resources"] == [{"kind": "test_thing", "name": "thing-1", "ext_id": "thing-1",
                                 "namespace": None, "labels": {"host": "internal.example"}}]


def test_connector_still_receives_the_credential(cfg):
    # The other side of the invariant: creds stay local, but they must reach the connector, or the
    # collector would be secure and useless.
    seen = {}
    CONNECTORS["test_capture"] = lambda c: seen.update(c) or Collected(resources=[])
    cfg = Config(**{**cfg.__dict__,
                    "targets": (Target(name="t2", type="test_capture", config={"password": PW}),)})
    _payload(cfg, {"job_id": "j", "connection_id": "c", "target": "t2"})
    assert seen["password"] == PW


def test_job_cannot_tell_the_collector_where_to_connect(cfg):
    # If a job could carry a config, whoever held the control plane could aim this process at any
    # host in the customer's network — or at a broker they own — using the customer's credentials.
    out = _payload(cfg, {"job_id": "j", "connection_id": "c", "target": "t1",
                         "config": {"url": "https://attacker.example", "password": "theirs"},
                         "type": "test_fake"})
    assert out["config"]["url"] == "https://svc.internal:9000"   # local config won
    assert "attacker.example" not in str(out)


def test_unknown_target_is_an_error_not_a_guess(cfg):
    out = _payload(cfg, {"job_id": "j", "connection_id": "c", "target": "nope"})
    assert out["status"] == "error" and "no target named" in out["error"]


def test_connector_failure_reports_without_leaking(cfg):
    CONNECTORS["test_boom"] = lambda c: (_ for _ in ()).throw(
        RuntimeError(f"connection refused for admin:{PW}@svc.internal"))
    cfg = Config(**{**cfg.__dict__,
                    "targets": (Target(name="t3", type="test_boom", config={"password": PW}),)})
    out = _payload(cfg, {"job_id": "j", "connection_id": "c", "target": "t3"})
    assert out["status"] == "error"
    assert "connection refused" in out["error"] and PW not in out["error"]


def test_secret_values_spans_targets_and_the_enroll_token(cfg):
    assert cfg.secret_values() == {PW, "enroll-token-abcdefgh"}


def test_public_config_keeps_the_host_and_drops_the_credential(cfg):
    assert cfg.targets[0].public_config() == {"url": "https://svc.internal:9000",
                                              "password": "[redacted]"}
