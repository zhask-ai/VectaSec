"""Proof mode (proof.py): one read-only, pre-authentication action per finding.

What is pinned:
  • the law: a proof is given NO secret (the Vault is never consulted, `config` is the
    connection's non-secret config) and every prover is one of the discover.* probes, which
    never authenticate or write;
  • the target comes only from the connection config or the scanned resource;
  • four verdicts and what each means: an unreachable target is NEVER reported as safe;
  • collector-mode connections are not contacted at all;
  • a proven attempt is stored, and cited in the evidence ledger; others are stored only.
"""
import inspect
import json

import pytest

from vectasec import proof
from vectasec.discover import http_probes as H
from vectasec.discover import probes as P
from vectasec.discover.probes import ProbeResult
from vectasec.registry import DETECTORS
from vectasec import detect as _detect  # noqa: F401 - registers detectors

TENANT = "00000000-0000-0000-0000-000000000001"
FINDING = "44444444-4444-4444-4444-444444444444"


def _with_probe(monkeypatch, rule_id, fn):
    old = proof.PROVERS[rule_id]
    monkeypatch.setitem(proof.PROVERS, rule_id,
                        proof.Prover(fn, old.opened, old.target, old.action))


def test_every_prover_is_a_registered_rule_and_a_discover_probe():
    rule_ids = {d.rule_id for d in DETECTORS}
    allowed = {f for m in (P, H) for _, f in inspect.getmembers(m, inspect.isfunction)
               if f.__name__.startswith("probe_")} | {proof._sweep_probe}
    for rule_id, prover in proof.PROVERS.items():
        assert rule_id in rule_ids, f"{rule_id} is not a rule any detector emits"
        assert prover.probe in allowed, f"{rule_id} uses something other than a discover probe"
        assert "No" in proof.describe(rule_id) and proof.NOT_DONE in proof.describe(rule_id)


def test_the_module_never_touches_credentials():
    """No import of the credential store, and no call that reads a secret."""
    code = [line for line in inspect.getsource(proof).splitlines()
            if line.strip().startswith(("import ", "from "))]
    assert not any("creds" in line or "vault" in line.lower() for line in code)
    assert "merge_secrets" not in inspect.getsource(proof)


@pytest.mark.parametrize("rule_id,config,resource,want", [
    ("REDIS.AUTH.NO_PASSWORD", {"host": "10.0.0.5", "port": "6380", "password": "x"}, {}, ("10.0.0.5", 6380)),
    ("REDIS.AUTH.NO_PASSWORD", {"host": "cache.internal"}, {}, ("cache.internal", 6379)),
    ("ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", {"base_url": "https://es.corp:9243"}, {}, ("es.corp", 9243)),
    ("ELASTICSEARCH.SECURITY.ANONYMOUS_ACCESS", {"base_url": "https://es.corp"}, {}, ("es.corp", 443)),
    ("KONG.ADMIN.UNAUTHENTICATED", {"url": "http://kong:8001"}, {}, ("kong", 8001)),
    ("KAFKA.LISTENER.PLAINTEXT", {"bootstrap": "b1:9092, b2:9092"}, {}, ("b1", 9092)),
    ("NATS.AUTH.NOT_REQUIRED", {"monitoring_url": "http://nats:8222"}, {"raw": {"port": 4333}}, ("nats", 4333)),
    ("NATS.AUTH.NOT_REQUIRED", {"monitoring_url": "http://nats:8222"}, {}, ("nats", 4222)),
    ("DISCOVERY.ACCESS.UNAUTHENTICATED", {"targets": "10.0.0.0/8"}, {"labels": {"host": "10.1.2.3", "port": "6379"}}, ("10.1.2.3", 6379)),
    ("DISCOVERY.ACCESS.UNAUTHENTICATED", {"targets": "10.0.0.0/8"}, {"labels": {}}, None),
    ("REDIS.AUTH.NO_PASSWORD", {}, {}, None),
])
def test_target_comes_from_config_or_resource(rule_id, config, resource, want):
    assert proof.resolve_target(rule_id, config, resource) == want


def test_proven_when_the_door_opens(monkeypatch):
    seen = {}

    def fake(host, port, timeout):
        seen["args"] = (host, port)
        return ProbeResult("redis", "7.2.4", evidence=["INFO answered without AUTH", "redis_version:7.2.4"],
                           signals={"auth_required": False})
    _with_probe(monkeypatch, "REDIS.AUTH.NO_PASSWORD", fake)
    r = proof.run_proof("REDIS.AUTH.NO_PASSWORD", {"host": "h", "password": "S3cret"}, {})
    assert r.verdict == "proven" and r.target == "h:6379" and seen["args"] == ("h", 6379)
    assert r.transcript[0] == "INFO answered without AUTH"
    assert "S3cret" not in json.dumps(r.as_dict())


def test_not_reproduced_when_auth_is_demanded(monkeypatch):
    _with_probe(monkeypatch, "REDIS.AUTH.NO_PASSWORD",
                lambda h, p, t: ProbeResult("redis", evidence=["-NOAUTH Authentication required"],
                                            signals={"auth_required": True}))
    assert proof.run_proof("REDIS.AUTH.NO_PASSWORD", {"host": "h"}, {}).verdict == "not_reproduced"


def test_no_answer_is_unreachable_never_safe(monkeypatch):
    _with_probe(monkeypatch, "REDIS.AUTH.NO_PASSWORD", lambda h, p, t: None)
    r = proof.run_proof("REDIS.AUTH.NO_PASSWORD", {"host": "h"}, {})
    assert r.verdict == "unreachable" and "private, down or filtered" in r.reason

    def boom(h, p, t):
        raise OSError("refused")
    _with_probe(monkeypatch, "REDIS.AUTH.NO_PASSWORD", boom)
    assert proof.run_proof("REDIS.AUTH.NO_PASSWORD", {"host": "h"}, {}).verdict == "unreachable"


def test_collector_connections_are_not_contacted(monkeypatch):
    called = []
    _with_probe(monkeypatch, "REDIS.AUTH.NO_PASSWORD", lambda *a: called.append(a))
    r = proof.run_proof("REDIS.AUTH.NO_PASSWORD", {"host": "h"}, {}, mode="collector")
    assert r.verdict == "unreachable" and called == [] and "says nothing" in r.reason


def test_unsupported_rule_takes_no_action():
    r = proof.run_proof("KAFKA.ACL.WILDCARD_PRINCIPAL", {"bootstrap": "b:9092"}, {})
    assert r.verdict == "unsupported" and r.target is None and "No action" in r.action
    assert not proof.supported("KAFKA.ACL.WILDCARD_PRINCIPAL")


def test_transcript_is_bounded_and_scrubbed(monkeypatch):
    lines = [f"line {i} password=hunter2" for i in range(50)] + ["x" * 5000]
    _with_probe(monkeypatch, "REDIS.AUTH.NO_PASSWORD",
                lambda h, p, t: ProbeResult("redis", evidence=lines,
                                            signals={"auth_required": False, "blob": {"a": 1}}))
    r = proof.run_proof("REDIS.AUTH.NO_PASSWORD", {"host": "h"}, {})
    assert len(r.transcript) == proof.MAX_TRANSCRIPT and "hunter2" not in json.dumps(r.transcript)
    assert "blob" not in r.signals


# ═══ persistence ═══════════════════════════════════════════════════════════
class _Cur:
    def __init__(self, row):
        self.row, self.log, self._one = row, [], None

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.log.append((s, params))
        if s.startswith("select f.rule_id"):
            self._one = self.row
        elif "returning id, created_at" in s:
            self._one = ("proof-1", "2026-11-23T10:00:00+00:00")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return []


ROW = ("REDIS.AUTH.NO_PASSWORD", "open", "rid-1", "redis_server", "h:6379", {}, {},
       "conn-1", "redis", {"host": "h"}, "cloud")


def _runner(verdict):
    return lambda rule, config, resource, mode="cloud": proof.ProofResult(
        verdict, "action", "h:6379", ["INFO answered without AUTH"], {"auth_required": False})


def test_proven_attempt_is_stored_and_cited_in_the_ledger():
    cur = _Cur(ROW)
    out = proof.prove_finding(cur, TENANT, FINDING, "user-1", runner=_runner("proven"))
    inserts = [s for s, _ in cur.log if s.startswith("insert into")]
    assert [s.split()[2] for s in inserts] == ["finding_proofs", "observations"]
    obs = next(p for s, p in cur.log if s.startswith("insert into observations"))
    assert "Proven reachable without credentials at h:6379" in obs[3]
    assert json.loads(obs[4])["kind"] == "proof"
    assert out["verdict"] == "proven" and out["id"] == "proof-1"


def test_other_verdicts_are_stored_but_not_cited_as_evidence():
    cur = _Cur(ROW)
    proof.prove_finding(cur, TENANT, FINDING, None, runner=_runner("not_reproduced"))
    assert [s.split()[2] for s, _ in cur.log if s.startswith("insert into")] == ["finding_proofs"]


def test_missing_finding_and_missing_connection():
    assert proof.prove_finding(_Cur(None), TENANT, FINDING) is None
    gone = ("REDIS.AUTH.NO_PASSWORD", "open", None, None, None, None, None, None, None, None, None)
    cur = _Cur(gone)
    out = proof.prove_finding(cur, TENANT, FINDING, runner=_runner("proven"))
    assert out["verdict"] == "unreachable", "no connection means nothing is contacted"
