"""Free external exposure scan: token format, the ownership gate (DNS TXT / PTR / A-record),
target expansion, the public-safe report, and the router's gate + rate limits.

Offline on purpose: the resolver and the sweep are injected, and the router is built with fake
dependencies and an in-memory DB (the suite's pattern for DB-touching endpoints is the live
end-to-end path; the contracts pinned here are the ones a stranger's first scan depends on).
"""
from __future__ import annotations

import base64
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from vectasec import exposure as X
from vectasec.api.exposure import MAX_SCANS_PER_DAY, build_router
from vectasec.discover.probes import ProbeResult
from vectasec.discover.sweep import Discovery
from vectasec.discover.targets import DEFAULT_PORTS

TODAY = date(2026, 10, 17)
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)


def make_resolver(table: dict):
    """(name, rtype) -> values; records every lookup so a test can assert what was asked."""
    calls: list[tuple[str, str]] = []

    def resolver(name, rtype):
        calls.append((name, rtype))
        return list(table.get((name.lower(), rtype.upper()), []))
    resolver.calls = calls
    return resolver


# ── Tokens ────────────────────────────────────────────────────────────────
def test_token_is_urlsafe_and_long_enough():
    t = X.issue_token()
    assert len(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))) >= 24
    assert all(c.isalnum() or c in "-_" for c in t)
    assert X.issue_token() != t


def test_txt_record_format():
    assert X.txt_record_for("abc") == "vectasec-verify=abc"


# ── verify_domain ─────────────────────────────────────────────────────────
def test_verify_domain_matches_on_apex():
    r = make_resolver({("example.com", "TXT"): ["v=spf1 -all", "vectasec-verify=tok"]})
    ok, detail = X.verify_domain("example.com", "tok", r)
    assert ok and detail == "TXT example.com"


def test_verify_domain_matches_on_vectasec_subdomain_and_strips_quotes():
    r = make_resolver({("_vectasec.example.com", "TXT"): ['"vectasec-verify=tok"']})
    ok, detail = X.verify_domain("Example.COM.", "tok", r)
    assert ok and detail == "TXT _vectasec.example.com"
    assert ("example.com", "TXT") in r.calls and ("_vectasec.example.com", "TXT") in r.calls


def test_verify_domain_mismatch_and_no_record():
    r = make_resolver({("example.com", "TXT"): ["vectasec-verify=other"]})
    ok, detail = X.verify_domain("example.com", "tok", r)
    assert not ok and "none equals" in detail
    ok, detail = X.verify_domain("example.com", "tok", make_resolver({}))
    assert not ok and "no TXT record" in detail


def test_verify_domain_tolerates_resolver_exception():
    def boom(name, rtype):
        raise OSError("resolver down")
    assert X.verify_domain("example.com", "tok", boom) == (
        False, "no TXT record found on example.com or _vectasec.example.com")


# ── verify_ip ─────────────────────────────────────────────────────────────
def test_verify_ip_via_ptr():
    r = make_resolver({("93.184.216.34", "PTR"): ["mq.example.com"]})
    assert X.verify_ip("93.184.216.34", ["example.com"], r) == (True, "ptr")


def test_verify_ip_via_a_record_of_middleware_hostname():
    r = make_resolver({("rabbitmq.example.com", "A"): ["93.184.216.35"]})
    assert X.verify_ip("93.184.216.35", ["example.com"], r) == (True, "a_record")


def test_verify_ip_cidr_every_address_must_be_owned():
    table = {(f"93.184.216.{i}", "PTR"): ["h.example.com"] for i in range(1, 255)}
    r = make_resolver(table)
    assert X.verify_ip("93.184.216.0/24", ["example.com"], r)[0] is True
    del table[("93.184.216.200", "PTR")]
    ok, why = X.verify_ip("93.184.216.0/24", ["example.com"], make_resolver(table))
    assert not ok and "93.184.216.200" in why


def test_verify_ip_rejects_ptr_to_unverified_domain_and_needs_a_domain():
    r = make_resolver({("93.184.216.34", "PTR"): ["notexample.com"]})
    assert X.verify_ip("93.184.216.34", ["example.com"], r)[0] is False
    ok, why = X.verify_ip("93.184.216.34", [], r)
    assert not ok and "verify a domain first" in why


def test_verify_ip_cidr_too_large_is_rejected_without_lookups():
    r = make_resolver({})
    ok, why = X.verify_ip("93.184.0.0/16", ["example.com"], r)
    assert not ok and "/24" in why and r.calls == []


def test_normalize_rejects_private_and_wide_ranges():
    with pytest.raises(ValueError, match="public"):
        X.normalize_ip_or_cidr("ip", "10.0.0.1")
    with pytest.raises(ValueError, match="/24"):
        X.normalize_ip_or_cidr("cidr", "93.184.0.0/20")
    assert X.normalize_ip_or_cidr("cidr", "93.184.216.7/24") == "93.184.216.0/24"
    with pytest.raises(ValueError, match="kind 'ip'"):
        X.normalize_domain("93.184.216.34")
    with pytest.raises(ValueError):
        X.normalize_domain("localhost")
    assert X.normalize_domain(" Example.COM. ") == "example.com"


# ── expand_targets ────────────────────────────────────────────────────────
def test_expand_targets_domain_dedupes_and_covers_middleware_hostnames():
    r = make_resolver({
        ("example.com", "A"): ["93.184.216.34"],
        ("example.com", "AAAA"): ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
        ("rabbitmq.example.com", "A"): ["93.184.216.34", "93.184.216.40"],
        ("kafka.example.com", "A"): ["93.184.216.41"],
    })
    hosts = X.expand_targets("domain", "example.com", r)
    assert hosts == ["93.184.216.34", "2606:2800:21f:cb07:6820:80da:af6b:8b2c",
                     "93.184.216.41", "93.184.216.40"]
    looked_up = {n for n, _ in r.calls}
    assert {"example.com", "kafka.example.com", "n8n.example.com", "mcp.example.com"} <= looked_up


def test_expand_targets_caps_at_max_hosts():
    table = {("example.com", "A"): [f"93.184.{i // 256}.{i % 256}" for i in range(100)]}
    hosts = X.expand_targets("domain", "example.com", make_resolver(table))
    assert len(hosts) == X.MAX_HOSTS == 32


def test_expand_targets_ip_and_cidr():
    assert X.expand_targets("ip", "93.184.216.34") == ["93.184.216.34"]
    hosts = X.expand_targets("cidr", "93.184.216.0/30")
    assert hosts == ["93.184.216.1", "93.184.216.2"]
    with pytest.raises(ValueError):
        X.expand_targets("cidr", "93.184.0.0/16")


# ── attach_cves / eol_status ──────────────────────────────────────────────
def test_attach_cves_uses_curated_dataset():
    hits = X.attach_cves("redis", "7.2.5")
    assert [h["id"] for h in hits] == ["CVE-2025-49844"]
    assert hits[0]["cvss"] == 10.0 and hits[0]["fixed_in"] == "7.2.11" and hits[0]["summary"]
    assert set(hits[0]) == {"id", "cvss", "summary", "fixed_in", "kev", "source_url"}
    assert X.attach_cves("redis", "7.2.11") == []          # fixed-in is exclusive
    assert X.attach_cves("redis", None) == []              # no version, no assertion
    assert X.attach_cves("mqtt", "3.1") == []


def test_eol_status_bands():
    assert X.eol_status("redis", "6.0.9", TODAY)["status"] == "eol"
    assert X.eol_status("redis", "7.2.5", TODAY)["status"] == "supported"
    assert X.eol_status("mqtt", "3", TODAY) == {
        "status": "unknown", "note": "no lifecycle data is curated for mqtt", "source_url": None}
    assert X.eol_status("redis", None, TODAY)["status"] == "unknown"


# ── run_exposure_scan ─────────────────────────────────────────────────────
def _fake_sweep(found: dict):
    """found: {(host, port): ProbeResult}. Records the call so timeout/targets can be asserted."""
    calls = []

    def sweep(targets, timeout):
        calls.append({"targets": targets, "timeout": timeout})
        return [Discovery(target=t, result=found[(t.host, t.port)])
                for t in targets if (t.host, t.port) in found]
    sweep.calls = calls
    return sweep


def test_run_exposure_scan_report_shape_cves_eol_and_scrubbing():
    long_banner = "RabbitMQ server banner " + "x" * 300
    sweep = _fake_sweep({
        ("203.0.113.10", 6379): ProbeResult(
            product="redis", version="7.2.5", transport="plaintext",
            evidence=["redis_version:7.2.5 read from INFO", "password=hunter2 in config line"],
            signals={"auth_required": False}, raw={"banner": "SECRET STUFF"}),
        ("203.0.113.11", 5672): ProbeResult(
            product="rabbitmq", version="3.12.1", transport="plaintext",
            evidence=[long_banner], signals={"auth_required": True, "mechanisms": ["PLAIN"]}),
        ("203.0.113.11", 1883): ProbeResult(
            product="mqtt", version=None, transport="plaintext",
            evidence=["CONNACK code 5"], signals={}),
    })
    report = X.run_exposure_scan(["203.0.113.10", "203.0.113.11"], sweep=sweep, now=NOW)

    assert set(report) == {"targets_probed", "hosts", "ports", "services", "refusals",
                           "partial", "headline", "generated_at"}
    assert report["hosts"] == ["203.0.113.10", "203.0.113.11"]
    assert report["ports"] == list(DEFAULT_PORTS)
    assert report["targets_probed"] == 2 * len(DEFAULT_PORTS)
    assert report["refusals"] == [] and report["partial"] is False
    assert report["generated_at"] == NOW.isoformat()
    assert sweep.calls[0]["timeout"] == 3.0

    svc = {(s["host"], s["port"]): s for s in report["services"]}
    assert list(svc) == [("203.0.113.10", 6379), ("203.0.113.11", 1883), ("203.0.113.11", 5672)]
    redis = svc[("203.0.113.10", 6379)]
    assert set(redis) == {"host", "port", "product", "version", "version_inferred", "transport",
                          "auth_observed", "evidence", "cves", "eol"}
    assert redis["auth_observed"] == "none"
    assert redis["cves"][0]["id"] == "CVE-2025-49844"
    assert redis["eol"]["status"] == "supported"
    assert redis["evidence"] == ["redis_version:7.2.5 read from INFO"]   # secret line dropped

    rmq = svc[("203.0.113.11", 5672)]
    assert rmq["auth_observed"] == "required"
    assert len(rmq["evidence"][0]) <= X.MAX_EVIDENCE_LEN and rmq["evidence"][0].endswith("…")
    assert rmq["eol"]["status"] == "eol" and rmq["cves"][0]["id"] == "CVE-2023-46118"

    mqtt = svc[("203.0.113.11", 1883)]
    assert mqtt["auth_observed"] == "unknown" and mqtt["cves"] == []
    assert mqtt["eol"]["status"] == "unknown"

    blob = repr(report)
    for forbidden in ("SECRET STUFF", "hunter2", "signals", "raw", "mechanisms"):
        assert forbidden not in blob
    assert report["headline"] == ("3 internet-reachable middleware services, 1 with a known "
                                  "critical CVE, 1 past end of life, 1 accepting unauthenticated access.")


def test_run_exposure_scan_empty_and_refusals():
    sweep = _fake_sweep({})
    report = X.run_exposure_scan(["203.0.113.10", "not a host!"], sweep=sweep, now=NOW)
    assert report["services"] == []
    assert report["headline"].startswith("No internet-reachable middleware services")
    assert any("not a host!" in r for r in report["refusals"])
    assert report["targets_probed"] == len(DEFAULT_PORTS)


def test_run_exposure_scan_scales_timeout_to_budget_and_cuts_off_overrun():
    import time
    sweep = _fake_sweep({})
    hosts = [f"203.0.113.{i}" for i in range(1, 201)]
    X.run_exposure_scan(hosts, sweep=sweep, now=NOW, time_budget_s=60)
    assert 1.0 <= sweep.calls[0]["timeout"] < 3.0

    def slow(targets, timeout):
        time.sleep(1.0)
        return []
    report = X.run_exposure_scan(["203.0.113.1"], sweep=slow, now=NOW, time_budget_s=0.05)
    assert report["partial"] is True and any("budget" in r for r in report["refusals"])


# ── Router ────────────────────────────────────────────────────────────────
class FakeCursor:
    def __init__(self, db):
        self.db, self.rows = db, []

    def execute(self, sql, params=()):
        s = " ".join(sql.split()).lower()
        d = self.db
        if "insert into exposure_targets" in s:
            tenant, kind, value, token, _actor = params
            key = (tenant, kind, value)
            if key in d.targets_by_key:
                t = d.targets_by_key[key]
                self.rows = [(t["id"], t["token"], t["verified_at"], False)]
            else:
                t = {"id": str(uuid.uuid4()), "tenant": tenant, "kind": kind, "value": value,
                     "token": token, "verified_at": None, "verify_method": None, "created_at": NOW}
                d.targets[t["id"]] = t
                d.targets_by_key[key] = t
                self.rows = [(t["id"], token, None, True)]
        elif "select kind, value, token, verified_at, verify_method" in s:
            tenant, tid = params
            t = d.targets.get(tid)
            self.rows = [] if not t or t["tenant"] != tenant else [
                (t["kind"], t["value"], t["token"], t["verified_at"], t["verify_method"])]
        elif "select value from exposure_targets" in s:
            self.rows = [(t["value"],) for t in d.targets.values()
                         if t["tenant"] == params[0] and t["kind"] == "domain" and t["verified_at"]]
        elif "update exposure_targets set verified_at" in s:
            method, tenant, tid = params
            d.targets[tid].update(verified_at=NOW, verify_method=method)
        elif "select t.id, t.kind" in s:
            self.rows = []
            for t in d.targets.values():
                if t["tenant"] != params[0]:
                    continue
                scans = [sc for sc in d.scans.values() if sc["target_id"] == t["id"]]
                sc = scans[-1] if scans else None
                self.rows.append((t["id"], t["kind"], t["value"], t["verified_at"],
                                  t["verify_method"], t["created_at"],
                                  sc and sc["id"], sc and sc["status"], sc and sc["started_at"],
                                  sc and sc["finished_at"], sc and sc["report"].get("headline")))
        elif "count(*) filter" in s:
            mine = [sc for sc in d.scans.values() if sc["tenant"] == params[0]]
            running = sum(1 for sc in mine if sc["status"] in ("queued", "running"))
            self.rows = [(running, len(mine))]
        elif "insert into exposure_scans" in s:
            tenant, tid = params
            sc = {"id": str(uuid.uuid4()), "tenant": tenant, "target_id": tid, "status": "running",
                  "started_at": NOW, "finished_at": None, "report": {}, "error": None}
            d.scans[sc["id"]] = sc
            self.rows = [(sc["id"],)]
        elif "update exposure_scans" in s:
            import json
            status, report, error, sid, tenant = params
            d.scans[sid].update(status=status, report=json.loads(report), error=error,
                                finished_at=NOW)
        elif "select s.target_id" in s:
            tenant, sid = params
            sc = d.scans.get(sid)
            if not sc or sc["tenant"] != tenant:
                self.rows = []
            else:
                t = d.targets[sc["target_id"]]
                self.rows = [(sc["target_id"], sc["status"], sc["started_at"], sc["finished_at"],
                              sc["report"], sc["error"], t["kind"], t["value"])]
        else:
            raise AssertionError(f"unexpected SQL: {s[:80]}")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    def __init__(self, db):
        self.db, self.autocommit, self.commits = db, True, 0

    def cursor(self):
        return FakeCursor(self.db)

    def commit(self):
        self.commits += 1
        self.db.commits += 1

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeDB:
    def __init__(self):
        self.targets, self.targets_by_key, self.scans, self.commits = {}, {}, {}, 0

    def __call__(self):
        return FakeConn(self)


TENANT = str(uuid.uuid4())
OTHER = str(uuid.uuid4())


def make_client(db, resolver=None, runner=None, tenant=TENANT):
    audits = []
    p = SimpleNamespace(tenant_id=tenant, actor="user-1", via="jwt", role="admin")
    router = build_router(lambda: p, lambda: p, db,
                          lambda cur, pp, action, target, detail: audits.append((action, target, detail)),
                          resolver=resolver, runner=runner, spawn=lambda fn: fn())
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)
    client.audits = audits
    return client


def test_create_target_201_idempotent_and_validated():
    db = FakeDB()
    c = make_client(db)
    r1 = c.post("/exposure/targets", json={"kind": "domain", "value": "Example.com."})
    assert r1.status_code == 201, r1.text
    body = r1.json()
    assert set(body) == {"target_id", "kind", "value", "token", "txt_record", "txt_names", "verified"}
    assert body["value"] == "example.com" and body["verified"] is False
    assert body["txt_record"] == f"vectasec-verify={body['token']}"
    assert body["txt_names"] == ["example.com", "_vectasec.example.com"]

    r2 = c.post("/exposure/targets", json={"kind": "domain", "value": "example.com"})
    assert r2.status_code == 201
    assert r2.json()["target_id"] == body["target_id"] and r2.json()["token"] == body["token"]
    assert [a[0] for a in c.audits] == ["exposure.target_created"]        # once, not twice

    assert c.post("/exposure/targets", json={"kind": "ip", "value": "10.0.0.1"}).status_code == 400
    assert c.post("/exposure/targets", json={"kind": "cidr", "value": "93.184.0.0/16"}).status_code == 400
    assert c.post("/exposure/targets", json={"kind": "mesh", "value": "x"}).status_code == 422


def test_scan_refused_until_verified_then_runs_and_is_readable():
    db = FakeDB()
    resolver = make_resolver({})
    canned = {"targets_probed": 20, "hosts": ["93.184.216.34"], "services": [], "refusals": [],
              "headline": "No internet-reachable middleware services were identified on the probed hosts.",
              "generated_at": NOW.isoformat()}
    runs = []

    def runner(hosts, time_budget_s):
        runs.append((hosts, time_budget_s))
        return canned
    c = make_client(db, resolver=resolver, runner=runner)
    tid = c.post("/exposure/targets", json={"kind": "domain", "value": "example.com"}).json()["target_id"]
    token = db.targets[tid]["token"]

    r = c.post(f"/exposure/targets/{tid}/scan")
    assert r.status_code == 403 and "not verified" in r.json()["detail"]
    assert runs == []

    v = c.post(f"/exposure/targets/{tid}/verify")
    assert v.status_code == 200
    assert v.json() == {"target_id": tid, "verified": False, "method": None,
                        "checked": ["TXT example.com", "TXT _vectasec.example.com"],
                        "detail": "no TXT record found on example.com or _vectasec.example.com"}
    resolver_ok = make_resolver({("_vectasec.example.com", "TXT"): [f"vectasec-verify={token}"],
                                 ("example.com", "A"): ["93.184.216.34"]})
    c = make_client(db, resolver=resolver_ok, runner=runner)
    v = c.post(f"/exposure/targets/{tid}/verify").json()
    assert v["verified"] is True and v["method"] == "dns_txt"
    assert db.targets[tid]["verify_method"] == "dns_txt"

    r = c.post(f"/exposure/targets/{tid}/scan")
    assert r.status_code == 202, r.text
    sid = r.json()["scan_id"]
    assert runs == [(["93.184.216.34"], 60.0)]
    assert ("exposure.scan_started", sid) in [(a[0], a[1]) for a in c.audits]

    g = c.get(f"/exposure/scans/{sid}")
    assert g.status_code == 200
    body = g.json()
    assert body["status"] == "done" and body["report"] == canned and body["error"] is None
    assert body["target"] == {"kind": "domain", "value": "example.com"}

    lst = c.get("/exposure/targets").json()["targets"]
    assert len(lst) == 1 and lst[0]["verified"] is True
    assert lst[0]["latest_scan"]["status"] == "done"
    assert lst[0]["latest_scan"]["headline"] == canned["headline"]

    # Other tenants see nothing.
    other = make_client(db, tenant=OTHER)
    assert other.get(f"/exposure/scans/{sid}").status_code == 404
    assert other.post(f"/exposure/targets/{tid}/scan").status_code == 404
    assert other.get("/exposure/targets").json()["targets"] == []


def test_scan_errors_land_in_the_row():
    db = FakeDB()
    c = make_client(db, resolver=make_resolver({("example.com", "A"): ["93.184.216.34"]}),
                    runner=lambda hosts, time_budget_s: (_ for _ in ()).throw(RuntimeError("boom")))
    tid = c.post("/exposure/targets", json={"kind": "domain", "value": "example.com"}).json()["target_id"]
    db.targets[tid]["verified_at"] = NOW
    sid = c.post(f"/exposure/targets/{tid}/scan").json()["scan_id"]
    body = c.get(f"/exposure/scans/{sid}").json()
    assert body["status"] == "error" and body["error"] == "RuntimeError: boom"


def test_ip_target_verifies_through_a_verified_domain():
    db = FakeDB()
    r = make_resolver({("93.184.216.34", "PTR"): ["mq.example.com"]})
    c = make_client(db, resolver=r)
    ip = c.post("/exposure/targets", json={"kind": "ip", "value": "93.184.216.34"}).json()
    assert ip["txt_names"] == []
    v = c.post(f"/exposure/targets/{ip['target_id']}/verify").json()
    assert v["verified"] is False and "verify a domain first" in v["detail"]

    dom = c.post("/exposure/targets", json={"kind": "domain", "value": "example.com"}).json()
    db.targets[dom["target_id"]]["verified_at"] = NOW
    v = c.post(f"/exposure/targets/{ip['target_id']}/verify").json()
    assert v["verified"] is True and v["method"] == "ptr"
    assert v["checked"] == ["PTR/A 93.184.216.34", "A/AAAA example.com"]


def test_rate_limits_one_running_and_ten_per_day():
    db = FakeDB()
    done = {"targets_probed": 0, "hosts": [], "services": [], "refusals": [], "headline": "x",
            "generated_at": NOW.isoformat()}
    # spawn that never runs: the scan stays 'running'.
    audits = []
    p = SimpleNamespace(tenant_id=TENANT, actor="u", via="jwt")
    stuck = build_router(lambda: p, lambda: p, db, lambda *a: audits.append(a),
                         runner=lambda hosts, time_budget_s: done,
                         resolver=make_resolver({}), spawn=lambda fn: None)
    app = FastAPI()
    app.include_router(stuck)
    c = TestClient(app)
    tid = c.post("/exposure/targets", json={"kind": "ip", "value": "93.184.216.34"}).json()["target_id"]
    db.targets[tid]["verified_at"] = NOW
    assert c.post(f"/exposure/targets/{tid}/scan").status_code == 202
    r = c.post(f"/exposure/targets/{tid}/scan")
    assert r.status_code == 429 and "already running" in r.json()["detail"]

    # Finish it, then exhaust the daily budget with synchronous runs.
    for sc in db.scans.values():
        sc["status"] = "done"
    c2 = make_client(db, resolver=make_resolver({}), runner=lambda hosts, time_budget_s: done)
    for _ in range(MAX_SCANS_PER_DAY - 1):
        assert c2.post(f"/exposure/targets/{tid}/scan").status_code == 202
    r = c2.post(f"/exposure/targets/{tid}/scan")
    assert r.status_code == 429 and "per day" in r.json()["detail"]
    assert len(db.scans) == MAX_SCANS_PER_DAY
