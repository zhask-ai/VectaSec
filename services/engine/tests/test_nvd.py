"""nvd.py — the live NVD feed enrichment hook, the CPE half of vulnerability coverage.

Hermetic: the HTTP seam (`_nvd_get`) and the rate-limit sleep seam (`_sleep`) are both
monkeypatched, so a full-estate test costs no network and no wall clock. The DB is the same
SQL-dispatch FakeCursor shape the osv/notify tests use.

The tests encode the module's honesty contract explicitly, because a test asserting `== []`
under an "unreachable" or "budget exhausted" name is a test asserting the silent-pass bug:
  * feed unreachable / budget exceeded -> a NOT-ASSESSABLE gap naming every CPE, never zero;
  * feed disabled                      -> zero findings AND zero network calls AND stats say so;
  * feed answers                       -> one finding per component, one citation per CVE.
"""
import json
import urllib.parse

import pytest

from vectasec import nvd

KONG_CPE = "cpe:2.3:a:konghq:kong_gateway:3.6.0:*:*:*:*:*:*:*"
PULSAR_CPE = "cpe:2.3:a:apache:pulsar:3.2.0:*:*:*:*:*:*:*"
REDIS_CPE = "cpe:2.3:a:redis:redis:7.2.4:*:*:*:*:*:*:*"


# ── Feed-shaped fixtures ───────────────────────────────────────────────────────
def cve_record(cid="CVE-2099-0001", *, score=9.8, metric="cvssMetricV31",
               severity_word="CRITICAL", status="Analyzed", desc="remote code execution",
               end=None, end_criteria="cpe:2.3:a:konghq:kong_gateway:*:*:*:*:*:*:*:*",
               tags=None, metrics=None):
    """One `vulnerabilities[].cve` object in the shape NVD's /cves/2.0 actually returns."""
    cve = {"id": cid, "vulnStatus": status,
           "descriptions": [{"lang": "es", "value": "ejecución remota"},
                            {"lang": "en", "value": desc}]}
    if metrics is not None:
        cve["metrics"] = metrics
    elif score is not None:
        cve["metrics"] = {metric: [{"source": "nvd@nist.gov", "type": "Primary",
                                    "cvssData": {"baseScore": score,
                                                 "baseSeverity": severity_word}}]}
    if end:
        cve["configurations"] = [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": end_criteria, "versionEndExcluding": end}]}]}]
    if tags:
        cve["cveTags"] = [{"sourceIdentifier": "cna@example.test", "tags": tags}]
    return cve


def feed(*cves, total=None):
    return {"vulnerabilities": [{"cve": c} for c in cves],
            "totalResults": len(cves) if total is None else total}


# ── DB fakes (SQL-dispatch, same shape as the osv/notify tests) ────────────────
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
        if s.startswith("select r.id, r.kind"):
            self._all = self.db.resource_rows
        elif s.startswith("select rule_id, scope from suppressions"):
            self._all = self.db.suppressions
        elif s.startswith("select f.resource_id, o.source_ref"):
            self._all = self.db.osv_rows
        elif s.startswith("insert into findings"):
            self.db.findings.append(params)
            self._one = (f"finding-{len(self.db.findings)}",)
        elif s.startswith("insert into observations"):
            self.db.observations.append(params)
        else:
            raise AssertionError(f"unexpected SQL: {s}")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class FakeConn:
    def __init__(self, resource_rows, suppressions=(), osv_rows=()):
        self.resource_rows = list(resource_rows)
        self.suppressions = list(suppressions)
        self.osv_rows = list(osv_rows)
        self.findings: list = []
        self.observations: list = []

    def cursor(self):
        return FakeCursor(self)


# (id, kind, name, ext_id, labels, raw-projection, connection type) — the projected row shape.
def _kong_row(version="3.6.0", inferred=False):
    """A CPE with NO bitnami purl — the exact coverage hole this module exists to close."""
    raw = {"version": version}
    if inferred:
        raw["version_inferred"] = True
    return ("rid-kong", "broker", "kong-node", "kong-1", {}, raw, "kong")


def _pulsar_row():
    return ("rid-pulsar", "broker", "pulsar-broker", "pulsar-1", {}, {"version": "3.2.0"},
            "pulsar")


def _redis_row():
    """Both identifiers: OSV already answered for this one, so NVD skips it unless asked."""
    return ("rid-redis", "redis_server", "redis@localhost", "redis-server", {},
            {"redis_version": "7.2.4"}, "redis")


def _valkey_row():
    """A purl but deliberately NO CPE (sbom.py refuses to invent one) — never queryable here."""
    return ("rid-valkey", "broker", "valkey", "valkey-1", {}, {"version": "8.0.1"}, "valkey")


@pytest.fixture(autouse=True)
def sleeps(monkeypatch):
    """Recorded rate-limit pauses. Also the hermeticity tripwire: any HTTP a test did not
    script fails it, and no test ever spends six real seconds honouring NVD's rate limit."""
    recorded: list[float] = []
    for var in ("VECTASEC_NVD_DISABLED", "VECTASEC_NVD_ALL", "NVD_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(nvd, "_sleep", recorded.append)
    monkeypatch.setattr(nvd, "_nvd_get",
                        lambda *a, **k: pytest.fail("unexpected _nvd_get"))
    return recorded


def script(monkeypatch, by_cpe: dict, *, fail=()):
    """Serve canned responses keyed by CPE; return the (url, headers) log."""
    calls: list[tuple[str, dict]] = []

    def get(url, headers):
        calls.append((url, headers))
        for cpe, resp in by_cpe.items():
            if urllib.parse.quote(cpe, safe="") in url:
                if cpe in fail:
                    raise ConnectionError("egress blocked")
                return resp
        raise AssertionError(f"unscripted NVD request: {url}")

    monkeypatch.setattr(nvd, "_nvd_get", get)
    return calls


# ── Severity banding ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("metric,score,band", [
    ("cvssMetricV31", 9.8, "critical"),
    ("cvssMetricV31", 9.0, "critical"),   # the band edge itself is critical, not high
    ("cvssMetricV31", 7.4, "high"),
    ("cvssMetricV30", 5.0, "medium"),
    ("cvssMetricV30", 4.0, "medium"),
    ("cvssMetricV2", 3.5, "low"),
    ("cvssMetricV31", 0.0, "info"),       # zero impact is info, not low
])
def test_band_edges_are_the_ones_osv_uses(metric, score, band):
    # The edges are IMPORTED from osv.py, never restated here: two feeds disagreeing about
    # what "high" means would make the severity column meaningless.
    got_band, derived, got_score, got_metric = nvd.cve_severity(
        cve_record(score=score, metric=metric))
    assert (got_band, got_score, got_metric) == (band, score, metric)
    assert str(score) in derived


def test_newest_cvss_generation_wins():
    # A legacy v2 score on a modern CVE would band a critical defect as medium.
    both = cve_record(metrics={
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
    })
    assert nvd.cve_severity(both)[:1] == ("critical",)
    assert nvd.cve_severity(both)[3] == "cvssMetricV31"


def test_absent_metrics_is_medium_and_says_nvd_published_no_score():
    band, derived, score, metric = nvd.cve_severity(cve_record(score=None))
    assert (band, score, metric) == ("medium", None, None)
    assert "no CVSS score" in derived            # never a fabricated number


def test_affected_ceilings_only_lift_versions_off_our_own_product():
    # One CVE's configuration can list a dozen unrelated products; an upgrade target taken
    # off the wrong one sends an operator to patch software they do not run.
    cve = cve_record(end="3.6.1")
    cve["configurations"][0]["nodes"].append({"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:pulsar:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "9.9.9"}]})
    assert nvd._affected_ceilings(cve, KONG_CPE) == ["3.6.1"]


def test_non_vulnerable_configuration_rows_are_not_upgrade_targets():
    cve = cve_record(end="3.6.1")
    cve["configurations"][0]["nodes"][0]["cpeMatch"][0]["vulnerable"] = False
    assert nvd._affected_ceilings(cve, KONG_CPE) == []


# ── enrich_nvd ─────────────────────────────────────────────────────────────────
def test_feed_hit_files_one_finding_with_one_observation_per_cve(monkeypatch):
    conn = FakeConn([_kong_row()])
    calls = script(monkeypatch, {KONG_CPE: feed(
        cve_record("CVE-2099-0001", score=9.8, desc="admin API RCE", end="3.6.1"),
        cve_record("CVE-2099-0002", score=5.4, metric="cvssMetricV30", desc="header smuggling"),
    )})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    # `requests` is tracked separately from `queried` because a component can carry several
    # alias CPEs — `queried` counting 25 while 100 requests went out is how the budget came to
    # authorise ten minutes of blocking sleep.
    assert stats == {"enabled": True, "mode": "components_without_purl", "components": 1,
                     "queried": 1, "cves": 2, "skipped_curated": 0, "skipped_osv": 0,
                     "skipped_rejected": 0, "unchecked": 0, "findings": 1,
                     "requests": 1, "requests_planned": 1}
    assert len(calls) == 1
    # cpeName is exact-match INCLUDING the version, so NVD does the range matching for us.
    assert "cpeName=cpe%3A2.3%3Aa%3Akonghq%3Akong_gateway%3A3.6.0" in calls[0][0]
    assert calls[0][1] == {}                          # no key configured, no key header

    assert len(conn.findings) == 1
    row = conn.findings[0]
    assert row[3] == nvd.RULE_VULN
    assert row[6] == "critical"                       # worst CVE wins the row
    assert row[7] == "open"
    assert row[10] == "assessed"
    assert KONG_CPE in row[9]

    assert len(conn.observations) == 2
    claims = [o[3] for o in conn.observations]
    assert any("CVE-2099-0001" in c and "admin API RCE" in c and KONG_CPE in c
               and "versions below 3.6.1" in c
               and "nvd.nist.gov/vuln/detail/CVE-2099-0001" in c for c in claims)
    assert any("CVE-2099-0002" in c and "severity medium" in c for c in claims)


def test_missing_score_is_declared_in_the_claim_not_invented(monkeypatch):
    conn = FakeConn([_kong_row()])
    script(monkeypatch, {KONG_CPE: feed(cve_record("CVE-2099-0003", score=None))})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert conn.findings[0][6] == "medium"
    assert "no CVSS score" in conn.observations[0][3]
    assert "no_cvss_score=1" in conn.findings[0][9]


def test_disputed_cve_is_filed_but_labelled(monkeypatch):
    conn = FakeConn([_kong_row()])
    script(monkeypatch, {KONG_CPE: feed(
        cve_record("CVE-2099-0004", tags=["disputed"]))})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert "DISPUTED" in conn.observations[0][3]


def test_rejected_cves_are_skipped(monkeypatch):
    # A withdrawn CVE filed as a finding is a false positive with a paper trail behind it.
    conn = FakeConn([_kong_row()])
    script(monkeypatch, {KONG_CPE: feed(
        cve_record("CVE-2099-0005", status="Rejected"),
        cve_record("CVE-2099-0006"),
    )})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["skipped_rejected"] == 1 and stats["cves"] == 1
    assert len(conn.observations) == 1
    assert "CVE-2099-0006" in conn.observations[0][3]


def test_curated_pack_overlap_is_skipped(monkeypatch):
    # CVE-2025-49844 is in cve_data.py for redis: detect/cve.py already files it with
    # KEV/ATT&CK context. Filing it again here would be a duplicate row for one defect.
    monkeypatch.setenv("VECTASEC_NVD_ALL", "1")
    conn = FakeConn([_redis_row()])
    script(monkeypatch, {REDIS_CPE: feed(cve_record("CVE-2025-49844"))})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["skipped_curated"] == 1
    assert stats["findings"] == 0 and conn.findings == []


def test_osv_feed_overlap_is_skipped_via_id_or_alias(monkeypatch):
    # OSV files GHSA ids; the CVE number NVD returns only meets its OSV twin in `aliases`.
    conn = FakeConn([_kong_row()],
                    osv_rows=[("rid-kong", {"osv_id": "GHSA-zzzz",
                                            "aliases": ["CVE-2099-0007"]}),
                              ("rid-kong", {"osv_id": "CVE-2099-0008", "aliases": []})])
    script(monkeypatch, {KONG_CPE: feed(
        cve_record("CVE-2099-0007"), cve_record("CVE-2099-0008"), cve_record("CVE-2099-0009"),
    )})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["skipped_osv"] == 2 and stats["cves"] == 1
    assert len(conn.observations) == 1
    assert "CVE-2099-0009" in conn.observations[0][3]


def test_osv_overlap_is_scoped_to_the_same_resource(monkeypatch):
    # An advisory filed against the Redis node says nothing about the Kong node next to it;
    # a connection-wide set would silently drop a real Kong CVE that shared an id.
    conn = FakeConn([_kong_row()],
                    osv_rows=[("rid-redis", {"osv_id": "CVE-2099-0007", "aliases": []})])
    script(monkeypatch, {KONG_CPE: feed(cve_record("CVE-2099-0007"))})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["skipped_osv"] == 0 and stats["findings"] == 1


def test_feed_unreachable_files_exactly_one_not_assessable_naming_the_cpes(monkeypatch):
    conn = FakeConn([_kong_row(), _pulsar_row()])
    script(monkeypatch, {KONG_CPE: feed(), PULSAR_CPE: feed()},
           fail=(KONG_CPE, PULSAR_CPE))

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["queried"] == 0 and stats["unchecked"] == 2
    assert stats["feed_error"].startswith("ConnectionError")
    assert len(conn.findings) == 1                     # ONE gap for the connection, not two
    row = conn.findings[0]
    assert row[3] == nvd.RULE_GAP
    assert row[6] == "info"
    assert row[10] == "not_assessable"
    assert KONG_CPE in row[9] and PULSAR_CPE in row[9]
    claims = " | ".join(o[3] for o in conn.observations)
    assert KONG_CPE in claims and PULSAR_CPE in claims
    assert "was not checked" in claims


def test_partial_feed_failure_still_files_the_findings_it_did_get(monkeypatch):
    conn = FakeConn([_kong_row(), _pulsar_row()])
    script(monkeypatch, {KONG_CPE: feed(cve_record("CVE-2099-0010")), PULSAR_CPE: feed()},
           fail=(PULSAR_CPE,))

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["queried"] == 1 and stats["unchecked"] == 1 and stats["findings"] == 2
    rules = [f[3] for f in conn.findings]
    assert rules == [nvd.RULE_VULN, nvd.RULE_GAP]


def test_component_budget_is_stated_never_silently_truncated(monkeypatch):
    monkeypatch.setattr(nvd, "MAX_REQUESTS", 1)
    conn = FakeConn([_kong_row(), _pulsar_row()])
    calls = script(monkeypatch, {KONG_CPE: feed()})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert len(calls) == 1                             # the cap really capped
    assert stats["unchecked"] == 1 and stats["findings"] == 1
    assert conn.findings[0][3] == nvd.RULE_GAP
    assert PULSAR_CPE in conn.observations[0][3] and "budget" in conn.observations[0][3]
    assert "MAX_REQUESTS" in conn.findings[0][8]     # remediation names the knob to turn


def test_disabled_env_makes_no_network_call_and_says_so(monkeypatch):
    monkeypatch.setenv("VECTASEC_NVD_DISABLED", "1")
    conn = FakeConn([_kong_row()])
    # The autouse fixture's seams fail the test if any HTTP is attempted.

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["enabled"] is False
    assert conn.findings == []                         # and NO unclosable gap finding


def test_default_mode_queries_only_components_osv_could_not_see(monkeypatch):
    conn = FakeConn([_kong_row(), _redis_row()])
    calls = script(monkeypatch, {KONG_CPE: feed()})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["mode"] == "components_without_purl"
    assert stats["components"] == 1                    # redis has a purl; OSV answered for it
    assert len(calls) == 1 and "kong_gateway" in calls[0][0]


def test_all_mode_queries_every_cpe_bearing_component(monkeypatch, sleeps):
    monkeypatch.setenv("VECTASEC_NVD_ALL", "1")
    conn = FakeConn([_kong_row(), _redis_row()])
    calls = script(monkeypatch, {KONG_CPE: feed(), REDIS_CPE: feed()})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["mode"] == "all_cpe_components" and stats["components"] == 2
    assert len(calls) == 2
    # One pause BETWEEN the two requests, none before the first.
    assert sleeps == [nvd._PAUSE_ANON]


def test_api_key_is_sent_and_shortens_the_rate_limit_pause(monkeypatch, sleeps):
    monkeypatch.setenv("NVD_API_KEY", "secret-key")
    conn = FakeConn([_kong_row(), _pulsar_row()])
    calls = script(monkeypatch, {KONG_CPE: feed(), PULSAR_CPE: feed()})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert all(h == {"apiKey": "secret-key"} for _, h in calls)
    assert sleeps == [nvd._PAUSE_KEYED]


def test_component_without_a_cpe_is_never_queried(monkeypatch):
    # valkey deliberately carries no CPE in sbom.py — a fabricated one would make an empty
    # NVD result look like a clean bill of health.
    conn = FakeConn([_valkey_row(),
                     ("rid-topic", "topic", "payments", "topic-payments", {}, {}, "kafka")])

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["components"] == 0 and stats["unchecked"] == 0
    assert conn.findings == []


def test_clean_feed_answer_files_nothing(monkeypatch):
    conn = FakeConn([_kong_row()])
    script(monkeypatch, {KONG_CPE: feed()})

    stats = nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert stats["queried"] == 1 and stats["cves"] == 0
    assert conn.findings == []


def test_truncated_page_is_stated_in_the_detail(monkeypatch):
    conn = FakeConn([_kong_row()])
    script(monkeypatch, {KONG_CPE: feed(cve_record("CVE-2099-0011"), total=900)})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert "nvd_reported_total=900" in conn.findings[0][9]


def test_inferred_version_is_declared_in_the_claim(monkeypatch):
    conn = FakeConn([_kong_row(inferred=True)])
    script(monkeypatch, {KONG_CPE: feed(cve_record("CVE-2099-0012"))})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert "inferred" in conn.observations[0][3]
    assert "version_inferred=true" in conn.findings[0][9]


def test_suppression_is_honoured_at_write_time(monkeypatch):
    conn = FakeConn([_kong_row()], suppressions=[(nvd.RULE_VULN, None)])   # tenant-wide
    script(monkeypatch, {KONG_CPE: feed(cve_record("CVE-2099-0013"))})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert conn.findings[0][7] == "suppressed"


def test_every_observation_carries_a_traceable_source_ref(monkeypatch):
    conn = FakeConn([_kong_row()])
    script(monkeypatch, {KONG_CPE: feed(
        cve_record("CVE-2099-0014", score=7.5, desc="path traversal", end="3.7.0"))})

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    ref = json.loads(conn.observations[0][4])
    assert ref["evidence_type"] == "nvd_feed"
    assert ref["cve_id"] == "CVE-2099-0014"
    assert ref["cvss_score"] == 7.5 and ref["severity_band"] == "high"
    assert ref["cvss_metric"] == "cvssMetricV31"
    # Everything the SBOM's vulnerabilities[] section renders, without a second round-trip.
    assert ref["summary"] == "path traversal"
    assert ref["version_end_excluding"] == ["3.7.0"]
    assert ref["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2099-0014"
    assert ref["cpe"] == KONG_CPE
    # The exact request a human can re-run to check the claim themselves.
    assert ref["query_url"].startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=")


def test_an_alias_matched_cve_cites_the_cpe_that_actually_returned_it(monkeypatch):
    """The whole point of the alias table is finding advisories filed under a vendor's OLDER
    name. Citing the primary CPE for those named an identifier that was never queried, dropped
    the fixed-in version (the ceiling filter keys on vendor:product), and published a query_url
    that returns nothing — so an operator checking the evidence would call it fabricated."""
    rabbit = ("rid-rabbit", "node", "rabbit@host", "node-rabbit", {},
              {"rabbitmq_version": "3.13.7"}, "rabbitmq")
    conn = FakeConn([rabbit])
    primary = "cpe:2.3:a:broadcom:rabbitmq_server:3.13.7:*:*:*:*:*:*:*"
    alias = "cpe:2.3:a:pivotal_software:rabbitmq:3.13.7:*:*:*:*:*:*:*"
    monkeypatch.setenv("VECTASEC_NVD_ALL", "1")       # rabbitmq has a purl, so widen the scope
    script(monkeypatch, {
        primary: feed(),
        "cpe:2.3:a:vmware:rabbitmq:3.13.7:*:*:*:*:*:*:*": feed(),
        "cpe:2.3:a:pivotal_software:rabbitmq_management:3.13.7:*:*:*:*:*:*:*": feed(),
        alias: feed(cve_record("CVE-2099-7777", score=7.5, desc="only under the old vendor",
                               end="3.13.8",
                               end_criteria="cpe:2.3:a:pivotal_software:rabbitmq:*:*:*:*:*:*:*:*")),
    })

    nvd.enrich_nvd(conn, "t1", "c1", "s1")

    assert len(conn.observations) == 1
    claim = conn.observations[0][3]
    ref = json.loads(conn.observations[0][4])
    assert alias in claim and primary not in claim
    assert ref["matched_cpe"] == alias
    assert "pivotal_software" in ref["query_url"]
    # The ceiling filter keys on vendor:product, so the primary would have dropped this.
    assert ref["version_end_excluding"] == ["3.13.8"]
