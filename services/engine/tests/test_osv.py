"""osv.py — the live OSV feed enrichment hook.

Hermetic: the two HTTP seams (`_osv_post`, `_osv_get`) are monkeypatched, and the module-level
kill-switch env var is cleared for every test. The DB is the same SQL-dispatch FakeCursor shape
the notify tests use.

The tests encode the module's honesty contract explicitly, because the audit rounds proved
twice that a test asserting `== []` under an "unreachable"/"unknown" name is a test asserting
the silent-pass bug:
  * feed unreachable  -> a NOT-ASSESSABLE gap finding, never zero findings;
  * feed disabled     -> zero findings AND zero network calls AND stats saying disabled;
  * feed answers      -> findings that cite each advisory individually.
"""
import pytest

from vectasec import osv


# ── CVSS v3 base-score arithmetic ──────────────────────────────────────────────
@pytest.mark.parametrize("vector,score", [
    # Spec-checked values (each verifiable against the FIRST.org calculator).
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),   # changed scope, elevated PR weight
    ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),   # 3.0 prefix uses the same math
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),   # zero impact means zero, not 0.1
])
def test_cvss3_base_score_known_vectors(vector, score):
    assert osv.cvss3_base_score(vector) == score


@pytest.mark.parametrize("vector", [
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # v4 math is different
    "CVSS:3.1/AV:N/AC:L",                                               # metrics missing
    "not a vector",
    "",
    None,
])
def test_cvss3_base_score_refuses_what_it_cannot_score(vector):
    # Mis-scoring a v4 vector with v3 weights would be a fabricated number; None routes the
    # caller to the fallback chain instead.
    assert osv.cvss3_base_score(vector) is None


def test_advisory_severity_prefers_vector_then_label_then_explicit_default():
    vec = {"severity": [{"type": "CVSS_V3",
                         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    band, derived, score = osv.advisory_severity(vec)
    assert (band, derived, score) == ("critical", "cvss_v3 9.8", 9.8)

    label = {"database_specific": {"severity": "MODERATE"}}
    band, derived, score = osv.advisory_severity(label)
    assert band == "medium" and "moderate" in derived and score is None

    band, derived, score = osv.advisory_severity({})
    assert band == "medium" and "stated no severity" in derived and score is None


def test_fixed_versions_collects_across_ranges():
    vuln = {"affected": [
        {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.12.7"}]}]},
        {"ranges": [{"events": [{"introduced": "3.11.0"}, {"fixed": "3.11.24"}]}]},
    ]}
    assert osv._fixed_versions(vuln) == ["3.11.24", "3.12.7"]


# ── DB fakes (SQL-dispatch, same shape as the notify tests) ────────────────────
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
    def __init__(self, resource_rows, suppressions=()):
        self.resource_rows = list(resource_rows)
        self.suppressions = list(suppressions)
        self.findings: list = []
        self.observations: list = []

    def cursor(self):
        return FakeCursor(self)


# (id, kind, name, ext_id, labels, raw-projection, connection type) — the projected row shape.
def _redis_row(version="7.2.4", inferred=False):
    raw = {"redis_version": version}
    if inferred:
        raw["version_inferred"] = True
    return ("rid-1", "redis_server", "redis@localhost", "redis-server",
            {}, raw, "redis")


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    monkeypatch.delenv("VECTASEC_OSV_DISABLED", raising=False)
    # Any HTTP that a test did not explicitly script is a hermeticity bug, not a slow test.
    monkeypatch.setattr(osv, "_osv_post",
                        lambda *a, **k: pytest.fail("unexpected _osv_post"))
    monkeypatch.setattr(osv, "_osv_get",
                        lambda *a, **k: pytest.fail("unexpected _osv_get"))


# ── enrich_osv ─────────────────────────────────────────────────────────────────
def test_feed_hit_files_one_finding_with_one_observation_per_advisory(monkeypatch):
    conn = FakeConn([_redis_row()])
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {
        "results": [{"vulns": [{"id": "GHSA-aaaa"}, {"id": "GHSA-bbbb"}]}]})
    details = {
        "GHSA-aaaa": {"id": "GHSA-aaaa", "aliases": ["CVE-2099-0001"],
                      "summary": "heap overflow",
                      "severity": [{"type": "CVSS_V3",
                                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                      "affected": [{"ranges": [{"events": [{"fixed": "7.2.11"}]}]}]},
        "GHSA-bbbb": {"id": "GHSA-bbbb", "aliases": [],
                      "summary": "minor DoS",
                      "database_specific": {"severity": "LOW"}},
    }
    monkeypatch.setattr(osv, "_osv_get", lambda url: details[url.rsplit("/", 1)[1]])

    stats = osv.enrich_osv(conn, "t1", "c1", "s1")

    assert stats == {"enabled": True, "components": 1, "queried": 1, "advisories": 2,
                     "skipped_curated": 0, "findings": 1}
    assert len(conn.findings) == 1
    row = conn.findings[0]
    assert row[3] == osv.RULE_VULN
    assert row[6] == "critical"                      # worst advisory wins the row
    assert row[7] == "open"
    assert row[10] == "assessed"
    # One citation per advisory, each naming its id, the fix, and the feed URL.
    assert len(conn.observations) == 2
    claims = [o[3] for o in conn.observations]
    assert any("GHSA-aaaa" in c and "fixed in 7.2.11" in c
               and "osv.dev/vulnerability/GHSA-aaaa" in c for c in claims)
    assert any("GHSA-bbbb" in c and "severity low" in c for c in claims)


def test_advisory_already_in_curated_dataset_is_skipped(monkeypatch):
    # CVE-2025-49844 is in cve_data.py for redis: detect/cve.py already files it with
    # KEV/ATT&CK context. Filing it again here would be a duplicate row for the same defect.
    conn = FakeConn([_redis_row()])
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {
        "results": [{"vulns": [{"id": "GHSA-redi"}]}]})
    monkeypatch.setattr(osv, "_osv_get", lambda url: {
        "id": "GHSA-redi", "aliases": ["CVE-2025-49844"], "summary": "RediShell"})

    stats = osv.enrich_osv(conn, "t1", "c1", "s1")

    assert stats["skipped_curated"] == 1
    assert stats["findings"] == 0
    assert conn.findings == []


def test_feed_unreachable_files_a_not_assessable_gap_never_silence(monkeypatch):
    conn = FakeConn([_redis_row()])

    def boom(url, body):
        raise ConnectionError("egress blocked")
    monkeypatch.setattr(osv, "_osv_post", boom)

    stats = osv.enrich_osv(conn, "t1", "c1", "s1")

    assert stats["feed_error"].startswith("ConnectionError")
    assert len(conn.findings) == 1
    row = conn.findings[0]
    assert row[3] == osv.RULE_GAP
    assert row[10] == "not_assessable"
    claim = conn.observations[0][3]
    assert "pkg:bitnami/redis@7.2.4" in claim and "could not be checked" in claim


def test_misaligned_batch_answer_is_a_gap_not_a_misattribution(monkeypatch):
    # Positional alignment IS the querybatch contract; a short answer silently zipped onto
    # the wrong components would attribute advisories to the wrong systems.
    conn = FakeConn([_redis_row()])
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {"results": []})

    stats = osv.enrich_osv(conn, "t1", "c1", "s1")

    assert "feed_error" in stats
    assert conn.findings[0][3] == osv.RULE_GAP


def test_disabled_env_makes_no_network_call_and_says_so(monkeypatch):
    monkeypatch.setenv("VECTASEC_OSV_DISABLED", "1")
    conn = FakeConn([_redis_row()])
    # The autouse fixture's seams fail the test if any HTTP is attempted.

    stats = osv.enrich_osv(conn, "t1", "c1", "s1")

    assert stats["enabled"] is False
    assert conn.findings == []


def test_no_purl_components_means_no_query(monkeypatch):
    # A kong node has a CPE but no bitnami purl; a versionless resource has neither.
    conn = FakeConn([
        ("rid-2", "broker", "kong-node", "kong-1", {"edition": "oss"},
         {"version": "3.6.0"}, "kong"),
        ("rid-3", "topic", "payments", "topic-payments", {}, {}, "kafka"),
    ])
    stats = osv.enrich_osv(conn, "t1", "c1", "s1")
    assert stats["components"] == 0
    assert conn.findings == []


def test_clean_feed_answer_files_nothing(monkeypatch):
    conn = FakeConn([_redis_row()])
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {"results": [{}]})
    stats = osv.enrich_osv(conn, "t1", "c1", "s1")
    assert stats["advisories"] == 0 and conn.findings == []


def test_suppression_is_honoured_at_write_time(monkeypatch):
    conn = FakeConn([_redis_row()],
                    suppressions=[(osv.RULE_VULN, None)])   # tenant-wide
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {
        "results": [{"vulns": [{"id": "GHSA-cccc"}]}]})
    monkeypatch.setattr(osv, "_osv_get", lambda url: {"id": "GHSA-cccc", "summary": "x"})

    osv.enrich_osv(conn, "t1", "c1", "s1")

    assert conn.findings[0][7] == "suppressed"


def test_detail_budget_exhausted_still_cites_by_id(monkeypatch):
    monkeypatch.setattr(osv, "MAX_VULN_DETAILS", 0)
    conn = FakeConn([_redis_row()])
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {
        "results": [{"vulns": [{"id": "GHSA-dddd"}]}]})
    # _osv_get stays the autouse tripwire: budget 0 must mean zero detail fetches.

    stats = osv.enrich_osv(conn, "t1", "c1", "s1")

    assert stats["findings"] == 1
    claim = conn.observations[0][3]
    assert "GHSA-dddd" in claim and "budget" in claim
    assert "per-run detail budget" in conn.findings[0][9]   # the cap is stated, not silent


def test_inferred_version_is_declared_in_the_claim(monkeypatch):
    conn = FakeConn([_redis_row(inferred=True)])
    monkeypatch.setattr(osv, "_osv_post", lambda url, body: {
        "results": [{"vulns": [{"id": "GHSA-eeee"}]}]})
    monkeypatch.setattr(osv, "_osv_get", lambda url: {"id": "GHSA-eeee", "summary": "x"})

    osv.enrich_osv(conn, "t1", "c1", "s1")

    assert "inferred" in conn.observations[0][3]


def test_query_batch_chunks_and_realigns(monkeypatch):
    calls = []

    def post(url, body):
        calls.append(len(body["queries"]))
        return {"results": [{"vulns": []} for _ in body["queries"]]}
    monkeypatch.setattr(osv, "_osv_post", post)
    monkeypatch.setattr(osv, "BATCH_CHUNK", 2)

    out = osv._query_batch([f"pkg:bitnami/redis@{i}" for i in range(5)])

    assert calls == [2, 2, 1]
    assert out == [[], [], [], [], []]
