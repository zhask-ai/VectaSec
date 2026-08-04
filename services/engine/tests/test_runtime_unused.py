"""`assess_unused` — the windowed negative-evidence claim, and the three things that gate it.

"This identity has never been observed in use" is the strongest claim the product makes from
absence, so it is the one most able to be wrong. Three separate gates stand in front of it, and
each has a distinct failure mode if it is removed:

  * **No runtime source** → say nothing. Kong and MCP have no live-client API, and identity.py
    still derives identities for them, so without this gate every such connection files an
    unclosable coverage gap on every scan forever.
  * **Window too short** → one honest gap, not N accusations. A fortnight of silence from a
    monthly batch job is not evidence.
  * **Evidence that cannot be ATTRIBUTED** → one honest gap, and one that explicitly does not
    close with time. Kafka's DescribeConsumerGroups reports a self-asserted `client.id` and no
    authenticated principal, so a Kafka connection accumulates genuine runtime rows whose
    principal is permanently NULL. Left unguarded it satisfies the window and then reports every
    declared ACL identity as unused — a confident claim from a source that cannot support it.

Offline: a fake cursor speaking exactly the SQL shapes assess_unused emits.
"""
import pytest

from vectasec.runtime_evidence import (
    MIN_SCANS, MIN_WINDOW_DAYS, RUNTIME_SOURCES, assess_unused, runtime_source_attributes,
    runtime_source_for,
)

TENANT = "00000000-0000-0000-0000-000000000001"
CONN = "11111111-1111-1111-1111-111111111111"
SCAN = "22222222-2222-2222-2222-222222222222"


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
        # Order matters: several of these share a prefix, so match on the distinguishing clause.
        if s.startswith("select type from connections"):
            self._one = (self.db.connector_type,)
        elif s.startswith("select exists"):
            self._one = (self.db.has_runtime_source,)
        elif "from resources" in s and "kind = any" in s:
            self._all = self.db.declared
        elif "distinct principal from runtime_evidence" in s:
            self._all = [(p,) for p in self.db.principals]
        elif "count(*) from runtime_evidence" in s:
            self._one = (self.db.evidence_rows,)
        elif s.startswith("select rule_id, scope from suppressions"):
            self._all = []
        elif "extract(epoch" in s:
            self._one = (self.db.days,)
        elif "count(*) from scans" in s:
            self._one = (self.db.scans,)
        elif s.startswith("insert into findings"):
            self.db.findings.append(params)
            self._one = ("f-%d" % len(self.db.findings),)
        elif s.startswith("insert into observations"):
            self.db.observations.append(params)
        else:
            raise AssertionError(f"unexpected SQL: {s[:120]}")

    def fetchone(self):
        return self._one

    def fetchall(self):
        return self._all


class FakeConn:
    autocommit = True

    def __init__(self, *, connector_type="rabbitmq", has_runtime_source=True,
                 declared=(("r-1", "guest", "user", "guest"),),
                 principals=("guest",), evidence_rows=3,
                 days=float(MIN_WINDOW_DAYS + 1), scans=MIN_SCANS + 1):
        self.connector_type = connector_type
        self.has_runtime_source = has_runtime_source
        self.declared = list(declared)
        self.principals = list(principals)
        self.evidence_rows = evidence_rows
        self.days, self.scans = days, scans
        self.findings, self.observations = [], []

    def cursor(self):
        return FakeCursor(self)

    # Findings are written as (tenant, scan, resource, rule, fingerprint, title, severity,
    # status, remediation, detail, assessment, reason) — see runtime_evidence._write_finding.
    def filed(self):
        return [{"severity": f[6], "remediation": f[8], "detail": f[9],
                 "assessment": f[10], "reason": f[11]} for f in self.findings]


def test_a_connector_with_no_runtime_source_says_nothing_at_all():
    """Kong/MCP have no live-client API. A finding nobody can ever close teaches people to
    ignore the rule."""
    conn = FakeConn(connector_type="kong", has_runtime_source=False)
    stats = assess_unused(conn, TENANT, CONN, SCAN)
    assert conn.findings == []
    assert stats["runtime_source"] is False
    assert stats["runtime_capable"] is False        # kong is not in RUNTIME_SOURCES


def test_capability_is_reported_separately_from_observation():
    """'Cannot see' and 'saw nothing' are opposite answers that an empty table renders
    identically — the stats must distinguish them."""
    kong = assess_unused(FakeConn(connector_type="kong", has_runtime_source=False),
                         TENANT, CONN, SCAN)
    kafka = assess_unused(FakeConn(connector_type="kafka", has_runtime_source=False),
                          TENANT, CONN, SCAN)
    assert kong["runtime_capable"] is False
    assert kafka["runtime_capable"] is True         # capable, just nothing observed yet
    assert runtime_source_for("kong") is None
    assert runtime_source_for("kafka") is not None


def test_a_full_window_with_attributable_evidence_names_the_unused_identity():
    conn = FakeConn(declared=[("r-1", "guest", "user", "guest"),
                              ("r-2", "batch", "user", "batch")],
                    principals=["guest"])
    stats = assess_unused(conn, TENANT, CONN, SCAN)
    assert stats["assessable"] is True
    assert stats["never_observed"] == 1
    filed = conn.filed()
    assert len(filed) == 1 and filed[0]["severity"] == "medium"
    assert filed[0]["assessment"] == "assessed"
    assert "'batch'" in conn.observations[0][3]


@pytest.mark.parametrize("days,scans", [(None, 0), (1.0, 2), (MIN_WINDOW_DAYS + 1, 3),
                                        (2.0, MIN_SCANS + 1)])
def test_a_short_window_files_one_gap_instead_of_accusations(days, scans):
    conn = FakeConn(declared=[("r-1", "a", "user", "a"), ("r-2", "b", "user", "b")],
                    principals=[], days=days, scans=scans)
    stats = assess_unused(conn, TENANT, CONN, SCAN)
    assert stats["assessable"] is False
    filed = conn.filed()
    assert len(filed) == 1 and filed[0]["assessment"] == "not_assessable"
    assert stats["never_observed"] == 0, "an unassessable window must claim nothing"


# ── The attribution gate ──────────────────────────────────────────────────────
def test_unattributable_evidence_never_becomes_an_unused_claim():
    """Kafka: real client sessions, permanently NULL principals, a satisfied window. The
    unguarded path would report EVERY declared identity as unused."""
    conn = FakeConn(connector_type="kafka",
                    declared=[("r-1", "svc-a", "identity", "svc-a"),
                              ("r-2", "svc-b", "identity", "svc-b")],
                    principals=[],           # nothing attributable, ever
                    evidence_rows=12,        # but plenty of observed sessions
                    days=float(MIN_WINDOW_DAYS * 3), scans=MIN_SCANS * 3)
    stats = assess_unused(conn, TENANT, CONN, SCAN)

    assert stats["attributable"] is False
    assert stats["assessable"] is False
    assert stats["never_observed"] == 0
    filed = conn.filed()
    assert len(filed) == 1, "one coverage gap, not one accusation per identity"
    assert filed[0]["assessment"] == "not_assessable"
    assert "cannot attribute" in filed[0]["reason"]


def test_the_unattributable_gap_does_not_promise_that_waiting_will_close_it():
    """The window gap closes with more scans; this one never does, because the ceiling is the
    API. Telling an operator to keep scanning would be advice that repeats forever."""
    conn = FakeConn(connector_type="kafka", principals=[], evidence_rows=9,
                    days=float(MIN_WINDOW_DAYS * 3), scans=MIN_SCANS * 3)
    assess_unused(conn, TENANT, CONN, SCAN)
    filed = conn.filed()[0]
    assert "does NOT close with time" in filed["detail"]
    assert "Once the window reaches" not in filed["remediation"]
    assert "authenticated per-client attribution" in filed["remediation"]


def test_a_source_that_has_simply_not_run_yet_is_not_called_unattributable():
    """Zero evidence rows is the young-connection case, which the window gate already owns.
    Conflating it with the API-ceiling case would give the wrong remediation."""
    conn = FakeConn(evidence_rows=0, principals=[], days=None, scans=0)
    stats = assess_unused(conn, TENANT, CONN, SCAN)
    assert stats["attributable"] is True
    assert "not started" in conn.filed()[0]["reason"]


def test_one_attributable_principal_is_enough_to_re_enable_the_claim():
    """A mixed source (some sessions attributable, some not) can still support the claim about
    the identities it CAN see."""
    conn = FakeConn(declared=[("r-1", "used", "user", "used"), ("r-2", "idle", "user", "idle")],
                    principals=["used"], evidence_rows=20)
    stats = assess_unused(conn, TENANT, CONN, SCAN)
    assert stats["attributable"] is True and stats["assessable"] is True
    assert stats["never_observed"] == 1


# ── The gate is DECLARED, not inferred, and fails closed ─────────────────────
def test_a_non_attributing_source_is_gated_even_if_the_data_says_otherwise():
    """The load-bearing case for declaring the capability instead of inferring it. One stray
    non-null principal on a Kafka connection — an older connector version, a hand-written row,
    a future change to what the connector emits — must not talk the claim back into existence.
    Inferring attribution from the data fails OPEN; a fabrication guard has to fail closed."""
    conn = FakeConn(connector_type="kafka",
                    declared=[("r-1", "svc-a", "identity", "svc-a"),
                              ("r-2", "svc-b", "identity", "svc-b")],
                    principals=["svc-a"],          # anomalous: Kafka cannot produce this
                    evidence_rows=30,
                    days=float(MIN_WINDOW_DAYS * 2), scans=MIN_SCANS * 2)
    stats = assess_unused(conn, TENANT, CONN, SCAN)

    assert stats["source_attributes"] is False
    assert stats["assessable"] is False, "declared capability must override observed data"
    assert stats["never_observed"] == 0
    filed = conn.filed()
    assert len(filed) == 1 and filed[0]["assessment"] == "not_assessable"


def test_only_the_structural_gap_claims_to_be_permanent():
    """An ATTRIBUTING source that has simply not named a principal yet is a temporary gap, and
    telling that operator the limit is their API would be false and would stop them waiting."""
    temporary = FakeConn(connector_type="rabbitmq", principals=[], evidence_rows=4,
                         days=float(MIN_WINDOW_DAYS * 2), scans=MIN_SCANS * 2)
    assess_unused(temporary, TENANT, CONN, SCAN)
    t = temporary.filed()[0]
    assert "does NOT close with time" not in t["detail"]
    assert "Once the window reaches" in t["remediation"]
    assert "none has yet named a principal" in t["reason"]

    structural = FakeConn(connector_type="kafka", principals=[], evidence_rows=4,
                          days=float(MIN_WINDOW_DAYS * 2), scans=MIN_SCANS * 2)
    assess_unused(structural, TENANT, CONN, SCAN)
    s = structural.filed()[0]
    assert "does NOT close with time" in s["detail"]
    assert "cannot attribute" in s["reason"]


def test_every_declared_runtime_source_states_whether_it_can_attribute():
    """A source added without this flag would default to nothing and silently decide whether an
    identity may be called unused. Make omission a test failure instead."""
    assert RUNTIME_SOURCES, "the capability map must not be empty"
    for ctype, source in RUNTIME_SOURCES.items():
        assert isinstance(source.attributes, bool), f"{ctype} must declare `attributes`"
        assert source.reads.strip(), f"{ctype} must say what it reads"
    # Kafka is the one that cannot, and it is the reason the flag exists.
    assert runtime_source_attributes("kafka") is False
    assert runtime_source_attributes("rabbitmq") is True
    assert runtime_source_attributes("kong") is None      # no source at all


def test_the_kafka_source_description_names_the_self_asserted_client_id():
    """The reason text quotes this into the finding, so it has to carry the limitation."""
    assert "self-asserted" in runtime_source_for("kafka")
