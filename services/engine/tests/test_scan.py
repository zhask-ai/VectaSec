"""Unit tests for the pure logic in scan.py. Offline: no DB, no target, no network.

These two functions are the only decisions the scan loop makes that a human's triage state
depends on, so they are the ones worth pinning:

  • fingerprint() wrong  => a finding an engineer already resolved resurrects as a fresh
    open row on the next scan, or two unrelated problems merge into one.
  • _is_suppressed() wrong => either a finding somebody explicitly accepted screams every
    scan, or — the dangerous direction — a finding nobody accepted is silently hidden.

Both are pure, so nothing has to be stood up to test them.
"""
import inspect

import pytest

from vectasec.contracts import Collected, Hit, Resource
from vectasec.scan import _is_suppressed, fingerprint, representative, run_scan

TENANT = "00000000-0000-0000-0000-000000000001"
OTHER_TENANT = "00000000-0000-0000-0000-000000000002"
CONN = "11111111-1111-1111-1111-111111111111"        # e.g. the tenant's `prod-kafka`
OTHER_CONN = "22222222-2222-2222-2222-222222222222"  # ...and its `staging-kafka`
RULE = "KAFKA.LISTENER.PLAINTEXT"


def res(kind="broker", ext_id="broker-1", name=None) -> Resource:
    return Resource(kind=kind, name=name or ext_id, ext_id=ext_id)


def supp(rule_id=RULE, **scope) -> dict:
    """A row as _active_suppressions() hands it over: {"rule_id": ..., "scope": {...}}."""
    return {"rule_id": rule_id, "scope": dict(scope)}


# ═══ fingerprint ══════════════════════════════════════════════════════════
def test_fingerprint_is_stable_across_calls():
    assert fingerprint(TENANT, CONN, RULE, "broker-1") == fingerprint(TENANT, CONN, RULE, "broker-1")


def test_fingerprint_is_stable_across_processes():
    """Pinned to a literal on purpose. sha256 is stable where Python's hash() is salted
    per-process (PYTHONHASHSEED), and this value is a PRIMARY KEY for triage state that
    already exists in customer databases: if this digest ever changes, every resolved
    finding in the field reopens as a brand-new row. Changing it is a data migration,
    not a refactor — this test is the tripwire that says so.

    It fired once, deliberately: adding connection_id changed every digest, which is why
    20260717000003_pipeline_fixes.sql re-fingerprints existing rows in place. That
    migration's SQL digest must reproduce this exact literal.
    """
    assert fingerprint(TENANT, CONN, RULE, "broker-1") == "c0fb0c7211ed7e7ee008d5fb863d60ac"


def test_fingerprint_shape_is_32_lowercase_hex():
    fp = fingerprint(TENANT, CONN, RULE, "broker-1")
    assert len(fp) == 32
    assert set(fp) <= set("0123456789abcdef")


def test_fingerprint_differs_across_rule_id():
    assert fingerprint(TENANT, CONN, RULE, "broker-1") != fingerprint(
        TENANT, CONN, "KAFKA.AUTHZ.NO_AUTHORIZER", "broker-1")


def test_fingerprint_differs_across_ext_id():
    assert fingerprint(TENANT, CONN, RULE, "broker-1") != fingerprint(TENANT, CONN, RULE, "broker-2")


def test_fingerprint_differs_across_tenant():
    """The multi-tenant one that actually matters: two customers with an identically-named
    broker and the same misconfiguration must not share a findings row. `findings` is
    UNIQUE (tenant_id, fingerprint), so a tenant-blind fingerprint would not corrupt data
    — but it would make one tenant's fingerprint a probe for another's, and it would break
    the ai_outputs cache, which is keyed on fingerprint and scoped per tenant.
    """
    assert fingerprint(TENANT, CONN, RULE, "broker-1") != fingerprint(
        OTHER_TENANT, CONN, RULE, "broker-1")


def test_fingerprint_differs_across_connection():
    """The regression that erased production findings.

    ext_id is only stable WITHIN a connection (contracts.Resource). A tenant with
    `prod-kafka` and `staging-kafka` gets `broker-1` and `topic-payments` from both, and the
    RabbitMQ connector emits the literal ext_id `cluster` for every connection it collects.
    With connection_id out of the hash, those two real, distinct problems collided on
    UNIQUE (tenant_id, fingerprint) into ONE row — so scanning staging overwrote the
    production finding's severity/detail and repointed it at the staging asset, and both
    clusters' observations accumulated under a single claim. Resources are already isolated
    per connection (UNIQUE (connection_id, ext_id)), which is what made this so quiet: two
    resource rows, one finding.
    """
    assert fingerprint(TENANT, CONN, RULE, "broker-1") != fingerprint(
        TENANT, OTHER_CONN, RULE, "broker-1")
    assert fingerprint(TENANT, CONN, RULE, "topic-payments") != fingerprint(
        TENANT, OTHER_CONN, RULE, "topic-payments")
    # RabbitMQ's constant ext_id — the 100%-certainty collision.
    assert fingerprint(TENANT, CONN, "RABBITMQ.USER.GUEST_REMOTE_LOGIN", "cluster") != fingerprint(
        TENANT, OTHER_CONN, "RABBITMQ.USER.GUEST_REMOTE_LOGIN", "cluster")


def test_fingerprint_is_distinct_across_every_pair_of_inputs():
    inputs = [(t, c, r, e)
              for t in (TENANT, OTHER_TENANT)
              for c in (CONN, OTHER_CONN)
              for r in (RULE, "KAFKA.AUTHZ.NO_AUTHORIZER")
              for e in ("broker-1", "broker-2", "topic-payments")]
    fps = [fingerprint(*i) for i in inputs]
    assert len(set(fps)) == len(inputs)


def test_fingerprint_ignores_everything_except_its_four_fields():
    """Deliberate per the docstring: no scan id, no resource uuid, no severity, no title.
    A rule that gets re-titled, or a resource that is deleted and recollected under a new
    uuid, must not orphan the triage state attached to the old fingerprint.

    connection_id is in the signature and the others are not for the same reason: it is
    resolved from (tenant, type, name) and is stable across scans, where a resource uuid is
    not. This assertion is what stops a scan id or a severity being added later.
    """
    assert list(inspect.signature(fingerprint).parameters) == [
        "tenant_id", "connection_id", "rule_id", "ext_id"]


def test_fingerprint_delimiter_is_unescaped_across_fields():
    """A documented boundary, currently unreachable — recorded so it stays that way.

    The fields are joined with '|' and never escaped, so "A|B" + "c" hashes identically to
    "A" + "B|c". This is safe TODAY only because the split is unambiguous in practice:
    tenant_id and connection_id are always uuids and every rule_id is a literal constant in
    a @detector decorator, and none can contain a pipe. ext_id is the last field, so a pipe
    there (a RabbitMQ vhost may legally contain one) cannot collide with anything.

    The day a rule_id gains a '|', two different findings silently become one.
    """
    assert fingerprint(TENANT, CONN, "A|B", "c") == fingerprint(TENANT, CONN, "A", "B|c")
    assert fingerprint(TENANT, CONN, RULE, "vhost-a|b") != fingerprint(TENANT, CONN, RULE, "vhost-a")


# ═══ _is_suppressed ═══════════════════════════════════════════════════════
def test_nothing_is_suppressed_when_there_are_no_suppressions():
    assert _is_suppressed([], RULE, res()) is False


def test_tenant_wide_scope_suppresses_every_resource():
    """An empty scope is the documented tenant-wide form ('{}' is the column default)."""
    s = [supp()]
    assert _is_suppressed(s, RULE, res(kind="broker", ext_id="broker-1")) is True
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-payments")) is True


def test_a_null_scope_is_also_tenant_wide():
    """A SQL NULL scope is ABSENT, and absent means tenant-wide — the same as {}. That must
    not be confused with the non-object scopes below: absent is a scope nobody wrote, a jsonb
    array is a scope somebody wrote WRONG, and only the first one is a blanket exception."""
    assert _is_suppressed([{"rule_id": RULE, "scope": None}], RULE, res()) is True


@pytest.mark.parametrize("bad", [[], ["topic"], "topic", 3, True])
def test_a_non_object_scope_never_suppresses_anything(bad):
    """`scope` is `jsonb not null default '{}'` with no shape check, and _is_suppressed did
    `scope = s['scope'] or {}` then treated any falsy scope as tenant-wide. So a jsonb `[]`
    — from a seed script, a CSV import, or a hand-written SQL exception, and a plausible slip
    given the sibling column `collectors.scopes` defaults to '[]' — silenced the rule for
    EVERY resource in the tenant. A jsonb string went the other way and raised AttributeError
    from `scope.get('ext_id')`, at a call site outside the per-detector try/except, killing
    the scan mid-transaction.

    Neither is a scope anyone wrote on purpose, so neither may hide a finding: an unevaluable
    scope fails closed, exactly like the unknown-key case below. The API's `scope: dict`
    validator rejects these shapes, but the API is not the only writer — the DB is the
    authority, which is why 20260717000003 also adds a jsonb_typeof check.
    """
    assert _is_suppressed([{"rule_id": RULE, "scope": bad}], RULE, res()) is False


def test_a_non_object_scope_does_not_mask_a_real_one():
    """Fail-closed must mean SKIP, not abort: a malformed row must not stop the loop before a
    valid suppression later in the list is consulted."""
    supps = [{"rule_id": RULE, "scope": []}, supp(ext_id="broker-1")]
    assert _is_suppressed(supps, RULE, res(ext_id="broker-1")) is True


def test_ext_id_scope_suppresses_only_that_resource():
    s = [supp(ext_id="broker-1")]
    assert _is_suppressed(s, RULE, res(ext_id="broker-1")) is True
    assert _is_suppressed(s, RULE, res(ext_id="broker-2")) is False


def test_ext_id_scope_matching_is_exact():
    s = [supp(ext_id="topic-payments")]
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-payments")) is True
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-payments-eu")) is False
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="payments")) is False


def test_kind_scope_suppresses_every_resource_of_that_kind():
    s = [supp(kind="topic")]
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-a")) is True
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-b")) is True
    assert _is_suppressed(s, RULE, res(kind="broker", ext_id="broker-1")) is False


def test_a_different_rule_id_is_never_suppressed():
    """The load-bearing negative. Accepting "PLAINTEXT is fine on this dev broker" must not
    silence NO_AUTHORIZER on the same broker — a suppression that leaks across rules hides
    findings nobody ever agreed to hide, and does it invisibly."""
    for s in ([supp()], [supp(ext_id="broker-1")], [supp(kind="broker")]):
        assert _is_suppressed(s, "KAFKA.AUTHZ.NO_AUTHORIZER", res(ext_id="broker-1")) is False


def test_rule_id_matching_is_exact_not_a_prefix():
    """Suppressing a whole rulepack is not an expressible scope, and must not become one by
    accident — 'KAFKA.' would otherwise silence twenty rules at once."""
    assert _is_suppressed([supp(rule_id="KAFKA.")], RULE, res()) is False
    assert _is_suppressed([supp(rule_id="KAFKA.LISTENER")], RULE, res()) is False
    assert _is_suppressed([supp(rule_id=RULE.lower())], RULE, res()) is False


def test_only_the_suppression_whose_rule_matches_is_consulted():
    supps = [supp(rule_id="KONG.AUTH.MISSING"),
             supp(rule_id="RABBITMQ.USER.GUEST", kind="broker"),
             supp(ext_id="broker-1")]
    assert _is_suppressed(supps, RULE, res(ext_id="broker-1")) is True
    assert _is_suppressed(supps, RULE, res(ext_id="broker-2")) is False


def test_a_later_matching_suppression_still_wins():
    """The loop must scan the whole list, not give up on the first rule_id match."""
    supps = [supp(ext_id="broker-9"), supp(ext_id="broker-2"), supp(ext_id="broker-1")]
    assert _is_suppressed(supps, RULE, res(ext_id="broker-1")) is True


def test_suppression_does_not_key_on_resource_name():
    """ext_id is the stable identity; name is cosmetic and connectors reuse it across kinds."""
    assert _is_suppressed([supp(ext_id="broker-1")], RULE,
                          res(ext_id="broker-2", name="broker-1")) is False


def test_an_unevaluable_scope_fails_closed():
    """scan.py understands `ext_id` and `kind` and nothing else. A scope key it cannot
    evaluate must leave the finding OPEN: a noisy finding is an annoyance, a silently
    hidden one is the failure that gets somebody breached.

    Note both keys below are spelled in the migration's own comment on `suppressions.scope`
    ({resource_id|kind|name_glob}) but are not implemented here — see the report.
    """
    assert _is_suppressed([supp(resource_id="8f14e45f-ea5c-4f3b-9a2b-000000000001")],
                          RULE, res()) is False
    assert _is_suppressed([supp(name_glob="payments*")], RULE,
                          res(kind="topic", ext_id="topic-payments-eu")) is False


def test_combined_ext_id_and_kind_scope_matches_on_either_not_both():
    """CHARACTERISATION — current semantics are OR, and that is over-broad. An operator who
    writes {"ext_id": "topic-payments", "kind": "topic"} to mean "just this one topic" gets
    every topic in the tenant suppressed, because the kind clause matches independently.
    Asserted here so the behaviour is visible rather than discovered in production. See the
    report; if this is tightened to AND, this test should flip.
    """
    s = [supp(ext_id="topic-payments", kind="topic")]
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-payments")) is True
    assert _is_suppressed(s, RULE, res(kind="topic", ext_id="topic-orders")) is True
    # The kind clause is what carries it — a different kind is still untouched.
    assert _is_suppressed(s, RULE, res(kind="broker", ext_id="broker-1")) is False


# ═══ run_scan: transaction boundaries ═════════════════════════════════════
# A fake connection that mirrors the two psycopg semantics these fixes turn on:
#   • Connection.__exit__ ROLLS BACK on an exception and never commits.
#   • a failed statement ABORTS the transaction — every later statement then raises
#     InFailedSqlTransaction until a rollback.
# Both are why a persist-phase error used to take the `scans` row down with it.
class _Aborted(Exception):
    """Stands in for psycopg.errors.InFailedSqlTransaction."""


class _FakeCursor:
    def __init__(self, conn):
        self._conn = conn
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self._conn.log.append(s)
        if self._conn.aborted:
            raise _Aborted("current transaction is aborted, commands ignored until rollback")
        if self._conn.fail_on and self._conn.fail_on in s:
            self._conn.aborted = True
            raise RuntimeError("duplicate key value violates unique constraint")
        if "from connections where" in s:
            self._row = None                      # force the INSERT path
        elif "returning id" in s:
            self._conn.n_ids += 1
            self._row = (f"id-{self._conn.n_ids}",)
        else:
            self._row = None

    def fetchone(self):
        return self._row

    def fetchall(self):
        return []                                 # no suppressions


class _FakeConn:
    def __init__(self, fail_on=None):
        self.log: list = []
        self.n_ids = 0
        self.aborted = False
        self.fail_on = fail_on
        self.autocommit = True

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        self.log.append("COMMIT")
        self.aborted = False

    def rollback(self):
        self.log.append("ROLLBACK")
        self.aborted = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *a):
        self.rollback() if exc_type else self.commit()
        return False


def _wire(monkeypatch, conn, collect, detectors=()):
    """Point run_scan at the fake connection, a fake connector and an explicit detector list.

    DETECTORS is replaced rather than appended to: the real registry auto-registers every
    Kafka/Kong/RabbitMQ/MCP rule at import, and a scan-loop test must not depend on what any
    of them happen to do to a resource.
    """
    from vectasec.registry import CONNECTORS
    monkeypatch.setattr("vectasec.db.connect", lambda: conn)
    monkeypatch.setitem(CONNECTORS, "faketype", collect)
    monkeypatch.setattr("vectasec.scan.DETECTORS", list(detectors))


def test_the_scan_row_is_committed_before_the_collect_starts(monkeypatch):
    """The comment in run_scan claims a slow or down target 'must not hold a write lock'.
    It was false: _ensure_connection's `update connections set config` takes an exclusive row
    lock and the scans INSERT was uncommitted, so both were held for the whole collect. A
    5-minute Kafka connect meant a concurrent POST /scans for the same connection blocked on
    that lock for 5 minutes, and 'running' was a status no reader could ever observe because
    the row was invisible outside the open transaction.
    """
    conn = _FakeConn()
    at_collect = {}

    def collect(config):
        at_collect["log"] = list(conn.log)
        return Collected(resources=[])

    _wire(monkeypatch, conn, collect)
    run_scan("faketype", {}, tenant_id=TENANT, connection_name="c")

    log = at_collect["log"]
    assert "COMMIT" in log, "the collect began inside an open write transaction"
    scans_insert = next(i for i, s in enumerate(log) if "insert into scans" in s)
    assert log.index("COMMIT") > scans_insert, "committed before the scans row was even written"


def test_a_persist_failure_is_recorded_as_an_error_scan(monkeypatch):
    """The Kong duplicate-plugin case: _persist_resources raises, and only the CONNECTOR had
    an error handler. The exception escaped `with connect() as conn`, psycopg rolled back, and
    the scans row went with it — so a nightly scan could fail every night for a month while the
    console showed a stale last_scanned_at and the previous scan's findings ageing quietly.
    """
    conn = _FakeConn(fail_on="insert into resources")
    _wire(monkeypatch, conn, lambda config: Collected(
        resources=[Resource(kind="thing", name="n", ext_id="x-1")]))

    with pytest.raises(RuntimeError, match="duplicate key"):
        run_scan("faketype", {}, tenant_id=TENANT, connection_name="c")

    err = next((i for i, s in enumerate(conn.log) if "update scans set status='error'" in s), None)
    assert err is not None, "the scan failed with no record of the failure in the database"
    # Rolled back FIRST: the aborted transaction would reject the error write itself.
    assert "ROLLBACK" in conn.log[:err]
    assert conn.log[err + 1] == "COMMIT", "the error status was written but never committed"


def test_a_connector_failure_is_still_recorded_as_an_error_scan(monkeypatch):
    """The path that already worked, pinned so restructuring the transaction did not lose it."""
    conn = _FakeConn()

    def collect(config):
        raise TimeoutError("broker unreachable")

    _wire(monkeypatch, conn, collect)
    with pytest.raises(TimeoutError):
        run_scan("faketype", {}, tenant_id=TENANT, connection_name="c")

    assert any("update scans set status='error'" in s for s in conn.log)


def test_the_findings_upsert_re_evaluates_suppression_status_every_scan(monkeypatch):
    """status was in the INSERT column list but NOT in the ON CONFLICT set-list, and the
    conflict branch is the one every re-scan takes — so status was written exactly once in a
    finding's life. An expired 30-day exception silently became a permanent one, hidden from
    blast radius and counted as passing by compliance. Nothing sweeps it: `expires_at` is read
    in exactly one place (_active_suppressions) and there is no cron job or trigger.

    The transition semantics are asserted against a real Postgres in the migration review; what
    this pins is that the scan loop asks the DB to re-evaluate at all.
    """
    from vectasec.contracts import Hit
    from vectasec.registry import DetectorDef

    fires = DetectorDef(kinds=("thing",), rule_id="TEST.RULE", severity="high", title="T",
                        fn=lambda r, ctx: [Hit(observation="o")])
    conn = _FakeConn()
    _wire(monkeypatch, conn,
          lambda config: Collected(resources=[Resource(kind="thing", name="n", ext_id="x-1")]),
          detectors=[fires])
    run_scan("faketype", {}, tenant_id=TENANT, connection_name="c")

    upsert = next(s for s in conn.log if "insert into findings" in s)
    assert "on conflict (tenant_id, fingerprint) do update" in upsert
    assert "status = case" in upsert, "the conflict branch never resets status; expiry is a no-op"
    # Never resurrects a status a human set.
    assert "else findings.status end" in upsert


# ═══ representative ═══════════════════════════════════════════════════════
# A detector may return several Hits for one resource, but fingerprint() has no per-Hit
# discriminator, so they all collapse into ONE findings row and the upsert does
# `severity = excluded.severity`. Without representative() the row kept whatever the LAST Hit in
# list order said — making the severity a customer sees a function of iteration order.
def hit(observation="o", severity=None, remediation="r", detail="d"):
    return Hit(observation=observation, severity=severity, remediation=remediation, detail=detail)


def test_representative_of_a_single_hit_is_that_hit():
    h = hit(severity="medium")
    assert representative([h], "high") == (h, "medium")


def test_a_hit_without_a_severity_defers_to_the_rules_declared_severity():
    h = hit(severity=None)
    assert representative([h], "high") == (h, "high")


def test_the_worst_severity_wins_regardless_of_position():
    first, last = hit(severity="critical"), hit(severity="low")
    assert representative([first, last], "medium")[1] == "critical"
    assert representative([last, first], "medium")[1] == "critical"


def test_a_none_severity_hit_is_ranked_against_the_rule_severity_not_skipped():
    """The case detect/kafka.py's _uniform() explicitly bails out of, and the one that bit
    detect/mcp.py: a mixed None/explicit group. The None Hit means "use the rule's severity" —
    here `high` — so it must OUTRANK the explicit `medium` that follows it. Ranking only the
    explicit severities, or taking the last, files a high finding as medium.
    """
    public, private = hit(observation="public plaintext endpoint", severity=None), \
        hit(observation="private token endpoint", severity="medium")
    rep, sev = representative([public, private], "high")
    assert sev == "high"
    assert rep is public


def test_the_representative_carries_its_own_remediation_and_detail():
    """The stored prose must belong to the Hit the severity came from. Otherwise a finding is
    filed at medium for an empty-authorization_servers MUST violation while its stored detail
    explains away a cosmetic trailing-slash delta — evidence contradicting its own finding.
    """
    real = hit(severity="medium", remediation="serve authorization_servers",
               detail="a MUST violation")
    cosmetic = hit(severity="info", remediation="normalise the slash",
                   detail="only a trailing-slash delta")
    rep, sev = representative([real, cosmetic], "medium")
    assert (sev, rep.remediation, rep.detail) == ("medium", "serve authorization_servers",
                                                  "a MUST violation")


def test_ties_keep_the_earliest_hit_so_the_result_is_order_stable():
    a, b = hit(observation="a", severity="high"), hit(observation="b", severity="high")
    assert representative([a, b], "low")[0] is a


def test_an_unrecognised_severity_never_outranks_a_known_one():
    """Fails safe: a typo'd severity must not silently become the whole finding's severity."""
    known, bogus = hit(severity="high"), hit(severity="HIGH")
    assert representative([known, bogus], "low")[1] == "high"
    assert representative([bogus, known], "low")[1] == "high"


def test_every_severity_tier_is_ordered():
    tiers = ["info", "low", "medium", "high", "critical"]
    for i, lower in enumerate(tiers):
        for higher in tiers[i + 1:]:
            assert representative([hit(severity=lower), hit(severity=higher)], "info")[1] == higher
