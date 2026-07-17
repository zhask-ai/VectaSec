"""Unit tests for the one claim the compliance page makes to the budget-holder.

Offline: the cursor is faked, nothing touches a DB.

The console (apps/web/app/compliance/frameworks.ts, apps/web/app/compliance/page.tsx) tells the
reader, as a property of the engine and not of a default: *a scan can prove a control fails, it
can never prove one passes; nothing here is marked passing on the strength of a clean scan.*

That is only true if `evaluate()` has no path to `pass` at all. It previously had one — an
opt-in `allow_pass=True` — and the `controls` table has no provenance column, so a row written
that way would have been indistinguishable from a human attestation and would have rendered
under the console's "every pass is attested" paragraph as a real score. These tests pin the
claim to the code, so that reintroducing any such flag fails here rather than in front of an
auditor.
"""
import inspect

import pytest

from vectasec.compliance import CONTROL_CATALOGUE, FRAMEWORKS, evaluate


class FakeCursor:
    """Just enough cursor for evaluate(): canned SELECT results, recorded INSERTs.

    evaluate() issues its selects in a fixed order — open findings, then scanned connection
    types, then NOT_ASSESSABLE rules — so they are replayed positionally.
    """

    def __init__(self, *, open_findings=(), scanned_types=(), not_assessable=()):
        self._selects = [
            list(open_findings),
            [(t,) for t in scanned_types],
            [(r,) for r in not_assessable],
        ]
        self._result: list = []
        self.inserts: list = []

    def execute(self, sql, params=None):
        if sql.lstrip().lower().startswith("insert"):
            self.inserts.append(params)
            self._result = []
            return
        self._result = self._selects.pop(0) if self._selects else []

    def fetchall(self):
        return self._result


def statuses(cur):
    """The status column of every row evaluate() wrote."""
    return [params[5] for params in cur.inserts]


def test_clean_covered_scan_never_writes_pass():
    """The exact scenario the console describes: we scanned a family, it came back clean.

    A clean Kafka scan means every Kafka-reachable control has coverage and no failing finding.
    That must render as `unknown` — "we looked and saw nothing" is not "you are compliant",
    because we saw only the brokers we scanned.
    """
    cur = FakeCursor(open_findings=[], scanned_types=["kafka"])

    result = evaluate(cur, "00000000-0000-0000-0000-000000000001")

    assert cur.inserts, "evaluate() wrote no controls at all"
    assert "kafka" in result["covered_families"], "coverage should still be reported"
    assert result["pass"] == 0
    assert "pass" not in statuses(cur)


def test_evaluate_has_no_flag_that_enables_pass():
    """No caller-supplied argument may re-open the door.

    `allow_pass=True` was a documented, supported public kwarg with zero callers — one keyword
    away from writing a scan-derived `pass` under a page asserting every pass is human-attested.
    Deleted, not defaulted off: a guarantee that holds only while nobody passes the flag is not
    a guarantee.
    """
    params = inspect.signature(evaluate).parameters
    assert "allow_pass" not in params

    with pytest.raises(TypeError):
        evaluate(FakeCursor(scanned_types=["kafka"]), "t", allow_pass=True)


def test_pass_is_unreachable_for_every_input_shape():
    """Sweep the branches: covered/uncovered, declared/undeclared, failing/clean, withdrawn.

    `pass` must not appear in any of them.
    """
    cases = [
        FakeCursor(open_findings=[], scanned_types=[]),
        FakeCursor(open_findings=[], scanned_types=["kafka", "kong", "rabbitmq", "mcp"]),
        # scan ran but could not read the target: coverage withdrawn
        FakeCursor(
            open_findings=[("f1", "KAFKA.SCAN.NOT_ASSESSABLE", {})],
            scanned_types=["kafka"],
            not_assessable=["KAFKA.SCAN.NOT_ASSESSABLE"],
        ),
    ]
    for cur in cases:
        evaluate(cur, "t")
        assert "pass" not in statuses(cur)

    for framework in FRAMEWORKS:
        cur = FakeCursor(open_findings=[], scanned_types=["kafka"])
        evaluate(cur, "t", frameworks=[framework])
        assert "pass" not in statuses(cur)


def test_a_finding_still_proves_fail():
    """The guard must not have been bought by making evaluate() inert.

    A mapped, ungated finding still has to move its control to `fail` — that is the one verdict
    a scan genuinely proves, and the product is worthless if this regresses to silence.
    """
    cur = FakeCursor(
        # ungated (no scope tags required), so it maps on a bare tenant with no scope declared
        open_findings=[("f1", "KAFKA.SASL.PLAIN_WITHOUT_TLS", {})],
        scanned_types=["kafka"],
    )

    result = evaluate(cur, "t")

    assert result["fail"] > 0, "a mapped finding must fail its controls"
    assert "fail" in statuses(cur)
    assert result["mapped_findings"] > 0


def test_undeclared_frameworks_are_not_applicable_not_pass():
    """Out-of-scope must resolve to `not_applicable` — never to the optimistic direction."""
    declared = FRAMEWORKS[0]
    others = [f for f in FRAMEWORKS if f != declared]
    assert others, "test needs more than one framework in the catalogue"

    cur = FakeCursor(open_findings=[], scanned_types=["kafka"])
    evaluate(cur, "t", frameworks=[declared])

    written = {(p[1], p[5]) for p in cur.inserts}
    for framework in others:
        got = {status for fw, status in written if fw == framework}
        assert got == {"not_applicable"}, f"{framework}: {got}"

    assert sum(len(c) for c in CONTROL_CATALOGUE.values()) == len(cur.inserts)
