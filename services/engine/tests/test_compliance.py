"""Unit tests for the claims the compliance page makes to the budget-holder.

Offline: the cursor is faked, nothing touches a DB.

The console (apps/web/app/compliance/*) tells the reader, as a property of the engine and not of
a default: *a scan can prove a control fails; it can never prove one passes on its own. A `pass`
means a human attested it, and a live failing finding always overrides that attestation.*

Those are only true if evaluate() has exactly ONE path to `pass` — a current attestation — and no
path from a clean scan alone, and if an assessed failing finding beats an attestation. A
not_assessable finding must never fail a control (it is our blind spot, not the tenant's fault).
These tests pin every one of those to the code so a regression fails here, not in front of an
auditor.
"""
import inspect

import pytest

from vectasec.compliance import CONTROL_CATALOGUE, FRAMEWORKS, evaluate


class FakeCursor:
    """Just enough cursor for evaluate(): canned SELECT results, recorded INSERTs.

    evaluate() issues its selects in a fixed order: open findings, then scanned connection types,
    then NOT_ASSESSABLE rules, then live attestations — replayed positionally. Finding rows are
    (id, rule_id, labels, assessment); a 3-tuple is padded to 'assessed' for brevity at call sites
    that don't care about assessability.
    """

    def __init__(self, *, open_findings=(), scanned_types=(), not_assessable=(), attestations=()):
        findings = [f if len(f) == 4 else (*f, "assessed") for f in open_findings]
        self._selects = [
            findings,
            [(t,) for t in scanned_types],
            [(r,) for r in not_assessable],
            [(fw, cid) for (fw, cid) in attestations],
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
    """The status column of every row evaluate() wrote (position 5, unchanged by the new column)."""
    return [params[5] for params in cur.inserts]


def status_of(cur, framework, control_id):
    for p in cur.inserts:
        if p[1] == framework and p[2] == control_id:
            return p[5]
    return None


# ── The pass contract ──────────────────────────────────────────────────────

def test_clean_covered_scan_without_attestation_is_unknown_never_pass():
    """We scanned a family and it came back clean, but nobody signed for it.

    Coverage without a failing finding is NOT compliance — we saw only the brokers we scanned.
    Without an attestation it must render `unknown`, never `pass`.
    """
    cur = FakeCursor(open_findings=[], scanned_types=["kafka"])
    result = evaluate(cur, "t")
    assert cur.inserts, "evaluate() wrote no controls at all"
    assert "kafka" in result["covered_families"], "coverage should still be reported"
    assert result["pass"] == 0
    assert "pass" not in statuses(cur)


def test_a_live_attestation_is_the_only_thing_that_writes_pass():
    """With a current attestation on a control that has no failing finding, and only then, `pass`."""
    fw, cid = FRAMEWORKS[0], next(iter(CONTROL_CATALOGUE[FRAMEWORKS[0]]))
    cur = FakeCursor(open_findings=[], scanned_types=["kafka"], attestations=[(fw, cid)])
    result = evaluate(cur, "t")
    assert status_of(cur, fw, cid) == "pass"
    assert result["pass"] == 1
    # every OTHER control stayed unknown/not_applicable — one attestation passes one control
    assert statuses(cur).count("pass") == 1


def test_attestation_cannot_override_a_live_assessed_failure():
    """Fail beats attestation. You cannot sign away a control the scanner proves is broken now."""
    # KAFKA.SASL.PLAIN_WITHOUT_TLS maps to PCI 8.3.2 ungated; assessed => it fails that control.
    cur = FakeCursor(
        open_findings=[("f1", "KAFKA.SASL.PLAIN_WITHOUT_TLS", {}, "assessed")],
        scanned_types=["kafka"],
        attestations=[("PCI_DSS_4_0_1", "8.3.2")],
    )
    evaluate(cur, "t")
    assert status_of(cur, "PCI_DSS_4_0_1", "8.3.2") == "fail", "attestation must not mask a live fail"


def test_expired_attestation_grants_no_pass():
    """An attestation the SQL filtered out (expired) simply isn't in the set, so no pass.

    _current_attestations' `expires_at > now()` filter is DB-side; here the expired row is
    represented by its absence from the canned attestations, which is what the filter produces.
    """
    cur = FakeCursor(open_findings=[], scanned_types=["kafka"], attestations=[])
    evaluate(cur, "t")
    assert "pass" not in statuses(cur)


def test_evaluate_has_no_flag_that_enables_pass_from_silence():
    """No caller-supplied argument may write `pass` from a clean scan. The only pass path is an
    attestation row, never a kwarg. `allow_pass` must stay deleted."""
    params = inspect.signature(evaluate).parameters
    assert "allow_pass" not in params
    with pytest.raises(TypeError):
        evaluate(FakeCursor(scanned_types=["kafka"]), "t", allow_pass=True)


# ── The assessability contract ──────────────────────────────────────────────

def test_not_assessable_finding_yields_unknown_never_fail():
    """A finding we could not assess is a coverage gap: it makes the control unknown, not fail."""
    cur = FakeCursor(
        open_findings=[("f1", "KAFKA.SASL.PLAIN_WITHOUT_TLS", {}, "not_assessable")],
        scanned_types=["kafka"],
    )
    result = evaluate(cur, "t")
    # PCI 8.3.2 is one of the controls that rule maps to; it must NOT be failed by a blind spot.
    assert status_of(cur, "PCI_DSS_4_0_1", "8.3.2") == "unknown"
    assert result["fail"] == 0, "a not_assessable finding must never fail a control"
    assert result["unassessable_findings"] > 0


def test_assessed_and_not_assessable_are_not_conflated():
    """An assessed failure fails; a separate not_assessable finding on another control is unknown."""
    cur = FakeCursor(
        open_findings=[
            ("f1", "KAFKA.SASL.PLAIN_WITHOUT_TLS", {}, "assessed"),        # -> fail 8.3.2
            ("f2", "KAFKA.TOPIC.AUTO_CREATE_ENABLED", {}, "not_assessable"),  # -> unknown 2.2.4
        ],
        scanned_types=["kafka"],
    )
    result = evaluate(cur, "t")
    assert status_of(cur, "PCI_DSS_4_0_1", "8.3.2") == "fail"
    assert status_of(cur, "PCI_DSS_4_0_1", "2.2.4") == "unknown"
    assert result["fail"] > 0 and result["unassessable_findings"] > 0


# ── Preserved from the original suite ───────────────────────────────────────

def test_a_finding_still_proves_fail():
    """A mapped, ungated, assessed finding still moves its control to `fail` — the one verdict a
    scan genuinely proves. The product is worthless if this regresses to silence."""
    cur = FakeCursor(
        open_findings=[("f1", "KAFKA.SASL.PLAIN_WITHOUT_TLS", {}, "assessed")],
        scanned_types=["kafka"],
    )
    result = evaluate(cur, "t")
    assert result["fail"] > 0
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
