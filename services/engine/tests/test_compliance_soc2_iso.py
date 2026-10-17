"""SOC 2 TSC and ISO/IEC 27001:2022 rows in compliance/map.py — the contract they must keep.

Offline: the cursor is faked, nothing touches a DB.

map.py's contract for every framework is structural: a control is in CONTROL_CATALOGUE only if
at least one implemented rule maps to it (an empty row reads as coverage we do not have), every
ControlRef points at a catalogued control (_ref() enforces this at import), and every
RULE_TO_CONTROLS key names a detector that actually exists (a mapping to a rule nobody runs is a
row that can never fire). These tests pin that for the two frameworks whose text is paraphrased
rather than quoted, plus the evaluate() behaviour the console relies on: a not_assessable finding
can only make a SOC 2 control `unknown`, an assessed one makes it `fail`.
"""
import vectasec.detect  # noqa: F401  — registers every detector module
from vectasec.compliance import CONTROL_CATALOGUE, FRAMEWORKS, RULE_TO_CONTROLS, controls_for, evaluate
from vectasec.compliance.map import ISO27001, SOC2
from vectasec.registry import DETECTORS

SOC2_CONTROLS = {"CC6.1", "CC6.2", "CC6.3", "CC6.6", "CC6.7", "CC7.1", "CC7.2"}
ISO_CONTROLS = {"A.5.15", "A.5.16", "A.5.17", "A.5.18", "A.8.2", "A.8.3", "A.8.5", "A.8.9",
                "A.8.20", "A.8.24"}
NEW = (SOC2, ISO27001)


class FakeCursor:
    """Same shape as test_compliance.FakeCursor: canned SELECTs replayed positionally (open
    findings, scanned connection types, NOT_ASSESSABLE rules, live attestations), INSERTs
    recorded. Finding rows are (id, rule_id, labels, assessment)."""

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


def status_of(cur, framework, control_id):
    for p in cur.inserts:
        if p[1] == framework and p[2] == control_id:
            return p[5]
    return None


def _refs_for(framework):
    """(rule_key, ControlRef) for every ref in RULE_TO_CONTROLS belonging to `framework`."""
    return [(key, ref) for key, refs in RULE_TO_CONTROLS.items()
            for ref in refs if ref.framework == framework]


# ── The catalogue ───────────────────────────────────────────────────────────

def test_both_frameworks_present_with_exactly_the_agreed_control_ids():
    assert SOC2 == "SOC2_TSC_2017" and ISO27001 == "ISO_27001_2022"
    assert SOC2 in FRAMEWORKS and ISO27001 in FRAMEWORKS
    assert set(CONTROL_CATALOGUE[SOC2]) == SOC2_CONTROLS
    assert set(CONTROL_CATALOGUE[ISO27001]) == ISO_CONTROLS


def test_paraphrase_is_declared_on_every_row():
    """Neither text is quoted (both are licensed). Every requirement must say so inline, because
    the UI renders `requirement` next to the finding as if it were the control's words."""
    for fw in NEW:
        for cid, control in CONTROL_CATALOGUE[fw].items():
            assert "Paraphrase of" in control.requirement, f"{fw}:{cid} does not declare paraphrase"
            assert cid in control.requirement, f"{fw}:{cid} paraphrase note names the wrong control"
            assert control.source_url.startswith("https://"), f"{fw}:{cid} has no source"


def test_every_catalogued_control_has_at_least_one_mapping():
    """The file contract: no permanently-unknown rows. A control nothing maps to must be removed,
    not carried."""
    for fw in NEW:
        mapped = {ref.control_id for _, ref in _refs_for(fw)}
        unmapped = set(CONTROL_CATALOGUE[fw]) - mapped
        assert not unmapped, f"{fw}: catalogued controls with no rule mapping: {sorted(unmapped)}"


def test_every_ref_points_at_a_catalogued_control():
    """_ref() enforces this at import, so this is a tripwire for a future hand-built ControlRef."""
    for fw in NEW:
        for key, ref in _refs_for(fw):
            assert ref.control_id in CONTROL_CATALOGUE[fw], f"{key} -> {fw}:{ref.control_id}"
            control = CONTROL_CATALOGUE[fw][ref.control_id]
            assert (ref.title, ref.requirement) == (control.title, control.requirement)


# ── The rule side ───────────────────────────────────────────────────────────

def test_every_mapped_rule_key_resolves_to_a_registered_detector():
    """A mapping to a rule nobody runs can never fire — it is a row that lies by omission.
    Exact keys must be registered rule ids; prefix keys must match at least one."""
    registered = {d.rule_id for d in DETECTORS}
    assert registered, "no detectors registered — did vectasec.detect import?"
    for fw in NEW:
        for key, _ in _refs_for(fw):
            if key.endswith("."):
                assert any(r.startswith(key) for r in registered), f"prefix {key} matches no rule"
            else:
                assert key in registered, f"{key} is mapped but no detector registers it"


def test_mapped_rules_are_not_shadowed_by_a_refusal():
    """controls_for() lets a NOT_MAPPED key of equal or greater specificity win. A rule that
    carries SOC 2 / ISO refs but resolves to () would be a silent dead mapping."""
    registered = {d.rule_id for d in DETECTORS}
    for fw in NEW:
        for key, _ in _refs_for(fw):
            probe = key if key in registered else next(r for r in sorted(registered) if r.startswith(key))
            assert any(ref.framework == fw for ref in controls_for(probe)), f"{probe} shadowed"


def test_confidence_and_relation_values_are_the_documented_ones():
    for fw in NEW:
        for key, ref in _refs_for(fw):
            assert ref.relation in ("violates", "supports"), (key, ref.relation)
            assert ref.confidence in ("A", "B"), (key, ref.confidence)
            # a gate without the B discount would assert a conditional claim unconditionally
            if ref.gate:
                assert ref.confidence == "B", f"{key} -> {fw}:{ref.control_id} gated but rated A"


def test_credential_lifecycle_never_used_maps_to_removal_controls():
    refs = {(r.framework, r.control_id): r for r in controls_for("CREDENTIAL.LIFECYCLE.NEVER_USED")}
    assert (SOC2, "CC6.2") in refs
    assert (ISO27001, "A.5.18") in refs
    # dormancy is indicative, never proof the authorization lapsed
    assert refs[(SOC2, "CC6.2")].relation == "supports"
    assert refs[(ISO27001, "A.5.18")].relation == "supports"


def test_orphaned_identity_is_direct_evidence_of_unremoved_access():
    refs = {(r.framework, r.control_id) for r in controls_for("CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY")}
    assert {(SOC2, "CC6.2"), (ISO27001, "A.5.18")} <= refs


def test_attack_path_chains_stay_unmapped():
    """A chain is a correlation of findings that already carry their own rows; mapping it would
    fail one control twice on one root cause. Pinned here as well as in test_detect_attack_path."""
    for rid in ("ATTACKPATH.EXPOSED_NHI_SENSITIVE", "ATTACKPATH.PUBLIC_OVERPRIVILEGED",
                "ATTACKPATH.SENSITIVE_ON_EXPOSED"):
        assert controls_for(rid) == ()


def test_existing_frameworks_untouched_by_the_addition():
    """Adding SOC 2 / ISO must not have changed what the other frameworks carry."""
    assert set(CONTROL_CATALOGUE["PCI_DSS_4_0_1"]) >= {"7.2.5", "8.3.2", "2.2.2", "4.2.1"}
    assert set(CONTROL_CATALOGUE["HIPAA"]) == {"164.312(a)(1)", "164.312(d)", "164.312(e)(1)"}
    assert set(CONTROL_CATALOGUE["DORA"]) == {"Art.9(2)", "Art.9(3)", "Art.9(4)"}
    assert set(CONTROL_CATALOGUE["NIS2"]) == {"21(2)(e)", "21(2)(g)", "21(2)(h)", "21(2)(i)"}


# ── evaluate() against a SOC 2 control ──────────────────────────────────────

def test_not_assessable_finding_makes_soc2_control_unknown_never_fail():
    """NEVER_USED is not_assessable for every real credential today (no connector records
    last-used). That must render CC6.2 `unknown` — our blind spot, not the tenant's failure."""
    cur = FakeCursor(
        open_findings=[("f1", "CREDENTIAL.LIFECYCLE.NEVER_USED", {}, "not_assessable")],
        scanned_types=["kafka"],
    )
    result = evaluate(cur, "t", frameworks=[SOC2])
    assert status_of(cur, SOC2, "CC6.2") == "unknown"
    assert result["fail"] == 0
    assert result["unassessable_findings"] > 0
    assert "pass" not in {p[5] for p in cur.inserts}


def test_assessed_finding_fails_soc2_control_and_ungated_iso_control():
    """KAFKA.LISTENER.PLAINTEXT -> CC6.7 and A.8.24 are ungated, so an assessed finding fails both.
    Its A.8.20 ref is also ungated (supports/B) and fails too; CC6.6 has no ref from this rule
    and stays unknown — a plaintext listener says nothing about outside-boundary exposure."""
    cur = FakeCursor(
        open_findings=[("f1", "KAFKA.LISTENER.PLAINTEXT", {}, "assessed")],
        scanned_types=["kafka"],
    )
    result = evaluate(cur, "t", frameworks=[SOC2, ISO27001])
    assert status_of(cur, SOC2, "CC6.7") == "fail"
    assert status_of(cur, ISO27001, "A.8.24") == "fail"
    assert status_of(cur, SOC2, "CC6.6") == "unknown"
    assert result["fail"] >= 2
    assert result["failing"][f"{SOC2}:CC6.7"] == ["f1"]


def test_gated_soc2_ref_is_silent_until_the_scope_tag_is_present():
    """KONG.ROUTE.NO_AUTH_PLUGIN -> CC6.6 is gated on public_facing. Without the tag the ref is
    dropped (silence, not a false claim); with it, the control fails."""
    finding = ("f1", "KONG.ROUTE.NO_AUTH_PLUGIN", {}, "assessed")
    cur = FakeCursor(open_findings=[finding], scanned_types=["kong"])
    evaluate(cur, "t", frameworks=[SOC2])
    assert status_of(cur, SOC2, "CC6.6") == "unknown"
    assert status_of(cur, SOC2, "CC6.1") == "fail"      # the ungated ref still fires

    cur = FakeCursor(open_findings=[finding], scanned_types=["kong"])
    evaluate(cur, "t", frameworks=[SOC2], scope_tags=("public_facing",))
    assert status_of(cur, SOC2, "CC6.6") == "fail"
