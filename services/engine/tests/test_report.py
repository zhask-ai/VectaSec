"""Unit tests for the pure report-export core (vectasec.report).

Everything here is offline: representative findings/controls/posture dicts in, OSCAL/CSV/Markdown
out. The properties pinned are the ones a report cannot get wrong without either breaking a
downstream OSCAL consumer or telling an auditor something the scan did not prove:

  • the OSCAL document carries the members the 1.1.x schema requires and round-trips through json
  • a control this run could not determine (`unknown`) is NEVER emitted as a satisfied finding
  • a not_assessable finding is an observation/coverage-gap, never a not-satisfied finding or risk
  • the CSV column order is stable and fields are escaped
  • the Markdown carries the score and the per-severity counts
"""
import csv
import io
import json

import pytest

from vectasec.report import (
    FINDINGS_CSV_COLUMNS,
    posture_from_counts,
    to_executive_summary_markdown,
    to_findings_csv,
    to_oscal_assessment_results,
    to_oscal_component_definition,
)

GEN_AT = "2026-07-24T12:00:00Z"
TENANT = "Acme Payments, Inc."


# ── representative fixtures ────────────────────────────────────────────────
def sample_findings():
    return [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "rule_id": "KAFKA.LISTENER.PLAINTEXT",
            "severity": "critical",
            "title": "Broker listener is PLAINTEXT",
            "status": "open",
            "connector": "kafka",
            "resource": "broker-0",
            "first_seen": "2026-07-01T00:00:00Z",
            "observation": "config listeners contains PLAINTEXT://0.0.0.0:9092",
            "remediation": "Switch the listener to SSL:// and disable PLAINTEXT.",
            "assessment": "assessed",
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "rule_id": "RABBITMQ.USER.DEFAULT_GUEST_PRESENT",
            "severity": "high",
            "title": "Default guest user present",
            "status": "triaged",
            "connector": "rabbitmq",
            "resource": "vhost=/, user=guest",
            "first_seen": "2026-07-02T00:00:00Z",
            "observation": "user 'guest' exists with administrator tag",
            "remediation": "Delete the guest account.",
            "assessment": "assessed",
        },
        {
            # a coverage gap: could NOT be assessed. Must never become a fail/risk.
            "id": "33333333-3333-3333-3333-333333333333",
            "rule_id": "RABBITMQ.SCAN.NOT_ASSESSABLE",
            "severity": "info",
            "title": "Management API unreachable",
            "status": "open",
            "connector": "rabbitmq",
            "resource": "mgmt-api",
            "first_seen": "2026-07-03T00:00:00Z",
            "observation": "management plugin API returned 401; config is redacted to null",
            "assessment": "not_assessable",
        },
        {
            # a field with a comma and a quote, to exercise CSV escaping.
            "id": "44444444-4444-4444-4444-444444444444",
            "rule_id": "KONG.ADMIN.LISTEN_WILDCARD",
            "severity": "medium",
            "title": 'Admin API bound to 0.0.0.0:8001, "wildcard"',
            "status": "open",
            "connector": "kong",
            "resource": "admin-listener",
            "first_seen": "2026-07-04T00:00:00Z",
            "observation": "admin_listen = 0.0.0.0:8001",
            "remediation": "Bind admin API to 127.0.0.1, then use a bastion.",
            "assessment": "assessed",
        },
    ]


def sample_controls():
    return [
        {
            "framework": "PCI_DSS_4_0_1",
            "control_id": "2.2.5",
            "title": "Insecure services have documented justification and mitigating features",
            "requirement": "If any insecure services, protocols, or daemons are present...",
            "status": "fail",
            "failing_finding_ids": ["11111111-1111-1111-1111-111111111111"],
            "unknown_finding_ids": [],
        },
        {
            "framework": "PCI_DSS_4_0_1",
            "control_id": "7.2.5",
            "title": "Application and system accounts have least privilege",
            "requirement": "All application and system accounts...",
            # unknown: clean-but-unattested. Must NOT appear as a satisfied OSCAL finding.
            "status": "unknown",
            "failing_finding_ids": [],
            "unknown_finding_ids": [],
        },
        {
            "framework": "PCI_DSS_4_0_1",
            "control_id": "2.2.2",
            "title": "Vendor default accounts are removed, disabled, or have changed passwords",
            "requirement": "Vendor default accounts are managed as follows...",
            # pass: only ever from a live attestation upstream. Satisfied here is legitimate.
            "status": "pass",
            "failing_finding_ids": [],
            "unknown_finding_ids": [],
        },
        {
            "framework": "DORA",
            "control_id": "Art.9(2)",
            "title": "Protection and prevention — data security",
            "requirement": "Financial entities shall...",
            # out of scope for this tenant.
            "status": "not_applicable",
            "failing_finding_ids": [],
            "unknown_finding_ids": [],
        },
    ]


def sample_posture():
    return {
        "score": 42,
        "grade": "D",
        "weighted": 55.5,
        "counts": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 1},
        "previous_score": 30,
    }


# ── posture helper mirrors posture.ts ──────────────────────────────────────
def test_posture_from_counts_matches_formula():
    # clean estate scores 100.
    assert posture_from_counts({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}) == {
        "score": 100, "grade": "A", "weighted": 0.0,
    }
    # weighted = 10*2 = 20 -> 100*(1 - 20/60) = 66.67 -> 67, grade C.
    two_crit = posture_from_counts({"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 0})
    assert two_crit["weighted"] == 20.0
    assert two_crit["score"] == 67
    assert two_crit["grade"] == "C"
    # info is excluded from the weighting.
    assert posture_from_counts({"info": 99})["score"] == 100


# ── OSCAL Assessment Results ───────────────────────────────────────────────
def test_oscal_has_required_members_and_round_trips():
    doc = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    # round-trips through json unchanged.
    assert json.loads(json.dumps(doc)) == doc

    ar = doc["assessment-results"]
    # root required members.
    for member in ("uuid", "metadata", "import-ap", "results"):
        assert member in ar, f"missing root member {member}"
    # metadata required members.
    for member in ("title", "last-modified", "version", "oscal-version"):
        assert member in ar["metadata"], f"missing metadata member {member}"
    assert ar["metadata"]["last-modified"] == GEN_AT
    assert ar["metadata"]["oscal-version"].startswith("1.1")
    # import-ap must carry an href.
    assert ar["import-ap"]["href"]

    result = ar["results"][0]
    for member in ("uuid", "description", "start", "reviewed-controls",
                   "observations", "findings", "risks"):
        assert member in result, f"missing result member {member}"
    assert result["start"] == GEN_AT
    # reviewed-controls carries a control-selections list.
    assert isinstance(result["reviewed-controls"]["control-selections"], list)


def test_oscal_observations_cover_every_finding_with_required_members():
    doc = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    observations = doc["assessment-results"]["results"][0]["observations"]
    assert len(observations) == len(sample_findings())
    for obs in observations:
        for member in ("uuid", "description", "methods", "collected"):
            assert member in obs, f"observation missing {member}"
        assert obs["methods"] == ["TEST"]


def test_oscal_unknown_control_is_not_a_satisfied_finding():
    doc = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    findings = doc["assessment-results"]["results"][0]["findings"]
    target_ids = {f["target"]["target-id"] for f in findings}
    # unknown control 7.2.5 and not_applicable Art.9(2) make NO determination.
    assert "PCI_DSS_4_0_1:7.2.5" not in target_ids
    assert "DORA:Art.9(2)" not in target_ids
    # fail -> not-satisfied, pass -> satisfied are both present and correct.
    by_target = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in findings}
    assert by_target["PCI_DSS_4_0_1:2.2.5"] == "not-satisfied"
    assert by_target["PCI_DSS_4_0_1:2.2.2"] == "satisfied"
    # every emitted finding state is a valid OSCAL objective-status token.
    assert all(state in ("satisfied", "not-satisfied") for state in by_target.values())


def test_oscal_failing_control_links_to_its_observation():
    doc = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    result = doc["assessment-results"]["results"][0]
    obs_uuids = {o["uuid"] for o in result["observations"]}
    fail = next(f for f in result["findings"]
                if f["target"]["target-id"] == "PCI_DSS_4_0_1:2.2.5")
    related = fail["related-observations"]
    assert related, "failing control should link to the finding evidence"
    assert all(r["observation-uuid"] in obs_uuids for r in related)


def test_oscal_not_assessable_finding_never_becomes_a_risk():
    doc = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    result = doc["assessment-results"]["results"][0]
    # risks: only open + assessable findings. The 3 open/assessable? open ones are 1,3(NA),4.
    # finding 3 is not_assessable -> excluded; finding 2 is triaged(open) & assessable -> included.
    risk_titles = {r["title"] for r in result["risks"]}
    assert "Management API unreachable" not in risk_titles  # not_assessable -> no risk
    for risk in result["risks"]:
        for member in ("uuid", "title", "description", "statement", "status"):
            assert member in risk, f"risk missing {member}"
        assert risk["status"] == "open"
    # the not_assessable finding IS present as an observation, typed as a coverage gap.
    gap = next(o for o in result["observations"] if o["title"] == "Management API unreachable")
    assert gap["types"] == ["coverage-gap"]


def test_oscal_is_deterministic():
    a = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    b = to_oscal_assessment_results(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    assert a == b


def test_oscal_empty_inputs_still_valid():
    doc = to_oscal_assessment_results(
        [], [], {"score": 100, "grade": "A", "weighted": 0, "counts": {}},
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    ar = doc["assessment-results"]
    assert ar["results"][0]["reviewed-controls"]["control-selections"][0] == {"include-all": {}}
    assert ar["results"][0]["observations"] == []
    assert json.loads(json.dumps(doc)) == doc


# ── OSCAL Component Definition ──────────────────────────────────────────────
def test_component_definition_skeleton():
    doc = to_oscal_component_definition(
        sample_controls(), tenant_name=TENANT, generated_at=GEN_AT,
    )
    cd = doc["component-definition"]
    for member in ("uuid", "metadata", "components"):
        assert member in cd
    for member in ("title", "last-modified", "version", "oscal-version"):
        assert member in cd["metadata"]
    component = cd["components"][0]
    for member in ("uuid", "type", "title", "description"):
        assert member in component
    # control-implementations are grouped by framework and carry implemented-requirements.
    impls = component["control-implementations"]
    frameworks = {ci["source"] for ci in impls}
    assert "#vectasec-framework-PCI_DSS_4_0_1" in frameworks
    for ci in impls:
        for member in ("uuid", "source", "description", "implemented-requirements"):
            assert member in ci
        for req in ci["implemented-requirements"]:
            assert "control-id" in req and "uuid" in req
    assert json.loads(json.dumps(doc)) == doc


# ── Findings CSV ───────────────────────────────────────────────────────────
def test_csv_column_order_is_stable():
    out = to_findings_csv(sample_findings())
    reader = list(csv.reader(io.StringIO(out)))
    assert tuple(reader[0]) == FINDINGS_CSV_COLUMNS
    assert reader[0] == [
        "rule_id", "severity", "connector", "resource", "title", "status",
        "first_seen", "observation", "remediation",
    ]


def test_csv_rows_sorted_worst_first_and_all_present():
    out = to_findings_csv(sample_findings())
    reader = list(csv.reader(io.StringIO(out)))
    body = reader[1:]
    assert len(body) == len(sample_findings())
    # critical first, then high, then medium, then info (the not_assessable one).
    severities = [row[1] for row in body]
    assert severities == ["critical", "high", "medium", "info"]


def test_csv_escapes_commas_and_quotes():
    out = to_findings_csv(sample_findings())
    reader = list(csv.reader(io.StringIO(out)))
    # the Kong row title has a comma and embedded quotes; csv must preserve it exactly on read-back.
    kong_row = next(r for r in reader if r[0] == "KONG.ADMIN.LISTEN_WILDCARD")
    assert kong_row[4] == 'Admin API bound to 0.0.0.0:8001, "wildcard"'
    # and the raw text must have quoted that field (escaping actually happened).
    assert '"Admin API bound to 0.0.0.0:8001, ""wildcard"""' in out


def test_csv_header_can_be_omitted():
    out = to_findings_csv(sample_findings(), include_header=False)
    reader = list(csv.reader(io.StringIO(out)))
    assert reader[0][0] == "KAFKA.LISTENER.PLAINTEXT"  # first data row, no header


def test_csv_tolerates_missing_fields():
    out = to_findings_csv([{"rule_id": "X.Y.Z", "severity": "low"}])
    reader = list(csv.reader(io.StringIO(out)))
    assert reader[1][0] == "X.Y.Z"
    assert reader[1][3] == ""  # resource absent -> empty, not a crash


# ── Executive summary Markdown ─────────────────────────────────────────────
def test_markdown_includes_score_and_severity_counts():
    md = to_executive_summary_markdown(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    assert TENANT in md
    assert "42/100" in md
    assert "Grade D" in md
    # every severity count from the posture is rendered.
    assert "| Critical | 1 |" in md
    assert "| High | 1 |" in md
    assert "| Medium | 1 |" in md
    assert "| Low | 0 |" in md
    assert "| Info | 1 |" in md
    assert "| **Total** | **4** |" in md


def test_markdown_trend_reflects_previous_score():
    md = to_executive_summary_markdown(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    assert "+12 vs previous (30)" in md
    assert "improved" in md


def test_markdown_trend_absent_when_no_previous():
    posture = {k: v for k, v in sample_posture().items() if k != "previous_score"}
    md = to_executive_summary_markdown(
        sample_findings(), sample_controls(), posture,
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    assert "no prior score on record" in md


def test_markdown_compliance_coverage_is_honest():
    md = to_executive_summary_markdown(
        sample_findings(), sample_controls(), sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    # PCI: 1 fail, 1 pass, 1 unknown, 0 n/a -> pass ratio 1/2 = 50%, coverage 2/3 = 67%.
    assert "| PCI_DSS_4_0_1 | 1 | 1 | 1 | 0 | 50% | 67% |" in md
    # the honesty note must be present verbatim in spirit.
    assert "can prove a control **fails**" in md
    assert "never as failures" in md


def test_markdown_pass_ratio_undefined_renders_dash_not_100pct():
    # no evaluated controls at all -> pass ratio is undefined, must not read as 100%.
    controls = [{"framework": "PCI_DSS_4_0_1", "control_id": "7.2.5", "status": "unknown"}]
    md = to_executive_summary_markdown(
        sample_findings(), controls, sample_posture(),
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    assert "| PCI_DSS_4_0_1 | 0 | 0 | 1 | 0 | — | 0% |" in md


def test_markdown_score_recomputed_when_absent():
    md = to_executive_summary_markdown(
        [], [], {"counts": {"critical": 2}},  # no score given -> recompute -> 67
        tenant_name=TENANT, generated_at=GEN_AT,
    )
    assert "67/100" in md
