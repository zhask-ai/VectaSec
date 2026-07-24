"""Pure report-export core: VectaSec findings/controls/posture → OSCAL, CSV, exec Markdown.

This module is the isolated *generation* half of reporting. It has no API, no web, no DB and no
clock: every function takes plain dicts/lists and a `generated_at` timestamp passed IN, and
returns a value. Nothing here calls datetime.now() or uuid4 — identifiers are derived with
uuid5 from stable inputs — so the same inputs always produce byte-identical output and the whole
surface is unit-testable offline. Wiring this into the API is a later, coordinated step.

Evidence honesty (the same contract compliance/map.py enforces, carried through to the exports):

  A finding can prove a control FAILS. A finding's absence can never prove one PASSES. So a
  control this run could not determine (status `unknown`) is NEVER emitted as a satisfied OSCAL
  finding, is excluded from the executive summary's pass ratio, and is reported as a coverage gap
  rather than folded into either the numerator or the denominator. A `not_assessable` VectaSec
  finding is our blind spot, not the tenant's failure: it becomes an OSCAL *observation* only,
  never a not-satisfied finding and never an open risk. `pass` is not manufactured anywhere here;
  it only appears in an OSCAL finding when the source control the caller handed us already holds
  status `pass` (which map.py writes solely from a live human attestation).

OSCAL structure verified against the NIST OSCAL Assessment Results 1.1.x JSON reference
(https://pages.nist.gov/OSCAL-Reference/models/v1.1.3/assessment-results/json-reference/). The
required members emitted are, at the root: `uuid`, `metadata`, `import-ap`, `results`; metadata:
`title`, `last-modified`, `version`, `oscal-version`; each result: `uuid`, `description`, `start`,
`reviewed-controls`; and the mapped `observations`, `findings`, `risks` collections.
"""
import csv
import io
import uuid
from typing import Optional

# One source of truth for "which statuses are still an unremediated problem on the asset".
# Imported, not re-declared, so this module and the compliance engine can never drift apart.
from .compliance import OPEN_STATUSES

__all__ = [
    "to_oscal_assessment_results",
    "to_oscal_component_definition",
    "to_findings_csv",
    "to_executive_summary_markdown",
    "posture_from_counts",
    "FINDINGS_CSV_COLUMNS",
    "OSCAL_VERSION",
]

OSCAL_VERSION = "1.1.3"

# Stable namespace for every uuid5 in this module. Fixed string => fixed namespace => deterministic
# document identifiers across runs and machines.
_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://vectasec.io/ns/report")

# Severity ordering used everywhere a report sorts or ranks: worst first.
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# posture.ts / `vectasec posture` weighting, mirrored so a caller can recompute a score offline.
_POSTURE_WEIGHTS = {"critical": 10.0, "high": 4.0, "medium": 1.5, "low": 0.5, "info": 0.0}

FINDINGS_CSV_COLUMNS = (
    "rule_id",
    "severity",
    "connector",
    "resource",
    "title",
    "status",
    "first_seen",
    "observation",
    "remediation",
)


# ── small tolerant accessors ──────────────────────────────────────────────
def _get(row: dict, *keys: str, default: str = "") -> str:
    """First present, non-None value among `keys`, coerced to str. Report inputs come from a few
    slightly different call sites (a raw findings row, a joined view, a Hit-derived dict), so we
    accept a handful of aliases per field rather than demand one exact shape."""
    for key in keys:
        if key in row and row[key] is not None:
            return str(row[key])
    return default


def _severity(row: dict) -> str:
    return _get(row, "severity", default="info").strip().lower() or "info"


def _rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, len(_SEVERITY_RANK))


def _connector(row: dict) -> str:
    return _get(row, "connector", "connection_type", "system", "connection_name", "connection")


def _resource(row: dict) -> str:
    return _get(row, "resource", "resource_name", "resource_ext_id", "namespace")


def _observation(row: dict) -> str:
    return _get(row, "observation", "claim", "detail")


def _remediation(row: dict) -> str:
    return _get(row, "remediation", "remediation_summary")


def _first_seen(row: dict) -> str:
    return _get(row, "first_seen", "firstSeen", "observed_at")


def _is_open(row: dict) -> bool:
    return _get(row, "status", default="open").strip().lower() in OPEN_STATUSES


def _is_assessable(row: dict) -> bool:
    """not_assessable findings are coverage gaps, never failures. Accept either an explicit
    `assessment`/`assessable` field or default to assessable when the caller omits it."""
    assessment = _get(row, "assessment").strip().lower()
    if assessment:
        return assessment != "not_assessable"
    if "assessable" in row and row["assessable"] is not None:
        return bool(row["assessable"])
    return True


def _finding_id(row: dict) -> str:
    """Stable key for one finding. Prefer the DB id (what controls.failing_finding_ids reference),
    then the cross-scan fingerprint, then a composed fallback so id-less inputs still get a uuid."""
    return _get(row, "id", "finding_id", "fingerprint",
                default=f"{_get(row, 'rule_id')}|{_resource(row)}|{_connector(row)}")


def _uid(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "::".join(parts)))


def _prop(name: str, value: str) -> dict:
    return {"name": name, "value": value}


def _fmt_num(value) -> str:
    """Render a weighted score without a trailing `.0` so 55.0 prints as 55, 55.5 stays 55.5."""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


# ── posture ───────────────────────────────────────────────────────────────
def posture_from_counts(counts: dict) -> dict:
    """Mirror of apps/web/lib/posture.ts: one interpretable score from open severity counts.

        weighted = 10·crit + 4·high + 1.5·med + 0.5·low   (info excluded)
        score    = 100 if weighted == 0 else max(1, round(100·(1 − weighted/(weighted+40))))

    Provided for callers/tests that want the number offline; the report functions themselves take
    a posture dict as a parameter and do not require this."""
    weighted = sum(_POSTURE_WEIGHTS[s] * float(counts.get(s, 0) or 0) for s in _POSTURE_WEIGHTS)
    if weighted == 0:
        score = 100
    else:
        score = max(1, round(100 * (1 - weighted / (weighted + 40))))
    return {"score": score, "grade": _grade(score), "weighted": weighted}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _posture_counts(posture: dict) -> dict:
    """Severity counts out of a posture dict, whether nested under `counts` or spread on top."""
    counts = posture.get("counts") if isinstance(posture, dict) else None
    if not isinstance(counts, dict):
        counts = posture if isinstance(posture, dict) else {}
    return {s: int(counts.get(s, 0) or 0) for s in _SEVERITY_ORDER}


# ── compliance tally (honest denominator, mirrors frameworks.ts score()) ───
def _control_status(row: dict) -> str:
    status = _get(row, "status", default="unknown").strip().lower()
    return status if status in ("pass", "fail", "unknown", "not_applicable") else "unknown"


def _framework_of(row: dict) -> str:
    return _get(row, "framework", default="")


def _control_id_of(row: dict) -> str:
    return _get(row, "control_id", "controlId", default="")


def _compliance_tally(controls: list) -> dict:
    """Per-framework and overall {pass, fail, unknown, not_applicable}. The only honest ratio is
    pass/(pass+fail): `unknown` is never counted as a pass (that is the lie the product refuses)
    nor as a fail (that claims knowledge we lack), and `not_applicable` is out of scope, not a
    gap. So both are excluded from the pass ratio; coverage = evaluated/in-scope keeps it honest."""
    by_fw: dict = {}
    overall = {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0}
    for row in controls or []:
        fw = _framework_of(row) or "(unspecified)"
        status = _control_status(row)
        by_fw.setdefault(fw, {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0})
        by_fw[fw][status] += 1
        overall[status] += 1
    return {"by_framework": by_fw, "overall": overall}


def _ratios(tally: dict) -> dict:
    evaluated = tally["pass"] + tally["fail"]
    in_scope = evaluated + tally["unknown"]
    return {
        "evaluated": evaluated,
        "in_scope": in_scope,
        "pass_ratio": (tally["pass"] / evaluated) if evaluated else None,
        "coverage": (evaluated / in_scope) if in_scope else None,
    }


# ── OSCAL Assessment Results ───────────────────────────────────────────────
def to_oscal_assessment_results(
    findings: list,
    controls: list,
    posture: dict,
    *,
    tenant_name: str,
    generated_at: str,
    assessment_plan_href: str = "#vectasec-generated-assessment",
    oscal_version: str = OSCAL_VERSION,
    document_version: str = "0.0.1",
) -> dict:
    """VectaSec findings/controls → an OSCAL 1.1.x Assessment Results document (a JSON-ready dict).

    The mapping is deliberately typed:
      • observation ← every VectaSec finding (the raw evidence read from the target).
      • finding     ← every *determinate* control the caller passes (status pass or fail). Its
                      target.status.state is satisfied/not-satisfied accordingly. Controls with
                      status `unknown` or `not_applicable` are NOT emitted as findings — they make
                      no satisfied/not-satisfied claim — but they still appear in reviewed-controls
                      so the document is transparent about what was in scope.
      • risk        ← every VectaSec finding that is open AND assessable (an actionable risk).
                      not_assessable findings never become risks (coverage gap, not a risk).

    `generated_at` is used verbatim as metadata.last-modified and the result's start; nothing here
    reads a clock. All uuids are uuid5-derived, so the document is fully deterministic."""
    findings = list(findings or [])
    controls = list(controls or [])

    result_uid = _uid("result", tenant_name, generated_at)

    observations = []
    obs_uuid_by_finding_id = {}
    for f in findings:
        fid = _finding_id(f)
        obs_uuid = _uid("observation", fid)
        obs_uuid_by_finding_id[fid] = obs_uuid
        assessable = _is_assessable(f)
        props = [
            _prop("rule-id", _get(f, "rule_id")),
            _prop("severity", _severity(f)),
            _prop("status", _get(f, "status", default="open")),
            _prop("assessment", "assessed" if assessable else "not_assessable"),
        ]
        connector = _connector(f)
        if connector:
            props.append(_prop("connector", connector))
        description = _observation(f) or _get(f, "title", default="(no observation recorded)")
        observations.append({
            "uuid": obs_uuid,
            "title": _get(f, "title", default=_get(f, "rule_id")),
            "description": description,
            "props": props,
            # TEST = an automated examination of the target's configuration.
            "methods": ["TEST"],
            # A finding proper vs. a coverage gap we could not settle.
            "types": ["finding"] if assessable else ["coverage-gap"],
            "collected": _first_seen(f) or generated_at,
        })

    oscal_findings = []
    for c in controls:
        status = _control_status(c)
        if status not in ("pass", "fail"):
            continue  # unknown / not_applicable make no determination — honesty contract.
        fw = _framework_of(c)
        cid = _control_id_of(c)
        target_id = f"{fw}:{cid}" if fw else cid
        state = "satisfied" if status == "pass" else "not-satisfied"
        related = [
            {"observation-uuid": obs_uuid_by_finding_id[str(i)]}
            for i in (c.get("failing_finding_ids") or [])
            if str(i) in obs_uuid_by_finding_id
        ]
        oscal_findings.append({
            "uuid": _uid("finding", fw, cid),
            "title": _get(c, "title", default=target_id),
            "description": _get(c, "requirement", "title", default=target_id),
            "props": [
                _prop("framework", fw),
                _prop("control-id", cid),
                _prop("vectasec-status", status),
            ],
            "target": {
                "type": "objective-id",
                "target-id": target_id,
                "status": {"state": state},
            },
            "related-observations": related,
        })

    risks = []
    for f in findings:
        if not (_is_open(f) and _is_assessable(f)):
            continue  # only open, assessable findings are actionable risks.
        fid = _finding_id(f)
        statement = _remediation(f) or _observation(f) or _get(f, "title", default="")
        risks.append({
            "uuid": _uid("risk", fid),
            "title": _get(f, "title", default=_get(f, "rule_id")),
            "description": _observation(f) or _get(f, "title", default=""),
            "statement": statement or "Remediation guidance not recorded for this finding.",
            "props": [_prop("severity", _severity(f)), _prop("rule-id", _get(f, "rule_id"))],
            "status": "open",
            "related-observations": [{"observation-uuid": obs_uuid_by_finding_id[fid]}],
        })

    reviewed_controls = _reviewed_controls(controls)

    posture_counts = _posture_counts(posture)
    score = posture.get("score") if isinstance(posture, dict) else None
    result_props = [_prop("vectasec-posture-score", str(score))] if score is not None else []
    for sev in _SEVERITY_ORDER:
        result_props.append(_prop(f"open-{sev}", str(posture_counts[sev])))

    result = {
        "uuid": result_uid,
        "title": f"{tenant_name} integration security scan",
        "description": (
            "Automated posture assessment of the tenant's integration-layer connectors by "
            "VectaSec. Controls with status 'unknown' were in scope but could not be determined "
            "by this scan and are reported as coverage gaps, never as satisfied."
        ),
        "start": generated_at,
        "props": result_props,
        "reviewed-controls": reviewed_controls,
        "observations": observations,
        "risks": risks,
        "findings": oscal_findings,
    }

    return {
        "assessment-results": {
            "uuid": _uid("assessment-results", tenant_name, generated_at),
            "metadata": _metadata(
                f"{tenant_name} — VectaSec Integration Security Assessment Results",
                generated_at, document_version, oscal_version,
            ),
            "import-ap": {
                "href": assessment_plan_href,
                "remarks": (
                    "VectaSec generates assessment results directly from continuous scans; there "
                    "is no separate OSCAL assessment-plan document. This self-reference satisfies "
                    "the required import-ap member."
                ),
            },
            "results": [result],
        }
    }


def _reviewed_controls(controls: list) -> dict:
    """control-selections listing exactly the controls this run reviewed. include-all only when
    the caller passed no controls at all (we reviewed nothing specific to name)."""
    selection_ids = []
    seen = set()
    for c in controls or []:
        fw = _framework_of(c)
        cid = _control_id_of(c)
        target_id = f"{fw}:{cid}" if fw else cid
        if target_id and target_id not in seen:
            seen.add(target_id)
            selection_ids.append(target_id)
    if not selection_ids:
        return {"control-selections": [{"include-all": {}}]}
    return {
        "control-selections": [
            {"include-controls": [{"control-id": cid} for cid in selection_ids]}
        ]
    }


def _metadata(title: str, generated_at: str, version: str, oscal_version: str) -> dict:
    return {
        "title": title,
        "last-modified": generated_at,
        "version": version,
        "oscal-version": oscal_version,
    }


# ── OSCAL Component Definition (minimal skeleton) ──────────────────────────
def to_oscal_component_definition(
    controls: list,
    *,
    tenant_name: str,
    generated_at: str,
    oscal_version: str = OSCAL_VERSION,
    document_version: str = "0.0.1",
) -> dict:
    """A minimal OSCAL 1.1.x Component Definition skeleton: one component representing the tenant's
    VectaSec-managed integration estate, carrying a control-implementation per framework built from
    the controls handed in. Enough to be a valid, round-trippable component-definition without
    inventing implementation prose the scan cannot support."""
    controls = list(controls or [])

    by_fw: dict = {}
    for c in controls:
        fw = _framework_of(c) or "(unspecified)"
        by_fw.setdefault(fw, [])
        by_fw[fw].append(c)

    component_uuid = _uid("component", tenant_name)
    control_implementations = []
    for fw in sorted(by_fw):
        seen = set()
        implemented = []
        for c in by_fw[fw]:
            cid = _control_id_of(c)
            if not cid or cid in seen:
                continue
            seen.add(cid)
            implemented.append({
                "uuid": _uid("impl-req", fw, cid),
                "control-id": f"{fw}:{cid}",
                "description": _get(c, "requirement", "title", default=f"{fw}:{cid}"),
                "props": [_prop("vectasec-status", _control_status(c))],
            })
        if not implemented:
            continue
        control_implementations.append({
            "uuid": _uid("control-implementation", fw),
            "source": f"#vectasec-framework-{fw}",
            "description": f"Controls evaluated by VectaSec for {fw}.",
            "implemented-requirements": implemented,
        })

    component = {
        "uuid": component_uuid,
        "type": "software",
        "title": f"{tenant_name} integration estate (VectaSec-managed)",
        "description": (
            "The set of integration-layer connectors (message brokers, API gateways, MCP servers "
            "and similar) that VectaSec continuously assesses for this tenant."
        ),
        "purpose": "Continuous security-posture and compliance-evidence generation.",
    }
    if control_implementations:
        component["control-implementations"] = control_implementations

    return {
        "component-definition": {
            "uuid": _uid("component-definition", tenant_name, generated_at),
            "metadata": _metadata(
                f"{tenant_name} — VectaSec Integration Component Definition",
                generated_at, document_version, oscal_version,
            ),
            "components": [component],
        }
    }


# ── Findings CSV ───────────────────────────────────────────────────────────
def to_findings_csv(findings: list, *, include_header: bool = True) -> str:
    """Findings → CSV string with a stable column order (FINDINGS_CSV_COLUMNS). Rows are sorted
    worst-severity-first, then rule_id/resource, so the file is deterministic regardless of the
    order the caller pulled rows in. Escaping is delegated to the stdlib csv writer (quotes fields
    containing commas, quotes or newlines), and the line terminator is pinned to '\\n' so output
    does not vary by platform."""
    rows = sorted(
        findings or [],
        key=lambda f: (_rank(_severity(f)), _get(f, "rule_id"), _resource(f), _finding_id(f)),
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    if include_header:
        writer.writerow(FINDINGS_CSV_COLUMNS)
    for f in rows:
        writer.writerow([
            _get(f, "rule_id"),
            _severity(f),
            _connector(f),
            _resource(f),
            _get(f, "title"),
            _get(f, "status", default="open"),
            _first_seen(f),
            _observation(f),
            _remediation(f),
        ])
    return buffer.getvalue()


# ── Executive summary (Markdown) ───────────────────────────────────────────
def to_executive_summary_markdown(
    findings: list,
    controls: list,
    posture: dict,
    *,
    tenant_name: str,
    generated_at: str,
    top_n: int = 5,
) -> str:
    """A structured executive report in Markdown: posture score + trend, severity breakdown, the
    worst open findings, compliance coverage per framework, and an explicit coverage-honesty note.
    Pure string assembly — deterministic for fixed inputs."""
    findings = list(findings or [])
    counts = _posture_counts(posture)
    score = posture.get("score")
    if score is None:
        score = posture_from_counts(counts)["score"]
    grade = posture.get("grade") or _grade(int(score))
    weighted = posture.get("weighted")
    if weighted is None:
        weighted = posture_from_counts(counts)["weighted"]

    lines: list[str] = []
    lines.append(f"# Executive Security Summary — {tenant_name}")
    lines.append("")
    lines.append(f"_Generated: {generated_at}_")
    lines.append("")

    # ── Posture ──
    lines.append("## Posture")
    lines.append("")
    lines.append(f"- **Score:** {score}/100 (Grade {grade})")
    previous = posture.get("previous_score")
    if previous is not None:
        delta = int(score) - int(previous)
        arrow = "improved" if delta > 0 else "declined" if delta < 0 else "unchanged"
        sign = f"+{delta}" if delta > 0 else str(delta)
        lines.append(f"- **Trend:** {sign} vs previous ({previous}) — posture {arrow}.")
    else:
        lines.append("- **Trend:** no prior score on record for comparison.")
    lines.append(f"- **Weighted risk:** {_fmt_num(weighted)} "
                 "(10·critical + 4·high + 1.5·medium + 0.5·low; info excluded).")
    lines.append("")

    # ── Severity breakdown ──
    total = sum(counts[s] for s in _SEVERITY_ORDER)
    lines.append("## Severity breakdown")
    lines.append("")
    lines.append("| Severity | Open findings |")
    lines.append("| --- | --- |")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.capitalize()} | {counts[sev]} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    # ── Worst open findings ──
    open_assessed = [f for f in findings if _is_open(f) and _is_assessable(f)]
    worst = sorted(
        open_assessed,
        key=lambda f: (_rank(_severity(f)), _get(f, "rule_id"), _resource(f), _finding_id(f)),
    )[:top_n]
    lines.append(f"## Top open findings (worst {len(worst)})")
    lines.append("")
    if worst:
        for f in worst:
            title = _get(f, "title", default=_get(f, "rule_id", default="(untitled finding)"))
            where = _resource(f) or _connector(f)
            suffix = f" — {where}" if where else ""
            lines.append(f"- **[{_severity(f).upper()}] {title}**{suffix} "
                         f"(`{_get(f, 'rule_id')}`)")
    else:
        lines.append("- No open, assessable findings.")
    lines.append("")

    # ── Compliance coverage ──
    tally = _compliance_tally(controls)
    lines.append("## Compliance coverage")
    lines.append("")
    lines.append("| Framework | Fail | Pass | Unknown | N/A | Pass ratio | Coverage |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for fw in sorted(tally["by_framework"]):
        counts_fw = tally["by_framework"][fw]
        r = _ratios(counts_fw)
        lines.append(
            f"| {fw} | {counts_fw['fail']} | {counts_fw['pass']} | {counts_fw['unknown']} | "
            f"{counts_fw['not_applicable']} | {_pct(r['pass_ratio'])} | {_pct(r['coverage'])} |"
        )
    overall = tally["overall"]
    ro = _ratios(overall)
    lines.append(
        f"| **All** | **{overall['fail']}** | **{overall['pass']}** | **{overall['unknown']}** | "
        f"**{overall['not_applicable']}** | **{_pct(ro['pass_ratio'])}** | "
        f"**{_pct(ro['coverage'])}** |"
    )
    lines.append("")

    # ── Coverage honesty ──
    lines.append("## Coverage honesty")
    lines.append("")
    lines.append(
        "- A scan can prove a control **fails**; it can never prove one **passes** on its own. "
        "A control with no live human attestation stays `unknown`, not `pass`."
    )
    lines.append(
        "- `unknown` controls are excluded from the pass ratio's denominator — counting "
        "unevaluated controls as passing (or as failing) would misstate what this scan knows."
    )
    lines.append(
        "- `not_applicable` controls are out of scope for this tenant, not coverage gaps."
    )
    not_assessable = [f for f in findings if not _is_assessable(f)]
    lines.append(
        f"- {len(not_assessable)} finding(s) were **not assessable** (the value needed could not "
        "be read); these are reported as coverage gaps, never as failures."
    )
    lines.append("")

    return "\n".join(lines)


def _pct(value: Optional[float]) -> str:
    """A ratio in [0,1] as a percent, or an em dash when undefined (0/0 is not 100%)."""
    if value is None:
        return "—"
    return f"{round(value * 100)}%"
