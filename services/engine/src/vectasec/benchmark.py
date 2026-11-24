"""The VectaSec Integration-Layer Benchmark: a published, numbered control list per system.

CIS publishes no benchmark for Kafka, RabbitMQ, Redis, NATS, Kong or n8n. A buyer therefore
has no neutral document to point at when asked "hardened against what?", and the category has
no budget line. This module turns the detector registry into that document: one benchmark per
system, each control with a stable number, a severity, what is checked, how to fix it (from the
guided-fix library) and the framework controls it supports (from compliance/map.py).

It is generated, never hand-copied, so the benchmark cannot drift from what the product checks:
a control exists here if and only if a detector exists for it.

Two outputs:
  catalogue()   the benchmark itself — public content, the same for every tenant.
  scorecard()   one tenant's result against it: pass / fail / not assessed / not scanned.

HONESTY
  * Control numbers are positional within a system and section; the rule id beside each one is
    the stable identifier. The document says so.
  * `pass` is only reported for a control whose system was scanned, whose resource kind the
    scan actually returned, and which raised no open finding and no not-assessable finding. A
    control the scan could not evaluate, or had nothing to run against, is `not_assessed`.
    A system that is not connected is `not_scanned`. Neither is ever counted as a pass.
  * This is VectaSec's benchmark, version-stamped, not a CIS document, and it says that too.
"""
from __future__ import annotations

from typing import Iterable, Optional

__all__ = ["VERSION", "SYSTEMS", "catalogue", "scorecard", "to_markdown", "load_scorecard"]

VERSION = "0.1"

# system key -> (title, rule-id prefixes, connection types that scan it)
SYSTEMS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "kafka": ("Apache Kafka", ("KAFKA.",), ("kafka", "msk", "confluent", "redpanda")),
    "rabbitmq": ("RabbitMQ", ("RABBITMQ.",), ("rabbitmq",)),
    "redis": ("Redis / Valkey", ("REDIS.",), ("redis",)),
    "nats": ("NATS", ("NATS.",), ("nats",)),
    "kong": ("Kong Gateway", ("KONG.",), ("kong",)),
    "n8n": ("n8n", ("N8N.",), ("n8n",)),
    "mcp": ("MCP servers", ("MCP.",), ("mcp",)),
    "mqtt": ("MQTT brokers", ("MQTT.",), ("mqtt",)),
    "elasticsearch": ("Elasticsearch / OpenSearch", ("ELASTICSEARCH.",), ("elasticsearch",)),
    "vault": ("HashiCorp Vault", ("VAULT.",), ("vault",)),
}

_SECTION_TITLES = {
    "AUTH": "Authentication", "AUTHZ": "Authorization", "ACL": "Access control lists",
    "TLS": "Transport encryption", "SSL": "Transport encryption", "LISTENER": "Listeners",
    "ADMIN": "Administrative interfaces", "NETWORK": "Network exposure", "VERSION": "Versions and patches",
    "CVE": "Versions and patches", "USER": "Users and credentials", "CREDENTIAL": "Users and credentials",
    "WORKFLOW": "Workflows", "WEBHOOK": "Webhooks", "ROUTE": "Routes", "PLUGIN": "Plugins",
    "TOOL": "Tools", "SESSION": "Sessions", "TRANSPORT": "Transport", "AUDIT": "Audit and logging",
}
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _section(rule_id: str) -> str:
    parts = rule_id.split(".")
    key = parts[1] if len(parts) > 2 else "GENERAL"
    return _SECTION_TITLES.get(key, key.replace("_", " ").capitalize())


def catalogue(detectors: Optional[Iterable] = None) -> dict:
    """{system: {title, version, sections: [{title, controls: [...]}], control_count}}."""
    if detectors is None:
        from . import detect as _detect  # noqa: F401 - registers detectors
        from .registry import DETECTORS
        detectors = DETECTORS
    from . import remediation
    from .compliance.map import RULE_TO_CONTROLS

    seen: dict[str, object] = {}
    for d in detectors:
        seen.setdefault(d.rule_id, d)

    out: dict[str, dict] = {}
    for key, (title, prefixes, _types) in SYSTEMS.items():
        rules = [d for rid, d in seen.items() if rid.startswith(prefixes)]
        sections: dict[str, list] = {}
        for d in rules:
            sections.setdefault(_section(d.rule_id), []).append(d)
        sec_list = []
        for si, sec_title in enumerate(sorted(sections), 1):
            controls = []
            ordered = sorted(sections[sec_title], key=lambda d: (_SEV_RANK.get(d.severity, 9), d.rule_id))
            for ci, d in enumerate(ordered, 1):
                found = remediation.lookup(d.rule_id)
                fix = found[1] if found else None
                refs = RULE_TO_CONTROLS.get(d.rule_id, ())
                controls.append({
                    "number": f"{si}.{ci}", "rule_id": d.rule_id, "title": d.title,
                    "severity": d.severity, "kinds": sorted(d.kinds),
                    "remediation": fix.summary if fix else None,
                    "verify": fix.verify_hint if fix else None,
                    "frameworks": sorted({f"{r.framework} {r.control_id}" for r in refs}),
                })
            sec_list.append({"number": str(si), "title": sec_title, "controls": controls})
        if sec_list:
            out[key] = {"key": key, "title": title, "version": VERSION, "sections": sec_list,
                        "control_count": sum(len(s["controls"]) for s in sec_list)}
    return out


def scorecard(cat: dict, connection_types: Iterable[str], findings: Iterable[dict],
              kinds_seen: Optional[dict] = None) -> dict:
    """findings: {rule_id, status, assessment}. kinds_seen: connection type -> set of resource
    kinds its scans returned. Per system: counts and a per-control result.

    `pass` needs three things: the system was scanned, the scan returned at least one resource
    of a kind the control applies to, and no open finding or coverage gap exists for it. A
    control whose resource kind the scan never returned is `not_assessed`: the check had
    nothing to run against, and an empty result is not evidence (the product's standing rule).
    With kinds_seen=None that third test is skipped (unit tests of the counting only)."""
    scanned = {str(t) for t in connection_types}
    failing: dict[str, int] = {}
    gaps: set = set()
    for f in findings:
        if f.get("status") not in ("open", "triaged", "in_progress"):
            continue
        if f.get("assessment") == "not_assessable":
            gaps.add(f["rule_id"])
        else:
            failing[f["rule_id"]] = failing.get(f["rule_id"], 0) + 1

    systems = []
    for key, bench in cat.items():
        types = SYSTEMS[key][2]
        is_scanned = bool(scanned & set(types))
        present = None
        if kinds_seen is not None:
            present = set()
            for t in types:
                present |= set(kinds_seen.get(t, ()))
        results, counts = {}, {"pass": 0, "fail": 0, "not_assessed": 0, "not_scanned": 0}
        for sec in bench["sections"]:
            for c in sec["controls"]:
                rid = c["rule_id"]
                if not is_scanned:
                    r = "not_scanned"
                elif rid in failing:
                    r = "fail"
                elif rid in gaps or (present is not None and not (set(c["kinds"]) & present)):
                    r = "not_assessed"
                else:
                    r = "pass"
                results[rid] = {"result": r, "open": failing.get(rid, 0)}
                counts[r] += 1
        assessed = counts["pass"] + counts["fail"]
        systems.append({"key": key, "title": bench["title"], "scanned": is_scanned,
                        "counts": counts, "controls": bench["control_count"],
                        "score": round(100 * counts["pass"] / assessed) if assessed else None,
                        "results": results})
    systems.sort(key=lambda s: (not s["scanned"], s["title"]))
    return {"version": VERSION, "systems": systems}


def load_scorecard(cur, tenant_id: str) -> dict:
    cur.execute("select distinct type from connections where tenant_id = %s and last_scanned_at is not null",
                (tenant_id,))
    types = [r[0] for r in cur.fetchall() or []]
    cur.execute("select rule_id, status, assessment from findings where tenant_id = %s", (tenant_id,))
    findings = [{"rule_id": r[0], "status": r[1], "assessment": r[2]} for r in cur.fetchall() or []]
    cur.execute(
        """select c.type, r.kind from resources r join connections c on c.id = r.connection_id
            where r.tenant_id = %s and not r.stale group by c.type, r.kind""", (tenant_id,))
    kinds_seen: dict[str, set] = {}
    for ctype, kind in cur.fetchall() or []:
        kinds_seen.setdefault(ctype, set()).add(kind)
    cat = catalogue()
    return {**scorecard(cat, types, findings, kinds_seen), "catalogue": cat}


_MARK = {"pass": "Pass", "fail": "FAIL", "not_assessed": "Not assessed", "not_scanned": "Not scanned"}


def to_markdown(bench: dict, results: Optional[dict] = None, *, generated_at: str = "") -> str:
    """One system's benchmark; with `results` (scorecard()['systems'][i]) it is a filled-in
    assessment, without it the blank public document."""
    lines = [f"# VectaSec Integration-Layer Benchmark: {bench['title']}", "",
             f"Version {bench['version']} · {bench['control_count']} controls"
             + (f" · assessed {generated_at[:10]}" if results and generated_at else ""), "",
             "> Published by VectaSec because no CIS Benchmark exists for this system. It is "
             "generated from the product's detectors, so every control here is one that is "
             "actually checked. Control numbers can change between versions; the rule id is the "
             "stable identifier. This is not a CIS document.", ""]
    if results:
        c = results["counts"]
        lines += [f"**Result: {c['pass']} pass, {c['fail']} fail, {c['not_assessed']} not assessed"
                  + (f" · score {results['score']}%" if results.get("score") is not None else "")
                  + ("" if results["scanned"] else " · this system is not connected") + "**", "",
                  "A control counts as a pass only when the system was scanned, the scan "
                  "returned something the control applies to, and no issue was found. Not "
                  "assessed is never a pass.", ""]
    for sec in bench["sections"]:
        lines += [f"## {sec['number']}. {sec['title']}", ""]
        for c in sec["controls"]:
            head = f"### {c['number']} {c['title']}"
            if results:
                head += f" — {_MARK[results['results'][c['rule_id']]['result']]}"
            lines += [head, "", f"- Rule: `{c['rule_id']}` · Severity: {c['severity']}"]
            if c["remediation"]:
                lines.append(f"- Fix: {c['remediation']}")
            if c["verify"]:
                lines.append(f"- Check it worked: {c['verify']}")
            if c["frameworks"]:
                lines.append(f"- Supports: {', '.join(c['frameworks'])}")
            lines.append("")
    return "\n".join(lines)
