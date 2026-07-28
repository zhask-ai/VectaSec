"""OSV enrichment — the scan loop's live vulnerability feed, run after a scan persists.

`sbom.py` established which identifiers actually resolve (a bitnami purl is the only free feed
that maps a RUNNING broker version to advisories — `pkg:bitnami/rabbitmq@3.13.7` returns three
advisories where NVD returns zero), but until now the SBOM only *emitted* the identifiers: a
human still had to paste them into a browser. This module closes that loop. After each scan it
takes every purl-addressable component the connection just reported and asks the OSV API which
advisories affect that exact version — OSV does the range matching server-side, so the answer
is affected-or-not for the version we read, not a catalogue to re-derive locally.

Relationship to the curated pack (`cve_data.py` / `detect/cve.py`): the curated pack is
network-free, hand-verified, and carries KEV/EPSS/ATT&CK context the feed does not; this module
is live and broad but only as good as the feed that day. They overlap on purpose, EXCEPT that an
advisory whose id/alias is already in the curated dataset for the same product is skipped here —
the same CVE filed twice against one resource under two rule ids is a duplicate row, not a
second opinion.

Honesty discipline, same as everywhere else in the product:
  * The feed being UNREACHABLE files a not-assessable coverage gap naming what could not be
    checked — never silence, because silence is byte-identical to "checked, clean".
  * The feed being DISABLED (`VECTASEC_OSV_DISABLED`, for air-gapped on-prem where the engine
    has no egress) is a recorded operator choice: stats say so, no gap finding is filed, and
    no network call is attempted.
  * An INFERRED version (probe capability matrix, not read off the wire) still drives the
    query, but every claim built on it says so inline.
  * The detail-fetch budget is a hard cap, and exceeding it is stated in the finding rather
    than silently truncated — ids beyond the cap are still cited, just without feed detail.
"""
from __future__ import annotations

import json
import math
import os
from types import SimpleNamespace

from .sbom import component_for
from .scan import _active_suppressions, _is_suppressed, fingerprint

OSV_API = "https://api.osv.dev/v1"

# querybatch accepts up to 1000 queries; chunk well below it so one oversized estate cannot
# produce a request the far end rejects wholesale.
BATCH_CHUNK = 200
# Per-run budget of GET /vulns/{id} detail fetches. Advisories beyond it are still cited by id.
MAX_VULN_DETAILS = 40
_TIMEOUT = 20.0

RULE_VULN = "SUPPLY.OSV.KNOWN_VULNERABILITY"
RULE_VULN_TITLE = "Running component version has a published OSV advisory"
RULE_GAP = "SUPPLY.OSV.NOT_ASSESSABLE"
RULE_GAP_TITLE = "OSV vulnerability feed could not be consulted"

# CVSS v3.1 base-score → house severity band (same bands as detect/cve.py).
_CVSS_BANDS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))
_RANK = ["info", "low", "medium", "high", "critical"]
# GHSA-style database_specific.severity → house band, the fallback when no vector is given.
_DB_SEVERITY = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}


def osv_disabled() -> bool:
    """Air-gapped opt-out. Checked at call time (not import) for the same reason config.py
    reads os.environ on every access — entry points load .env after import."""
    return bool(os.environ.get("VECTASEC_OSV_DISABLED", "").strip())


# ── HTTP seams (monkeypatched in tests, same pattern as ai.py's _openai_post) ──
def _osv_post(url: str, body: dict) -> dict:
    import httpx
    r = httpx.post(url, json=body, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _osv_get(url: str) -> dict:
    import httpx
    r = httpx.get(url, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


# ── CVSS v3.x base score from a vector string ─────────────────────────────────
# OSV severity entries carry the CVSS VECTOR, not a number. The base-score arithmetic is fully
# specified (CVSS v3.1 §7.1) and deterministic, so computing it here is honest in a way that
# guessing a band from prose is not. v4 vectors use different arithmetic and fall through to
# the database_specific fallback rather than being mis-scored with v3 weights.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vector: str) -> float | None:
    """Base score for a CVSS:3.0/3.1 vector, or None when the vector is not parseable v3."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    m: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        k, _, v = part.partition(":")
        m[k] = v
    try:
        scope_changed = m["S"] == "C"
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    if scope_changed:
        raw = 1.08 * raw
    return _roundup(min(raw, 10.0))


def _roundup(x: float) -> float:
    """CVSS §Appendix A Roundup: smallest 0.1 increment >= x, with the spec's own guard
    against float representation error."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def advisory_severity(vuln: dict) -> tuple[str, str, float | None]:
    """(house severity band, how it was derived, numeric CVSS score or None). Vector math
    first, GHSA-style words second, and an explicit stated-by-nobody default last — recorded
    so the reader can see which. The numeric score travels into source_ref so downstream
    consumers (the SBOM's vulnerabilities section) never re-parse the derivation prose."""
    for entry in vuln.get("severity") or []:
        score = cvss3_base_score(entry.get("score", ""))
        if score is not None:
            band = "info"
            for floor, name in _CVSS_BANDS:
                if score >= floor:
                    band = name
                    break
            return band, f"cvss_v3 {score}", score
    word = str((vuln.get("database_specific") or {}).get("severity", "")).lower()
    if word in _DB_SEVERITY:
        return _DB_SEVERITY[word], f"feed severity label {word!r}", None
    return "medium", "default (the feed stated no severity)", None


def _fixed_versions(vuln: dict) -> list[str]:
    """Every 'fixed' event across the advisory's affected ranges — the actionable part."""
    fixed = []
    for aff in vuln.get("affected") or []:
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(str(ev["fixed"]))
    return sorted(set(fixed))


def _curated_ids() -> dict[str, str]:
    """cve_id -> product for the curated dataset, to skip advisories already filed by
    detect/cve.py against the same product."""
    from .cve_data import CVES
    return {c["cve_id"]: c["product"] for c in CVES}


def _components(cur, tenant_id: str, connection_id: str) -> list[dict]:
    """purl-bearing components for this connection's live resources. Same raw-key projection
    discipline as the /reports/sbom query — the SBOM reads a handful of keys, so only those
    keys leave the database."""
    cur.execute(
        """select r.id, r.kind, r.name, r.ext_id, r.labels,
                  jsonb_build_object(
                    'product', r.raw->'product', 'version', r.raw->'version',
                    'version_inferred', r.raw->'version_inferred',
                    'redis_version', r.raw->'redis_version',
                    'rabbitmq_version', r.raw->'rabbitmq_version',
                    'broker_version', r.raw->'broker_version',
                    'kafka_version', r.raw->'kafka_version',
                    'etcdserver', r.raw->'etcdserver') as raw,
                  c.type
             from resources r join connections c on c.id = r.connection_id
            where r.tenant_id = %s and r.connection_id = %s
              and coalesce(r.stale, false) = false
            order by r.ext_id""",
        (tenant_id, connection_id),
    )
    out = []
    for rid, kind, name, ext_id, labels, raw, ctype in cur.fetchall():
        comp = component_for({"kind": kind, "name": name, "ext_id": ext_id,
                              "labels": labels, "raw": raw, "connection_type": ctype})
        if comp and comp.get("purl"):
            out.append({"resource_id": rid, "ext_id": ext_id, "kind": kind,
                        "purl": comp["purl"], "name": comp["name"],
                        "version": comp["version"],
                        "inferred": "evidence" in comp})
    return out


def enrich_osv(conn, tenant_id: str, connection_id: str, scan_id: str) -> dict:
    """The post-persist hook: query OSV for this connection's components, file findings.

    Runs in its own transaction (the caller commits/rolls back), and everything it writes is a
    finding plus its citations — the same contract the scan spine keeps.
    """
    stats = {"enabled": True, "components": 0, "queried": 0, "advisories": 0,
             "skipped_curated": 0, "findings": 0}
    if osv_disabled():
        # A recorded operator choice, not a silent pass: the scan's stats carry enabled=False,
        # and an air-gapped estate does not accumulate an unclosable "feed unreachable" gap.
        stats["enabled"] = False
        return stats

    with conn.cursor() as cur:
        comps = _components(cur, tenant_id, connection_id)
        stats["components"] = len(comps)
        if not comps:
            return stats

        supps = _active_suppressions(cur, tenant_id)

        try:
            results = _query_batch([c["purl"] for c in comps])
        except Exception as e:
            # The feed could not be consulted at all. One honest gap for the connection —
            # NOT one per component — naming everything that went unchecked.
            _write_finding(
                cur, tenant_id, scan_id, connection_id,
                comps[0]["resource_id"], "osv-feed", RULE_GAP, RULE_GAP_TITLE,
                severity="info",
                observation=(
                    f"{len(comps)} component(s) with OSV-queryable identifiers "
                    f"({', '.join(c['purl'] for c in comps[:10])}"
                    f"{', …' if len(comps) > 10 else ''}) could not be checked against the "
                    f"OSV vulnerability feed: {type(e).__name__}: {e}"),
                detail=("An unqueried feed is not a clean feed. This finding records that the "
                        "check did not happen; it makes no claim about the components."),
                remediation=("Allow the engine egress to api.osv.dev, or set "
                             "VECTASEC_OSV_DISABLED=1 to record that this estate deliberately "
                             "runs without live feed enrichment."),
                assessment="not_assessable",
                reason=f"OSV querybatch failed: {type(e).__name__}",
                extra={"purls": [c["purl"] for c in comps]},
                supps=supps,
            )
            stats["feed_error"] = f"{type(e).__name__}: {e}"
            stats["findings"] = 1
            return stats

        stats["queried"] = len(comps)
        curated = _curated_ids()
        budget = MAX_VULN_DETAILS

        for comp, vulns in zip(comps, results):
            ids = [v.get("id") for v in vulns if v.get("id")]
            keep, skipped = [], 0
            details: dict[str, dict] = {}
            for vid in ids:
                # Fetch detail first when budget allows: aliases live in the detail record,
                # and the curated-overlap check needs them (an OSV id like GHSA-… only maps
                # to its CVE alias there).
                d = None
                if budget > 0:
                    try:
                        d = _osv_get(f"{OSV_API}/vulns/{vid}")
                        budget -= 1
                    except Exception:
                        d = None  # cited by id below; the batch already proved it affects us
                aliases = set((d or {}).get("aliases") or []) | {vid}
                overlap = [a for a in aliases
                           if curated.get(a) == comp["name"].lower()]
                if overlap:
                    skipped += 1
                    continue
                keep.append(vid)
                if d is not None:
                    details[vid] = d

            stats["advisories"] += len(keep)
            stats["skipped_curated"] += skipped
            if not keep:
                continue  # feed answered; everything it returned is already filed elsewhere

            severity = "info"
            observations = []
            for vid in keep:
                d = details.get(vid)
                inferred_clause = (
                    " (version inferred from the service's advertised protocol capability "
                    "matrix, not read off the wire)" if comp["inferred"] else "")
                if d is None:
                    band, derived = "medium", "default (detail not fetched)"
                    observations.append((
                        f"the OSV feed reports advisory {vid} as affecting {comp['purl']}"
                        f"{inferred_clause}; advisory detail was not fetched "
                        f"(per-run budget of {MAX_VULN_DETAILS} detail reads exhausted or "
                        f"the read failed) — see https://osv.dev/vulnerability/{vid}",
                        {"osv_id": vid, "detail_fetched": False,
                         "severity_band": band, "cvss_score": None}))
                else:
                    band, derived, score = advisory_severity(d)
                    fixed = _fixed_versions(d)
                    summary = d.get("summary") or d.get("details", "")[:160] or vid
                    observations.append((
                        f"{comp['name']} reports version {comp['version']!r}"
                        f"{inferred_clause}, which the OSV feed reports as affected by "
                        f"{vid} — {summary} — severity {band} ({derived})"
                        + (f", fixed in {', '.join(fixed[:5])}" if fixed else "")
                        + f"; see https://osv.dev/vulnerability/{vid}",
                        {"osv_id": vid, "aliases": sorted(set(d.get("aliases") or [])),
                         "severity_derived": derived, "severity_band": band,
                         "cvss_score": score, "summary": summary[:160],
                         "fixed": fixed[:10], "detail_fetched": True}))
                if _RANK.index(band) > _RANK.index(severity):
                    severity = band

            unfetched = sum(1 for v in observations if not v[1]["detail_fetched"])
            _write_finding(
                cur, tenant_id, scan_id, connection_id,
                comp["resource_id"], comp["ext_id"], RULE_VULN, RULE_VULN_TITLE,
                severity=severity,
                observation=None,  # per-advisory observations below
                observations=observations,
                detail=(
                    f"purl={comp['purl']} advisories={len(keep)}"
                    + (f" (detail fetched for {len(keep) - unfetched}; the remaining "
                       f"{unfetched} are cited by id only — per-run detail budget is "
                       f"{MAX_VULN_DETAILS})" if unfetched else "")
                    + (" version_inferred=true" if comp["inferred"] else "")
                    + (f" curated_overlap_skipped={skipped}" if skipped else "")),
                remediation=(
                    f"Review the cited OSV advisories for {comp['name']} "
                    f"{comp['version']} and upgrade to a release that clears them. Each "
                    "observation links the advisory record with its fixed versions."),
                assessment="assessed",
                reason=None,
                extra={"purl": comp["purl"], "version": comp["version"],
                       "version_inferred": comp["inferred"]},
                supps=supps, kind=comp["kind"],
            )
            stats["findings"] += 1
    return stats


def _query_batch(purls: list[str]) -> list[list[dict]]:
    """querybatch over all purls, chunked. Returns one vuln list per purl, positionally.

    The version travels INSIDE the purl, so OSV answers affected-or-not for that exact
    version — there is no local range matching to get wrong."""
    out: list[list[dict]] = []
    for i in range(0, len(purls), BATCH_CHUNK):
        chunk = purls[i:i + BATCH_CHUNK]
        resp = _osv_post(f"{OSV_API}/querybatch",
                         {"queries": [{"package": {"purl": p}} for p in chunk]})
        results = resp.get("results") or []
        if len(results) != len(chunk):
            # Positional alignment is the whole contract; a short answer silently shifted
            # onto the wrong components would attribute advisories to the wrong systems.
            raise ValueError(
                f"OSV querybatch returned {len(results)} results for {len(chunk)} queries")
        out.extend([r.get("vulns") or [] for r in results])
    return out


def _write_finding(cur, tenant_id, scan_id, connection_id, resource_id, ext_id,
                   rule_id, title, *, severity, observation, detail, remediation,
                   assessment, reason, extra, supps=None, kind="component",
                   observations=None):
    """One finding plus its citation(s), in the caller's transaction — the same shape as
    runtime_evidence._write_finding, parameterized by rule. Suppressions are evaluated at
    write time AND re-evaluated in ON CONFLICT, because status written on INSERT only runs
    once in a finding's life (the lesson _persist_scan documents)."""
    suppressed = _is_suppressed(supps or [], rule_id,
                                SimpleNamespace(ext_id=ext_id or "connection", kind=kind))
    fp = fingerprint(tenant_id, str(connection_id), rule_id, ext_id or "connection")
    cur.execute(
        """insert into findings
             (tenant_id, scan_id, resource_id, rule_id, fingerprint, title, severity,
              status, remediation, detail, assessment, assessment_reason)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           on conflict (tenant_id, fingerprint) do update
              set last_seen = now(), scan_id = excluded.scan_id,
                  severity = excluded.severity, detail = excluded.detail,
                  remediation = excluded.remediation,
                  assessment = excluded.assessment,
                  assessment_reason = excluded.assessment_reason,
                  status = case
                    when excluded.status = 'suppressed' then 'suppressed'
                    when findings.status = 'suppressed' then 'open'
                    else findings.status
                  end
           returning id""",
        (tenant_id, scan_id, resource_id, rule_id, fp, title, severity,
         "suppressed" if suppressed else "open",
         remediation, detail, assessment, reason),
    )
    finding_id = cur.fetchone()[0]
    claims = observations if observations is not None else [(observation, {})]
    for claim, per_obs in claims:
        cur.execute(
            """insert into observations (tenant_id, finding_id, resource_id, claim, source_ref)
               values (%s,%s,%s,%s,%s)""",
            (tenant_id, finding_id, resource_id, claim,
             json.dumps({"rule_id": rule_id, "resource": ext_id, "scan_id": str(scan_id),
                         "evidence_type": "osv_feed", **(extra or {}), **per_obs})),
        )
