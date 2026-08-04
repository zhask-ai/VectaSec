"""NVD enrichment — the CPE half of the live vulnerability feed, run after a scan persists.

`osv.py` closed the loop for every component carrying a bitnami purl. That is most of the
estate but nowhere near all of it: the Bitnami OSV ecosystem does not index Kong, Pulsar,
Solace or IBM MQ, so `sbom.py` emitted a verified CPE for those components and then nothing
ever asked a feed about it. A component whose only identifier nobody queries is, in the
findings queue, byte-identical to a component that was checked and came back clean — which is
precisely the failure mode the CPE table in sbom.py was hand-verified to avoid. This module
asks NVD, so the two identifiers sbom.py deliberately emits both reach a feed.

Scope is narrow on purpose. By default only components with NO purl are queried, because the
OSV path already answered for the rest and NVD's anonymous rate limit is five requests per
thirty seconds — re-asking about components OSV covered is how a scan gets throttled into the
very coverage gap this module exists to close. `VECTASEC_NVD_ALL=1` widens it to every
CPE-bearing component for operators who want both feeds' opinions on everything.

Honesty discipline, the same as osv.py:
  * The feed being UNREACHABLE, or a component falling past the per-run budget, files a
    not-assessable coverage gap naming every CPE that went unchecked — never silence.
  * The feed being DISABLED (`VECTASEC_NVD_DISABLED`, air-gapped on-prem) is a recorded
    operator choice: stats say so, no gap finding is filed, no network call is attempted.
  * A CVE NVD marks `vulnStatus: "Rejected"` is skipped and counted. Filing a withdrawn CVE
    as a finding is a false positive with a paper trail behind it.
  * Severity comes from the band edges osv.py owns (`_CVSS_BANDS`, imported rather than
    copied) so the two feeds can never drift into disagreeing about what "high" means. A CVE
    NVD publishes with no metrics at all is filed at medium and SAYS the feed stated no score.
  * A CVE already filed against this resource by the curated pack or by the OSV feed is
    skipped: the same defect on one resource under two rule ids is a duplicate row, not a
    second opinion.
"""
from __future__ import annotations

import json
import os
import urllib.parse
from types import SimpleNamespace

from .osv import _CVSS_BANDS, _RANK, _curated_ids
from .sbom import component_for, cpes_for
from .scan import _active_suppressions, _is_suppressed, fingerprint

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail"

# Hard per-run cap on REQUESTS. Exceeding it is STATED (a not-assessable finding naming the
# leftovers), never silently truncated — at six seconds a request an unbounded estate would
# otherwise turn one scan's enrichment into an hour of blocking sleeps.
#
# Counted in requests rather than components because a component can carry several CPEs: with a
# component cap of 25, RabbitMQ's four aliases authorised 100 requests and ~10 minutes of
# blocking sleep, which alone exceeds the worker's 600s visibility timeout and gets the job
# redelivered while it is still running.
MAX_REQUESTS = 25
_TIMEOUT = 30.0
# NVD publishes 5 requests / 30s anonymous and 50 / 30s with a key. These are the documented
# floors plus a margin; going under them earns a 403 that looks exactly like egress being
# blocked, which would file a coverage gap for a problem that is really our own impatience.
_PAUSE_ANON = 6.0
_PAUSE_KEYED = 0.6

RULE_VULN = "SUPPLY.NVD.KNOWN_VULNERABILITY"
RULE_VULN_TITLE = "Running component version has a published NVD CVE"
RULE_GAP = "SUPPLY.NVD.NOT_ASSESSABLE"
RULE_GAP_TITLE = "NVD vulnerability feed could not be consulted"

# NVD carries several CVSS generations per CVE. Newest first: a v2 score on a modern CVE is a
# legacy artifact, and letting it win would band a critical defect as medium.
_METRIC_KEYS = (("cvssMetricV31", "cvss_v3.1"),
                ("cvssMetricV30", "cvss_v3.0"),
                ("cvssMetricV2", "cvss_v2"))


def nvd_disabled() -> bool:
    """Air-gapped opt-out. Checked at call time (not import) for the same reason config.py
    reads os.environ on every access — entry points load .env after import."""
    return bool(os.environ.get("VECTASEC_NVD_DISABLED", "").strip())


def nvd_all() -> bool:
    """Belt-and-braces mode: query NVD for every CPE-bearing component, not just the ones OSV
    could not see. Off by default — see the module docstring on rate limits."""
    return bool(os.environ.get("VECTASEC_NVD_ALL", "").strip())


def _api_key() -> str:
    return os.environ.get("NVD_API_KEY", "").strip()


# ── HTTP / clock seams (monkeypatched in tests, same pattern as osv.py's _osv_get) ──
def _nvd_get(url: str, headers: dict) -> dict:
    import httpx
    r = httpx.get(url, headers=headers, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _sleep(seconds: float) -> None:
    import time
    time.sleep(seconds)


def cve_severity(cve: dict) -> tuple[str, str, float | None, str | None]:
    """(house band, how it was derived, numeric base score or None, which metric block).

    Unlike OSV — which hands over a CVSS vector and leaves the arithmetic to the consumer —
    NVD publishes the base score itself, so there is nothing to compute and nothing to get
    wrong. The band edges come from osv.py so a score of 7.4 means "high" in both feeds.
    A CVE with no metrics block at all gets an explicit stated-by-nobody default, recorded in
    the derivation string, because a missing score is not a low score.
    """
    metrics = cve.get("metrics") or {}
    for key, label in _METRIC_KEYS:
        for entry in metrics.get(key) or []:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                continue
            score = float(score)
            band = "info"
            for floor, name in _CVSS_BANDS:
                if score >= floor:
                    band = name
                    break
            return band, f"{label} {score}", score, key
    return "medium", "default (NVD published no CVSS score)", None, None


def _description(cve: dict) -> str:
    """The English description NVD publishes, or the CVE id when it publishes none. Never a
    summary we composed — every word in an observation has to be traceable to the response."""
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
            return str(d["value"])
    return str(cve.get("id") or "")


def _is_rejected(cve: dict) -> bool:
    return str(cve.get("vulnStatus") or "").strip().lower() == "rejected"


def _is_disputed(cve: dict) -> bool:
    """NVD tags contested records rather than withdrawing them. A disputed CVE is still a real
    published record so it is still filed — but the claim says so, because presenting a
    contested defect as settled fact is the same overstatement as inventing a score."""
    for tag in cve.get("cveTags") or []:
        if isinstance(tag, dict) and "disputed" in (tag.get("tags") or []):
            return True
    return False


def _affected_ceilings(cve: dict, cpe: str) -> list[str]:
    """`versionEndExcluding` values from the configuration nodes that match OUR vendor:product.

    This is the closest thing NVD gives to a fixed-in version, and it is only honest with the
    vendor:product filter: a single CVE's configuration can list a dozen unrelated products,
    and lifting a ceiling off the wrong one would hand an operator an upgrade target for
    software they do not run.
    """
    base = ":".join(cpe.split(":")[:5])
    out = []
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                criteria = str(match.get("criteria") or "")
                if ":".join(criteria.split(":")[:5]) != base:
                    continue
                end = match.get("versionEndExcluding")
                if end:
                    out.append(str(end))
    return sorted(set(out))


def _components(cur, tenant_id: str, connection_id: str) -> list[dict]:
    """CPE-bearing components for this connection's live resources.

    Same projection as osv.py's query — the SBOM builder reads a handful of raw keys, so only
    those keys leave the database — but selected on the other identifier axis. `purl` travels
    with each component because whether OSV could see it is what decides, below, if NVD is
    asked about it at all.
    """
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
        if comp and comp.get("cpe"):
            out.append({"resource_id": rid, "ext_id": ext_id, "kind": kind,
                        "cpe": comp["cpe"], "purl": comp.get("purl"),
                        # NVD files each CVE under whichever vendor string was current when it
                        # was published and never back-fills a rename, so RabbitMQ's advisories
                        # are split across Pivotal, VMware and Broadcom. Querying only the
                        # primary loses the older two thirds — silently, as an empty result.
                        "cpes": cpes_for(comp["name"], comp["version"]) or [comp["cpe"]],
                        "name": comp["name"], "version": comp["version"],
                        "inferred": "evidence" in comp})
    return out


def _osv_filed_ids(cur, tenant_id: str, connection_id: str) -> dict[str, set[str]]:
    """resource id -> every CVE id the OSV feed has already filed against that resource.

    Keyed per RESOURCE, not per connection: an advisory filed against the Redis node says
    nothing about the Kong node next to it, and a connection-wide set would silently drop a
    real Kong CVE that happened to share an id. `aliases` matters as much as `osv_id` — OSV
    files GHSA ids, so the CVE number NVD returns only meets its OSV twin in the alias list.
    Resolved findings are excluded: a human marking the OSV row resolved is a statement that
    the problem is gone, which is not a live duplicate for this run to defer to.
    """
    cur.execute(
        """select f.resource_id, o.source_ref
             from findings f
             join observations o on o.finding_id = f.id
             join resources r on r.id = f.resource_id
            where f.tenant_id = %s and r.connection_id = %s
              and f.rule_id = %s and f.status != 'resolved'""",
        (tenant_id, connection_id, "SUPPLY.OSV.KNOWN_VULNERABILITY"),
    )
    filed: dict[str, set[str]] = {}
    for resource_id, source_ref in cur.fetchall():
        if isinstance(source_ref, str):
            try:
                source_ref = json.loads(source_ref)
            except ValueError:
                continue
        if not isinstance(source_ref, dict):
            continue
        ids = {str(a) for a in (source_ref.get("aliases") or []) if a}
        if source_ref.get("osv_id"):
            ids.add(str(source_ref["osv_id"]))
        if ids:
            filed.setdefault(str(resource_id), set()).update(ids)
    return filed


def _query_cpe(cpe: str, headers: dict) -> tuple[list[dict], int]:
    """(CVE records, NVD's own totalResults) for one exact CPE.

    `cpeName` is exact-match INCLUDING the version, so NVD does the range matching server-side
    and answers affected-or-not for the version we actually read — the same property that makes
    the purl query in osv.py honest. There is no local range comparison here to get wrong.
    """
    url = f"{NVD_API}?cpeName={urllib.parse.quote(cpe, safe='')}"
    resp = _nvd_get(url, headers)
    items = [i for i in (resp.get("vulnerabilities") or []) if isinstance(i, dict)]
    total = resp.get("totalResults")
    return ([i.get("cve") or {} for i in items],
            total if isinstance(total, int) else len(items))


def enrich_nvd(conn, tenant_id: str, connection_id: str, scan_id: str) -> dict:
    """The post-persist hook: query NVD for this connection's CPE-only components, file findings.

    Runs in its own transaction (the caller commits/rolls back), and everything it writes is a
    finding plus its citations — the same contract the scan spine keeps.
    """
    all_mode = nvd_all()
    stats = {"enabled": True,
             "mode": "all_cpe_components" if all_mode else "components_without_purl",
             "components": 0, "queried": 0, "cves": 0, "skipped_curated": 0,
             "skipped_osv": 0, "skipped_rejected": 0, "unchecked": 0, "findings": 0}
    if nvd_disabled():
        # A recorded operator choice, not a silent pass: stats carry enabled=False, and an
        # air-gapped estate does not accumulate an unclosable "feed unreachable" gap.
        stats["enabled"] = False
        return stats

    with conn.cursor() as cur:
        candidates = _components(cur, tenant_id, connection_id)
        # The default narrow set. A component OSV already answered for does not need a second
        # feed's opinion badly enough to spend one of five requests per thirty seconds on it.
        comps = [c for c in candidates if all_mode or not c["purl"]]
        stats["components"] = len(comps)
        if not comps:
            return stats

        supps = _active_suppressions(cur, tenant_id)
        curated = _curated_ids()
        osv_filed = _osv_filed_ids(cur, tenant_id, connection_id)

        key = _api_key()
        headers = {"apiKey": key} if key else {}
        pause = _PAUSE_KEYED if key else _PAUSE_ANON

        # The budget counts REQUESTS, not components. Each component now issues one request per
        # alias CPE (RabbitMQ has four), so a component budget of 25 authorised up to 100
        # requests — 99 pauses of six seconds, ~10 minutes of blocking sleep, which alone
        # exceeds the worker's visibility timeout and makes the queue redeliver the job while
        # it is still running.
        queryable, deferred, spent = [], [], 0
        for comp in comps:
            need = len(comp["cpes"])
            if spent + need <= MAX_REQUESTS:
                queryable.append(comp)
                spent += need
            else:
                deferred.append(comp)
        unchecked = [(c, "budget",
                      (f"the per-run budget of {MAX_REQUESTS} NVD requests was already "
                       f"spent on other components")) for c in deferred]
        stats["requests_planned"] = spent

        first_query = True
        for comp in queryable:
            # Every CPE this component has ever been filed under, deduped by CVE id. A failure
            # on ANY of them makes the component unchecked rather than partially checked: half
            # a vendor's history is not a coverage claim we can stand behind.
            #
            # The CPE that MATCHED travels with the CVE. Citing `comp["cpe"]` for all of them
            # named an identifier that was never queried for the alias-matched ones — which is
            # every advisory filed under a vendor's older name, i.e. exactly what the alias
            # table exists to find — and produced a `query_url` that returns nothing, so an
            # operator checking our evidence would conclude the finding was fabricated.
            cves, failure, total = [], None, 0
            seen_ids: set[str] = set()
            for cpe in comp["cpes"]:
                if not first_query:
                    _sleep(pause)
                first_query = False
                try:
                    got, reported = _query_cpe(cpe, headers)
                except Exception as e:   # noqa: BLE001 - any feed failure is a coverage gap
                    # Narrowing this would let an unanticipated error leave the run as silence,
                    # and silence is byte-identical to "checked, clean".
                    failure = f"{type(e).__name__}: {e}"
                    break
                stats["requests"] = stats.get("requests", 0) + 1
                total = max(total, reported)   # per-query total; summing double-counts a CVE
                for cve in got:                # that two aliases both return
                    cid = str(cve.get("id") or "")
                    if cid and cid not in seen_ids:
                        seen_ids.add(cid)
                        cves.append((cpe, cve))
            if failure is not None:
                unchecked.append((comp, "feed_error", failure))
                stats.setdefault("feed_error", failure)
                continue
            stats["queried"] += 1

            keep = []
            for matched_cpe, cve in cves:
                cid = str(cve.get("id") or "")
                if not cid:
                    continue
                if _is_rejected(cve):
                    stats["skipped_rejected"] += 1
                    continue
                if curated.get(cid) == comp["name"].lower():
                    stats["skipped_curated"] += 1
                    continue
                if cid in osv_filed.get(str(comp["resource_id"]), set()):
                    stats["skipped_osv"] += 1
                    continue
                keep.append((matched_cpe, cve))

            stats["cves"] += len(keep)
            if not keep:
                continue  # the feed answered; everything it returned is already filed elsewhere

            severity = "info"
            observations = []
            inferred_clause = (
                " (version inferred from the service's advertised protocol capability matrix, "
                "not read off the wire)" if comp["inferred"] else "")
            for matched_cpe, cve in keep:
                cid = str(cve["id"])
                band, derived, score, metric = cve_severity(cve)
                # The CPE THIS CVE came back from — not the component's primary. The ceiling
                # filter keys on vendor:product, so using the primary dropped the fixed-in
                # version for precisely the vendor-renamed advisories.
                ceilings = _affected_ceilings(cve, matched_cpe)
                disputed = _is_disputed(cve)
                observations.append((
                    f"{comp['name']} reports version {comp['version']!r}{inferred_clause}, and "
                    f"NVD returns {cid} for the exact CPE {matched_cpe} — "
                    f"{_description(cve)[:240]} — severity {band} ({derived})"
                    + (f"; NVD's matching configuration marks versions below "
                       f"{', '.join(ceilings[:5])} as affected" if ceilings else "")
                    + ("; NVD records this CVE as DISPUTED by at least one source"
                       if disputed else "")
                    + f"; see {NVD_CVE_URL}/{cid}",
                    {"cve_id": cid, "severity_band": band, "severity_derived": derived,
                     "cvss_score": score, "cvss_metric": metric,
                     "nvd_vuln_status": cve.get("vulnStatus"),
                     "disputed": disputed,
                     # The SBOM's vulnerabilities[] section is built from these citations, not
                     # from a second feed round-trip, so everything it renders lives here.
                     "summary": _description(cve)[:160],
                     "version_end_excluding": ceilings[:10],
                     "matched_cpe": matched_cpe,
                     "query_url": f"{NVD_API}?cpeName={urllib.parse.quote(matched_cpe, safe='')}",
                     "url": f"{NVD_CVE_URL}/{cid}"}))
                if _RANK.index(band) > _RANK.index(severity):
                    severity = band

            no_score = sum(1 for _, ref in observations if ref["cvss_score"] is None)
            _write_finding(
                cur, tenant_id, scan_id, connection_id,
                comp["resource_id"], comp["ext_id"], RULE_VULN, RULE_VULN_TITLE,
                severity=severity,
                observation=None,  # per-CVE observations below
                observations=observations,
                detail=(
                    f"cpe={comp['cpe']} cves={len(keep)}"
                    + (" version_inferred=true" if comp["inferred"] else "")
                    + (f" no_cvss_score={no_score} (filed at medium; NVD published no score "
                       f"for those)" if no_score else "")
                    + (f" nvd_reported_total={total} (more than this page returned; the "
                       f"citations below are the records NVD sent)"
                       if total > len(cves) else "")),
                remediation=(
                    f"Review the cited NVD records for {comp['name']} {comp['version']} and "
                    f"upgrade to a release that clears them. Each observation links the NVD "
                    f"record; where NVD's configuration bounds the affected range, the "
                    f"version it excludes is named."),
                assessment="assessed",
                reason=None,
                extra={"cpe": comp["cpe"], "version": comp["version"],
                       "version_inferred": comp["inferred"],
                       "query_url": f"{NVD_API}?cpeName={urllib.parse.quote(comp['cpe'], safe='')}"},
                supps=supps, kind=comp["kind"],
            )
            stats["findings"] += 1

        stats["unchecked"] = len(unchecked)
        if unchecked:
            _write_gap(cur, tenant_id, scan_id, connection_id, unchecked, supps)
            stats["findings"] += 1
    return stats


def _write_gap(cur, tenant_id, scan_id, connection_id, unchecked, supps) -> None:
    """ONE not-assessable finding for the connection naming every CPE that went unchecked.

    Not one per component: the gap is a property of the run, and twenty rows saying the same
    thing would bury the real findings next to them. One observation per unchecked component
    still names each CPE and the specific reason it was skipped, because "some components were
    not checked" is not an actionable statement about any of them.
    """
    codes = sorted({code for _, code, _ in unchecked})
    observations = [(
        (f"{comp['name']} {comp['version']} ({comp['cpe']}) was not checked against the NVD "
         f"vulnerability feed: {why}"),
        {"cpe": comp["cpe"], "resource": comp["ext_id"], "skip_reason": code},
    ) for comp, code, why in unchecked]
    _write_finding(
        cur, tenant_id, scan_id, connection_id,
        unchecked[0][0]["resource_id"], "nvd-feed", RULE_GAP, RULE_GAP_TITLE,
        severity="info",
        observation=None,
        observations=observations,
        detail=(f"{len(unchecked)} component(s) with NVD-queryable CPEs went unchecked: "
                + ", ".join(comp["cpe"] for comp, _, _ in unchecked)),
        remediation=(
            ("Allow the engine egress to services.nvd.nist.gov, or set "
             "VECTASEC_NVD_DISABLED=1 to record that this estate deliberately runs without "
             "live feed enrichment. " if "feed_error" in codes else "")
            + (f"Set NVD_API_KEY to lift the anonymous rate limit, or raise MAX_REQUESTS "
               f"(currently {MAX_REQUESTS}) so a run can cover the whole estate. "
               if "budget" in codes else "")
            + "Until then these components carry no NVD verdict either way."),
        assessment="not_assessable",
        reason=f"NVD not consulted for {len(unchecked)} component(s): {', '.join(codes)}",
        extra={"cpes": [comp["cpe"] for comp, _, _ in unchecked]},
        supps=supps,
    )


def _write_finding(cur, tenant_id, scan_id, connection_id, resource_id, ext_id,
                   rule_id, title, *, severity, observation, detail, remediation,
                   assessment, reason, extra, supps=None, kind="component",
                   observations=None):
    """One finding plus its citation(s), in the caller's transaction — the same shape as
    osv._write_finding, parameterized by rule. Suppressions are evaluated at write time AND
    re-evaluated in ON CONFLICT, because status written on INSERT only runs once in a
    finding's life (the lesson _persist_scan documents)."""
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
                    when excluded.status = 'suppressed'
                          and findings.status in ('open','suppressed') then 'suppressed'
                    when findings.status = 'suppressed'
                          and excluded.status <> 'suppressed' then 'open'
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
                         "evidence_type": "nvd_feed", **(extra or {}), **per_obs})),
        )
