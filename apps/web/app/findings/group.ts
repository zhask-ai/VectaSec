import {
  SEVERITIES,
  SEVERITY_RANK,
  UI_STATUS_OF,
  type Assessment,
  type FindingStatus,
  type Severity,
  type UiStatus,
} from '@/lib/types';
import { UI_STATUSES, systemOf, type FindingFilters } from './query';

/* The list DTOs and the pure transformations over them.
 *
 * Separated from data.ts (which is `server-only`) because none of this touches Postgres: it is
 * the grouping, the sort and the facet arithmetic — the product's actual anti-fatigue logic —
 * and it is worth being able to exercise without a database or a request. data.ts fetches;
 * this decides what the fetch means.
 */

export type ResourceRef = {
  id: string;
  kind: string;
  name: string;
  namespace: string | null;
};

export type FindingRow = {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  uiStatus: UiStatus;
  resource: ResourceRef | null;
  /** Number of observations backing this finding. Zero is meaningful and must be visible: a
   * finding with no evidence is a rumour, and the AI layer refuses to triage it (api/main.py
   * returns 422). Surfacing the 0 is how that becomes explicable instead of mysterious. */
  evidenceCount: number;
  /** 'not_assessable' = a coverage gap. Rendered with NotAssessedBadge, never a severity mark. */
  assessment: Assessment;
  assessmentReason: string | null;
  lastSeenLabel: string;
  lastSeenIso: string;
};

/** Occurrences of one rule_id across many assets, collapsed to one decision.
 *
 * This is THE anti-fatigue lever: a wildcard ACL on 200 topics is one problem with one answer,
 * not 200 problems. Note this is GROUPING (rule_id across assets), which is a different concept
 * from DEDUP (fingerprint across scans — already done in the DB, one row per issue per asset). */
export type RuleGroup = {
  ruleId: string;
  title: string;
  /** The WORST severity in the group, not "the rule's severity". A detector may override
   * severity per hit (`Hit.severity or Detector.severity` in scan.py), so occurrences of one
   * rule genuinely can differ — collapsing them under an assumed-uniform severity would hide
   * the critical one inside a group labelled "medium". */
  severity: Severity;
  mixedSeverity: boolean;
  count: number;
  evidenceCount: number;
  /** How many occurrences in this group are coverage gaps (not_assessable). */
  notAssessableCount: number;
  /** Every occurrence is a coverage gap — the whole group is "we could not check", so the header
   * shows NotAssessedBadge instead of a severity mark. A group's stored severity still drives its
   * SORT position (a not-assessable gap on a nominally-critical rule deserves attention), but the
   * visual must not read as a real critical. */
  allNotAssessable: boolean;
  statusCounts: { status: UiStatus; count: number }[];
  lastSeenLabel: string;
  lastSeenIso: string;
  findings: FindingRow[];
};

export type Facets = {
  severity: { key: Severity; count: number }[];
  status: { key: UiStatus; count: number }[];
  systems: { key: string; count: number }[];
};

/** Severity is stored as `text`, not an enum (see migration 001), so Postgres would sort it
 * alphabetically — critical, high, info, low, medium. Wrong, and wrong in the direction that
 * puts `info` above `low`. So ordering is: last_seen DESC in the DB, then a STABLE sort by
 * severity rank here. Array.prototype.sort is stable per spec (ES2019+), so the DB's recency
 * order survives inside each severity band and the result is "severity, then last_seen"
 * exactly — without needing Postgres to know how to rank a severity.
 *
 * That stability is load-bearing, not incidental: swap this for an unstable sort and the
 * ordering silently degrades to "severity, then arbitrary".
 *
 * The DB-side fix is an enum or a sort_order column. That is a migration, and migrations are
 * not this module's to write. */
export function bySeverityThenRecency<T extends { severity: Severity }>(rows: T[]): T[] {
  return [...rows].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

/** Collapse rows into one group per rule_id.
 *
 * `rows` MUST arrive in last_seen-descending order (data.ts orders the query that way). Three
 * things depend on it and none of them re-sort: a group's `lastSeen` is taken from the first
 * occurrence it saw, and the group ORDER within a severity band comes from Map insertion order
 * — which is the order each rule first appeared, i.e. its most recent occurrence. Feed this
 * unordered rows and it still returns correct counts, but "most recent" quietly becomes
 * "whichever row happened to be first". */
export function groupByRule(rows: FindingRow[]): RuleGroup[] {
  const byRule = new Map<string, FindingRow[]>();
  for (const row of rows) {
    const bucket = byRule.get(row.ruleId);
    if (bucket) bucket.push(row);
    else byRule.set(row.ruleId, [row]);
  }

  const groups: RuleGroup[] = [];
  for (const [ruleId, findings] of byRule) {
    const ranked = bySeverityThenRecency(findings);
    const worst = ranked[0].severity;

    const statusTally = new Map<UiStatus, number>();
    for (const f of findings) statusTally.set(f.uiStatus, (statusTally.get(f.uiStatus) ?? 0) + 1);

    // findings[0], not ranked[0]: the newest occurrence, not the worst one. The group header
    // answers "when did we last see this rule fire", which is a question about time.
    const newest = findings[0];

    const notAssessableCount = findings.reduce((n, f) => n + (f.assessment === 'not_assessable' ? 1 : 0), 0);

    groups.push({
      ruleId,
      title: ranked[0].title,
      severity: worst,
      mixedSeverity: findings.some((f) => f.severity !== worst),
      count: findings.length,
      evidenceCount: findings.reduce((n, f) => n + f.evidenceCount, 0),
      notAssessableCount,
      allNotAssessable: notAssessableCount === findings.length,
      // Iterated in UI_STATUSES order so the pills read open -> muted regardless of which
      // status happened to be tallied first.
      statusCounts: UI_STATUSES.filter((s) => statusTally.has(s)).map((s) => ({
        status: s,
        count: statusTally.get(s)!,
      })),
      lastSeenLabel: newest.lastSeenLabel,
      lastSeenIso: newest.lastSeenIso,
      findings: ranked,
    });
  }

  return bySeverityThenRecency(groups);
}

/** One row of the `findings_facets` view: a (rule, severity, status) bucket and how many
 * findings are in it. NOT one row per finding — see `n`. */
export type FacetRow = { severity: string; status: string; rule_id: string; n: number };

/** Facet counts.
 *
 * Each facet is counted with every OTHER facet applied but not its own — the standard faceted
 * semantics, and the only ones that are useful: a severity list where selecting "critical"
 * zeroes every other severity tells you nothing about what you would get by also selecting
 * "high". A facet without a count forces a click to learn nothing, so these are always shown.
 *
 * `rows` are PRE-AGGREGATED buckets from the `findings_facets` view — NOT one row per finding —
 * so every tally sums `r.n` rather than counting rows. That is what makes these counts exact:
 * an unbounded select of raw findings is truncated at PostgREST's Max Rows, which would
 * undercount every facet while the `count: 'exact'` total rendered beside them (filters.tsx
 * "{total} findings match") is not truncated. The bucket count is bounded by
 * rules x severities x statuses, so it cannot reach the cap. Count rows here instead of summing
 * `n` and the cap comes straight back.
 */
export function buildFacets(rows: FacetRow[], f: FindingFilters): Facets {
  const matchSeverity = (r: FacetRow) =>
    f.severity.length === 0 || f.severity.includes(r.severity as Severity);
  const matchStatus = (r: FacetRow) =>
    f.status.length === 0 || f.status.includes(UI_STATUS_OF[r.status as FindingStatus] ?? 'open');
  const matchSystem = (r: FacetRow) => !f.system || systemOf(r.rule_id) === f.system;
  const matchRule = (r: FacetRow) => !f.rule || r.rule_id.startsWith(f.rule);

  const tally = <K extends string>(keep: (r: FacetRow) => boolean, key: (r: FacetRow) => K): Map<K, number> => {
    const m = new Map<K, number>();
    for (const r of rows) {
      if (!keep(r)) continue;
      const k = key(r);
      m.set(k, (m.get(k) ?? 0) + r.n);
    }
    return m;
  };

  const sevCounts = tally((r) => matchStatus(r) && matchSystem(r) && matchRule(r), (r) => r.severity as Severity);
  const statusCounts = tally(
    (r) => matchSeverity(r) && matchSystem(r) && matchRule(r),
    (r) => UI_STATUS_OF[r.status as FindingStatus] ?? 'open',
  );
  const systemCounts = tally((r) => matchSeverity(r) && matchStatus(r) && matchRule(r), (r) => systemOf(r.rule_id));

  return {
    // Every severity and status is listed even at zero: a facet that disappears when it empties
    // makes the user wonder whether the filter or the data changed.
    severity: SEVERITIES.map((key) => ({ key, count: sevCounts.get(key) ?? 0 })),
    status: UI_STATUSES.map((key) => ({ key, count: statusCounts.get(key) ?? 0 })),
    systems: [...systemCounts.entries()]
      .map(([key, count]) => ({ key, count }))
      .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key)),
  };
}
