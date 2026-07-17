import 'server-only';

import { cache } from 'react';

import { createClient } from '@/lib/supabase/server';
import { UI_STATUS_OF, type Assessment, type FindingStatus, type Severity, type UiStatus } from '@/lib/types';
import { ASSESSMENTS } from './assessment';
import { absolute, relative } from './format';
import {
  buildFacets,
  groupByRule,
  type AssessmentFacet,
  type FacetRow,
  type Facets,
  type FindingRow,
  type ResourceRef,
  type RuleGroup,
} from './group';
import { type FindingFilters } from './query';

// Re-exported so consumers have one import site for the DTOs: they are this layer's contract,
// even though the shapes and the grouping over them live next door in group.ts.
export type { AssessmentFacet, Facets, FindingRow, ResourceRef, RuleGroup } from './group';

/* Findings Data Access Layer.
 *
 * `server-only`: importing this from a client component is a BUILD error, not a review catch.
 *
 * Two rules this file lives by:
 *
 *  • There is NO tenant filter in any query here, and there must not be one. RLS scopes every
 *    read to the caller's tenants (`findings_select ... to authenticated`). A WHERE clause is
 *    a suggestion; a policy is a boundary. If you ever find yourself adding `.eq('tenant_id',…)`
 *    to make something work, the bug is in the session, not in the query.
 *
 *  • Every select lists its columns. `resources.raw` is the raw collector payload and
 *    `connections.config` holds credential refs — `select('*')` on either would ship them to a
 *    client component with the rest of the props. The narrow column lists below are the DTO
 *    boundary; keep them narrow.
 */

/** Row ceiling for the table. Beyond this the answer is a filter, not a longer page — but the
 * count returned alongside is the true filtered total (`count: 'exact'`), so the UI can say how
 * much it is not showing rather than quietly truncating. */
export const LIST_LIMIT = 500;

/** UiStatus -> the DB states it covers. The inverse of UI_STATUS_OF: the UI collapses six
 * states to four, but a query has to expand back to all six or a filter silently drops rows —
 * "Muted" that forgets `accepted` is a filter that hides findings from the person who muted
 * them. */
const DB_STATUSES_OF: Record<UiStatus, FindingStatus[]> = {
  open: ['open'],
  in_progress: ['triaged', 'in_progress'],
  resolved: ['resolved'],
  muted: ['suppressed', 'accepted'],
};

/** Apply every finding filter EXCEPT assessment. Shared by the list query and the two assessment
 * head-counts, so the coverage-gap facet is counted with the other facets applied but not its own
 * — the standard faceted semantics (see buildFacets). The list query layers assessment on top.
 *
 * `T` is a FREE generic, deliberately unconstrained: supabase-js builders carry very deep generic
 * types, and constraining T against a structural builder shape makes TS give up (TS2589 "type
 * instantiation is excessively deep"). Instead the body casts to a tiny local chain shape — every
 * filter method returns the same builder, so this is sound — and returns back as T, which at the
 * call site is the real builder with `.in`/`.eq`/etc. still available. */
function sharedFindingFilters<T>(q: T, filters: FindingFilters): T {
  type Chain = { in(c: string, v: readonly string[]): Chain; like(c: string, p: string): Chain };
  let out = q as unknown as Chain;
  if (filters.severity.length) out = out.in('severity', filters.severity);
  if (filters.status.length) out = out.in('status', filters.status.flatMap((s) => DB_STATUSES_OF[s]));
  if (filters.system) out = out.like('rule_id', `${filters.system}.%`);
  if (filters.rule) out = out.like('rule_id', `${filters.rule}%`);
  return out as unknown as T;
}

/* The shape PostgREST returns for the list select below. Written out rather than inferred
 * because the project has no generated DB types, so supabase-js hands back `any` — and an
 * `any` that flows into a client component's props is how `raw` eventually leaks. */
type ListRowRaw = {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  assessment: string;
  assessment_reason: string | null;
  last_seen: string;
  resources: { id: string; kind: string; name: string; namespace: string | null } | null;
  /** PostgREST returns an aggregate embed as an array: `[{ count: 3 }]`, or `[]` for none. */
  observations: { count: number }[] | null;
};

export type FindingsView =
  | { state: 'error'; message: string }
  | { state: 'no-connections' }
  | { state: 'never-scanned'; connections: number }
  | {
      state: 'ok';
      groups: RuleGroup[];
      /** True filtered total, even when `groups` was capped at LIST_LIMIT. */
      total: number;
      shown: number;
      truncated: boolean;
      facets: Facets;
      /** The assessment axis is not in the findings_facets view (that groups by rule/severity/
       * status only), so its counts are computed with exact head queries rather than through
       * buildFacets. Kept separate for exactly that reason. */
      assessmentFacet: AssessmentFacet[];
      /** Findings exist for this tenant, but not under these filters. Distinguishes
       * "you are clean" from "your filter is too narrow" — which must never look alike. */
      tenantHasFindings: boolean;
      connections: number;
      scannedAtLabel: string | null;
      /** The caller's tenant id, resolved under RLS — the only thing the live-findings island
       * needs, and never a secret (it is already the filter on every row the page renders). */
      tenantId: string | null;
    };

export async function getFindingsView(filters: FindingFilters): Promise<FindingsView> {
  const supabase = await createClient();

  const base = supabase
    .from('findings')
    // resources is embedded WITHOUT `raw`, and connections is not embedded at all. Both carry
    // payloads that must never reach a client component; the fix is to not select them.
    .select(
      'id, rule_id, title, severity, status, assessment, assessment_reason, last_seen, resources(id, kind, name, namespace), observations(count)',
      { count: 'exact' },
    )
    .order('last_seen', { ascending: false })
    .limit(LIST_LIMIT);

  let q = sharedFindingFilters(base, filters);
  // Assessment is layered on ONLY here, not in the shared helper: the two head-counts below need
  // the other filters without it, so the coverage-gap facet counts against the same base the
  // severity/status facets do.
  if (filters.assessment.length) q = q.in('assessment', filters.assessment);

  const assessmentCount = (a: Assessment) =>
    sharedFindingFilters(
      // head: true means no rows cross the wire — count only, and count: 'exact' is never
      // truncated at Max Rows the way a row fetch is. This is how the coverage-gap facet stays
      // exact past the 1000-row cap.
      supabase.from('findings').select('id', { count: 'exact', head: true }),
      filters,
    ).eq('assessment', a);

  const [connectionsRes, facetRes, listRes, tenantRes, assessedRes, notAssessableRes] = await Promise.all([
    supabase.from('connections').select('id, last_scanned_at'),
    // Facet source: pre-aggregated buckets, unfiltered — counts have to be computed against the
    // unfiltered set or every facet reads zero as soon as you use it.
    //
    // This reads the `findings_facets` VIEW, not `findings`, and that is load-bearing rather
    // than an optimisation. Selecting raw finding rows here (as this did) returns an unbounded
    // response, which PostgREST truncates at Max Rows — 1000 on hosted Supabase — while
    // `listRes.count` below is `count: 'exact'` and is NOT truncated. Past the cap the sidebar
    // rendered facets summing to 1000 directly beneath "1500 findings match" (filters.tsx:105).
    // Two numbers from two mechanisms, disagreeing by construction. The view groups by
    // (rule, severity, status), so its row count is bounded by the rulepack and can never reach
    // the cap — which also retires the old O(findings)-over-the-wire ceiling noted here.
    supabase.from('findings_facets').select('severity, status, rule_id, n'),
    q,
    // The tenant id for the live-findings island. RLS scopes `tenants` to the caller's
    // memberships, so this cannot name a foreign tenant; limit(1) matches the console's
    // one-tenant-per-view assumption (see LiveFindings).
    supabase.from('tenants').select('id').limit(1),
    assessmentCount('assessed'),
    assessmentCount('not_assessable'),
  ]);

  if (connectionsRes.error) return { state: 'error', message: connectionsRes.error.message };
  if (facetRes.error) return { state: 'error', message: facetRes.error.message };
  if (listRes.error) return { state: 'error', message: listRes.error.message };

  const connections = connectionsRes.data ?? [];
  if (connections.length === 0) return { state: 'no-connections' };

  const scannedAt =
    connections
      .map((c) => c.last_scanned_at as string | null)
      .filter((d): d is string => Boolean(d))
      .sort()
      .at(-1) ?? null;

  const facetRows = (facetRes.data ?? []) as FacetRow[];
  if (!scannedAt && facetRows.length === 0) {
    return { state: 'never-scanned', connections: connections.length };
  }

  const rows = ((listRes.data ?? []) as unknown as ListRowRaw[]).map(toFindingRow);

  // These enhancements never fail the page: they run under the same RLS as the list, so if the
  // list came back they almost certainly did too — but a hiccup on one should cost the assessment
  // facet or the live pill, not the whole queue. Default rather than error.
  const assessmentCounts: Record<Assessment, number> = {
    assessed: assessedRes.count ?? 0,
    not_assessable: notAssessableRes.count ?? 0,
  };

  return {
    state: 'ok',
    groups: groupByRule(rows),
    total: listRes.count ?? rows.length,
    shown: rows.length,
    truncated: (listRes.count ?? 0) > rows.length,
    facets: buildFacets(facetRows, filters),
    assessmentFacet: ASSESSMENTS.map((key) => ({ key, count: assessmentCounts[key] })),
    tenantHasFindings: facetRows.length > 0,
    connections: connections.length,
    scannedAtLabel: scannedAt ? relative(scannedAt) : null,
    tenantId: (tenantRes.data?.[0]?.id as string | undefined) ?? null,
  };
}

function toFindingRow(r: ListRowRaw): FindingRow {
  const status = r.status as FindingStatus;
  return {
    id: r.id,
    ruleId: r.rule_id,
    title: r.title,
    severity: r.severity as Severity,
    status,
    // A status the UI does not know about must not silently vanish from a filter or a pill;
    // fall back to 'open' so an unmapped state reads as "needs a human", not as "handled".
    uiStatus: UI_STATUS_OF[status] ?? 'open',
    resource: r.resources
      ? {
          id: r.resources.id,
          kind: r.resources.kind,
          name: r.resources.name,
          namespace: r.resources.namespace,
        }
      : null,
    evidenceCount: r.observations?.[0]?.count ?? 0,
    // Any value other than the two known ones falls back to 'assessed' — a coverage gap must be
    // an explicit, checked state, never something an unrecognised string slides into.
    assessment: r.assessment === 'not_assessable' ? 'not_assessable' : 'assessed',
    assessmentReason: r.assessment_reason,
    lastSeenLabel: relative(r.last_seen),
    lastSeenIso: absolute(r.last_seen),
  };
}

/* ── Detail ─────────────────────────────────────────────────────────────── */

export type EvidenceItem = {
  id: string;
  claim: string;
  sourceRef: Record<string, unknown>;
  observedAtIso: string;
  observedAtLabel: string;
};

export type TriageView = {
  summary: string;
  businessRisk: string;
  exploitability: string;
  priority: string;
  confidence: string;
  model: string;
  /** False when `model === 'rule-based-fallback'`. The user must always know which pixels are
   * generated and which are deterministic — mislabelling the fallback as AI is a lie about
   * provenance in the one place this product cannot afford one. */
  isAi: boolean;
  /** The rule's severity floor overrode the model's own priority (e.g. the model said P3 but a
   * critical rule floors it at P0). Read defensively — absent on triage written before the engine
   * emitted it. When true, `modelPriority` is the number the model actually returned. */
  priorityFloorApplied: boolean;
  /** The model's own priority before any floor, e.g. "P3". Only meaningful when
   * priorityFloorApplied is true; null when the engine did not record it. */
  modelPriority: string | null;
  createdAtIso: string;
  createdAtLabel: string;
  /** Observation ids this output actually cited (ai_output_evidence), NOT every observation on
   * the finding. The distinction is the whole point of the citation gate. */
  citedObservationIds: string[];
};

export type FindingDetail = {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  uiStatus: UiStatus;
  /** 'not_assessable' = a coverage gap. The header shows NotAssessedBadge instead of a severity
   * mark and surfaces assessmentReason, so it cannot be read as a real finding or a clean pass. */
  assessment: Assessment;
  assessmentReason: string | null;
  assignee: string | null;
  remediation: string | null;
  detail: string | null;
  fingerprint: string;
  firstSeenIso: string;
  firstSeenLabel: string;
  lastSeenIso: string;
  lastSeenLabel: string;
  resource:
    | (ResourceRef & { extId: string; connectionType: string | null; connectionName: string | null })
    | null;
  evidence: EvidenceItem[];
  triage: TriageView | null;
};

type DetailRowRaw = {
  id: string;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  assessment: string;
  assessment_reason: string | null;
  assignee: string | null;
  remediation: string | null;
  detail: string | null;
  fingerprint: string;
  first_seen: string;
  last_seen: string;
  resources: {
    id: string;
    kind: string;
    name: string;
    namespace: string | null;
    ext_id: string;
    connections: { type: string; name: string } | null;
  } | null;
};

/** Wrapped in React `cache()` because generateMetadata and the page component both need the
 * finding, and without it that is two identical round trips (four, counting the evidence and
 * triage reads below) for one page view. Dedup is per-request, so it never serves one user's
 * row to another — which matters here more than the saved query, since the row is tenant data. */
export const getFinding = cache(async (id: string): Promise<FindingDetail | null> => {
  const supabase = await createClient();

  // `.maybeSingle()`, not `.single()`: a finding in another tenant is invisible under RLS, which
  // is indistinguishable from one that does not exist — and that is exactly right. Both are a
  // 404 to this user; neither is an error worth logging.
  const { data, error } = await supabase
    .from('findings')
    .select(
      'id, rule_id, title, severity, status, assessment, assessment_reason, assignee, remediation, detail, fingerprint, first_seen, last_seen, ' +
        'resources(id, kind, name, namespace, ext_id, connections(type, name))',
    )
    .eq('id', id)
    .maybeSingle();

  if (error || !data) return null;
  const row = data as unknown as DetailRowRaw;

  const [evidence, triage] = await Promise.all([
    getEvidence(id),
    getTriage(row.id),
  ]);

  const status = row.status as FindingStatus;
  return {
    id: row.id,
    ruleId: row.rule_id,
    title: row.title,
    severity: row.severity as Severity,
    status,
    uiStatus: UI_STATUS_OF[status] ?? 'open',
    assessment: row.assessment === 'not_assessable' ? 'not_assessable' : 'assessed',
    assessmentReason: row.assessment_reason,
    assignee: row.assignee,
    remediation: row.remediation,
    detail: row.detail,
    fingerprint: row.fingerprint,
    firstSeenIso: absolute(row.first_seen),
    firstSeenLabel: relative(row.first_seen),
    lastSeenIso: absolute(row.last_seen),
    lastSeenLabel: relative(row.last_seen),
    resource: row.resources
      ? {
          id: row.resources.id,
          kind: row.resources.kind,
          name: row.resources.name,
          namespace: row.resources.namespace,
          extId: row.resources.ext_id,
          connectionType: row.resources.connections?.type ?? null,
          connectionName: row.resources.connections?.name ?? null,
        }
      : null,
    evidence,
    triage,
  };
});

async function getEvidence(findingId: string): Promise<EvidenceItem[]> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('observations')
    .select('id, claim, source_ref, observed_at')
    .eq('finding_id', findingId)
    .order('observed_at', { ascending: true });

  if (error || !data) return [];

  return data.map((o) => ({
    id: o.id as string,
    claim: o.claim as string,
    sourceRef: (o.source_ref ?? {}) as Record<string, unknown>,
    observedAtIso: absolute(o.observed_at as string),
    observedAtLabel: relative(o.observed_at as string),
  }));
}

/** The most recent triage written for one finding.
 *
 * Read by FINDING ID, not by the engine's cache key. The engine keys `ai_outputs.fingerprint` on
 * the finding's fingerprint *and* a hash of the claims the triage was written from (ai.py
 * `evidence_key`), so that a re-scan which reads different evidence regenerates rather than
 * re-pointing old prose at new facts. That means one finding can own several ai_outputs rows
 * over its life — one per distinct evidence set — and the cache key is not something the console
 * can reconstruct. The newest row is the current triage; its citations come from
 * `ai_output_evidence`, so the page shows exactly the observations that triage was written from
 * even when the ledger has since grown past them.
 */
async function getTriage(findingId: string): Promise<TriageView | null> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('ai_outputs')
    .select('id, content, model, created_at, ai_output_evidence(observation_id)')
    .eq('kind', 'triage')
    .eq('finding_id', findingId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (error || !data) return null;

  const row = data as unknown as {
    content: string;
    model: string | null;
    created_at: string;
    ai_output_evidence: { observation_id: string }[] | null;
  };

  // `content` is JSON written by the engine (ai.py). It is data we wrote, not user input — but
  // a parse failure here would take down a page whose job is to show evidence, and the evidence
  // does not depend on the triage. Degrade to "no triage" rather than to a 500.
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(row.content) as Record<string, unknown>;
  } catch {
    return null;
  }

  const str = (k: string): string => (typeof parsed[k] === 'string' ? (parsed[k] as string) : '');
  const model = row.model ?? 'unknown';

  // Read DEFENSIVELY: these keys are absent on triage rows written before the engine emitted them,
  // so only a literal `true` counts as "floor applied", and model_priority is null unless it is
  // actually a string. Never infer a floor from a missing field.
  const priorityFloorApplied = parsed['priority_floor_applied'] === true;
  const modelPriority = typeof parsed['model_priority'] === 'string' ? (parsed['model_priority'] as string) : null;

  return {
    summary: str('summary'),
    businessRisk: str('business_risk'),
    exploitability: str('exploitability'),
    priority: str('priority') || 'P?',
    confidence: str('confidence') || 'unknown',
    model,
    isAi: model !== 'rule-based-fallback',
    priorityFloorApplied,
    modelPriority,
    createdAtIso: absolute(row.created_at),
    createdAtLabel: relative(row.created_at),
    citedObservationIds: (row.ai_output_evidence ?? []).map((e) => e.observation_id),
  };
}

export type ActionContext = {
  tenantId: string;
  ruleId: string;
  /** The connector's stable id for the resource — the only per-resource key the scan loop's
   * suppression matcher understands (scan.py `_is_suppressed`). Null when the finding has no
   * resource row, which makes a resource-scoped suppression impossible rather than wrong. */
  extId: string | null;
  resourceKind: string | null;
};

/** Everything an action needs about a finding, read UNDER RLS in one query.
 *
 * This IS the authorization check, not a lookup. If the policy does not return the row, the
 * caller is not a member of that tenant and the action must not proceed — so `null` here means
 * refuse, never "carry on with a default".
 *
 * It also exists to keep every identity an action sends to the engine server-derived. The
 * engine takes its tenant from a self-asserted header (api/main.py `principal`) and does NOT
 * verify membership, so a rule_id or an ext_id posted from a form is attacker-controlled input:
 * a suppression could be written against a rule the user never saw. Re-reading them from the
 * row the user's own policy allowed them to see means the engine can only ever be handed a
 * tenant, rule and resource that Postgres already agreed this user can reach.
 */
export async function getActionContext(findingId: string): Promise<ActionContext | null> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('findings')
    .select('tenant_id, rule_id, resources(ext_id, kind)')
    .eq('id', findingId)
    .maybeSingle();

  if (error || !data) return null;
  const row = data as unknown as {
    tenant_id: string;
    rule_id: string;
    resources: { ext_id: string; kind: string } | null;
  };

  return {
    tenantId: row.tenant_id,
    ruleId: row.rule_id,
    extId: row.resources?.ext_id ?? null,
    resourceKind: row.resources?.kind ?? null,
  };
}
