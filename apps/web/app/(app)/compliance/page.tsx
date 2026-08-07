import type { Route } from 'next';
import Link from 'next/link';

import { canEdit, getOwnMembership } from '@/lib/role';
import { createClient } from '@/lib/supabase/server';
import { SEVERITIES, SEVERITY_RANK, type ControlStatus, type Severity } from '@/lib/types';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { IconAlertTriangle, IconClock, IconLayers, IconShieldCheck } from '@/components/ui/icons';
import { Meter } from '@/components/ui/meter';
import { Page } from '@/components/ui/page';
import { PageHeader, SectionHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { AttestControl } from './attest-control';
import { ControlStatusBadge, CoverageBar, FidelityTag } from './control-status';
import {
  FRAMEWORK_ORDER,
  STATUS_RANK,
  compareControlId,
  metaFor,
  normalizeStatus,
  pct,
  score,
  type Score,
} from './frameworks';

/* Compliance — the budget-holder's view, and the one most easily turned into a lie.
 *
 * The whole design of this page is downstream of one rule (docs/research/compliance-mapping.md
 * §0): a finding can prove a control FAILS; a finding's absence can never prove it PASSES.
 * So the score is computed over evaluated controls only, unevaluated controls are shown rather
 * than hidden or rounded away, and 0/0 renders as "Not scored" — not as 100%.
 *
 * Reads cookies via the Supabase server client, so this route is dynamic and never prerendered.
 */

type ControlRow = {
  id: string;
  framework: string;
  control_id: string;
  title: string;
  requirement: string | null;
  status: string;
  failing_finding_ids: unknown;
  evaluated_at: string | null;
};

type FindingRow = {
  id: string;
  title: string;
  severity: string;
  status: string;
  rule_id: string;
};

/** The live human sign-off behind a `pass`. Provenance only — the write happens through the engine
 *  API; the console reads control_attestations directly (it has an RLS select policy) for who/when. */
type AttestationRef = {
  attestedBy: string;
  createdAt: string;
  scope: string;
  note: string | null;
  expiresAt: string | null;
};

type Control = {
  id: string;
  framework: string;
  control_id: string;
  title: string;
  requirement: string | null;
  status: ControlStatus;
  evaluated_at: string | null;
  findings: FindingRow[];
  /** Cited finding ids that no longer resolve. Surfaced, not swallowed — a control failing on
   *  evidence that has since vanished is a control due for re-evaluation, and saying "3
   *  findings" while listing 1 would be the console inventing the other two. */
  missingEvidence: number;
  /** The live attestation whose sign-off produced this control's `pass` (null otherwise). */
  attestation: AttestationRef | null;
};

type FrameworkGroup = { framework: string; controls: Control[]; score: Score; evaluatedAt: string | null };

type PageData =
  | { state: 'ok'; groups: FrameworkGroup[] }
  | { state: 'no-connections' }
  | { state: 'never-evaluated'; connections: number }
  | { state: 'error'; message: string };

/** `failing_finding_ids` is jsonb: the column shape is a convention, not a constraint. */
function findingIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((v): v is string => typeof v === 'string');
}

/* `findings.severity` is `text` with the enum only in a SQL comment — same as controls.status.
 * So a cast to Severity is a guess, and a wrong guess is worse here than anywhere else: an
 * unrecognised value would render a SeverityBadge with no shape and an undefined colour var,
 * silently dropping the exact redundancy channel components/ui/severity.tsx exists to
 * guarantee. Unrecognised severities are shown as their literal value instead — the finding
 * stays visible, and we neither downgrade it to `info` nor invent a rank for it.
 *
 * `in` would be wrong here: `'toString' in SEVERITY_RANK` is true via the prototype. */
function isSeverity(v: unknown): v is Severity {
  return typeof v === 'string' && (SEVERITIES as readonly string[]).includes(v);
}

/** Unrecognised sorts last rather than producing a NaN comparator. */
function severityRank(v: string): number {
  return isSeverity(v) ? SEVERITY_RANK[v] : SEVERITIES.length;
}

/** A severity the console does not know. Rendered as the raw string in mono — evidence, and
 * legible as "the detector said something we do not model" rather than as a real severity. */
function UnknownSeverity({ raw }: { raw: string }) {
  return (
    <span
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 'var(--text-2xs)',
        color: 'var(--text-secondary)',
        border: '1px dashed var(--border-strong)',
        borderRadius: 'var(--radius-sm)',
        padding: '1px var(--space-2)',
        whiteSpace: 'nowrap',
      }}
    >
      {raw || '(no severity)'}
      <span className="vs-visually-hidden"> — unrecognised severity value</span>
    </span>
  );
}

async function getData(): Promise<PageData> {
  const supabase = await createClient();

  // RLS scopes all reads to the caller's tenant. There is no tenant filter in the query
  // because there must not be one — a WHERE clause is a suggestion, a policy is a boundary.
  const [controlsRes, connectionsRes, attestationsRes] = await Promise.all([
    supabase
      .from('controls')
      .select('id, framework, control_id, title, requirement, status, failing_finding_ids, evaluated_at'),
    supabase.from('connections').select('id'),
    // Attestation provenance for the passing controls. The engine writes the pass AND the row; the
    // console only reads who/when back (control_attestations has an RLS select policy). Bounded by
    // the control catalogue, so no cap concern. created_at desc so the newest wins per control.
    supabase
      .from('control_attestations')
      .select('framework, control_id, attested_by, scope, note, created_at, expires_at')
      .order('created_at', { ascending: false }),
  ]);

  if (controlsRes.error) return { state: 'error', message: controlsRes.error.message };
  if (connectionsRes.error) return { state: 'error', message: connectionsRes.error.message };
  if (attestationsRes.error) return { state: 'error', message: attestationsRes.error.message };

  const rows = (controlsRes.data ?? []) as ControlRow[];
  const connections = connectionsRes.data ?? [];

  // Newest LIVE (unexpired) attestation per control. Only a live one produces a `pass` (the engine
  // ignores expired ones), so an expired attestation is not provenance for a current pass and is
  // skipped here. Rows arrive created_at desc, so the first seen per key is the newest.
  const attestations = (attestationsRes.data ?? []) as {
    framework: string;
    control_id: string;
    attested_by: string;
    scope: string;
    note: string | null;
    created_at: string;
    expires_at: string | null;
  }[];
  const now = Date.now();
  const attestationOf = new Map<string, AttestationRef>();
  for (const a of attestations) {
    if (a.expires_at && new Date(a.expires_at).getTime() <= now) continue; // lapsed — not a pass
    const key = `${a.framework}:${a.control_id}`;
    if (attestationOf.has(key)) continue; // keep the newest (first seen in desc order)
    attestationOf.set(key, {
      attestedBy: a.attested_by,
      createdAt: a.created_at,
      scope: a.scope,
      note: a.note,
      expiresAt: a.expires_at,
    });
  }

  // "Nothing to show" is three different facts, and an empty state that conflates them tells
  // the user nothing about what to do next.
  if (rows.length === 0) {
    if (connections.length === 0) return { state: 'no-connections' };
    return { state: 'never-evaluated', connections: connections.length };
  }

  // One round trip for every cited finding: `failing_finding_ids` is jsonb with no FK, so
  // PostgREST cannot join it. RLS still applies, so an id belonging to another tenant simply
  // does not come back — which is the correct outcome, not an error to handle.
  const citedIds = [...new Set(rows.flatMap((r) => findingIds(r.failing_finding_ids)))];
  const findingsById = new Map<string, FindingRow>();

  if (citedIds.length > 0) {
    const findingsRes = await supabase
      .from('findings')
      .select('id, title, severity, status, rule_id')
      .in('id', citedIds);

    if (findingsRes.error) return { state: 'error', message: findingsRes.error.message };
    for (const f of (findingsRes.data ?? []) as FindingRow[]) findingsById.set(f.id, f);
  }

  const byFramework = new Map<string, Control[]>();

  for (const row of rows) {
    const ids = findingIds(row.failing_finding_ids);
    const findings = ids
      .map((id) => findingsById.get(id))
      .filter((f): f is FindingRow => f !== undefined)
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

    const status = normalizeStatus(row.status);
    const control: Control = {
      id: row.id,
      framework: row.framework,
      control_id: row.control_id,
      title: row.title,
      requirement: row.requirement,
      status,
      evaluated_at: row.evaluated_at,
      findings,
      missingEvidence: ids.length - findings.length,
      // Provenance only shown where it means something — on a control that is actually passing.
      attestation: status === 'pass' ? attestationOf.get(`${row.framework}:${row.control_id}`) ?? null : null,
    };

    const list = byFramework.get(row.framework);
    if (list) list.push(control);
    else byFramework.set(row.framework, [control]);
  }

  const known = FRAMEWORK_ORDER.filter((f) => byFramework.has(f)) as string[];
  const extra = [...byFramework.keys()].filter((f) => !known.includes(f)).sort();

  const groups: FrameworkGroup[] = [...known, ...extra].map((framework) => {
    const controls = byFramework.get(framework)!.sort(
      (a, b) => STATUS_RANK[a.status] - STATUS_RANK[b.status] || compareControlId(a.control_id, b.control_id),
    );

    const evaluatedAt =
      controls
        .map((c) => c.evaluated_at)
        .filter((d): d is string => Boolean(d))
        .sort()
        .at(-1) ?? null;

    return { framework, controls, score: score(controls.map((c) => c.status)), evaluatedAt };
  });

  return { state: 'ok', groups };
}

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

/* The findings queue owns its own filter contract and does not exist yet, so this param name
 * is a convention rather than an agreement. It is defined once on purpose: if the queue names
 * it differently, this line is the only edit. A mismatch degrades to "lands on the unfiltered
 * queue", which is survivable precisely because the evidence list is rendered inline here —
 * the link is a convenience, not the answer.
 *
 * The `as Route` cast is the same deliberate exception layout.tsx documents: typedRoutes
 * cannot check a route whose page another agent has not landed yet. Delete the cast when
 * /findings exists. */
const findingHref = (id: string) => `/findings?finding=${encodeURIComponent(id)}` as Route;

/* Severity distribution for the collapsed summary. A spread, not a partition: unrecognised
 * severities are omitted here (they have no badge to render) but still counted in the "N
 * findings" beside it and listed in full on expand, so nothing is hidden by the omission. */
function severitySpread(findings: FindingRow[]): [Severity, number][] {
  const counts = new Map<Severity, number>();
  for (const f of findings) {
    if (!isSeverity(f.severity)) continue;
    counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => SEVERITY_RANK[a[0]] - SEVERITY_RANK[b[0]]);
}

/** The score, and — inseparably — its coverage. These are never rendered apart: a percentage
 * without a denominator is the number every compliance dashboard uses to mislead. */
function ScoreBlock({ score: s }: { score: Score }) {
  return (
    <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
        <span
          data-numeric
          style={{
            fontSize: s.ratio === null ? 'var(--text-lg)' : 'var(--text-3xl)',
            lineHeight: s.ratio === null ? 'var(--leading-lg)' : 'var(--leading-3xl)',
            fontWeight: 600,
            // Not tinted by result. A score is a fact; colouring it green or red editorialises
            // a number whose denominator the reader has not read yet.
            color: s.ratio === null ? 'var(--text-secondary)' : 'var(--text-primary)',
          }}
        >
          {s.ratio === null ? 'Not scored' : pct(s.ratio)}
        </span>
        {s.ratio !== null && (
          <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            {s.tally.pass} of {s.evaluated} evaluated passing
          </span>
        )}
      </div>

      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        {s.inScope === 0 ? (
          'No controls in scope.'
        ) : (
          <>
            Coverage <strong data-numeric style={{ color: 'var(--text-primary)' }}>{pct(s.coverage ?? 0)}</strong> —{' '}
            {s.evaluated} of {s.inScope} in-scope controls evaluated
            {s.tally.not_applicable > 0 && `, ${s.tally.not_applicable} out of scope`}.
          </>
        )}
      </span>
    </div>
  );
}

/** A framework-specific qualification. Not a warning — a calm statement of how much the rows
 * below are worth. Rendered flat rather than as an expandable, because a caveat behind a
 * disclosure is a caveat designed not to be read. */
function Caveat({ children }: { children: React.ReactNode }) {
  return (
    <p
      style={{
        margin: 0,
        padding: 'var(--space-2) var(--space-3)',
        borderLeft: '2px solid var(--border-interactive)',
        background: 'var(--bg)',
        borderRadius: '0 var(--radius-sm) var(--radius-sm) 0',
        fontSize: 'var(--text-xs)',
        lineHeight: 'var(--leading-sm)',
        color: 'var(--text-secondary)',
      }}
    >
      {children}
    </p>
  );
}

/** The evidence cell: which findings cause this control to fail, and how bad they are.
 *
 * Collapsed by default but the severity spread shows in the summary, so the row is scannable
 * without a click and expandable when it is the row you care about. Native <details> keeps
 * the whole page a Server Component — no client bundle for a disclosure. */
function Evidence({ control, editable }: { control: Control; editable: boolean }) {
  // A passing control is passing on a human's sign-off, never on a scan — so its "evidence" is the
  // attestation provenance, not findings.
  if (control.status === 'pass') {
    return <AttestationProvenance attestation={control.attestation} />;
  }

  // Not evaluated: no violation was found, but a clean scan is not a pass. This is exactly where a
  // human can attest — so the coverage gap doubles as the call to action.
  if (control.status === 'unknown') {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>
          No violation found — but a clean scan is not a pass.
        </span>
        {/* Attesting is an accountable sign-off — editor+ only. Viewers still see the honest
            "unknown" state; they just cannot sign it away. */}
        {editable && <AttestControl controlPk={control.id} controlLabel={control.control_id} />}
      </div>
    );
  }

  // not_applicable: out of scope. Attesting it would be meaningless — the engine keeps it out of
  // scope regardless — so no affordance here.
  if (control.status !== 'fail') {
    return <span style={{ color: 'var(--text-muted)' }}>—</span>;
  }

  if (control.findings.length === 0) {
    // Fail with nothing to cite. Say so rather than rendering an empty disclosure: an
    // uncitable failure is itself the finding.
    return (
      <span style={{ color: 'var(--sev-medium-fg)' }}>
        {control.missingEvidence > 0
          ? `${control.missingEvidence} cited finding${control.missingEvidence === 1 ? '' : 's'} no longer visible`
          : 'failing, no finding cited'}
      </span>
    );
  }

  return (
    <details>
      <summary style={{ cursor: 'pointer' }}>
        <span
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            verticalAlign: 'middle',
          }}
        >
          <span data-numeric style={{ color: 'var(--text-secondary)' }}>
            {control.findings.length} finding{control.findings.length === 1 ? '' : 's'}
          </span>
          {severitySpread(control.findings).map(([sev, n]) => (
            <SeverityBadge key={sev} severity={sev} variant="inline" count={n} />
          ))}
        </span>
      </summary>

      <ul
        style={{
          listStyle: 'none',
          margin: 'var(--space-2) 0 var(--space-3)',
          padding: 0,
          display: 'grid',
          gap: 'var(--space-2)',
        }}
      >
        {control.findings.map((f) => (
          <li key={f.id} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            {isSeverity(f.severity) ? (
              <SeverityBadge severity={f.severity} />
            ) : (
              <UnknownSeverity raw={f.severity} />
            )}
            <Link href={findingHref(f.id)} style={{ color: 'var(--text-primary)' }}>
              {f.title}
            </Link>
            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              {f.rule_id}
            </span>
            {/* A control still failing on a finding somebody already resolved means the
                control has not been re-evaluated since. Show the status so the staleness is
                visible instead of being mistaken for a live failure. */}
            {f.status !== 'open' && (
              <span style={{ color: 'var(--text-secondary)' }}>({f.status})</span>
            )}
          </li>
        ))}

        {control.missingEvidence > 0 && (
          <li style={{ color: 'var(--text-secondary)' }}>
            + {control.missingEvidence} cited finding{control.missingEvidence === 1 ? '' : 's'} no
            longer visible — re-evaluate this control.
          </li>
        )}
      </ul>
    </details>
  );
}

/** yyyy-mm-dd, UTC. For dates (expiry, sign-off day) where a relative label is either wrong — the
 *  page's relative() only handles the past, and an expiry is in the future — or less useful. */
function dateOnly(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

/** Who signed, when, over what scope. The provenance behind a `pass` — shown in place of evidence,
 *  because a passing control is passing on a human's word, not a scan. */
function AttestationProvenance({ attestation }: { attestation: AttestationRef | null }) {
  if (!attestation) {
    // The engine only writes `pass` on a live attestation, so a pass with none we can read means
    // the row is not visible here (or lapsed between the two reads). Say so rather than letting the
    // pass read as scan-proven — that is the exact dishonesty this page exists to refuse.
    return (
      <span style={{ color: 'var(--sev-medium-fg)', fontSize: 'var(--text-2xs)' }}>
        passing on an attestation this view cannot show — re-check who signed it
      </span>
    );
  }

  return (
    <div style={{ display: 'grid', gap: '2px', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
      <span>
        Attested by{' '}
        {/* No display names exist in the schema (same limit as finding assignees), so the signer is
            shown as the head of their user id — enough to correlate, honest about what we have. */}
        <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
          {attestation.attestedBy.slice(0, 8)}
        </code>{' '}
        <span title={dateOnly(attestation.createdAt)}>{relative(attestation.createdAt)}</span>
      </span>
      <span>
        Scope: <span style={{ color: 'var(--text-primary)' }}>{attestation.scope}</span>
      </span>
      {attestation.note && <span>Note: {attestation.note}</span>}
      <span>
        {attestation.expiresAt
          ? `Expires ${dateOnly(attestation.expiresAt)}`
          : 'No expiry — permanent (discouraged)'}
      </span>
      <span style={{ color: 'var(--text-muted)' }}>Human sign-off, not a scan result.</span>
    </div>
  );
}

/* ── Aggregates & framework state ─────────────────────────────────────────── */

type Aggregate = {
  frameworks: number;
  controls: number;
  attested: number;
  failing: number;
  notScored: number;
  outOfScope: number;
};

/** The KPI rollup across every framework the engine evaluated. Each number is a straight sum of
 *  per-framework tallies — no framework contributes a `pass` it did not earn through attestation,
 *  and `notScored` (unevaluated) is counted apart from `attested`, never folded into it. */
function aggregate(groups: FrameworkGroup[]): Aggregate {
  const agg: Aggregate = { frameworks: groups.length, controls: 0, attested: 0, failing: 0, notScored: 0, outOfScope: 0 };
  for (const g of groups) {
    agg.controls += g.controls.length;
    agg.attested += g.score.tally.pass;
    agg.failing += g.score.tally.fail;
    agg.notScored += g.score.tally.unknown;
    agg.outOfScope += g.score.tally.not_applicable;
  }
  return agg;
}

/** The framework's headline state, for the overview pill. The vocabulary is deliberately honest:
 *  a live failing control makes the framework "Failing"; nothing evaluated is "Not scored" (never
 *  a silent 100%); evaluated-and-clean but with unevaluated in-scope controls is "Partial
 *  coverage", not "Attested"; only full evaluation with no failures is "Attested" — and even that
 *  word says "a human signed", not "compliant". */
function frameworkState(s: Score): { tone: StatusTone; label: string } {
  if (s.tally.fail > 0) return { tone: 'bad', label: 'Failing' };
  if (s.evaluated === 0) return { tone: 'neutral', label: 'Not scored' };
  if ((s.coverage ?? 1) < 1) return { tone: 'warn', label: 'Partial coverage' };
  return { tone: 'ok', label: 'Attested' };
}

/* ── Sections ─────────────────────────────────────────────────────────────── */

/** The KPI band. Five numbers a budget-holder reads first, each labelled so the honest one
 *  ("Not scored" is not "passing") cannot be misread as the flattering one. */
function KpiRow({ agg }: { agg: Aggregate }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: 'var(--space-3)',
      }}
    >
      <Card hover>
        <CardBody>
          <StatTile label="Frameworks" value={agg.frameworks} icon={<IconLayers size={13} />} sub="evaluated for this tenant" />
        </CardBody>
      </Card>
      <Card hover>
        <CardBody>
          <StatTile label="Controls" value={agg.controls} sub="across all frameworks" />
        </CardBody>
      </Card>
      <Card hover>
        <CardBody>
          <StatTile
            label="Attested"
            value={agg.attested}
            tone={agg.attested > 0 ? 'good' : 'neutral'}
            icon={<IconShieldCheck size={13} />}
            sub="passing on a human sign-off"
          />
        </CardBody>
      </Card>
      <Card hover>
        <CardBody>
          <StatTile
            label="Failing"
            value={agg.failing}
            tone={agg.failing > 0 ? 'bad' : 'neutral'}
            icon={<IconAlertTriangle size={13} />}
            sub="a live finding proves it"
          />
        </CardBody>
      </Card>
      <Card hover>
        <CardBody>
          <StatTile
            label="Not scored"
            value={agg.notScored}
            tone={agg.notScored > 0 ? 'warn' : 'neutral'}
            icon={<IconClock size={13} />}
            sub="no result yet — not passing"
          />
        </CardBody>
      </Card>
    </div>
  );
}

/** The at-a-glance card for one framework: headline state, the honest score-with-coverage, and a
 *  Meter of what is actually attested. The Meter is drawn over ALL controls (attested / total) so
 *  it can never read fuller than the framework is — and when nothing is in scope it is dropped
 *  entirely rather than shown as an empty-or-full bar, with ScoreBlock stating "Not scored". */
function FrameworkOverview({ group }: { group: FrameworkGroup }) {
  const meta = metaFor(group.framework);
  const s = group.score;
  const st = frameworkState(s);
  const total = group.controls.length;

  return (
    <Card>
      <div style={{ padding: 'var(--space-4)', display: 'grid', gap: 'var(--space-3)', height: '100%' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 'var(--space-2)' }}>
          <div style={{ display: 'grid', gap: 'var(--space-1)', minWidth: 0 }}>
            <span style={{ fontSize: 'var(--text-base)', lineHeight: 'var(--leading-base)', fontWeight: 600, color: 'var(--text-primary)' }}>
              {meta.label} {meta.version}
            </span>
            <span>
              <FidelityTag fidelity={meta.fidelity} />
            </span>
          </div>
          <StatusPill tone={st.tone} label={st.label} variant="soft" />
        </div>

        <ScoreBlock score={s} />

        {/* Only where there is something in scope to attest. Otherwise ScoreBlock already says
            "Not scored" / "No controls in scope", and a meter would invent a fraction. */}
        {s.inScope > 0 && (
          <Meter
            value={s.tally.pass}
            max={total}
            tone="good"
            showValue={false}
            label={`Attested — ${s.tally.pass} of ${total} control${total === 1 ? '' : 's'}`}
          />
        )}

        <a
          href={`#framework-${group.framework}`}
          style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', textDecoration: 'none', marginTop: 'auto' }}
        >
          View {total} control{total === 1 ? '' : 's'} →
        </a>
      </div>
    </Card>
  );
}

/* The control mosaic — the whole framework in one glance: one cell per control, coloured by
 * status, failing cells ringed. The same information as the table below (which stays the
 * record), compressed to the shape auditors actually ask about: "how much of this framework is
 * red". Colour never stands alone — every cell carries a title (id · status · requirement), a
 * legend names the hues in words, and the aria-label states the tally. */
const MOSAIC_COLOR: Record<ControlStatus, string> = {
  pass: 'var(--sev-low-solid)',
  fail: 'var(--sev-critical-solid)',
  unknown: 'var(--sev-medium-solid)',
  not_applicable: 'var(--grid)',
};
const MOSAIC_LABEL: Record<ControlStatus, string> = {
  pass: 'pass',
  fail: 'fail',
  unknown: 'unknown',
  not_applicable: 'n/a',
};

function ControlMosaic({ controls }: { controls: Control[] }) {
  if (controls.length === 0) return null;
  const tally = (s: ControlStatus) => controls.filter((c) => c.status === s).length;
  const summary = (['fail', 'pass', 'unknown', 'not_applicable'] as ControlStatus[])
    .map((s) => `${tally(s)} ${MOSAIC_LABEL[s]}`)
    .join(', ');
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <div
        role="img"
        aria-label={`Control mosaic: ${summary}`}
        style={{ display: 'flex', flexWrap: 'wrap', gap: 4, maxWidth: 640 }}
      >
        {controls.map((c) => (
          <span
            key={c.id}
            title={`${c.control_id} · ${MOSAIC_LABEL[c.status]}${c.title ? ` · ${c.title}` : ''}`}
            style={{
              width: 13,
              height: 13,
              borderRadius: 3.5,
              background: MOSAIC_COLOR[c.status] ?? 'var(--grid)',
              opacity: c.status === 'not_applicable' ? 0.8 : 1,
              boxShadow:
                c.status === 'fail'
                  ? '0 0 0 1.5px color-mix(in srgb, var(--sev-critical-solid) 45%, transparent)'
                  : 'inset 0 0 0 1px rgb(0 0 0 / 0.06)',
            }}
          />
        ))}
      </div>
      <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }} data-numeric>
        {(['fail', 'pass', 'unknown', 'not_applicable'] as ControlStatus[]).map((s) => (
          <span key={s} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <span aria-hidden="true" style={{ width: 9, height: 9, borderRadius: 2.5, background: MOSAIC_COLOR[s] }} />
            {tally(s)} {MOSAIC_LABEL[s]}
          </span>
        ))}
      </div>
    </div>
  );
}

function FrameworkCard({ group, editable }: { group: FrameworkGroup; editable: boolean }) {
  const meta = metaFor(group.framework);

  return (
    <Card>
      <CardHeader>
        <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <CardTitle>
            {meta.label} {meta.version}
          </CardTitle>
          <FidelityTag fidelity={meta.fidelity} />
        </span>
        <CardMeta>
          {group.evaluatedAt ? `evaluated ${relative(group.evaluatedAt)}` : 'never evaluated'}
        </CardMeta>
      </CardHeader>

      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <ScoreBlock score={group.score} />
          <CoverageBar tally={group.score.tally} total={group.controls.length} />
          <ControlMosaic controls={group.controls} />
          <Caveat>{meta.caveat}</Caveat>
        </div>
      </CardBody>

      <Table density="relaxed" caption={`${meta.label} ${meta.version} controls, failing first`}>
        <THead>
          <TR>
            <TH width="140px">Status</TH>
            <TH width="120px">Control</TH>
            <TH>Requirement</TH>
            <TH width="34%">Evidence / attestation</TH>
            <TH width="110px">Evaluated</TH>
          </TR>
        </THead>
        <TBody>
          {group.controls.map((c) => (
            <TR key={c.id}>
              <TD>
                <ControlStatusBadge status={c.status} />
              </TD>
              <TD mono>{c.control_id}</TD>
              <TD>
                <span style={{ color: 'var(--text-primary)' }}>{c.title}</span>
                {c.requirement && (
                  <span style={{ display: 'block', color: 'var(--text-secondary)' }}>
                    {c.requirement}
                  </span>
                )}
              </TD>
              <TD>
                <Evidence control={c} editable={editable} />
              </TD>
              <TD muted>{c.evaluated_at ? relative(c.evaluated_at) : '—'}</TD>
            </TR>
          ))}
        </TBody>
      </Table>

      <CardFooter>{meta.scope}</CardFooter>
    </Card>
  );
}

/* The evidence-bundle formats VectaSec's reporting module produces. Kept as data so the panel
 * lists exactly what the engine can generate and nothing it cannot. */
const EXPORT_FORMATS: { name: string; desc: string; href: string; filename: string }[] = [
  {
    name: 'OSCAL 1.1',
    desc: 'Assessment results as NIST OSCAL 1.1 JSON — machine-readable, for a GRC platform or an auditor’s toolchain.',
    href: '/api/reports/oscal',
    filename: 'vectasec-oscal.json',
  },
  {
    name: 'Findings CSV',
    desc: 'One row per finding: rule, severity, system, resource, status, evidence and remediation — for a spreadsheet or a ticket import.',
    href: '/api/reports/csv',
    filename: 'vectasec-findings.csv',
  },
  {
    name: 'Executive report',
    desc: 'A narrative Markdown summary for leadership: posture, severity breakdown, worst findings, and compliance coverage.',
    href: '/api/reports/summary',
    filename: 'vectasec-report.md',
  },
];

/** The evidence-export affordance — and a deliberately HONEST one.
 *
 * The reporting module in the engine generates all three formats today, but there is no console
 * endpoint that returns them (lib/engine.ts exposes no report route). So this ships no download
 * button that would 404, and no button that looks live but does nothing. It states what the
 * reporting API produces, and shows each format with a plainly-disabled control and a "coming to
 * the console" note. When a report route lands in lib/engine.ts, wire these to it. */
function ExportPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence export</CardTitle>
        <CardMeta>generated live from your tenant’s current results</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
            VectaSec’s reporting engine generates a full evidence bundle from the results above. Each
            download is produced on demand from your tenant’s current findings, controls and posture —
            deterministic, and honest about coverage (a control is never reported passing without a
            human attestation).
          </p>

          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
            {EXPORT_FORMATS.map((f) => (
              <li
                key={f.name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 'var(--space-4)',
                  padding: 'var(--space-3)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div style={{ display: 'grid', gap: '2px', minWidth: 0 }}>
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {f.name}
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-secondary)' }}>
                    {f.desc}
                  </span>
                </div>
                {/* A real download: this href hits app/api/reports/[format], which authenticates the
                    user server-side, calls the engine's reporting endpoint with the engine token, and
                    streams the file back. Read-only export of data the user can already see. */}
                <a
                  href={f.href}
                  download={f.filename}
                  style={{
                    flexShrink: 0,
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: 'var(--space-2) var(--space-3)',
                    fontSize: 'var(--text-sm)',
                    fontWeight: 500,
                    color: 'var(--text-primary)',
                    background: 'var(--surface)',
                    border: '1px solid var(--border-interactive)',
                    borderRadius: 'var(--radius-md)',
                    textDecoration: 'none',
                  }}
                >
                  Download
                </a>
              </li>
            ))}
          </ul>
        </div>
      </CardBody>
      <CardFooter>
        Downloads are generated live by the reporting engine from your tenant’s current results.
      </CardFooter>
    </Card>
  );
}

/** The page's thesis, stated before any number is shown. Everything below is arithmetic; this is
 *  the part that makes the arithmetic honest, so it is rendered flat and in full — never abridged
 *  into the header or hidden behind a disclosure. */
function Thesis() {
  return (
    <p
      style={{
        margin: 0,
        maxWidth: '84ch',
        fontSize: 'var(--text-sm)',
        lineHeight: 'var(--leading-sm)',
        color: 'var(--text-secondary)',
      }}
    >
      A scan can prove a control <strong style={{ color: 'var(--text-primary)' }}>fails</strong>. It
      can never prove one passes — the absence of a finding is not evidence of compliance, only
      evidence of what was looked at. So nothing here is ever marked passing on the strength of a
      clean scan: a scan emits only <em>fails</em>, <em>not applicable</em>, and{' '}
      <em>not evaluated</em>. A control reaches <strong style={{ color: 'var(--text-primary)' }}>passing</strong>{' '}
      only when a human <strong style={{ color: 'var(--text-primary)' }}>attests</strong> it — signs
      off, over a stated scope, that it is met — and a live failing finding always overrides that
      sign-off (you cannot attest away a broken control). So a pass here is someone&rsquo;s
      accountable sign-off, shown with its provenance, never the by-product of a clean scan. Scores
      are computed over evaluated controls only. Controls that were not evaluated are shown, counted
      separately, and never counted as passing.
    </p>
  );
}

export default async function CompliancePage() {
  const data = await getData();

  // Role gates the attest affordance only; every read on this page is RLS-scoped regardless.
  const membership = await getOwnMembership();
  const editable = canEdit(membership?.role);

  const groups = data.state === 'ok' ? data.groups : [];
  const agg = aggregate(groups);
  const latestEval =
    groups
      .map((g) => g.evaluatedAt)
      .filter((d): d is string => Boolean(d))
      .sort()
      .at(-1) ?? null;

  const headerMeta =
    data.state === 'ok'
      ? `${agg.frameworks} framework${agg.frameworks === 1 ? '' : 's'} · ${agg.controls} control${
          agg.controls === 1 ? '' : 's'
        }${latestEval ? ` · evaluated ${relative(latestEval)}` : ''}`
      : undefined;

  const missingFrameworks =
    data.state === 'ok'
      ? FRAMEWORK_ORDER.filter((f) => !data.groups.some((g) => g.framework === f))
      : [];

  return (
    <Page>
      <PageHeader
        title="Compliance"
        description="Framework posture you can defend: a scan can prove a control fails, but only a human attesting can make one pass."
        meta={headerMeta}
      />

      <Thesis />

      {data.state === 'error' && (
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load controls" description={data.message} />
          </CardBody>
        </Card>
      )}

      {data.state === 'no-connections' && (
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="Connect your first system"
              description="Compliance controls are evaluated from findings, and findings come from a scan. Nothing is connected yet, so there is nothing to evaluate against."
            />
          </CardBody>
        </Card>
      )}

      {data.state === 'never-evaluated' && (
        <Card>
          <CardBody>
            <EmptyState
              tone="pending"
              title="No control catalogue yet"
              description="Connected, but the engine has not evaluated a framework catalogue for this tenant. Controls appear here after the compliance mapping runs against a completed scan. Until then nothing is scored — which is not the same as compliant."
              meta={`${data.connections} connection${data.connections === 1 ? '' : 's'} configured`}
            />
          </CardBody>
        </Card>
      )}

      {data.state === 'ok' && (
        <>
          <KpiRow agg={agg} />

          <section style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <SectionHeader title="Frameworks" meta="coverage at a glance" />
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
                gap: 'var(--space-4)',
              }}
            >
              {data.groups.map((g) => (
                <FrameworkOverview key={g.framework} group={g} />
              ))}
            </div>
          </section>

          <section style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <SectionHeader title="Control detail" meta="failing first" />
            <div style={{ display: 'grid', gap: 'var(--space-5)' }}>
              {data.groups.map((g) => (
                // Anchor target for the overview cards' "View controls →" links. scroll-margin keeps
                // the card header clear of the top edge when jumped to.
                <div key={g.framework} id={`framework-${g.framework}`} style={{ scrollMarginTop: 'var(--space-6)' }}>
                  <FrameworkCard group={g} editable={editable} />
                </div>
              ))}
            </div>
          </section>

          <ExportPanel />

          {/* Absent frameworks are named rather than silently omitted — but they are NOT rendered
              as empty scorecards, because "PCI: not scored" on a tenant that has no CDE would
              invent a scope obligation the engine never asserted. */}
          {missingFrameworks.length > 0 && (
            <p
              style={{
                margin: 0,
                fontSize: 'var(--text-xs)',
                lineHeight: 'var(--leading-sm)',
                color: 'var(--text-secondary)',
              }}
            >
              Not evaluated for this tenant:{' '}
              {missingFrameworks.map((f) => metaFor(f).label).join(', ')}. A framework appears here once
              the engine determines it is in scope and evaluates a catalogue for it. Its absence is not a
              statement that it does not apply to you.
            </p>
          )}
        </>
      )}
    </Page>
  );
}
