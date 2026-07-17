import type { Route } from 'next';
import Link from 'next/link';

import { createClient } from '@/lib/supabase/server';
import { SEVERITIES, SEVERITY_RANK, type ControlStatus, type Severity } from '@/lib/types';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
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

type Control = {
  id: string;
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

  // RLS scopes both reads to the caller's tenant. There is no tenant filter in the query
  // because there must not be one — a WHERE clause is a suggestion, a policy is a boundary.
  const [controlsRes, connectionsRes] = await Promise.all([
    supabase
      .from('controls')
      .select('id, framework, control_id, title, requirement, status, failing_finding_ids, evaluated_at'),
    supabase.from('connections').select('id'),
  ]);

  if (controlsRes.error) return { state: 'error', message: controlsRes.error.message };
  if (connectionsRes.error) return { state: 'error', message: connectionsRes.error.message };

  const rows = (controlsRes.data ?? []) as ControlRow[];
  const connections = connectionsRes.data ?? [];

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

    const control: Control = {
      id: row.id,
      control_id: row.control_id,
      title: row.title,
      requirement: row.requirement,
      status: normalizeStatus(row.status),
      evaluated_at: row.evaluated_at,
      findings,
      missingEvidence: ids.length - findings.length,
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
function Evidence({ control }: { control: Control }) {
  if (control.status !== 'fail') {
    return (
      <span style={{ color: 'var(--text-muted)' }}>
        {control.status === 'unknown' ? 'no evidence gathered' : '—'}
      </span>
    );
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

function FrameworkCard({ group }: { group: FrameworkGroup }) {
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
          <Caveat>{meta.caveat}</Caveat>
        </div>
      </CardBody>

      <Table density="relaxed" caption={`${meta.label} ${meta.version} controls, failing first`}>
        <THead>
          <TR>
            <TH width="140px">Status</TH>
            <TH width="120px">Control</TH>
            <TH>Requirement</TH>
            <TH width="34%">Evidence</TH>
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
                <Evidence control={c} />
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

export default async function CompliancePage() {
  const data = await getData();

  const missingFrameworks =
    data.state === 'ok'
      ? FRAMEWORK_ORDER.filter((f) => !data.groups.some((g) => g.framework === f))
      : [];

  return (
    <div style={{ display: 'grid', gap: 'var(--space-5)', maxWidth: 1200 }}>
      <header style={{ display: 'grid', gap: 'var(--space-2)' }}>
        <h1
          style={{
            margin: 0,
            fontSize: 'var(--text-xl)',
            lineHeight: 'var(--leading-xl)',
            fontWeight: 600,
          }}
        >
          Compliance
        </h1>

        {/* The thesis of the page, stated before any number is shown. Everything below is
            arithmetic; this is the part that makes the arithmetic honest. */}
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
          clean scan: the engine emits only <em>fails</em>, <em>not applicable</em>, and{' '}
          <em>not evaluated</em>. Marking a control passed requires a human attestation with
          scope-coverage evidence behind it, and that is not built yet — so no control here is
          passing today. Scores are computed over evaluated controls only. Controls that were not
          evaluated are shown, counted separately, and never counted as passing.
        </p>
      </header>

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
              description="Connected, but the engine has not evaluated a framework catalogue for this tenant. Controls appear here after the compliance mapping runs against a completed scan."
              meta={`${data.connections} connection${data.connections === 1 ? '' : 's'} configured`}
            />
          </CardBody>
        </Card>
      )}

      {data.state === 'ok' && data.groups.map((g) => <FrameworkCard key={g.framework} group={g} />)}

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
    </div>
  );
}
