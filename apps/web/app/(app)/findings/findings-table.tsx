'use client';

import Link from 'next/link';
import { useState } from 'react';

import { Chip } from '@/components/ui/chip';
import { SeverityBadge } from '@/components/ui/severity';
import { TBody, THead, TD, TH, TR, Table } from '@/components/ui/table';
import { NotAssessedBadge } from './assessment';
import type { FindingRow, RuleGroup } from './group';
import { findingHref, systemOf } from './query';
import { StatusPill } from './status';

/* The findings queue.
 *
 * Grouped by rule_id, because that is the single most effective anti-fatigue lever we have: a
 * wildcard ACL on 200 topics is ONE problem with ONE answer, not 200 decisions. The group row
 * is the unit of decision; the occurrences are the evidence that it is real.
 *
 * Grouping (rule_id across assets) is not dedup (fingerprint across scans). Dedup already
 * happened in Postgres — one row per issue per asset, `last_seen` updated in place. This is the
 * second collapse, and only this one is the UI's job.
 *
 * Client because rows expand; it fetches nothing. The server does the query, the grouping and
 * the sort, and hands down a DTO — `resources.raw` is never selected, so it cannot ride along
 * in these props.
 *
 * The two time columns answer two different questions: AGE (first_seen, the oldest occurrence)
 * is "how long has this been true", LAST SEEN is "is it still true". An old open critical is a
 * worse fact than a fresh one, so both are on the row.
 */

export function FindingsTable({ groups }: { groups: RuleGroup[] }) {
  // A single group means the user has already narrowed to one rule — making them click again to
  // see the thing they filtered for is a toll booth.
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(groups.length === 1 ? [groups[0].ruleId] : []),
  );

  const toggle = (ruleId: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (!next.delete(ruleId)) next.add(ruleId);
      return next;
    });

  return (
    <Table density="compact" caption="Findings grouped by rule, sorted by severity then most recently seen">
      <THead>
        <TR>
          <TH width="28px">
            <span className="vs-visually-hidden">Expand</span>
          </TH>
          {/* aria-sort on the two columns the server actually ordered by. Claiming a sort we did
              not perform would be worse than claiming none. */}
          <TH width="104px" sort="desc">
            Severity
          </TH>
          <TH width="1%">Rule</TH>
          <TH width="1%">System</TH>
          <TH>Title</TH>
          <TH width="20%">Resource</TH>
          <TH width="130px">Status</TH>
          {/* Counts are compared, so they are right-aligned and tabular. Dates are read, not
              compared, so they are not. */}
          <TH width="80px" numeric>
            Evidence
          </TH>
          <TH width="88px">Age</TH>
          <TH width="96px" sort="desc">
            Last seen
          </TH>
        </TR>
      </THead>

      <TBody>
        {groups.map((g) =>
          g.count === 1 ? (
            <SingleRow key={g.ruleId} group={g} finding={g.findings[0]} />
          ) : (
            <GroupRows
              key={g.ruleId}
              group={g}
              open={expanded.has(g.ruleId)}
              onToggle={() => toggle(g.ruleId)}
            />
          ),
        )}
      </TBody>
    </Table>
  );
}

/** One occurrence, so the group IS the finding — no expander, and the row links straight to it.
 * Wrapping a single occurrence in a collapsed group would add a click that reveals one row. */
function SingleRow({ group, finding }: { group: RuleGroup; finding: FindingRow }) {
  const gap = finding.assessment === 'not_assessable';
  return (
    <TR>
      <TD>{null}</TD>
      <TD>
        {/* A coverage gap carries no severity mark — it is not a vulnerability on that axis. */}
        {gap ? <NotAssessedBadge /> : <SeverityBadge severity={finding.severity} />}
      </TD>
      <TD mono muted>
        {group.ruleId}
      </TD>
      <TD>
        <SystemChip ruleId={group.ruleId} />
      </TD>
      <TD>
        <Link href={findingHref(finding.id)} style={{ color: 'var(--text-primary)' }}>
          {finding.title}
        </Link>
        {gap && <GapReason reason={finding.assessmentReason} />}
      </TD>
      <TD>
        <ResourceCell finding={finding} />
      </TD>
      <TD>
        <StatusPill status={finding.uiStatus} />
      </TD>
      <TD numeric>
        <EvidenceCount n={finding.evidenceCount} />
      </TD>
      <TD muted>
        <Age label={finding.firstSeenLabel} iso={finding.firstSeenIso} />
      </TD>
      <TD muted>
        <time dateTime={finding.lastSeenIso} title={finding.lastSeenIso}>
          {finding.lastSeenLabel}
        </time>
      </TD>
    </TR>
  );
}

function GroupRows({
  group,
  open,
  onToggle,
}: {
  group: RuleGroup;
  open: boolean;
  onToggle: () => void;
}) {
  const resourceCount = new Set(group.findings.map((f) => f.resource?.id ?? f.id)).size;

  return (
    <>
      <TR>
        <TD>
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            style={{
              display: 'grid',
              placeItems: 'center',
              width: 20,
              height: 20,
              padding: 0,
              border: 0,
              background: 'transparent',
              color: 'var(--text-secondary)',
              cursor: 'pointer',
              font: 'inherit',
            }}
          >
            <span aria-hidden="true" style={{ lineHeight: 1 }}>
              {open ? '▾' : '▸'}
            </span>
            <span className="vs-visually-hidden">
              {open ? 'Collapse' : 'Expand'} {group.count} occurrences of {group.ruleId}
            </span>
          </button>
        </TD>

        <TD>
          {/* The ×N is the whole point of the row: one badge, one decision. When every occurrence
              is a coverage gap the whole group is "we could not check", so it shows the neutral
              mark instead of a severity — the stored severity only drove its sort position. */}
          {group.allNotAssessable ? (
            <NotAssessedBadge count={group.count} />
          ) : (
            // Count the ASSESSED occurrences here — the gaps are tallied separately below, so the
            // ×N beside a severity never silently includes a coverage gap.
            <SeverityBadge severity={group.severity} count={group.assessedCount} />
          )}
          {/* A detector may override severity per hit (scan.py: `h.severity or d.severity`), so
              a group can genuinely be mixed. Saying so prevents the worst outcome of grouping —
              a critical occurrence hidden inside a row labelled with a lower severity. */}
          {!group.allNotAssessable && group.mixedSeverity && (
            <span
              style={{ marginLeft: 'var(--space-1)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}
            >
              mixed
            </span>
          )}
          {/* A partly-uncheckable group: some occurrences are real findings, some are coverage
              gaps. Flag the gaps so the severity badge is not read as covering all N. */}
          {!group.allNotAssessable && group.notAssessableCount > 0 && (
            <span
              style={{ marginLeft: 'var(--space-1)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}
            >
              +{group.notAssessableCount} not assessed
            </span>
          )}
        </TD>

        <TD mono muted>
          {group.ruleId}
        </TD>
        <TD>
          <SystemChip ruleId={group.ruleId} />
        </TD>
        <TD>{group.title}</TD>
        <TD muted>
          {resourceCount} resource{resourceCount === 1 ? '' : 's'}
        </TD>
        <TD>
          <span style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
            {group.statusCounts.map(({ status, count }) => (
              <StatusPill key={status} status={status} count={count} />
            ))}
          </span>
        </TD>
        <TD numeric>
          <EvidenceCount n={group.evidenceCount} />
        </TD>
        <TD muted>
          <Age label={group.firstSeenLabel} iso={group.firstSeenIso} />
        </TD>
        <TD muted>
          <time dateTime={group.lastSeenIso} title={group.lastSeenIso}>
            {group.lastSeenLabel}
          </time>
        </TD>
      </TR>

      {open && group.findings.map((f) => <OccurrenceRow key={f.id} finding={f} />)}
    </>
  );
}

/** One occurrence inside an expanded group.
 *
 * A raw <tr> rather than <TR>: the design system's only row variant is `selected`, which means
 * "the user selected this" and writes data-selected. Borrowing it for "this row is subordinate"
 * would put a selection flag on rows nobody selected — a lie to tests, to CSS, and to anything
 * reading the DOM. The one thing needed here is recession, so it recedes onto --bg and nothing
 * else changes.
 *
 * Rule, System and Title are left empty on purpose: they are identical to the group header
 * directly above (title comes from the detector, so it is constant per rule; system is the
 * rule's first segment). Repeating them per row is exactly the noise grouping exists to remove.
 * What differs — resource, status, evidence, age, recency — is what stays.
 */
function OccurrenceRow({ finding }: { finding: FindingRow }) {
  const cell: React.CSSProperties = { padding: '0 var(--space-3)' };
  return (
    <tr style={{ height: 'var(--vs-row-h)', borderBottom: '1px solid var(--border)', background: 'var(--bg)' }}>
      <td />
      <td style={{ ...cell, textAlign: 'left' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <span aria-hidden="true" style={{ color: 'var(--text-secondary)' }}>
            ↳
          </span>
          {finding.assessment === 'not_assessable' ? (
            <NotAssessedBadge variant="inline" />
          ) : (
            <SeverityBadge severity={finding.severity} variant="inline" />
          )}
        </span>
      </td>
      <td />
      <td />
      {/* The otherwise-empty title column carries the coverage-gap reason for this occurrence —
          each not_assessable finding can have a different reason, so it belongs on the row. */}
      <td style={cell}>
        {finding.assessment === 'not_assessable' && <GapReason reason={finding.assessmentReason} />}
      </td>
      <td style={cell}>
        {/* The link lives on the resource here, and on the title in a single-occurrence row:
            in both cases it is the most specific identity the row carries. A finding is
            rule × resource, and the group header already supplied the rule. */}
        <Link href={findingHref(finding.id)} style={{ color: 'var(--text-primary)' }}>
          <ResourceCell finding={finding} />
        </Link>
      </td>
      <td style={cell}>
        <StatusPill status={finding.uiStatus} />
      </td>
      <td data-numeric style={{ ...cell, textAlign: 'right' }}>
        <EvidenceCount n={finding.evidenceCount} />
      </td>
      <td style={{ ...cell, color: 'var(--text-secondary)' }}>
        <Age label={finding.firstSeenLabel} iso={finding.firstSeenIso} />
      </td>
      <td style={{ ...cell, color: 'var(--text-secondary)' }}>
        <time dateTime={finding.lastSeenIso} title={finding.lastSeenIso}>
          {finding.lastSeenLabel}
        </time>
      </td>
    </tr>
  );
}

/** The system a rule belongs to — its first dotted segment (KAFKA.ACL.001 -> KAFKA). A quiet
 * mono chip, not a link: the FilterBar owns system filtering, and a link inside a row that already
 * links elsewhere is an ambiguous target. */
function SystemChip({ ruleId }: { ruleId: string }) {
  return <Chip mono>{systemOf(ruleId)}</Chip>;
}

/** Age = time since first_seen. Left-aligned (a date is read, not compared) but tabular so the
 * leading numeral lines up down the column; the absolute UTC first_seen rides the tooltip. */
function Age({ label, iso }: { label: string; iso: string }) {
  return (
    <time dateTime={iso} title={`First seen ${iso}`} style={{ fontVariantNumeric: 'tabular-nums' }}>
      {label}
    </time>
  );
}

function ResourceCell({ finding }: { finding: FindingRow }) {
  const r = finding.resource;
  // findings.resource_id is nullable and the row survives its resource being deleted. Say which
  // it is: a blank cell reads as a rendering bug.
  if (!r) return <span style={{ color: 'var(--text-secondary)' }}>—</span>;

  return (
    <span style={{ display: 'inline-flex', alignItems: 'baseline', gap: 'var(--space-1)', minWidth: 0 }}>
      <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-2xs)' }}>{r.kind}</span>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>{r.name}</span>
      {r.namespace && (
        <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-2xs)' }}>· {r.namespace}</span>
      )}
    </span>
  );
}

/** The reason a coverage gap could not be checked, shown inline and muted. A not_assessable
 * finding with no stated reason is still a gap — say so rather than rendering nothing, so the
 * badge is never left unexplained. */
function GapReason({ reason }: { reason: string | null }) {
  return (
    <span
      style={{
        display: 'block',
        marginTop: '2px',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        color: 'var(--text-secondary)',
      }}
    >
      {reason?.trim() ? reason : 'No reason recorded for why this could not be assessed.'}
    </span>
  );
}

/** Zero evidence is load-bearing, not an empty cell: the engine refuses to triage a finding
 * with no observations (422 — "a finding with no evidence is a rumour"), so this 0 is the
 * explanation for a detail page with no AI section and no button that works. */
function EvidenceCount({ n }: { n: number }) {
  return (
    <span style={{ color: n === 0 ? 'var(--text-secondary)' : 'var(--text-primary)' }}>
      {n}
      <span className="vs-visually-hidden"> observation{n === 1 ? '' : 's'}</span>
    </span>
  );
}
