'use client';

import Link from 'next/link';
import type { Route } from 'next';
import { useState } from 'react';

import { IconChevronRight } from '@/components/ui/icons';
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
 * ROW ANATOMY: one composite "Finding" cell — the title on top, `rule_id · SYSTEM` as a quiet
 * mono subline — instead of separate Rule / System / Title columns. Three columns of competing
 * text made every row a different height (long titles wrapped three lines while rule ids ate a
 * third of the table saying less), which is what made the queue read as clutter. One flexible
 * cell, title clamped to a line, gives every row the same silhouette; the full title rides the
 * tooltip and the detail page. "mixed" / "+N not assessed" annotations live on the subline for
 * the same reason.
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
    <Table density="relaxed" fixed caption="Findings grouped by rule, sorted by severity then most recently seen">
      <THead>
        <TR>
          <TH width="32px">
            <span className="vs-visually-hidden">Expand</span>
          </TH>
          {/* aria-sort on the two columns the server actually ordered by. Claiming a sort we did
              not perform would be worse than claiming none. */}
          <TH width="118px" sort="desc">
            Severity
          </TH>
          {/* An explicit width claim: with auto table layout, a column whose content can all
              ellipsis to nothing gets bullied by columns that cannot — and the title is the one
              cell a human actually reads. */}
          <TH width="36%">Finding</TH>
          <TH width="20%">Resource</TH>
          <TH width="120px">Status</TH>
          {/* Counts are compared, so they are right-aligned and tabular. Dates are read, not
              compared, so they are not. */}
          <TH width="64px" numeric>
            Evidence
          </TH>
          <TH width="72px">Age</TH>
          <TH width="88px" sort="desc">
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

/** The composite Finding cell: one clamped title line over a quiet `rule · SYSTEM` subline.
 * The subline is plain muted mono — boxed chips here multiplied by 48 rows was chip soup. */
function FindingCell({
  title,
  ruleId,
  href,
  note,
  children,
}: {
  title: string;
  ruleId: string;
  href?: Route;
  /** Inline annotations after the rule — "mixed", "+2 not assessed". */
  note?: React.ReactNode;
  /** An optional block under the subline (the coverage-gap reason). */
  children?: React.ReactNode;
}) {
  const titleEl = (
    <span
      title={title}
      style={{
        display: 'block',
        fontSize: 'var(--text-sm)',
        fontWeight: 500,
        color: 'var(--text-primary)',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
      }}
    >
      {title}
    </span>
  );
  return (
    <span style={{ display: 'grid', gap: 1, minWidth: 0, padding: 'var(--space-2) 0' }}>
      {href ? (
        <Link href={href} style={{ minWidth: 0 }}>
          {titleEl}
        </Link>
      ) : (
        titleEl
      )}
      <span
        style={{
          display: 'flex',
          alignItems: 'baseline',
          gap: 'var(--space-2)',
          minWidth: 0,
          fontSize: 'var(--text-2xs)',
          color: 'var(--text-muted)',
        }}
      >
        <span style={{ fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {ruleId}
        </span>
        <span aria-hidden="true">·</span>
        <span style={{ letterSpacing: '0.04em' }}>{systemOf(ruleId)}</span>
        {note}
      </span>
      {children}
    </span>
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
      <TD>
        <FindingCell title={finding.title} ruleId={group.ruleId} href={findingHref(finding.id)}>
          {gap && <GapReason reason={finding.assessmentReason} />}
        </FindingCell>
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
      {/* The WHOLE row is the toggle target (a 20px caret alone is a dexterity test); the button
          stays inside as the named, focusable control. stopPropagation on it prevents the double
          fire when the button itself is the click. */}
      <tr
        data-toggle-row
        onClick={onToggle}
        style={{ height: 'var(--vs-row-h)', borderBottom: '1px solid var(--border)' }}
      >
        <td style={{ padding: '0 var(--space-3)' }}>
          <button
            type="button"
            className="vs-rowchevron"
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
            aria-expanded={open}
          >
            <IconChevronRight size={13} />
            <span className="vs-visually-hidden">
              {open ? 'Collapse' : 'Expand'} {group.count} occurrences of {group.ruleId}
            </span>
          </button>
        </td>

        <td style={{ padding: '0 var(--space-3)' }}>
          {/* The ×N is the whole point of the row: one badge, one decision. When every occurrence
              is a coverage gap the whole group is "we could not check", so it shows the neutral
              mark instead of a severity — the stored severity only drove its sort position. */}
          {group.allNotAssessable ? (
            <NotAssessedBadge count={group.count} />
          ) : (
            // Count the ASSESSED occurrences here — the gaps are tallied separately on the
            // subline, so the ×N beside a severity never silently includes a coverage gap.
            <SeverityBadge severity={group.severity} count={group.assessedCount} />
          )}
        </td>

        <td style={{ padding: '0 var(--space-3)' }}>
          <FindingCell
            title={group.title}
            ruleId={group.ruleId}
            note={
              <>
                {/* A detector may override severity per hit (scan.py: `h.severity or
                    d.severity`), so a group can genuinely be mixed. Saying so prevents the worst
                    outcome of grouping — a critical occurrence hidden inside a row labelled with
                    a lower severity. */}
                {!group.allNotAssessable && group.mixedSeverity && (
                  <span style={{ color: 'var(--sev-medium-fg)', fontWeight: 600 }}>mixed severity</span>
                )}
                {/* A partly-uncheckable group: some occurrences are real findings, some are
                    coverage gaps. Flag the gaps so the badge is not read as covering all N. */}
                {!group.allNotAssessable && group.notAssessableCount > 0 && (
                  <span>+{group.notAssessableCount} not assessed</span>
                )}
              </>
            }
          />
        </td>
        <td style={{ padding: '0 var(--space-3)', color: 'var(--text-muted)', fontSize: 'var(--text-xs)' }}>
          {resourceCount} resource{resourceCount === 1 ? '' : 's'}
        </td>
        <td style={{ padding: '0 var(--space-3)' }}>
          <span style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
            {group.statusCounts.map(({ status, count }) => (
              <StatusPill key={status} status={status} count={count} />
            ))}
          </span>
        </td>
        <td data-numeric style={{ padding: '0 var(--space-3)', textAlign: 'right' }}>
          <EvidenceCount n={group.evidenceCount} />
        </td>
        <td style={{ padding: '0 var(--space-3)', color: 'var(--text-muted)' }}>
          <Age label={group.firstSeenLabel} iso={group.firstSeenIso} />
        </td>
        <td style={{ padding: '0 var(--space-3)', color: 'var(--text-muted)' }}>
          <time dateTime={group.lastSeenIso} title={group.lastSeenIso}>
            {group.lastSeenLabel}
          </time>
        </td>
      </tr>

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
 * The Finding column is left empty on purpose (bar a per-occurrence coverage-gap reason): title
 * and rule are identical to the group header directly above, and repeating them per row is
 * exactly the noise grouping exists to remove. What differs — resource, status, evidence, age,
 * recency — is what stays.
 */
function OccurrenceRow({ finding }: { finding: FindingRow }) {
  const cell: React.CSSProperties = { padding: '0 var(--space-3)' };
  return (
    <tr style={{ height: 'var(--row-default)', borderBottom: '1px solid var(--border)', background: 'var(--bg)' }}>
      <td />
      <td style={{ ...cell, textAlign: 'left' }}>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <span aria-hidden="true" style={{ color: 'var(--text-muted)' }}>
            ↳
          </span>
          {finding.assessment === 'not_assessable' ? (
            <NotAssessedBadge variant="inline" />
          ) : (
            <SeverityBadge severity={finding.severity} variant="inline" />
          )}
        </span>
      </td>
      {/* The otherwise-empty Finding column carries the coverage-gap reason for this occurrence —
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
    // Every segment may shrink: an unshrinkable namespace like `deploy/dev/docker-compose.yml`
    // widens the whole column and starves the titles two cells over. Kind keeps a floor (it is
    // one short word); name and namespace truncate with their full values on the tooltip.
    <span style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-1)', minWidth: 0, maxWidth: '100%' }}>
      <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)', flexShrink: 0 }}>{r.kind}</span>
      <span
        title={r.name}
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-2xs)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          minWidth: 40,
        }}
      >
        {r.name}
      </span>
      {r.namespace && (
        <span
          title={r.namespace}
          style={{
            color: 'var(--text-muted)',
            fontSize: 'var(--text-2xs)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            flexShrink: 2,
            minWidth: 24,
          }}
        >
          · {r.namespace}
        </span>
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
