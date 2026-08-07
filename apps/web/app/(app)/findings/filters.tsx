'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState, useTransition, type ReactNode } from 'react';

import { SeverityBadge } from '@/components/ui/severity';
import { Toolbar, ToolbarDivider, ToolbarField } from '@/components/ui/toolbar';
import type { Assessment, Severity, UiStatus } from '@/lib/types';
import { ASSESSMENT_LABEL, NotAssessedBadge } from './assessment';
import type { AssessmentFacet, Facets } from './group';
import { StatusPill } from './status';
import { findingsHref, hasActiveFilters, toggle, type FindingFilters } from './query';

/* The findings FilterBar — one premium row above the queue.
 *
 * DESIGN.md's rule is "filters in one row above the content"; the faceted left rail is a
 * permitted exception, not a requirement, and a horizontal bar keeps the full page width for a
 * dense table. Every facet is a toggle here, so the bar reads at a glance: which severities are
 * live, which have zero, what's selected.
 *
 * Client only because it writes the URL; it holds NO filter state of its own (the one exception is
 * the search box's mid-typing draft). `filters` is a prop from the server and every control
 * navigates rather than setting state — that is what makes a filtered view a linkable URL and
 * keeps the query on the server where the data is. Counts stay visible even at zero: a facet that
 * vanishes when it empties leaves you unsure whether the filter or the data changed, and colour is
 * never the only signal (each chip carries a shape + word from SeverityBadge / StatusPill).
 */

export function Filters({
  filters,
  facets,
  assessmentFacet,
  total,
}: {
  filters: FindingFilters;
  facets: Facets;
  assessmentFacet: AssessmentFacet[];
  total: number;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const active = hasActiveFilters(filters);

  const go = (next: FindingFilters) => {
    startTransition(() => {
      router.push(findingsHref(next), { scroll: false });
    });
  };

  return (
    <div
      // aria-busy rather than a spinner: the table stays readable and interactive during the
      // transition, so the only thing that should change is what assistive tech announces.
      aria-busy={pending}
      style={{ opacity: pending ? 0.72 : 1, transition: 'opacity var(--motion-fast) var(--ease-standard)' }}
    >
      <Toolbar
        aria-label="Filter findings"
        end={
          <>
            <RuleSearch value={filters.rule} onSubmit={(rule) => go({ ...filters, rule })} />
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
              <span data-numeric style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                {total}
              </span>{' '}
              match{total === 1 ? '' : 'es'}
            </span>
            {active && (
              // A button, not a link: it clears state rather than navigating to a place. Uses the
              // same URL model — go() with an empty filter set produces the clean /findings URL.
              <button
                type="button"
                onClick={() => go({ severity: [], status: [], assessment: [], system: null, rule: null })}
                style={{
                  border: '1px solid var(--border-interactive)',
                  borderRadius: 'var(--radius-md)',
                  background: 'transparent',
                  color: 'var(--text-secondary)',
                  fontSize: 'var(--text-2xs)',
                  height: 'var(--row-compact)',
                  padding: '0 var(--space-3)',
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                }}
              >
                Clear
              </button>
            )}
          </>
        }
      >
        <ToolbarField label="Severity">
          <ChipGroup>
            {facets.severity.map(({ key, count }) => (
              <ToggleChip
                key={key}
                pressed={filters.severity.includes(key)}
                count={count}
                onClick={() => go({ ...filters, severity: toggle(filters.severity, key) as Severity[] })}
              >
                <SeverityBadge severity={key} variant="inline" />
              </ToggleChip>
            ))}
          </ChipGroup>
        </ToolbarField>

        <ToolbarDivider />

        <ToolbarField label="Status">
          <ChipGroup>
            {facets.status.map(({ key, count }) => (
              <ToggleChip
                key={key}
                pressed={filters.status.includes(key)}
                count={count}
                onClick={() => go({ ...filters, status: toggle(filters.status, key) as UiStatus[] })}
              >
                <StatusPill status={key} />
              </ToggleChip>
            ))}
          </ChipGroup>
        </ToolbarField>

        <ToolbarDivider />

        {/* Assessability. A `not_assessable` finding is a COVERAGE GAP, not a vulnerability — this
            facet isolates the gaps ("what could we not check") or hides them to work the real
            queue. Counts are exact head-counts (data.ts), not tallied from the capped list, so they
            stay honest past the row cap. */}
        <ToolbarField label="Assessment">
          <ChipGroup>
            {assessmentFacet.map(({ key, count }) => (
              <ToggleChip
                key={key}
                pressed={filters.assessment.includes(key)}
                count={count}
                onClick={() => go({ ...filters, assessment: toggle(filters.assessment, key) as Assessment[] })}
              >
                {key === 'not_assessable' ? (
                  <NotAssessedBadge variant="inline" />
                ) : (
                  <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', fontWeight: 600, letterSpacing: '0.04em' }}>
                    {ASSESSMENT_LABEL[key].toUpperCase()}
                  </span>
                )}
              </ToggleChip>
            ))}
          </ChipGroup>
        </ToolbarField>

        {/* Systems are whatever the connectors actually produced, so this is absent rather than an
            empty control on a single-system tenant — a lone "System" dropdown with one option is a
            question mark where there is no question. Single-select: rule_id has exactly one system,
            so two selected is an empty result by construction. */}
        {facets.systems.length > 1 && (
          <>
            <ToolbarDivider />
            <ToolbarField label="System" htmlFor="system-filter">
              <select
                id="system-filter"
                value={filters.system ?? ''}
                onChange={(e) => go({ ...filters, system: e.target.value || null })}
                style={{
                  border: '1px solid var(--border-interactive)',
                  borderRadius: 'var(--radius-md)',
                  background: 'var(--bg)',
                  color: 'var(--text-primary)',
                  height: 'var(--row-compact)',
                  padding: '0 var(--space-2)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 'var(--text-2xs)',
                  maxWidth: 220,
                }}
              >
                <option value="">All systems</option>
                {facets.systems.map(({ key, count }) => (
                  <option key={key} value={key}>
                    {key} ({count})
                  </option>
                ))}
              </select>
            </ToolbarField>
          </>
        )}
      </Toolbar>
    </div>
  );
}

/** A horizontal wrap of toggle chips inside a labelled toolbar field. */
function ChipGroup({ children }: { children: ReactNode }) {
  return <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', flexWrap: 'wrap' }}>{children}</div>;
}

/** One multi-select facet value, as a pressable chip. Selection is carried by THREE non-colour
 * channels — aria-pressed, a raised/tinted surface, and a leading check glyph — so it survives
 * greyscale and a screen reader, matching the console's SC 1.4.1 contract. A zero facet stays
 * pressable (unchecking the filter that emptied it is the next thing you want) but its count
 * recedes to --text-muted, which still clears 4.5:1. */
function ToggleChip({
  pressed,
  count,
  onClick,
  children,
}: {
  pressed: boolean;
  count: number;
  onClick: () => void;
  children: ReactNode;
}) {
  const dim = count === 0 && !pressed;

  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        height: 26,
        padding: '0 var(--space-2)',
        // --border-interactive on every state: the outline is the chip's only structural edge and
        // owes SC 1.4.11's 3:1, which --border (1.38:1) does not clear. The pressed accent border
        // clears it too (checked pair: --accent on all three surfaces ≥3:1 both themes).
        border: `1px solid ${pressed ? 'var(--accent)' : 'var(--border-interactive)'}`,
        borderRadius: 'var(--radius-full)',
        background: pressed ? 'var(--accent-soft)' : 'transparent',
        cursor: 'pointer',
        font: 'inherit',
        whiteSpace: 'nowrap',
        transition: 'background var(--motion-fast) var(--ease-standard), border-color var(--motion-fast) var(--ease-standard)',
      }}
    >
      <span
        aria-hidden="true"
        style={{ width: 8, fontSize: 'var(--text-2xs)', color: pressed ? 'var(--text-primary)' : 'var(--text-muted)' }}
      >
        {pressed ? '✓' : ''}
      </span>
      {children}
      <span
        data-numeric
        style={{ fontSize: 'var(--text-2xs)', color: dim ? 'var(--text-muted)' : 'var(--text-secondary)' }}
      >
        {count}
      </span>
    </button>
  );
}

function RuleSearch({ value, onSubmit }: { value: string | null; onSubmit: (v: string | null) => void }) {
  // The one place local state is correct: an input the user is mid-typing is not shareable state,
  // and pushing a URL per keystroke would fire a query per keystroke. It syncs FROM the URL on
  // navigation so Back, a pasted link, and Clear all land in the box. The match is a rule_id
  // PREFIX (KAFKA.ACL matches KAFKA.ACL.*) — the same predicate the facet view is bounded by, which
  // is what keeps the visible total and the facet counts from disagreeing.
  const [draft, setDraft] = useState(value ?? '');
  useEffect(() => setDraft(value ?? ''), [value]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(draft.trim() || null);
      }}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)' }}
    >
      <label htmlFor="rule-filter" className="vs-visually-hidden">
        Search by rule id (prefix)
      </label>
      <input
        id="rule-filter"
        name="rule"
        type="search"
        value={draft}
        placeholder="Search rule id…"
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => setDraft(e.target.value)}
        style={{
          border: '1px solid var(--border-interactive)',
          background: 'var(--bg)',
          color: 'var(--text-primary)',
          borderRadius: 'var(--radius-md)',
          padding: '0 var(--space-2)',
          height: 'var(--row-compact)',
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-2xs)',
          width: 190,
          maxWidth: '40vw',
        }}
      />
    </form>
  );
}
