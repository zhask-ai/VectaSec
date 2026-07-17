'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState, useTransition } from 'react';

import { SeverityBadge } from '@/components/ui/severity';
import type { Severity, UiStatus } from '@/lib/types';
import type { Facets } from './group';
import { StatusPill } from './status';
import { findingsHref, toggle, type FindingFilters } from './query';

/* Facets.
 *
 * Client only because it writes the URL; it holds no filter state of its own. The URL is the
 * state — `filters` is a prop from the server, and every control below navigates rather than
 * setting anything. That is what makes a filtered view linkable, and what keeps the query on
 * the server where the data is.
 *
 * Counts are always visible, including zeros: a facet without a count forces a click to learn
 * nothing, and one that vanishes when it empties leaves you unsure whether the filter or the
 * data changed.
 */

export function Filters({
  filters,
  facets,
  total,
}: {
  filters: FindingFilters;
  facets: Facets;
  total: number;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();

  const go = (next: FindingFilters) => {
    startTransition(() => {
      router.push(findingsHref(next), { scroll: false });
    });
  };

  return (
    <aside
      aria-label="Filters"
      // aria-busy rather than a spinner: the table stays readable and interactive during the
      // transition, so the only thing that should change is what assistive tech announces.
      aria-busy={pending}
      style={{
        display: 'grid',
        gap: 'var(--space-4)',
        alignContent: 'start',
        opacity: pending ? 0.7 : 1,
        transition: 'opacity 120ms ease',
      }}
    >
      <RuleSearch value={filters.rule} onSubmit={(rule) => go({ ...filters, rule })} />

      <Facet label="Severity">
        {facets.severity.map(({ key, count }) => (
          <FacetRow
            key={key}
            checked={filters.severity.includes(key)}
            count={count}
            onChange={() => go({ ...filters, severity: toggle(filters.severity, key) as Severity[] })}
          >
            <SeverityBadge severity={key} variant="inline" />
          </FacetRow>
        ))}
      </Facet>

      <Facet label="Status">
        {facets.status.map(({ key, count }) => (
          <FacetRow
            key={key}
            checked={filters.status.includes(key)}
            count={count}
            onChange={() => go({ ...filters, status: toggle(filters.status, key) as UiStatus[] })}
          >
            <StatusPill status={key} />
          </FacetRow>
        ))}
      </Facet>

      {/* Systems are whatever the connectors actually produced, so this facet is absent rather
          than empty on a Kafka-only tenant — an empty "System" list is a question mark where
          there is no question. */}
      {facets.systems.length > 1 && (
        <Facet label="System">
          {facets.systems.map(({ key, count }) => (
            <FacetRow
              key={key}
              checked={filters.system === key}
              count={count}
              // Single-select: rule_id has exactly one system, so two of them selected is an
              // empty result by construction. A radio would be a lie about multi-select.
              onChange={() => go({ ...filters, system: filters.system === key ? null : key })}
            >
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>{key}</span>
            </FacetRow>
          ))}
        </Facet>
      )}

      <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        <span data-numeric>{total}</span> finding{total === 1 ? '' : 's'} match
      </div>
    </aside>
  );
}

function RuleSearch({ value, onSubmit }: { value: string | null; onSubmit: (v: string | null) => void }) {
  // The one place local state is correct: an input the user is mid-typing is not shareable
  // state, and pushing a URL per keystroke would fire a query per keystroke. It syncs FROM the
  // URL on navigation so Back, a pasted link, and "Clear filters" all land in the box.
  const [draft, setDraft] = useState(value ?? '');
  useEffect(() => setDraft(value ?? ''), [value]);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(draft.trim() || null);
      }}
      style={{ display: 'grid', gap: 'var(--space-2)' }}
    >
      <label
        htmlFor="rule-filter"
        style={{
          fontSize: 'var(--text-2xs)',
          fontWeight: 600,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          color: 'var(--text-secondary)',
        }}
      >
        Rule
      </label>
      <input
        id="rule-filter"
        name="rule"
        type="search"
        value={draft}
        placeholder="KAFKA.ACL"
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => setDraft(e.target.value)}
        style={{
          // --border-interactive, not --border: this outline is the only thing that says
          // "control" here, and --border is 1.38:1 (globals.css says so).
          border: '1px solid var(--border-interactive)',
          background: 'var(--bg)',
          color: 'var(--text-primary)',
          borderRadius: 'var(--radius-md)',
          padding: '0 var(--space-2)',
          height: 'var(--row-compact)',
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-2xs)',
          width: '100%',
        }}
      />
      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        Prefix match. Press Enter.
      </p>
    </form>
  );
}

function Facet({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <fieldset style={{ border: 0, margin: 0, padding: 0, display: 'grid', gap: '2px' }}>
      <legend
        style={{
          padding: 0,
          marginBottom: 'var(--space-1)',
          fontSize: 'var(--text-2xs)',
          fontWeight: 600,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          color: 'var(--text-secondary)',
        }}
      >
        {label}
      </legend>
      {children}
    </fieldset>
  );
}

function FacetRow({
  checked,
  count,
  onChange,
  children,
}: {
  checked: boolean;
  count: number;
  onChange: () => void;
  children: React.ReactNode;
}) {
  // A zero facet stays clickable — unchecking the filter that emptied it is exactly what the
  // user wants next — but it recedes.
  //
  // The recession is NOT `opacity`. Opacity composites the whole row against the page, and at
  // 0.55 over --bg that took --text-secondary from 8.64:1 to 3.34:1 and a severity label from
  // 8.51:1 to 3.27:1 (2.59:1 in light) — under SC 1.4.3's 4.5:1 floor, on a row this component
  // deliberately keeps ACTIVE, so the inactive-component exemption does not apply. And every
  // severity renders at zero on an unfiltered view (buildFacets emits the full key list), so
  // this was the default state of the page, not an edge case.
  //
  // Recede with a token that still passes instead: --text-muted clears 4.5:1 on --bg in both
  // themes (`pnpm contrast` asserts it), and the badge keeps its own full-contrast colour.
  // "A facet count nobody can read" is the same failure as "a facet with no count".
  const dim = count === 0 && !checked;

  return (
    <label
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-2)',
        height: 'var(--row-compact)',
        padding: '0 var(--space-2)',
        borderRadius: 'var(--radius-sm)',
        cursor: 'pointer',
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        style={{ accentColor: 'var(--focus-ring)', margin: 0 }}
      />
      <span style={{ flex: 1, minWidth: 0 }}>{children}</span>
      <span
        data-numeric
        style={{
          fontSize: 'var(--text-2xs)',
          color: dim ? 'var(--text-muted)' : 'var(--text-secondary)',
        }}
      >
        {count}
      </span>
    </label>
  );
}
