import type { ReactNode } from 'react';

/* Toolbar / FilterBar — the single row above a table where filters, search and view-actions live.
 *
 * The rule this encodes: filters go in ONE row above the content, not in a left rail that steals
 * horizontal space from a dense table and not scattered into the table header. (Findings' faceted
 * left rail is the deliberate exception — a queue with many multi-select facets earns a rail; a
 * table with two or three filters wants a bar.)
 *
 * Layout: a left cluster (filters, in source/tab order) and a right cluster (search, density,
 * export). It wraps rather than scrolls, and never forces the page into horizontal scroll.
 */

export function Toolbar({
  children,
  end,
  'aria-label': ariaLabel = 'Filters and actions',
}: {
  /** The left cluster — filter controls, in reading order. */
  children: ReactNode;
  /** The right cluster — search, view toggles, export. */
  end?: ReactNode;
  'aria-label'?: string;
}) {
  return (
    <div
      role="group"
      aria-label={ariaLabel}
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 'var(--space-3)',
        flexWrap: 'wrap',
        padding: 'var(--space-2) var(--space-3)',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', minWidth: 0 }}>
        {children}
      </div>
      {end && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>{end}</div>
      )}
    </div>
  );
}

/** A labelled slot inside the toolbar — small caps label beside its control. */
export function ToolbarField({ label, htmlFor, children }: { label: string; htmlFor?: string; children: ReactNode }) {
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
      <label
        htmlFor={htmlFor}
        style={{
          fontSize: 'var(--text-2xs)',
          fontWeight: 600,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          color: 'var(--text-secondary)',
        }}
      >
        {label}
      </label>
      {children}
    </div>
  );
}

/** A hairline vertical divider between toolbar clusters. */
export function ToolbarDivider() {
  return <span aria-hidden="true" style={{ width: 1, alignSelf: 'stretch', background: 'var(--border)', margin: '0 var(--space-1)' }} />;
}
