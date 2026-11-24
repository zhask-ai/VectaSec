import type { ReactNode } from 'react';

/* Page + section headers.
 *
 * Every route currently hand-rolls its own `<h1 style={{fontSize:'var(--text-xl)'…}}>` plus a
 * flex row for its provenance meta (see Overview's Shell, Scans' Page, Identities' Page). This is
 * that pattern, extracted: one <h1> per route, an optional one-line description, a right-aligned
 * actions slot, and a provenance `meta` line — because an unlabelled view reads as untrustworthy
 * and a stale one with no "as of" reads as fresh.
 *
 * PageHeader owns the route's single <h1>. SectionHeader is an <h2> for a band within a page and
 * must never be the only heading — it structures, it does not title.
 */

export function PageHeader({
  title,
  description,
  meta,
  actions,
}: {
  title: string;
  /** One calm sentence on what this view answers. Optional — omit rather than pad. */
  description?: string;
  /** Provenance: "6 systems · scanned 4m ago". Right-aligned, tabular. */
  meta?: ReactNode;
  /** Primary/secondary actions for the whole page. */
  actions?: ReactNode;
}) {
  return (
    <header style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          gap: 'var(--space-4)',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-3)', minWidth: 0 }}>
          <h1
            style={{
              margin: 0,
              fontSize: 'var(--text-2xl)',
              lineHeight: 'var(--leading-2xl)',
              fontWeight: 650,
              letterSpacing: '-0.02em',
              color: 'var(--text-primary)',
            }}
          >
            {title}
          </h1>
          {meta && (
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
              {meta}
            </span>
          )}
        </div>
        {actions && <div className="vs-pagehead-actions">{actions}</div>}
      </div>
      {description && (
        <p
          style={{
            margin: 0,
            maxWidth: '68ch',
            fontSize: 'var(--text-base)',
            lineHeight: 'var(--leading-lg)',
            color: 'var(--text-secondary)',
          }}
        >
          {description}
        </p>
      )}
    </header>
  );
}

export function SectionHeader({
  title,
  meta,
  actions,
}: {
  title: string;
  meta?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'baseline',
        justifyContent: 'space-between',
        gap: 'var(--space-3)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', minWidth: 0 }}>
        <h2
          style={{
            margin: 0,
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            fontWeight: 600,
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
            color: 'var(--text-secondary)',
          }}
        >
          {title}
        </h2>
        {meta && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{meta}</span>}
      </div>
      {actions && <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>{actions}</div>}
    </div>
  );
}
