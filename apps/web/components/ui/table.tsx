import type { ReactNode, CSSProperties } from 'react';

/* Table primitives for a findings queue — closer to a log viewer than to a SaaS data grid.
 *
 * Density is a feature: analysts scan, and a console that hides data behind cards gets
 * abandoned for a CSV export. Hence 32/40/48px rows rather than the general-enterprise
 * 40/48/56 — and when density is tight, shrink PADDING, never type. 11px is the floor.
 *
 * No zebra striping: it collides with hover, selection, and severity tint states, which are
 * all doing real work here. 1px dividers instead.
 */

export type Density = 'compact' | 'default' | 'relaxed';

const ROW_HEIGHT: Record<Density, string> = {
  compact: 'var(--row-compact)',
  default: 'var(--row-default)',
  relaxed: 'var(--row-relaxed)',
};

export function Table({
  children,
  density = 'default',
  caption,
}: {
  children: ReactNode;
  density?: Density;
  /** Visually hidden but read aloud — a bare grid of cells is meaningless to a screen reader. */
  caption?: string;
}) {
  return (
    <div style={{ overflowX: 'auto', width: '100%' }}>
      <table
        data-density={density}
        style={
          {
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: 'var(--text-xs)',
            lineHeight: 'var(--leading-xs)',
            '--vs-row-h': ROW_HEIGHT[density],
          } as CSSProperties
        }
      >
        {caption && <caption className="vs-visually-hidden">{caption}</caption>}
        {children}
      </table>
    </div>
  );
}

/** Sticky header — non-negotiable at our row counts. */
export function THead({ children }: { children: ReactNode }) {
  return (
    <thead
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 1,
        background: 'var(--surface)',
      }}
    >
      {children}
    </thead>
  );
}

export function TBody({ children }: { children: ReactNode }) {
  return <tbody>{children}</tbody>;
}

export function TR({
  children,
  selected = false,
}: {
  children: ReactNode;
  selected?: boolean;
}) {
  return (
    <tr
      data-selected={selected || undefined}
      style={{
        height: 'var(--vs-row-h)',
        borderBottom: '1px solid var(--border)',
        background: selected ? 'var(--surface-raised)' : 'transparent',
      }}
    >
      {children}
    </tr>
  );
}

/** `numeric` right-aligns and switches on tabular figures so digits line up column-wise.
 * Qualitative numbers — dates, IDs, ports — stay left-aligned; they are read, not compared.
 * `sort` renders the indicator; the header must match its column's alignment. */
export function TH({
  children,
  numeric = false,
  sort,
  width,
}: {
  children: ReactNode;
  numeric?: boolean;
  sort?: 'asc' | 'desc' | 'none';
  width?: string;
}) {
  return (
    <th
      scope="col"
      aria-sort={sort ? (sort === 'none' ? 'none' : `${sort}ending`) : undefined}
      style={{
        width,
        textAlign: numeric ? 'right' : 'left',
        padding: '0 var(--space-3)',
        height: 'var(--row-compact)',
        borderBottom: '1px solid var(--border-strong)',
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      {children}
      {sort && sort !== 'none' && <span aria-hidden="true"> {sort === 'asc' ? '↑' : '↓'}</span>}
    </th>
  );
}

export function TD({
  children,
  numeric = false,
  mono = false,
  muted = false,
}: {
  children: ReactNode;
  numeric?: boolean;
  /** Evidence, IDs, fingerprints, config. Evidence in a proportional font does not read as
   *  evidence. */
  mono?: boolean;
  muted?: boolean;
}) {
  return (
    <td
      data-numeric={numeric || undefined}
      style={{
        textAlign: numeric ? 'right' : 'left',
        padding: '0 var(--space-3)',
        color: muted ? 'var(--text-muted)' : 'var(--text-primary)',
        fontFamily: mono ? 'var(--font-mono)' : 'inherit',
        verticalAlign: 'middle',
      }}
    >
      {children}
    </td>
  );
}
