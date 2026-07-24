import type { ReactNode } from 'react';

/* Chart kit shared rules. No charting library ships — these are hand-built SVG marks, because a
 * dependency that pulls its own colours and its own axis conventions is exactly what breaks a
 * design system's consistency, and because a console this dense cannot afford a runtime for a
 * sparkline.
 *
 * The dataviz non-negotiables, encoded here so every chart obeys them:
 *  · CATEGORICAL is a FIXED-ORDER palette, assigned by position and NEVER cycled past its end
 *    (a 9th series is a design smell, not a colour lookup). It is for nominal categories only —
 *    never for status. Status uses the reserved severity tokens, always with an icon+label.
 *  · One axis carries scale; the other carries category. Gridlines are recessive (--grid), thin,
 *    and sit UNDER the marks. All text is an ink token (--text-*), never a series colour.
 *  · Every chart carries a text alternative — an SVG <title>/<desc> and, where a distribution
 *    matters, a visually-hidden table — so the data survives without the pixels.
 */

/** Fixed categorical order. Index in, CSS var out. Throws past 8 rather than silently repeating. */
export const CATEGORICAL = ['--cat-1', '--cat-2', '--cat-3', '--cat-4', '--cat-5', '--cat-6', '--cat-7', '--cat-8'] as const;

export function categorical(i: number): string {
  if (i < 0 || i >= CATEGORICAL.length) {
    // A chart needing a 9th hue wants a rethink (group the tail into "other"), not a wrapped index.
    return 'var(--text-muted)';
  }
  return `var(${CATEGORICAL[i]})`;
}

/** Compact integer formatting for axis/value labels: 1_240 → "1.2k". */
export function compact(n: number): string {
  if (Math.abs(n) >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, '')}M`;
  if (Math.abs(n) >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, '')}k`;
  return String(n);
}

/** The visually-hidden table alternative for a chart. Screen readers get the numbers; the SVG
 * stays aria-hidden and decorative. */
export function ChartTable({
  caption,
  columns,
  rows,
}: {
  caption: string;
  columns: string[];
  rows: (ReactNode | string | number)[][];
}) {
  return (
    <table className="vs-visually-hidden">
      <caption>{caption}</caption>
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c} scope="col">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            {r.map((cell, j) => (
              <td key={j}>{cell}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** A shared legend for ≥2 series. Each swatch pairs colour with a label — colour is never the
 * only key. Pass the swatch colour as a CSS var string. */
export function Legend({ items }: { items: { color: string; label: ReactNode; value?: ReactNode }[] }) {
  return (
    <ul
      style={{
        listStyle: 'none',
        display: 'flex',
        flexWrap: 'wrap',
        gap: 'var(--space-1) var(--space-3)',
        margin: 0,
        padding: 0,
      }}
    >
      {items.map((it, i) => (
        <li key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: 2, background: it.color, flexShrink: 0 }} />
          <span>{it.label}</span>
          {it.value !== undefined && (
            <span data-numeric style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              {it.value}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}
