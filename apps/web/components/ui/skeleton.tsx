import type { Density } from './table';

/* Skeletons, not spinners: they preserve layout, communicate shape, and cause no reflow.
 * A spinner says "wait"; a skeleton says "here is what is coming".
 *
 * The shimmer keyframes live here rather than globals.css so the animation ships only on
 * routes that actually render a skeleton. prefers-reduced-motion is honoured globally.
 */

const SHIMMER = `
@keyframes vs-shimmer {
  0%   { opacity: 0.45; }
  50%  { opacity: 0.85; }
  100% { opacity: 0.45; }
}`;

export function Skeleton({
  width = '100%',
  height = 12,
  radius = 'var(--radius-sm)',
}: {
  width?: string | number;
  height?: string | number;
  radius?: string;
}) {
  return (
    <>
      <style>{SHIMMER}</style>
      <span
        aria-hidden="true"
        style={{
          display: 'block',
          width,
          height,
          borderRadius: radius,
          background: 'var(--surface-raised)',
          animation: 'vs-shimmer 1.6s ease-in-out infinite',
        }}
      />
    </>
  );
}

const ROW_HEIGHT: Record<Density, string> = {
  compact: 'var(--row-compact)',
  default: 'var(--row-default)',
  relaxed: 'var(--row-relaxed)',
};

/** Placeholder rows for a loading table.
 *
 * `density` MUST match the real table's density: if skeleton rows are not exactly the final
 * row height, the page jumps when data lands (CLS) — which defeats the entire point of using
 * a skeleton instead of a spinner. */
export function SkeletonRows({
  count = 8,
  density = 'default',
  columns = [{ width: '40%' }, { width: '20%' }, { width: '15%' }, { width: '10%' }],
}: {
  count?: number;
  density?: Density;
  columns?: { width: string }[];
}) {
  return (
    <div role="status" aria-label="Loading">
      <span className="vs-visually-hidden">Loading…</span>
      {Array.from({ length: count }, (_, i) => (
        <div
          key={i}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--space-4)',
            height: ROW_HEIGHT[density],
            padding: '0 var(--space-3)',
            borderBottom: '1px solid var(--border)',
          }}
        >
          {columns.map((c, j) => (
            <Skeleton key={j} width={c.width} />
          ))}
        </div>
      ))}
    </div>
  );
}
