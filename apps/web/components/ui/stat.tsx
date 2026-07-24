import type { ReactNode } from 'react';
import { IconArrowUp, IconArrowDown } from './icons';

/* StatTile / KPI — one big comparable number with a label, and an honest delta.
 *
 * Every dashboard here grows its own `Stat` (Identities has one inline; Overview has three
 * shapes of it). This is the shared one. The value is tabular-nums and large; the label is small
 * caps above or below; an optional delta carries BOTH an arrow (▲/▼) AND a signed number, so the
 * direction survives greyscale and colour-blindness — colour is never the only signal here either.
 *
 * `intent` decides whether "up" is good. For an open-critical count, up is BAD (red ↑); for a
 * coverage percentage, up is GOOD (positive ↑). Stating it at the call site keeps the tile from
 * guessing — a KPI that colours a rising breach count green is worse than no colour at all.
 */

export type StatTone = 'neutral' | 'good' | 'warn' | 'bad';

const TONE_COLOR: Record<StatTone, string> = {
  neutral: 'var(--text-primary)',
  good: 'var(--sev-low-fg)',
  warn: 'var(--sev-medium-fg)',
  bad: 'var(--sev-critical-fg)',
};

export function StatTile({
  label,
  value,
  unit,
  sub,
  tone = 'neutral',
  delta,
  size = 'md',
}: {
  label: string;
  value: ReactNode;
  /** e.g. "%", "ms" — set smaller and muted, never competing with the number. */
  unit?: string;
  /** One line of context under the value — what it is drawn from. */
  sub?: ReactNode;
  tone?: StatTone;
  /** A period-over-period change. `goodDirection` says which way is healthy. */
  delta?: { value: number; goodDirection?: 'up' | 'down'; label?: string };
  size?: 'sm' | 'md' | 'lg';
}) {
  const valueSize = size === 'lg' ? 'var(--text-4xl)' : size === 'sm' ? 'var(--text-2xl)' : 'var(--text-3xl)';
  const valueLeading = size === 'lg' ? 'var(--leading-4xl)' : size === 'sm' ? 'var(--leading-2xl)' : 'var(--leading-3xl)';

  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)', minWidth: 0 }}>
      <div
        style={{
          fontSize: 'var(--text-2xs)',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          color: 'var(--text-secondary)',
          fontWeight: 600,
        }}
      >
        {label}
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <span
          data-numeric
          style={{
            fontSize: valueSize,
            lineHeight: valueLeading,
            fontWeight: 680,
            letterSpacing: '-0.02em',
            color: TONE_COLOR[tone],
          }}
        >
          {value}
          {unit && (
            <span style={{ fontSize: '0.5em', fontWeight: 600, color: 'var(--text-muted)', marginLeft: 2 }}>{unit}</span>
          )}
        </span>
        {delta && <Delta {...delta} />}
      </div>
      {sub && (
        <div style={{ fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
          {sub}
        </div>
      )}
    </div>
  );
}

function Delta({ value, goodDirection = 'up', label }: { value: number; goodDirection?: 'up' | 'down'; label?: string }) {
  if (value === 0) {
    return (
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
        no change{label ? ` ${label}` : ''}
      </span>
    );
  }
  const up = value > 0;
  const isGood = (up && goodDirection === 'up') || (!up && goodDirection === 'down');
  const color = isGood ? 'var(--sev-low-fg)' : 'var(--sev-high-fg)';
  return (
    <span
      style={{ display: 'inline-flex', alignItems: 'center', gap: 2, fontSize: 'var(--text-2xs)', fontWeight: 600, color, fontVariantNumeric: 'tabular-nums' }}
    >
      {up ? <IconArrowUp size={12} /> : <IconArrowDown size={12} />}
      <span aria-hidden="true">
        {up ? '+' : ''}
        {value}
      </span>
      <span className="vs-visually-hidden">
        {up ? 'up' : 'down'} {Math.abs(value)}, {isGood ? 'improving' : 'worsening'}
      </span>
      {label && <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>{label}</span>}
    </span>
  );
}
