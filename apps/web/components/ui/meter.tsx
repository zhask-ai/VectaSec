import type { ReactNode } from 'react';

/* Meter + ProgressRing — bounded-value marks (a fraction of a known whole), as opposed to a
 * StatTile (an unbounded count) or a chart (a distribution over time/category).
 *
 * Meter is a thin horizontal bar for a ratio: coverage %, controls attested, quota used. It is a
 * real <meter> role via aria, and it states the numbers in text beside it — the bar is the glance,
 * the text is the truth.
 *
 * ProgressRing is the posture gauge: one 0–100 score on an arc, the grade colour in the centre.
 * The score is always shown as a numeral too (a ring alone is not a number), and colour follows
 * the posture grade, never a raw hue — so it reads on the same A–F scale as the rest of the app.
 */

export function Meter({
  value,
  max = 100,
  label,
  tone = 'accent',
  showValue = true,
}: {
  value: number;
  max?: number;
  label?: string;
  tone?: 'accent' | 'good' | 'warn' | 'bad' | 'neutral';
  showValue?: boolean;
}) {
  const pct = max <= 0 ? 0 : Math.max(0, Math.min(1, value / max));
  const color =
    tone === 'good' ? 'var(--sev-low-solid)'
    : tone === 'warn' ? 'var(--sev-medium-solid)'
    : tone === 'bad' ? 'var(--sev-critical-solid)'
    : tone === 'neutral' ? 'var(--text-muted)'
    : 'var(--accent)';

  return (
    <div style={{ display: 'grid', gap: 4 }}>
      {(label || showValue) && (
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-2)', fontSize: 'var(--text-2xs)' }}>
          {label && <span style={{ color: 'var(--text-secondary)' }}>{label}</span>}
          {showValue && (
            <span data-numeric style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
              {Math.round(pct * 100)}%
            </span>
          )}
        </div>
      )}
      <div
        role="meter"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={label}
        style={{ height: 6, borderRadius: 'var(--radius-full)', background: 'var(--border)', overflow: 'hidden' }}
      >
        <div style={{ width: `${pct * 100}%`, height: '100%', background: color, borderRadius: 'var(--radius-full)' }} />
      </div>
    </div>
  );
}

export function ProgressRing({
  value,
  max = 100,
  size = 96,
  thickness = 8,
  color = 'var(--accent)',
  label,
  sublabel,
  center,
}: {
  value: number;
  max?: number;
  size?: number;
  thickness?: number;
  /** The arc colour. For posture, pass gradeColor(grade) so it tracks the A–F scale. */
  color?: string;
  label?: string;
  sublabel?: ReactNode;
  /** Override the centre content (defaults to the value numeral). */
  center?: ReactNode;
}) {
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  const pct = max <= 0 ? 0 : Math.max(0, Math.min(1, value / max));
  const dash = c * pct;

  return (
    <div style={{ display: 'inline-grid', placeItems: 'center', gap: 'var(--space-1)' }}>
      <div style={{ position: 'relative', width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          role="meter"
          aria-valuenow={value}
          aria-valuemin={0}
          aria-valuemax={max}
          aria-label={label ?? 'score'}
          style={{ transform: 'rotate(-90deg)' }}
        >
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={thickness} />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={thickness}
            strokeLinecap="round"
            strokeDasharray={`${dash} ${c - dash}`}
          />
        </svg>
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'grid',
            placeItems: 'center',
            textAlign: 'center',
          }}
        >
          {center ?? (
            <span data-numeric style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)', lineHeight: 1 }}>
              {value}
            </span>
          )}
        </div>
      </div>
      {sublabel && <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{sublabel}</div>}
    </div>
  );
}
