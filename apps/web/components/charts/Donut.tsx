'use client';

import { useState, type ReactNode } from 'react';
import { categorical, ChartTable, Legend } from './utils';

/* Donut — a distribution over NOMINAL categories (findings by system, resources by kind). Uses
 * the fixed categorical palette, assigned by position, never status colour: a donut of "systems"
 * must not borrow the red that means critical.
 *
 * A donut, not a pie: the hole holds the total, which is the number people actually want, and the
 * ring makes part-to-whole legible without asking anyone to compare wedge angles precisely (that
 * is what the legend's values are for). Segments are sorted largest-first so the eye starts at 12
 * o'clock with the biggest share. A legend is mandatory — a wedge with no label is a colour
 * riddle — and a hidden table carries the exact numbers.
 */

export type DonutSlice = { label: string; value: number };

export function Donut({
  data,
  size = 132,
  thickness = 16,
  centerLabel,
  caption = 'Distribution',
}: {
  data: DonutSlice[];
  size?: number;
  thickness?: number;
  /** Defaults to the summed total + "total". */
  centerLabel?: ReactNode;
  caption?: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const slices = [...data].filter((d) => d.value > 0).sort((a, b) => b.value - a.value);
  const total = slices.reduce((s, d) => s + d.value, 0);

  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;

  if (total === 0) {
    return (
      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>No data to chart yet.</p>
    );
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
      <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          role="img"
          aria-label={`${caption}: ${slices.map((s) => `${s.label} ${s.value}`).join(', ')}`}
          style={{ transform: 'rotate(-90deg)' }}
        >
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={thickness} />
          {slices.map((s, i) => {
            const frac = s.value / total;
            const dash = c * frac;
            const seg = (
              <circle
                key={i}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={categorical(i)}
                strokeWidth={hover === i ? thickness + 2 : thickness}
                strokeDasharray={`${dash} ${c - dash}`}
                strokeDashoffset={-offset}
                style={{ opacity: hover === null || hover === i ? 1 : 0.45, transition: 'opacity var(--motion-fast) var(--ease-standard)' }}
                onMouseEnter={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
              />
            );
            offset += dash;
            return seg;
          })}
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', textAlign: 'center' }}>
          {centerLabel ?? (
            <div style={{ display: 'grid', gap: 0 }}>
              <span data-numeric style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, letterSpacing: '-0.02em', lineHeight: 1, color: 'var(--text-primary)' }}>
                {hover === null ? total : slices[hover].value}
              </span>
              <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                {hover === null ? 'total' : slices[hover].label}
              </span>
            </div>
          )}
        </div>
      </div>

      <div style={{ minWidth: 0 }}>
        <Legend
          items={slices.map((s, i) => ({
            color: categorical(i),
            label: s.label,
            value: `${s.value} · ${Math.round((s.value / total) * 100)}%`,
          }))}
        />
      </div>

      <ChartTable
        caption={caption}
        columns={['Category', 'Value', 'Share']}
        rows={slices.map((s) => [s.label, s.value, `${Math.round((s.value / total) * 100)}%`])}
      />
    </div>
  );
}
