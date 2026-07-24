'use client';

import { useId, useState } from 'react';
import { ChartTable, compact } from './utils';

/* Sparkline — a single series over time, no axes, for a trend at a glance (posture over scans,
 * open-findings over days). This is the componentised form of the inline sparkline Overview drew
 * by hand.
 *
 * Design choices that make it honest:
 *  · The y-domain spans the OBSERVED range, not 0–max, so small real movement is visible — and
 *    the value labels (first → last) print the absolute numbers so the zoomed domain cannot
 *    mislead. A trend line without its endpoints is a shape with no scale.
 *  · Neutral ink by default: identity is carried by the surrounding card, not by hue. Pass
 *    `tone` only when the line itself IS the status (a posture line coloured by grade).
 *  · Hover reveals the point value; the whole thing has a table alternative for screen readers.
 */

export type SparkPoint = { x: string | number; y: number };

export function Sparkline({
  points,
  width = 220,
  height = 40,
  tone,
  valueLabel = (n) => String(n),
  caption = 'Trend',
  ariaLabel,
}: {
  points: SparkPoint[];
  width?: number;
  height?: number;
  /** A CSS colour var for the line; defaults to neutral --text-secondary. */
  tone?: string;
  valueLabel?: (n: number) => string;
  caption?: string;
  ariaLabel?: string;
}) {
  const id = useId();
  const [hover, setHover] = useState<number | null>(null);

  if (points.length < 2) {
    return (
      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', lineHeight: 'var(--leading-2xs)' }}>
        Not enough history yet — the trend appears after a couple of data points.
      </p>
    );
  }

  const pad = 4;
  const ys = points.map((p) => p.y);
  const min = Math.min(...ys);
  const max = Math.max(...ys);
  const x = (i: number) => pad + (i * (width - 2 * pad)) / (points.length - 1);
  const y = (v: number) => (max === min ? height / 2 : pad + (height - 2 * pad) * (1 - (v - min) / (max - min)));
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(p.y).toFixed(1)}`).join(' ');
  const areaD = `${d} L${x(points.length - 1).toFixed(1)} ${height - pad} L${x(0).toFixed(1)} ${height - pad} Z`;

  const line = tone ?? 'var(--text-secondary)';
  const first = points[0];
  const last = points[points.length - 1];
  const delta = last.y - first.y;
  const label = ariaLabel ?? `${caption}: ${valueLabel(first.y)} to ${valueLabel(last.y)} across ${points.length} points`;

  return (
    <div style={{ display: 'grid', gap: 4 }}>
      <div style={{ position: 'relative' }}>
        <svg
          width={width}
          height={height}
          viewBox={`0 0 ${width} ${height}`}
          role="img"
          aria-label={label}
          style={{ maxWidth: '100%', display: 'block', overflow: 'visible' }}
          onMouseLeave={() => setHover(null)}
        >
          <title>{label}</title>
          <defs>
            <linearGradient id={`${id}-fill`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={line} stopOpacity="0.16" />
              <stop offset="100%" stopColor={line} stopOpacity="0" />
            </linearGradient>
          </defs>
          <path d={areaD} fill={`url(#${id}-fill)`} stroke="none" />
          <path d={d} fill="none" stroke={line} strokeWidth="1.75" strokeLinejoin="round" strokeLinecap="round" />
          <circle cx={x(points.length - 1)} cy={y(last.y)} r="2.75" fill={line} />
          {hover !== null && (
            <>
              <line x1={x(hover)} y1={pad} x2={x(hover)} y2={height - pad} stroke="var(--grid)" strokeWidth="1" />
              <circle cx={x(hover)} cy={y(points[hover].y)} r="3" fill="var(--surface)" stroke={line} strokeWidth="1.75" />
            </>
          )}
          {/* Invisible hit targets — one per point, so hover works without a positioning lib. */}
          {points.map((p, i) => (
            <rect
              key={i}
              x={x(i) - (width - 2 * pad) / (points.length - 1) / 2}
              y={0}
              width={(width - 2 * pad) / (points.length - 1)}
              height={height}
              fill="transparent"
              onMouseEnter={() => setHover(i)}
            />
          ))}
        </svg>
        {hover !== null && (
          <span
            role="status"
            style={{
              position: 'absolute',
              top: -2,
              left: Math.min(Math.max(x(hover), 0), width - 40),
              transform: 'translateY(-100%)',
              padding: '2px 6px',
              background: 'var(--surface-raised)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-sm)',
              boxShadow: 'var(--shadow-popover)',
              fontSize: 'var(--text-2xs)',
              color: 'var(--text-primary)',
              whiteSpace: 'nowrap',
              pointerEvents: 'none',
            }}
            data-numeric
          >
            {valueLabel(points[hover].y)}
          </span>
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }} data-numeric>
        <span>{valueLabel(first.y)}</span>
        <span style={{ color: delta === 0 ? 'var(--text-muted)' : 'var(--text-secondary)', fontWeight: 600 }}>
          {delta === 0 ? 'unchanged' : delta > 0 ? `+${compact(delta)}` : compact(delta)}
        </span>
        <span>{valueLabel(last.y)}</span>
      </div>
      <ChartTable
        caption={caption}
        columns={['Point', 'Value']}
        rows={points.map((p, i) => [String(p.x ?? i + 1), valueLabel(p.y)])}
      />
    </div>
  );
}
