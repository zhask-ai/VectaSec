'use client';

import { useState } from 'react';
import { SEVERITIES, SEVERITY_RANK, type Severity, type SeverityCounts } from '@/lib/types';
import { SeverityBadge } from '@/components/ui/severity';
import { ChartTable } from './utils';

/* SeverityBar — the open-findings severity mix as one stacked horizontal bar.
 *
 * This is the ONE chart that intentionally uses status colour as the encoding, because severity
 * IS the dimension. It stays honest by never relying on colour alone: segments run in fixed
 * SEVERITY_RANK order (critical first — position is a channel), each carries the reserved
 * --sev-*-solid (non-text 3:1), and the legend under it is a row of SeverityBadges, each with its
 * shape + word + count. Greyscale it and the order and the badges still tell the whole story.
 *
 * One axis: length encodes count; there is no second scale, so there are no gridlines to recede —
 * the segment values and the legend carry the numbers.
 */

const FULL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export function SeverityBar({
  counts,
  height = 12,
  showLegend = true,
  caption = 'Open findings by severity',
}: {
  counts: SeverityCounts;
  height?: number;
  showLegend?: boolean;
  caption?: string;
}) {
  const [hover, setHover] = useState<Severity | null>(null);
  const order = [...SEVERITIES].sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]);
  const total = order.reduce((s, k) => s + (counts[k] || 0), 0);

  if (total === 0) {
    return (
      <div
        role="img"
        aria-label="No open findings"
        style={{ height, borderRadius: 'var(--radius-full)', background: 'var(--border)' }}
        title="No open findings"
      />
    );
  }

  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <div
        role="img"
        aria-label={`${total} open findings: ${order.map((k) => `${counts[k]} ${FULL[k].toLowerCase()}`).join(', ')}`}
        style={{
          display: 'flex',
          height,
          width: '100%',
          borderRadius: 'var(--radius-full)',
          overflow: 'hidden',
          background: 'var(--border)',
        }}
      >
        {order.map((sev) => {
          const n = counts[sev] || 0;
          if (n === 0) return null;
          const pct = (n / total) * 100;
          return (
            <div
              key={sev}
              title={`${n} ${FULL[sev]}`}
              onMouseEnter={() => setHover(sev)}
              onMouseLeave={() => setHover(null)}
              style={{
                width: `${pct}%`,
                background: `var(--sev-${sev}-solid)`,
                opacity: hover && hover !== sev ? 0.5 : 1,
                transition: 'opacity var(--motion-fast) var(--ease-standard)',
              }}
            />
          );
        })}
      </div>

      {showLegend && (
        <ul style={{ listStyle: 'none', display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1) var(--space-3)', margin: 0, padding: 0 }}>
          {order.map((sev) => (
            <li
              key={sev}
              onMouseEnter={() => setHover(sev)}
              onMouseLeave={() => setHover(null)}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                opacity: hover && hover !== sev ? 0.55 : 1,
                transition: 'opacity var(--motion-fast) var(--ease-standard)',
              }}
            >
              <SeverityBadge severity={sev} variant="inline" />
              <span data-numeric style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, color: counts[sev] ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                {counts[sev] || 0}
              </span>
            </li>
          ))}
        </ul>
      )}

      <ChartTable
        caption={caption}
        columns={['Severity', 'Open findings']}
        rows={order.map((sev) => [FULL[sev], counts[sev] || 0])}
      />
    </div>
  );
}
