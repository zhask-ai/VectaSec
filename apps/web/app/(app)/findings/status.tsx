import type { UiStatus } from '@/lib/types';
import { UI_STATUS_LABEL } from './query';

/* The status pill.
 *
 * STATUS IS DELIBERATELY NOT COLOUR-CODED. Every hue in this console belongs to severity, and
 * that is the whole accessibility argument: critical/high/medium already sit on the red–orange–
 * amber axis that deuteranopia collapses, and the label + shape redundancy is what rescues it.
 * Giving status its own palette would put a second, unrelated meaning on the same channel —
 * a green "resolved" next to an amber "medium" reads as two severities to anyone scanning, and
 * as noise to anyone who cannot separate the hues at all. So status is distinguished by TEXT,
 * a mark, and border treatment, and hue stays where it earns its keep.
 *
 * `muted` uses --text-secondary rather than --text-muted despite wanting to recede: muted text
 * is 4.37:1 on --surface-raised (documented in globals.css) and these pills render on raised
 * rows when a group is expanded. De-emphasis comes from the dashed border instead.
 */

const MARK: Record<UiStatus, string> = {
  open: '●',
  in_progress: '◐',
  resolved: '✓',
  muted: '⊘',
};

const STYLE: Record<UiStatus, { color: string; border: string; dashed: boolean }> = {
  open: { color: 'var(--text-primary)', border: 'var(--border-interactive)', dashed: false },
  in_progress: { color: 'var(--text-primary)', border: 'var(--border-strong)', dashed: false },
  resolved: { color: 'var(--text-secondary)', border: 'var(--border)', dashed: false },
  muted: { color: 'var(--text-secondary)', border: 'var(--border-strong)', dashed: true },
};

export function StatusPill({ status, count }: { status: UiStatus; count?: number }) {
  const s = STYLE[status];

  return (
    <span
      data-status={status}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        padding: '1px var(--space-2)',
        border: `1px ${s.dashed ? 'dashed' : 'solid'} ${s.border}`,
        borderRadius: 'var(--radius-full)',
        color: s.color,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: 500,
        whiteSpace: 'nowrap',
      }}
    >
      <span aria-hidden="true" style={{ fontSize: '0.8em', opacity: 0.9 }}>
        {MARK[status]}
      </span>
      {UI_STATUS_LABEL[status]}
      {count !== undefined && count > 1 && (
        <span data-numeric style={{ opacity: 0.85 }}>
          <span aria-hidden="true">×{count}</span>
          <span className="vs-visually-hidden">, {count} findings</span>
        </span>
      )}
    </span>
  );
}
