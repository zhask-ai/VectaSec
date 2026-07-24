import type { ReactNode } from 'react';

/* Chip / Tag — a small neutral label for metadata: a system name, a rule id, a count, a label
 * key/value. NOT a status and NOT a severity (those are StatusPill and SeverityBadge, which carry
 * shapes and reserved colour). A chip is quiet by default; `tone` tints it only when the metadata
 * itself is a mild signal (a wildcard grant, a weak hash), reusing the severity tint tokens so it
 * reads on the same scale without inventing colour.
 *
 * `inferred` draws the dashed border that the data-classification chip established as the house
 * tell for "derived from naming, not proven" — kept here so any inferred tag can borrow it.
 */

export type ChipTone = 'neutral' | 'accent' | 'high' | 'medium' | 'low' | 'info';

const TONE: Record<ChipTone, { fg: string; bg: string; border: string }> = {
  neutral: { fg: 'var(--text-secondary)', bg: 'transparent', border: 'var(--border-strong)' },
  accent: { fg: 'var(--sev-low-fg)', bg: 'var(--sev-low-bg)', border: 'var(--sev-low-bg)' },
  high: { fg: 'var(--sev-high-fg)', bg: 'var(--sev-high-bg)', border: 'var(--sev-high-bg)' },
  medium: { fg: 'var(--sev-medium-fg)', bg: 'var(--sev-medium-bg)', border: 'var(--sev-medium-bg)' },
  low: { fg: 'var(--sev-low-fg)', bg: 'var(--sev-low-bg)', border: 'var(--sev-low-bg)' },
  info: { fg: 'var(--sev-info-fg)', bg: 'var(--sev-info-bg)', border: 'var(--sev-info-bg)' },
};

export function Chip({
  children,
  tone = 'neutral',
  mono = false,
  inferred = false,
  title,
}: {
  children: ReactNode;
  tone?: ChipTone;
  /** IDs, rule keys, config values read as evidence — set mono. */
  mono?: boolean;
  /** Dashed border = derived from naming, not proven (the DataClassChips convention). */
  inferred?: boolean;
  title?: string;
}) {
  const t = TONE[tone];
  return (
    <span
      title={title}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 3,
        maxWidth: '100%',
        padding: '1px 6px',
        border: `1px ${inferred ? 'dashed' : 'solid'} ${t.border}`,
        borderRadius: 'var(--radius-sm)',
        background: t.bg,
        color: t.fg,
        fontFamily: mono ? 'var(--font-mono)' : 'inherit',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: tone === 'neutral' ? 500 : 600,
        letterSpacing: mono ? 0 : '0.01em',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
      }}
    >
      {children}
    </span>
  );
}
