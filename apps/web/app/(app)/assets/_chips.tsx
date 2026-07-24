import type { Json } from '@/lib/types';
import { Chip } from '@/components/ui/chip';
import { labelEntries } from './_lib';

/* Small shared marks for the two asset views. */

/** A resource the last scan did not return.
 *
 * Deliberately NOT greyed out, which is the reflex for "old" rows. An asset that vanished is a
 * SIGNAL, not noise: a topic that stopped existing may mean someone deleted it, and the finding
 * attached to it may now be unverifiable. So stale reads as a warning mark, and the row keeps
 * full-contrast text. Colour + word + border, never colour alone.
 */
export function StaleChip({ title }: { title?: string }) {
  return (
    <span
      title={title ?? 'Not returned by the most recent scan of its connection'}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        padding: '1px var(--space-2)',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--sev-medium-fg)',
        color: 'var(--sev-medium-fg)',
        background: 'var(--sev-medium-bg)',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
      }}
    >
      <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
        <path d="M4 0L8 7H0z" fill="var(--sev-medium-fg)" />
      </svg>
      STALE
      <span className="vs-visually-hidden">— not seen in the most recent scan</span>
    </span>
  );
}

/** Labels as key=value chips. `max` keeps a 30-label resource from owning the row. */
export function LabelChips({ labels, max = 4 }: { labels: Json; max?: number }) {
  const entries = labelEntries(labels);
  if (entries.length === 0) return <span style={{ color: 'var(--text-muted)' }}>—</span>;

  const shown = entries.slice(0, max);
  const rest = entries.length - shown.length;

  return (
    <span style={{ display: 'inline-flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
      {shown.map(([k, v]) => (
        <Chip key={k} mono title={`${k}=${v}`}>
          {k}={v}
        </Chip>
      ))}
      {rest > 0 && (
        <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-2xs)' }}>+{rest}</span>
      )}
    </span>
  );
}
