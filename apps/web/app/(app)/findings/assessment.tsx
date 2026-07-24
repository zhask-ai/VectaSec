import type { Assessment } from '@/lib/types';

/* The "Not assessed" mark — the visual for a COVERAGE GAP.
 *
 * A `not_assessable` finding means the detector could not read the very thing it needed to check
 * (migration 006): "we could not tell", which is neither "this is broken" (a real finding) nor
 * "this is fine" (a clean pass). It must be impossible to confuse with either.
 *
 * DELIBERATELY NOT A SEVERITY COLOUR. Every hue in this console belongs to severity; a coverage
 * gap is not on that axis, so it carries no severity fill. It is distinguished by three non-colour
 * channels at once — the word NOT ASSESSED, a dashed (never solid) border, and a "?" mark rendered
 * as inline SVG so a missing glyph cannot drop the channel. That satisfies SC 1.4.1 (never colour
 * alone) the same way SeverityBadge does, and the dashed-neutral treatment reads as structural
 * rather than as an `info` severity, which is the one severity it could otherwise be mistaken for.
 */

/** The uncertainty mark: a question mark. Distinct from every severity shape (octagon/diamond/
 * triangle/circle/dash) and from the control marks, so greyscale survives. */
function Mark({ color }: { color: string }) {
  return (
    <svg width={10} height={10} viewBox="0 0 10 10" aria-hidden="true">
      <path
        d="M2.6 3.4a2.4 2.4 0 1 1 3.1 2.3c-.7.3-.8.8-.8 1.4"
        fill="none"
        stroke={color}
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="4.9" cy="8.7" r="0.85" fill={color} />
    </svg>
  );
}

export function NotAssessedBadge({
  variant = 'badge',
  count,
}: {
  /** 'badge' = dashed neutral pill (default). 'inline' = mark + label, no border, for dense rows. */
  variant?: 'badge' | 'inline';
  /** Occurrence count, for a grouped row of coverage gaps. */
  count?: number;
}) {
  const isBadge = variant === 'badge';
  const color = 'var(--text-secondary)';

  return (
    <span
      data-assessment="not_assessable"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        // Dashed, never solid: severity soft badges are solid-tinted, so the dashed outline is the
        // structural tell that this is a coverage gap and not one of them.
        border: isBadge ? '1px dashed var(--border-interactive)' : undefined,
        background: 'transparent',
        color,
        padding: isBadge ? '1px var(--space-2)' : '0',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
      }}
    >
      <Mark color={color} />
      <span aria-hidden="true">NOT ASSESSED</span>
      <span className="vs-visually-hidden">Not assessed — a coverage gap, not a vulnerability</span>
      {count !== undefined && count > 1 && (
        <span data-numeric style={{ opacity: 0.85, fontWeight: 500 }}>
          <span aria-hidden="true">×{count}</span>
          <span className="vs-visually-hidden">, {count} occurrences</span>
        </span>
      )}
    </span>
  );
}

/** Filter vocabulary for the assessment axis. Two values only, so a segmented facet rather than a
 * long list. Labels are the human words, not the DB literals. */
export const ASSESSMENTS: readonly Assessment[] = ['assessed', 'not_assessable'];

export const ASSESSMENT_LABEL: Record<Assessment, string> = {
  assessed: 'Assessed',
  not_assessable: 'Not assessed',
};
