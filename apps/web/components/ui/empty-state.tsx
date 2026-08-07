import type { ReactNode } from 'react';

/* Empty states.
 *
 * A blank table leaves users unsure whether the product is broken or whether they need to act.
 * These states are not interchangeable:
 *
 *   tone           when                        message                          action
 *   ─────────────  ──────────────────────────  ───────────────────────────────  ─────────────
 *   'setup'        no connections              "Connect your first system"      → onboarding
 *   'pending'      connected, never scanned    "First scan starts in ~2 min"    → Run now
 *   'scanning'     scan in flight              use <SkeletonRows>, not this     —
 *   'clean'        scanned, zero findings      "No findings. 6 systems, 4m ago" → inventory
 *   'filtered'     zero MATCHES                "No findings match these filters" → Clear filters
 *   'error'        the READ FAILED             "Could not load findings"        → retry
 *
 * `tone` is REQUIRED because 'clean' and 'filtered' are the two everyone conflates, and in a
 * security tool that is a real bug: "you are secure" and "your filter is too narrow" must
 * never look alike. They are given different marks and different colours here so they cannot.
 *
 * 'clean' MUST pass `meta` — what was scanned and when. A zero state with no provenance reads
 * as broken, not as clean.
 *
 * 'error' exists because a failed read is NOT a result of zero, and rendering one as 'filtered'
 * makes a screen reader announce "No matches" over a database outage — telling an analyst their
 * estate is empty because Postgres was unreachable. It is the only tone that carries
 * role="alert" (so a client-side transition announces it) and the only one whose hidden label
 * says "Error". Never reach for 'filtered' to render a failure.
 */

export type EmptyTone = 'setup' | 'pending' | 'clean' | 'filtered' | 'error';

const MARK: Record<EmptyTone, { glyph: string; color: string; label: string }> = {
  setup: { glyph: '+', color: 'var(--text-secondary)', label: 'Setup required' },
  pending: { glyph: '⋯', color: 'var(--text-secondary)', label: 'Pending' },
  clean: { glyph: '✓', color: 'var(--sev-low-fg)', label: 'All clear' },
  filtered: { glyph: '⌗', color: 'var(--text-muted)', label: 'No matches' },
  error: { glyph: '!', color: 'var(--sev-critical-fg)', label: 'Error' },
};

export function EmptyState({
  tone,
  title,
  description,
  action,
  meta,
}: {
  tone: EmptyTone;
  title: string;
  description: string;
  /** Always give a way out — an empty state without a next step is a dead end. */
  action?: ReactNode;
  /** Provenance: "6 systems scanned 4m ago". Required in spirit for tone='clean'. */
  meta?: string;
}) {
  const mark = MARK[tone];
  const isError = tone === 'error';

  return (
    <div
      data-empty-tone={tone}
      // role="alert" only for 'error'. On a client transition this is what gets the failure
      // announced at all; on the other tones it would shout a routine zero-result at every
      // navigation. (A hard page load does not announce alerts — the hidden "Error." label
      // below is what carries it there.)
      role={isError ? 'alert' : undefined}
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--space-2)',
        padding: 'var(--space-7) var(--space-4)',
        textAlign: 'center',
      }}
    >
      <span
        aria-hidden="true"
        style={{
          display: 'grid',
          placeItems: 'center',
          width: 44,
          height: 44,
          borderRadius: 'var(--radius-full)',
          border: `1px dashed ${isError ? 'var(--sev-critical-solid)' : 'var(--border-strong)'}`,
          padding: 4,
        }}
      >
        <span
          style={{
            display: 'grid',
            placeItems: 'center',
            width: '100%',
            height: '100%',
            borderRadius: 'var(--radius-full)',
            border: `1px solid ${isError ? 'var(--sev-critical-solid)' : 'var(--border-interactive)'}`,
            background: isError ? 'var(--sev-critical-bg)' : 'var(--surface-raised)',
            boxShadow: 'var(--shadow-sm)',
            color: mark.color,
            fontSize: 'var(--text-base)',
            lineHeight: 1,
          }}
        >
          {mark.glyph}
        </span>
      </span>
      <span className="vs-visually-hidden">{mark.label}.</span>

      <h3
        style={{
          margin: 0,
          fontSize: 'var(--text-base)',
          lineHeight: 'var(--leading-base)',
          fontWeight: 600,
          color: 'var(--text-primary)',
        }}
      >
        {title}
      </h3>

      <p
        style={{
          margin: 0,
          maxWidth: '44ch',
          fontSize: 'var(--text-sm)',
          lineHeight: 'var(--leading-sm)',
          color: 'var(--text-secondary)',
        }}
      >
        {description}
      </p>

      {/* Said in words, not just in colour: the whole hazard of an error rendered as an empty
          state is that it reads as "nothing found". */}
      {isError && (
        <p
          style={{
            margin: 0,
            maxWidth: '44ch',
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            color: 'var(--text-secondary)',
          }}
        >
          This is a failure to read, not a clean result. Do not read it as &ldquo;nothing found&rdquo;.
        </p>
      )}

      {meta && (
        <p
          style={{
            margin: 0,
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            color: 'var(--text-muted)',
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {meta}
        </p>
      )}

      {action && <div style={{ marginTop: 'var(--space-2)' }}>{action}</div>}
    </div>
  );
}
