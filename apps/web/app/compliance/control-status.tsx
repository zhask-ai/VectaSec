import type { ControlStatus } from '@/lib/types';
import type { Fidelity, Tally } from './frameworks';
import { FIDELITY } from './frameworks';

/* Control status marks, built to the same contract as components/ui/severity.tsx: LABEL +
 * SHAPE + colour, never colour alone, shapes as inline SVG rather than unicode so a missing
 * glyph cannot silently drop a redundancy channel.
 *
 * Status is NOT severity and does not reuse SeverityBadge — a failing control and a critical
 * finding are different claims about different objects, and one component rendering both
 * would blur them. The colour TOKENS are shared because they are the only audited palette we
 * have; the vocabulary is not.
 *
 * The labels are deliberately not the raw DB values:
 *   unknown        -> NOT EVALUATED  ("unknown" reads as a system fault; it is a coverage gap)
 *   not_applicable -> OUT OF SCOPE   (says WHY it is not applicable: a scope gate failed)
 */

const MARK: Record<
  ControlStatus,
  { label: string; full: string; fg: string; bg: string }
> = {
  fail: {
    label: 'FAIL',
    full: 'Failing',
    fg: 'var(--sev-critical-fg)',
    bg: 'var(--sev-critical-bg)',
  },
  pass: {
    label: 'PASS',
    full: 'Passing',
    fg: 'var(--sev-low-fg)',
    bg: 'var(--sev-low-bg)',
  },
  unknown: {
    // --text-secondary, not --text-muted: muted is 4.37:1 on --surface-raised and this mark
    // has to stay readable wherever it lands.
    label: 'NOT EVALUATED',
    full: 'Not evaluated',
    fg: 'var(--text-secondary)',
    bg: 'var(--sev-info-bg)',
  },
  not_applicable: {
    label: 'OUT OF SCOPE',
    full: 'Out of scope',
    fg: 'var(--text-muted)',
    bg: 'transparent',
  },
};

function Shape({ status }: { status: ControlStatus }) {
  const fill = MARK[status].fg;
  const common = { width: 10, height: 10, viewBox: '0 0 10 10', 'aria-hidden': true } as const;

  switch (status) {
    case 'fail': // filled octagon — the stop sign, and the only filled-solid mark here
      return (
        <svg {...common}>
          <path d="M3 0h4l3 3v4l-3 3H3L0 7V3z" fill={fill} />
        </svg>
      );
    case 'pass': // check
      return (
        <svg {...common}>
          <path
            d="M1 5.5L3.6 8 9 1.8"
            fill="none"
            stroke={fill}
            strokeWidth="1.75"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case 'unknown': // hollow square — an empty box reads as "nothing determined"
      return (
        <svg {...common}>
          <rect x="1" y="1" width="8" height="8" fill="none" stroke={fill} strokeWidth="1.5" />
        </svg>
      );
    case 'not_applicable': // dash
      return (
        <svg {...common}>
          <rect x="0" y="4" width="10" height="2" rx="1" fill={fill} />
        </svg>
      );
  }
}

export function ControlStatusBadge({ status }: { status: ControlStatus }) {
  const mark = MARK[status];

  return (
    <span
      data-control-status={status}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        background: mark.bg,
        color: mark.fg,
        padding: '2px var(--space-2)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
      }}
    >
      <Shape status={status} />
      <span aria-hidden="true">{mark.label}</span>
      <span className="vs-visually-hidden">{mark.full}</span>
    </span>
  );
}

/** Fidelity tag for a framework header. Small, and adjacent to the framework name, because
 * "how much is this mapping worth" is not a footnote. */
export function FidelityTag({ fidelity }: { fidelity: Fidelity }) {
  const strong = fidelity === 'direct';

  return (
    <span
      title={FIDELITY[fidelity].note}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '1px var(--space-2)',
        border: `1px solid ${strong ? 'var(--border-interactive)' : 'var(--border-strong)'}`,
        borderRadius: 'var(--radius-full)',
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: 500,
        letterSpacing: '0.02em',
        whiteSpace: 'nowrap',
      }}
    >
      {FIDELITY[fidelity].label}
    </span>
  );
}

/* Bar segment order mirrors STATUS_RANK: fail, unknown, pass, out of scope. Putting
 * `unknown` second rather than last is the whole point of the bar — it makes an under-scanned
 * framework LOOK under-scanned, which a bare percentage never does. */
const BAR_ORDER: ControlStatus[] = ['fail', 'unknown', 'pass', 'not_applicable'];

const BAR_FILL: Record<ControlStatus, string> = {
  fail: 'var(--sev-critical-solid)',
  unknown: 'var(--border-strong)',
  pass: 'var(--sev-low-solid)',
  not_applicable: 'var(--border)',
};

/** Composition of every control in a framework.
 *
 * The bar itself is aria-hidden and carries no meaning on its own — the legend below it is
 * the content, with counts and text labels. That split is deliberate: it lets the bar be
 * purely chromatic (which is what makes it scannable) without the colour ever being the only
 * way to read the number.
 */
export function CoverageBar({ tally, total }: { tally: Tally; total: number }) {
  if (total === 0) return null;

  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <div
        aria-hidden="true"
        style={{
          display: 'flex',
          height: 8,
          borderRadius: 'var(--radius-full)',
          overflow: 'hidden',
          background: 'var(--border)',
        }}
      >
        {BAR_ORDER.filter((s) => tally[s] > 0).map((s) => (
          <div
            key={s}
            style={{ width: `${(tally[s] / total) * 100}%`, background: BAR_FILL[s] }}
          />
        ))}
      </div>

      <ul
        style={{
          listStyle: 'none',
          margin: 0,
          padding: 0,
          display: 'flex',
          flexWrap: 'wrap',
          gap: 'var(--space-1) var(--space-4)',
        }}
      >
        {BAR_ORDER.map((s) => (
          <li key={s} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <ControlStatusBadge status={s} />
            <span
              data-numeric
              style={{
                fontSize: 'var(--text-xs)',
                fontWeight: 600,
                color: tally[s] === 0 ? 'var(--text-muted)' : 'var(--text-primary)',
              }}
            >
              {tally[s]}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
