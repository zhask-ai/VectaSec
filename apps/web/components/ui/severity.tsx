import type { Severity } from '@/lib/types';

/* The severity mark. Four redundant channels: LABEL + SHAPE + colour + (sort) position.
 *
 * There is deliberately no `showLabel={false}` prop and no bare-dot variant. Encoding severity
 * by colour alone fails WCAG SC 1.4.1 — which is Level A, the *lowest* bar, not AA. The
 * lightness escape hatch in 1.4.1 does not rescue us either: it does not apply when content
 * "relies on the user's ability to accurately perceive or differentiate a particular color",
 * and critical/high/medium is exactly the red–orange–amber axis that protanopia and
 * deuteranopia collapse (~8% of men). So the label is structural, not a default.
 *
 * Shapes are inline SVG rather than unicode glyphs (▲ ◆ ⬤) because glyph rendering varies by
 * installed font and can silently fall back to a box — which would drop a redundancy channel
 * without anyone noticing.
 *
 * THE TEST: screenshot the console, convert to greyscale, confirm every severity is still
 * readable. If it isn't, this component is broken. Cheap as a CI visual-regression check.
 */

export type SeverityProps = {
  severity: Severity;
  /** 'badge' = tinted pill (the default; solid fills fail contrast with white text).
   *  'inline' = shape + label with no tint, for dense table cells. */
  variant?: 'badge' | 'inline';
  /** Occurrence count. Grouping by rule is the main anti-fatigue lever: "×7" is one decision,
   *  seven rows is seven decisions with the same answer. */
  count?: number;
  className?: string;
};

const LABEL: Record<Severity, string> = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED',
  low: 'LOW',
  info: 'INFO',
};

/** Screen readers get the full word; sighted users get the compact label. */
const FULL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

function Shape({ severity }: { severity: Severity }) {
  const fill = `var(--sev-${severity}-fg)`;
  const common = { width: 10, height: 10, viewBox: '0 0 10 10', 'aria-hidden': true } as const;

  switch (severity) {
    case 'critical': // filled octagon
      return (
        <svg {...common}>
          <path d="M3 0h4l3 3v4l-3 3H3L0 7V3z" fill={fill} />
        </svg>
      );
    case 'high': // filled diamond
      return (
        <svg {...common}>
          <path d="M5 0l5 5-5 5-5-5z" fill={fill} />
        </svg>
      );
    case 'medium': // filled triangle
      return (
        <svg {...common}>
          <path d="M5 0l5 9H0z" fill={fill} />
        </svg>
      );
    case 'low': // outline circle
      return (
        <svg {...common}>
          <circle cx="5" cy="5" r="4" fill="none" stroke={fill} strokeWidth="1.75" />
        </svg>
      );
    case 'info': // dash
      return (
        <svg {...common}>
          <rect x="0" y="4" width="10" height="2" rx="1" fill={fill} />
        </svg>
      );
  }
}

export function SeverityBadge({ severity, variant = 'badge', count, className }: SeverityProps) {
  const isBadge = variant === 'badge';

  return (
    <span
      className={className}
      data-severity={severity}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        // The tint is decorative only — label + shape carry the meaning, so SC 1.4.11's 3:1
        // does not apply to it. Badge bg/fg pairs still clear 4.5:1 for the text; the hairline
        // is the solid at low alpha, keeping the pill crisp on both themes.
        background: isBadge ? `var(--sev-${severity}-bg)` : 'transparent',
        border: isBadge
          ? `1px solid color-mix(in srgb, var(--sev-${severity}-solid) 28%, transparent)`
          : '1px solid transparent',
        color: `var(--sev-${severity}-fg)`,
        padding: isBadge ? '1px var(--space-2)' : '0',
        borderRadius: 'var(--radius-full)',
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        whiteSpace: 'nowrap',
      }}
    >
      <Shape severity={severity} />
      <span aria-hidden="true">{LABEL[severity]}</span>
      <span className="vs-visually-hidden">{FULL[severity]} severity</span>
      {count !== undefined && count > 1 && (
        <span data-numeric style={{ opacity: 0.85, fontWeight: 500 }}>
          <span aria-hidden="true">×{count}</span>
          <span className="vs-visually-hidden">, {count} occurrences</span>
        </span>
      )}
    </span>
  );
}
