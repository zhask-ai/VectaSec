/* StatusPill — an operational status word with a shape, for the non-severity states scattered
 * across the console: scan status (queued/running/done/error), connection health
 * (active/degraded/offline), control status (pass/fail/unknown). Scans and Connections each
 * hand-roll this exact "word + SVG shape so it survives greyscale" mark; this is the shared one.
 *
 * Distinct from SeverityBadge (which is the reserved risk axis) and from Chip (a neutral tag).
 * Like both, the mark carries a SHAPE and a WORD, never colour alone — the tone hue only supports.
 */

export type StatusTone = 'ok' | 'warn' | 'bad' | 'info' | 'neutral';

const TONE: Record<StatusTone, { color: string; shape: 'dot' | 'ring' | 'triangle' | 'octagon' | 'dash' }> = {
  ok: { color: 'var(--sev-low-fg)', shape: 'ring' },
  warn: { color: 'var(--sev-medium-fg)', shape: 'triangle' },
  bad: { color: 'var(--sev-critical-fg)', shape: 'octagon' },
  info: { color: 'var(--sev-low-fg)', shape: 'dot' },
  neutral: { color: 'var(--text-secondary)', shape: 'dash' },
};

function Shape({ shape, color, pulse }: { shape: string; color: string; pulse?: boolean }) {
  const common = { width: 9, height: 9, viewBox: '0 0 10 10', 'aria-hidden': true } as const;
  const node = () => {
    switch (shape) {
      case 'octagon':
        return <path d="M3 0h4l3 3v4l-3 3H3L0 7V3z" fill={color} />;
      case 'triangle':
        return <path d="M5 0l5 9H0z" fill={color} />;
      case 'ring':
        return <circle cx="5" cy="5" r="4" fill="none" stroke={color} strokeWidth="1.75" />;
      case 'dash':
        return <rect x="0" y="4" width="10" height="2" rx="1" fill={color} />;
      default:
        return <circle cx="5" cy="5" r="3.4" fill={color} />;
    }
  };
  return (
    <svg {...common} style={pulse ? { animation: 'vs-pulse 1.2s ease-in-out infinite' } : undefined}>
      {node()}
    </svg>
  );
}

/** The tint pair behind each tone's soft pill — reuses the severity tint tokens so operational
 * states read on the same scale without inventing colour. Decorative; word + shape carry it. */
const SOFT_BG: Record<StatusTone, { bg: string; border: string }> = {
  ok: { bg: 'var(--sev-low-bg)', border: 'color-mix(in srgb, var(--sev-low-solid) 26%, transparent)' },
  warn: { bg: 'var(--sev-medium-bg)', border: 'color-mix(in srgb, var(--sev-medium-solid) 30%, transparent)' },
  bad: { bg: 'var(--sev-critical-bg)', border: 'color-mix(in srgb, var(--sev-critical-solid) 26%, transparent)' },
  info: { bg: 'var(--sev-low-bg)', border: 'color-mix(in srgb, var(--sev-low-solid) 26%, transparent)' },
  neutral: { bg: 'var(--sev-info-bg)', border: 'var(--border)' },
};

export function StatusPill({
  tone,
  label,
  /** For in-flight states: gently pulse the mark. */
  pulse = false,
  /** 'plain' = shape + word only (dense cells); 'soft' = tinted pill. */
  variant = 'plain',
}: {
  tone: StatusTone;
  label: string;
  pulse?: boolean;
  variant?: 'plain' | 'soft';
}) {
  const t = TONE[tone];
  const soft = variant === 'soft';
  return (
    <span
      data-status-tone={tone}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        color: t.color,
        background: soft ? SOFT_BG[tone].bg : 'transparent',
        border: soft ? `1px solid ${SOFT_BG[tone].border}` : undefined,
        padding: soft ? '1px var(--space-2)' : 0,
        borderRadius: 'var(--radius-full)',
        fontWeight: 600,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        whiteSpace: 'nowrap',
      }}
    >
      <Shape shape={t.shape} color={t.color} pulse={pulse} />
      {label}
    </span>
  );
}
