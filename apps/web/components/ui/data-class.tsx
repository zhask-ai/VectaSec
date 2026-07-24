/* Data-classification chip. Renders the inferred data classes (PCI/PII/PHI/…) on a resource.
 *
 * HONESTY IS THE POINT. VectaSec reads configuration, not payloads, so a class is inferred from
 * the resource's NAME, never proven from content. The chip therefore says "named like", carries a
 * dotted (inferred) border rather than a solid one, and its tooltip states the matched signal.
 * Sensitivity drives the hue via the existing severity tokens — high==critical-ish red, medium==
 * amber, low==blue — so it reads on the same scale as findings without inventing new colors.
 *
 * Label + text carry the meaning; the tint is decorative (same contract as SeverityBadge), so a
 * greyscale render still shows the class words. */

const SENS_TOKEN: Record<string, string> = {
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
  none: 'sev-info',
};

const CLASS_LABEL: Record<string, string> = {
  pci: 'PCI',
  phi: 'PHI',
  pii: 'PII',
  secrets: 'Secrets',
  financial: 'Financial',
  auth: 'Auth',
};

export function DataClassChips({
  classes,
  sensitivity,
  signals,
}: {
  classes: string[];
  sensitivity: string;
  /** "pci:payments,pii:customer" — the matched naming signals, shown in the title. */
  signals?: string;
}) {
  if (!classes.length) return null;
  const token = SENS_TOKEN[sensitivity] ?? 'sev-info';
  const title = signals
    ? `Inferred from naming — matched: ${signals.replace(/,/g, ', ')}`
    : 'Inferred from the resource name, not from payload inspection';

  return (
    <span style={{ display: 'inline-flex', gap: '4px', flexWrap: 'wrap' }} title={title}>
      {classes.map((c) => (
        <span
          key={c}
          data-data-class={c}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            // Dashed border = inferred, not proven. The one visual tell that this is a hint.
            border: `1px dashed var(--${token}-fg)`,
            color: `var(--${token}-fg)`,
            background: `var(--${token}-bg)`,
            padding: '1px 6px',
            borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            fontWeight: 600,
            letterSpacing: '0.03em',
            whiteSpace: 'nowrap',
          }}
        >
          {CLASS_LABEL[c] ?? c.toUpperCase()}
        </span>
      ))}
    </span>
  );
}
