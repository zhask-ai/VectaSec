import type { ButtonHTMLAttributes, ReactNode } from 'react';

/* Button. One typed control replacing the four hand-rolled `primaryButtonStyle` consts scattered
 * across connections/, compliance/ and settings/ (each a comment saying "mirror … until ui/ grows
 * these" — this is ui/ growing them).
 *
 * Four variants, each a real semantic:
 *   primary   — the ONE affirmative action on a view (Connect, Attest, Invite). Accent fill.
 *   secondary — the common neutral action (Cancel, Edit, Export). Hairline + surface.
 *   ghost     — low-emphasis / toolbar action; no border until hover.
 *   danger    — destructive (Suppress, Remove). Reads as critical, and MUST still be confirmed —
 *               a red button is a warning, not a guardrail.
 *
 * Not a <Link>. A button that navigates is an accessibility bug (no ⌘-click, no right-click-open,
 * announced as "button" not "link"). For navigation use LinkButton, which is an <a> styled the
 * same — pass Next's <Link> as `as` or wrap a <Link> around children with `render`. Kept minimal:
 * this file styles; routing stays with next/link at the call site.
 */

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md';

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Leading icon — decorative; the label names the action. */
  icon?: ReactNode;
  /** Full-bleed width (forms, mobile). */
  block?: boolean;
};

const SIZE: Record<ButtonSize, { height: string; padX: string; font: string }> = {
  sm: { height: 'var(--row-compact)', padX: 'var(--space-3)', font: 'var(--text-xs)' },
  md: { height: 'var(--row-default)', padX: 'var(--space-4)', font: 'var(--text-sm)' },
};

/* --border-interactive on every bordered variant: a control's outline owes SC 1.4.11's 3:1, and
 * only --border-interactive clears it (the source audit enforces this on <button>). */
function surfaceFor(variant: ButtonVariant) {
  switch (variant) {
    case 'primary':
      return { bg: 'var(--accent)', fg: 'var(--accent-fg)', border: 'var(--accent)', weight: 600 };
    case 'secondary':
      return { bg: 'var(--surface)', fg: 'var(--text-primary)', border: 'var(--border-interactive)', weight: 500 };
    case 'ghost':
      return { bg: 'transparent', fg: 'var(--text-secondary)', border: 'transparent', weight: 500 };
    case 'danger':
      return { bg: 'var(--sev-critical-bg)', fg: 'var(--sev-critical-fg)', border: 'var(--sev-critical-solid)', weight: 600 };
  }
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  block = false,
  disabled,
  children,
  style,
  ...rest
}: Props) {
  const s = SIZE[size];
  const c = surfaceFor(variant);

  return (
    <button
      disabled={disabled}
      data-variant={variant}
      className="vs-button"
      style={{
        display: block ? 'flex' : 'inline-flex',
        width: block ? '100%' : undefined,
        alignItems: 'center',
        justifyContent: 'center',
        gap: 'var(--space-2)',
        height: s.height,
        padding: `0 ${s.padX}`,
        background: c.bg,
        color: c.fg,
        border: `1px solid ${c.border}`,
        borderRadius: 'var(--radius-md)',
        fontFamily: 'inherit',
        fontSize: s.font,
        fontWeight: c.weight,
        lineHeight: 1,
        whiteSpace: 'nowrap',
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.55 : 1,
        transition: `background var(--motion-fast) var(--ease-standard), border-color var(--motion-fast) var(--ease-standard)`,
        ...style,
      }}
      {...rest}
    >
      {icon && (
        <span aria-hidden="true" style={{ display: 'inline-flex', flexShrink: 0 }}>
          {icon}
        </span>
      )}
      {children}
    </button>
  );
}

/* Hover/active affordances live on `.vs-button` in globals.css so they work without JS, respond
 * to :hover/:active that inline styles cannot express, and stay in one place. */
