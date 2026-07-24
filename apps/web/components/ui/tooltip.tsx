'use client';

import { useId, useState, type ReactNode } from 'react';

/* Tooltip — supplementary text on hover AND focus, announced to screen readers.
 *
 * Deliberately small and honest about its limits: a tooltip is for a SUPPLEMENT (the matched
 * naming signal behind an inferred chip, the full ISO timestamp behind a relative one), never for
 * information the user must have to act — that belongs in the layout. It shows on hover and on
 * keyboard focus (a hover-only tooltip is invisible to keyboard and touch users), and the trigger
 * is wired with aria-describedby so the content is read, not just seen.
 *
 * No portal, no positioning library: it renders a positioned span next to the trigger. For the
 * console's uses (short strings on inline marks) that is enough; if a future case needs collision
 * flipping, that is when a heavier popover earns its weight — not before.
 */

export function Tooltip({
  content,
  children,
  side = 'top',
}: {
  content: ReactNode;
  /** The trigger. Must be focusable for keyboard users (a button, link, or tabIndex=0 element). */
  children: ReactNode;
  side?: 'top' | 'bottom';
}) {
  const id = useId();
  const [open, setOpen] = useState(false);

  const pos =
    side === 'top'
      ? { bottom: 'calc(100% + 6px)', left: '50%', transform: 'translateX(-50%)' }
      : { top: 'calc(100% + 6px)', left: '50%', transform: 'translateX(-50%)' };

  return (
    <span
      style={{ position: 'relative', display: 'inline-flex' }}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocusCapture={() => setOpen(true)}
      onBlurCapture={() => setOpen(false)}
    >
      <span aria-describedby={open ? id : undefined}>{children}</span>
      <span
        role="tooltip"
        id={id}
        hidden={!open}
        style={{
          position: 'absolute',
          ...pos,
          zIndex: 'var(--z-overlay)',
          maxWidth: 260,
          width: 'max-content',
          padding: '4px var(--space-2)',
          background: 'var(--surface-raised)',
          color: 'var(--text-primary)',
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-sm)',
          boxShadow: 'var(--shadow-popover)',
          fontSize: 'var(--text-2xs)',
          lineHeight: 'var(--leading-2xs)',
          fontWeight: 400,
          textTransform: 'none',
          letterSpacing: 0,
          whiteSpace: 'normal',
          pointerEvents: 'none',
        }}
      >
        {content}
      </span>
    </span>
  );
}
