'use client';

import { useEffect, useRef, type ReactNode } from 'react';
import { IconClose } from './icons';

/* SlideOver / Drawer — a right-edge panel for detail-in-context: a finding's full evidence and
 * triage without leaving the queue, a resource's blast radius beside the table it came from.
 *
 * Why a drawer and not a route: the queue is the analyst's place, and a finding is a glance, not a
 * destination. A drawer keeps the list under it and the URL where it was. (When the detail IS the
 * destination — a deep link pasted into Slack — that stays a real route, findings/[id]; this is
 * the in-flow companion, not a replacement.)
 *
 * Accessibility is the whole cost of a drawer done right: it is a modal dialog, so it traps focus,
 * closes on Escape and on scrim click, restores focus to the trigger on close, and locks body
 * scroll while open. Skipping any of those turns an enhancement into a keyboard trap.
 */

export function Drawer({
  open,
  onClose,
  title,
  description,
  footer,
  children,
  width = 480,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  width?: number;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreTo = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    restoreTo.current = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    // Move focus into the panel.
    const panel = panelRef.current;
    panel?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== 'Tab' || !panel) return;
      // Minimal focus trap: cycle within the panel's tabbable set.
      const focusables = panel.querySelectorAll<HTMLElement>(
        'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])',
      );
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.body.style.overflow = prevOverflow;
      restoreTo.current?.focus?.();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 'var(--z-overlay)' }}>
      {/* Scrim — click to dismiss. Kept subtle; a security console dimming to near-black reads as
          an alert, which this is not. */}
      <div
        onClick={onClose}
        style={{
          position: 'absolute',
          inset: 0,
          background: 'rgba(11, 11, 11, 0.32)',
          animation: 'vs-fade-in var(--motion-fast) var(--ease-out)',
        }}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : undefined}
        tabIndex={-1}
        style={{
          position: 'absolute',
          top: 0,
          right: 0,
          bottom: 0,
          width: `min(${width}px, 100vw)`,
          display: 'grid',
          gridTemplateRows: 'auto 1fr auto',
          background: 'var(--surface)',
          borderLeft: '1px solid var(--border-strong)',
          boxShadow: 'var(--shadow-popover)',
          animation: 'vs-slide-in var(--motion-standard) var(--ease-out)',
          outline: 'none',
        }}
      >
        <header
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: 'var(--space-3)',
            padding: 'var(--space-4)',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <div style={{ display: 'grid', gap: 2, minWidth: 0 }}>
            <h2 style={{ margin: 0, fontSize: 'var(--text-lg)', lineHeight: 'var(--leading-lg)', fontWeight: 620, color: 'var(--text-primary)' }}>
              {title}
            </h2>
            {description && (
              <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 28,
              height: 28,
              flexShrink: 0,
              background: 'transparent',
              color: 'var(--text-secondary)',
              border: '1px solid var(--border-interactive)',
              borderRadius: 'var(--radius-sm)',
              cursor: 'pointer',
            }}
          >
            <IconClose size={16} />
          </button>
        </header>

        <div style={{ overflowY: 'auto', padding: 'var(--space-4)' }}>{children}</div>

        {footer && (
          <footer style={{ padding: 'var(--space-3) var(--space-4)', borderTop: '1px solid var(--border)', display: 'flex', gap: 'var(--space-2)', justifyContent: 'flex-end' }}>
            {footer}
          </footer>
        )}
      </div>
    </div>
  );
}
