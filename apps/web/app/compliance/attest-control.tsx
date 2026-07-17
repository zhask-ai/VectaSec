'use client';

import { useActionState, useState } from 'react';

import { attestControlAction, type AttestState } from './actions';

/* The attest affordance for a single control.
 *
 * A <form> around a Server Action, so it works without JavaScript and re-verifies the caller
 * server-side (see actions.ts). Nothing is optimistic: the engine is the only thing that knows
 * whether the pass was written, and showing "passing" for an attestation that never landed is the
 * one lie a compliance view cannot afford.
 *
 * COPY IS LOAD-BEARING here. Attestation is a human sign-off — a person taking responsibility that
 * a control is met over a stated scope — not a scan result. The wording says so plainly, so nobody
 * reads a `pass` here as "the scanner proved it". And a control with a live failing finding cannot
 * be attested: this component is only rendered for non-failing controls (fail beats attestation),
 * and the engine and the action both refuse it anyway.
 */

export function AttestControl({ controlPk, controlLabel }: { controlPk: string; controlLabel: string }) {
  const [state, formAction, pending] = useActionState<AttestState, FormData>(attestControlAction, null);
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-1)', maxWidth: 340 }}>
        <button type="button" onClick={() => setOpen(true)} style={buttonStyle}>
          Attest this control…
        </button>
        <Hint>
          A human sign-off that this control is met, over a scope you state. A clean scan never marks
          a control passing on its own — only a person can.
        </Hint>
        <Result state={state} />
      </div>
    );
  }

  return (
    <form action={formAction} style={{ display: 'grid', gap: 'var(--space-2)', maxWidth: 340 }}>
      <input type="hidden" name="controlPk" value={controlPk} />

      <Label htmlFor={`scope-${controlPk}`}>Scope (required)</Label>
      <input
        id={`scope-${controlPk}`}
        name="scope"
        required
        placeholder="e.g. all production Kafka brokers, Q3 2026"
        autoComplete="off"
        style={inputStyle}
      />

      <Label htmlFor={`note-${controlPk}`}>Note (optional)</Label>
      <textarea
        id={`note-${controlPk}`}
        name="note"
        rows={2}
        placeholder="How is this control met? The next auditor will read this."
        style={{ ...inputStyle, height: 'auto', padding: 'var(--space-2)', resize: 'vertical', fontFamily: 'inherit' }}
      />

      <Label htmlFor={`expires-${controlPk}`}>Expires (optional)</Label>
      <input id={`expires-${controlPk}`} name="expires" type="date" style={inputStyle} />
      <Hint>An attestation lapses on its expiry — after that the control returns to “not evaluated” until it is signed again. A permanent one is discouraged.</Hint>

      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <button type="submit" disabled={pending} aria-busy={pending || undefined} style={{ ...buttonStyle, opacity: pending ? 0.55 : 1 }}>
          {pending ? 'Signing…' : `Sign attestation for ${controlLabel}`}
        </button>
        <button type="button" onClick={() => setOpen(false)} style={buttonStyle}>
          Cancel
        </button>
      </div>
      <Hint>Attestation is a human sign-off. A control with a live failing finding cannot be attested — a failure always wins.</Hint>
      <Result state={state} />
    </form>
  );
}

/* ── Primitives ───────────────────────────────────────────────────────────
 * Local to compliance, tokens only, mirroring the findings actions rail. The design system has no
 * button/input yet; delete these the day components/ui grows the real thing. */

const inputStyle: React.CSSProperties = {
  // --border-interactive, not --border: for a control whose outline is its only visual indicator,
  // --border's 1.38:1 fails SC 1.4.11 (globals.css flags this as the most-missed dark a11y bug).
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  padding: '0 var(--space-2)',
  height: 'var(--row-default)',
  width: '100%',
};

const buttonStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  fontWeight: 500,
  padding: '0 var(--space-3)',
  height: 'var(--row-compact)',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
};

function Label({ children, htmlFor }: { children: React.ReactNode; htmlFor: string }) {
  return (
    <label
      htmlFor={htmlFor}
      style={{
        fontSize: 'var(--text-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        color: 'var(--text-secondary)',
      }}
    >
      {children}
    </label>
  );
}

function Hint({ children }: { children: React.ReactNode }) {
  return (
    <p style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
      {children}
    </p>
  );
}

/** role="status": the outcome of an action must be announced, not just coloured. --text-secondary
 * on failure (never --text-muted, which is 4.37:1 on raised surfaces). */
function Result({ state }: { state: AttestState }) {
  if (!state) return null;
  return (
    <p
      role="status"
      style={{
        margin: 0,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
      }}
    >
      {state.ok ? '' : 'Not applied — '}
      {state.message}
    </p>
  );
}
