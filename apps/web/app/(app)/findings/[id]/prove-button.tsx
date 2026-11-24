'use client';

import { useActionState } from 'react';

import { proveFindingAction, type ActionState } from '../actions';

/* The Prove button — a <form> around a Server Action, like Verify. The label says what it does
 * ("read-only"), the sentence beside it (rendered by ProofCard) says exactly what is sent. */
export function ProveButton({ findingId, again }: { findingId: string; again: boolean }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(proveFindingAction, null);
  return (
    <form action={action} style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <input type="hidden" name="findingId" value={findingId} />
      <button
        type="submit"
        className="vs-button"
        data-variant="secondary"
        disabled={pending}
        aria-busy={pending || undefined}
        style={{
          border: '1px solid var(--border-interactive)',
          borderRadius: 'var(--radius-md)',
          background: 'var(--surface-raised)',
          color: 'var(--text-primary)',
          fontSize: 'var(--text-xs)',
          fontWeight: 600,
          padding: '0 var(--space-3)',
          height: 'var(--row-default)',
          cursor: pending ? 'wait' : 'pointer',
          opacity: pending ? 0.6 : 1,
        }}
      >
        {pending ? 'Checking…' : again ? 'Prove again — read-only' : 'Prove it — read-only'}
      </button>
      {state && (
        <span role="status" style={{ fontSize: 'var(--text-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.message}
        </span>
      )}
    </form>
  );
}
