'use client';

import { useActionState } from 'react';

import { verifyFindingAction, type ActionState } from '../actions';

/* The Verify button — a <form> around a Server Action, so it works without JS and re-verifies
 * the caller server-side. It queues a rescan; it never claims the fix worked. The outcome lands
 * on the next render (status flips to resolved, or stays open with "verify failed" in the trail). */
export function VerifyButton({ findingId, pendingSince, disabled }: { findingId: string; pendingSince: string | null; disabled?: boolean }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(verifyFindingAction, null);
  const inFlight = pending || Boolean(pendingSince);

  return (
    <form action={action} style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <input type="hidden" name="findingId" value={findingId} />
      <button
        type="submit"
        className="vs-button"
        data-variant="primary"
        disabled={disabled || inFlight}
        aria-busy={pending || undefined}
        style={{
          border: '1px solid var(--accent)',
          borderRadius: 'var(--radius-md)',
          background: 'var(--accent)',
          color: 'var(--accent-fg)',
          fontSize: 'var(--text-xs)',
          fontWeight: 600,
          padding: '0 var(--space-3)',
          height: 'var(--row-default)',
          cursor: disabled || inFlight ? 'not-allowed' : 'pointer',
          opacity: disabled || inFlight ? 0.6 : 1,
        }}
        title="Queue a read-only rescan of this system; the finding resolves itself if the issue is gone"
      >
        {pending ? 'Queuing…' : pendingSince ? 'Verification pending' : 'Verify fix — rescan'}
      </button>
      {pendingSince && !state && (
        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          Rescan requested {pendingSince}. The result lands when the scan completes.
        </span>
      )}
      {state && (
        <span role="status" style={{ fontSize: 'var(--text-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.message}
        </span>
      )}
    </form>
  );
}
