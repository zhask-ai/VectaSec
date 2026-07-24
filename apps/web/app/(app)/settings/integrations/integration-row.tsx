'use client';

import { useActionState, useState } from 'react';

import { deleteIntegrationAction, testIntegrationAction, type ActionState } from './actions';

/* Per-integration controls: Test (a real delivery attempt) and Remove (two-step, in place).
 * Same shape as connections/row-actions — independent forms, shared result line. */

export function IntegrationRowActions({ integrationId, name }: { integrationId: string; name: string }) {
  const [testState, testAction, testPending] = useActionState<ActionState, FormData>(testIntegrationAction, null);
  const [deleteState, deleteAction, deletePending] = useActionState<ActionState, FormData>(deleteIntegrationAction, null);
  const [armed, setArmed] = useState(false);
  const [last, setLast] = useState<'test' | 'delete' | null>(null);

  const state = last === 'test' ? testState : last === 'delete' ? deleteState : null;

  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
        <form action={testAction} onSubmit={() => setLast('test')} style={{ display: 'contents' }}>
          <input type="hidden" name="integrationId" value={integrationId} />
          <button
            type="submit"
            disabled={testPending}
            aria-busy={testPending || undefined}
            title={`Send a test message through ${name}`}
            style={{ ...btn, opacity: testPending ? 0.55 : 1 }}
          >
            {testPending ? 'Sending…' : 'Test'}
          </button>
        </form>

        {!armed ? (
          <button type="button" onClick={() => setArmed(true)} title={`Remove ${name}`} style={btn}>
            Remove
          </button>
        ) : (
          <form action={deleteAction} onSubmit={() => setLast('delete')} style={{ display: 'contents' }}>
            <input type="hidden" name="integrationId" value={integrationId} />
            <button
              type="submit"
              disabled={deletePending}
              aria-busy={deletePending || undefined}
              style={{ ...btn, color: 'var(--sev-critical-fg)', borderColor: 'var(--sev-critical-fg)', opacity: deletePending ? 0.55 : 1 }}
            >
              {deletePending ? 'Removing…' : 'Rules stop delivering — confirm'}
            </button>
            <button type="button" onClick={() => setArmed(false)} style={btn}>
              Keep
            </button>
          </form>
        )}
      </div>

      {state && (
        <p role="status" style={{ margin: 0, maxWidth: 380, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.message}
        </p>
      )}
    </div>
  );
}

const btn: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-2xs)',
  fontWeight: 500,
  padding: '0 var(--space-2)',
  height: 'var(--row-compact)',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
};
