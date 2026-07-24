'use client';

import { useActionState, useState } from 'react';

import {
  deleteConnectionAction,
  scanConnectionAction,
  testConnectionAction,
  type ActionState,
} from './actions';

/* Per-connection controls, living inside a table row.
 *
 * Three independent forms (scan / test / delete) rather than one with intent switches, so each
 * keeps its own pending state and the browser's no-JS fallback still posts something sensible.
 * Results render in a shared line under the buttons — the newest action's outcome is the one a
 * human is waiting on, and three stacked status lines in a table cell is noise.
 *
 * Delete is two-step in place: first click arms it, second confirms. It removes the
 * connection and everything collected through it (the server says the counts back), so the
 * armed state names the consequence rather than asking "are you sure".
 */

export function RowActions({
  connectionId,
  name,
  scanActive,
}: {
  connectionId: string;
  name: string;
  /** True while this connection already has a queued/running scan — Scan now is disabled so
   * an impatient double-click cannot pile up identical jobs. */
  scanActive: boolean;
}) {
  const [scanState, scanAction, scanPending] = useActionState<ActionState, FormData>(scanConnectionAction, null);
  const [testState, testAction, testPending] = useActionState<ActionState, FormData>(testConnectionAction, null);
  const [deleteState, deleteAction, deletePending] = useActionState<ActionState, FormData>(deleteConnectionAction, null);
  const [armed, setArmed] = useState(false);
  const [last, setLast] = useState<'scan' | 'test' | 'delete' | null>(null);

  const state = last === 'scan' ? scanState : last === 'test' ? testState : last === 'delete' ? deleteState : null;

  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
        <form action={scanAction} onSubmit={() => setLast('scan')} style={{ display: 'contents' }}>
          <input type="hidden" name="connectionId" value={connectionId} />
          <button
            type="submit"
            disabled={scanPending || scanActive}
            aria-busy={scanPending || undefined}
            title={scanActive ? 'A scan is already queued or running' : `Queue a scan of ${name}`}
            style={{ ...btn, fontWeight: 600, opacity: scanPending || scanActive ? 0.55 : 1 }}
          >
            {scanPending ? 'Queuing…' : scanActive ? 'Scanning…' : 'Scan now'}
          </button>
        </form>

        <form action={testAction} onSubmit={() => setLast('test')} style={{ display: 'contents' }}>
          <input type="hidden" name="connectionId" value={connectionId} />
          <button
            type="submit"
            disabled={testPending}
            aria-busy={testPending || undefined}
            title={`Check ${name} is reachable (read-only collect, persists nothing)`}
            style={{ ...btn, opacity: testPending ? 0.55 : 1 }}
          >
            {testPending ? 'Testing…' : 'Test'}
          </button>
        </form>

        {!armed ? (
          <button type="button" onClick={() => setArmed(true)} title={`Remove ${name}`} style={btn}>
            Remove
          </button>
        ) : (
          <form action={deleteAction} onSubmit={() => setLast('delete')} style={{ display: 'contents' }}>
            <input type="hidden" name="connectionId" value={connectionId} />
            <button
              type="submit"
              disabled={deletePending}
              aria-busy={deletePending || undefined}
              style={{ ...btn, color: 'var(--sev-critical-fg)', borderColor: 'var(--sev-critical-fg)', opacity: deletePending ? 0.55 : 1 }}
            >
              {deletePending ? 'Removing…' : 'Delete data too — confirm'}
            </button>
            <button type="button" onClick={() => setArmed(false)} style={btn}>
              Keep
            </button>
          </form>
        )}
      </div>

      {state && (
        <p
          role="status"
          style={{
            margin: 0,
            maxWidth: 360,
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
          }}
        >
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
