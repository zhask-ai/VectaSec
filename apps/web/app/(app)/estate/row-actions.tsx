'use client';

import { useActionState, useState } from 'react';

import { IconPlay, IconTrash, IconZap } from '@/components/ui/icons';
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
 * Visually they are now a compact icon-labelled cluster (.vs-actionbtn) that sits quiet until
 * the row is hovered — three full text buttons per row made every row shout. Results render in
 * a shared line under the cluster: the newest action's outcome is the one a human is waiting
 * on, and three stacked status lines in a table cell is noise.
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
    <div data-row-actions style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <div style={{ display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
        <form action={scanAction} onSubmit={() => setLast('scan')} style={{ display: 'contents' }}>
          <input type="hidden" name="connectionId" value={connectionId} />
          <button
            type="submit"
            className="vs-actionbtn"
            disabled={scanPending || scanActive}
            aria-busy={scanPending || undefined}
            title={scanActive ? 'A scan is already queued or running' : `Queue a scan of ${name}`}
          >
            <IconPlay size={12} />
            {scanPending ? 'Queuing…' : scanActive ? 'Scanning…' : 'Scan'}
          </button>
        </form>

        <form action={testAction} onSubmit={() => setLast('test')} style={{ display: 'contents' }}>
          <input type="hidden" name="connectionId" value={connectionId} />
          <button
            type="submit"
            className="vs-actionbtn"
            disabled={testPending}
            aria-busy={testPending || undefined}
            title={`Check ${name} is reachable (read-only collect, persists nothing)`}
          >
            <IconZap size={12} />
            {testPending ? 'Testing…' : 'Test'}
          </button>
        </form>

        {!armed ? (
          <button
            type="button"
            className="vs-actionbtn"
            data-danger
            onClick={() => setArmed(true)}
            title={`Remove ${name} and everything collected through it`}
            aria-label={`Remove ${name}`}
          >
            <IconTrash size={12} />
          </button>
        ) : (
          <form action={deleteAction} onSubmit={() => setLast('delete')} style={{ display: 'contents' }}>
            <input type="hidden" name="connectionId" value={connectionId} />
            <button
              type="submit"
              className="vs-actionbtn"
              disabled={deletePending}
              aria-busy={deletePending || undefined}
              style={{
                color: 'var(--sev-critical-fg)',
                borderColor: 'var(--sev-critical-solid)',
                background: 'var(--sev-critical-bg)',
                fontWeight: 600,
              }}
            >
              {deletePending ? 'Removing…' : 'Delete data too — confirm'}
            </button>
            <button type="button" className="vs-actionbtn" onClick={() => setArmed(false)}>
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
