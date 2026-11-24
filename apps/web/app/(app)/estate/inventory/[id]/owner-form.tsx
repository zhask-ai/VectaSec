'use client';

import { useActionState } from 'react';

import { confirmOwnerAction, type OwnerState } from './owner-action';

export function OwnerForm({ resourceId, current, editable, confirmed }: { resourceId: string; current: string; editable: boolean; confirmed: boolean }) {
  const [state, action, pending] = useActionState<OwnerState, FormData>(confirmOwnerAction, null);
  if (!editable) {
    return <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>Confirming an owner needs an editor or admin role.</p>;
  }
  const control: React.CSSProperties = {
    height: 'var(--row-default)',
    padding: '0 var(--space-3)',
    borderRadius: 'var(--radius-md)',
    border: '1px solid var(--border-interactive)',
    background: 'var(--surface-raised)',
    color: 'var(--text-primary)',
    fontSize: 'var(--text-sm)',
    minWidth: 0,
  };
  return (
    <form action={action} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <input type="hidden" name="resourceId" value={resourceId} />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <label className="vs-visually-hidden" htmlFor={`owner-${resourceId}`}>
          Owner
        </label>
        <input id={`owner-${resourceId}`} name="owner" defaultValue={current} required maxLength={200} placeholder="sam@company.com or Data team" style={{ ...control, flex: '2 1 220px' }} />
        <label className="vs-visually-hidden" htmlFor={`note-${resourceId}`}>
          Note
        </label>
        <input id={`note-${resourceId}`} name="note" maxLength={300} placeholder="Note (optional): what it is for" style={{ ...control, flex: '3 1 220px' }} />
        <button
          type="submit"
          className="vs-button"
          data-variant="primary"
          disabled={pending}
          style={{
            height: 'var(--row-default)',
            padding: '0 var(--space-4)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--accent)',
            background: 'var(--accent)',
            color: 'var(--accent-fg)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            cursor: pending ? 'wait' : 'pointer',
          }}
        >
          {pending ? 'Saving…' : confirmed ? 'Re-confirm' : 'Confirm owner'}
        </button>
      </div>
      {state && (
        <span role="status" style={{ fontSize: 'var(--text-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.message}
        </span>
      )}
    </form>
  );
}
