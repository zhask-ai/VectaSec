'use client';

import { useActionState } from 'react';

import { mintCanaryAction, revokeCanaryAction, type ActionState, type MintState } from './actions';

const control: React.CSSProperties = {
  height: 'var(--row-default)',
  padding: '0 var(--space-2)',
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border-interactive)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  width: '100%',
  minWidth: 0,
};
const label: React.CSSProperties = {
  display: 'grid',
  gap: 'var(--space-1)',
  fontSize: 'var(--text-2xs)',
  fontWeight: 600,
  color: 'var(--text-secondary)',
  minWidth: 0,
};
const mono: React.CSSProperties = {
  margin: 0,
  padding: 'var(--space-3)',
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border)',
  background: 'var(--surface-raised)',
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-2xs)',
  whiteSpace: 'pre-wrap',
  overflowWrap: 'anywhere',
};

export function MintForm({ editable }: { editable: boolean }) {
  const [state, action, pending] = useActionState<MintState, FormData>(mintCanaryAction, null);
  const m = state?.ok ? state.minted : undefined;
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <form action={action} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--space-3)', alignItems: 'end' }}>
        <label style={label}>
          Name (shown in the alert)
          <input name="name" required maxLength={120} placeholder="Old billing export" style={control} />
        </label>
        <label style={label}>
          Where you will put it (optional)
          <input name="placed_in" maxLength={300} placeholder="n8n workflow “Invoices (old)”" style={control} />
        </label>
        <button
          type="submit"
          className="vs-button"
          data-variant="primary"
          disabled={pending || !editable}
          aria-busy={pending || undefined}
          style={{
            border: '1px solid var(--accent)',
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent)',
            color: 'var(--accent-fg)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            padding: '0 var(--space-4)',
            height: 'var(--row-default)',
            justifySelf: 'start',
            cursor: pending || !editable ? 'not-allowed' : 'pointer',
            opacity: pending || !editable ? 0.6 : 1,
          }}
        >
          {pending ? 'Creating…' : 'Create canary'}
        </button>
      </form>
      {!editable && (
        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          Creating a canary needs an editor or admin role.
        </span>
      )}
      {state && !state.ok && (
        <span role="alert" style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
          {state.message}
        </span>
      )}
      {m && (
        <div role="status" style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', fontWeight: 600 }}>{state?.message}</p>
          <pre style={mono}>{m.url ?? m.path}</pre>
          {m.snippets.map((s) => (
            <div key={s.title} style={{ display: 'grid', gap: 'var(--space-1)' }}>
              <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, color: 'var(--text-secondary)' }}>{s.title}</span>
              <pre style={mono}>{s.body}</pre>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function RevokeButton({ id }: { id: string }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(revokeCanaryAction, null);
  return (
    <form action={action} style={{ display: 'inline-flex', gap: 'var(--space-2)', alignItems: 'center' }}>
      <input type="hidden" name="id" value={id} />
      <button type="submit" className="vs-actionbtn" data-danger disabled={pending}>
        {pending ? 'Revoking…' : 'Revoke'}
      </button>
      {state && !state.ok && (
        <span role="alert" style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
          {state.message}
        </span>
      )}
    </form>
  );
}
