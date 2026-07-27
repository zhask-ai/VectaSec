'use client';

import { useActionState } from 'react';

import { createOrgAction, type ActionState } from './actions';

export function CreateOrgForm() {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(createOrgAction, null);

  const field: React.CSSProperties = {
    width: '100%',
    padding: '8px 10px',
    background: 'var(--surface)',
    color: 'var(--text-primary)',
    border: '1px solid var(--border-interactive)',
    borderRadius: 'var(--radius-sm, 6px)',
    fontSize: 'var(--text-sm)',
  };

  return (
    <form action={formAction} style={{ display: 'grid', gap: 12 }}>
      <div style={{ display: 'grid', gap: 6 }}>
        <label htmlFor="name" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
          Organization name
        </label>
        <input
          id="name"
          name="name"
          type="text"
          required
          minLength={2}
          maxLength={80}
          placeholder="Acme Corp"
          autoComplete="organization"
          style={field}
        />
      </div>

      {state && !state.ok && (
        <p role="alert" style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--sev-critical-fg)' }}>
          {state.message}
        </p>
      )}

      <button
        type="submit"
        disabled={pending}
        style={{
          padding: '9px 12px',
          background: pending ? 'var(--surface-raised)' : 'var(--accent)',
          color: pending ? 'var(--text-secondary)' : 'var(--accent-fg)',
          border: '1px solid var(--border-interactive)',
          borderRadius: 'var(--radius-sm, 6px)',
          fontSize: 'var(--text-sm)',
          fontWeight: 600,
          cursor: pending ? 'default' : 'pointer',
        }}
      >
        {pending ? 'Creating…' : 'Create organization'}
      </button>
    </form>
  );
}
