'use client';

import { useActionState } from 'react';

import {
  adminChangeRoleAction,
  adminInviteAction,
  adminRemoveMemberAction,
  type ActionState,
} from './actions';

const field: React.CSSProperties = {
  padding: '7px 9px',
  background: 'var(--surface)',
  color: 'var(--text-primary)',
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-sm, 6px)',
  fontSize: 'var(--text-sm)',
};

function Feedback({ state }: { state: ActionState }) {
  if (!state) return null;
  return (
    <p
      role={state.ok ? 'status' : 'alert'}
      style={{
        margin: 0,
        fontSize: 'var(--text-2xs)',
        color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
      }}
    >
      {state.message}
    </p>
  );
}

/** Invite-on-behalf: the same engine path an org admin uses, acting as the operator. */
export function AdminInviteForm({ orgId }: { orgId: string }) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(adminInviteAction, null);

  return (
    <form action={formAction} style={{ display: 'grid', gap: 8 }}>
      <input type="hidden" name="org" value={orgId} />
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input
          type="email"
          name="email"
          required
          placeholder="person@company.com"
          aria-label="Email to invite"
          style={{ ...field, flex: '1 1 220px' }}
        />
        <select name="role" defaultValue="editor" aria-label="Role" style={field}>
          <option value="admin">admin</option>
          <option value="editor">editor</option>
          <option value="viewer">viewer</option>
        </select>
        <button
          type="submit"
          disabled={pending}
          style={{
            ...field,
            background: pending ? 'var(--surface-raised)' : 'var(--accent)',
            color: pending ? 'var(--text-secondary)' : 'var(--accent-fg)',
            fontWeight: 600,
            cursor: pending ? 'default' : 'pointer',
          }}
        >
          {pending ? 'Inviting…' : 'Invite'}
        </button>
      </div>
      <Feedback state={state} />
    </form>
  );
}

/** Per-member row controls: role select (applies on change) + remove. */
export function AdminMemberControls({
  orgId,
  userId,
  role,
}: {
  orgId: string;
  userId: string;
  role: string;
}) {
  const [roleState, roleAction, rolePending] = useActionState<ActionState, FormData>(
    adminChangeRoleAction,
    null,
  );
  const [removeState, removeAction, removePending] = useActionState<ActionState, FormData>(
    adminRemoveMemberAction,
    null,
  );

  return (
    <div style={{ display: 'grid', gap: 4 }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <form action={roleAction}>
          <input type="hidden" name="org" value={orgId} />
          <input type="hidden" name="user_id" value={userId} />
          <select
            name="role"
            defaultValue={role}
            aria-label="Change role"
            disabled={rolePending}
            onChange={(e) => e.currentTarget.form?.requestSubmit()}
            style={{ ...field, padding: '4px 6px', fontSize: 'var(--text-2xs)' }}
          >
            <option value="admin">admin</option>
            <option value="editor">editor</option>
            <option value="viewer">viewer</option>
          </select>
        </form>
        <form action={removeAction}>
          <input type="hidden" name="org" value={orgId} />
          <input type="hidden" name="user_id" value={userId} />
          <button
            type="submit"
            disabled={removePending}
            style={{
              ...field,
              padding: '4px 8px',
              fontSize: 'var(--text-2xs)',
              color: 'var(--sev-critical-fg)',
              background: 'transparent',
              cursor: removePending ? 'default' : 'pointer',
            }}
          >
            {removePending ? 'Removing…' : 'Remove'}
          </button>
        </form>
      </div>
      <Feedback state={roleState ?? removeState} />
    </div>
  );
}
