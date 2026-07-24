'use client';

import { useActionState, useState } from 'react';

import { addMemberAction, changeRoleAction, removeMemberAction, type ActionState } from './actions';

/* Per-member controls and the add-member form. Same pattern as connections/row-actions: each
 * mutation is its own <form> around a Server Action (no-JS safe, server re-verified), nothing
 * optimistic, results rendered under the control that caused them. Remove is two-step in
 * place, and the armed label names the consequence. */

const ROLES: { value: string; label: string; hint: string }[] = [
  { value: 'admin', label: 'admin', hint: 'Manages members, integrations and settings.' },
  { value: 'editor', label: 'editor', hint: 'Runs scans, works findings, attests controls.' },
  { value: 'viewer', label: 'viewer', hint: 'Reads everything, changes nothing.' },
];

export function MemberRowControls({
  userId,
  email,
  role,
  isSelf,
}: {
  userId: string;
  email: string;
  role: string;
  /** The caller's own row: allowed (the engine protects the last admin), but labelled, because
   * demoting yourself is the one click here that locks the clicker out. */
  isSelf: boolean;
}) {
  const [roleState, roleAction, rolePending] = useActionState<ActionState, FormData>(changeRoleAction, null);
  const [removeState, removeAction, removePending] = useActionState<ActionState, FormData>(removeMemberAction, null);
  const [armed, setArmed] = useState(false);
  const [last, setLast] = useState<'role' | 'remove' | null>(null);

  const state = last === 'role' ? roleState : last === 'remove' ? removeState : null;

  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap', alignItems: 'center' }}>
        <form action={roleAction} onSubmit={() => setLast('role')} style={{ display: 'contents' }}>
          <input type="hidden" name="userId" value={userId} />
          <label htmlFor={`role-${userId}`} className="vs-visually-hidden">
            Role for {email}
          </label>
          {/* key remounts the select when the saved role changes, so the DOM can never show a
              role the database does not hold after React 19's post-action form reset.
              The live DB also holds legacy tier synonyms (owner→admin tier, analyst→editor
              tier — same mapping as lib/role.ts and the engine's ROLE_RANK); the select speaks
              the three console roles, so legacy values default to their tier's option. */}
          <select
            id={`role-${userId}`}
            key={role}
            name="role"
            defaultValue={role === 'owner' ? 'admin' : role === 'analyst' ? 'editor' : role}
            disabled={rolePending}
            style={selectStyle}
          >
            {ROLES.map((r) => (
              <option key={r.value} value={r.value} title={r.hint}>
                {r.label}
              </option>
            ))}
          </select>
          <button type="submit" disabled={rolePending} aria-busy={rolePending || undefined} style={{ ...btn, opacity: rolePending ? 0.55 : 1 }}>
            {rolePending ? 'Saving…' : 'Change role'}
          </button>
        </form>

        {!armed ? (
          <button type="button" onClick={() => setArmed(true)} title={`Remove ${email}`} style={btn}>
            Remove
          </button>
        ) : (
          <form action={removeAction} onSubmit={() => setLast('remove')} style={{ display: 'contents' }}>
            <input type="hidden" name="userId" value={userId} />
            <button
              type="submit"
              disabled={removePending}
              aria-busy={removePending || undefined}
              style={{ ...btn, color: 'var(--sev-critical-fg)', borderColor: 'var(--sev-critical-fg)', opacity: removePending ? 0.55 : 1 }}
            >
              {removePending
                ? 'Removing…'
                : isSelf
                  ? 'Remove yourself — confirm'
                  : `Revoke ${email}'s access — confirm`}
            </button>
            <button type="button" onClick={() => setArmed(false)} style={btn}>
              Keep
            </button>
          </form>
        )}
      </div>

      {state && (
        <p role="status" style={{ margin: 0, maxWidth: 420, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.message}
        </p>
      )}
    </div>
  );
}

export function AddMemberForm() {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(addMemberAction, null);
  const [role, setRole] = useState('viewer');

  return (
    <form action={formAction} style={{ display: 'grid', gap: 'var(--space-2)', maxWidth: 560 }}>
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'end' }}>
        <div style={{ display: 'grid', gap: 'var(--space-1)', flex: '1 1 240px' }}>
          <label htmlFor="add-member-email" style={labelStyle}>
            Email
          </label>
          <input
            id="add-member-email"
            name="email"
            type="email"
            required
            maxLength={254}
            placeholder="colleague@example.com"
            autoComplete="off"
            spellCheck={false}
            style={inputStyle}
          />
        </div>
        <div style={{ display: 'grid', gap: 'var(--space-1)' }}>
          <label htmlFor="add-member-role" style={labelStyle}>
            Role
          </label>
          {/* Controlled via state + hidden-input-free: the select itself submits; value bound
              to state only so the hint below always matches what will be submitted. */}
          <select id="add-member-role" name="role" value={role} onChange={(e) => setRole(e.target.value)} style={{ ...inputStyle, width: 'auto' }}>
            {ROLES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
        <button type="submit" disabled={pending} aria-busy={pending || undefined} style={{ ...btn, height: 'var(--row-default)', fontWeight: 600, opacity: pending ? 0.55 : 1 }}>
          {pending ? 'Adding…' : 'Add member'}
        </button>
      </div>

      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
        {ROLES.find((r) => r.value === role)?.hint} If an account with this email exists it is
        added directly; otherwise the engine sends an invitation email when invites are enabled,
        and says so honestly when they are not.
      </p>

      {state && (
        <p role="status" style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.ok ? '' : 'Not applied — '}
          {state.message}
        </p>
      )}
    </form>
  );
}

/* ── Primitives (tokens only; mirror connections/row-actions until ui/ grows these) ────── */

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

const inputStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  padding: '0 var(--space-2)',
  height: 'var(--row-default)',
  width: '100%',
};

const selectStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-2xs)',
  padding: '0 var(--space-1)',
  height: 'var(--row-compact)',
};

const labelStyle: React.CSSProperties = {
  fontSize: 'var(--text-2xs)',
  fontWeight: 600,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  color: 'var(--text-secondary)',
};
