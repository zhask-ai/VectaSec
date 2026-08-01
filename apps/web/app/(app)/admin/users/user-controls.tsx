'use client';

import { useActionState, useState } from 'react';

import { Drawer } from '@/components/ui/drawer';
import { StatusPill } from '@/components/ui/status-pill';
import {
  adminAddToOrgAction,
  adminDeleteUserAction,
  adminGrantSuperAction,
  adminRemoveFromOrgAction,
  adminRevokeSuperAction,
  adminSetRoleAction,
  type ActionState,
} from './actions';

/* Per-user management for platform operators: every org this account belongs to, its role in
 * each, the operator roster, and the delete.
 *
 * A DRAWER, not a row of inline buttons, because managing one account means several related
 * decisions ("which orgs is this person in, and should they still be?") and a table row can
 * hold one of them at most. It also gives the destructive half a place to live BELOW the
 * routine half, behind its own heading, instead of a delete button sitting one careless click
 * away from a role select.
 *
 * Every control is its own <form> around its own Server Action: a role select and a delete
 * must not share a submit, and each keeps its own pending state so one in-flight call does not
 * grey out the rest.
 */

export type Membership = { tenant_id: string; tenant: string; role: string };
export type OrgOption = { id: string; name: string };

const ROLES = ['admin', 'editor', 'viewer'] as const;

export function UserControls({
  userId,
  email,
  memberships,
  isSuper,
  isSelf,
  orgs,
}: {
  userId: string;
  email: string;
  memberships: Membership[];
  isSuper: boolean;
  isSelf: boolean;
  orgs: OrgOption[];
}) {
  const [open, setOpen] = useState(false);

  // Orgs this account is NOT already in — the only ones "add to organization" can mean.
  const joinable = orgs.filter((o) => !memberships.some((m) => m.tenant_id === o.id));

  return (
    <>
      <button type="button" onClick={() => setOpen(true)} style={linkButtonStyle}>
        Manage
      </button>

      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        width={560}
        title={email}
        description={
          isSuper
            ? 'Platform operator — admin rank in every organization.'
            : `${memberships.length} organization${memberships.length === 1 ? '' : 's'}`
        }
      >
        <div style={{ display: 'grid', gap: 'var(--space-5)' }}>
          <Section title="Organizations" hint="Role changes and removals take effect on their next action — sessions are re-checked, not merely expired.">
            {memberships.length === 0 ? (
              <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                This account belongs to no organization. It can sign in, and will see nothing until
                it is added to one.
              </p>
            ) : (
              <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
                {memberships.map((m) => (
                  <MembershipRow key={m.tenant_id} userId={userId} membership={m} />
                ))}
              </div>
            )}
          </Section>

          {joinable.length > 0 && (
            <Section title="Add to an organization">
              <AddToOrg userId={userId} email={email} orgs={joinable} />
            </Section>
          )}

          <Section
            title="Platform operator"
            hint="Operators get admin rank in every organization and can reach this page."
          >
            <SuperToggle userId={userId} isSuper={isSuper} isSelf={isSelf} />
          </Section>

          <Section title="Delete account" danger>
            <DeleteAccount userId={userId} email={email} isSuper={isSuper} isSelf={isSelf} />
          </Section>
        </div>
      </Drawer>
    </>
  );
}

/** Invite anyone, into any org — the platform-level entry point, for an address that may have
 * no account at all. The engine resolves the email: an existing account is simply added, and a
 * new one is created through GoTrue's admin invite so they get an email to set a password.
 * Rate-limited server-side per tenant, because this endpoint mails an address the caller
 * chose from the customer's domain. */
export function InviteUser({ orgs }: { orgs: OrgOption[] }) {
  const [open, setOpen] = useState(false);
  const [state, action, pending] = useActionState<ActionState, FormData>(adminAddToOrgAction, null);

  return (
    <>
      <button type="button" onClick={() => setOpen(true)} style={primaryButtonStyle}>
        + Invite a user
      </button>

      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        width={480}
        title="Invite a user"
        description="They are added to the organization you pick. If no account exists for the address, one is created and they get an email to set a password."
      >
        {orgs.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            There are no organizations yet. A user must belong to one, so create an organization
            first.
          </p>
        ) : (
          <form action={action} style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <label style={fieldLabelStyle}>
              Email
              <input
                name="email"
                type="email"
                required
                autoComplete="off"
                spellCheck={false}
                placeholder="person@company.com"
                style={inputStyle}
              />
            </label>
            <label style={fieldLabelStyle}>
              Organization
              <select name="org" required style={{ ...selectStyle, height: 'var(--row-default)' }}>
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </select>
            </label>
            <label style={fieldLabelStyle}>
              Role
              <select name="role" defaultValue="viewer" style={{ ...selectStyle, height: 'var(--row-default)' }}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </label>
            <button type="submit" disabled={pending} style={primaryButtonStyle}>
              {pending ? 'Inviting…' : 'Send invitation'}
            </button>
            <Result state={state} />
          </form>
        )}
      </Drawer>
    </>
  );
}

/* ── Sections ──────────────────────────────────────────────────────────────────────────── */

function Section({
  title,
  hint,
  danger,
  children,
}: {
  title: string;
  hint?: string;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <section
      style={{
        display: 'grid',
        gap: 'var(--space-2)',
        ...(danger
          ? {
              padding: 'var(--space-3)',
              border: '1px solid var(--sev-critical-fg)',
              borderRadius: 'var(--radius-md)',
              background: 'var(--sev-critical-bg)',
            }
          : null),
      }}
    >
      <h3
        style={{
          margin: 0,
          fontSize: 'var(--text-2xs)',
          fontWeight: 600,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          color: danger ? 'var(--sev-critical-fg)' : 'var(--text-secondary)',
        }}
      >
        {title}
      </h3>
      {hint && (
        <p style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
          {hint}
        </p>
      )}
      {children}
    </section>
  );
}

function MembershipRow({ userId, membership }: { userId: string; membership: Membership }) {
  const [roleState, roleAction, rolePending] = useActionState<ActionState, FormData>(adminSetRoleAction, null);
  const [rmState, rmAction, rmPending] = useActionState<ActionState, FormData>(adminRemoveFromOrgAction, null);
  const state = roleState ?? rmState;

  return (
    <div
      style={{
        display: 'grid',
        gap: 'var(--space-2)',
        padding: 'var(--space-3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        background: 'var(--surface)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
          {membership.tenant}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          {/* Role select submits on change — one control, one decision, no separate Save to
              forget. The engine refuses to demote an org's last admin and says so. */}
          <form action={roleAction}>
            <input type="hidden" name="org" value={membership.tenant_id} />
            <input type="hidden" name="userId" value={userId} />
            <select
              name="role"
              defaultValue={normalizeRole(membership.role)}
              disabled={rolePending}
              onChange={(e) => e.currentTarget.form?.requestSubmit()}
              aria-label={`Role in ${membership.tenant}`}
              style={selectStyle}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </form>
          <form action={rmAction}>
            <input type="hidden" name="org" value={membership.tenant_id} />
            <input type="hidden" name="userId" value={userId} />
            <button type="submit" disabled={rmPending} style={dangerButtonStyle}>
              {rmPending ? 'Removing…' : 'Remove'}
            </button>
          </form>
        </div>
      </div>
      <Result state={state} />
    </div>
  );
}

function AddToOrg({ userId, email, orgs }: { userId: string; email: string; orgs: OrgOption[] }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(adminAddToOrgAction, null);
  void userId; // membership is resolved by email server-side; the id is not part of this call.

  return (
    <form action={action} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <input type="hidden" name="email" value={email} />
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <select name="org" required aria-label="Organization" style={{ ...selectStyle, flex: 1, minWidth: 180 }}>
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>
              {o.name}
            </option>
          ))}
        </select>
        <select name="role" defaultValue="viewer" aria-label="Role" style={selectStyle}>
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <button type="submit" disabled={pending} style={buttonStyle}>
          {pending ? 'Adding…' : 'Add'}
        </button>
      </div>
      <Result state={state} />
    </form>
  );
}

function SuperToggle({ userId, isSuper, isSelf }: { userId: string; isSuper: boolean; isSelf: boolean }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(
    isSuper ? adminRevokeSuperAction : adminGrantSuperAction,
    null,
  );

  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
        <StatusPill tone={isSuper ? 'ok' : 'neutral'} label={isSuper ? 'operator' : 'not an operator'} />
        {isSuper && isSelf ? (
          // Self-revocation is a silent lockout — the console keeps rendering until the next
          // page load. The engine refuses it too; saying so here saves a pointless round trip.
          <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
            You cannot revoke your own operator rank — ask another operator.
          </span>
        ) : (
          <form action={action}>
            <input type="hidden" name="userId" value={userId} />
            <button type="submit" disabled={pending} style={isSuper ? dangerButtonStyle : buttonStyle}>
              {pending ? 'Working…' : isSuper ? 'Revoke operator rank' : 'Make platform operator'}
            </button>
          </form>
        )}
      </div>
      <Result state={state} />
    </div>
  );
}

function DeleteAccount({
  userId,
  email,
  isSuper,
  isSelf,
}: {
  userId: string;
  email: string;
  isSuper: boolean;
  isSelf: boolean;
}) {
  const [state, action, pending] = useActionState<ActionState, FormData>(adminDeleteUserAction, null);
  const [confirm, setConfirm] = useState('');

  if (isSelf) {
    return (
      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--sev-critical-fg)' }}>
        You cannot delete your own account.
      </p>
    );
  }
  if (isSuper) {
    return (
      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--sev-critical-fg)' }}>
        This account is a platform operator. Revoke its operator rank first — two deliberate
        steps, so deleting an operator is never one misclick.
      </p>
    );
  }

  const armed = confirm.toLowerCase() === email.toLowerCase();

  return (
    <form action={action} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <input type="hidden" name="userId" value={userId} />
      <input type="hidden" name="email" value={email} />
      <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-primary)' }}>
        Deletes the account and every membership it holds. They can no longer sign in. There is
        no undo.
      </p>
      <label style={{ display: 'grid', gap: 'var(--space-1)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        Type <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{email}</strong> to confirm
        <input
          name="confirm"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="off"
          spellCheck={false}
          style={inputStyle}
        />
      </label>
      {/* Disabled until the name matches — a hint, not the gate. The action re-checks the
          typed value server-side, because a disabled attribute stops nobody who can POST. */}
      <button type="submit" disabled={!armed || pending} style={{ ...dangerButtonStyle, opacity: armed ? 1 : 0.5 }}>
        {pending ? 'Deleting…' : 'Delete this account permanently'}
      </button>
      <Result state={state} />
    </form>
  );
}

/* ── Primitives ────────────────────────────────────────────────────────────────────────── */

function normalizeRole(raw: string): string {
  const r = raw.toLowerCase();
  if (r === 'owner' || r === 'admin') return 'admin';
  if (r === 'editor' || r === 'analyst') return 'editor';
  return 'viewer';
}

function Result({ state }: { state: ActionState }) {
  if (!state) return null;
  return (
    <p
      role="status"
      style={{
        margin: 0,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
      }}
    >
      {state.ok ? '' : 'Not applied — '}
      {state.message}
    </p>
  );
}

const buttonStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  fontWeight: 500,
  padding: '0 var(--space-3)',
  height: 'var(--row-compact)',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
};

const dangerButtonStyle: React.CSSProperties = {
  ...buttonStyle,
  color: 'var(--sev-critical-fg)',
  borderColor: 'var(--sev-critical-fg)',
};

const primaryButtonStyle: React.CSSProperties = {
  ...buttonStyle,
  height: 'var(--row-default)',
  fontWeight: 600,
  background: 'var(--accent)',
  color: 'var(--accent-fg)',
};

const fieldLabelStyle: React.CSSProperties = {
  display: 'grid',
  gap: 'var(--space-1)',
  fontSize: 'var(--text-2xs)',
  fontWeight: 600,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  color: 'var(--text-secondary)',
};

const linkButtonStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'transparent',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-2xs)',
  fontWeight: 500,
  padding: '0 var(--space-2)',
  height: 'var(--row-compact)',
  cursor: 'pointer',
};

const selectStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  height: 'var(--row-compact)',
  padding: '0 var(--space-2)',
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
