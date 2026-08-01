'use server';

import { revalidatePath } from 'next/cache';

import { engineDelete, enginePatch, enginePost } from '@/lib/engine';
import { getOwnMembership, isSuperAdmin } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

/* Platform-operator actions on ANY user, from the platform user list.
 *
 * Two kinds of thing live here and they authorize differently:
 *
 *   TENANT-SCOPED (add to org, change role in org, remove from org) reuse the ordinary
 *   /members endpoints, targeted at whichever org the operator picked. A super_admins row
 *   grants the admin tier in every tenant, so the engine accepts the call and audits it
 *   under the operator's real user id, inside that org's trail — which is where a customer
 *   admin looking for "who added this account" would go looking.
 *
 *   PLATFORM-SCOPED (delete the account, grant/revoke operator rank) hit /admin/* and are
 *   gated by the engine's `super_operator` dependency, which requires an actual roster row
 *   and refuses tenant admins however senior. Their guards — no self-delete, no
 *   self-revoke, no deleting another operator, no revoking the last one — live in the
 *   engine, and its refusals are shown here verbatim.
 *
 * Console-side checks exist so a non-operator gets an honest refusal without a network hop;
 * the engine's check is the real one. The tenant header for platform calls is the operator's
 * OWN tenant: audit_log.tenant_id is not nullable, and a platform action has no tenant of its
 * own — the target user id is in `target`, so the trail is complete regardless.
 */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED = 'Platform operators only. Nothing was sent.';
const ROLES = ['admin', 'editor', 'viewer'] as const;

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

/** Operator identity, plus a tenant to act in. `orgId` is supplied for tenant-scoped calls
 * (the org the operator picked in the UI); platform calls pass none and borrow the
 * operator's own tenant purely so the audit row has somewhere to land. */
async function authorizeOperator(orgId?: string) {
  const user = await getVerifiedUser();
  if (!user) return null;
  if (!(await isSuperAdmin())) return null;
  if (orgId) {
    if (!isUuid(orgId)) return null;
    return { tenantId: orgId, actor: user.id };
  }
  const own = await getOwnMembership();
  if (!own) return null;
  return { tenantId: own.tenantId, actor: user.id };
}

function done(message: string): ActionState {
  revalidatePath('/admin/users');
  revalidatePath('/admin');
  return { ok: true, message };
}

/* ── Tenant-scoped: membership and permissions ─────────────────────────────────────────── */

/** Add an existing account to an org, or invite a brand-new one by email. The engine resolves
 * the address against real accounts and sends the GoTrue invite when there is none — its
 * refusals ("no user with this email", the invite rate limit) are the honest ones. */
export async function adminAddToOrgAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const orgId = str(form, 'org');
  const email = str(form, 'email').toLowerCase().slice(0, 254);
  const role = str(form, 'role');

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, message: 'Enter the email address the person signs in with.' };
  }
  if (!(ROLES as readonly string[]).includes(role)) return { ok: false, message: 'Pick a role.' };

  const auth = await authorizeOperator(orgId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ email: string; role: string; invited: boolean }>(
    '/members',
    { email, role },
    auth,
  );
  if (!res.ok) return { ok: false, message: res.message };

  return done(
    res.data.invited
      ? `Invited ${res.data.email} as ${res.data.role} — they get an email to set a password, and they are a member already.`
      : `Added ${res.data.email} as ${res.data.role}.`,
  );
}

/** Change a user's role inside one org. The engine refuses to demote that org's last admin
 * and says so. */
export async function adminSetRoleAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const orgId = str(form, 'org');
  const userId = str(form, 'userId');
  const role = str(form, 'role');

  if (!isUuid(userId) || !(ROLES as readonly string[]).includes(role)) {
    return { ok: false, message: 'Malformed request.' };
  }

  const auth = await authorizeOperator(orgId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePatch<{ role: string }>(`/members/${userId}`, { role }, auth);
  if (!res.ok) return { ok: false, message: res.message };

  return done(`Role changed to ${res.data.role}.`);
}

/** Remove a user from one org. The account itself is untouched — that is the delete below. */
export async function adminRemoveFromOrgAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const orgId = str(form, 'org');
  const userId = str(form, 'userId');
  if (!isUuid(userId)) return { ok: false, message: 'Malformed request.' };

  const auth = await authorizeOperator(orgId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ removed: boolean }>(`/members/${userId}`, auth);
  if (!res.ok) return { ok: false, message: res.message };

  return done('Removed from the organization. The account still exists.');
}

/* ── Platform-scoped: the account itself, and the operator roster ──────────────────────── */

/** Delete an auth account platform-wide, with every membership it held.
 *
 * Typed confirmation is required and checked HERE as well as being asked for in the UI: a
 * disabled button is a hint, not a gate, and this is the one action in the console with no
 * undo. The engine still refuses self-deletion and deleting another operator. */
export async function adminDeleteUserAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const userId = str(form, 'userId');
  const email = str(form, 'email');
  const confirm = str(form, 'confirm');

  if (!isUuid(userId)) return { ok: false, message: 'Malformed request.' };
  if (confirm.toLowerCase() !== email.toLowerCase() || !email) {
    return { ok: false, message: 'Type the account’s email exactly to confirm. Nothing was deleted.' };
  }

  const auth = await authorizeOperator();
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ email: string; memberships_removed: number }>(
    `/admin/users/${userId}`,
    auth,
  );
  if (!res.ok) return { ok: false, message: res.message };

  return done(
    `Deleted ${res.data.email} and ${res.data.memberships_removed} membership${
      res.data.memberships_removed === 1 ? '' : 's'
    }. They can no longer sign in.`,
  );
}

/** Grant platform operator rank — full access to every org and this surface. */
export async function adminGrantSuperAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const userId = str(form, 'userId');
  if (!isUuid(userId)) return { ok: false, message: 'Malformed request.' };

  const auth = await authorizeOperator();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ email: string }>(`/admin/super-admins/${userId}`, {}, auth);
  if (!res.ok) return { ok: false, message: res.message };

  return done(`${res.data.email} is now a platform operator — admin rank in every organization.`);
}

/** Revoke platform operator rank. The engine refuses self-revocation (a silent lockout) and
 * refuses to remove the last operator. */
export async function adminRevokeSuperAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const userId = str(form, 'userId');
  if (!isUuid(userId)) return { ok: false, message: 'Malformed request.' };

  const auth = await authorizeOperator();
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ revoked: boolean }>(`/admin/super-admins/${userId}`, auth);
  if (!res.ok) return { ok: false, message: res.message };

  return done('Platform operator rank revoked. Their tenant memberships are unchanged.');
}
