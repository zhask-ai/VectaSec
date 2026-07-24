'use server';

import { revalidatePath } from 'next/cache';

import { engineDelete, enginePatch, enginePost } from '@/lib/engine';
import { getOwnMembership, isAdmin } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

/* Member management — admin-only, engine-written.
 *
 * The browser role cannot write tenant_members (SELECT-only, own row), so every change goes
 * through the engine, which audits it and enforces the invariants the console must not try to
 * re-implement (notably last-admin protection: the engine refuses to demote or remove the
 * only admin, and its refusal message is shown verbatim).
 *
 * Same posture as every other action file:
 *   1. getVerifiedUser() — revocation-checked. A revoked admin must not mint members.
 *   2. Role re-read from the caller's own tenant_members row on every action. Admin only.
 *   3. Tenant from that same RLS-read membership row — never from the form.
 */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED = 'You are not signed in, or you are not an admin of this tenant. Nothing was sent.';

const ROLES = ['admin', 'editor', 'viewer'] as const;
type FormRole = (typeof ROLES)[number];

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

/** Identity + admin role + tenant, or refusal. The tenant comes from the caller's own
 * membership row (RLS: user_id = auth.uid()), so it can only name a tenant they belong to. */
async function authorizeAdmin() {
  const user = await getVerifiedUser();
  if (!user) return null;
  const membership = await getOwnMembership();
  if (!membership || !isAdmin(membership.role)) return null;
  return { tenantId: membership.tenantId, actor: user.id };
}

export async function addMemberAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const email = str(form, 'email').toLowerCase().slice(0, 254);
  const role = str(form, 'role');

  // Not full RFC validation — the engine resolves the address against real accounts and is
  // the authority. This just catches an obviously empty or mangled field before a round trip.
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, message: 'Enter the email address the person signs in with.' };
  }
  if (!(ROLES as readonly string[]).includes(role)) return { ok: false, message: 'Pick a role.' };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ user_id: string; email: string; role: string; invited: boolean }>(
    '/members',
    { email, role: role as FormRole },
    auth,
  );
  // The engine's refusals are the honest ones (404: "no user with this email — they must sign
  // up first", 409: "already a member — use the role select instead") and are shown verbatim.
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/members');
  return {
    ok: true,
    message: res.data.invited
      ? `Invited ${res.data.email} as ${res.data.role} — they get an email to set a password, and they are a member already.`
      : `Added ${res.data.email} as ${res.data.role}.`,
  };
}

export async function changeRoleAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const userId = str(form, 'userId');
  const role = str(form, 'role');

  if (!isUuid(userId)) return { ok: false, message: DENIED };
  if (!(ROLES as readonly string[]).includes(role)) return { ok: false, message: 'Pick a role.' };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePatch<{ user_id: string; role: string }>(
    `/members/${userId}`,
    { role: role as FormRole },
    auth,
  );
  // Last-admin protection lives in the engine (demoting the only admin is refused there);
  // surface its exact words.
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/members');
  return {
    ok: true,
    message:
      userId === auth.actor && role !== 'admin'
        ? `Role changed to ${res.data.role}. That was your own membership — you lose access to Settings on the next page load.`
        : `Role changed to ${res.data.role}.`,
  };
}

export async function removeMemberAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const userId = str(form, 'userId');
  if (!isUuid(userId)) return { ok: false, message: DENIED };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ removed?: boolean }>(`/members/${userId}`, auth);
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/members');
  return {
    ok: true,
    message:
      userId === auth.actor
        ? 'You removed yourself from this tenant. Access ends on your next page load.'
        : 'Member removed. Their access ends on their next action — sessions are re-checked, not merely expired.',
  };
}
