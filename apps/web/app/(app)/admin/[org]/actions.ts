'use server';

import { revalidatePath } from 'next/cache';

import { engineDelete, enginePatch, enginePost } from '@/lib/engine';
import { isSuperAdmin } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

/* Operator actions on a customer org — invite on their behalf, fix a role, remove a member.
 *
 * Authorization is two-layered and the ENGINE's layer is the real one: it resolves the
 * actor's rank itself, and a super_admins row grants the admin tier in any tenant (audited
 * under the operator's real user id). The console-side check exists so a non-operator gets
 * an honest refusal without a network hop. The tenant id comes from the route — acceptable
 * ONLY because the engine re-authorizes the actor against it; nothing here trusts the form.
 */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED = 'Super admins only. Nothing was sent.';
const ROLES = ['admin', 'editor', 'viewer'] as const;

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

async function authorizeOperator(orgId: string) {
  if (!isUuid(orgId)) return null;
  const user = await getVerifiedUser();
  if (!user) return null;
  if (!(await isSuperAdmin())) return null;
  return { tenantId: orgId, actor: user.id };
}

export async function adminInviteAction(_prev: ActionState, form: FormData): Promise<ActionState> {
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

  revalidatePath(`/admin/${orgId}`);
  return {
    ok: true,
    message: res.data.invited
      ? `Invited ${res.data.email} as ${res.data.role} — they get an email to set a password.`
      : `Added ${res.data.email} as ${res.data.role}.`,
  };
}

export async function adminChangeRoleAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const orgId = str(form, 'org');
  const userId = str(form, 'user_id');
  const role = str(form, 'role');
  if (!isUuid(userId) || !(ROLES as readonly string[]).includes(role)) {
    return { ok: false, message: 'Malformed request.' };
  }

  const auth = await authorizeOperator(orgId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePatch<{ role: string }>(`/members/${userId}`, { role }, auth);
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath(`/admin/${orgId}`);
  return { ok: true, message: `Role changed to ${res.data.role}.` };
}

export async function adminRemoveMemberAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const orgId = str(form, 'org');
  const userId = str(form, 'user_id');
  if (!isUuid(userId)) return { ok: false, message: 'Malformed request.' };

  const auth = await authorizeOperator(orgId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ removed: boolean }>(`/members/${userId}`, auth);
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath(`/admin/${orgId}`);
  return { ok: true, message: 'Member removed.' };
}
