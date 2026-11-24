'use server';

import { revalidatePath } from 'next/cache';

import { enginePost } from '@/lib/engine';
import { canEdit, getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

export type OwnerState = { ok: boolean; message: string } | null;

export async function confirmOwnerAction(_prev: OwnerState, form: FormData): Promise<OwnerState> {
  const resourceId = String(form.get('resourceId') ?? '');
  const owner = String(form.get('owner') ?? '').trim();
  const note = String(form.get('note') ?? '').trim();
  if (!owner) return { ok: false, message: 'Name the owner: an email or a team.' };
  const [user, membership] = await Promise.all([getVerifiedUser(), getOwnMembership()]);
  if (!user || !membership || !canEdit(membership.role)) {
    return { ok: false, message: 'You are not signed in or your role is view-only. Nothing was saved.' };
  }
  const res = await enginePost<{ owner: string; previous: string | null }>(
    '/access/owner',
    { resource_id: resourceId, owner, note },
    { tenantId: membership.tenantId, actor: user.id },
  );
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath(`/estate/inventory/${resourceId}`);
  revalidatePath('/access');
  return {
    ok: true,
    message: res.data.previous && res.data.previous !== res.data.owner
      ? `Owner changed from ${res.data.previous} to ${res.data.owner}. Recorded in the audit log.`
      : `Confirmed ${res.data.owner} as owner today. Recorded in the audit log.`,
  };
}
