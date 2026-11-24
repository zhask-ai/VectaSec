'use server';

import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';

import { enginePost } from '@/lib/engine';
import { canEdit, getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

/* Breach-day mode. One action: hand the engine an advisory (a product name, optionally the
 * affected version range) and it matches it against the stored inventory. No system is
 * contacted. The engine validates again; these checks only keep an obviously empty form from
 * making the round trip. */

export type ActionState = { ok: boolean; message: string } | null;

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

export async function createBriefAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const product = str(form, 'product') || str(form, 'product_pick');
  const kind = str(form, 'kind') === 'vendor_breach' ? 'vendor_breach' : 'vulnerability';
  const affected = str(form, 'affected');
  const title = str(form, 'title');
  const reference = str(form, 'reference');
  if (!product) return { ok: false, message: 'Name the product or vendor, for example n8n, redis or kong.' };
  if (product.length > 100) return { ok: false, message: 'That product name is too long.' };

  const [user, membership] = await Promise.all([getVerifiedUser(), getOwnMembership()]);
  if (!user || !membership || !canEdit(membership.role)) {
    return { ok: false, message: 'You are not signed in or your role is view-only. Nothing was run.' };
  }

  const res = await enginePost<{ id: string }>(
    '/breach-briefs',
    { product, kind, affected, title, reference },
    { tenantId: membership.tenantId, actor: user.id },
    20_000,
  );
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath('/findings/breach-day');
  redirect(`/findings/breach-day?id=${res.data.id}`);
}
