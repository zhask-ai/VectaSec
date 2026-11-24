'use server';

import { revalidatePath } from 'next/cache';

import { enginePost } from '@/lib/engine';
import { canEdit, getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

/* Canaries. Minting returns the URL exactly once: the engine stores only its hash, so the
 * result is handed back in the action state for the form to show, and is never persisted or
 * put in a URL by the console either. */

export type Minted = { url: string | null; path: string; note: string; snippets: { title: string; body: string }[] };
export type MintState = { ok: boolean; message: string; minted?: Minted } | null;
export type ActionState = { ok: boolean; message: string } | null;

const DENIED = 'You are not signed in or your role is view-only. Nothing was created.';

async function authorize() {
  const [user, membership] = await Promise.all([getVerifiedUser(), getOwnMembership()]);
  if (!user || !membership || !canEdit(membership.role)) return null;
  return { tenantId: membership.tenantId, actor: user.id };
}

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

export async function mintCanaryAction(_prev: MintState, form: FormData): Promise<MintState> {
  const name = str(form, 'name');
  const placed_in = str(form, 'placed_in');
  if (!name) return { ok: false, message: 'Give it a name you will recognise in an alert.' };
  const auth = await authorize();
  if (!auth) return { ok: false, message: DENIED };
  const res = await enginePost<Minted>('/canaries', { name, placed_in }, auth);
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath('/findings/canaries');
  return { ok: true, message: res.data.note, minted: res.data };
}

export async function revokeCanaryAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const id = str(form, 'id');
  if (!/^[0-9a-f-]{36}$/i.test(id)) return { ok: false, message: DENIED };
  const auth = await authorize();
  if (!auth) return { ok: false, message: DENIED };
  const res = await enginePost<{ revoked: boolean }>(`/canaries/${id}/revoke`, {}, auth);
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath('/findings/canaries');
  return { ok: true, message: 'Revoked. Requests to it are no longer recorded.' };
}
