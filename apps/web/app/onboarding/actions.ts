'use server';

import { redirect } from 'next/navigation';

import { createClient, getVerifiedUser } from '@/lib/supabase/server';

/* Org creation — the one write a brand-new user is allowed. All the authorization lives in
 * the DB function: create_org() is SECURITY DEFINER, reads auth.uid() itself, enforces the
 * one-org-per-creator rule, and inserts the tenant + admin membership atomically. The action
 * just relays its refusal messages, which are written for humans.
 */

export type ActionState = { ok: boolean; message: string } | null;

export async function createOrgAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const name = String(form.get('name') ?? '').trim();
  if (name.length < 2 || name.length > 80) {
    return { ok: false, message: 'Give your organization a name (2–80 characters).' };
  }

  const user = await getVerifiedUser();
  if (!user) return { ok: false, message: 'You are not signed in.' };

  const supabase = await createClient();
  const { error } = await supabase.rpc('create_org', { org_name: name });
  if (error) {
    // The function's raise messages are the honest ones ("you already created an
    // organization…"); show them rather than a generic failure.
    return { ok: false, message: error.message };
  }

  redirect('/');
}
