'use server';

import { revalidatePath } from 'next/cache';

import { enginePost } from '@/lib/engine';
import { canEdit, getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

/* External exposure scan — the free entry point (docs/vectasec-smb-strategy-2026-10.md §4
 * item 5). Three Server Actions over the engine's /exposure/* routes: register a target and get
 * the DNS TXT token, prove ownership, run the credential-less sweep. Every action re-verifies the
 * caller and the role; the engine enforces the ownership gate and the rate limits again. */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED = 'You are not signed in or your role is view-only. Nothing was sent.';

async function authorize() {
  const [user, membership] = await Promise.all([getVerifiedUser(), getOwnMembership()]);
  if (!user || !membership || !canEdit(membership.role)) return null;
  return { tenantId: membership.tenantId, actor: user.id };
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

export async function createExposureTargetAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const kind = str(form, 'kind');
  const value = str(form, 'value').toLowerCase();
  if (!['domain', 'ip', 'cidr'].includes(kind)) return { ok: false, message: 'Pick domain, IP or CIDR.' };
  if (!value || value.length > 253 || /\s/.test(value)) return { ok: false, message: 'Enter a domain, IP or CIDR.' };
  const auth = await authorize();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ target_id: string; txt_record: string }>('/exposure/targets', { kind, value }, auth);
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath('/estate/unmonitored');
  return { ok: true, message: `Target added. Publish the TXT record ${res.data.txt_record} and press Verify.` };
}

export async function verifyExposureTargetAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const id = str(form, 'targetId');
  if (!isUuid(id)) return { ok: false, message: DENIED };
  const auth = await authorize();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ verified: boolean; method: string | null; checked: string[] }>(`/exposure/targets/${id}/verify`, {}, auth, 20_000);
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath('/estate/unmonitored');
  return res.data.verified
    ? { ok: true, message: `Ownership verified via ${res.data.method}. You can run the scan now.` }
    : { ok: false, message: `Not verified yet. Looked up: ${res.data.checked.join(', ') || 'nothing'}. DNS changes can take a few minutes to propagate.` };
}

export async function startExposureScanAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const id = str(form, 'targetId');
  if (!isUuid(id)) return { ok: false, message: DENIED };
  const auth = await authorize();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ scan_id: string }>(`/exposure/targets/${id}/scan`, {}, auth);
  if (!res.ok) return { ok: false, message: res.message };
  revalidatePath('/estate/unmonitored');
  return { ok: true, message: 'Scan started. It probes read-only, pre-authentication, and finishes within about a minute.' };
}
