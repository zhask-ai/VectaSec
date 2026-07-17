'use server';

import { revalidatePath } from 'next/cache';

import { createClient, getVerifiedUser } from '@/lib/supabase/server';
import { enginePost } from '../findings/engine';

/* Compliance mutations — attesting a control.
 *
 * The honest model (docs/research/compliance-mapping.md §0, migration 006): a scan can prove a
 * control FAILS; nothing a scan sees can prove it PASSES. The only thing that can is a human taking
 * responsibility for it, over a stated scope. So `pass` is written by exactly one path — this
 * attestation — and a live assessed failing finding always overrides it (fail beats attestation).
 *
 * Same posture as findings/actions.ts, and for the same reasons:
 *   1. getVerifiedUser(), not getClaims() — a revoked user's still-signed token must not attest.
 *   2. The control is re-read under RLS. That read IS the authorization check and the source of the
 *      tenant, framework and control_id the engine is handed — never the form. The engine takes its
 *      tenant from a self-asserted header and does not verify membership, so anything posted from a
 *      form is attacker-controlled; re-reading the row the caller's own policy returned is what
 *      keeps the engine bound to a control this user can actually see.
 *
 * Degrades gracefully: enginePost returns a soft error when the engine is unreachable, and the page
 * (which reads controls and attestations from Supabase) stays intact — the control is simply shown
 * unchanged with a message, never a crash.
 */

export type AttestState = { ok: boolean; message: string } | null;

const DENIED = 'You are not signed in, or this control is not yours to attest. Nothing was sent.';

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

export async function attestControlAction(_prev: AttestState, form: FormData): Promise<AttestState> {
  // The control ROW id (a uuid), used only to re-read the row under RLS. framework/control_id are
  // NOT taken from the form — a posted pair could name a control the caller cannot see.
  const controlPk = str(form, 'controlPk');
  const scope = str(form, 'scope').slice(0, 2000);
  const note = str(form, 'note').slice(0, 2000);
  const expiresRaw = str(form, 'expires'); // '' or a yyyy-mm-dd from a <input type="date">

  // Checked here as well as in the engine so the message lands next to the empty field rather than
  // after a round trip. An attestation with no scope is not an attestation.
  if (!scope) {
    return { ok: false, message: 'A scope is required — say what you are attesting, over which systems and period.' };
  }
  if (!isUuid(controlPk)) return { ok: false, message: DENIED };

  const user = await getVerifiedUser();
  if (!user) return { ok: false, message: DENIED };

  const supabase = await createClient();
  const { data, error } = await supabase
    .from('controls')
    .select('tenant_id, framework, control_id, status')
    .eq('id', controlPk)
    .maybeSingle();

  if (error || !data) return { ok: false, message: DENIED };
  const control = data as { tenant_id: string; framework: string; control_id: string; status: string };

  // Fail beats attestation — refuse here too, not only in the engine, so the reason lands at the
  // button. You cannot sign away a control the scanner can currently prove is broken.
  if (control.status === 'fail') {
    return {
      ok: false,
      message: 'This control has a live failing finding. Resolve it before attesting — a failure always overrides an attestation.',
    };
  }

  // Optional expiry: a date-only value, sent as an ISO timestamp. Empty = no expiry (discouraged,
  // but the engine and schema allow it).
  let expiresAt: string | null = null;
  if (expiresRaw) {
    const d = new Date(expiresRaw);
    if (Number.isNaN(d.getTime())) return { ok: false, message: 'That expiry date is not valid.' };
    expiresAt = d.toISOString();
  }

  const res = await enginePost<{ status?: string }>(
    `/compliance/${encodeURIComponent(control.framework)}/${encodeURIComponent(control.control_id)}/attest`,
    { scope, note: note || null, expires_at: expiresAt },
    { tenantId: control.tenant_id, actor: user.id },
  );

  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/compliance');
  return {
    ok: true,
    message: `Attested ${control.framework} ${control.control_id}. It now shows as passing on your sign-off.`,
  };
}
