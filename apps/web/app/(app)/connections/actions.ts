'use server';

import { revalidatePath } from 'next/cache';

import { engineDelete, enginePatch, enginePost } from '@/lib/engine';
import { canEdit, getOwnMembership, getRoleInTenant } from '@/lib/role';
import { createClient, getVerifiedUser } from '@/lib/supabase/server';
import { specFor } from './connector-fields';

/* Connection mutations: connect a system, test it, scan it, remove it.
 *
 * Same posture as findings/actions.ts, because Server Actions are directly POSTable:
 *
 *   1. getVerifiedUser() on every action — revocation-checked, not just signature-checked.
 *      Connections carry credentials; a revoked analyst must not be able to add or delete one.
 *   2. Tenant is NEVER a form field. For actions on an existing connection it comes from the
 *      row RLS returned (the read IS the authorization — IDOR-safe by construction). For
 *      `add` there is no row yet, so it comes from the caller's own tenant_members row.
 *   3. Config values are assembled from the connector's DECLARED field spec only. A form key
 *      outside the spec is dropped, so a crafted POST cannot smuggle arbitrary config
 *      (`active_probes`, `verify_tls=false`, …) through this path — those knobs exist, but
 *      they belong to the CLI where the operator can see what they typed.
 *
 * Credentials pass through here as ciphertext-in-transit (HTTPS) → engine → connections.config.
 * They are never persisted by this process, never logged, and never echoed back to the form.
 */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED =
  'You are not signed in, this connection is not yours to change, or your role is view-only. Nothing was sent.';

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

/** Authorize an action on an EXISTING connection: the row read under RLS is the proof this
 * user may act on it, and the row's tenant_id is the only tenant the engine is told. The
 * caller's role in THAT tenant must allow mutation — viewers read this page; they do not get
 * to scan, test, retime or delete from it, and hiding the buttons is not the check (a Server
 * Action is directly POSTable). The engine enforces roles too; this is defense in depth. */
async function authorizeConnection(connectionId: string) {
  if (!isUuid(connectionId)) return null;

  const user = await getVerifiedUser();
  if (!user) return null;

  const supabase = await createClient();
  const { data, error } = await supabase
    .from('connections')
    .select('id, tenant_id, type, name')
    .eq('id', connectionId)
    .maybeSingle();
  if (error || !data) return null;

  const tenantId = (data as { tenant_id: string }).tenant_id;
  const role = await getRoleInTenant(tenantId);
  if (!canEdit(role)) return null;

  return {
    actor: user.id,
    tenantId,
    type: (data as { type: string }).type,
    name: (data as { name: string }).name,
  };
}

function revalidateAll(): void {
  revalidatePath('/connections');
  revalidatePath('/scans');
  revalidatePath('/');
}

/* ── Add (and optionally scan) ───────────────────────────────────────────── */
export async function addConnectionAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const type = str(form, 'type');
  const name = str(form, 'name').slice(0, 120);
  const scanNow = str(form, 'scanNow') === 'on';

  const spec = specFor(type);
  if (!spec) return { ok: false, message: 'Unknown connector type.' };
  if (!name) return { ok: false, message: 'Give the connection a name you will recognise later.' };

  // Whitelist assembly: only keys the spec declares can reach the engine from this form.
  const config: Record<string, string> = {};
  for (const f of spec.fields) {
    const v = str(form, `cfg_${f.key}`);
    if (v) config[f.key] = v;
    else if (f.required) {
      return { ok: false, message: `${f.label} is required for ${spec.label}.` };
    }
  }

  const user = await getVerifiedUser();
  if (!user) return { ok: false, message: DENIED };
  // Membership supplies both the tenant (same refusal semantics as lib/tenant.ts — a
  // multi-tenant user gets no create-actions until a switcher exists) and the role gate.
  const membership = await getOwnMembership();
  if (!membership || !canEdit(membership.role)) return { ok: false, message: DENIED };

  const auth = { tenantId: membership.tenantId, actor: user.id };
  const created = await enginePost<{ connection_id: string; created: boolean }>(
    '/connections',
    { type, name, config, mode: 'cloud' },
    auth,
  );
  if (!created.ok) return { ok: false, message: created.message };

  if (!scanNow) {
    revalidateAll();
    return {
      ok: true,
      message: `${created.data.created ? 'Connected' : 'Updated'} ${spec.label} “${name}”. Use Scan now when ready.`,
    };
  }

  const scan = await enginePost<{ scan_id: string }>(
    `/connections/${created.data.connection_id}/scan`,
    {},
    auth,
  );
  revalidateAll();
  if (!scan.ok) {
    return {
      ok: true,
      message: `Connected “${name}”, but the scan could not be queued: ${scan.message}`,
    };
  }
  return {
    ok: true,
    message: `Connected ${spec.label} “${name}” and queued its first scan. Watch it on the Scans page — findings appear as soon as it completes.`,
  };
}

/* ── Scan now ─────────────────────────────────────────────────────────────── */
export async function scanConnectionAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const auth = await authorizeConnection(str(form, 'connectionId'));
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ scan_id: string; mode: string }>(
    `/connections/${str(form, 'connectionId')}/scan`,
    {},
    { tenantId: auth.tenantId, actor: auth.actor },
  );
  if (!res.ok) return { ok: false, message: res.message };

  revalidateAll();
  return {
    ok: true,
    message:
      res.data.mode === 'collector'
        ? `Scan queued for “${auth.name}” — its collector picks it up on the next poll.`
        : `Scan queued for “${auth.name}”.`,
  };
}

/* ── Test ─────────────────────────────────────────────────────────────────── */
/** A real collect against the target — reachability proven by the same code path a scan
 * uses, so it can legitimately take as long as the connector's timeout. */
export async function testConnectionAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const auth = await authorizeConnection(str(form, 'connectionId'));
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<
    { ok: boolean; resources?: number; kinds?: Record<string, number>; error?: string }
  >(
    `/connections/${str(form, 'connectionId')}/test`,
    {},
    { tenantId: auth.tenantId, actor: auth.actor },
    45_000,
  );
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/connections');
  if (!res.data.ok) {
    return { ok: false, message: `“${auth.name}” is not reachable: ${res.data.error ?? 'unknown error'}` };
  }
  const kinds = Object.entries(res.data.kinds ?? {})
    .map(([k, n]) => `${n} ${k}`)
    .join(', ');
  return {
    ok: true,
    message: `“${auth.name}” is reachable — a scan would see ${res.data.resources} resource${res.data.resources === 1 ? '' : 's'}${kinds ? ` (${kinds})` : ''}.`,
  };
}

/* ── Cadence ──────────────────────────────────────────────────────────────── */
/** The recurring-scan interval (connections.scan_interval_minutes, consumed by the DB
 * scheduler's queue_due_scans()). Whitelisted values only — a crafted POST must not schedule
 * a 1-minute hammer against someone's production broker. 'off' clears it: absence means
 * point-in-time only, which is a meaningful state, not a default. */
const INTERVAL_CHOICES = [30, 60, 360, 1440, 10080] as const;

export async function setCadenceAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const connectionId = str(form, 'connectionId');
  const raw = str(form, 'interval');

  let interval: number | null;
  if (raw === 'off') {
    interval = null;
  } else {
    const n = Number(raw);
    if (!(INTERVAL_CHOICES as readonly number[]).includes(n)) {
      return { ok: false, message: 'Pick a cadence from the list.' };
    }
    interval = n;
  }

  const auth = await authorizeConnection(connectionId);
  if (!auth) return { ok: false, message: DENIED };

  // Engine response: {connection_id, type, name, scan_interval_minutes, previous}. The applied
  // value is echoed back; use it (not the submitted one) so the message reports what is stored.
  const res = await enginePatch<{
    connection_id: string;
    type: string;
    name: string;
    scan_interval_minutes: number | null;
    previous: number | null;
  }>(
    `/connections/${connectionId}`,
    { scan_interval_minutes: interval },
    { tenantId: auth.tenantId, actor: auth.actor },
  );
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/connections');
  const applied = res.data.scan_interval_minutes;
  return {
    ok: true,
    message:
      applied === null
        ? `Recurring scans turned off for “${auth.name}” — it now scans only when asked.`
        : `“${auth.name}” now rescans automatically ${cadenceLabel(applied)}.`,
  };
}

function cadenceLabel(minutes: number): string {
  if (minutes % 1440 === 0) return `every ${minutes / 1440 === 1 ? 'day' : `${minutes / 1440} days`}`;
  if (minutes % 60 === 0) return `every ${minutes / 60 === 1 ? 'hour' : `${minutes / 60} hours`}`;
  return `every ${minutes} minutes`;
}

/* ── Delete ───────────────────────────────────────────────────────────────── */
export async function deleteConnectionAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const auth = await authorizeConnection(str(form, 'connectionId'));
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ resources: number; findings: number }>(
    `/connections/${str(form, 'connectionId')}`,
    { tenantId: auth.tenantId, actor: auth.actor },
  );
  if (!res.ok) return { ok: false, message: res.message };

  revalidateAll();
  return {
    ok: true,
    message: `Removed “${auth.name}” (${res.data.resources} resources, ${res.data.findings} findings). Scan history is kept.`,
  };
}
