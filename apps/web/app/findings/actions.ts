'use server';

import { revalidatePath } from 'next/cache';

import { canEdit, getRoleInTenant } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';
import { getActionContext } from './data';
import { enginePost } from '@/lib/engine';

/* Findings mutations.
 *
 * The browser role is SELECT-only on every table, so nothing here writes to Postgres. Each
 * action forwards to the engine API, which authenticates the actor and writes an audit_log row
 * in the same transaction as the change.
 *
 * EVERY action re-verifies, and that is not belt-and-braces. A Server Action is reachable as a
 * direct POST to the route it was defined on, so `proxy.ts` covering /findings proves nothing
 * about a caller who never loaded the page — and a matcher edit could remove even that with no
 * test failing. The two checks below are the real ones:
 *
 *   1. getVerifiedUser(), not getClaims() — a network hop to the Auth server on every action.
 *      getClaims verifies a signature, not revocation: a fired analyst's unexpired token still
 *      has a valid signature. Paying the round trip on a button click is nothing; letting a
 *      revoked user suppress a finding is a finding against us.
 *   2. getActionContext() reads the finding under RLS. If Postgres does not hand back the row,
 *      the user cannot act on it — including the "does this user have permission to act on THIS
 *      resource" question that authentication alone never answers (IDOR).
 *
 * Both must pass before anything is sent. Fail closed, and say so plainly.
 */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED =
  'You are not signed in, this finding is not yours to change, or your role is view-only. Nothing was sent.';

/** Resolve identity + authorization for one action. Returns null when any check fails —
 * callers must treat that as a refusal, never as a reason to continue with defaults. */
async function authorize(findingId: string) {
  if (!isUuid(findingId)) return null;

  const user = await getVerifiedUser();
  if (!user) return null;

  const ctx = await getActionContext(findingId);
  if (!ctx) return null;

  // Role check, scoped to the tenant the RLS-read row named (so it works for multi-tenant
  // users too). Viewers read findings; changing status, assignment, suppressions or triage is
  // editor+. Hidden buttons are not the check — this is, and the engine checks again.
  const role = await getRoleInTenant(ctx.tenantId);
  if (!canEdit(role)) return null;

  // The actor is the verified user's id — never a form field. The engine writes it verbatim to
  // the audit log, so a client-supplied actor would be a forged signature on a real action.
  return { ctx, actor: user.id };
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

/** Refresh both views this finding appears in. The list shows its status and its group's
 * tally, so revalidating only the detail page leaves the queue lying about what just changed. */
function revalidateFinding(findingId: string): void {
  revalidatePath('/findings');
  revalidatePath(`/findings/${findingId}`);
}

/* ── Status ───────────────────────────────────────────────────────────────
 * 'suppressed' is absent on purpose and the engine refuses it too: a suppression carries a
 * reason and an expiry and is applied by the scan loop. A plain status write would create an
 * exception nobody can review or expire. Use suppressAction. */
const STATUSES = ['open', 'triaged', 'in_progress', 'resolved', 'accepted'] as const;
type EngineStatus = (typeof STATUSES)[number];

export async function setStatusAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const findingId = str(form, 'findingId');
  const status = str(form, 'status');
  const note = str(form, 'note').slice(0, 2000);

  if (!(STATUSES as readonly string[]).includes(status)) {
    return { ok: false, message: 'Unknown status.' };
  }

  const auth = await authorize(findingId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ previous: string; status: string }>(
    `/findings/${findingId}/status`,
    { status: status as EngineStatus, note },
    { tenantId: auth.ctx.tenantId, actor: auth.actor },
  );

  if (!res.ok) return { ok: false, message: res.message };
  revalidateFinding(findingId);
  return { ok: true, message: `Status changed from ${res.data.previous} to ${res.data.status}.` };
}

/* ── Assign ───────────────────────────────────────────────────────────────
 * Only "assign to me" and "unassign" exist, and that is a data limit rather than a design one:
 * `findings.assignee` is a bare uuid, and tenant_members' RLS policy is `user_id = auth.uid()`
 * — you can see your OWN membership row and no one else's. There is no readable roster and no
 * display name anywhere in the schema, so a picker could offer nothing but raw uuids. Assigning
 * to a colleague needs a profiles table; until then this is the honest subset. */
export async function assignAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const findingId = str(form, 'findingId');
  const intent = str(form, 'intent');

  if (intent !== 'me' && intent !== 'none') return { ok: false, message: 'Unknown assign action.' };

  const auth = await authorize(findingId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ assignee: string | null }>(
    `/findings/${findingId}/assign`,
    { assignee: intent === 'me' ? auth.actor : null },
    { tenantId: auth.ctx.tenantId, actor: auth.actor },
  );

  if (!res.ok) return { ok: false, message: res.message };
  revalidateFinding(findingId);
  return { ok: true, message: intent === 'me' ? 'Assigned to you.' : 'Unassigned.' };
}

/* ── Suppress ─────────────────────────────────────────────────────────────
 * The scan loop matches suppressions on {} (tenant-wide), {ext_id} or {kind} and nothing else
 * — scan.py `_is_suppressed`, and the engine rejects unknown keys rather than storing a
 * suppression the user believes is in force but which matches nothing.
 *
 * (lib/types.ts documents the scope as {resource_id|kind|name_glob}. That comment is stale;
 * the scanner and the API agree on ext_id|kind, and they are the ones that decide.) */
export type SuppressScope = 'resource' | 'kind' | 'tenant';

const EXPIRY_DAYS = [30, 60, 90] as const;

export async function suppressAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const findingId = str(form, 'findingId');
  const scope = str(form, 'scope') as SuppressScope;
  const reason = str(form, 'reason').slice(0, 2000);
  const expiresRaw = str(form, 'expires');

  if (scope !== 'resource' && scope !== 'kind' && scope !== 'tenant') {
    return { ok: false, message: 'Unknown suppression scope.' };
  }
  // Checked here as well as by the engine so the user gets the message next to the textarea
  // they left empty, rather than a round trip to be told the same thing.
  if (!reason) {
    return { ok: false, message: 'A reason is required — a suppression nobody explained cannot be reviewed later.' };
  }

  const auth = await authorize(findingId);
  if (!auth) return { ok: false, message: DENIED };

  // rule_id and ext_id come from the row RLS returned, NOT from the form. A posted rule_id
  // would let a caller suppress a rule they cannot see.
  const { ctx } = auth;
  let engineScope: Record<string, string> = {};
  if (scope === 'resource') {
    if (!ctx.extId) return { ok: false, message: 'This finding has no resource, so it cannot be suppressed for one.' };
    engineScope = { ext_id: ctx.extId };
  } else if (scope === 'kind') {
    if (!ctx.resourceKind) return { ok: false, message: 'This finding has no resource, so it has no kind to suppress.' };
    engineScope = { kind: ctx.resourceKind };
  }

  let expiresAt: string | null = null;
  if (expiresRaw !== 'never') {
    const days = Number(expiresRaw);
    if (!(EXPIRY_DAYS as readonly number[]).includes(days)) {
      return { ok: false, message: 'Pick an expiry.' };
    }
    expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
  }

  const res = await enginePost<{ id: string }>(
    '/suppressions',
    { rule_id: ctx.ruleId, scope: engineScope, reason, expires_at: expiresAt },
    { tenantId: ctx.tenantId, actor: auth.actor },
  );

  if (!res.ok) return { ok: false, message: res.message };
  revalidateFinding(findingId);

  // The engine returns applies_at_next_scan: true, and the message says so rather than letting
  // the user believe the row went quiet now. The scan loop applies suppressions, so findings
  // that are already open keep their status until the next scan re-evaluates them. A user who
  // expects silence and gets an alert stops trusting the button.
  return {
    ok: true,
    message: `Suppression created for ${ctx.ruleId}. It applies at the next scan — this finding keeps its current status until then.`,
  };
}

/* ── Triage ───────────────────────────────────────────────────────────────
 * Generates the cached triage for this finding's fingerprint, or returns the existing one.
 * Cheap when cached; a model call when not — hence the longer timeout. */
export async function triageAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const findingId = str(form, 'findingId');

  const auth = await authorize(findingId);
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ model: string }>(
    `/findings/${findingId}/triage`,
    {},
    { tenantId: auth.ctx.tenantId, actor: auth.actor },
    60_000,
  );

  if (!res.ok) return { ok: false, message: res.message };
  revalidateFinding(findingId);
  return {
    ok: true,
    message:
      res.data.model === 'rule-based-fallback'
        ? 'Triage generated deterministically — the AI model was unavailable.'
        : 'Triage generated.',
  };
}
