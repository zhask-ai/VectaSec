'use server';

import { revalidatePath } from 'next/cache';

import { engineDelete, enginePost } from '@/lib/engine';
import { getOwnMembership, isAdmin } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';
import { CONNECTORS } from '../../estate/connector-fields';
import { integrationSpecFor } from './integration-fields';

/* Alert integrations and routing rules — admin-only, engine-written.
 *
 * Same posture as members/actions.ts: getVerifiedUser (revocation-checked), admin role
 * re-read per action, tenant from the caller's own RLS-read membership row, config assembled
 * ONLY from the integration type's declared field spec (a crafted POST cannot smuggle extra
 * config keys through this path), secrets pass through and are never echoed back.
 */

export type ActionState = { ok: boolean; message: string } | null;

const DENIED = 'You are not signed in, or you are not an admin of this tenant. Nothing was sent.';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
/** Valid connector-type filters — derived from the connector catalogue so every connector the
 * picker offers is routable. A hardcoded copy here once rejected 35 of 39 types. */
const CONNECTOR_TYPES: string[] = CONNECTORS.map((c) => c.type);

function str(form: FormData, key: string): string {
  const v = form.get(key);
  return typeof v === 'string' ? v.trim() : '';
}

function isUuid(v: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
}

async function authorizeAdmin() {
  const user = await getVerifiedUser();
  if (!user) return null;
  const membership = await getOwnMembership();
  if (!membership || !isAdmin(membership.role)) return null;
  return { tenantId: membership.tenantId, actor: user.id };
}

/* ── Integrations ─────────────────────────────────────────────────────────── */

export async function addIntegrationAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const type = str(form, 'type');
  const name = str(form, 'name').slice(0, 120);

  const spec = integrationSpecFor(type);
  if (!spec) return { ok: false, message: 'Unknown integration type.' };
  if (!name) return { ok: false, message: 'Give the integration a name you will recognise in routing rules.' };

  // Whitelist assembly: only keys the spec declares can reach the engine from this form.
  // Empty SECRET fields are omitted, not refused: the engine upserts on tenant+type+name and
  // treats an absent secret as "unchanged", so re-saving must not force re-pasting a token.
  // (On a genuine create the engine 400s with its own message — shown verbatim below.)
  const config: Record<string, string> = {};
  for (const f of spec.fields) {
    const v = str(form, `cfg_${f.key}`);
    if (v) config[f.key] = v;
    else if (f.required && !f.secret) return { ok: false, message: `${f.label} is required for ${spec.label}.` };
  }

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ integration_id: string; created: boolean }>(
    '/integrations',
    { type: spec.type, name, config, enabled: true },
    auth,
  );
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/integrations');
  return {
    ok: true,
    message: res.data.created
      ? `Added ${spec.label} “${name}”. Use Test to prove it delivers, then point a routing rule at it.`
      : `Updated ${spec.label} “${name}” — same name, same destination, new config. Secrets you left blank are unchanged.`,
  };
}

export async function deleteIntegrationAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const id = str(form, 'integrationId');
  if (!isUuid(id)) return { ok: false, message: DENIED };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ deleted: boolean }>(`/integrations/${id}`, auth);
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/integrations');
  return { ok: true, message: 'Integration removed. Routing rules that pointed at it no longer deliver anywhere.' };
}

/** A real delivery attempt against the destination — it can legitimately take as long as the
 * destination's timeout, hence the longer budget than the 8s default. */
export async function testIntegrationAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const id = str(form, 'integrationId');
  if (!isUuid(id)) return { ok: false, message: DENIED };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await enginePost<{ ok: boolean; error?: string }>(`/integrations/${id}/test`, {}, auth, 30_000);
  if (!res.ok) return { ok: false, message: res.message };

  if (!res.data.ok) {
    return { ok: false, message: `Delivery failed: ${res.data.error ?? 'the destination did not accept the test message'}.` };
  }
  return { ok: true, message: 'Test delivered — check the destination for the test message.' };
}

/* ── Routing rules ────────────────────────────────────────────────────────── */

export async function addRoutingRuleAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const minSeverity = str(form, 'minSeverity');
  const connectorType = str(form, 'connectorType'); // '' = any
  const integrationId = str(form, 'integrationId');

  if (!(SEVERITIES as readonly string[]).includes(minSeverity)) {
    return { ok: false, message: 'Pick a minimum severity.' };
  }
  if (connectorType && !(CONNECTOR_TYPES as readonly string[]).includes(connectorType)) {
    return { ok: false, message: 'Unknown connector type.' };
  }
  if (!isUuid(integrationId)) return { ok: false, message: 'Pick a destination integration.' };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  // The engine's match vocabulary is a nested object: {min_severity?, connector_types?: [...],
  // rule_prefixes?: [...], notify_on?: [...]}; {} routes everything, notify_on defaults to
  // both new_findings and scan_failed. This form speaks severity + one connector type.
  const match: { min_severity: string; connector_types?: string[] } = { min_severity: minSeverity };
  if (connectorType) match.connector_types = [connectorType];

  const res = await enginePost<{ routing_rule_id: string; integration: { id: string; type: string; name: string } }>(
    '/routing-rules',
    { integration_id: integrationId, match, enabled: true },
    auth,
  );
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/integrations');
  return { ok: true, message: 'Routing rule added. It applies to findings from the next scan onward.' };
}

export async function deleteRoutingRuleAction(_prev: ActionState, form: FormData): Promise<ActionState> {
  const id = str(form, 'ruleId');
  if (!isUuid(id)) return { ok: false, message: DENIED };

  const auth = await authorizeAdmin();
  if (!auth) return { ok: false, message: DENIED };

  const res = await engineDelete<{ deleted: boolean }>(`/routing-rules/${id}`, auth);
  if (!res.ok) return { ok: false, message: res.message };

  revalidatePath('/settings/integrations');
  return { ok: true, message: 'Routing rule removed. Findings it matched are no longer delivered by it.' };
}
