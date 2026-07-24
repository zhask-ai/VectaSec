import 'server-only';

import { cache } from 'react';

import { createClient } from '@/lib/supabase/server';

/* Role resolution — who may change things, from the caller's OWN membership row.
 *
 * `tenant_members` RLS is `user_id = auth.uid()` (migration 002, tenant_members_select), so
 * every query in this file can only ever return the caller's own rows. That is the whole
 * guarantee: the role is read from a row Postgres already scoped to the caller, never from a
 * form, a cookie, or a client component prop.
 *
 * THE UI GATE IS COURTESY; THE ACTION GATE IS THE CHECK. Hiding a button does not stop a
 * direct POST to a Server Action, so every mutating action re-reads the role server-side
 * before calling the engine (which enforces again — three layers, engine authoritative).
 *
 * The console speaks three roles. The schema's `role` column is free text with legacy values
 * (owner|admin|analyst|viewer from migration 001), so they are normalised here in one place:
 * owner→admin, analyst→editor, anything unrecognised→viewer. Fail closed: an unknown role
 * must never gain edit rights by default.
 */

export type Role = 'admin' | 'editor' | 'viewer';

function normalizeRole(raw: string): Role {
  const r = raw.toLowerCase();
  if (r === 'admin' || r === 'owner') return 'admin';
  if (r === 'editor' || r === 'analyst') return 'editor';
  return 'viewer';
}

/** The caller's single membership: tenant + role. Mirrors getOwnTenantId's multi-tenant
 * refusal — a user in several tenants gets null (treated as view-only in the UI) until a
 * tenant switcher exists. Per-row actions still work for them via getRoleInTenant, which is
 * scoped to the tenant the RLS-read row named. Cached: one query per render pass. */
export const getOwnMembership = cache(async (): Promise<{ tenantId: string; role: Role } | null> => {
  const supabase = await createClient();
  const { data, error } = await supabase.from('tenant_members').select('tenant_id, role').limit(2);
  if (error || !data || data.length === 0) return null;
  if (data.length > 1) return null;
  const row = data[0] as { tenant_id: string; role: string };
  return { tenantId: row.tenant_id, role: normalizeRole(row.role) };
});

/** The caller's role in ONE tenant — for actions on an existing row, whose tenant came from
 * an RLS-authorized read. RLS means this returns a row only when the caller really is a
 * member of that tenant; null is a refusal, never a default. */
export async function getRoleInTenant(tenantId: string): Promise<Role | null> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('tenant_members')
    .select('role')
    .eq('tenant_id', tenantId)
    .maybeSingle();
  if (error || !data) return null;
  return normalizeRole((data as { role: string }).role);
}

/** Editors and admins mutate operational state (scans, connections, triage, attestations). */
export function canEdit(role: Role | null | undefined): boolean {
  return role === 'admin' || role === 'editor';
}

/** Admins alone touch the tenant itself: members, integrations, settings. */
export function isAdmin(role: Role | null | undefined): boolean {
  return role === 'admin';
}
