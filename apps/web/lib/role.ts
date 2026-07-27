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

/** The caller's ACTIVE membership: tenant + role. One org — that org. Several orgs — the one
 * the switcher cookie names (validated against membership: the cookie selects, membership
 * authorizes), else the first by name — deterministic and visible, because the top-bar
 * switcher displays exactly what is active. Cached: one query per render pass. */
export const getOwnMembership = cache(async (): Promise<{ tenantId: string; role: Role } | null> => {
  const memberships = await getMemberships();
  if (memberships.length === 0) return null;
  if (memberships.length > 1) {
    const { cookies } = await import('next/headers');
    const picked = (await cookies()).get(TENANT_COOKIE)?.value;
    const match = memberships.find((m) => m.tenantId === picked);
    if (match) return { tenantId: match.tenantId, role: match.role };
  }
  const first = memberships[0];
  return { tenantId: first.tenantId, role: first.role };
});

/** Every membership the caller holds, with the tenant's name for the switcher. RLS scopes
 * both tables to the caller, so this list can only ever name their own orgs. Sorted by name
 * so "the first" is deterministic — and visible: the top-bar switcher shows what is active. */
export const getMemberships = cache(
  async (): Promise<{ tenantId: string; tenantName: string; role: Role }[]> => {
    const supabase = await createClient();
    const { data, error } = await supabase
      .from('tenant_members')
      .select('tenant_id, role, tenants(name)');
    if (error || !data) return [];
    const rows = data as unknown as { tenant_id: string; role: string; tenants: { name: string } | null }[];
    return rows
      .map((r) => ({
        tenantId: r.tenant_id,
        tenantName: r.tenants?.name ?? 'Unnamed',
        role: normalizeRole(r.role),
      }))
      .sort((a, b) => a.tenantName.localeCompare(b.tenantName));
  },
);

/** The tenant cookie a multi-org user picked in the switcher. Only ever honoured when it
 * names a tenant the caller actually belongs to — the cookie selects, membership authorizes. */
export const TENANT_COOKIE = 'vs-tenant';

/** True when the caller is a platform operator (a super_admins row — readable only for
 * yourself under RLS). Grants the /admin surface; tenant-level rights stay membership's. */
export const isSuperAdmin = cache(async (): Promise<boolean> => {
  const supabase = await createClient();
  const { data, error } = await supabase.from('super_admins').select('user_id').limit(1);
  return !error && !!data && data.length > 0;
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
