import 'server-only';

import { getOwnMembership } from '@/lib/role';

/* Tenant resolution for actions that create something NEW.
 *
 * Actions on an existing row (a finding, a control, a connection) derive their tenant from
 * that row, read under RLS — the read is the authorization. Creating a connection has no row
 * yet, so the tenant comes from the caller's own membership instead: `tenant_members` RLS is
 * `user_id = auth.uid()`, so this query can only ever return tenants the user belongs to.
 * Never accept a tenant from a form for the same reason the engine's audit actor is never a
 * form field: it would be attacker-controlled.
 */
export async function getOwnTenantId(): Promise<string | null> {
  // Delegates to the switcher-aware resolution in lib/role.ts: one org — that org; several —
  // the validated cookie pick, else the first by name. Never a tenant the caller is not in.
  const membership = await getOwnMembership();
  return membership?.tenantId ?? null;
}
