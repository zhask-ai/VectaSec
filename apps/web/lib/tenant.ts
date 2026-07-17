import 'server-only';

import { createClient } from '@/lib/supabase/server';

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
  const supabase = await createClient();
  const { data, error } = await supabase.from('tenant_members').select('tenant_id').limit(2);
  if (error || !data || data.length === 0) return null;
  // A user in several tenants needs a tenant switcher before create-actions are safe to
  // offer — picking one silently would file their connection under a tenant they cannot see
  // is wrong. Until the switcher exists, refuse rather than guess.
  if (data.length > 1) return null;
  return (data[0] as { tenant_id: string }).tenant_id;
}
