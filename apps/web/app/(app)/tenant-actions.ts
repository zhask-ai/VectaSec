'use server';

import { revalidatePath } from 'next/cache';
import { cookies } from 'next/headers';

import { getMemberships, TENANT_COOKIE } from '@/lib/role';

/* The tenant switcher's one write: remember which of the caller's orgs is active. The cookie
 * is a UI preference, not an authorization — every read of it (getOwnMembership) re-validates
 * against the caller's own tenant_members rows, so a forged cookie selects nothing.
 */
export async function switchTenantAction(form: FormData): Promise<void> {
  const tenantId = String(form.get('tenant') ?? '');
  const memberships = await getMemberships();
  if (!memberships.some((m) => m.tenantId === tenantId)) return;

  (await cookies()).set(TENANT_COOKIE, tenantId, {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 60 * 60 * 24 * 365,
  });
  revalidatePath('/', 'layout');
}
