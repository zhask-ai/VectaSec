import 'server-only';

import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';
import { cache } from 'react';

/* Server-side Supabase access. `server-only` makes it a BUILD ERROR if this file is ever
 * imported from a client component — the env read and the auth surface must never ship.
 *
 * The real authorization boundary is Postgres RLS. proxy.ts is a UX redirect and can be
 * silently bypassed (Server Functions are POSTs to the page route; a matcher change or a
 * refactor removes coverage without a test failing). Anything mutating must re-verify
 * inside itself. Three layers; only RLS is load-bearing.
 */

function env(name: 'NEXT_PUBLIC_SUPABASE_URL' | 'NEXT_PUBLIC_SUPABASE_ANON_KEY'): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is not set — see .env at the repo root`);
  return v;
}

export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(env('NEXT_PUBLIC_SUPABASE_URL'), env('NEXT_PUBLIC_SUPABASE_ANON_KEY'), {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Called from a Server Component, where cookies are immutable. Safe to ignore:
          // proxy.ts refreshes the session on every request, so the write is redundant here.
        }
      },
    },
  });
}

/** Signature-verified claims. Cached per request: one auth read per render pass, and it
 * discourages threading the user object between components (which is how it leaks to a
 * client boundary). Use for page/route protection and for reading `sub`.
 *
 * Verifies the JWT against the JWKS — locally via WebCrypto when the project uses asymmetric
 * signing keys, so usually no network hop. Never `getSession()` on the server: it only reads
 * the cookie and is not guaranteed to revalidate the token. */
export const getClaims = cache(async () => {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (error) return null;
  return data?.claims ?? null;
});

/** Authoritative, server-confirmed user. Always costs a network request to the Auth server.
 *
 * Use this — NOT getClaims — for privilege-sensitive operations: role changes, creating a
 * suppression, connection/credential changes, API-key issuance, tenant admin.
 *
 * Why the split: getClaims verifies a *signature*, not *revocation*. A valid token keeps
 * working until it expires, so a revoked or demoted user would retain access. In a security
 * product that is a finding against us. Keep the access-token TTL short to bound the window. */
export const getVerifiedUser = cache(async () => {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getUser();
  if (error) return null;
  return data.user;
});
