import { redirect } from 'next/navigation';

import { createClient, getClaims } from '@/lib/supabase/server';
import { getMemberships, getOwnMembership, isAdmin, isSuperAdmin } from '@/lib/role';
import { postureScore } from '@/lib/posture';
import { SEVERITIES, type Severity, type SeverityCounts } from '@/lib/types';
import { ShellChrome } from '@/components/shell/ShellChrome';

/* The AUTHED layout — wraps every route in the (app) group in the console shell.
 *
 * It resolves, under RLS, the few things the chrome needs and hands them to <ShellChrome> as plain
 * props: the tenant name (for the top bar + account menu), the live posture score (the top-bar
 * chip, computed from open-findings facets with the SAME formula as the Overview hero so the two
 * can never disagree), the admin flag (which decides whether the Settings nav entry renders — a
 * courtesy, re-checked server-side on every settings page and action), and the signed-in email.
 *
 * Every read here is RLS-scoped to the caller's tenant; there is no tenant filter in the query
 * because the policy is the boundary. Reads run per-request (cookies), so these routes are dynamic
 * — correct for a console whose every number is live.
 */

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const supabase = await createClient();

  const [memberships, facetsRes, connRes, membership, claims, superAdmin] = await Promise.all([
    getMemberships(),
    supabase.from('findings_facets').select('severity, n').eq('status', 'open'),
    supabase.from('connections').select('id', { count: 'exact', head: true }),
    getOwnMembership(),
    getClaims(),
    isSuperAdmin(),
  ]);

  // A brand-new self-served user has no org yet: onboarding names one. Platform operators
  // without a membership skip it — forcing US to create a customer org would be absurd.
  if (memberships.length === 0 && !superAdmin) redirect('/onboarding');

  const tenantName =
    memberships.find((m) => m.tenantId === membership?.tenantId)?.tenantName ??
    memberships[0]?.tenantName ??
    'VectaSec';

  // Posture is only meaningful once something is connected; before that the console is in setup
  // and a "100 · A" chip would be a comforting lie. Null hides the chip until there is an estate.
  let posture = null as ReturnType<typeof postureScore> | null;
  if ((connRes.count ?? 0) > 0 && !facetsRes.error) {
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
    for (const row of (facetsRes.data ?? []) as { severity: string; n: number }[]) {
      if ((row.severity as Severity) in counts) counts[row.severity as Severity] += row.n;
    }
    posture = postureScore(counts);
  }

  const email = (claims?.email as string | undefined) ?? null;

  return (
    <ShellChrome
      tenantName={tenantName}
      posture={posture}
      isAdmin={isAdmin(membership?.role)}
      isSuperAdmin={superAdmin}
      userEmail={email}
      memberships={memberships.map((m) => ({ tenantId: m.tenantId, tenantName: m.tenantName }))}
      activeTenantId={membership?.tenantId ?? null}
    >
      {children}
    </ShellChrome>
  );
}
