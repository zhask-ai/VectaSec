import { redirect } from 'next/navigation';

import { createClient, getClaims } from '@/lib/supabase/server';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { CreateOrgForm } from './create-org-form';

/* First-run: an authed user with no organization names theirs and becomes its admin.
 *
 * Invited users never see this page — the engine's invite writes their membership before
 * their first sign-in, so the layout's gate finds a membership and lets them straight into
 * their inviter's org. This page is only for genuinely new, self-served users. Anyone who
 * already belongs somewhere is bounced home rather than offered a second org (create_org
 * enforces the same rule server-side; the redirect is just the polite version).
 */

export const metadata = { title: 'Welcome · VectaSec' };

export default async function OnboardingPage() {
  const claims = await getClaims();
  if (!claims) redirect('/login');

  const supabase = await createClient();
  const { data } = await supabase.from('tenant_members').select('tenant_id').limit(1);
  if (data && data.length > 0) redirect('/');

  const email = (claims.email as string | undefined) ?? '';

  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '60dvh' }}>
      <Card style={{ width: 420 }}>
        <CardHeader>
          <CardTitle>Name your organization</CardTitle>
          <CardMeta>{email}</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 12 }}>
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              This is your workspace: your team, your connected systems, your findings. You will
              be its admin — you can invite your team from Settings once you are in.
            </p>
            <CreateOrgForm />
            <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
              Expecting to join an existing team? Ask your admin to invite {email || 'your email'}{' '}
              from Settings → Members — the invite adds you automatically.
            </p>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
