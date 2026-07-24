import Link from 'next/link';

import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { getOwnMembership, isAdmin } from '@/lib/role';

/* Settings · General — the honest single-tenant admin view.
 *
 * The SSO section states the current state plainly and offers no toggle, because there is
 * nothing a toggle here could truthfully do: SAML/OIDC is Supabase Auth configuration
 * (dashboard or management API), not a console-writable row. A switch that "enables SSO"
 * without wiring an IdP would be theatre in the one product that cannot afford it.
 */

export const metadata = { title: 'Settings · VectaSec' };

export default async function SettingsGeneralPage() {
  // The layout hides this page's render for non-admins, but page segments execute regardless
  // of the layout — so gate here too. Nothing sensitive is fetched below; the gate keeps that
  // true if this page ever grows a query.
  const membership = await getOwnMembership();
  if (!isAdmin(membership?.role)) return null;

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <Card>
        <CardHeader>
          <CardTitle>Workspace</CardTitle>
          <CardMeta>admin-only area</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-2)', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)' }}>
            <p style={{ margin: 0, color: 'var(--text-secondary)', maxWidth: '72ch' }}>
              Manage who can see and change this tenant under{' '}
              <Link href="/settings/members" style={{ color: 'var(--text-primary)' }}>
                Members
              </Link>
              , and where findings are delivered under{' '}
              <Link href="/settings/integrations" style={{ color: 'var(--text-primary)' }}>
                Integrations
              </Link>
              . Roles: <strong style={{ color: 'var(--text-primary)' }}>admin</strong> manages the
              tenant, <strong style={{ color: 'var(--text-primary)' }}>editor</strong> runs scans and
              works findings, <strong style={{ color: 'var(--text-primary)' }}>viewer</strong> reads
              everything and changes nothing.
            </p>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Single sign-on</CardTitle>
          <CardMeta>email + password today</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-3)', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)', maxWidth: '72ch' }}>
            <p style={{ margin: 0 }}>
              This workspace authenticates with{' '}
              <strong style={{ color: 'var(--text-primary)' }}>email and password</strong> through
              Supabase Auth. SAML or OIDC single sign-on is not configured.
            </p>
            <p style={{ margin: 0 }}>
              Enabling SSO requires configuring an identity provider in Supabase Auth (SAML 2.0 is a
              Supabase Pro-plan feature configured per project; OIDC providers are added in the Auth
              provider settings). There is no switch here because the console cannot do that
              configuration for you — once the provider is wired, sign-in picks it up without a
              console change.
            </p>
            <p style={{ margin: 0, fontSize: 'var(--text-xs)' }}>
              Until then: use strong unique passwords, and remove members promptly on the Members tab
              — removal takes effect on their next action, not just their next sign-in.
            </p>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
