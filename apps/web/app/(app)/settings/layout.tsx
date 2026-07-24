import { Card, CardBody } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
import { getOwnMembership, isAdmin } from '@/lib/role';
import { SettingsTabs } from './tabs';

/* The Settings shell — tenant administration (members, integrations, sign-on), admin-only.
 *
 * The gate here is presentation: it decides whether the tabs and pages RENDER. It is not the
 * authorization — page segments execute independently of whether a layout includes them, and
 * Server Actions are directly POSTable — so every settings page re-checks the role before
 * fetching and every settings action re-verifies with getVerifiedUser + a fresh role read.
 * Three layers again; the engine's own role enforcement is the load-bearing one.
 */

export const metadata = { title: 'Settings · VectaSec' };

export default async function SettingsLayout({ children }: { children: React.ReactNode }) {
  const membership = await getOwnMembership();
  const admin = isAdmin(membership?.role);

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1080 }}>
      <PageHeader
        title="Settings"
        description="Tenant administration — who can access this workspace, where findings are delivered, and how members sign in."
      />

      {admin ? (
        <>
          <SettingsTabs />
          {children}
        </>
      ) : (
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="Settings is for tenant admins"
              description="Managing members, alert integrations and sign-on needs an admin role. Ask a tenant admin if you need access — nothing on this page is readable or changeable with your current role."
            />
          </CardBody>
        </Card>
      )}
    </div>
  );
}
