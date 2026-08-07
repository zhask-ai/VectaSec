import Link from 'next/link';
import type { Route } from 'next';
import { notFound } from 'next/navigation';

import { createClient } from '@/lib/supabase/server';
import { isSuperAdmin } from '@/lib/role';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Page } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* The operator's org list — every tenant on the platform, with the numbers that say whether
 * it is alive: members, connections, open findings, last scan. Reads through admin_orgs(),
 * a definer function that re-checks super_admins itself; the notFound() here is privacy
 * (the page does not exist for non-operators), not the security boundary.
 */

export const metadata = { title: 'Organizations · VectaSec' };

type OrgRow = {
  id: string;
  name: string;
  plan: string;
  created_at: string;
  created_by_email: string | null;
  members: number;
  connections: number;
  open_findings: number;
  last_scan: string | null;
};

function relative(iso: string | null): string {
  if (!iso) return 'never';
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export default async function AdminOrgsPage() {
  if (!(await isSuperAdmin())) notFound();

  const supabase = await createClient();
  const { data, error } = await supabase.rpc('admin_orgs');
  const orgs = (data ?? []) as OrgRow[];

  return (
    <Page>
      <PageHeader
        title="Organizations"
        description="Every organization on the platform — who created it, how many people are in it, and whether it is actually scanning."
        meta={`${orgs.length} org${orgs.length === 1 ? '' : 's'}`}
      />
      <Card>
        <CardHeader>
          <CardTitle>All organizations</CardTitle>
          <CardMeta>platform-wide · super admin only</CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {error ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState tone="error" title="Could not load organizations" description={error.message} />
            </div>
          ) : orgs.length === 0 ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState tone="setup" title="No organizations yet" description="Signups land here." />
            </div>
          ) : (
            <Table density="default" caption="All organizations, newest first">
              <THead>
                <TR>
                  <TH width="24%">Organization</TH>
                  <TH width="10%">Plan</TH>
                  <TH width="22%">Created by</TH>
                  <TH width="10%" numeric>Members</TH>
                  <TH width="12%" numeric>Connections</TH>
                  <TH width="12%" numeric>Open findings</TH>
                  <TH width="10%">Last scan</TH>
                </TR>
              </THead>
              <TBody>
                {orgs.map((o) => (
                  <TR key={o.id}>
                    <TD>
                      <Link href={`/admin/${o.id}` as Route} style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                        {o.name}
                      </Link>
                      <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                        created {relative(o.created_at)}
                      </div>
                    </TD>
                    <TD>{o.plan}</TD>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere' }}>
                        {o.created_by_email ?? '—'}
                      </span>
                    </TD>
                    <TD numeric>{o.members}</TD>
                    <TD numeric>{o.connections}</TD>
                    <TD numeric>
                      {o.open_findings > 0 ? o.open_findings : <span style={{ color: 'var(--text-muted)' }}>0</span>}
                    </TD>
                    <TD>{relative(o.last_scan)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </Page>
  );
}
