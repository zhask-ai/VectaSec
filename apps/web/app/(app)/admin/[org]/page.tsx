import Link from 'next/link';
import { notFound } from 'next/navigation';

import { createClient } from '@/lib/supabase/server';
import { isSuperAdmin } from '@/lib/role';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { AdminInviteForm, AdminMemberControls } from './org-controls';

/* One customer org, managed by the operator: its members and roles, and an invite that acts
 * on the customer's behalf — the same engine path their own admin uses, audited under the
 * operator's real user id. Last-admin protection is the engine's and applies to us too.
 */

export const metadata = { title: 'Organization · VectaSec' };

const ONLINE_WINDOW_MS = 2 * 60_000;

type OrgRow = { id: string; name: string; plan: string; created_at: string; created_by_email: string | null };
type MemberRow = {
  user_id: string;
  email: string | null;
  full_name: string | null;
  role: string;
  last_seen_at: string | null;
  joined_at: string;
};

function relative(iso: string | null): string {
  if (!iso) return 'never';
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export default async function AdminOrgPage({ params }: { params: Promise<{ org: string }> }) {
  if (!(await isSuperAdmin())) notFound();

  const { org } = await params;
  if (!/^[0-9a-f-]{36}$/i.test(org)) notFound();

  const supabase = await createClient();
  const [orgsRes, membersRes] = await Promise.all([
    supabase.rpc('admin_orgs'),
    supabase.rpc('admin_org_members', { org }),
  ]);

  const orgRow = ((orgsRes.data ?? []) as OrgRow[]).find((o) => o.id === org);
  if (!orgRow) notFound();
  const members = (membersRes.data ?? []) as MemberRow[];

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1080 }}>
      <PageHeader
        title={orgRow.name}
        description={`${orgRow.plan} plan · created ${relative(orgRow.created_at)} by ${orgRow.created_by_email ?? 'unknown'}`}
        meta={`${members.length} member${members.length === 1 ? '' : 's'}`}
      />
      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        <Link href="/admin" style={{ color: 'var(--text-primary)' }}>
          ← All organizations
        </Link>
      </p>

      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
          <CardMeta>role changes and removals go through the engine — audited, last-admin protected</CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {membersRes.error ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState tone="error" title="Could not load members" description={membersRes.error.message} />
            </div>
          ) : members.length === 0 ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState tone="setup" title="No members" description="Invite someone below." />
            </div>
          ) : (
            <Table density="default" caption={`Members of ${orgRow.name}`}>
              <THead>
                <TR>
                  <TH width="34%">Member</TH>
                  <TH width="14%">Presence</TH>
                  <TH width="14%">Joined</TH>
                  <TH width="38%">Role / actions</TH>
                </TR>
              </THead>
              <TBody>
                {members.map((m) => {
                  const isOnline =
                    !!m.last_seen_at && Date.now() - new Date(m.last_seen_at).getTime() < ONLINE_WINDOW_MS;
                  return (
                    <TR key={m.user_id}>
                      <TD>
                        <div style={{ fontWeight: 600 }}>
                          {m.full_name || <span style={{ color: 'var(--text-muted)' }}>(no name)</span>}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere' }}>
                          {m.email ?? m.user_id}
                        </div>
                      </TD>
                      <TD>
                        <StatusPill tone={isOnline ? 'ok' : 'neutral'} label={isOnline ? 'online' : 'offline'} pulse={isOnline} />
                      </TD>
                      <TD>{relative(m.joined_at)}</TD>
                      <TD>
                        <AdminMemberControls orgId={org} userId={m.user_id} role={m.role} />
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Invite on their behalf</CardTitle>
          <CardMeta>they get the same invite email their own admin would send</CardMeta>
        </CardHeader>
        <CardBody>
          <AdminInviteForm orgId={org} />
        </CardBody>
      </Card>
    </div>
  );
}
