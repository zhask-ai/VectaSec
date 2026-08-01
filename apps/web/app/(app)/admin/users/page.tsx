import { notFound } from 'next/navigation';

import { createClient, getVerifiedUser } from '@/lib/supabase/server';
import { isSuperAdmin } from '@/lib/role';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { AutoRefresh } from '@/components/AutoRefresh';
import { InviteUser, UserControls, type OrgOption } from './user-controls';

/* The operator's user list — every account on the platform, with presence. "Online" is a
 * heartbeat under 2 minutes old (the shell touches last_seen_at once a minute); it is
 * presence by polling, honest about its resolution, and the page refreshes itself so the
 * dots stay live. Reads via admin_users(), which re-checks super_admins itself.
 */

export const metadata = { title: 'Users · VectaSec' };

const ONLINE_WINDOW_MS = 2 * 60_000;

type UserRow = {
  user_id: string;
  email: string;
  full_name: string | null;
  created_at: string;
  last_seen_at: string | null;
  is_super: boolean;
  memberships: { tenant_id: string; tenant: string; role: string }[];
};

function relative(iso: string | null): string {
  if (!iso) return 'never';
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export default async function AdminUsersPage() {
  if (!(await isSuperAdmin())) notFound();

  const supabase = await createClient();
  // admin_orgs() feeds the "add to an organization" picker; both RPCs re-check super_admins
  // themselves, so this page's notFound() above is privacy, not the security boundary.
  const [{ data, error }, orgsRes, me] = await Promise.all([
    supabase.rpc('admin_users'),
    supabase.rpc('admin_orgs'),
    getVerifiedUser(),
  ]);
  const users = (data ?? []) as UserRow[];
  const orgs = ((orgsRes.data ?? []) as { id: string; name: string }[]).map(
    (o): OrgOption => ({ id: o.id, name: o.name }),
  );
  const online = users.filter(
    (u) => u.last_seen_at && Date.now() - new Date(u.last_seen_at).getTime() < ONLINE_WINDOW_MS,
  ).length;

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <AutoRefresh active />
      <PageHeader
        title="Users"
        description="Every account on the platform, with live presence — a green dot is a console open within the last two minutes."
        meta={`${users.length} user${users.length === 1 ? '' : 's'} · ${online} online`}
        actions={<InviteUser orgs={orgs} />}
      />
      <Card>
        <CardHeader>
          <CardTitle>All users</CardTitle>
          <CardMeta>
            {online} online now · presence is a 1-minute heartbeat, not a realtime channel
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {error ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState tone="error" title="Could not load users" description={error.message} />
            </div>
          ) : users.length === 0 ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState tone="setup" title="No users yet" description="Signups land here." />
            </div>
          ) : (
            <Table density="default" caption="All users, newest first">
              <THead>
                <TR>
                  <TH width="26%">User</TH>
                  <TH width="11%">Presence</TH>
                  <TH width="12%">Last seen</TH>
                  <TH width="29%">Organizations</TH>
                  <TH width="11%">Joined</TH>
                  <TH width="11%">Manage</TH>
                </TR>
              </THead>
              <TBody>
                {users.map((u) => {
                  const isOnline =
                    !!u.last_seen_at && Date.now() - new Date(u.last_seen_at).getTime() < ONLINE_WINDOW_MS;
                  return (
                    <TR key={u.user_id}>
                      <TD>
                        <div style={{ fontWeight: 600 }}>
                          {u.full_name || <span style={{ color: 'var(--text-muted)' }}>(no name)</span>}
                          {u.is_super && (
                            <span
                              style={{
                                marginLeft: 6,
                                fontSize: 'var(--text-2xs)',
                                color: 'var(--accent-fg)',
                                border: '1px solid var(--border-interactive)',
                                borderRadius: 999,
                                padding: '0 6px',
                              }}
                            >
                              super admin
                            </span>
                          )}
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere' }}>
                          {u.email}
                        </div>
                      </TD>
                      <TD>
                        <StatusPill tone={isOnline ? 'ok' : 'neutral'} label={isOnline ? 'online' : 'offline'} pulse={isOnline} />
                      </TD>
                      <TD>{relative(u.last_seen_at)}</TD>
                      <TD>
                        {u.memberships.length === 0 ? (
                          <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>no organization</span>
                        ) : (
                          <span style={{ fontSize: 'var(--text-2xs)' }}>
                            {u.memberships.map((m, i) => (
                              <span key={m.tenant_id}>
                                {i > 0 && ' · '}
                                {m.tenant} <span style={{ color: 'var(--text-muted)' }}>({m.role})</span>
                              </span>
                            ))}
                          </span>
                        )}
                      </TD>
                      <TD>{relative(u.created_at)}</TD>
                      <TD>
                        <UserControls
                          userId={u.user_id}
                          email={u.email}
                          memberships={u.memberships}
                          isSuper={u.is_super}
                          isSelf={u.user_id === me?.id}
                          orgs={orgs}
                        />
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
