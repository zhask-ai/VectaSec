import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { engineGet } from '@/lib/engine';
import { getOwnMembership, isAdmin } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { AddMemberForm, MemberRowControls } from './member-controls';

/* Settings · Members — who can see and change this tenant.
 *
 * The roster is READ from the engine, not Supabase: tenant_members RLS is own-row-only (that
 * is what makes the role read trustworthy), so the console cannot list colleagues directly.
 * The engine can, and it is also the only write path — so this page has a single source for
 * both directions and degrades to an honest error card when the engine (or this endpoint)
 * is not there yet.
 */

export const metadata = { title: 'Members · VectaSec' };

type MemberRow = { user_id: string; email: string | null; role: string; created_at?: string };

function roleTone(role: string): string {
  if (role === 'admin' || role === 'owner') return 'var(--sev-medium-fg)';
  if (role === 'editor' || role === 'analyst') return 'var(--sev-low-fg)';
  return 'var(--text-secondary)';
}

export default async function MembersPage() {
  // Page-level gate: the layout hides the render, but this segment executes (and fetches)
  // regardless of the layout, so the fetch itself must be behind the role check.
  const membership = await getOwnMembership();
  if (!isAdmin(membership?.role) || !membership) return null;

  const claims = await getClaims();
  const currentUserId = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!currentUserId) return null;

  // The engine wraps the roster: {members: [...]}.
  const res = await engineGet<{ members: MemberRow[] }>('/members', {
    tenantId: membership.tenantId,
    actor: currentUserId,
  });
  const members = res.ok ? res.data.members : [];

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
          <CardMeta>
            {res.ok ? `${members.length} member${members.length === 1 ? '' : 's'}` : 'unavailable'}
          </CardMeta>
        </CardHeader>
        <CardBody pad={!res.ok || members.length === 0}>
          {!res.ok ? (
            // Not an empty roster — a failed read. The engine may be down, or may not expose
            // member management yet; either way the message is the engine's own.
            <EmptyState
              tone="error"
              title="Could not load members"
              description={`${res.message} Membership itself is unaffected — this is only the management view.`}
            />
          ) : members.length === 0 ? (
            <EmptyState
              tone="setup"
              title="No members listed"
              description="The engine returned an empty roster. At minimum you belong to this tenant, so an empty list usually means the engine's member API is not fully wired yet."
            />
          ) : (
            <Table density="default" caption="Tenant members and their roles">
              <THead>
                <TR>
                  <TH width="34%">Email</TH>
                  <TH width="14%">Role</TH>
                  <TH>Manage</TH>
                </TR>
              </THead>
              <TBody>
                {members.map((m) => (
                  <TR key={m.user_id}>
                    <TD>
                      {/* email comes from a LEFT JOIN on auth.users — null if the auth user
                          vanished; the membership row is still real and manageable. */}
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                        {m.email ?? <span style={{ color: 'var(--text-muted)' }}>account deleted</span>}
                      </span>
                      {m.user_id === currentUserId && (
                        <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                          you
                        </span>
                      )}
                    </TD>
                    <TD>
                      <span
                        style={{
                          display: 'inline-flex',
                          padding: '1px var(--space-2)',
                          border: '1px solid var(--border-strong)',
                          borderRadius: 'var(--radius-full)',
                          fontSize: 'var(--text-2xs)',
                          fontWeight: 600,
                          letterSpacing: '0.04em',
                          textTransform: 'uppercase',
                          color: roleTone(m.role),
                        }}
                      >
                        {m.role}
                      </span>
                    </TD>
                    <TD>
                      <MemberRowControls
                        userId={m.user_id}
                        email={m.email ?? 'this member'}
                        role={m.role}
                        isSelf={m.user_id === currentUserId}
                      />
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Add a member</CardTitle>
          <CardMeta>they must have signed up already</CardMeta>
        </CardHeader>
        <CardBody>
          <AddMemberForm />
        </CardBody>
      </Card>
    </div>
  );
}
