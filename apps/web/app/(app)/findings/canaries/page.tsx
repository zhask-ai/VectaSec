import { createClient } from '@/lib/supabase/server';
import { canEdit, getOwnMembership } from '@/lib/role';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { FindingsTabs } from '../tabs';
import { MintForm, RevokeButton } from './canary-forms';

/* Findings · Canaries — decoy URLs that alert when someone tries them (engine: canary.py).
 *
 * A canary goes where an intruder reads: a disabled workflow, an env file, a note beside real
 * credentials. A request to it means someone was reading there. The URL is shown once at
 * creation (only its hash is stored), every caller gets the same 404, and a hit records the
 * address, client and method only.
 */

type Canary = {
  id: string;
  name: string;
  placed_in: string;
  token_prefix: string;
  created_at: string;
  revoked_at: string | null;
  last_hit_at: string | null;
  hit_count: number;
};
type Hit = { id: string; canary_id: string; at: string; source_ip: string | null; user_agent: string | null; method: string | null };

export const metadata = { title: 'Findings · Canaries · VectaSec' };

function stamp(iso: string | null): string {
  return iso ? new Date(iso).toISOString().slice(0, 16).replace('T', ' ') : '—';
}

export default async function CanariesPage() {
  const supabase = await createClient();
  const [canariesRes, hitsRes, membership] = await Promise.all([
    supabase
      .from('canaries')
      .select('id, name, placed_in, token_prefix, created_at, revoked_at, last_hit_at, hit_count')
      .order('created_at', { ascending: false })
      .limit(200),
    supabase.from('canary_hits').select('id, canary_id, at, source_ip, user_agent, method').order('at', { ascending: false }).limit(50),
    getOwnMembership(),
  ]);
  const editable = canEdit(membership?.role ?? null);

  const frame = (children: React.ReactNode) => (
    <PageShell>
      <PageHeader
        title="Findings"
        description="Decoys that tell you someone is reading where they should not: a URL nothing legitimate calls."
      />
      <FindingsTabs />
      {children}
    </PageShell>
  );

  if (canariesRes.error) {
    const missing = /canaries|schema cache|42P01|PGRST205/i.test(`${canariesRes.error.code} ${canariesRes.error.message}`);
    return frame(
      <Card>
        <CardBody>
          <EmptyState
            tone={missing ? 'setup' : 'error'}
            title={missing ? 'Canaries are not switched on for this database yet' : 'Could not load canaries'}
            description={missing ? 'Apply migration 20261123000004_canaries.sql.' : canariesRes.error.message}
          />
        </CardBody>
      </Card>,
    );
  }

  const canaries = (canariesRes.data ?? []) as Canary[];
  const hits = (hitsRes.data ?? []) as Hit[];
  const nameOf = new Map(canaries.map((c) => [c.id, c.name]));
  const tripped = canaries.filter((c) => c.hit_count > 0 && !c.revoked_at).length;

  return frame(
    <>
      <Card accent>
        <CardHeader>
          <CardTitle>Create a canary</CardTitle>
          <CardMeta>the URL is shown once</CardMeta>
        </CardHeader>
        <CardBody>
          <MintForm editable={editable} />
        </CardBody>
        <CardFooter>
          Put it where only an intruder would find and try it. It detects someone who reads that
          place and calls the URL; it does not detect an intruder who never looks there.
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Your canaries</CardTitle>
          <CardMeta>
            {canaries.length} · {tripped} tripped
          </CardMeta>
        </CardHeader>
        <CardBody pad={canaries.length === 0}>
          {canaries.length === 0 ? (
            <EmptyState
              tone="pending"
              title="No canary yet"
              description="Create one above and paste it into a disabled workflow, an environment file, or a note next to real credentials."
            />
          ) : (
            <Table density="compact" caption="Canaries">
              <THead>
                <TR>
                  <TH width="24%">Name</TH>
                  <TH width="26%">Placed in</TH>
                  <TH width="14%">Status</TH>
                  <TH width="8%" numeric>
                    Hits
                  </TH>
                  <TH width="14%">Last hit</TH>
                  <TH width="14%">Action</TH>
                </TR>
              </THead>
              <TBody>
                {canaries.map((c) => (
                  <TR key={c.id}>
                    <TD>
                      <span style={{ display: 'grid', gap: 2, padding: 'var(--space-2) 0' }}>
                        <span style={{ fontWeight: 600 }}>{c.name}</span>
                        <code style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>/c/{c.token_prefix}…</code>
                      </span>
                    </TD>
                    <TD muted>{c.placed_in || 'not recorded'}</TD>
                    <TD>
                      {c.revoked_at ? (
                        <StatusPill tone="neutral" label="Revoked" />
                      ) : c.hit_count > 0 ? (
                        <StatusPill tone="bad" variant="soft" label="Tripped" />
                      ) : (
                        <StatusPill tone="ok" label="Quiet" />
                      )}
                    </TD>
                    <TD numeric>{c.hit_count}</TD>
                    <TD muted>{stamp(c.last_hit_at)}</TD>
                    <TD>{!c.revoked_at && editable ? <RevokeButton id={c.id} /> : <span style={{ color: 'var(--text-muted)' }}>—</span>}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      {hits.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent hits</CardTitle>
            <CardMeta>newest first · times in UTC</CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Requests that reached a canary">
              <THead>
                <TR>
                  <TH width="18%">When</TH>
                  <TH width="24%">Canary</TH>
                  <TH width="18%">From</TH>
                  <TH width="10%">Method</TH>
                  <TH width="30%">Client</TH>
                </TR>
              </THead>
              <TBody>
                {hits.map((h) => (
                  <TR key={h.id}>
                    <TD muted>{stamp(h.at)}</TD>
                    <TD>{nameOf.get(h.canary_id) ?? 'removed'}</TD>
                    <TD mono>{h.source_ip ?? 'unknown'}</TD>
                    <TD muted>{h.method ?? '—'}</TD>
                    <TD muted>
                      <span style={{ overflowWrap: 'anywhere' }}>{h.user_agent ?? 'not sent'}</span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
          <CardFooter>
            The address is what the caller&apos;s connection or proxy reported and can be forged.
            Request bodies and headers are never stored. The first hit in an hour alerts your
            chat, webhook, email and SIEM integrations.
          </CardFooter>
        </Card>
      )}
    </>,
  );
}
