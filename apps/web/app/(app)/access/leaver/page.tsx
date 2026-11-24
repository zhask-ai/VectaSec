import Link from 'next/link';
import type { Route } from 'next';

import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { Toolbar, ToolbarField } from '@/components/ui/toolbar';
import { AccessTabs } from '../tabs';

/* Access · Leavers — everything one person owns across the connected systems.
 *
 * Pick a person; the engine (leaver.py) joins what scans stored: their accounts, what names
 * them as owner or creator, and what belongs to someone else but runs on something of theirs.
 * That last list is the one an offboarding checklist misses.
 *
 * A GET form, so the report is a link you can paste into the offboarding ticket. Nothing here
 * changes anything in any system.
 */

type Item = {
  id: string;
  kind: string;
  name: string;
  system: string;
  connection: string;
  active?: string | null;
  last_used_at?: string;
  detail?: string;
  because?: string[];
  other_owners?: string[];
};
type Report = {
  person: string;
  accounts: Item[];
  owns: Item[];
  breaks: Item[];
  systems_without_owner_data: string[];
  checklist: string[];
  scope_note: string;
};
type Person = { person: string; owns: number; accounts: number };

export const metadata = { title: 'Access · Leavers · VectaSec' };

export default async function LeaverPage({ searchParams }: { searchParams: Promise<{ person?: string }> }) {
  const params = await searchParams;
  const person = (params.person ?? '').trim().slice(0, 200) || null;

  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const auth = { tenantId: membership.tenantId, actor };

  const [peopleRes, reportRes] = await Promise.all([
    engineGet<{ people: Person[] }>('/people', auth),
    person ? engineGet<Report>(`/people/report?person=${encodeURIComponent(person)}`, auth) : Promise.resolve(null),
  ]);
  const people = peopleRes.ok ? peopleRes.data.people : [];

  return (
    <PageShell>
      <PageHeader
        title="Access"
        description="When someone leaves: their accounts, what they own, and what keeps running on their authority."
      />
      <AccessTabs />

      <form method="GET">
        <Toolbar
          end={
            <>
              <Button type="submit" variant="primary" size="sm">
                Show report
              </Button>
              {person && (
                <a
                  href={`/api/reports/leaver?person=${encodeURIComponent(person)}`}
                  className="vs-actionbtn"
                  title="This report as a Markdown document for the offboarding ticket"
                >
                  Download report
                </a>
              )}
            </>
          }
        >
          <ToolbarField label="Person (email or name, exact)" htmlFor="leaver-person">
            <input
              id="leaver-person"
              name="person"
              list="leaver-people"
              defaultValue={person ?? ''}
              placeholder="sam@yourcompany.com"
              required
              autoComplete="off"
              style={{
                height: 'var(--row-compact)',
                minWidth: 280,
                padding: '0 var(--space-2)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-interactive)',
                background: 'var(--surface-raised)',
                color: 'var(--text-primary)',
                fontSize: 'var(--text-xs)',
              }}
            />
            <datalist id="leaver-people">
              {people.map((p) => (
                <option key={p.person} value={p.person} />
              ))}
            </datalist>
          </ToolbarField>
        </Toolbar>
      </form>

      {!peopleRes.ok ? (
        <Card>
          <CardBody>
            <EmptyState tone="error" title="The Leaver report is unavailable" description={peopleRes.message} />
          </CardBody>
        </Card>
      ) : !person ? (
        <PeopleList people={people} />
      ) : !reportRes || !reportRes.ok ? (
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not build the report" description={reportRes?.message ?? 'The engine did not answer.'} />
          </CardBody>
        </Card>
      ) : (
        <ReportView rep={reportRes.data} />
      )}
    </PageShell>
  );
}

function PeopleList({ people }: { people: Person[] }) {
  if (people.length === 0) {
    return (
      <Card>
        <CardBody>
          <EmptyState
            tone="pending"
            title="No person is named as an owner yet"
            description="This list fills in from systems whose API returns an owner or creator, such as Zapier, n8n, Workato, Airflow and tagged cloud identities. Type a name above to check anyway."
          />
        </CardBody>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>People named in your systems</CardTitle>
        <CardMeta>{people.length} · most first</CardMeta>
      </CardHeader>
      <CardBody pad={false}>
        <Table density="compact" caption="People named as owner, creator or account holder">
          <THead>
            <TR>
              <TH width="60%">Person</TH>
              <TH width="20%" numeric>
                Owns
              </TH>
              <TH width="20%" numeric>
                Accounts
              </TH>
            </TR>
          </THead>
          <TBody>
            {people.slice(0, 200).map((p) => (
              <TR key={p.person}>
                <TD>
                  <Link
                    href={`/access/leaver?person=${encodeURIComponent(p.person)}` as Route}
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}
                  >
                    {p.person}
                  </Link>
                </TD>
                <TD numeric>{p.owns}</TD>
                <TD numeric>{p.accounts}</TD>
              </TR>
            ))}
          </TBody>
        </Table>
      </CardBody>
    </Card>
  );
}

function ReportView({ rep }: { rep: Report }) {
  const nothing = rep.accounts.length === 0 && rep.owns.length === 0;
  return (
    <>
      <Card accent>
        <CardHeader>
          <CardTitle>{rep.person}</CardTitle>
          <CardMeta>
            {rep.breaks.length} keep running · {rep.owns.length} owned · {rep.accounts.length} account
            {rep.accounts.length === 1 ? '' : 's'}
          </CardMeta>
        </CardHeader>
        <CardBody>
          <ol style={{ margin: 0, paddingLeft: 'var(--space-5)', display: 'grid', gap: 'var(--space-2)', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' }}>
            {rep.checklist.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ol>
        </CardBody>
        <CardFooter>
          {rep.scope_note}
          {rep.systems_without_owner_data.length > 0 && (
            <> Connected systems with no owner data: {rep.systems_without_owner_data.join(', ')}.</>
          )}
        </CardFooter>
      </Card>

      {!nothing && (
        <>
          <Section
            title="Keeps running on their authority"
            meta="owned by someone else, depends on something of theirs"
            items={rep.breaks}
            empty="Nothing owned by others depends on what this person owns."
            last="Depends on"
            render={(x) => (x.because ?? []).join(', ')}
          />
          <Section
            title="They own"
            meta="named as owner, creator or editor"
            items={rep.owns}
            empty="No resource names this person as owner."
            last="Detail"
            render={(x) => x.detail ?? ''}
          />
          <Section
            title="Their accounts"
            meta="their own login in a connected system"
            items={rep.accounts}
            empty="No account with this exact name was found."
            last="Role"
            render={(x) => x.detail ?? ''}
          />
        </>
      )}
    </>
  );
}

function Section({
  title,
  meta,
  items,
  empty,
  last,
  render,
}: {
  title: string;
  meta: string;
  items: Item[];
  empty: string;
  last: string;
  render: (x: Item) => string;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardMeta>
          {items.length} · {meta}
        </CardMeta>
      </CardHeader>
      <CardBody pad={items.length === 0}>
        {items.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{empty}</p>
        ) : (
          <Table density="compact" caption={title}>
            <THead>
              <TR>
                <TH width="34%">Item</TH>
                <TH width="18%">Kind</TH>
                <TH width="22%">Connection</TH>
                <TH width="26%">{last}</TH>
              </TR>
            </THead>
            <TBody>
              {items.map((x) => (
                <TR key={x.id}>
                  <TD>
                    <Link
                      href={`/estate/inventory/${x.id}` as Route}
                      style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', overflowWrap: 'anywhere' }}
                    >
                      {x.name}
                    </Link>
                  </TD>
                  <TD>
                    <Chip mono>{x.kind}</Chip>
                  </TD>
                  <TD muted>
                    {x.connection || '—'}
                    {x.system ? ` · ${x.system}` : ''}
                  </TD>
                  <TD muted>{render(x) || '—'}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardBody>
    </Card>
  );
}
