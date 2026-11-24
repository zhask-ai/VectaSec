import Link from 'next/link';
import type { Route } from 'next';

import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { StatTile } from '@/components/ui/stat';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { AccessTabs } from '../tabs';

/* Access · Right-size — grants versus observed use, as a dry run (engine: impact.recommend).
 *
 * For every identity that holds a grant: what it may do, what it was seen doing, and the
 * difference written as a diff ("- all on *", "+ read on orders"). Nothing is applied; the
 * diff is for the person who owns the change.
 *
 * "Cannot assess" is a first-class answer and the page counts it: most systems expose no usage
 * that names an identity, and saying so is better than recommending removals from silence.
 */

type Diff = { op: '+' | '-'; action: string; target: string };
type Rec = {
  identity: string;
  resource_id: string;
  system: string;
  verdict: 'narrow' | 'remove_all' | 'trim' | 'cannot_assess' | 'right_sized';
  confidence: string;
  reason: string;
  grants: number;
  wildcards: number;
  diff: Diff[];
};
type Resp = { recommendations: Rec[]; total: number; counts: Record<string, number>; min_window_days: number; scope_note: string };

export const metadata = { title: 'Access · Right-size · VectaSec' };

const VERDICT: Record<Rec['verdict'], { label: string; tone: StatusTone }> = {
  narrow: { label: 'Narrow the wildcard', tone: 'warn' },
  remove_all: { label: 'Never seen: disable', tone: 'warn' },
  trim: { label: 'Trim unused grants', tone: 'info' },
  cannot_assess: { label: 'Cannot assess', tone: 'neutral' },
  right_sized: { label: 'Right-sized', tone: 'ok' },
};

export default async function RightSizePage({ searchParams }: { searchParams: Promise<{ show?: string }> }) {
  const showAll = (await searchParams).show === 'all';
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const res = await engineGet<Resp>('/access/least-privilege', { tenantId: membership.tenantId, actor }, 20_000);

  const frame = (children: React.ReactNode) => (
    <PageShell>
      <PageHeader
        title="Access"
        description="What each identity may do against what it was seen doing, written as a change you could make."
      />
      <AccessTabs />
      {children}
    </PageShell>
  );

  if (!res.ok) {
    return frame(
      <Card>
        <CardBody>
          <EmptyState tone="error" title="Right-sizing is unavailable" description={res.message} />
        </CardBody>
      </Card>,
    );
  }
  const d = res.data;
  const n = (k: string) => d.counts[k] ?? 0;
  const actionable = d.recommendations.filter((r) => r.verdict === 'narrow' || r.verdict === 'remove_all' || r.verdict === 'trim');
  const rows = showAll ? d.recommendations : actionable;

  if (d.total === 0) {
    return frame(
      <Card>
        <CardBody>
          <EmptyState
            tone="pending"
            title="No identity with grants yet"
            description="This page fills in once a scan returns identities and what they are allowed to do."
          />
        </CardBody>
      </Card>,
    );
  }

  return frame(
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 'var(--space-4)' }}>
        {(
          [
            ['Wildcards to narrow', n('narrow'), 'seen using less than granted', n('narrow') ? 'warn' : 'neutral'],
            ['Never seen', n('remove_all'), `in ${d.min_window_days}+ days of scans`, n('remove_all') ? 'warn' : 'neutral'],
            ['Grants to trim', n('trim'), 'specific grants not seen used', 'neutral'],
            ['Right-sized', n('right_sized'), 'every grant matched use', 'neutral'],
            ['Cannot assess', n('cannot_assess'), 'no usage signal or too short', 'neutral'],
          ] as const
        ).map(([label, value, sub, tone]) => (
          <Card key={label}>
            <CardBody>
              <StatTile label={label} value={value} sub={sub} tone={tone} size="sm" />
            </CardBody>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{showAll ? 'Every identity with grants' : 'Changes you could make'}</CardTitle>
          <CardMeta>
            {rows.length} of {d.total} ·{' '}
            <Link href={(showAll ? '/access/right-size' : '/access/right-size?show=all') as Route}>
              {showAll ? 'show only changes' : 'show all'}
            </Link>
          </CardMeta>
        </CardHeader>
        <CardBody pad={rows.length === 0}>
          {rows.length === 0 ? (
            <EmptyState
              tone="clean"
              title="No change to recommend"
              description={`Of ${d.total} identities, ${n('right_sized')} are right-sized and ${n('cannot_assess')} cannot be assessed (no usage signal that names an identity, or watched for under ${d.min_window_days} days).`}
            />
          ) : (
            <Table density="compact" caption="Least-privilege recommendations">
              <THead>
                <TR>
                  <TH width="22%">Identity</TH>
                  <TH width="17%">Verdict</TH>
                  <TH width="27%">Why</TH>
                  <TH width="34%">Dry-run change</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map((r) => (
                  <TR key={`${r.resource_id}`}>
                    <TD>
                      <span style={{ display: 'grid', gap: 2, padding: 'var(--space-2) 0', minWidth: 0 }}>
                        <Link
                          href={`/estate/inventory/${r.resource_id}` as Route}
                          style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', overflowWrap: 'anywhere' }}
                        >
                          {r.identity}
                        </Link>
                        <span>
                          <Chip mono>{r.system}</Chip>
                        </span>
                      </span>
                    </TD>
                    <TD>
                      <StatusPill tone={VERDICT[r.verdict].tone} variant="soft" label={VERDICT[r.verdict].label} />
                    </TD>
                    <TD>
                      <span style={{ fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-sm)' }}>{r.reason}</span>
                    </TD>
                    <TD>
                      {r.diff.length === 0 ? (
                        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>no change</span>
                      ) : (
                        <ul
                          aria-label={`Proposed change for ${r.identity}`}
                          style={{ listStyle: 'none', margin: 0, padding: 'var(--space-2) 0', display: 'grid', gap: 2, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}
                        >
                          {r.diff.slice(0, 8).map((x, i) => (
                            <li key={i} style={{ color: x.op === '-' ? 'var(--text-secondary)' : 'var(--text-primary)', overflowWrap: 'anywhere' }}>
                              <span aria-hidden="true">{x.op} </span>
                              <span className="vs-visually-hidden">{x.op === '-' ? 'remove: ' : 'add: '}</span>
                              {x.action || 'access'} on {x.target || '(unnamed)'}
                            </li>
                          ))}
                          {r.diff.length > 8 && <li style={{ color: 'var(--text-muted)' }}>… {r.diff.length - 8} more</li>}
                        </ul>
                      )}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
        <CardFooter>{d.scope_note}</CardFooter>
      </Card>
    </>,
  );
}
