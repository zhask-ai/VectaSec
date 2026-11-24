import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import { canEdit, getOwnMembership } from '@/lib/role';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { FindingsTabs } from '../tabs';
import { BriefForm } from './brief-form';

/* Findings · Breach day.
 *
 * The page for the day a product you run is being exploited, or a vendor that holds your tokens
 * says it was breached. Name it; the engine matches it against the inventory it already holds
 * (breach.py) and answers three things: where you run it and on which version, which
 * identities that system accepts in rotation order, and which credentials for other systems
 * the tool holds. No system is contacted, so the answer is immediate.
 *
 * A brief is stored as it was computed. Reopening one shows what was known on the day.
 */

type System = {
  name: string;
  source: string;
  status: 'affected' | 'unknown' | 'not_affected';
  versions: { version: string; inferred: boolean; status: string; resource: string }[];
  last_scanned_at: string | null;
};
type Rotate = {
  order: number;
  identity: string;
  owner: string;
  credential_types: string;
  last_used_at: string;
  why: string[];
};
type Held = { name: string; kind: string; for: string; owner: string; used_by: string; connection: string };
type Brief = {
  title: string;
  product: string;
  kind: string;
  affected: string;
  reference: string;
  headline: string;
  systems: System[];
  rotate: Rotate[];
  rotate_total: number;
  held: Held[];
  steps: string[];
  scope_note: string;
};
type BriefRow = { id: string; title: string; product: string; kind: string; created_at: string; summary: Brief };

export const metadata = { title: 'Findings · Breach day · VectaSec' };

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const STATUS: Record<System['status'], { label: string; tone: StatusTone }> = {
  affected: { label: 'Affected version', tone: 'bad' },
  unknown: { label: 'Version unknown', tone: 'warn' },
  not_affected: { label: 'Not affected', tone: 'ok' },
};

function stamp(iso: string | null): string {
  return iso ? new Date(iso).toISOString().slice(0, 16).replace('T', ' ') : 'never';
}

export default async function BreachDayPage({ searchParams }: { searchParams: Promise<{ id?: string }> }) {
  const params = await searchParams;
  const wanted = params.id && UUID_RE.test(params.id) ? params.id : null;
  const supabase = await createClient();

  const [briefsRes, connectionsRes, membership] = await Promise.all([
    supabase
      .from('breach_briefs')
      .select('id, title, product, kind, created_at, summary')
      .order('created_at', { ascending: false })
      .limit(20),
    supabase.from('connections').select('type').order('type'),
    getOwnMembership(),
  ]);
  const editable = canEdit(membership?.role ?? null);
  const systems = [...new Set(((connectionsRes.data ?? []) as { type: string }[]).map((c) => c.type))];

  if (briefsRes.error) {
    const missing = /breach_briefs|schema cache|42P01|PGRST205/i.test(`${briefsRes.error.code} ${briefsRes.error.message}`);
    return (
      <Frame>
        <Card>
          <CardBody>
            <EmptyState
              tone={missing ? 'setup' : 'error'}
              title={missing ? 'Breach day is not switched on for this database yet' : 'Could not load briefs'}
              description={
                missing
                  ? 'Apply migration 20261123000003_breach_briefs.sql to create the table that stores briefs.'
                  : briefsRes.error.message
              }
            />
          </CardBody>
        </Card>
      </Frame>
    );
  }

  const briefs = (briefsRes.data ?? []) as unknown as BriefRow[];
  const current = (wanted ? briefs.find((b) => b.id === wanted) : null) ?? briefs[0] ?? null;

  return (
    <Frame>
      <Card accent>
        <CardHeader>
          <CardTitle>Something was breached or disclosed. Am I affected?</CardTitle>
        </CardHeader>
        <CardBody>
          <BriefForm systems={systems} editable={editable} />
        </CardBody>
      </Card>

      {current ? (
        <BriefView row={current} />
      ) : (
        <Card>
          <CardBody>
            <EmptyState
              tone="pending"
              title="No brief yet"
              description="Name a product above. You get the systems that run it, the versions the last scan recorded, the identities to rotate in order, and the credentials the tool holds for other systems."
            />
          </CardBody>
        </Card>
      )}

      {briefs.length > 1 && (
        <Card>
          <CardHeader>
            <CardTitle>Earlier briefs</CardTitle>
            <CardMeta>stored as computed on the day</CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Earlier breach-day briefs">
              <THead>
                <TR>
                  <TH width="18%">When</TH>
                  <TH width="42%">Brief</TH>
                  <TH width="20%">Product</TH>
                  <TH width="20%">Kind</TH>
                </TR>
              </THead>
              <TBody>
                {briefs
                  .filter((b) => b.id !== current?.id)
                  .map((b) => (
                    <TR key={b.id}>
                      <TD muted>{stamp(b.created_at)}</TD>
                      <TD>
                        <Link href={`/findings/breach-day?id=${b.id}` as Route} style={{ color: 'var(--text-primary)' }}>
                          {b.title}
                        </Link>
                      </TD>
                      <TD>
                        <Chip mono>{b.product}</Chip>
                      </TD>
                      <TD muted>{b.kind.replace('_', ' ')}</TD>
                    </TR>
                  ))}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      )}
    </Frame>
  );
}

function BriefView({ row }: { row: BriefRow }) {
  const b = row.summary;
  const p: React.CSSProperties = { margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)' };
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{b.title}</CardTitle>
          <CardMeta>
            {stamp(row.created_at)} UTC · {b.kind.replace('_', ' ')}
            {b.affected ? ` · affected ${b.affected}` : ''}
          </CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
            <p style={{ ...p, fontWeight: 600 }}>{b.headline}</p>
            <ol style={{ margin: 0, paddingLeft: 'var(--space-5)', display: 'grid', gap: 'var(--space-2)', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' }}>
              {b.steps.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ol>
            <span style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'center' }}>
              <a href={`/api/reports/breach-brief?id=${row.id}`} className="vs-actionbtn" title="This brief as a Markdown document">
                Download brief
              </a>
              {b.reference && (
                <a href={b.reference} target="_blank" rel="noreferrer noopener" style={{ fontSize: 'var(--text-2xs)' }}>
                  Advisory
                </a>
              )}
            </span>
          </div>
        </CardBody>
        <CardFooter>{b.scope_note}</CardFooter>
      </Card>

      {b.systems.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Where you run it</CardTitle>
            <CardMeta>{b.systems.length} system{b.systems.length === 1 ? '' : 's'} · affected first</CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Systems matching the advisory">
              <THead>
                <TR>
                  <TH width="26%">System</TH>
                  <TH width="20%">Status</TH>
                  <TH width="24%">Version the scan read</TH>
                  <TH width="16%">How we know</TH>
                  <TH width="14%">Last scan</TH>
                </TR>
              </THead>
              <TBody>
                {b.systems.map((s, i) => (
                  <TR key={`${s.name}-${i}`}>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>{s.name}</span>
                    </TD>
                    <TD>
                      <StatusPill tone={STATUS[s.status].tone} variant="soft" label={STATUS[s.status].label} />
                    </TD>
                    <TD>
                      {s.versions.length === 0 ? (
                        <span style={{ color: 'var(--text-muted)' }}>not read by the scan</span>
                      ) : (
                        <span style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                          {s.versions.map((v, j) => (
                            <Chip key={j} mono inferred={v.inferred} title={v.inferred ? 'Inferred, not read: treated as unknown' : v.resource}>
                              {v.version}
                            </Chip>
                          ))}
                        </span>
                      )}
                    </TD>
                    <TD muted>{s.source}</TD>
                    <TD muted>{stamp(s.last_scanned_at)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      )}

      {b.rotate.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Rotate in this order</CardTitle>
            <CardMeta>
              {b.rotate.length} of {b.rotate_total} identit{b.rotate_total === 1 ? 'y' : 'ies'} this system accepts
            </CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Identities to rotate, most dangerous first">
              <THead>
                <TR>
                  <TH width="6%" numeric>
                    #
                  </TH>
                  <TH width="26%">Identity</TH>
                  <TH width="16%">Owner</TH>
                  <TH width="14%">Credential</TH>
                  <TH width="14%">Last used</TH>
                  <TH width="24%">Why this position</TH>
                </TR>
              </THead>
              <TBody>
                {b.rotate.map((r) => (
                  <TR key={`${r.order}-${r.identity}`}>
                    <TD numeric>{r.order}</TD>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>{r.identity}</span>
                    </TD>
                    <TD muted>{r.owner || 'no owner recorded'}</TD>
                    <TD muted>{r.credential_types || '—'}</TD>
                    <TD muted>{/^\d{4}-/.test(r.last_used_at) ? r.last_used_at.slice(0, 10) : r.last_used_at}</TD>
                    <TD>
                      <span style={{ fontSize: 'var(--text-2xs)' }}>{r.why.join(' · ') || 'no extra risk recorded'}</span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
          <CardFooter>
            A ranking by what each identity can reach, for the person who owns the change. VectaSec
            rotates nothing itself.
          </CardFooter>
        </Card>
      )}

      {b.held.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Credentials it holds for other systems</CardTitle>
            <CardMeta>{b.held.length} · rotate each at its destination</CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Third-party credentials held by the tool">
              <THead>
                <TR>
                  <TH width="32%">Credential</TH>
                  <TH width="22%">For</TH>
                  <TH width="20%">Owner</TH>
                  <TH width="10%" numeric>
                    Used by
                  </TH>
                  <TH width="16%">In</TH>
                </TR>
              </THead>
              <TBody>
                {b.held.map((h, i) => (
                  <TR key={`${h.name}-${i}`}>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>{h.name}</span>
                    </TD>
                    <TD>
                      <Chip mono>{h.for}</Chip>
                    </TD>
                    <TD muted>{h.owner || 'no owner recorded'}</TD>
                    <TD numeric muted>
                      {h.used_by || '—'}
                    </TD>
                    <TD muted>{h.connection}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      )}
    </>
  );
}

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <PageShell>
      <PageHeader
        title="Findings"
        description="For the day a product you run is exploited or a vendor is breached: where you run it, and what to rotate first."
      />
      <FindingsTabs />
      {children}
    </PageShell>
  );
}
