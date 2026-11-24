import Link from 'next/link';
import type { Route } from 'next';

import { createClient, getClaims } from '@/lib/supabase/server';
import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import type { Severity } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { Toolbar, ToolbarField } from '@/components/ui/toolbar';
import { EstateTabs } from '../tabs';
import { ExplainCard } from './explain-card';
import {
  CHANGE_KINDS,
  ChangeChip,
  ChangeWindow,
  FieldDiff,
  changeLabel,
  dayOf,
  stamp,
  timeOf,
  type ChangeKind,
  type ChangeRow,
} from './_parts';

/* Estate · History — the Time machine.
 *
 * Three questions, one page:
 *   1. What changed between scans?      the change list, newest first, grouped by day
 *   2. What did it look like on a date? the "as recorded on" panel (?at=YYYY-MM-DD)
 *   3. Can I hand this to a reviewer?   the CSV / Markdown access-and-change report
 *
 * The change list is read straight from `resource_changes` under RLS, like every list in the
 * console. The as-of panel is computed by the engine (GET /timeline/as-of) because finding
 * status on a past date is replayed from the audit trail, and that logic lives in one place.
 *
 * WHAT THIS PAGE MUST NOT IMPLY. A scanner that polls knows what changed and the two scans it
 * changed between. It knows who only where the system's API says so. The footer says it; the
 * "Changed by" column says "not exposed" rather than leaving a blank that reads as "nobody".
 */

const LIST_LIMIT = 300;
const WINDOWS = [7, 30, 90, 365] as const;

type Row = ChangeRow & { connections: { id: string; name: string; type: string } | null };
type ConnectionRow = { id: string; name: string; type: string };

type AsOf = {
  at: string;
  first_scan_at: string | null;
  posture: { taken_at: string; score: number; findings_total: number } | null;
  resources_total: number;
  open_by_severity: Record<Severity, number>;
  open_total: number;
  open_findings: {
    id: string;
    rule_id: string;
    title: string;
    severity: Severity;
    status_now: string;
    first_seen: string;
    resource: string | null;
    connection: string | null;
  }[];
  still_open_now: number;
  changes_since: Record<ChangeKind, number>;
  caveats: string[];
};

export const metadata = { title: 'Estate · History · VectaSec' };

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export default async function HistoryPage({
  searchParams,
}: {
  searchParams: Promise<{ days?: string; connection?: string; change?: string; at?: string; explain?: string }>;
}) {
  const params = await searchParams;
  const days = WINDOWS.find((w) => String(w) === params.days) ?? 30;
  const connFilter = params.connection?.trim() || null;
  const changeFilter = CHANGE_KINDS.find((c) => c === params.change) ?? null;
  const at = params.at && DATE_RE.test(params.at) ? params.at : null;
  const explain = params.explain === '1';

  const since = new Date(Date.now() - days * 86_400_000).toISOString();
  const supabase = await createClient();

  let listQ = supabase
    .from('resource_changes')
    .select(
      'id, resource_id, connection_id, kind, name, change, fields, field_count, actor, prev_seen_at, observed_at, connections(id, name, type)',
      { count: 'exact' },
    )
    .gte('observed_at', since)
    .order('observed_at', { ascending: false })
    .limit(LIST_LIMIT);
  if (connFilter) listQ = listQ.eq('connection_id', connFilter);
  if (changeFilter) listQ = listQ.eq('change', changeFilter);

  // Exact per-type totals for the window (head counts, never a tally of a capped page).
  const countOf = (change: ChangeKind) => {
    let q = supabase
      .from('resource_changes')
      .select('id', { count: 'exact', head: true })
      .gte('observed_at', since)
      .eq('change', change);
    if (connFilter) q = q.eq('connection_id', connFilter);
    return q;
  };

  const [listRes, connectionsRes, everRes, scansRes, ...countRes] = await Promise.all([
    listQ,
    supabase.from('connections').select('id, name, type').order('name'),
    supabase.from('resource_changes').select('id', { count: 'exact', head: true }),
    supabase.from('scans').select('id', { count: 'exact', head: true }).eq('status', 'done'),
    ...CHANGE_KINDS.map(countOf),
  ]);

  const connections = (connectionsRes.data ?? []) as ConnectionRow[];
  const exportQuery = `?days=${days}`;

  if (listRes.error) {
    // 42P01 / PGRST205: the table is not there yet. That is a deployment step, not a bug the
    // reader can act on by retrying, so say which step.
    const missing = /resource_changes|schema cache|42P01|PGRST205/i.test(
      `${listRes.error.code} ${listRes.error.message}`,
    );
    return (
      <Frame>
        <Card>
          <CardBody>
            <EmptyState
              tone={missing ? 'setup' : 'error'}
              title={missing ? 'History is not switched on for this database yet' : 'Could not load history'}
              description={
                missing
                  ? 'The change-history table has not been created. Apply migration 20261123000001_resource_changes.sql; history is recorded from the next scan after that.'
                  : listRes.error.message
              }
            />
          </CardBody>
        </Card>
      </Frame>
    );
  }

  const rows = (listRes.data ?? []) as unknown as Row[];
  const total = listRes.count ?? rows.length;
  const everTotal = everRes.count ?? 0;
  const scansDone = scansRes.count ?? 0;
  const counts = Object.fromEntries(
    CHANGE_KINDS.map((c, i) => [c, countRes[i]?.count ?? 0]),
  ) as Record<ChangeKind, number>;

  const asOf = at ? await loadAsOf(at) : null;

  const byDay = new Map<string, Row[]>();
  for (const r of rows) {
    const d = dayOf(r.observed_at);
    const list = byDay.get(d);
    if (list) list.push(r);
    else byDay.set(d, [r]);
  }

  const filtered = connFilter !== null || changeFilter !== null;
  const meta =
    everTotal === 0 ? undefined : `${total} change${total === 1 ? '' : 's'} in the last ${days} days`;

  return (
    <Frame meta={meta}>
      <Filters
        connections={connections}
        days={days}
        connFilter={connFilter}
        changeFilter={changeFilter}
        at={at}
        exportQuery={exportQuery}
      />

      {at && <AsOfPanel at={at} result={asOf} />}

      {explain && everTotal > 0 && <ExplainCard days={days} />}

      {connections.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="No systems connected"
              description="History is built from scans. Connect a system and it starts with the second scan."
              action={<LinkButton href={'/estate'}>Go to Connected</LinkButton>}
            />
          </CardBody>
        </Card>
      ) : everTotal === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              tone="pending"
              title="No changes recorded yet"
              description="History is recorded from the next completed scan of each connection. Anything added, removed or reconfigured since the scan before it is listed here with the before and after values. A connection's very first scan is its baseline and records nothing."
              meta={`${scansDone} completed scan${scansDone === 1 ? '' : 's'} before history was switched on`}
            />
          </CardBody>
        </Card>
      ) : (
        <>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: 'var(--space-4)',
            }}
          >
            <StatBox label="Modified" value={counts.modified} sub="configuration differs" tone={counts.modified ? 'warn' : 'neutral'} />
            <StatBox label="Added" value={counts.added} sub="new since a previous scan" />
            <StatBox label="Removed" value={counts.removed} sub="no longer returned" />
            <StatBox label="Returned" value={counts.returned} sub="gone, then back" />
          </div>

          {total === 0 ? (
            <Card>
              <CardBody>
                <EmptyState
                  tone={filtered ? 'filtered' : 'clean'}
                  title={filtered ? 'No changes match these filters' : `No changes in the last ${days} days`}
                  description={
                    filtered
                      ? 'Changes exist, but none for this connection and change type in this window.'
                      : 'Scans ran and found the same configuration each time. Older changes exist; widen the window to see them.'
                  }
                  action={<LinkButton href={'/estate/changes?days=365' as Route}>Show the last year</LinkButton>}
                />
              </CardBody>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>What changed</CardTitle>
                <CardMeta>
                  {rows.length} of {total} shown · newest first · times in UTC
                </CardMeta>
              </CardHeader>
              <CardBody pad={false}>
                <Table density="compact" caption="Configuration changes between scans, newest first">
                  <THead>
                    <TR>
                      <TH width="8%">Seen</TH>
                      <TH width="11%">Change</TH>
                      <TH width="22%">Resource</TH>
                      <TH width="14%">Connection</TH>
                      <TH width="25%">What changed</TH>
                      <TH width="11%">Happened</TH>
                      <TH width="9%">Changed by</TH>
                    </TR>
                  </THead>
                  {[...byDay.entries()].map(([day, list]) => (
                    <TBody key={day}>
                      <TR>
                        <TD colSpan={7}>
                          <span
                            style={{
                              fontSize: 'var(--text-2xs)',
                              fontWeight: 600,
                              letterSpacing: '0.04em',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {day} · {list.length} change{list.length === 1 ? '' : 's'}
                          </span>
                        </TD>
                      </TR>
                      {list.map((r) => (
                        <TR key={r.id}>
                          <TD muted>
                            <time dateTime={r.observed_at} title={stamp(r.observed_at)}>
                              {timeOf(r.observed_at)}
                            </time>
                          </TD>
                          <TD>
                            <ChangeChip change={r.change} />
                          </TD>
                          <TD>
                            <span style={{ display: 'grid', gap: 2, minWidth: 0, padding: 'var(--space-2) 0' }}>
                              {r.resource_id ? (
                                <Link
                                  href={`/estate/inventory/${r.resource_id}` as Route}
                                  style={{
                                    fontFamily: 'var(--font-mono)',
                                    color: 'var(--text-primary)',
                                    overflowWrap: 'anywhere',
                                  }}
                                >
                                  {r.name}
                                </Link>
                              ) : (
                                <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>{r.name}</span>
                              )}
                              <span>
                                <Chip mono>{r.kind}</Chip>
                              </span>
                            </span>
                          </TD>
                          <TD>
                            {r.connections ? (
                              <span style={{ color: 'var(--text-secondary)' }}>
                                {r.connections.name}
                                <span style={{ color: 'var(--text-muted)' }}> · {r.connections.type}</span>
                              </span>
                            ) : (
                              <span style={{ color: 'var(--text-muted)' }}>connection removed</span>
                            )}
                          </TD>
                          <TD>
                            <div style={{ padding: 'var(--space-2) 0', minWidth: 0 }}>
                              <FieldDiff row={r} />
                            </div>
                          </TD>
                          <TD>
                            <ChangeWindow row={r} />
                          </TD>
                          <TD>
                            {r.actor ? (
                              <span style={{ fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere' }}>{r.actor}</span>
                            ) : (
                              <span
                                style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}
                                title="This system's API does not return who made the change."
                              >
                                not exposed
                              </span>
                            )}
                          </TD>
                        </TR>
                      ))}
                    </TBody>
                  ))}
                </Table>
              </CardBody>
              <CardFooter>
                {total > rows.length && (
                  <>
                    Showing the newest {rows.length} of {total}. Narrow by connection or change type, or
                    export the full window.{' '}
                  </>
                )}
                Built from read-only scans: each row is a difference between two scans, and it happened
                somewhere between them. A change made and undone between two scans is not recorded. This
                is not the system&apos;s own audit log.
              </CardFooter>
            </Card>
          )}
        </>
      )}
    </Frame>
  );
}

async function loadAsOf(at: string): Promise<{ ok: true; data: AsOf } | { ok: false; message: string }> {
  const membership = await getOwnMembership();
  const claims = await getClaims();
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return { ok: false, message: 'You are not signed in to a workspace.' };
  return engineGet<AsOf>(`/timeline/as-of?at=${encodeURIComponent(at)}`, {
    tenantId: membership.tenantId,
    actor,
  });
}

const SEVS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function AsOfPanel({ at, result }: { at: string; result: Awaited<ReturnType<typeof loadAsOf>> | null }) {
  if (!result || !result.ok) {
    return (
      <Card accent>
        <CardHeader>
          <CardTitle>As recorded on {at}</CardTitle>
        </CardHeader>
        <CardBody>
          <EmptyState
            tone="error"
            title="The look-back is unavailable"
            description={result?.message ?? 'The engine did not answer.'}
          />
        </CardBody>
      </Card>
    );
  }
  const d = result.data;
  const before = d.first_scan_at !== null && new Date(d.at) < new Date(d.first_scan_at);
  const since = d.changes_since;
  const sinceTotal = since.added + since.removed + since.modified + since.returned;
  const fixed = d.open_total - d.still_open_now;

  return (
    <Card accent>
      <CardHeader>
        <CardTitle>As recorded on {at}</CardTitle>
        <CardMeta>end of day, UTC</CardMeta>
      </CardHeader>
      <CardBody>
        {before || d.first_scan_at === null ? (
          <EmptyState
            tone="pending"
            title="Nothing was recorded yet on this date"
            description={
              d.first_scan_at
                ? `The first completed scan was on ${stamp(d.first_scan_at)} UTC. Pick that date or later.`
                : 'No scan has completed yet.'
            }
          />
        ) : (
          <div style={{ display: 'grid', gap: 'var(--space-5)' }}>
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: 'var(--space-4)',
              }}
            >
              <StatTile
                label="Posture score"
                value={d.posture ? d.posture.score : '—'}
                sub={d.posture ? `snapshot of ${stamp(d.posture.taken_at)}` : 'no snapshot by this date'}
                size="sm"
              />
              <StatTile
                label="Open findings then"
                value={d.open_total}
                tone={d.open_by_severity.critical > 0 ? 'bad' : d.open_by_severity.high > 0 ? 'warn' : 'neutral'}
                sub={`${d.still_open_now} still open now · ${fixed} since closed`}
                size="sm"
              />
              <StatTile label="Resources then" value={d.resources_total} sub="in the inventory" size="sm" />
              <StatTile
                label="Changes since"
                value={sinceTotal}
                sub={`${since.modified} modified · ${since.added} added · ${since.removed} removed`}
                size="sm"
              />
            </div>

            {d.open_total > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)' }}>
                {SEVS.filter((s) => (d.open_by_severity[s] ?? 0) > 0).map((s) => (
                  <SeverityBadge key={s} severity={s} count={d.open_by_severity[s]} />
                ))}
              </div>
            )}

            {d.open_findings.length > 0 && (
              <details>
                <summary style={{ cursor: 'pointer', fontSize: 'var(--text-xs)', fontWeight: 600 }}>
                  The {d.open_findings.length} finding{d.open_findings.length === 1 ? '' : 's'} open on that date
                  {d.open_total > d.open_findings.length ? ` (of ${d.open_total}, worst first)` : ''}
                </summary>
                <div style={{ marginTop: 'var(--space-3)' }}>
                  <Table density="compact" caption={`Findings open on ${at}`}>
                    <THead>
                      <TR>
                        <TH width="12%">Severity</TH>
                        <TH width="40%">Finding</TH>
                        <TH width="22%">Resource</TH>
                        <TH width="14%">Open since</TH>
                        <TH width="12%">Now</TH>
                      </TR>
                    </THead>
                    <TBody>
                      {d.open_findings.map((f) => (
                        <TR key={f.id}>
                          <TD>
                            <SeverityBadge severity={f.severity} />
                          </TD>
                          <TD>
                            <Link href={`/findings/${f.id}` as Route} style={{ color: 'var(--text-primary)' }}>
                              {f.title}
                            </Link>
                          </TD>
                          <TD muted>
                            <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>
                              {f.resource ?? '—'}
                            </span>
                          </TD>
                          <TD muted>{stamp(f.first_seen).slice(0, 10)}</TD>
                          <TD>
                            <Chip tone={f.status_now === 'open' ? 'medium' : 'neutral'}>
                              {f.status_now === 'open' ? 'still open' : f.status_now.replace('_', ' ')}
                            </Chip>
                          </TD>
                        </TR>
                      ))}
                    </TBody>
                  </Table>
                </div>
              </details>
            )}
          </div>
        )}
      </CardBody>
      <CardFooter>{d.caveats[d.caveats.length - 1]}</CardFooter>
    </Card>
  );
}

function StatBox({
  label,
  value,
  sub,
  tone = 'neutral',
}: {
  label: string;
  value: number;
  sub: string;
  tone?: 'neutral' | 'warn';
}) {
  return (
    <Card>
      <CardBody>
        <StatTile label={label} value={value} sub={sub} tone={tone} size="sm" />
      </CardBody>
    </Card>
  );
}

function Frame({ children, meta }: { children: React.ReactNode; meta?: string }) {
  return (
    <PageShell>
      <PageHeader
        title="Estate"
        description="What changed between scans, what the estate looked like on a past date, and a report you can hand to a reviewer."
        meta={meta}
      />
      <EstateTabs />
      {children}
    </PageShell>
  );
}

function Filters({
  connections,
  days,
  connFilter,
  changeFilter,
  at,
  exportQuery,
}: {
  connections: ConnectionRow[];
  days: number;
  connFilter: string | null;
  changeFilter: ChangeKind | null;
  at: string | null;
  exportQuery: string;
}) {
  const active = connFilter !== null || changeFilter !== null || at !== null || days !== 30;
  const today = new Date().toISOString().slice(0, 10);
  return (
    <form method="GET">
      <Toolbar
        end={
          <>
            <Button type="submit" variant="secondary" size="sm">
              Apply
            </Button>
            {active && <LinkButton href={'/estate/changes'}>Clear</LinkButton>}
            <Link
              href={`/estate/changes?days=${days}&explain=1` as Route}
              className="vs-actionbtn"
              title="Have AI read the recorded changes and say in plain words what they mean. It can only cite changes listed here."
            >
              Explain with AI
            </Link>
            <a
              href={`/api/reports/changes-csv${exportQuery}`}
              className="vs-actionbtn"
              title={`Every change in the last ${days} days, one row per changed field`}
            >
              Report · CSV
            </a>
            <a
              href={`/api/reports/changes-md${exportQuery}`}
              className="vs-actionbtn"
              title={`Access and change report for the last ${days} days: changes, findings opened, status changes`}
            >
              Report · for a reviewer
            </a>
          </>
        }
      >
        <ToolbarField label="Window" htmlFor="filter-days">
          <select id="filter-days" name="days" defaultValue={String(days)} style={controlStyle}>
            {WINDOWS.map((w) => (
              <option key={w} value={w}>
                {w === 365 ? 'Last year' : `Last ${w} days`}
              </option>
            ))}
          </select>
        </ToolbarField>
        <ToolbarField label="Connection" htmlFor="filter-connection">
          <select id="filter-connection" name="connection" defaultValue={connFilter ?? ''} style={controlStyle}>
            <option value="">All</option>
            {connections.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.type})
              </option>
            ))}
          </select>
        </ToolbarField>
        <ToolbarField label="Change" htmlFor="filter-change">
          <select id="filter-change" name="change" defaultValue={changeFilter ?? ''} style={controlStyle}>
            <option value="">All</option>
            {CHANGE_KINDS.map((c) => (
              <option key={c} value={c}>
                {changeLabel(c)}
              </option>
            ))}
          </select>
        </ToolbarField>
        <ToolbarField label="Look back to" htmlFor="filter-at">
          <input
            id="filter-at"
            type="date"
            name="at"
            defaultValue={at ?? ''}
            max={today}
            style={{ ...controlStyle, minWidth: 140 }}
          />
        </ToolbarField>
      </Toolbar>
    </form>
  );
}

// Same control and link-button treatment as the Inventory tab: the border is the control's only
// boundary, so it uses the 3:1 interactive border token.
const controlStyle: React.CSSProperties = {
  height: 'var(--row-compact)',
  minWidth: 150,
  padding: '0 var(--space-2)',
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border-interactive)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
};

function LinkButton({ href, children }: { href: Route; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        height: 'var(--row-compact)',
        padding: '0 var(--space-3)',
        borderRadius: 'var(--radius-md)',
        border: '1px solid var(--border-interactive)',
        background: 'var(--surface)',
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        textDecoration: 'none',
      }}
    >
      {children}
    </Link>
  );
}
