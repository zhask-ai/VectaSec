import Link from 'next/link';
import type { Route } from 'next';

import { canEdit, getOwnMembership } from '@/lib/role';
import { createClient } from '@/lib/supabase/server';
import { SEVERITIES, SEVERITY_RANK, type Severity } from '@/lib/types';
import { AutoRefresh } from '@/components/AutoRefresh';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { IconAlertTriangle, IconFindings, IconForType, IconPlug, IconRadar } from '@/components/ui/icons';
import { Page } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Toolbar } from '@/components/ui/toolbar';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { RouteTabs } from '@/components/ui/route-tabs';
import { CONNECTORS } from './connector-fields';
import { ConnectDrawer } from './connect-drawer';
import { CadenceSelect } from './cadence-select';
import { RowActions } from './row-actions';

/* Connected systems — the coverage view AND the connect-and-scan surface. "What are we NOT
 * seeing" is the question this page exists to answer, so a broken connection has to be
 * louder than a healthy one; connecting something new and scanning it happens here too,
 * through the engine API (actions.ts) — the browser itself still cannot write a row.
 *
 * `connections.config` is deliberately never selected: it carries credential references, and a
 * column that is never fetched cannot be leaked by a later refactor that passes a row to a
 * client component. RLS scopes every read; no query filters by tenant_id on purpose.
 *
 * COUNTS. The per-connection resource and open-finding tallies used to come from two tenant-wide
 * unbounded fetches (every resource, every open finding) reduced in JS. PostgREST caps an
 * unbounded response at Max Rows (1000 hosted), so past the cap every connection's numbers were
 * silently low — the most dangerous kind of wrong on a page whose whole job is coverage honesty.
 * Connections are FEW (a human connects each one), so the fix is per-connection queries: exact
 * head-counts for resources, and a per-connection scoped read for open findings with an exact
 * count. No count crosses the wire unbounded, and no SECURITY DEFINER RPC/view (which would run as
 * postgres/BYPASSRLS and leak every tenant).
 *
 * The design system (PageHeader/StatTile/Toolbar/StatusPill/SeverityBadge) frames it; every
 * mutation still flows through the same Server Actions (ConnectDrawer / RowActions / CadenceSelect),
 * role-gated by `editable` in the UI and re-checked server-side.
 */

/** Bound on the per-connection open-finding sample. The per-severity mini-summary is built from
 * this sample (exact while a connection has ≤ LIST_LIMIT open findings, which is the norm); the
 * open COUNT beside it is count:'exact' and is never truncated, so the total is always right. */
const LIST_LIMIT = 500;

type ConnectionRow = {
  id: string;
  type: string;
  name: string;
  mode: string;
  status: string;
  last_scanned_at: string | null;
  created_at: string;
  scan_interval_minutes: number | null;
  collector_id: string | null;
  collectors: { id: string; name: string; status: string; last_heartbeat: string | null } | null;
};

type ScanRow = { id: string; status: string; started_at: string; finished_at: string | null };

/* The connectable catalogue is connector-fields.ts itself — derived, never restated. A
 * hardcoded list here said "5 connector types available" long after the registry grew to 37,
 * under-selling coverage by 32 systems on the page whose entire job is coverage honesty. */
const CONNECTOR_COUNT = CONNECTORS.length;
/** A few names for the empty state, so "connect something" has concrete examples. */
const CONNECTOR_EXAMPLES = ['kafka', 'rabbitmq', 'kong', 'redis', 'mcp'];

export const metadata = { title: 'Connected systems · VectaSec' };

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

function absolute(iso: string): string {
  return new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

/** "every 30m / every 6h / every 2d" — the recurring-scan cadence, human units. */
function cadence(minutes: number): string {
  if (minutes % 1440 === 0) return `every ${minutes / 1440}d`;
  if (minutes % 60 === 0) return `every ${minutes / 60}h`;
  return `every ${minutes}m`;
}

/** Connection status → operational tone. `status` is free text in the schema, so unknown values
 * must still render (mapping to a fixed union would turn an unrecognised state into a blank cell,
 * and a blank cell reads as "fine"). */
function statusTone(status: string): StatusTone {
  if (status === 'error' || status === 'offline') return 'bad';
  if (status === 'degraded' || status === 'pending' || status === 'queued' || status === 'running') return 'warn';
  if (status === 'active' || status === 'done') return 'ok';
  return 'neutral';
}

type DisplayRow = ConnectionRow & {
  scan: ScanRow | null;
  counts: { total: number; stale: number };
  open: number;
  worst: Severity | null;
  sevCounts: Partial<Record<Severity, number>>;
  sampleSize: number;
};

/** A connection needing an operator's eyes: its last scan failed, it has never been scanned, or its
 * status is anything other than healthy. Drives the "Needs attention" filter and tile. */
function needsAttention(r: DisplayRow): boolean {
  return (
    r.scan?.status === 'error' ||
    !r.last_scanned_at ||
    r.status === 'error' ||
    r.status === 'offline' ||
    r.status === 'degraded' ||
    r.status === 'pending'
  );
}

export default async function ConnectionsPage({
  searchParams,
}: {
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const sp = await searchParams;
  const statusFilter = typeof sp.status === 'string' ? sp.status : undefined;

  const supabase = await createClient();

  // Role gates the mutation UI only — every read below is RLS-scoped regardless. Viewers see
  // the same coverage truth; they just get no buttons (and the Server Actions re-check the
  // role anyway, because a hidden button is not an authorization boundary).
  const membership = await getOwnMembership();
  const editable = canEdit(membership?.role);

  const connectionsRes = await supabase
    .from('connections')
    .select(
      'id, type, name, mode, status, last_scanned_at, created_at, scan_interval_minutes, collector_id, collectors(id, name, status, last_heartbeat)',
    )
    .order('name');

  if (connectionsRes.error) {
    return (
      <Shell editable={editable}>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load connections" description={connectionsRes.error.message} />
          </CardBody>
        </Card>
      </Shell>
    );
  }

  const connections = (connectionsRes.data ?? []) as unknown as ConnectionRow[];

  if (connections.length === 0) {
    return (
      <Shell editable={editable}>
        <SetupState editable={editable} />
      </Shell>
    );
  }

  // Everything per-connection in one pass. N is the number of systems a human connected, so it
  // stays small — small enough that N bounded queries beat two tenant-wide unbounded fetches that
  // capped at Max Rows. Each read below is either an exact head-count or scoped to ONE connection.
  //
  // The latest-scan read stays per-connection for the reason it always was: PostgREST has no
  // "latest per group", and a single ordered+limited fetch would starve a rarely-scanned
  // connection of its row behind a noisy one's history — a false "never scanned" is worse than an
  // extra round trip.
  const perConnection = await Promise.all(
    connections.map(async (c) => {
      const [scanRes, resTotalRes, resStaleRes, openRes] = await Promise.all([
        supabase
          .from('scans')
          .select('id, status, started_at, finished_at')
          .eq('connection_id', c.id)
          .order('started_at', { ascending: false })
          .limit(1)
          .maybeSingle(),
        supabase.from('resources').select('id', { count: 'exact', head: true }).eq('connection_id', c.id),
        supabase
          .from('resources')
          .select('id', { count: 'exact', head: true })
          .eq('connection_id', c.id)
          .eq('stale', true),
        // Open findings for THIS connection. findings carry no connection_id — they hang off a
        // resource — so the inner join reaches connection_id and drops findings whose resource was
        // deleted (an orphan cannot be attributed to a connection). count:'exact' gives the true
        // open count even though the row sample is capped at LIST_LIMIT; the sample feeds the
        // severity mini-summary.
        supabase
          .from('findings')
          .select('severity, resources!inner(connection_id)', { count: 'exact' })
          .eq('status', 'open')
          .eq('resources.connection_id', c.id)
          .limit(LIST_LIMIT),
      ]);
      return { c, scanRes, resTotalRes, resStaleRes, openRes };
    }),
  );

  // A failed read is not zero coverage — surface it rather than rendering plausible-but-wrong
  // zeros on the one page whose job is to say what is NOT being seen.
  const failed = perConnection.find((p) => p.resTotalRes.error ?? p.resStaleRes.error ?? p.openRes.error);
  if (failed) {
    const message = (failed.resTotalRes.error ?? failed.resStaleRes.error ?? failed.openRes.error)!.message;
    return (
      <Shell editable={editable}>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load connection health" description={message} />
          </CardBody>
        </Card>
      </Shell>
    );
  }

  const rows: DisplayRow[] = perConnection.map(({ c, scanRes, resTotalRes, resStaleRes, openRes }) => {
    const scan = (scanRes.data as ScanRow | null) ?? null;
    const sevs = ((openRes.data ?? []) as unknown as { severity: Severity }[]).map((f) => f.severity);
    let worst: Severity | null = null;
    const sevCounts: Partial<Record<Severity, number>> = {};
    for (const s of sevs) {
      sevCounts[s] = (sevCounts[s] ?? 0) + 1;
      if (worst === null || SEVERITY_RANK[s] < SEVERITY_RANK[worst]) worst = s;
    }
    return {
      ...c,
      scan,
      counts: { total: resTotalRes.count ?? 0, stale: resStaleRes.count ?? 0 },
      open: openRes.count ?? 0,
      worst,
      sevCounts,
      sampleSize: sevs.length,
    };
  });

  const broken = rows.filter((r) => r.scan?.status === 'error').length;
  const unscanned = rows.filter((r) => !r.last_scanned_at).length;
  const scanning = rows.filter((r) => r.scan?.status === 'queued' || r.scan?.status === 'running').length;
  const attention = rows.filter(needsAttention).length;
  const openTotal = rows.reduce((s, r) => s + r.open, 0);

  const visible =
    statusFilter === 'attention'
      ? rows.filter(needsAttention)
      : statusFilter === 'healthy'
        ? rows.filter((r) => !needsAttention(r))
        : rows;

  const filters: { key: string; label: string; href: Route; count: number }[] = [
    { key: 'all', label: 'All', href: '/connections' as Route, count: rows.length },
    { key: 'attention', label: 'Needs attention', href: '/connections?status=attention' as Route, count: attention },
    { key: 'healthy', label: 'Healthy', href: '/connections?status=healthy' as Route, count: rows.length - attention },
  ];
  const activeFilter = statusFilter === 'attention' || statusFilter === 'healthy' ? statusFilter : 'all';

  return (
    <Shell editable={editable}>
      {/* Poll only while something is actually in flight; static again the render after. */}
      <AutoRefresh active={scanning > 0} />

      {/* Collection health is stated before the inventory, because every count below is only as
          true as the scan that produced it. A failing connection reporting "0 open findings" is
          the most dangerous cell on this page. */}
      {broken > 0 && (
        <Card style={{ borderColor: 'var(--sev-high-fg)' }}>
          <CardBody>
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
              <strong>
                {broken} connection{broken === 1 ? '' : 's'} failed{' '}
                {broken === 1 ? 'its' : 'their'} most recent scan.
              </strong>{' '}
              Finding counts for {broken === 1 ? 'it' : 'them'} are from the last scan that
              succeeded and may be out of date. A connection that cannot collect reports no
              findings — which is not the same as having none.
            </p>
          </CardBody>
        </Card>
      )}

      {/* Estate summary. Computed from the whole estate, not the current filter. */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)' }}>
        <Card hover>
          <CardBody>
            <StatTile label="Connections" value={rows.length} icon={<IconPlug size={13} />} sub={`${CONNECTOR_COUNT} connectors available`} />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Needs attention"
              value={attention}
              tone={attention > 0 ? 'warn' : 'neutral'}
              icon={<IconAlertTriangle size={13} />}
              sub={broken > 0 ? `${broken} failed last scan` : unscanned > 0 ? `${unscanned} never scanned` : 'all healthy'}
            />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Open findings"
              value={openTotal}
              tone={openTotal > 0 ? 'bad' : 'neutral'}
              icon={<IconFindings size={13} />}
              sub="attributed to a connection"
            />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Scanning"
              value={scanning}
              tone={scanning > 0 ? 'warn' : 'neutral'}
              icon={<IconRadar size={13} />}
              sub={scanning > 0 ? 'live — refreshing' : 'nothing in flight'}
            />
          </CardBody>
        </Card>
      </div>

      {/* Filter bar — one row above the table, state in the URL so a view is shareable. */}
      <Toolbar
        end={
          <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
            showing {visible.length} of {rows.length}
          </span>
        }
      >
        <span
          style={{
            fontSize: 'var(--text-2xs)',
            fontWeight: 600,
            letterSpacing: '0.04em',
            textTransform: 'uppercase',
            color: 'var(--text-secondary)',
          }}
        >
          Status
        </span>
        {filters.map((f) => {
          const active = f.key === activeFilter;
          return (
            <Link
              key={f.key}
              href={f.href}
              className="vs-filterpill"
              data-active={active || undefined}
              aria-current={active ? 'true' : undefined}
            >
              {f.label}
              <span data-numeric style={{ color: 'var(--text-muted)' }}>
                {f.count}
              </span>
            </Link>
          );
        })}
      </Toolbar>

      <Card>
        <CardHeader>
          <CardTitle>Connected systems</CardTitle>
          <CardMeta>
            {rows.length} connection{rows.length === 1 ? '' : 's'}
            {unscanned > 0 && ` · ${unscanned} never scanned`}
            {scanning > 0 && ` · ${scanning} scanning`}
            {activeFilter !== 'all' && ` · filtered to ${activeFilter}`}
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {visible.length === 0 ? (
            <EmptyState
              tone="filtered"
              title="No connections match this filter"
              description={
                activeFilter === 'attention'
                  ? 'Nothing needs attention — every connection has scanned cleanly.'
                  : 'Every connection currently needs attention.'
              }
              action={
                <Link href={'/connections' as Route} style={clearFilterStyle}>
                  Clear filter
                </Link>
              }
            />
          ) : (
            <Table density="relaxed" caption="Connected systems and their collection status">
              <THead>
                <TR>
                  <TH width="24%">System</TH>
                  <TH width="12%">Status</TH>
                  <TH width="17%">Last scan</TH>
                  <TH width="8%" numeric>
                    Resources
                  </TH>
                  <TH width="19%">Open findings</TH>
                  <TH width="20%">Actions</TH>
                </TR>
              </THead>
              <TBody>
                {visible.map((r) => (
                  <TR key={r.id}>
                    <TD>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0, padding: 'var(--space-2) 0' }}>
                        <span aria-hidden="true" className="vs-icontile">
                          <IconForType type={r.type} />
                        </span>
                        <span style={{ display: 'grid', gap: 1, minWidth: 0 }}>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {r.name}
                          </span>
                          <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                            {r.type}
                            {/* Mode matters when it is NOT the default path: a collector
                                connection names its collector; cloud is implied by silence. */}
                            {r.collectors && (
                              <> · via {r.collectors.name} ({r.collectors.status})</>
                            )}
                          </span>
                          {r.mode === 'collector' && !r.collectors && (
                            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
                              collector mode · no collector enrolled
                            </span>
                          )}
                        </span>
                      </span>
                    </TD>
                    <TD>
                      <ConnStatus
                        status={r.scan?.status === 'error' ? 'error' : r.status}
                        detail={r.scan?.status === 'error' ? 'last scan failed' : undefined}
                        pulse={r.scan?.status === 'queued' || r.scan?.status === 'running'}
                      />
                    </TD>
                    <TD>
                      {r.last_scanned_at ? (
                        <span title={absolute(r.last_scanned_at)}>{relative(r.last_scanned_at)}</span>
                      ) : (
                        // Never-scanned is not "0 findings", and the two must not read alike.
                        <span style={{ color: 'var(--sev-medium-fg)', fontWeight: 600 }}>never</span>
                      )}
                      {r.scan && r.scan.status !== 'done' && (
                        <span
                          style={{
                            display: 'block',
                            fontSize: 'var(--text-2xs)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          scan {r.scan.status} · {relative(r.scan.started_at)}
                        </span>
                      )}
                      {/* Recurring cadence (connections.scan_interval_minutes, consumed by the
                          DB scheduler queue_due_scans()). Absence means point-in-time only —
                          say nothing rather than invent a default. Editors get the chip-select
                          (which displays AND changes it); viewers get the static line alone. */}
                      {editable ? (
                        <CadenceSelect connectionId={r.id} current={r.scan_interval_minutes} />
                      ) : (
                        r.scan_interval_minutes != null && (
                          <span
                            style={{
                              display: 'block',
                              fontSize: 'var(--text-2xs)',
                              color: 'var(--text-secondary)',
                            }}
                            title="Rescanned automatically on this cadence"
                          >
                            rescans {cadence(r.scan_interval_minutes)}
                          </span>
                        )
                      )}
                    </TD>
                    <TD numeric>
                      {r.counts.total === 0 ? (
                        <span style={{ color: 'var(--text-muted)' }}>0</span>
                      ) : (
                        <Link href={`/assets?connection=${r.id}`} style={{ color: 'var(--text-primary)' }}>
                          {r.counts.total}
                          {r.counts.stale > 0 && (
                            <span style={{ color: 'var(--sev-medium-fg)' }}> ({r.counts.stale} stale)</span>
                          )}
                        </Link>
                      )}
                    </TD>
                    <TD>
                      <FindingSummary row={r} />
                    </TD>
                    <TD>
                      {editable ? (
                        <RowActions
                          connectionId={r.id}
                          name={r.name}
                          scanActive={r.scan?.status === 'queued' || r.scan?.status === 'running'}
                        />
                      ) : (
                        // Absent, not disabled: a row of dead buttons begs to be clicked and
                        // answered with a refusal. Say why there is nothing here instead.
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>view only</span>
                      )}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </Shell>
  );
}

/** Route frame: the single <h1> via PageHeader, the section tab strip, then the page body grid.
 * Every branch (error, empty, populated) renders through here so the header never disappears
 * under a failure — and so the connect action is reachable at the TOP of every one of them,
 * including the error state, where "connect a different system" may be the actual fix.
 *
 * Connected and Coverage are two views of one subject, so they are tabs of a single "Systems"
 * section rather than two sidebar entries competing to mean the same thing. */
function Shell({ children, editable }: { children: React.ReactNode; editable?: boolean }) {
  return (
    <Page>
      <PageHeader
        title="Systems"
        description="The systems VectaSec is collecting from, and how healthy that collection is. A broken connection is louder than a clean one — it is the coverage gap."
        meta="read-only"
        actions={editable ? <ConnectDrawer /> : undefined}
      />
      {/* No counts in the tabs. The connectable list here (connector-fields.ts, a mirror of the
          registry) and the engine's live registry on Coverage can legitimately differ by a
          connector between regenerations — and two adjacent numbers that disagree read as a bug
          even when both are honest. Each page states its own count, from its own source. */}
      <RouteTabs
        aria-label="Systems views"
        tabs={[
          { href: '/connections' as Route, label: 'Connected' },
          { href: '/systems' as Route, label: 'Coverage' },
        ]}
      />
      {children}
    </Page>
  );
}

/** The per-connection severity mini-summary: the worst level as the one badge (one badge, one
 * decision), an exact open total, and a compact stacked severity bar showing the mix. The old
 * row of five ×N badges wrapped to three lines on busy connections and made the whole table
 * ragged; the bar says the same thing in six pixels of height. Colour is never alone — the
 * badge + counts text carry the levels, and the full mix rides the tooltip. */
function FindingSummary({ row }: { row: DisplayRow }) {
  if (!row.worst) {
    return row.last_scanned_at ? (
      <span style={{ color: 'var(--text-muted)' }}>none</span>
    ) : (
      <span style={{ color: 'var(--text-muted)' }}>not scanned</span>
    );
  }
  const truncated = row.open > row.sampleSize;
  const mix = SEVERITIES.filter((s) => (row.sevCounts[s] ?? 0) > 0);
  const mixLabel = mix.map((s) => `${row.sevCounts[s]} ${s}`).join(' · ');
  return (
    <div style={{ display: 'grid', gap: 4, maxWidth: 210 }} title={mixLabel}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
        <SeverityBadge variant="inline" severity={row.worst} />
        <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
          {row.open} open{truncated ? ` · top ${LIST_LIMIT} sampled` : ''}
        </span>
      </div>
      <div
        aria-hidden="true"
        style={{ display: 'flex', height: 5, borderRadius: 'var(--radius-full)', overflow: 'hidden', background: 'var(--grid)' }}
      >
        {mix.map((s) => (
          <span
            key={s}
            style={{
              width: `${(100 * (row.sevCounts[s] ?? 0)) / row.sampleSize}%`,
              background: `var(--sev-${s}-solid)`,
              minWidth: 3,
            }}
          />
        ))}
      </div>
      <span className="vs-visually-hidden">{mixLabel}</span>
    </div>
  );
}

/** Connection status via the shared StatusPill (shape + word + tone), with the scan-failure
 * detail on a second line so a stale count is never read as fresh. */
function ConnStatus({ status, detail, pulse }: { status: string; detail?: string; pulse?: boolean }) {
  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: 2, alignItems: 'flex-start' }}>
      <StatusPill tone={statusTone(status)} label={status} pulse={pulse} />
      {detail && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{detail}</span>}
    </span>
  );
}

function SetupState({ editable }: { editable: boolean }) {
  if (!editable) {
    return (
      <Card>
        <CardBody>
          <EmptyState
            tone="setup"
            title="No systems connected"
            description="VectaSec scans the integration layer — the brokers, gateways and MCP servers between your services. Connecting one needs an editor or admin role; ask an admin to connect a system or to change your role."
            meta={`${CONNECTOR_COUNT} connectors available — ${CONNECTOR_EXAMPLES.join(', ')} and more`}
          />
        </CardBody>
      </Card>
    );
  }

  return (
    <Card>
      <CardBody>
        <EmptyState
          tone="setup"
          title="No systems connected"
          description="VectaSec scans the integration layer — the brokers, gateways and MCP servers between your services. Connect one to start; the first scan runs immediately."
          meta={`${CONNECTOR_COUNT} connectors available — ${CONNECTOR_EXAMPLES.join(', ')} and more`}
        />
        {/* No connect form here: the action lives in the page header, where it is reachable
            without scrolling past whatever this page grows into. */}
      </CardBody>
    </Card>
  );
}

const clearFilterStyle: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  height: 'var(--row-compact)',
  padding: '0 var(--space-3)',
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  fontWeight: 500,
  textDecoration: 'none',
};
