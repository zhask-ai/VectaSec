import Link from 'next/link';

import { canEdit, getOwnMembership } from '@/lib/role';
import { createClient } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Severity } from '@/lib/types';
import { AutoRefresh } from '@/components/AutoRefresh';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { AddConnection } from './add-connection';
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
 */

/** Bound on the per-connection open-finding sample used only to pick the worst severity badge; the
 * open COUNT beside it is count:'exact' and is never truncated, so the number is always right even
 * when the sample is capped. */
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

/** The connector types the engine registers today (services/engine/src/vectasec/connect/). */
const CONNECTOR_TYPES = ['kafka', 'kong', 'rabbitmq', 'mcp'];

export const metadata = { title: 'Connections · VectaSec' };

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

export default async function ConnectionsPage() {
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
      <Page>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load connections" description={connectionsRes.error.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const connections = (connectionsRes.data ?? []) as unknown as ConnectionRow[];

  if (connections.length === 0) return <Page><SetupState editable={editable} /></Page>;

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
        // open count even though the row sample is capped at LIST_LIMIT; the sample only feeds the
        // worst-severity badge.
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
      <Page>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load connection health" description={message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const rows = perConnection.map(({ c, scanRes, resTotalRes, resStaleRes, openRes }) => {
    const scan = (scanRes.data as ScanRow | null) ?? null;
    const sevs = ((openRes.data ?? []) as unknown as { severity: Severity }[]).map((f) => f.severity);
    let worst: Severity | null = null;
    for (const s of sevs) if (worst === null || SEVERITY_RANK[s] < SEVERITY_RANK[worst]) worst = s;
    return {
      ...c,
      scan,
      counts: { total: resTotalRes.count ?? 0, stale: resStaleRes.count ?? 0 },
      open: openRes.count ?? 0,
      worst,
    };
  });

  const broken = rows.filter((r) => r.scan?.status === 'error').length;
  const unscanned = rows.filter((r) => !r.last_scanned_at).length;
  const scanning = rows.filter((r) => r.scan?.status === 'queued' || r.scan?.status === 'running').length;

  return (
    <Page>
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

      <Card>
        <CardHeader>
          <CardTitle>Connected systems</CardTitle>
          <CardMeta>
            {rows.length} connection{rows.length === 1 ? '' : 's'}
            {unscanned > 0 && ` · ${unscanned} never scanned`}
            {scanning > 0 && ` · ${scanning} scanning`}
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          <Table density="default" caption="Connected systems and their collection status">
            <THead>
              <TR>
                <TH width="18%">Name</TH>
                <TH width="8%">Type</TH>
                <TH width="12%">Status</TH>
                <TH width="13%">Last scan</TH>
                <TH width="10%" numeric>
                  Resources
                </TH>
                <TH width="13%">Open findings</TH>
                <TH width="26%">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => (
                <TR key={r.id}>
                  <TD>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{r.name}</span>
                    {/* Mode matters when it is NOT the default path: a collector connection
                        names its collector; cloud is implied by saying nothing. */}
                    {r.collectors && (
                      <span
                        style={{
                          display: 'block',
                          fontSize: 'var(--text-2xs)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        via {r.collectors.name} ({r.collectors.status})
                      </span>
                    )}
                    {r.mode === 'collector' && !r.collectors && (
                      <span
                        style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}
                      >
                        collector mode · no collector enrolled
                      </span>
                    )}
                  </TD>
                  <TD mono>{r.type}</TD>
                  <TD>
                    <StatusChip
                      status={r.scan?.status === 'error' ? 'error' : r.status}
                      detail={r.scan?.status === 'error' ? 'last scan failed' : undefined}
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
                        say nothing rather than invent a default. */}
                    {r.scan_interval_minutes != null && (
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
                    )}
                    {/* Editors change the cadence right where it is displayed; viewers see
                        the display alone. */}
                    {editable && (
                      <CadenceSelect connectionId={r.id} current={r.scan_interval_minutes} />
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
                    {r.worst ? (
                      <SeverityBadge severity={r.worst} count={r.open} />
                    ) : r.last_scanned_at ? (
                      <span style={{ color: 'var(--text-muted)' }}>none</span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>not scanned</span>
                    )}
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
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                        view only
                      </span>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </CardBody>
      </Card>

      {editable && <ConnectHelp />}
    </Page>
  );
}

function Page({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
        Connections
      </h1>
      {children}
    </div>
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
            meta={`connectors available: ${CONNECTOR_TYPES.join(', ')}`}
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
          meta={`connectors available: ${CONNECTOR_TYPES.join(', ')}`}
        />
        <div style={{ maxWidth: 640, margin: '0 auto', display: 'grid', gap: 'var(--space-4)' }}>
          <AddConnection />
          <details>
            <summary
              style={{ cursor: 'pointer', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}
            >
              Prefer the CLI?
            </summary>
            <div style={{ marginTop: 'var(--space-2)' }}>
              <ConnectSnippet />
            </div>
          </details>
        </div>
      </CardBody>
    </Card>
  );
}

function ConnectHelp() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect another system</CardTitle>
        <CardMeta>read-only · scans run from the worker, never the browser</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <AddConnection />
          <details>
            <summary
              style={{ cursor: 'pointer', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}
            >
              Prefer the CLI?
            </summary>
            <div style={{ marginTop: 'var(--space-2)' }}>
              <ConnectSnippet />
            </div>
          </details>
        </div>
      </CardBody>
    </Card>
  );
}

/** The CLI path — same result as the form, from wherever the target is reachable. The form
 * submits through the engine API with a verified actor (actions.ts); this snippet exists for
 * operators whose broker is only reachable from a bastion the browser isn't on. */
function ConnectSnippet() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        Run the engine CLI where the system is reachable. It reads; it never writes to the target.
      </p>
      <pre
        style={{
          margin: 0,
          padding: 'var(--space-3)',
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-2xs)',
          lineHeight: 'var(--leading-sm)',
          color: 'var(--text-primary)',
          overflowX: 'auto',
        }}
      >
        <span style={{ color: 'var(--text-muted)' }}># save a connection, then scan it by name</span>
        {'\n'}vectasec connections add --type kafka --name prod-kafka --bootstrap broker-1:9092
        {'\n'}vectasec scan --connection prod-kafka
        {'\n\n'}
        <span style={{ color: 'var(--text-muted)' }}># or ad-hoc (saves the connection as a side effect)</span>
        {'\n'}vectasec scan --type rabbitmq --url http://localhost:15672 --username svc --password ***
        {'\n'}vectasec scan --type kong --url http://localhost:8001
        {'\n'}vectasec scan --type mcp --url https://mcp.example.com
      </pre>
      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec connections</code> lists the estate;{' '}
        <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec scans</code> shows history;{' '}
        <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec doctor</code> checks wiring. Scans
        queued here need <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec worker</code>{' '}
        running to execute.
      </p>
    </div>
  );
}

/** Connection status. `status` is free text in the schema, so unknown values must still render
 * — mapping to a fixed union would turn an unrecognised state into a blank cell, and a blank
 * cell reads as "fine". */
function StatusChip({ status, detail }: { status: string; detail?: string }) {
  const tone: 'bad' | 'warn' | 'ok' | 'neutral' =
    status === 'error' || status === 'offline'
      ? 'bad'
      : status === 'degraded' || status === 'pending' || status === 'queued'
        ? 'warn'
        : status === 'active' || status === 'done'
          ? 'ok'
          : 'neutral';

  const color = {
    bad: 'var(--sev-critical-fg)',
    warn: 'var(--sev-medium-fg)',
    ok: 'var(--sev-low-fg)',
    neutral: 'var(--text-secondary)',
  }[tone];

  return (
    <span style={{ display: 'inline-flex', flexDirection: 'column', gap: '1px' }}>
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 'var(--space-1)',
          color,
          fontWeight: 600,
          fontSize: 'var(--text-2xs)',
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
        }}
      >
        {/* Shape carries the state alongside the word, so it survives greyscale. */}
        <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
          {tone === 'bad' ? (
            <path d="M2.5 0h3L8 2.5v3L5.5 8h-3L0 5.5v-3z" fill={color} />
          ) : tone === 'warn' ? (
            <path d="M4 0L8 7H0z" fill={color} />
          ) : (
            <circle cx="4" cy="4" r="3" fill="none" stroke={color} strokeWidth="1.5" />
          )}
        </svg>
        {status}
      </span>
      {detail && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{detail}</span>}
    </span>
  );
}
