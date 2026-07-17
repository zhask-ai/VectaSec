import { createClient } from '@/lib/supabase/server';
import { SEVERITIES, SEVERITY_RANK, type Severity, type SeverityCounts } from '@/lib/types';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';

/* Overview — minimal, and deliberately so: it exists to prove the Supabase → RSC → RLS path
 * works end to end. The real landing view (posture score, ranked "do this now" queue grouped
 * by rule, coverage, delta since last scan, compliance strip) belongs to another agent.
 *
 * Reads cookies, so this route is dynamic and is never prerendered at build time.
 */

type Overview =
  | { state: 'ok'; counts: SeverityCounts; total: number; scannedAt: string | null; connections: number }
  | { state: 'no-connections' }
  | { state: 'never-scanned'; connections: number }
  | { state: 'error'; message: string };

async function getOverview(): Promise<Overview> {
  const supabase = await createClient();

  // RLS scopes both reads to the caller's tenant; there is no tenant filter in the query
  // because there must not be one — a WHERE clause is a suggestion, a policy is a boundary.
  // (`findings_facets` is a security_invoker view, so the same policy applies to it.)
  //
  // Counts come from the aggregate view, not from `select('severity')` over raw findings. An
  // unbounded PostgREST select is truncated at Max Rows (1000 on hosted Supabase), and this
  // page derived BOTH the total and every per-severity count from that one array — so past the
  // cap they stayed consistent with each other and were silently, uncontradictably low. A
  // security console under-reporting "8 critical open" is the worst instance of that bug in the
  // product: nothing on screen tells you the number is short. The view groups by
  // (rule, severity, status), which is tens of rows however many findings exist.
  const [connectionsRes, findingsRes] = await Promise.all([
    supabase.from('connections').select('id, last_scanned_at'),
    supabase.from('findings_facets').select('severity, n').eq('status', 'open'),
  ]);

  if (connectionsRes.error) return { state: 'error', message: connectionsRes.error.message };
  if (findingsRes.error) return { state: 'error', message: findingsRes.error.message };

  const connections = connectionsRes.data ?? [];
  if (connections.length === 0) return { state: 'no-connections' };

  const scannedAt = connections
    .map((c) => c.last_scanned_at)
    .filter((d): d is string => Boolean(d))
    .sort()
    .at(-1) ?? null;

  if (!scannedAt) return { state: 'never-scanned', connections: connections.length };

  const buckets = (findingsRes.data ?? []) as { severity: string; n: number }[];
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
  let total = 0;
  for (const row of buckets) {
    const sev = row.severity as Severity;
    // total counts every open finding, including one whose severity the UI does not know —
    // an unrecognised severity must not quietly vanish from the headline number.
    total += row.n;
    if (sev in counts) counts[sev] += row.n;
  }

  return {
    state: 'ok',
    counts,
    total,
    scannedAt,
    connections: connections.length,
  };
}

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export default async function OverviewPage() {
  const overview = await getOverview();

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 960 }}>
      <h1
        style={{
          margin: 0,
          fontSize: 'var(--text-xl)',
          lineHeight: 'var(--leading-xl)',
          fontWeight: 600,
        }}
      >
        Overview
      </h1>

      <Card>
        <CardHeader>
          <CardTitle>Open findings by severity</CardTitle>
          {overview.state === 'ok' && overview.scannedAt && (
            // Stale-while-revalidate labelling beats a full-page spinner, and an unlabelled
            // number is an untrustworthy number.
            <CardMeta>
              {overview.connections} connection{overview.connections === 1 ? '' : 's'} · scanned{' '}
              {relative(overview.scannedAt)}
            </CardMeta>
          )}
        </CardHeader>

        <CardBody>
          {overview.state === 'error' && (
            <EmptyState
              tone="error"
              title="Could not load findings"
              description={overview.message}
            />
          )}

          {overview.state === 'no-connections' && (
            <EmptyState
              tone="setup"
              title="Connect your first system"
              description="VectaSec scans the integration layer — Kafka, Kong, RabbitMQ, MCP. Nothing is connected yet."
            />
          )}

          {overview.state === 'never-scanned' && (
            <EmptyState
              tone="pending"
              title="Connected. First scan pending."
              description="Collection has not run yet. Findings appear here once the first scan completes."
              meta={`${overview.connections} connection${overview.connections === 1 ? '' : 's'} configured`}
            />
          )}

          {/* "You are secure" and "your filter is too narrow" must never look alike, so the
              zero state carries its provenance: what was scanned, and when. */}
          {overview.state === 'ok' && overview.total === 0 && (
            <EmptyState
              tone="clean"
              title="No open findings"
              description="Every rule passed on the last scan."
              meta={`${overview.connections} connection${
                overview.connections === 1 ? '' : 's'
              } scanned ${relative(overview.scannedAt!)}`}
            />
          )}

          {overview.state === 'ok' && overview.total > 0 && (
            <ul
              style={{
                listStyle: 'none',
                margin: 0,
                padding: 0,
                display: 'grid',
                gap: 'var(--space-2)',
              }}
            >
              {/* Sorted by severity descending — order is a redundant channel that survives
                  greyscale when hue does not. */}
              {[...SEVERITIES]
                .sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])
                .map((sev) => (
                  <li
                    key={sev}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 'var(--space-3)',
                      height: 'var(--row-compact)',
                    }}
                  >
                    <SeverityBadge severity={sev} />
                    <span
                      data-numeric
                      style={{
                        fontSize: 'var(--text-base)',
                        fontWeight: 600,
                        color: overview.counts[sev] === 0 ? 'var(--text-muted)' : 'var(--text-primary)',
                      }}
                    >
                      {overview.counts[sev]}
                    </span>
                  </li>
                ))}
            </ul>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
