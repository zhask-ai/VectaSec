import Link from 'next/link';

import { createClient } from '@/lib/supabase/server';
import { AutoRefresh } from '@/components/AutoRefresh';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* Scan history — the answer to "I clicked Scan now; what happened?"
 *
 * Server-rendered under RLS like every read. While anything is queued or running the page
 * polls itself (AutoRefresh); the moment the last scan lands it goes static again. Each row
 * states what the scan produced — resources seen, findings open — and an error row carries
 * the actual error string, because "error" with no words is a support ticket.
 *
 * `stats` is the engine's own jsonb (scan.py writes it): duration_ms, resources, findings,
 * detector_errors, error. Fields are read defensively — an old scan predates some keys.
 */

export const metadata = { title: 'Scans · VectaSec' };

const LIMIT = 50;

type ScanRow = {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  stats: {
    resources?: number;
    findings?: number;
    suppressed?: number;
    observations?: number;
    duration_ms?: number;
    error?: string;
    detector_errors?: string[];
  } | null;
  connections: { id: string; name: string; type: string } | null;
};

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

function duration(r: ScanRow): string {
  if (r.stats?.duration_ms != null) {
    const ms = r.stats.duration_ms;
    return ms >= 10_000 ? `${Math.round(ms / 1000)}s` : `${ms}ms`;
  }
  if (r.status === 'queued' || r.status === 'running') {
    const s = Math.max(0, Math.floor((Date.now() - new Date(r.started_at).getTime()) / 1000));
    return `${s}s…`;
  }
  return '—';
}

export default async function ScansPage() {
  const supabase = await createClient();

  const res = await supabase
    .from('scans')
    .select('id, status, started_at, finished_at, stats, connections(id, name, type)')
    .order('started_at', { ascending: false })
    .limit(LIMIT);

  if (res.error) {
    return (
      <Page active={false}>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load scans" description={res.error.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const rows = (res.data ?? []) as unknown as ScanRow[];
  const active = rows.filter((r) => r.status === 'queued' || r.status === 'running').length;

  if (rows.length === 0) {
    return (
      <Page active={false}>
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="No scans yet"
              description="Connect a system and hit Scan now — every run lands here with what it saw."
            />
            <p style={{ textAlign: 'center', margin: 0 }}>
              <Link href="/connections" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Go to Connections →
              </Link>
            </p>
          </CardBody>
        </Card>
      </Page>
    );
  }

  const meta = `last ${rows.length} scan${rows.length === 1 ? '' : 's'}${active > 0 ? ` · ${active} in flight` : ''}`;

  return (
    <Page active={active > 0} meta={meta}>
      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
          <CardMeta>
            last {rows.length} scan{rows.length === 1 ? '' : 's'}
            {active > 0 && ` · ${active} in flight`}
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          <Table density="default" caption="Scan history, newest first">
            <THead>
              <TR>
                <TH width="12%">Status</TH>
                <TH width="24%">Connection</TH>
                <TH width="16%">Started</TH>
                <TH width="10%" numeric>
                  Duration
                </TH>
                <TH width="10%" numeric>
                  Resources
                </TH>
                <TH width="10%" numeric>
                  Findings
                </TH>
                <TH width="18%">Detail</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => (
                <TR key={r.id}>
                  <TD>
                    <ScanStatus status={r.status} />
                  </TD>
                  <TD>
                    {r.connections ? (
                      <span style={{ fontFamily: 'var(--font-mono)' }}>
                        {r.connections.type}/{r.connections.name}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--text-muted)' }}>(connection removed)</span>
                    )}
                  </TD>
                  <TD>
                    <span title={absolute(r.started_at)}>{relative(r.started_at)}</span>
                  </TD>
                  <TD numeric>{duration(r)}</TD>
                  <TD numeric>{r.status === 'done' ? (r.stats?.resources ?? '—') : '—'}</TD>
                  <TD numeric>
                    {r.status === 'done' ? (
                      (r.stats?.findings ?? 0) > 0 ? (
                        <Link href="/findings" style={{ color: 'var(--text-primary)' }}>
                          {r.stats?.findings}
                        </Link>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>0</span>
                      )
                    ) : (
                      '—'
                    )}
                  </TD>
                  <TD>
                    {r.status === 'error' && (
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
                        {r.stats?.error ?? 'failed — no error recorded'}
                      </span>
                    )}
                    {r.status === 'done' && (r.stats?.detector_errors?.length ?? 0) > 0 && (
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
                        {r.stats?.detector_errors?.length} detector error
                        {(r.stats?.detector_errors?.length ?? 0) === 1 ? '' : 's'}
                      </span>
                    )}
                    {r.status === 'done' && (r.stats?.suppressed ?? 0) > 0 && (
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                        {' '}
                        {r.stats?.suppressed} suppressed
                      </span>
                    )}
                    {r.status === 'queued' && (
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                        waiting for a worker
                      </span>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </CardBody>
      </Card>

      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        Queued scans are executed by <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec worker</code>{' '}
        (or an enrolled collector, for collector-mode connections). If a scan sits queued,{' '}
        <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec doctor</code> will say why.
      </p>
    </Page>
  );
}

function Page({ children, active, meta }: { children: React.ReactNode; active: boolean; meta?: string }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <AutoRefresh active={active} />
      <PageHeader
        title="Scans"
        description="Every scan run, newest first — what each one saw and whether it landed."
        meta={meta}
      />
      {children}
    </div>
  );
}

/** Operational status as the shared StatusPill: word + shape so the state survives greyscale, and
 * a gentle pulse while a scan is still queued or running so "in flight" reads at a glance. */
function ScanStatus({ status }: { status: string }) {
  const inFlight = status === 'queued' || status === 'running';
  const tone: StatusTone =
    status === 'error' ? 'bad' : inFlight ? 'warn' : status === 'done' ? 'ok' : 'neutral';

  return <StatusPill tone={tone} label={status} pulse={inFlight} />;
}
