'use client';

import { useState, useTransition } from 'react';

import { Drawer } from '@/components/ui/drawer';
import { EmptyState } from '@/components/ui/empty-state';
import { IconClock } from '@/components/ui/icons';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { listScansAction, type ScanHistoryRow } from './actions';

/* The scan-history drawer — what the /scans page used to be, per connection, in place.
 *
 * A scan run is context for a connection row ("why does this say 0 findings?"), not a
 * destination, so it is a drawer beside the table rather than a nav item. Rows load on open
 * through a read-only Server Action under the caller's own RLS session: a viewer sees history,
 * and still cannot queue anything. Nothing is cached across opens — a scan may have landed since.
 */

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

function duration(r: ScanHistoryRow): string {
  if (r.finished_at) {
    const ms = new Date(r.finished_at).getTime() - new Date(r.started_at).getTime();
    return ms >= 10_000 ? `${Math.round(ms / 1000)}s` : `${ms}ms`;
  }
  if (r.status === 'queued' || r.status === 'running') return 'in flight';
  return '—';
}

function tone(status: string): StatusTone {
  if (status === 'error') return 'bad';
  if (status === 'queued' || status === 'running') return 'warn';
  if (status === 'done') return 'ok';
  return 'neutral';
}

export function ScanHistoryButton({ connectionId, name }: { connectionId: string; name: string }) {
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState<ScanHistoryRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, start] = useTransition();

  function show() {
    setOpen(true);
    setRows(null);
    setError(null);
    start(async () => {
      const res = await listScansAction(connectionId);
      if (res.ok) setRows(res.rows);
      else setError(res.message);
    });
  }

  return (
    <>
      <button type="button" className="vs-actionbtn" onClick={show} title={`Scan history for ${name}`}>
        <IconClock size={12} />
        History
      </button>

      <Drawer open={open} onClose={() => setOpen(false)} width={640} title={`Scans · ${name}`} description="Every run of this connection, newest first — what each one saw and whether it landed.">
        {error ? (
          <EmptyState tone="error" title="Could not load scan history" description={error} />
        ) : pending || rows === null ? (
          <p role="status" style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            Loading scans…
          </p>
        ) : rows.length === 0 ? (
          <EmptyState tone="setup" title="No scans yet" description="Hit Scan on this connection — every run lands here with what it saw." />
        ) : (
          <Table density="default" caption={`Scan history for ${name}`}>
            <THead>
              <TR>
                <TH width="18%">Status</TH>
                <TH width="22%">Started</TH>
                <TH width="12%" numeric>Duration</TH>
                <TH width="12%" numeric>Resources</TH>
                <TH width="12%" numeric>Findings</TH>
                <TH width="24%">Detail</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => {
                const inFlight = r.status === 'queued' || r.status === 'running';
                const detErrors = r.stats?.detector_errors?.length ?? 0;
                return (
                  <TR key={r.id}>
                    <TD>
                      <StatusPill tone={tone(r.status)} label={r.status} pulse={inFlight} />
                    </TD>
                    <TD>
                      <span title={absolute(r.started_at)}>{relative(r.started_at)}</span>
                    </TD>
                    <TD numeric>{duration(r)}</TD>
                    <TD numeric>{r.status === 'done' ? (r.stats?.resources ?? '—') : '—'}</TD>
                    <TD numeric>{r.status === 'done' ? (r.stats?.findings ?? 0) : '—'}</TD>
                    <TD>
                      {r.status === 'error' && (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
                          {r.stats?.error ?? 'failed — no error recorded'}
                        </span>
                      )}
                      {r.status === 'done' && detErrors > 0 && (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
                          {detErrors} detector error{detErrors === 1 ? '' : 's'}
                        </span>
                      )}
                      {r.status === 'done' && (r.stats?.suppressed ?? 0) > 0 && (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}> {r.stats?.suppressed} suppressed</span>
                      )}
                      {r.status === 'queued' && (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>waiting for a worker</span>
                      )}
                    </TD>
                  </TR>
                );
              })}
            </TBody>
          </Table>
        )}
        <p style={{ margin: 'var(--space-4) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          Queued scans are executed by <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec worker</code> (or an
          enrolled collector). If a scan sits queued, <code style={{ fontFamily: 'var(--font-mono)' }}>vectasec doctor</code>{' '}
          will say why.
        </p>
      </Drawer>
    </>
  );
}
