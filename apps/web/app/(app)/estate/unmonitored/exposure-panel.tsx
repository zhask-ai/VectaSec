'use client';

import { useActionState } from 'react';

import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import {
  createExposureTargetAction,
  startExposureScanAction,
  verifyExposureTargetAction,
  type ActionState,
} from './actions';

/* The external exposure scan panel — enter a domain, prove you own it, see what the internet
 * sees. No credentials, no agent. Everything rendered here comes from the exposure_targets /
 * exposure_scans rows the server page read under RLS; the actions post to the engine. */

export type ExposureTargetRow = {
  id: string;
  kind: string;
  value: string;
  token: string;
  verified_at: string | null;
  verify_method: string | null;
  created_at: string;
};

export type ExposureScanRow = {
  id: string;
  target_id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  report: {
    headline?: string;
    targets_probed?: number;
    hosts?: string[];
    services?: {
      host: string;
      port: number;
      product: string;
      version?: string | null;
      version_inferred?: boolean;
      transport?: string;
      auth_observed?: string;
      cves?: { id: string; cvss?: number | null; summary?: string }[];
      eol?: { status: string; note?: string };
    }[];
    refusals?: string[];
    generated_at?: string;
  } | null;
};

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

export function ExposurePanel({
  targets,
  scans,
  editable,
  available,
}: {
  targets: ExposureTargetRow[];
  scans: ExposureScanRow[];
  editable: boolean;
  /** false when the exposure tables are not readable (migration not applied yet). */
  available: boolean;
}) {
  const latestByTarget = new Map<string, ExposureScanRow>();
  for (const sc of scans) {
    const prev = latestByTarget.get(sc.target_id);
    if (!prev || (sc.started_at ?? '') > (prev.started_at ?? '')) latestByTarget.set(sc.target_id, sc);
  }

  if (!available) {
    return (
      <EmptyState
        tone="pending"
        title="External exposure scan not enabled on this deployment"
        description="The exposure_targets / exposure_scans tables are not readable — apply the 20261017000003 migration and reload."
      />
    );
  }

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      {editable && <AddTarget />}

      {targets.length === 0 ? (
        <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
          Add a domain you operate. VectaSec issues a DNS TXT token; once it resolves, a read-only sweep of the common
          middleware ports on that domain (and names like kafka., mq., redis., api., n8n., mcp.) runs with no
          credentials and reports only product, version and port — plus any known CVE or end-of-life status.
        </p>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
          {targets.map((t) => (
            <li key={t.id} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)', display: 'grid', gap: 'var(--space-3)' }}>
              <TargetRow target={t} scan={latestByTarget.get(t.id) ?? null} editable={editable} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function AddTarget() {
  const [state, action, pending] = useActionState<ActionState, FormData>(createExposureTargetAction, null);
  return (
    <form action={action} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
      <label style={{ display: 'grid', gap: 4 }}>
        <span style={labelStyle}>Kind</span>
        <select name="kind" defaultValue="domain" style={inputStyle}>
          <option value="domain">Domain</option>
          <option value="ip">IP address</option>
          <option value="cidr">CIDR (≤ /24)</option>
        </select>
      </label>
      <label style={{ display: 'grid', gap: 4, flex: '1 1 240px' }}>
        <span style={labelStyle}>Target</span>
        <input name="value" required placeholder="example.com" autoComplete="off" spellCheck={false} style={inputStyle} />
      </label>
      <button type="submit" className="vs-button" data-variant="primary" disabled={pending} aria-busy={pending || undefined} style={primaryStyle}>
        {pending ? 'Adding…' : 'Add target'}
      </button>
      {state && (
        <span role="status" style={{ flexBasis: '100%', fontSize: 'var(--text-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.message}
        </span>
      )}
    </form>
  );
}

function TargetRow({ target, scan, editable }: { target: ExposureTargetRow; scan: ExposureScanRow | null; editable: boolean }) {
  const [verifyState, verifyAction, verifying] = useActionState<ActionState, FormData>(verifyExposureTargetAction, null);
  const [scanState, scanAction, starting] = useActionState<ActionState, FormData>(startExposureScanAction, null);
  const verified = Boolean(target.verified_at);
  const inFlight = scan?.status === 'queued' || scan?.status === 'running';
  const txt = `vectasec-verify=${target.token}`;

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{target.value}</span>
        <Chip mono>{target.kind}</Chip>
        {verified ? (
          <StatusPill tone="ok" label={`verified · ${target.verify_method ?? 'dns'}`} />
        ) : (
          <StatusPill tone="warn" label="ownership not verified" />
        )}
        {scan && <StatusPill tone={scan.status === 'error' ? 'bad' : inFlight ? 'warn' : 'ok'} label={`scan ${scan.status}`} pulse={inFlight} />}
      </div>

      {!verified && (
        <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
            Prove you operate this target: publish a DNS TXT record on <code>{target.kind === 'domain' ? target.value : 'a domain whose A/PTR records cover it'}</code>{' '}
            (or on <code>_vectasec.{target.value}</code>) with exactly this value, then press Verify.
          </p>
          <pre style={preStyle}>{txt}</pre>
          {editable && (
            <form action={verifyAction} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              <input type="hidden" name="targetId" value={target.id} />
              <button type="submit" className="vs-actionbtn" disabled={verifying} aria-busy={verifying || undefined}>
                {verifying ? 'Checking DNS…' : 'Verify ownership'}
              </button>
              {verifyState && (
                <span role="status" style={{ fontSize: 'var(--text-2xs)', color: verifyState.ok ? 'var(--text-secondary)' : 'var(--sev-medium-fg)' }}>
                  {verifyState.message}
                </span>
              )}
            </form>
          )}
        </div>
      )}

      {verified && editable && (
        <form action={scanAction} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
          <input type="hidden" name="targetId" value={target.id} />
          <button type="submit" className="vs-actionbtn" disabled={starting || inFlight} aria-busy={starting || undefined}>
            {starting ? 'Starting…' : inFlight ? 'Scanning…' : scan ? 'Rescan' : 'Run exposure scan'}
          </button>
          {scanState && (
            <span role="status" style={{ fontSize: 'var(--text-2xs)', color: scanState.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
              {scanState.message}
            </span>
          )}
        </form>
      )}

      {scan && scan.status === 'error' && (
        <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>{scan.error ?? 'The scan failed without recording why.'}</p>
      )}

      {scan && scan.status === 'done' && scan.report && <Report scan={scan} />}
    </>
  );
}

function Report({ scan }: { scan: ExposureScanRow }) {
  const r = scan.report!;
  const services = r.services ?? [];
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <p style={{ margin: 0, fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
        {r.headline ?? `${services.length} internet-reachable service${services.length === 1 ? '' : 's'}`}
        <span style={{ marginLeft: 'var(--space-2)', fontSize: 'var(--text-2xs)', fontWeight: 400, color: 'var(--text-muted)' }}>
          {r.targets_probed ?? r.hosts?.length ?? 0} hosts probed{scan.finished_at ? ` · ${relative(scan.finished_at)}` : ''}
        </span>
      </p>
      {services.length === 0 ? (
        <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
          No middleware answered on the probed ports. That is what was reachable from here at this moment — not a statement about ports or hosts not probed.
        </p>
      ) : (
        <Table density="compact" caption="Internet-reachable middleware found by the exposure scan">
          <THead>
            <TR>
              <TH width="26%">Host</TH>
              <TH width="8%" numeric>Port</TH>
              <TH width="18%">Product</TH>
              <TH width="12%">Auth</TH>
              <TH width="36%">Risk</TH>
            </TR>
          </THead>
          <TBody>
            {services.map((sv, i) => {
              const worst = (sv.cves ?? []).reduce<number>((m, c) => Math.max(m, c.cvss ?? 0), 0);
              return (
                <TR key={`${sv.host}:${sv.port}:${i}`}>
                  <TD mono>{sv.host}</TD>
                  <TD numeric>{sv.port}</TD>
                  <TD>
                    {sv.product}
                    {sv.version && (
                      <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                        {sv.version}
                        {sv.version_inferred ? ' (inferred)' : ''}
                      </span>
                    )}
                  </TD>
                  <TD>
                    {sv.auth_observed === 'none' ? <Chip tone="high">none observed</Chip> : sv.auth_observed === 'required' ? <Chip tone="info">required</Chip> : <span style={{ color: 'var(--text-muted)' }}>unknown</span>}
                  </TD>
                  <TD>
                    <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                      {(sv.cves ?? []).slice(0, 3).map((c) => (
                        <Chip key={c.id} mono title={c.summary ?? ''}>
                          {c.id}
                          {c.cvss != null ? ` · ${c.cvss}` : ''}
                        </Chip>
                      ))}
                      {worst >= 9 && <SeverityBadge severity="critical" variant="inline" />}
                      {sv.eol?.status === 'eol' && <Chip tone="high">end of life</Chip>}
                      {sv.eol?.status === 'approaching' && <Chip tone="medium">EOL soon</Chip>}
                      {!sv.cves?.length && sv.eol?.status !== 'eol' && sv.eol?.status !== 'approaching' && (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>no known CVE for this version</span>
                      )}
                    </span>
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
      {(r.refusals?.length ?? 0) > 0 && (
        <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
          {r.refusals!.length} target{r.refusals!.length === 1 ? '' : 's'} refused or unreachable — not probed, not clean.
        </p>
      )}
    </div>
  );
}

const labelStyle: React.CSSProperties = {
  fontSize: 'var(--text-2xs)',
  fontWeight: 600,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  color: 'var(--text-secondary)',
};

const inputStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  padding: '0 var(--space-2)',
  height: 'var(--row-default)',
  width: '100%',
};

const primaryStyle: React.CSSProperties = {
  border: '1px solid var(--accent)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--accent)',
  color: 'var(--accent-fg)',
  fontSize: 'var(--text-xs)',
  fontWeight: 600,
  padding: '0 var(--space-3)',
  height: 'var(--row-default)',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
};

const preStyle: React.CSSProperties = {
  margin: 0,
  padding: 'var(--space-2) var(--space-3)',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-xs)',
  color: 'var(--text-primary)',
  overflowX: 'auto',
};
