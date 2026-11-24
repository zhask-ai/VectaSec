import Link from 'next/link';
import type { Route } from 'next';

import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import type { FindingDetail } from '../data';

/* "Before you fix this" — what the change would touch (engine: impact.py).
 *
 * Sits directly above the guided fix, because the reason fixes do not get applied is rarely
 * "I do not know the command"; it is "I do not know what stops working". The engine joins the
 * runtime evidence ledger and the resource graph and returns who was seen using the resource,
 * what depends on it, what else the same fix closes, and a runbook.
 *
 * Three verdicts. `unknown` is the common one and is shown as unknown: a system with no usage
 * signal must not produce an empty "consumers" list that reads as "safe to change".
 */

type Impact = {
  verdict: 'will_affect' | 'no_use_seen' | 'unknown';
  why: string;
  scope: 'everyone' | 'principal' | 'resource';
  consumers: { principal: string; peer_host: string; last_seen: string; observed_scans: number }[];
  consumers_total: number;
  dependents: { id: string; kind: string; name: string; owner: string }[];
  dependents_total: number;
  also_closes: { id: string; rule_id: string; title: string }[];
  usage_source: string | null;
  window_days: number | null;
  runbook: string[];
};

const VERDICT: Record<Impact['verdict'], { label: string; tone: StatusTone }> = {
  will_affect: { label: 'Will affect running clients', tone: 'warn' },
  no_use_seen: { label: 'No use seen', tone: 'ok' },
  unknown: { label: 'Usage unknown', tone: 'neutral' },
};

export async function ImpactCard({ finding }: { finding: FindingDetail }) {
  if (finding.status === 'resolved') return null;
  const [membership, user] = await Promise.all([getOwnMembership(), getVerifiedUser()]);
  if (!membership || !user) return null;
  const res = await engineGet<Impact>(`/findings/${finding.id}/impact`, {
    tenantId: membership.tenantId,
    actor: user.id,
  });
  if (!res.ok) return null;
  const d = res.data;
  const v = VERDICT[d.verdict];
  const small: React.CSSProperties = { fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', margin: 0 };
  const h: React.CSSProperties = { fontSize: 'var(--text-2xs)', fontWeight: 600, color: 'var(--text-secondary)', margin: 0 };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Before you fix this</CardTitle>
        <CardMeta>
          {d.window_days === null ? 'not watched yet' : `watched ${Math.round(d.window_days)} day${Math.round(d.window_days) === 1 ? '' : 's'}`}
        </CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
            <span>
              <StatusPill tone={v.tone} variant="soft" label={v.label} />
            </span>
            <p style={small}>{d.why}</p>
          </div>

          {d.consumers.length > 0 && (
            <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
              <p style={h}>
                Seen using it ({d.consumers.length}
                {d.consumers_total > d.consumers.length ? ` of ${d.consumers_total}` : ''})
              </p>
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-1)' }}>
                {d.consumers.slice(0, 12).map((c, i) => (
                  <li key={i} style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'baseline', fontSize: 'var(--text-xs)' }}>
                    <code>{c.principal}</code>
                    {c.peer_host && <span style={{ color: 'var(--text-secondary)' }}>from {c.peer_host}</span>}
                    <span style={{ color: 'var(--text-muted)' }}>
                      last seen {new Date(c.last_seen).toISOString().slice(0, 10)} · in {c.observed_scans} scan
                      {c.observed_scans === 1 ? '' : 's'}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {d.dependents.length > 0 && (
            <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
              <p style={h}>Depends on it ({d.dependents_total})</p>
              <span style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                {d.dependents.slice(0, 16).map((x) => (
                  <Link key={x.id} href={`/estate/inventory/${x.id}` as Route} style={{ textDecoration: 'none' }}>
                    <Chip mono title={`${x.kind}${x.owner ? ` · owner ${x.owner}` : ''}`}>
                      {x.name}
                    </Chip>
                  </Link>
                ))}
              </span>
            </div>
          )}

          {d.runbook.length > 0 && (
            <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
              <p style={h}>{d.scope === 'principal' ? 'Rotate without an outage' : 'Change it safely'}</p>
              <ol style={{ margin: 0, paddingLeft: 'var(--space-5)', display: 'grid', gap: 'var(--space-1)', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' }}>
                {d.runbook.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </div>
          )}

          {d.also_closes.length > 0 && (
            <p style={{ ...small, color: 'var(--text-secondary)' }}>
              Same resource, also open:{' '}
              {d.also_closes.slice(0, 5).map((s, i) => (
                <span key={s.id}>
                  {i > 0 ? ', ' : ''}
                  <Link href={`/findings/${s.id}` as Route}>{s.title || s.rule_id}</Link>
                </span>
              ))}
              . One change window can cover them.
            </p>
          )}
        </div>
      </CardBody>
      <CardFooter>
        {d.usage_source
          ? `Usage comes from: ${d.usage_source} Sampled at scan time, so short-lived clients can be missed.`
          : 'This system gives no usage signal. Dependencies shown come from configuration only.'}
      </CardFooter>
    </Card>
  );
}
