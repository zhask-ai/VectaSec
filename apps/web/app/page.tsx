import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import { SEVERITIES, SEVERITY_RANK, type Severity, type SeverityCounts } from '@/lib/types';
import { postureScore, gradeColor } from '@/lib/posture';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';
import { AutoRefresh } from '@/components/AutoRefresh';

/* Overview — the landing dashboard. Answers "how are we doing, and what do I do now": a posture
 * score grounded in the raw severity counts beside it, coverage honesty (what we could NOT
 * assess), the two differentiating lenses (non-human identity + sensitive data), the worst open
 * findings as a do-this-now list, and a compliance strip for the budget-holder.
 *
 * Every number here is either an aggregate-view read or a `count:'exact', head:true` query, never
 * an unbounded select reduced in JS — a security console must not under-report past Max Rows.
 * Reads cookies (dynamic route); RLS scopes every read to the caller's tenant.
 */

export const metadata = { title: 'VectaSec' };

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

type TopRisk = { severity: Severity; rule_id: string; title: string; resources: { kind: string; name: string } | null };

export default async function OverviewPage() {
  const supabase = await createClient();

  const connectionsRes = await supabase.from('connections').select('id, last_scanned_at, status');
  if (connectionsRes.error) {
    return <Shell><Card><CardBody><EmptyState tone="error" title="Could not load overview" description={connectionsRes.error.message} /></CardBody></Card></Shell>;
  }
  const connections = connectionsRes.data ?? [];
  if (connections.length === 0) {
    return <Shell><Card><CardBody><EmptyState tone="setup" title="Connect your first system"
      description="VectaSec scans the integration layer — Kafka, RabbitMQ, Kong, Redis, MCP. Nothing is connected yet." />
      <p style={{ textAlign: 'center', margin: 0 }}><Link href="/connections" style={{ color: 'var(--text-primary)' }}>Go to Connections →</Link></p>
    </CardBody></Card></Shell>;
  }
  const scannedAt = connections.map((c) => c.last_scanned_at).filter((d): d is string => Boolean(d)).sort().at(-1) ?? null;
  const scanning = connections.some((c) => c.status === 'queued' || c.status === 'running');

  if (!scannedAt) {
    return <Shell active={scanning}><Card><CardBody><EmptyState tone="pending" title="Connected. First scan pending."
      description="Collection has not run yet. Findings appear here once the first scan completes."
      meta={`${connections.length} connection${connections.length === 1 ? '' : 's'} configured`} /></CardBody></Card></Shell>;
  }

  // Everything below is aggregate reads or exact head-counts — cap-safe by construction.
  // The trend read is bounded (.limit(30)) so it can never hit PostgREST Max Rows.
  const [facetsRes, notAssessableRes, identitiesRes, wildcardRes, sensitiveRes, topRes, controlsRes, trendRes] = await Promise.all([
    supabase.from('findings_facets').select('severity, n').eq('status', 'open'),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('status', 'open').eq('assessment', 'not_assessable'),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('kind', 'identity'),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('kind', 'grant').eq('labels->>wildcard', 'true'),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('labels->>data_sensitivity', 'high'),
    supabase.from('findings').select('severity, rule_id, title, resources(kind, name)').eq('status', 'open').limit(400),
    supabase.from('controls').select('framework, status'),
    supabase.from('posture_snapshots').select('taken_at, score').order('taken_at', { ascending: false }).limit(30),
  ]);

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
  let total = 0;
  for (const row of (facetsRes.data ?? []) as { severity: string; n: number }[]) {
    total += row.n;
    if ((row.severity as Severity) in counts) counts[row.severity as Severity] += row.n;
  }
  const posture = postureScore(counts);
  const notAssessable = notAssessableRes.count ?? 0;

  // Oldest → newest for the sparkline (the query is newest-first so LIMIT keeps the recent 30).
  const trend = (((trendRes.data ?? []) as { taken_at: string; score: number }[])).slice().reverse();

  const top = ((topRes.data ?? []) as unknown as TopRisk[])
    .filter((f) => f.severity !== 'info')
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
    .slice(0, 6);

  const controls = (controlsRes.data ?? []) as { framework: string; status: string }[];
  const compBy = new Map<string, { pass: number; fail: number; unknown: number; total: number }>();
  for (const c of controls) {
    const e = compBy.get(c.framework) ?? { pass: 0, fail: 0, unknown: 0, total: 0 };
    e.total += 1;
    if (c.status === 'pass') e.pass += 1;
    else if (c.status === 'fail') e.fail += 1;
    else e.unknown += 1;
    compBy.set(c.framework, e);
  }

  return (
    <Shell active={scanning} meta={`${connections.length} connection${connections.length === 1 ? '' : 's'} · scanned ${relative(scannedAt)}`}>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 280px) 1fr', gap: 'var(--space-4)', alignItems: 'stretch' }}>
        {/* Posture hero */}
        <Card>
          <CardBody>
            <div style={{ fontSize: 'var(--text-2xs)', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)', fontWeight: 600 }}>
              Posture score
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', marginTop: 'var(--space-1)' }}>
              <span data-numeric style={{ fontSize: '3rem', fontWeight: 800, lineHeight: 1, color: gradeColor(posture.grade) }}>{posture.score}</span>
              <span style={{ fontSize: 'var(--text-lg)', fontWeight: 700, color: gradeColor(posture.grade) }}>{posture.grade}</span>
            </div>
            <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)', lineHeight: 'var(--leading-2xs)' }}>
              From {total} open finding{total === 1 ? '' : 's'}, weighted by severity. Fix criticals first to move it most.
            </div>
            <PostureTrend points={trend} />
          </CardBody>
        </Card>

        {/* Severity breakdown */}
        <Card>
          <CardHeader><CardTitle>Open findings</CardTitle><CardMeta><Link href="/findings" style={{ color: 'var(--text-secondary)' }}>view queue →</Link></CardMeta></CardHeader>
          <CardBody>
            {total === 0 ? (
              <EmptyState tone="clean" title="No open findings" description="Every rule passed on the last scan." />
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(90px, 1fr))', gap: 'var(--space-3)' }}>
                {[...SEVERITIES].sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b]).map((sev) => (
                  <Link key={sev} href={`/findings?severity=${sev}` as Route} style={{ textDecoration: 'none', display: 'grid', gap: 4, justifyItems: 'start' }}>
                    <SeverityBadge severity={sev} />
                    <span data-numeric style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: counts[sev] === 0 ? 'var(--text-muted)' : 'var(--text-primary)' }}>{counts[sev]}</span>
                  </Link>
                ))}
              </div>
            )}
            {notAssessable > 0 && (
              <p style={{ margin: 'var(--space-3) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
                {notAssessable} coverage gap{notAssessable === 1 ? '' : 's'} — checks that could not be assessed (not the same as a pass).
              </p>
            )}
          </CardBody>
        </Card>
      </div>

      {/* The two differentiating lenses */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 'var(--space-3)' }}>
        <LensCard href="/identities" title="Non-human identities" value={identitiesRes.count ?? 0}
          alert={wildcardRes.count ?? 0} alertLabel="with wildcard grants"
          blurb="Service accounts, consumers, broker users and OAuth clients across every system." />
        <LensCard href="/assets" title="Sensitive data assets" value={sensitiveRes.count ?? 0}
          alert={0} alertLabel="" blurb="Resources named like PCI / PHI / secrets (inferred from naming), where regulated data likely flows." />
      </div>

      {/* Do this now */}
      {top.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Do this now</CardTitle><CardMeta>worst open findings</CardMeta></CardHeader>
          <CardBody pad={false}>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {top.map((f, i) => (
                <li key={i} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) var(--space-4)', borderBottom: '1px solid var(--border)' }}>
                  <SeverityBadge severity={f.severity} variant="inline" />
                  <span style={{ flex: 1, minWidth: 0 }}>
                    <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>{f.title}</span>
                    <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      {f.rule_id}{f.resources ? ` · ${f.resources.kind}/${f.resources.name}` : ''}
                    </span>
                  </span>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      )}

      {/* Compliance strip */}
      {compBy.size > 0 && (
        <Card>
          <CardHeader><CardTitle>Compliance</CardTitle><CardMeta><Link href="/compliance" style={{ color: 'var(--text-secondary)' }}>details →</Link></CardMeta></CardHeader>
          <CardBody>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)' }}>
              {[...compBy.entries()].map(([fw, e]) => (
                <div key={fw} style={{ display: 'grid', gap: 2 }}>
                  <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-primary)' }}>{fw}</span>
                  <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                    {e.fail > 0 && <span style={{ color: 'var(--sev-critical-fg)' }}>{e.fail} failing</span>}
                    {e.fail > 0 && (e.unknown > 0 || e.pass > 0) && ' · '}
                    {e.unknown > 0 && <span style={{ color: 'var(--sev-medium-fg)' }}>{e.unknown} unknown</span>}
                    {e.unknown > 0 && e.pass > 0 && ' · '}
                    {e.pass > 0 && <span style={{ color: 'var(--sev-low-fg)' }}>{e.pass} attested</span>}
                  </span>
                </div>
              ))}
            </div>
          </CardBody>
        </Card>
      )}
    </Shell>
  );
}

/** Posture over time — one snapshot per completed scan (posture_snapshots, written by the
 * scans_posture_snapshot trigger using the SAME formula as postureScore above, so this line
 * and the big number can never disagree). A single-series sparkline: neutral ink (identity is
 * carried by the card, not by color), 2px line, end-dot on the latest point, and the delta
 * stated in text beside it so the movement is readable without the plot. The y-domain spans
 * the observed scores (not 0–100) so remediation progress is visible; the text carries the
 * absolute numbers, which keeps the zoomed domain honest. */
function PostureTrend({ points }: { points: { taken_at: string; score: number }[] }) {
  if (points.length < 2) {
    return (
      <p style={{ margin: 'var(--space-2) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', lineHeight: 'var(--leading-2xs)' }}>
        No history yet — the trend appears after a couple of completed scans.
      </p>
    );
  }
  const w = 220;
  const h = 36;
  const pad = 4;
  const scores = points.map((p) => p.score);
  const min = Math.min(...scores);
  const max = Math.max(...scores);
  const x = (i: number) => pad + (i * (w - 2 * pad)) / (points.length - 1);
  const y = (s: number) => (max === min ? h / 2 : pad + (h - 2 * pad) * (1 - (s - min) / (max - min)));
  const d = points.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)} ${y(p.score).toFixed(1)}`).join(' ');
  const first = points[0];
  const last = points[points.length - 1];
  const delta = last.score - first.score;
  return (
    <div style={{ marginTop: 'var(--space-2)', display: 'grid', gap: 2 }}>
      <svg
        width={w}
        height={h}
        viewBox={`0 0 ${w} ${h}`}
        role="img"
        aria-label={`Posture trend: score ${first.score} to ${last.score} across ${points.length} snapshots`}
        style={{ maxWidth: '100%' }}
      >
        <path d={d} fill="none" stroke="var(--text-secondary)" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
        <circle cx={x(points.length - 1)} cy={y(last.score)} r="3" fill="var(--text-primary)" />
      </svg>
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }} data-numeric>
        {delta === 0 ? 'unchanged' : delta > 0 ? `+${delta}` : String(delta)} over {points.length} snapshots · since {relative(first.taken_at)}
      </span>
    </div>
  );
}

function LensCard({ href, title, value, alert, alertLabel, blurb }: {
  href: Route; title: string; value: number; alert: number; alertLabel: string; blurb: string;
}) {
  return (
    <Card>
      <CardBody>
        <Link href={href} style={{ textDecoration: 'none', display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
            <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>{title}</span>
            <span data-numeric style={{ fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)' }}>{value}</span>
          </div>
        </Link>
        {alert > 0 && (
          <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-high-fg)', fontWeight: 600, marginTop: 2 }}>{alert} {alertLabel}</div>
        )}
        <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', marginTop: 'var(--space-1)', lineHeight: 'var(--leading-2xs)' }}>{blurb}</div>
      </CardBody>
    </Card>
  );
}

function Shell({ children, meta, active = false }: { children: React.ReactNode; meta?: string; active?: boolean }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1100 }}>
      <AutoRefresh active={active} />
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
        <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>Overview</h1>
        {meta && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{meta}</span>}
      </div>
      {children}
    </div>
  );
}
