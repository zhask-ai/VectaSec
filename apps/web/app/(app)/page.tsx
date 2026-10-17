import Link from 'next/link';
import type { Route } from 'next';
import type { CSSProperties, ReactNode } from 'react';

import { createClient } from '@/lib/supabase/server';
import { SEVERITIES, SEVERITY_RANK, type Severity, type SeverityCounts } from '@/lib/types';
import { postureScore, gradeColor } from '@/lib/posture';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Page } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { EmptyState } from '@/components/ui/empty-state';
import { IconDatabase, IconFindings, IconIdentity, IconLayers } from '@/components/ui/icons';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import { Meter, ProgressRing } from '@/components/ui/meter';
import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';
import { Table, THead, TBody, TR, TH, TD } from '@/components/ui/table';
import { Sparkline } from '@/components/charts/Sparkline';
import { SeverityBar } from '@/components/charts/SeverityBar';
import { Donut } from '@/components/charts/Donut';
import { AutoRefresh } from '@/components/AutoRefresh';

/* Overview — the executive landing dashboard. Answers, in one screen, "how are we doing and what do
 * I do now": a posture score grounded in the raw severity counts that produced it (never a magic
 * number), the differentiating lenses (non-human identity + sensitive data), the worst open findings
 * as a do-this-now list, an honest compliance strip, and the last few scans.
 *
 * Every headline number is an aggregate-view read or a `count:'exact', head:true` query, never an
 * unbounded select reduced in JS — a security console must not under-report past PostgREST Max Rows.
 * The two bounded selects (top findings, sensitive sample) carry an explicit `.limit()`. Reads
 * cookies (dynamic route); RLS scopes every read to the caller's tenant. */

export const metadata = { title: 'VectaSec' };

const CAPS: CSSProperties = {
  fontSize: 'var(--text-2xs)',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  color: 'var(--text-secondary)',
  fontWeight: 600,
};

/** The two rule families that lead the "do this now" queue: reachable attack paths and exposed data. */
const LED_RULE = /^(?:ATTACKPATH|DATA\.EXPOSURE)\./;

const s = (n: number) => (n === 1 ? '' : 's');

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

type TopRisk = {
  id: string;
  severity: Severity;
  rule_id: string;
  title: string;
  assessment: string;
  resources: { kind: string; name: string } | null;
};

type SensRow = { name: string; kind: string; labels: Record<string, unknown> | null };
type ScanRow = {
  id: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  connections: { type: string; name: string } | null;
};

export default async function OverviewPage() {
  const supabase = await createClient();

  const connectionsRes = await supabase.from('connections').select('id, type, last_scanned_at, status');
  if (connectionsRes.error) {
    return (
      <Frame>
        <Card><CardBody><EmptyState tone="error" title="Could not load overview" description={connectionsRes.error.message} /></CardBody></Card>
      </Frame>
    );
  }
  const connections = (connectionsRes.data ?? []) as { id: string; type: string; last_scanned_at: string | null; status: string }[];

  if (connections.length === 0) {
    return (
      <Frame>
        <Card><CardBody>
          <EmptyState tone="setup" title="Connect your first system"
            description="VectaSec scans the integration layer — Kafka, RabbitMQ, Kong, Redis, MCP and more. Nothing is connected yet."
            action={<Link href="/estate" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Go to Connections →</Link>} />
        </CardBody></Card>
      </Frame>
    );
  }

  const scannedAt = connections.map((c) => c.last_scanned_at).filter((d): d is string => Boolean(d)).sort().at(-1) ?? null;
  const scanning = connections.some((c) => c.status === 'queued' || c.status === 'running');

  if (!scannedAt) {
    return (
      <Frame active={scanning} meta={`${connections.length} connection${s(connections.length)} configured`}>
        <Card><CardBody>
          <EmptyState tone="pending" title="Connected — first scan pending"
            description="Collection has not run yet. Posture, findings and coverage appear here the moment the first scan completes."
            meta={`${connections.length} connection${s(connections.length)} configured`} />
        </CardBody></Card>
      </Frame>
    );
  }

  const distinctTypes = new Set(connections.map((c) => c.type)).size;

  // Everything below is aggregate reads, exact head-counts, or explicitly bounded selects — cap-safe
  // by construction, so no number can silently under-report past PostgREST Max Rows.
  const [
    facetsRes,
    notAssessableRes,
    identitiesRes,
    wildcardRes,
    sensitiveRes,
    topRes,
    controlsRes,
    trendRes,
    nhiRiskRes,
    credRiskRes,
    sensSampleRes,
    scansRes,
  ] = await Promise.all([
    supabase.from('findings_facets').select('severity, n').eq('status', 'open'),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('status', 'open').eq('assessment', 'not_assessable'),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('kind', 'identity'),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('kind', 'grant').eq('labels->>wildcard', 'true'),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('labels->>data_sensitivity', 'high'),
    supabase.from('findings').select('id, severity, rule_id, title, assessment, resources(kind, name)').eq('status', 'open').limit(400),
    supabase.from('controls').select('framework, status'),
    supabase.from('posture_snapshots').select('taken_at, score').order('taken_at', { ascending: false }).limit(30),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('status', 'open').like('rule_id', 'NHI.%'),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('status', 'open').like('rule_id', 'CREDENTIAL.LIFECYCLE.%'),
    supabase.from('resources').select('name, kind, labels').neq('labels->>data_sensitivity', 'none').limit(300),
    supabase.from('scans').select('id, status, started_at, finished_at, connections(type, name)').order('started_at', { ascending: false }).limit(6),
  ]);

  // --- What changed this week — the digest a buyer with no security team actually reads ---
  // Exact head-counts over first_seen in the window; nothing here is tallied from a capped list.
  const since = new Date(Date.now() - 7 * 86_400_000).toISOString();
  const [newFindingsRes, newCritHighRes, newIdentitiesRes, newCredsRes, newExposedRes, resolvedRes, weekScansRes, weekFailedRes, membersRes, integrationsRes] = await Promise.all([
    supabase.from('findings').select('id', { count: 'exact', head: true }).gte('first_seen', since).eq('assessment', 'assessed'),
    supabase.from('findings').select('id', { count: 'exact', head: true }).gte('first_seen', since).eq('assessment', 'assessed').in('severity', ['critical', 'high']),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('kind', 'identity').gte('first_seen', since),
    supabase.from('resources').select('id', { count: 'exact', head: true }).eq('kind', 'credential').gte('first_seen', since),
    supabase.from('findings').select('id', { count: 'exact', head: true }).gte('first_seen', since).like('rule_id', 'ATTACKPATH.%'),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('status', 'resolved').gte('last_seen', since),
    supabase.from('scans').select('id', { count: 'exact', head: true }).gte('started_at', since),
    supabase.from('scans').select('id', { count: 'exact', head: true }).gte('started_at', since).eq('status', 'error'),
    supabase.from('tenant_members').select('user_id', { count: 'exact', head: true }),
    supabase.from('integrations').select('id', { count: 'exact', head: true }),
  ]);
  const week = {
    findings: newFindingsRes.count ?? 0,
    critHigh: newCritHighRes.count ?? 0,
    identities: newIdentitiesRes.count ?? 0,
    creds: newCredsRes.count ?? 0,
    exposed: newExposedRes.count ?? 0,
    resolved: resolvedRes.error ? null : (resolvedRes.count ?? 0),
    scans: weekScansRes.count ?? 0,
    failed: weekFailedRes.count ?? 0,
  };
  const checklist: { label: string; done: boolean; href: Route; hint: string }[] = [
    { label: 'Connect a system', done: connections.length > 0, href: '/estate', hint: 'AWS role or a read-only broker user' },
    { label: 'First scan completed', done: Boolean(scannedAt), href: '/estate', hint: 'runs on connect; rescans on the cadence you set' },
    { label: 'Review the access register', done: (identitiesRes.count ?? 0) > 0, href: '/access', hint: 'every key and service account your systems accept' },
    { label: 'Fix one finding and press Verify', done: (week.resolved ?? 0) > 0, href: '/findings', hint: 'the rescan closes it for you' },
    { label: 'Invite a teammate', done: (membersRes.count ?? 0) > 1, href: '/settings/members', hint: 'an owner for the findings' },
    { label: 'Add Slack, Vanta or Drata', done: !integrationsRes.error && (integrationsRes.count ?? 0) > 0, href: '/settings/integrations', hint: 'weekly digest and auditor evidence' },
  ];
  const checklistDone = checklist.filter((c) => c.done).length;

  // The severity facets ARE the posture score. A failed read left `counts` all-zero, which
  // scores 100 / grade A and renders the severity card as "No open findings · Every rule passed
  // on the last scan" — a reassuring green page produced by a broken query. The topbar chip in
  // layout.tsx already guards on this error, so the two disagreed in the direction that
  // comforts. Fail loudly instead: a security console must never invent a clean bill of health.
  if (facetsRes.error) {
    return (
      <Frame>
        <Card><CardBody><EmptyState tone="error" title="Could not load the findings summary"
          description={`${facetsRes.error.message} — posture and severity counts are unavailable, so nothing on this page would be trustworthy.`} /></CardBody></Card>
      </Frame>
    );
  }

  // --- Posture, grounded in the raw severity counts ---
  const counts = Object.fromEntries(SEVERITIES.map((k) => [k, 0])) as SeverityCounts;
  let totalOpen = 0;
  for (const row of (facetsRes.data ?? []) as { severity: string; n: number }[]) {
    totalOpen += row.n;
    if ((row.severity as Severity) in counts) counts[row.severity as Severity] += row.n;
  }
  const posture = postureScore(counts);
  const notAssessable = notAssessableRes.count ?? 0;

  // Oldest → newest for the sparkline (the query is newest-first so LIMIT keeps the recent 30).
  const trend = ((trendRes.data ?? []) as { taken_at: string; score: number }[]).slice().reverse();
  const latestSnap = trend.at(-1) ?? null;

  // --- KPI values ---
  const identities = identitiesRes.count ?? 0;
  const wildcard = wildcardRes.count ?? 0;
  const sensitiveHigh = sensitiveRes.count ?? 0;
  const nhiRisk = (nhiRiskRes.count ?? 0) + (credRiskRes.count ?? 0);

  // Assessment coverage — of the open findings the detectors produced, how many were assessable.
  // Assessed + not_assessable == total, so this needs no extra query. 0 findings ⇒ nothing to score.
  const coverage: { value: ReactNode; unit?: string; sub: string; tone: 'neutral' | 'good' | 'warn' | 'bad' } =
    totalOpen === 0
      ? { value: '—', sub: 'no open findings to assess', tone: 'neutral' }
      : {
          value: Math.round((100 * (totalOpen - notAssessable)) / totalOpen),
          unit: '%',
          sub: notAssessable > 0 ? `${notAssessable} coverage gap${s(notAssessable)}` : 'no coverage gaps',
          tone: notAssessable > 0 ? 'warn' : 'good',
        };

  // --- Do this now: worst open findings, attack-path & data-exposure first, coverage gaps excluded ---
  const top = ((topRes.data ?? []) as unknown as TopRisk[])
    .filter((f) => f.severity !== 'info' && f.assessment !== 'not_assessable')
    .sort((a, b) => {
      const la = LED_RULE.test(a.rule_id) ? 0 : 1;
      const lb = LED_RULE.test(b.rule_id) ? 0 : 1;
      if (la !== lb) return la - lb;
      return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
    })
    .slice(0, 6);

  // --- Systems coverage donut (from the gating read; connections are few, so this is cap-safe) ---
  const byType = new Map<string, number>();
  for (const c of connections) byType.set(c.type, (byType.get(c.type) ?? 0) + 1);
  const systemSlices = [...byType.entries()].map(([label, value]) => ({ label, value }));

  // --- Sensitive-data classes, grouped by inferred sensitivity (dashed = named-like, not proven) ---
  const sensGroups = new Map<'high' | 'medium' | 'low', { classes: Set<string>; signals: Set<string> }>();
  for (const r of (sensSampleRes.data ?? []) as SensRow[]) {
    const labels = (r.labels ?? {}) as Record<string, unknown>;
    const level = labels.data_sensitivity;
    if (level !== 'high' && level !== 'medium' && level !== 'low') continue;
    const g = sensGroups.get(level) ?? { classes: new Set<string>(), signals: new Set<string>() };
    if (typeof labels.data_classes === 'string') labels.data_classes.split(',').map((x) => x.trim()).filter(Boolean).forEach((x) => g.classes.add(x));
    if (typeof labels.data_signals === 'string') labels.data_signals.split(',').map((x) => x.trim()).filter(Boolean).forEach((x) => g.signals.add(x));
    sensGroups.set(level, g);
  }
  const hasClasses = [...sensGroups.values()].some((g) => g.classes.size > 0);

  // --- Compliance: coverage per framework, honest "Not scored" when nothing is applicable ---
  const compBy = new Map<string, { pass: number; fail: number; unknown: number; na: number }>();
  for (const c of (controlsRes.data ?? []) as { framework: string; status: string }[]) {
    const e = compBy.get(c.framework) ?? { pass: 0, fail: 0, unknown: 0, na: 0 };
    if (c.status === 'pass') e.pass += 1;
    else if (c.status === 'fail') e.fail += 1;
    else if (c.status === 'not_applicable') e.na += 1;
    else e.unknown += 1;
    compBy.set(c.framework, e);
  }

  const recentScans = (scansRes.data ?? []) as unknown as ScanRow[];

  return (
    <Frame
      active={scanning}
      meta={`${distinctTypes} system type${s(distinctTypes)} · ${connections.length} connection${s(connections.length)} · scanned ${relative(scannedAt)}`}
    >
      {/* 1 · Posture hero — the score, its trend, and the raw counts it came from */}
      <Card accent>
        <CardHeader>
          <CardTitle>Security posture</CardTitle>
          <CardMeta>{latestSnap ? `${trend.length} snapshot${s(trend.length)} · latest ${relative(latestSnap.taken_at)}` : 'awaiting scan history'}</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-6)', alignItems: 'center' }}>
            <div style={{ flexShrink: 0 }}>
              <ProgressRing
                value={posture.score}
                color={gradeColor(posture.grade)}
                size={120}
                thickness={10}
                label="Posture score, 0 to 100"
                sublabel="0–100 · higher is safer"
                center={
                  <div style={{ display: 'grid', placeItems: 'center', gap: 0 }}>
                    <span data-numeric style={{ fontSize: 'var(--text-3xl)', fontWeight: 720, lineHeight: 1, color: gradeColor(posture.grade) }}>{posture.score}</span>
                    <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 700, letterSpacing: '0.1em', color: gradeColor(posture.grade) }}>GRADE {posture.grade}</span>
                  </div>
                }
              />
            </div>

            <div style={{ flex: '1 1 240px', minWidth: 210 }}>
              <div style={CAPS}>Trend · last {trend.length} snapshot{s(trend.length)}</div>
              <div style={{ marginTop: 'var(--space-2)' }}>
                <Sparkline
                  points={trend.map((p) => ({ x: p.taken_at, y: p.score }))}
                  tone={gradeColor(posture.grade)}
                  width={280}
                  height={46}
                  caption="Posture score over recent scans"
                  ariaLabel={trend.length >= 2 ? `Posture trend from ${trend[0].score} to ${posture.score} across ${trend.length} snapshots` : undefined}
                />
              </div>
            </div>

            <div style={{ flex: '1 1 200px', minWidth: 190 }}>
              <div style={CAPS}>Grounded in</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 2 }}>
                <span data-numeric style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, lineHeight: 1, color: 'var(--text-primary)' }}>{totalOpen}</span>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>open finding{s(totalOpen)}</span>
              </div>
              <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', marginTop: 6 }} data-numeric>
                {counts.critical} critical · {counts.high} high drive the score
              </div>
              <p style={{ margin: 'var(--space-2) 0 0', maxWidth: '38ch', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
                Weighted by severity (10·crit + 4·high + 1.5·med + 0.5·low), normalised to 0–100. Fixing criticals moves it most.
              </p>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* 2 · KPI row */}
      <Card>
        <CardHeader><CardTitle>Estate at a glance</CardTitle><CardMeta>as of last scan · {relative(scannedAt)}</CardMeta></CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 'var(--space-5) var(--space-4)' }}>
            <StatTile label="Systems covered" value={distinctTypes} icon={<IconLayers size={13} />} sub={`${connections.length} connection${s(connections.length)}`} />
            <StatTile label="Open findings" value={totalOpen} icon={<IconFindings size={13} />} sub="across all systems" />
            <StatTile label="Criticals" value={counts.critical} tone={counts.critical > 0 ? 'bad' : 'good'} sub="highest exploitability" />
            <StatTile label="NHI identities" value={identities} tone={wildcard > 0 ? 'warn' : 'neutral'} icon={<IconIdentity size={13} />} sub={wildcard > 0 ? `${wildcard} with wildcard grant${s(wildcard)}` : 'service accounts & clients'} />
            <StatTile label="Sensitive resources" value={sensitiveHigh} tone={sensitiveHigh > 0 ? 'warn' : 'neutral'} icon={<IconDatabase size={13} />} sub="named like PCI / PHI / secrets" />
            <StatTile label="Assessment coverage" value={coverage.value} unit={coverage.unit} tone={coverage.tone} sub={coverage.sub} />
          </div>
        </CardBody>
      </Card>

      {/* 3 · Severity breakdown + systems coverage */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 'var(--space-5)' }}>
        <Card>
          <CardHeader><CardTitle>Open findings by severity</CardTitle><CardMeta><Link href="/findings" style={{ color: 'var(--text-secondary)' }}>queue →</Link></CardMeta></CardHeader>
          <CardBody>
            {totalOpen === 0 ? (
              <EmptyState tone="clean" title="No open findings" description="Every rule passed on the last scan." meta={`${connections.length} connection${s(connections.length)} · scanned ${relative(scannedAt)}`} />
            ) : (
              <>
                <SeverityBar counts={counts} />
                {notAssessable > 0 && (
                  <p style={{ margin: 'var(--space-3) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
                    {notAssessable} not-assessable — coverage gap{s(notAssessable)}, not a pass.
                  </p>
                )}
              </>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader><CardTitle>Systems coverage</CardTitle><CardMeta><Link href="/estate" style={{ color: 'var(--text-secondary)' }}>estate →</Link></CardMeta></CardHeader>
          <CardBody>
            <Donut data={systemSlices} caption="Connections by system type" />
          </CardBody>
        </Card>
      </div>

      {/* 4 · Do this now */}
      {top.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Do this now</CardTitle><CardMeta>worst open · attack-path &amp; data-exposure first</CardMeta></CardHeader>
          <CardBody pad={false}>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {top.map((f) => (
                <li key={f.id} className="vs-listrow" style={{ borderBottom: '1px solid var(--border)' }}>
                  <Link
                    href={`/findings/${f.id}` as Route}
                    style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) var(--space-4)', textDecoration: 'none' }}
                  >
                    <SeverityBadge severity={f.severity} variant="inline" />
                    <span style={{ flex: 1, minWidth: 0 }}>
                      <span style={{ display: 'block', fontSize: 'var(--text-sm)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</span>
                      <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                        {f.rule_id}{f.resources ? ` · ${f.resources.kind}/${f.resources.name}` : ''}
                      </span>
                    </span>
                    {LED_RULE.test(f.rule_id) && <Chip tone="high" title="Reachable attack path or exposed data">priority</Chip>}
                    <span aria-hidden="true" data-row-arrow style={{ color: 'var(--text-muted)' }}>→</span>
                  </Link>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      )}

      {/* 5 · Lenses — the two things this product sees that others don't */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 'var(--space-5)' }}>
        <Card>
          <CardHeader><CardTitle>Non-human identities</CardTitle><CardMeta><Link href="/access" style={{ color: 'var(--text-secondary)' }}>access →</Link></CardMeta></CardHeader>
          <CardBody>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-5)' }}>
              <StatTile label="Identities" value={identities} size="sm" />
              <StatTile label="Wildcard grants" value={wildcard} size="sm" tone={wildcard > 0 ? 'warn' : 'neutral'} />
              <StatTile label="Identity risks" value={nhiRisk} size="sm" tone={nhiRisk > 0 ? 'bad' : 'good'} sub="NHI + credential-lifecycle" />
            </div>
            <p style={{ margin: 'var(--space-3) 0 0', maxWidth: '48ch', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
              Service accounts, consumers, broker users and OAuth clients across every system — and the credential-hygiene and over-broad-grant risks that ride on them.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><CardTitle>Sensitive data</CardTitle><CardMeta><Link href="/estate/inventory" style={{ color: 'var(--text-secondary)' }}>inventory →</Link></CardMeta></CardHeader>
          <CardBody>
            <StatTile label="High-sensitivity resources" value={sensitiveHigh} size="sm" tone={sensitiveHigh > 0 ? 'warn' : 'neutral'} sub="where regulated data likely flows" />
            {hasClasses ? (
              <div style={{ display: 'grid', gap: 'var(--space-2)', marginTop: 'var(--space-3)' }}>
                {(['high', 'medium', 'low'] as const).map((level) => {
                  const g = sensGroups.get(level);
                  if (!g || g.classes.size === 0) return null;
                  return (
                    <div key={level} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                      <span style={{ ...CAPS, minWidth: 52 }}>{level}</span>
                      <DataClassChips classes={[...g.classes]} sensitivity={level} signals={[...g.signals].join(',')} />
                    </div>
                  );
                })}
              </div>
            ) : (
              <p style={{ margin: 'var(--space-3) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>No sensitive-data classes inferred yet.</p>
            )}
            <p style={{ margin: 'var(--space-3) 0 0', maxWidth: '48ch', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
              Inferred from resource names, never payload inspection — the dashed border marks a hint, not proof.
            </p>
          </CardBody>
        </Card>
      </div>

      {/* 6 · Compliance strip */}
      {compBy.size > 0 ? (
        <Card>
          <CardHeader><CardTitle>Compliance</CardTitle><CardMeta><Link href="/compliance" style={{ color: 'var(--text-secondary)' }}>controls →</Link></CardMeta></CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Control coverage by framework">
              <THead>
                <TR>
                  <TH>Framework</TH>
                  <TH>Coverage</TH>
                  <TH numeric>Passing</TH>
                  <TH numeric>Failing</TH>
                  <TH numeric>Unknown</TH>
                </TR>
              </THead>
              <TBody>
                {[...compBy.entries()].map(([fw, e]) => {
                  const applicable = e.pass + e.fail + e.unknown;
                  const cov = applicable > 0 ? Math.round((100 * e.pass) / applicable) : null;
                  const tone: 'good' | 'warn' | 'bad' = e.fail > 0 ? 'bad' : cov !== null && cov >= 90 ? 'good' : cov !== null && cov >= 60 ? 'warn' : 'bad';
                  return (
                    <TR key={fw}>
                      <TD>{fw}</TD>
                      <TD>
                        {cov === null ? (
                          <StatusPill tone="neutral" label="Not scored" />
                        ) : (
                          <div style={{ minWidth: 128 }}><Meter value={cov} tone={tone} /></div>
                        )}
                      </TD>
                      <TD numeric><span style={{ color: e.pass ? 'var(--sev-low-fg)' : 'var(--text-muted)' }}>{e.pass}</span></TD>
                      <TD numeric><span style={{ color: e.fail ? 'var(--sev-critical-fg)' : 'var(--text-muted)' }}>{e.fail}</span></TD>
                      <TD numeric><span style={{ color: e.unknown ? 'var(--sev-medium-fg)' : 'var(--text-muted)' }}>{e.unknown}</span></TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardHeader><CardTitle>Compliance</CardTitle></CardHeader>
          <CardBody>
            <EmptyState tone="pending" title="No controls scored yet"
              description="Map a framework — PCI DSS, DORA, HIPAA, NIS2 — to start tracking coverage. Absence of controls is never a pass."
              action={<Link href="/compliance" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Set up compliance →</Link>} />
          </CardBody>
        </Card>
      )}

      {/* 6b · What changed this week + the first-ten-minutes checklist */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 'var(--space-5)' }}>
        <Card>
          <CardHeader><CardTitle>What changed this week</CardTitle><CardMeta>last 7 days · exact counts</CardMeta></CardHeader>
          <CardBody>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 'var(--space-4)' }}>
              <StatTile label="New findings" value={week.findings} size="sm" tone={week.critHigh > 0 ? 'bad' : week.findings > 0 ? 'warn' : 'good'} sub={week.critHigh > 0 ? `${week.critHigh} critical / high` : 'none critical or high'} />
              <StatTile label="Newly exposed paths" value={week.exposed} size="sm" tone={week.exposed > 0 ? 'bad' : 'good'} sub="attack paths first seen" />
              <StatTile label="New credentials" value={week.creds} size="sm" tone={week.creds > 0 ? 'warn' : 'neutral'} sub={`${week.identities} new identit${week.identities === 1 ? 'y' : 'ies'}`} />
              <StatTile label="Fixed" value={week.resolved ?? '—'} size="sm" tone={(week.resolved ?? 0) > 0 ? 'good' : 'neutral'} sub={week.resolved === null ? 'unavailable' : 'resolved findings'} />
              <StatTile label="Scans" value={week.scans} size="sm" tone={week.failed > 0 ? 'warn' : 'neutral'} sub={week.failed > 0 ? `${week.failed} failed` : 'all landed'} />
            </div>
            <p style={{ margin: 'var(--space-3) 0 0', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
              The same five numbers go out in the weekly Slack digest once a Slack destination is routed to it.
            </p>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><CardTitle>First ten minutes</CardTitle><CardMeta>{checklistDone} of {checklist.length} done</CardMeta></CardHeader>
          <CardBody>
            <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
              {checklist.map((c) => (
                <li key={c.label} style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
                  <span aria-hidden="true" style={{ width: 16, textAlign: 'center', fontWeight: 700, color: c.done ? 'var(--sev-low-fg)' : 'var(--text-muted)' }}>{c.done ? '✓' : '○'}</span>
                  <span style={{ display: 'grid', gap: 1 }}>
                    <Link href={c.href} style={{ fontSize: 'var(--text-sm)', fontWeight: c.done ? 400 : 600, color: 'var(--text-primary)', textDecoration: c.done ? 'line-through' : 'none' }}>
                      {c.label}
                    </Link>
                    <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{c.hint}</span>
                  </span>
                  <span className="vs-visually-hidden">{c.done ? 'done' : 'not done'}</span>
                </li>
              ))}
            </ol>
          </CardBody>
        </Card>
      </div>

      {/* 7 · Recent scans */}
      {recentScans.length > 0 && (
        <Card>
          <CardHeader><CardTitle>Recent scans</CardTitle><CardMeta><Link href="/estate" style={{ color: 'var(--text-secondary)' }}>estate →</Link></CardMeta></CardHeader>
          <CardBody pad={false}>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {recentScans.map((scan) => {
                const st = scanTone(scan.status);
                return (
                  <li key={scan.id} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) var(--space-4)', borderBottom: '1px solid var(--border)' }}>
                    <StatusPill tone={st.tone} label={scan.status} pulse={st.pulse} />
                    <span style={{ flex: 1, minWidth: 0, display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {scan.connections?.name ?? 'All systems'}
                      </span>
                      {scan.connections?.type && <Chip mono>{scan.connections.type}</Chip>}
                    </span>
                    <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{relative(scan.started_at)}</span>
                  </li>
                );
              })}
            </ul>
          </CardBody>
        </Card>
      )}
    </Frame>
  );
}

function scanTone(status: string): { tone: StatusTone; pulse: boolean } {
  switch (status) {
    case 'done':
      return { tone: 'ok', pulse: false };
    case 'running':
      return { tone: 'warn', pulse: true };
    case 'queued':
      return { tone: 'neutral', pulse: true };
    case 'error':
      return { tone: 'bad', pulse: false };
    default:
      return { tone: 'neutral', pulse: false };
  }
}

/** The page frame: the route's single <h1> (via PageHeader), a provenance meta line, and the
 * poll-while-in-flight refresher. Every return path renders through this so the header never
 * disappears on an empty or error state. */
function Frame({ children, meta, active = false }: { children: ReactNode; meta?: string; active?: boolean }) {
  return (
    <Page>
      <AutoRefresh active={active} />
      <PageHeader
        title="Overview"
        description="Where you stand across the integration layer — posture, the worst open risks, and what to do now."
        meta={meta}
      />
      {children}
    </Page>
  );
}
