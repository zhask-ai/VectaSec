import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Severity } from '@/lib/types';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader, SectionHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { Donut } from '@/components/charts/Donut';

import { DataFilters } from './data-filters';

/* Data (DSPM) — the data-security posture surface.
 *
 * Answers "where does sensitive data live across the integration layer, how sensitive is it, and
 * where is it exposed". Reads REAL data under RLS like every console page: the sensitive-resource
 * inventory (resources whose derived `data_sensitivity` label is not 'none') and the DATA.* finding
 * family (DATA.SENSITIVE.INVENTORY + the DATA.EXPOSURE.* toxic combinations).
 *
 * HONESTY IS THE POINT. VectaSec reads configuration and naming, never payloads. A class here means
 * a resource is *named like* it carries that data — never that it is proven to. So every data-class
 * mark is dashed (inferred), the framing says "named like" not "contains", and empty states never
 * imply "clean/secure" when we simply have nothing classified yet.
 *
 * COUNTS caveat: unbounded PostgREST selects cap at Max Rows (~1000) on hosted, so headline totals
 * come from exact `head` counts and the tables/breakdowns are bounded by an explicit limit; when the
 * two disagree the view says so rather than silently truncating.
 */

export const metadata = { title: 'Data · VectaSec' };

const ROW_CAP = 1000;

type ResourceRow = {
  id: string;
  name: string;
  kind: string | null;
  labels: Record<string, string> | null;
  connections?: { type: string; name: string } | null;
};

type DataFindingRow = { id: string; rule_id: string; severity: Severity; status: string; resource_id: string | null };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

function lbl(r: { labels: Record<string, string> | null }, k: string): string {
  return (r.labels ?? {})[k] ?? '';
}

function lblList(r: { labels: Record<string, string> | null }, k: string): string[] {
  const v = lbl(r, k);
  return v ? v.split(',').map((s) => s.trim()).filter(Boolean) : [];
}

function leaf(name: string): string {
  return (name || '').split(':').pop() || name;
}

function one(v: string | string[] | undefined): string {
  return typeof v === 'string' ? v : '';
}

const SENS_RANK: Record<string, number> = { high: 0, medium: 1, low: 2, none: 3 };

const SENS_LEVELS = [
  { key: 'high', label: 'High', solid: 'var(--sev-high-solid)', fg: 'var(--sev-high-fg)' },
  { key: 'medium', label: 'Medium', solid: 'var(--sev-medium-solid)', fg: 'var(--sev-medium-fg)' },
  { key: 'low', label: 'Low', solid: 'var(--sev-low-solid)', fg: 'var(--sev-low-fg)' },
] as const;

type DataRow = {
  id: string;
  name: string;
  kind: string;
  system: string;
  connector: { type: string; name: string } | null;
  dataClasses: string[];
  sensitivity: string;
  signals: string;
};

function prettyExposure(ruleId: string): string {
  const suffix = (ruleId || '').split('.').pop() || ruleId;
  return suffix.replace(/_/g, ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase());
}

export default async function DataPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const fClass = one(sp['class']);
  const fSensitivity = one(sp.sensitivity);
  const fSystem = one(sp.system);

  const supabase = await createClient();

  // Exact head counts for the headline KPIs (accurate beyond the row cap), plus the bounded
  // inventory and the DATA.* finding family. jsonb labels are filtered with the `->>` operator.
  const [sensCountRes, highCountRes, exposureCountRes, resourcesRes, findingsRes] = await Promise.all([
    supabase.from('resources').select('*', { count: 'exact', head: true }).neq('labels->>data_sensitivity', 'none'),
    supabase.from('resources').select('*', { count: 'exact', head: true }).eq('labels->>data_sensitivity', 'high'),
    supabase.from('findings').select('*', { count: 'exact', head: true }).like('rule_id', 'DATA.EXPOSURE.%'),
    supabase
      .from('resources')
      .select('id, name, kind, labels, connections(type, name)')
      .neq('labels->>data_sensitivity', 'none')
      .order('name')
      .limit(ROW_CAP),
    supabase.from('findings').select('id, rule_id, severity, status, resource_id').like('rule_id', 'DATA.%').limit(ROW_CAP),
  ]);

  const err = resourcesRes.error ?? findingsRes.error;
  if (err) {
    return (
      <Page>
        <PageHeader title="Data" description="Data-security posture across the integration layer." />
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load data posture" description={err.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const resources = (resourcesRes.data ?? []) as unknown as ResourceRow[];
  const findings = (findingsRes.data ?? []) as unknown as DataFindingRow[];

  const rows: DataRow[] = resources.map((r) => ({
    id: r.id,
    name: r.name,
    kind: r.kind ?? '',
    system: lbl(r, 'system'),
    connector: r.connections ?? null,
    dataClasses: lblList(r, 'data_classes'),
    sensitivity: lbl(r, 'data_sensitivity') || 'none',
    signals: lbl(r, 'data_signals'),
  }));
  const rowById = new Map(rows.map((r) => [r.id, r]));

  const exactTotal = sensCountRes.count ?? rows.length;
  const highTotal = highCountRes.count ?? rows.filter((r) => r.sensitivity === 'high').length;
  const exposureTotal = exposureCountRes.count ?? findings.filter((f) => f.rule_id.startsWith('DATA.EXPOSURE.')).length;
  const distinctClasses = new Set(rows.flatMap((r) => r.dataClasses));
  const truncated = rows.length < exactTotal;

  // Honest empty: nothing classified and no DATA.* findings yet. Never implies "clean/secure".
  if (rows.length === 0 && findings.length === 0) {
    return (
      <Page>
        <SetupState />
      </Page>
    );
  }

  // Filter options + filtered inventory (over the bounded loaded set).
  const systemOptions = [...new Set(rows.map((r) => r.system).filter(Boolean))].sort();
  const classOptions = [...new Set(rows.flatMap((r) => r.dataClasses))].sort();
  const sensitivityOptions = SENS_LEVELS.map((l) => l.key).filter((k) => rows.some((r) => r.sensitivity === k));
  const filtered = rows.filter(
    (r) =>
      (!fClass || r.dataClasses.includes(fClass)) &&
      (!fSensitivity || r.sensitivity === fSensitivity) &&
      (!fSystem || r.system === fSystem),
  );
  const filtersActive = Boolean(fClass || fSensitivity || fSystem);

  // Sensitivity breakdown (loaded rows). Fixed keys so indexing stays fully typed.
  const sensCounts = { high: 0, medium: 0, low: 0 };
  for (const r of rows) {
    if (r.sensitivity === 'high') sensCounts.high += 1;
    else if (r.sensitivity === 'medium') sensCounts.medium += 1;
    else if (r.sensitivity === 'low') sensCounts.low += 1;
  }
  const sensTotal = sensCounts.high + sensCounts.medium + sensCounts.low;

  // Data-class distribution (loaded rows): count + the strongest sensitivity carrying each class.
  const classMap = new Map<string, { cls: string; count: number; sens: string }>();
  for (const r of rows)
    for (const c of r.dataClasses) {
      const ex = classMap.get(c);
      if (!ex) classMap.set(c, { cls: c, count: 1, sens: r.sensitivity });
      else {
        ex.count += 1;
        if ((SENS_RANK[r.sensitivity] ?? 3) < (SENS_RANK[ex.sens] ?? 3)) ex.sens = r.sensitivity;
      }
    }
  const classAggs = [...classMap.values()].sort((a, b) => b.count - a.count);

  // Distribution by system (nominal → the categorical Donut). Tail grouped into "other".
  const bySystem = new Map<string, number>();
  for (const r of rows) {
    const s = r.system || 'unlabeled';
    bySystem.set(s, (bySystem.get(s) ?? 0) + 1);
  }
  const systemSlicesAll = [...bySystem.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
  const systemSlices = systemSlicesAll.slice(0, 7);
  const systemRest = systemSlicesAll.slice(7);
  if (systemRest.length) systemSlices.push({ label: 'other', value: systemRest.reduce((s, x) => s + x.value, 0) });

  // Exposure callouts: the DATA.EXPOSURE.* toxic combinations, worst-first.
  const exposure = findings
    .filter((f) => f.rule_id.startsWith('DATA.EXPOSURE.'))
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
  const exposureTruncated = exposure.length < exposureTotal;

  return (
    <Page>
      <PageHeader
        title="Data"
        description="Where sensitive data (PCI, PHI, PII, secrets) flows through the integration layer, which systems carry it, and where it sits exposed — inferred from naming, never from payloads."
        meta={`${exactTotal} sensitive resources · ${systemOptions.length} system${systemOptions.length === 1 ? '' : 's'}`}
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 'var(--space-3)' }}>
        <KpiCard>
          <StatTile label="Sensitive resources" value={exactTotal} sub="named like they carry sensitive data" />
        </KpiCard>
        <KpiCard>
          <StatTile label="High sensitivity" value={highTotal} tone={highTotal ? 'warn' : 'good'} sub="PCI / PHI / secrets-class naming" />
        </KpiCard>
        <KpiCard>
          <StatTile label="Data classes" value={distinctClasses.size} sub={`distinct classes${truncated ? ' in loaded set' : ''}`} />
        </KpiCard>
        <KpiCard>
          <StatTile label="Exposed sensitive" value={exposureTotal} tone={exposureTotal ? 'bad' : 'good'} sub="on a plaintext / open surface" />
        </KpiCard>
      </div>

      {/* Honesty framing — set the "named like, not proven" contract before the data. */}
      <Card>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
            <SectionHeader title="How this is classified" meta="inference, not payload inspection" />
            <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
              Classification is inferred from naming. VectaSec matches each resource&rsquo;s name against known tokens (for
              example <span style={{ fontFamily: 'var(--font-mono)' }}>payments</span>,{' '}
              <span style={{ fontFamily: 'var(--font-mono)' }}>ssn</span>,{' '}
              <span style={{ fontFamily: 'var(--font-mono)' }}>card</span>) — it never reads or inspects the data itself. A
              class here means a resource is <em>named like</em> it carries that data, not that it is proven to. Inferred
              classes carry a dashed border throughout, and every count states what it is drawn from.
            </p>
          </div>
        </CardBody>
      </Card>

      {/* Exposure callouts — the toxic combination, surfaced prominently. */}
      <Card>
        <CardHeader>
          <CardTitle>Exposed sensitive data</CardTitle>
          <CardMeta>
            {exposureTotal} DATA.EXPOSURE finding{exposureTotal === 1 ? '' : 's'}
            {exposureTruncated ? ` · showing first ${exposure.length}` : ''}
          </CardMeta>
        </CardHeader>
        <CardBody pad={exposure.length > 0}>
          {exposure.length === 0 ? (
            <EmptyState
              tone="clean"
              title="No sensitive-data exposures detected"
              description="No resource named like it carries sensitive data was found on a plaintext or unauthenticated surface (the DATA.EXPOSURE toxic combination)."
              meta={`${exactTotal} sensitive resources · DATA.EXPOSURE checks`}
            />
          ) : (
            <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
              <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
                Each is a toxic combination: a resource named like it carries sensitive data (DATA.SENSITIVE.INVENTORY)
                sitting on a plaintext or unauthenticated surface. Open the finding for the full evidence and reach.
              </p>
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
                {exposure.map((f) => {
                  const res = f.resource_id ? rowById.get(f.resource_id) : undefined;
                  return (
                    <li
                      key={f.id}
                      style={{
                        display: 'grid',
                        gap: 'var(--space-2)',
                        padding: 'var(--space-3)',
                        border: '1px solid var(--border)',
                        borderLeft: `3px solid var(--sev-${f.severity}-solid)`,
                        borderRadius: 'var(--radius-md)',
                        background: 'var(--surface)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                        <SeverityBadge severity={f.severity} />
                        <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {prettyExposure(f.rule_id)}
                        </span>
                        {f.status !== 'open' && <StatusPill tone="neutral" label={f.status} />}
                        <Link
                          href={`/findings/${f.id}` as Route}
                          style={{ marginLeft: 'auto', fontSize: 'var(--text-sm)', color: 'var(--text-primary)', whiteSpace: 'nowrap' }}
                        >
                          View finding &rarr;
                        </Link>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <Chip mono>{f.rule_id}</Chip>
                        {res ? (
                          <>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                              on {leaf(res.name)}
                            </span>
                            {res.dataClasses.length > 0 && (
                              <DataClassChips classes={res.dataClasses} sensitivity={res.sensitivity} signals={res.signals} />
                            )}
                          </>
                        ) : (
                          f.resource_id && (
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                              on {leaf(f.resource_id)}
                            </span>
                          )
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Sensitivity lens — by sensitivity, by data class, and where it lives. */}
      <SectionHeader title="Sensitivity lens" meta={`from ${rows.length} loaded resource${rows.length === 1 ? '' : 's'}`} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 'var(--space-3)', alignItems: 'stretch' }}>
        <Card>
          <CardHeader>
            <CardTitle>By sensitivity</CardTitle>
            <CardMeta>{sensTotal} classified</CardMeta>
          </CardHeader>
          <CardBody>
            {sensTotal === 0 ? (
              <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>No sensitivity levels to chart yet.</p>
            ) : (
              <SensitivityBreakdown counts={sensCounts} total={sensTotal} />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>By data class</CardTitle>
            <CardMeta>{classAggs.length} class{classAggs.length === 1 ? '' : 'es'} · inferred</CardMeta>
          </CardHeader>
          <CardBody>
            {classAggs.length === 0 ? (
              <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>No data classes inferred yet.</p>
            ) : (
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
                {classAggs.map((a) => (
                  <li key={a.cls} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
                    <DataClassChips classes={[a.cls]} sensitivity={a.sens} />
                    <span data-numeric style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
                      {a.count}
                    </span>
                    <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>resource{a.count === 1 ? '' : 's'}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Where it lives</CardTitle>
            <CardMeta>sensitive resources by system</CardMeta>
          </CardHeader>
          <CardBody>
            <Donut data={systemSlices} caption="Sensitive resources by system" />
          </CardBody>
        </Card>
      </div>

      {/* Sensitive-data inventory — the dense, filterable table. */}
      <Card>
        <CardHeader>
          <CardTitle>Sensitive-data inventory</CardTitle>
          <CardMeta>
            {filtersActive ? `${filtered.length} of ${rows.length} shown` : `${rows.length} resource${rows.length === 1 ? '' : 's'}`}
            {truncated ? ` · showing first ${rows.length} of ${exactTotal}` : ''}
          </CardMeta>
        </CardHeader>
        <CardBody>
          <DataFilters
            classes={classOptions}
            sensitivities={sensitivityOptions}
            systems={systemOptions}
            dataClass={fClass}
            sensitivity={fSensitivity}
            system={fSystem}
          />
        </CardBody>
        <CardBody pad={false}>
          {filtered.length === 0 ? (
            <EmptyState
              tone="filtered"
              title="No resources match these filters"
              description="No sensitive-data resource matches the current class, sensitivity and system filters."
              action={
                <Link href="/data" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                  Clear filters
                </Link>
              }
            />
          ) : (
            <Table density="default" caption="Resources named like they carry sensitive data">
              <THead>
                <TR>
                  <TH width="26%">Resource</TH>
                  <TH width="12%">System</TH>
                  <TH width="10%">Kind</TH>
                  <TH width="22%">Data classes</TH>
                  <TH width="10%">Sensitivity</TH>
                  <TH width="20%">Matched signals</TH>
                </TR>
              </THead>
              <TBody>
                {filtered.map((r) => (
                  <TR key={r.id}>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{leaf(r.name)}</span>
                      {r.connector && (
                        <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                          {r.connector.type}/{r.connector.name}
                        </span>
                      )}
                    </TD>
                    <TD mono>{r.system || '—'}</TD>
                    <TD>
                      <span style={{ color: 'var(--text-secondary)' }}>{r.kind || '—'}</span>
                    </TD>
                    <TD>
                      {r.dataClasses.length > 0 ? (
                        <DataClassChips classes={r.dataClasses} sensitivity={r.sensitivity} signals={r.signals} />
                      ) : (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>—</span>
                      )}
                    </TD>
                    <TD>
                      <SensTag level={r.sensitivity} />
                    </TD>
                    <TD>
                      {r.signals ? (
                        <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {r.signals
                            .split(',')
                            .map((s) => s.trim())
                            .filter(Boolean)
                            .slice(0, 4)
                            .map((s) => (
                              <Chip key={s} mono>
                                {s}
                              </Chip>
                            ))}
                        </span>
                      ) : (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>—</span>
                      )}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', maxWidth: 760 }}>
        The inventory is derived from what each connector already reads — Kafka topics, RabbitMQ queues, Kong routes, MCP
        tools — with data classes inferred from resource names, never from payload contents. &ldquo;Named like&rdquo; is a
        hint to investigate, not a proof of contents.
        {truncated ? ` Showing the first ${rows.length} of ${exactTotal}; refine with filters to narrow the set.` : ''}
      </p>
    </Page>
  );
}

function SensTag({ level }: { level: string }) {
  if (level === 'high') return <Chip tone="high">High</Chip>;
  if (level === 'medium') return <Chip tone="medium">Medium</Chip>;
  if (level === 'low') return <Chip tone="low">Low</Chip>;
  return <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>—</span>;
}

function SensitivityBreakdown({ counts, total }: { counts: { high: number; medium: number; low: number }; total: number }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
      <div
        style={{
          display: 'flex',
          height: 12,
          borderRadius: 'var(--radius-full)',
          overflow: 'hidden',
          border: '1px solid var(--border)',
          background: 'var(--surface-raised)',
        }}
      >
        {SENS_LEVELS.map((l) =>
          counts[l.key] > 0 ? (
            <div
              key={l.key}
              title={`${l.label}: ${counts[l.key]}`}
              style={{ width: `${(counts[l.key] / total) * 100}%`, background: l.solid }}
            />
          ) : null,
        )}
      </div>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
        {SENS_LEVELS.map((l) => (
          <li key={l.key} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span aria-hidden="true" style={{ width: 10, height: 10, borderRadius: 2, background: l.solid, flexShrink: 0 }} />
            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: l.fg }}>{l.label}</span>
            <span data-numeric style={{ marginLeft: 'auto', fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
              {counts[l.key]}
            </span>
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', width: 40, textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>
              {Math.round((counts[l.key] / total) * 100)}%
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function KpiCard({ children }: { children: React.ReactNode }) {
  return (
    <Card>
      <CardBody>{children}</CardBody>
    </Card>
  );
}

function Page({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>{children}</div>;
}

function SetupState() {
  const sources = ['Kafka topics', 'RabbitMQ queues', 'Kong routes', 'Redis keyspaces', 'MCP tools'];
  return (
    <>
      <PageHeader
        title="Data"
        description="Where sensitive data flows through your integration layer — inferred from naming, never from payloads."
      />
      <Card>
        <CardBody>
          <EmptyState
            tone="setup"
            title="No sensitive data classified yet"
            description="Connect and scan a system and any resource named like it carries sensitive data (PCI, PHI, PII, secrets) is classified here — inferred from the resource name, not from its contents."
            action={
              <Link href="/connections" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Go to Connections →
              </Link>
            }
          />
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', justifyContent: 'center', marginTop: 'var(--space-2)' }}>
            {sources.map((s) => (
              <Chip key={s}>{s}</Chip>
            ))}
          </div>
        </CardBody>
      </Card>
    </>
  );
}
