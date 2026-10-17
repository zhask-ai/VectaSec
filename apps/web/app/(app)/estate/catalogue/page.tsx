import Link from 'next/link';
import type { Route } from 'next';

import { engineGet } from '@/lib/engine';
import { canEdit, getOwnMembership } from '@/lib/role';
import { createClient, getVerifiedUser } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Severity } from '@/lib/types';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { IconFindings, IconLayers, IconPlug, IconShieldCheck } from '@/components/ui/icons';
import { Page } from '@/components/ui/page';
import { PageHeader, SectionHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill } from '@/components/ui/status-pill';
import { EstateTabs } from '../tabs';
import { Donut } from '@/components/charts/Donut';
// The connect flow is one component shared by both tabs of this section: connecting from the
// catalogue must open the same drawer, not bounce the user to the other tab to start over.
import { ConnectDrawer } from '../connect-drawer';
import { SHELF, SWEEP_TYPE, onShelf } from '../shelf';

/* /estate/catalogue — "What we can assess". The falsifiable coverage catalogue.
 *
 * TWO TIERS (docs/vectasec-smb-strategy-2026-10.md §3, estate/shelf.ts): the twelve-card shelf an
 * SMB new to cloud recognises is shown open; the other 27 connectors sit under "Enterprise, on
 * request", collapsed. Every connector is still live in the engine and still connectable — the
 * tier is what a first session sees, not what the product supports.
 *
 * Three sources, three trust levels, kept honestly separate:
 *
 *   1. WHAT WE CAN ASSESS — the connector registry (rule counts + input fields per system).
 *      Authoritative and live from the engine (GET /connectors); the local CATEGORIES map below
 *      only GROUPS and LABELS those types, it never invents a rule count. If the engine can't be
 *      reached the catalogue still renders (from the local map) but says so and shows no counts —
 *      a coverage page that fabricates numbers is the one thing worse than a blank one.
 *
 *   2. WHAT YOU HAVE CONNECTED — the tenant's `connections` rows (RLS-scoped), grouped by type,
 *      with live per-system open-finding tallies. Independent of the engine: your estate is real
 *      whether or not the registry answered.
 *
 *   3. WHAT WE DO NOT YET SUPPORT — a short, curated, hardcoded roadmap list. Named out loud
 *      because "we cover everything" is a lie and a security buyer can smell it; the honest gap
 *      is more persuasive than the boast.
 *
 * No count crosses the wire unbounded: connections are few (a human connects each), and the
 * per-connection open-finding read is count:'exact' with a bounded row sample that only feeds the
 * worst-severity mark — the same posture the /connections page proved.
 */

export const metadata = { title: 'Estate · What we can assess · VectaSec' };

/** Bound on the per-connection open-finding sample (feeds the worst-severity mark only; the open
 * COUNT beside it is count:'exact' and is never truncated). Mirrors /connections. */
const LIST_LIMIT = 500;

/* ── The category map (LOCAL — grouping + labels only; rule counts come from the engine) ──── */

type CategoryDef = {
  id: string;
  label: string;
  /** One honest sentence: what this class of system is, and why its posture matters. */
  blurb: string;
  types: string[];
};

const CATEGORIES: CategoryDef[] = [
  {
    id: 'streaming',
    label: 'Message brokers & streaming',
    blurb: 'The event backbone — brokers, topics, ACLs, schema governance and stream processors where a weak listener exposes everything downstream.',
    types: ['kafka', 'confluent', 'redpanda', 'schema_registry', 'kafka_connect', 'flink', 'pulsar', 'nats'],
  },
  {
    id: 'mom',
    label: 'Classic message-oriented middleware',
    blurb: 'Long-lived enterprise queues where guest access, weak TLS and over-broad vhosts persist for years.',
    types: ['rabbitmq', 'ibmmq', 'activemq', 'solace'],
  },
  {
    id: 'cloud',
    label: 'Cloud messaging',
    blurb: 'Managed queues, topics and event buses whose exposure lives in IAM policy, not in a config file.',
    types: ['aws', 'azure', 'gcp'],
  },
  {
    id: 'gateway',
    label: 'API gateways',
    blurb: 'The public edge — routes, plugins and consumer credentials that decide what the outside world can reach.',
    types: ['kong'],
  },
  {
    id: 'mesh',
    label: 'Service mesh & Kubernetes',
    blurb: 'East-west traffic policy: mTLS posture, network policy and workload identity between services.',
    types: ['k8s'],
  },
  {
    id: 'ipaas',
    label: 'iPaaS & workflow automation',
    blurb: 'Low-code integration platforms that hold credentials to everything they connect — a single flow can reach production data.',
    types: ['n8n', 'mulesoft', 'boomi', 'workato'],
  },
  {
    id: 'coordination',
    label: 'Coordination & config',
    blurb: 'The cluster brain — service discovery and distributed config where an open endpoint hands over the whole topology.',
    types: ['coord'],
  },
  {
    id: 'vectordb',
    label: 'Vector databases',
    blurb: 'The AI retrieval layer — collections and namespaces holding embedded, often sensitive, source content.',
    types: ['vectordb'],
  },
  {
    id: 'mcp',
    label: 'MCP & agent gateways',
    blurb: 'Model Context Protocol servers and agent gateways: transport, auth and the exposed tool surface an agent can invoke.',
    types: ['mcp'],
  },
  {
    id: 'secrets',
    label: 'Secrets & identity',
    blurb: 'The trust roots — secret stores and identity providers whose misconfiguration compromises every consumer at once.',
    types: ['vault', 'keycloak'],
  },
  {
    id: 'datastore',
    label: 'Search, cache & proxy',
    blurb: 'Fast paths to data — search indices, caches and connection proxies that frequently ship unauthenticated by default.',
    types: ['elasticsearch', 'solr', 'memcached', 'pgbouncer', 'redis'],
  },
  {
    id: 'rpc',
    label: 'RPC & API contracts',
    blurb: 'Service-to-service contracts: introspection exposure, missing auth and over-permissive schemas.',
    types: ['graphql', 'grpc', 'openapi'],
  },
  {
    id: 'orchestration',
    label: 'Data orchestration',
    blurb: 'Pipeline schedulers holding connection credentials to every source and sink they move data between.',
    types: ['airflow'],
  },
  {
    id: 'mft',
    label: 'Managed file transfer & EDI',
    blurb: 'B2B file exchange — the partner-facing surface where a stale account or weak cipher becomes a supply-chain foothold.',
    types: ['mft'],
  },
  {
    id: 'iac',
    label: 'Integration-as-code',
    blurb: 'The manifests that deploy the estate. The only source that can see a credential committed to a repository — a running broker cannot tell you its password is also in git.',
    types: ['iac'],
  },
];

/** Human labels for the engine's type ids. Unknown types fall back to a prettified id — an
 * engine that registers a connector this map hasn't caught should still appear, never vanish. */
const TYPE_LABELS: Record<string, string> = {
  kafka: 'Apache Kafka',
  confluent: 'Confluent',
  redpanda: 'Redpanda',
  schema_registry: 'Schema Registry',
  kafka_connect: 'Kafka Connect',
  flink: 'Apache Flink',
  pulsar: 'Apache Pulsar',
  nats: 'NATS',
  rabbitmq: 'RabbitMQ',
  ibmmq: 'IBM MQ',
  activemq: 'ActiveMQ',
  solace: 'Solace',
  aws: 'AWS messaging',
  azure: 'Azure messaging',
  gcp: 'Google Cloud messaging',
  kong: 'Kong Gateway',
  k8s: 'Kubernetes',
  n8n: 'n8n',
  mulesoft: 'MuleSoft',
  boomi: 'Boomi',
  workato: 'Workato',
  coord: 'ZooKeeper / etcd',
  vectordb: 'Vector database',
  mcp: 'MCP server',
  vault: 'HashiCorp Vault',
  keycloak: 'Keycloak',
  elasticsearch: 'Elasticsearch',
  solr: 'Apache Solr',
  memcached: 'Memcached',
  pgbouncer: 'PgBouncer',
  redis: 'Redis',
  graphql: 'GraphQL',
  grpc: 'gRPC',
  openapi: 'OpenAPI / REST',
  airflow: 'Apache Airflow',
  mft: 'Managed file transfer',
  iac: 'Deployment manifests',
};

/** type id → category id. Built once; anything the engine reports that isn't mapped lands in
 * an honest "Other" bucket rather than being silently dropped. */
const CATEGORY_OF: Record<string, string> = Object.fromEntries(
  CATEGORIES.flatMap((cat) => cat.types.map((t): [string, string] => [t, cat.id])),
);

const OTHER: CategoryDef = {
  id: 'other',
  label: 'Other',
  blurb: 'Connectors the engine registers that this catalogue has not yet grouped.',
  types: [],
};

/** Named, honestly, as NOT covered today. The roadmap long-tail — a curated set, not the whole
 * universe. Being specific about the gap is what makes the coverage claim above credible. */
const NOT_YET_SUPPORTED: { name: string; note: string }[] = [
  { name: 'IBM Sterling / Cleo', note: 'MFT & B2B integration long-tail' },
  { name: 'Temporal', note: 'durable workflow execution' },
  { name: 'Debezium / Kafka Connect sink lineage', note: 'CDC sink attribution' },
  { name: 'Zapier / Make', note: 'SaaS workflow automation' },
  { name: 'TIBCO / Informatica / WSO2', note: 'legacy ESB & iPaaS' },
];

/* ── Engine + Supabase shapes ────────────────────────────────────────────── */

type ConnectorInfo = { type: string; rules?: number; fields?: unknown[] };
type ConnectorsResponse = { connectors: ConnectorInfo[] };

type ConnRow = { id: string; type: string; status: string; last_scanned_at: string | null };

type StatusTone = 'ok' | 'warn' | 'bad' | 'neutral';

/** One catalogued system, merged from the engine (authoritative counts) or, when the engine is
 * unreachable, from the local map (counts null). */
type SystemEntry = {
  type: string;
  label: string;
  categoryId: string;
  /** null = engine registry unavailable, count genuinely unknown (never render as 0). */
  rules: number | null;
  fieldCount: number | null;
};

/** Live rollup of the tenant's connections of a given type. */
type TypeRollup = {
  connCount: number;
  neverScanned: number;
  tone: StatusTone;
  toneLabel: string;
  /** Sum of count:'exact' open findings across this type's connections. Exact. */
  open: number;
  worstSev: Severity | null;
  /** Per-severity tallies from the bounded sample (approximate once `open` exceeds the cap). */
  sevCounts: Partial<Record<Severity, number>>;
};

function prettify(type: string): string {
  return String(type)
    .split(/[_\-]/)
    .map((w) => (w ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(' ');
}

/** Connection status → operational tone. Free text in the schema, so unknown values stay
 * neutral rather than being coerced to "fine". */
function statusTone(status: string): StatusTone {
  if (status === 'error' || status === 'offline') return 'bad';
  if (status === 'degraded' || status === 'pending' || status === 'queued') return 'warn';
  if (status === 'active' || status === 'done') return 'ok';
  return 'neutral';
}

const TONE_RANK: Record<StatusTone, number> = { bad: 0, warn: 1, neutral: 2, ok: 3 };

export default async function SystemsPage() {
  const supabase = await createClient();

  // Engine registry auth: same posture as every other engine read — tenant from the caller's
  // own membership row, actor from a server-confirmed user. Either being absent (build env, no
  // membership) simply means "coverage unavailable", handled gracefully below.
  const [membership, user] = await Promise.all([getOwnMembership(), getVerifiedUser()]);
  // Gates the connect action in the UI only; the Server Action re-checks the role, because a
  // hidden button is not an authorization boundary.
  const editable = canEdit(membership?.role);

  const coverage =
    membership && user
      ? await engineGet<ConnectorsResponse>('/connectors', { tenantId: membership.tenantId, actor: user.id })
      : null;
  // Narrow to the array (or null) so a false/absent result can never be read as `.data`.
  const connectors = coverage && coverage.ok ? coverage.data.connectors : null;
  const engineOk = connectors !== null;

  // Build the catalogue. Engine list is authoritative when present; the local map is the
  // graceful fallback (rule counts unknown, never faked).
  const entries: SystemEntry[] = connectors
    ? connectors.map((c) => ({
        type: c.type,
        label: TYPE_LABELS[c.type] ?? prettify(c.type),
        categoryId: CATEGORY_OF[c.type] ?? 'other',
        rules: typeof c.rules === 'number' ? c.rules : null,
        fieldCount: Array.isArray(c.fields) ? c.fields.length : null,
      }))
    : CATEGORIES.flatMap((cat) =>
        cat.types.map((t) => ({
          type: t,
          label: TYPE_LABELS[t] ?? prettify(t),
          categoryId: cat.id,
          rules: null,
          fieldCount: null,
        })),
      );

  // The tenant's estate — RLS-scoped, independent of the engine. `config` is never selected
  // (it carries credential refs); a column never fetched can't be leaked downstream.
  const connRes = await supabase.from('connections').select('id, type, status, last_scanned_at').order('type');
  const connError = connRes.error?.message ?? null;
  const connected = (connRes.data ?? []) as unknown as ConnRow[];

  // Per-connection open findings, one bounded query each (connections are few). findings hang off
  // a resource, so the inner join reaches connection_id and drops orphans; count:'exact' is the
  // true open count even when the row sample is capped.
  const findingResults = connError
    ? []
    : await Promise.all(
        connected.map(async (c) => {
          const res = await supabase
            .from('findings')
            .select('severity, resources!inner(connection_id)', { count: 'exact' })
            .eq('status', 'open')
            .eq('resources.connection_id', c.id)
            .limit(LIST_LIMIT);
          return { c, res };
        }),
      );
  // A failed finding read is not zero findings — degrade the mini-summaries to "unavailable"
  // rather than render reassuring zeros on a coverage page.
  const findingsError = findingResults.some((f) => f.res.error);

  // Roll up connections + findings by type.
  const rollup = new Map<string, TypeRollup>();
  for (const c of connected) {
    const r =
      rollup.get(c.type) ??
      ({ connCount: 0, neverScanned: 0, tone: 'ok', toneLabel: 'connected', open: 0, worstSev: null, sevCounts: {} } as TypeRollup);
    r.connCount += 1;
    if (!c.last_scanned_at) r.neverScanned += 1;
    const tone = statusTone(c.status);
    if (TONE_RANK[tone] < TONE_RANK[r.tone]) {
      r.tone = tone;
      r.toneLabel = c.status;
    }
    rollup.set(c.type, r);
  }
  if (!findingsError) {
    for (const { c, res } of findingResults) {
      const r = rollup.get(c.type);
      if (!r) continue;
      r.open += res.count ?? 0;
      const sevs = ((res.data ?? []) as unknown as { severity: Severity }[]).map((f) => f.severity);
      for (const s of sevs) {
        r.sevCounts[s] = (r.sevCounts[s] ?? 0) + 1;
        if (r.worstSev === null || SEVERITY_RANK[s] < SEVERITY_RANK[r.worstSev]) r.worstSev = s;
      }
    }
  }

  // Tiering: shelf types (and the sweep) are rendered above; the category grouping below is the
  // enterprise tier only, so a connector never appears twice.
  const shelfTypes = entries.filter((e) => onShelf(e.type)).map((e) => e.type);
  const sweepEntry = entries.find((e) => e.type === SWEEP_TYPE) ?? null;
  const enterpriseEntries = entries.filter((e) => !onShelf(e.type) && e.type !== SWEEP_TYPE);
  const shelfConnected = shelfTypes.filter((t) => (rollup.get(t)?.connCount ?? 0) > 0).length;
  const enterpriseConnected = enterpriseEntries.filter((e) => (rollup.get(e.type)?.connCount ?? 0) > 0).length;

  // Group the ENTERPRISE entries by category, in the fixed category order (+ Other last).
  const byCategory = new Map<string, SystemEntry[]>();
  for (const e of enterpriseEntries) {
    const list = byCategory.get(e.categoryId) ?? [];
    list.push(e);
    byCategory.set(e.categoryId, list);
  }
  const orderedCategories = [...CATEGORIES, OTHER].filter((cat) => (byCategory.get(cat.id)?.length ?? 0) > 0);

  // Estate totals.
  const totalConnectors = entries.length;
  const totalRules = engineOk ? entries.reduce((s, e) => s + (e.rules ?? 0), 0) : null;
  const connectedTypes = rollup.size;
  const brokenTypes = [...rollup.values()].filter((r) => r.tone === 'bad').length;
  const totalOpen = findingsError ? null : [...rollup.values()].reduce((s, r) => s + r.open, 0);

  // Donut: connections by category (nominal distribution — categorical palette, never status).
  const catConn = new Map<string, number>();
  for (const c of connected) {
    const cat = CATEGORY_OF[c.type] ?? 'other';
    catConn.set(cat, (catConn.get(cat) ?? 0) + 1);
  }
  const donutData = [...CATEGORIES, OTHER]
    .map((cat) => ({ label: cat.label, value: catConn.get(cat.id) ?? 0 }))
    .filter((d) => d.value > 0);

  const headerMeta = engineOk
    ? `${totalConnectors} connectors · ${totalRules} detection rules · from engine registry`
    : 'coverage counts unavailable · catalogue from roadmap';

  return (
    <Page>
      <PageHeader
        title="Estate"
        description="What we can assess: the twelve systems on the shelf, the rest on request, and your connected estate with its live findings mapped onto both. This is the coverage claim, made falsifiable."
        meta={headerMeta}
        actions={editable ? <ConnectDrawer /> : undefined}
      />
      <EstateTabs />

      {!engineOk && (
        <Card style={{ borderColor: 'var(--sev-medium-solid)' }}>
          <CardBody>
            <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <StatusPill tone="warn" label="coverage unavailable" />
              <p style={{ margin: 0, maxWidth: '72ch', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-primary)' }}>
                Rule counts and input fields come live from the engine registry, which did not respond. The catalogue below
                still lists every system class VectaSec covers, and your connected estate and its findings are read from
                Supabase and unaffected — only the per-system rule counts are showing as “—”.
              </p>
            </div>
          </CardBody>
        </Card>
      )}

      {/* Estate summary tiles. */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)' }}>
        <Card hover>
          <CardBody>
            <StatTile
              label="Systems covered"
              value={totalConnectors}
              icon={<IconLayers size={13} />}
              sub={engineOk ? `across ${orderedCategories.length} categories` : 'from the roadmap catalogue'}
            />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Detection rules"
              value={totalRules ?? '—'}
              tone="neutral"
              icon={<IconShieldCheck size={13} />}
              sub={engineOk ? 'shipped in the engine registry' : 'engine registry unavailable'}
            />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Connected"
              value={connectedTypes}
              tone={brokenTypes > 0 ? 'warn' : 'neutral'}
              icon={<IconPlug size={13} />}
              sub={brokenTypes > 0 ? `${brokenTypes} with a broken connection` : 'system types in your tenant'}
            />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Open findings"
              value={totalOpen ?? '—'}
              tone={totalOpen && totalOpen > 0 ? 'bad' : 'neutral'}
              icon={<IconFindings size={13} />}
              sub={findingsError ? 'read failed — not zero' : 'attributed to a connected system'}
            />
          </CardBody>
        </Card>
      </div>

      {/* Connections-by-category distribution. */}
      <Card>
        <CardHeader>
          <CardTitle>Where your estate sits</CardTitle>
          <CardMeta>connections by system class · RLS-scoped</CardMeta>
        </CardHeader>
        <CardBody>
          {donutData.length > 0 ? (
            <Donut data={donutData} caption="Connections by system class" />
          ) : connError ? (
            <EmptyState tone="error" title="Could not load your connections" description={connError} />
          ) : (
            <EmptyState
              tone="setup"
              title="No systems connected yet"
              description="The catalogue below is what VectaSec can assess. Connect a system to map your own estate onto it."
              // Opens the drawer in place. A link to the other tab made "Connect a system"
              // mean "go somewhere that has a connect button", which is one click of nothing.
              action={editable ? <ConnectDrawer label="Connect a system" /> : undefined}
            />
          )}
        </CardBody>
      </Card>

      {/* Tier 1 — the shelf. A card can front several connector types; counts are summed. */}
      <section style={{ display: 'grid', gap: 'var(--space-3)' }}>
        <SectionHeader
          title="On the shelf"
          meta={`${SHELF.length} cards · ${shelfTypes.length} connectors · ${shelfConnected} connected`}
        />
        <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-secondary)' }}>
          The systems a team new to cloud actually runs. Each connects read-only in minutes — a CloudFormation
          role, a read-only broker user, a service account — and feeds the Access register and the findings queue.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(238px, 1fr))', gap: 'var(--space-3)' }}>
          {SHELF.map((card) => {
            const members = entries.filter((e) => card.types.includes(e.type));
            const merged: SystemEntry = {
              type: card.types.join(' · '),
              label: card.label,
              categoryId: card.id,
              rules: engineOk ? members.reduce((n, e) => n + (e.rules ?? 0), 0) : null,
              fieldCount: null,
            };
            const roll = mergeRollups(card.types.map((t) => rollup.get(t)));
            return <SystemCard key={card.id} entry={merged} rollup={roll} findingsError={findingsError} connError={connError} note={card.note} />;
          })}
        </div>
        {sweepEntry && (
          <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
            Plus the <strong style={{ color: 'var(--text-primary)' }}>network discovery sweep</strong> — the free external exposure
            scan behind the Unmonitored tab{sweepEntry.rules != null ? ` (${sweepEntry.rules} rules)` : ''}; no credentials needed.
          </p>
        )}
      </section>

      {/* Tier 2 — everything else, collapsed. Still grouped by class so a buyer who runs Solace
          finds it under the class they would look in. */}
      <details>
        <summary style={{ cursor: 'pointer', padding: 'var(--space-2) 0' }}>
          <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
            Enterprise, on request
          </span>
          <span style={{ marginLeft: 'var(--space-2)', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
            {enterpriseEntries.length} connectors · {enterpriseConnected} connected · fully supported, hidden by default
          </span>
        </summary>
        <div style={{ display: 'grid', gap: 'var(--space-5)', paddingTop: 'var(--space-3)' }}>
      {orderedCategories.map((cat) => {
        const list = (byCategory.get(cat.id) ?? []).slice().sort((a, b) => (b.rules ?? -1) - (a.rules ?? -1));
        const connectedInCat = list.filter((e) => (rollup.get(e.type)?.connCount ?? 0) > 0).length;
        const rulesInCat = engineOk ? list.reduce((s, e) => s + (e.rules ?? 0), 0) : null;
        return (
          <section key={cat.id} style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <SectionHeader
              title={cat.label}
              meta={
                `${list.length} system${list.length === 1 ? '' : 's'}` +
                (connectedInCat > 0 ? ` · ${connectedInCat} connected` : '') +
                (rulesInCat != null ? ` · ${rulesInCat} rules` : '')
              }
            />
            <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-secondary)' }}>
              {cat.blurb}
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(238px, 1fr))', gap: 'var(--space-3)' }}>
              {list.map((entry) => (
                <SystemCard key={entry.type} entry={entry} rollup={rollup.get(entry.type)} findingsError={findingsError} connError={connError} />
              ))}
            </div>
          </section>
        );
      })}
        </div>
      </details>

      {/* The honest gap. */}
      <section style={{ display: 'grid', gap: 'var(--space-3)' }}>
        <SectionHeader title="Not yet supported" meta="on the roadmap — not assessed today" />
        <Card>
          <CardBody>
            <p style={{ margin: '0 0 var(--space-3)', maxWidth: '80ch', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-secondary)' }}>
              VectaSec does not assess these today. They are named here rather than omitted: a coverage page you can
              trust is one that also tells you where the edges are.
            </p>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 'var(--space-2)' }}>
              {NOT_YET_SUPPORTED.map((item) => (
                <li key={item.name} style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', minWidth: 0 }}>
                  <StatusPill tone="neutral" label="planned" />
                  <span style={{ minWidth: 0 }}>
                    <span style={{ display: 'block', fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>{item.name}</span>
                    <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{item.note}</span>
                  </span>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      </section>
    </Page>
  );
}

/** Sum the per-type rollups behind one shelf card (Kafka = kafka + confluent + redpanda). The
 * worst tone and worst severity win; counts add. undefined when no member type is connected. */
function mergeRollups(parts: (TypeRollup | undefined)[]): TypeRollup | undefined {
  const present = parts.filter((p): p is TypeRollup => Boolean(p));
  if (present.length === 0) return undefined;
  const out: TypeRollup = { connCount: 0, neverScanned: 0, tone: 'ok', toneLabel: 'connected', open: 0, worstSev: null, sevCounts: {} };
  for (const p of present) {
    out.connCount += p.connCount;
    out.neverScanned += p.neverScanned;
    out.open += p.open;
    if (TONE_RANK[p.tone] < TONE_RANK[out.tone]) {
      out.tone = p.tone;
      out.toneLabel = p.toneLabel;
    }
    if (p.worstSev && (out.worstSev === null || SEVERITY_RANK[p.worstSev] < SEVERITY_RANK[out.worstSev])) out.worstSev = p.worstSev;
    for (const [sev, n] of Object.entries(p.sevCounts) as [Severity, number][]) out.sevCounts[sev] = (out.sevCounts[sev] ?? 0) + n;
  }
  return out;
}

/* ── System card ─────────────────────────────────────────────────────────── */

function SystemCard({
  entry,
  rollup,
  findingsError,
  connError,
  note,
}: {
  entry: SystemEntry;
  rollup: TypeRollup | undefined;
  findingsError: boolean;
  connError: string | null;
  /** Shelf cards only: where a related system lives ("MSK via AWS"). */
  note?: string;
}) {
  const connectedCount = rollup?.connCount ?? 0;
  const isConnected = connectedCount > 0;

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-2)', minWidth: 0 }}>
          {/* Name + rule count. */}
          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 'var(--space-2)' }}>
            <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {entry.label}
            </span>
            <span data-numeric style={{ flexShrink: 0, fontSize: 'var(--text-2xs)', fontWeight: 600, color: entry.rules == null ? 'var(--text-muted)' : 'var(--text-secondary)' }}>
              {entry.rules == null ? '—' : `${entry.rules} rules`}
            </span>
          </div>

          {/* Type id + input count (evidence — mono). */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <Chip mono>{entry.type}</Chip>
            {entry.fieldCount != null && (
              <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                {entry.fieldCount} input{entry.fieldCount === 1 ? '' : 's'}
              </span>
            )}
          </div>
          {note && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{note}</span>}

          <div style={{ height: 1, background: 'var(--border)' }} aria-hidden="true" />

          {/* Connection state. */}
          {connError ? (
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>connection status unavailable</span>
          ) : isConnected ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
              <StatusPill tone={rollup!.tone} label={rollup!.tone === 'bad' ? rollup!.toneLabel : `${connectedCount} connected`} />
              {rollup!.neverScanned > 0 && (
                <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)', fontWeight: 600 }}>
                  {rollup!.neverScanned} never scanned
                </span>
              )}
            </div>
          ) : (
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>not connected</span>
          )}

          {/* Finding mini-summary. */}
          {isConnected && !connError && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', flexWrap: 'wrap', minHeight: 16 }}>
              {findingsError ? (
                <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>findings unavailable</span>
              ) : rollup!.open === 0 ? (
                <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>no open findings</span>
              ) : rollup!.worstSev ? (
                <SeverityBadge severity={rollup!.worstSev} count={rollup!.open} />
              ) : (
                <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{rollup!.open} open</span>
              )}
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
}

