import type { Severity } from '@/lib/types';
import { createClient } from '@/lib/supabase/server';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* Supply chain — the components actually running, and the identifiers that reach a CVE feed.
 *
 * Why both identifiers are shown per row rather than hidden in the download: they reach
 * different feeds and the feeds disagree about coverage. RabbitMQ and NATS are invisible to
 * NVD (which the CPE reaches); Pulsar is invisible to OSV (which the PURL reaches); Kong is
 * invisible to both. A missing identifier is therefore a real, visible coverage gap for that
 * component, not a cosmetic omission — so the table shows exactly which feeds each component
 * can be looked up in.
 *
 * The version column repeats the discovery page's inference marker for the same reason: an
 * inferred version is what a CVE lookup will be performed against, so its provenance has to
 * travel with it.
 */

export const metadata = { title: 'Supply chain · VectaSec' };

// Mirrors sbom.py::CPE_VENDOR_PRODUCT. The first version of this map stored the vendor ONLY
// and reused `product` as the CPE product name — which silently emitted `konghq:kong` (real:
// `kong_gateway`), `nats:nats` (real: `nats_server`) and `elastic:opensearch` (real:
// `elasticsearch`), each next to a green "NVD" pill. A user pasting one of those into NVD gets
// zero hits and concludes the broker is clean. Both HALVES of the pair must be mirrored, and
// the trailing `:*` components are part of a well-formed CPE 2.3 string, not decoration.
const CPE: Record<string, [vendor: string, product: string]> = {
  kafka: ['apache', 'kafka'], redis: ['redis', 'redis'], rabbitmq: ['vmware', 'rabbitmq'],
  kong: ['konghq', 'kong_gateway'], vault: ['hashicorp', 'vault'],
  elasticsearch: ['elastic', 'elasticsearch'], opensearch: ['elastic', 'elasticsearch'],
  pulsar: ['apache', 'pulsar'], nats: ['nats', 'nats_server'], etcd: ['etcd', 'etcd'],
  activemq: ['apache', 'activemq'], zookeeper: ['apache', 'zookeeper'],
  memcached: ['memcached', 'memcached'], solr: ['apache', 'solr'],
  consul: ['hashicorp', 'consul'],
};

function cpeFor(product: string, version: string): string | null {
  const pair = CPE[product];
  return pair ? `cpe:2.3:a:${pair[0]}:${pair[1]}:${version}:*:*:*:*:*:*:*` : null;
}
const BITNAMI = new Set([
  'kafka', 'redis', 'rabbitmq', 'vault', 'elasticsearch', 'nats', 'etcd',
  'activemq', 'zookeeper', 'memcached', 'solr', 'consul', 'valkey',
]);

type ResourceRow = {
  id: string;
  kind: string;
  name: string;
  labels: Record<string, string> | null;
  raw: Record<string, unknown> | null;
  connections: { type: string } | null;
};

type Component = {
  id: string;
  product: string;
  version: string;
  inferred: boolean;
  purl: string | null;
  cpe: string | null;
  where: string;
  probed: boolean;
};

function versionOf(raw: Record<string, unknown> | null, labels: Record<string, string> | null) {
  const r = raw ?? {};
  for (const key of ['version', 'redis_version', 'rabbitmq_version', 'broker_version', 'kafka_version', 'etcdserver']) {
    const v = r[key];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  const l = labels?.version;
  return typeof l === 'string' && l.trim() ? l.trim() : null;
}

type OsvFinding = {
  id: string;
  rule_id: string;
  severity: Severity;
  status: string;
  assessment: string | null;
  detail: string | null;
  last_seen: string | null;
  resources: { name: string } | null;
  scans: { connections: { name: string } | null } | null;
};

export default async function SupplyChainPage() {
  const supabase = await createClient();
  const [{ data }, { data: osvData }] = await Promise.all([
    supabase
      .from('resources')
      .select('id, kind, name, labels, raw, connections(type)')
      .limit(1000),
    supabase
      .from('findings')
      .select('id, rule_id, severity, status, assessment, detail, last_seen, resources(name), scans(connections(name))')
      .like('rule_id', 'SUPPLY.OSV.%')
      .neq('status', 'resolved')
      .order('last_seen', { ascending: false })
      .limit(50),
  ]);

  const rows = (data ?? []) as unknown as ResourceRow[];
  const osvFindings = (osvData ?? []) as unknown as OsvFinding[];
  const feedGaps = osvFindings.filter((f) => f.rule_id === 'SUPPLY.OSV.NOT_ASSESSABLE');
  const feedHits = osvFindings.filter((f) => f.rule_id === 'SUPPLY.OSV.KNOWN_VULNERABILITY');
  const seen = new Set<string>();
  const components: Component[] = [];

  for (const r of rows) {
    const labels = r.labels ?? {};
    const raw = r.raw ?? {};
    const product = String(labels.product ?? raw.product ?? r.connections?.type ?? '').toLowerCase();
    const version = versionOf(raw, labels);
    if (!product || !version) continue;
    // One row per (product, version): five brokers of the same version are one supply-chain
    // fact, and listing them five times would misrepresent the exposure as five problems.
    const key = `${product}@${version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    components.push({
      id: r.id,
      product,
      version,
      inferred: labels.version_inferred === 'true' || raw.version_inferred === true,
      purl: BITNAMI.has(product) ? `pkg:bitnami/${product}@${version}` : null,
      cpe: cpeFor(product, version),
      where: r.name,
      probed: r.kind === 'discovered_service',
    });
  }
  components.sort((a, b) => a.product.localeCompare(b.product) || a.version.localeCompare(b.version));

  const anyProbed = components.some((c) => c.probed);
  const unreachable = components.filter((c) => !c.purl && !c.cpe);

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <PageHeader
        title="Supply chain"
        description="The component versions actually running in the estate, with the identifiers that reach a vulnerability feed."
        meta={components.length ? `${components.length} distinct component${components.length === 1 ? '' : 's'}` : undefined}
      />

      <Card>
        <CardHeader>
          <CardTitle>Export</CardTitle>
          <CardMeta>CycloneDX 1.6 · a build SBOM cannot describe what is running</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <a
              href="/api/reports/sbom"
              style={{
                padding: '9px 14px',
                background: 'var(--accent)',
                color: 'var(--accent-fg)',
                border: '1px solid var(--border-interactive)',
                borderRadius: 'var(--radius-sm, 6px)',
                fontSize: 'var(--text-sm)',
                fontWeight: 600,
                textDecoration: 'none',
              }}
            >
              Download SBOM
            </a>
            <StatusPill
              tone={anyProbed ? 'warn' : 'ok'}
              label={anyProbed ? 'lifecycle: discovery' : 'lifecycle: operations'}
            />
          </div>
          <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
            {anyProbed
              ? 'Some versions here were read by an unauthenticated network probe, so the document declares the weaker `discovery` lifecycle phase rather than the flattering one.'
              : 'Every version was read by an authenticated connector, so the document declares the `operations` lifecycle phase.'}{' '}
            It also declares itself an incomplete inventory — a scanner sees the systems it was
            pointed at, never a whole software supply chain.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Live OSV feed</CardTitle>
          <CardMeta>
            queried after every scan for each component with a purl — OSV matches the exact
            running version server-side
          </CardMeta>
        </CardHeader>
        <CardBody pad={osvFindings.length === 0}>
          {osvFindings.length === 0 ? (
            <EmptyState
              tone="setup"
              title="No feed results recorded yet"
              description="The OSV enrichment runs automatically after each scan. Scan a connection whose connector reads a product version, or check that the engine has egress to api.osv.dev (VECTASEC_OSV_DISABLED skips the check deliberately)."
            />
          ) : (
            <Table density="default" caption="OSV feed results per component">
              <THead>
                <TR>
                  <TH width="12%">Severity</TH>
                  <TH width="66%">Result</TH>
                  <TH width="12%">Status</TH>
                  <TH width="10%">Last seen</TH>
                </TR>
              </THead>
              <TBody>
                {feedHits.map((f) => (
                  <TR key={f.id}>
                    <TD>
                      <SeverityBadge severity={f.severity} />
                    </TD>
                    <TD>
                      <div style={{ display: 'grid', gap: 2 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere' }}>
                          {f.detail ?? '—'}
                        </span>
                        {/* The same broker can be observed by more than one connection (its own
                            connector AND a network-discovery probe), each filing its own
                            finding — name the observer so twin rows read as two viewpoints,
                            not a duplicate. */}
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                          {f.resources?.name ?? 'component'}
                          {f.scans?.connections?.name ? ` · via ${f.scans.connections.name}` : ''}
                        </span>
                      </div>
                    </TD>
                    <TD>
                      <StatusPill
                        tone={f.status === 'open' ? 'warn' : 'neutral'}
                        label={f.status}
                      />
                    </TD>
                    <TD muted>
                      <span style={{ fontSize: 'var(--text-2xs)' }}>
                        {f.last_seen ? f.last_seen.slice(0, 10) : '—'}
                      </span>
                    </TD>
                  </TR>
                ))}
                {feedGaps.map((f) => (
                  <TR key={f.id}>
                    <TD>
                      <StatusPill tone="warn" label="feed gap" />
                    </TD>
                    <TD>
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                        The feed could not be consulted — an unqueried feed is not a clean
                        feed, so this is recorded rather than silently skipped.
                      </span>
                    </TD>
                    <TD>
                      <StatusPill tone="neutral" label="not assessable" />
                    </TD>
                    <TD muted>
                      <span style={{ fontSize: 'var(--text-2xs)' }}>
                        {f.last_seen ? f.last_seen.slice(0, 10) : '—'}
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Components</CardTitle>
          <CardMeta>
            each carries both identifiers where they exist — they reach different feeds
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {components.length === 0 ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState
                tone="setup"
                title="No component versions yet"
                description="Connect and scan a system. Any connector that reads a product version contributes to the estate SBOM."
              />
            </div>
          ) : (
            <Table density="default" caption="Component versions running in the estate">
              <THead>
                <TR>
                  <TH width="16%">Product</TH>
                  <TH width="14%">Version</TH>
                  <TH width="16%">Feeds reachable</TH>
                  <TH width="54%">Identifiers</TH>
                </TR>
              </THead>
              <TBody>
                {components.map((c) => (
                  <TR key={`${c.product}-${c.version}`}>
                    <TD>
                      <span style={{ fontWeight: 600 }}>{c.product}</span>
                    </TD>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>
                        {c.version}
                      </span>
                      {c.inferred && (
                        <div
                          title="Derived from advertised protocol capabilities — no version string was disclosed. CVE matching runs against this."
                          style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', borderBottom: '1px dashed var(--border)', display: 'inline-block' }}
                        >
                          inferred
                        </div>
                      )}
                    </TD>
                    <TD>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        <StatusPill tone={c.purl ? 'ok' : 'neutral'} label={c.purl ? 'OSV' : 'no OSV'} />
                        <StatusPill tone={c.cpe ? 'ok' : 'neutral'} label={c.cpe ? 'NVD' : 'no NVD'} />
                      </div>
                    </TD>
                    <TD>
                      <div style={{ display: 'grid', gap: 2, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere' }}>
                        {c.purl && <span>{c.purl}</span>}
                        {c.cpe && <span style={{ color: 'var(--text-secondary)' }}>{c.cpe}</span>}
                        {!c.purl && !c.cpe && (
                          <span style={{ color: 'var(--sev-medium-fg)' }}>
                            no vulnerability identifier exists for this product
                          </span>
                        )}
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      {unreachable.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Vulnerability-feed gaps</CardTitle>
            <CardMeta>components no public feed can be queried for</CardMeta>
          </CardHeader>
          <CardBody>
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
              {unreachable.map((c) => `${c.product} ${c.version}`).join(', ')}
            </p>
            <p style={{ margin: '8px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
              These are running, and identified, but neither OSV nor NVD indexes them under an
              identifier we can construct. That is a gap in the public feeds rather than in this
              scan — and it means an empty CVE result for them proves nothing.
            </p>
          </CardBody>
        </Card>
      )}
    </div>
  );
}
