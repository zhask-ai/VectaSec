import type { Severity } from '@/lib/types';
import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { createClient, getVerifiedUser } from '@/lib/supabase/server';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { IconForType } from '@/components/ui/icons';
import { Page } from '@/components/ui/page';
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
// Re-verified against the live NVD API on 2026-08-03 alongside the engine's copy. Three entries
// were stale here after that check corrected them upstream — and a stale entry is not cosmetic:
// this table renders a copyable CPE next to a green "NVD" pill, so a user pasting the old
// `nats:nats_server` got zero results (the real pair is `linuxfoundation:nats-server`, 36 CVEs)
// and concluded the broker was clean. OpenSearch was borrowing Elasticsearch's pair, which both
// inherits Elastic's post-fork CVEs and misses OpenSearch's own.
const CPE: Record<string, [vendor: string, product: string]> = {
  kafka: ['apache', 'kafka'], redis: ['redis', 'redis'],
  rabbitmq: ['broadcom', 'rabbitmq_server'],
  kong: ['konghq', 'kong_gateway'], vault: ['hashicorp', 'vault'],
  elasticsearch: ['elastic', 'elasticsearch'], opensearch: ['amazon', 'opensearch'],
  pulsar: ['apache', 'pulsar'], nats: ['linuxfoundation', 'nats-server'], etcd: ['etcd', 'etcd'],
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

type LicenseRow = {
  product: string;
  version: string;
  known: boolean;
  licenses: string[];
  osi_approved: boolean | null;
  source_url: string | null;
  choice: boolean;
  connections: string[];
};
type LicensingResponse = {
  components: LicenseRow[];
  summary: { total: number; non_osi: number; unknown: number };
};

const exportBtn: React.CSSProperties = {
  display: 'inline-flex',
  alignItems: 'center',
  padding: '9px 14px',
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  fontSize: 'var(--text-sm)',
  fontWeight: 600,
  lineHeight: 1,
  textDecoration: 'none',
};

export default async function SupplyChainPage() {
  const supabase = await createClient();
  const [user, membership] = await Promise.all([getVerifiedUser(), getOwnMembership()]);
  // Licensing is resolved engine-side against the version we READ, because the terms are
  // version-dependent (Redis 7.2 is BSD, 7.4 is source-available, 8.0 is AGPL). Mirroring that
  // table into the browser would be a second copy to drift, and a drifted licence claim ends up
  // in somebody's compliance report.
  const licensingRes =
    user && membership
      ? await engineGet<LicensingResponse>('/licensing', {
          tenantId: membership.tenantId,
          actor: user.id,
        })
      : null;
  const licensing = licensingRes && licensingRes.ok ? licensingRes.data : null;
  // The one engine probe this page already makes doubles as the health check for everything
  // else engine-backed on it: the SBOM/VEX exports are generated engine-side, so when the
  // engine is unreachable those download links would 502. Say so up front instead.
  const engineDown = licensingRes !== null && !licensingRes.ok;
  const engineMsg = engineDown ? licensingRes.message : null;

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
    <Page>
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
            {engineDown ? (
              // Dead links dressed as downloads are worse than a stated limit: these documents
              // are generated engine-side, and this deployment cannot reach an engine.
              <>
                <span aria-disabled="true" style={{ ...exportBtn, background: 'var(--surface)', color: 'var(--text-muted)', borderColor: 'var(--border-strong)', cursor: 'not-allowed' }}>
                  Download SBOM
                </span>
                <span aria-disabled="true" style={{ ...exportBtn, background: 'var(--surface)', color: 'var(--text-muted)', borderColor: 'var(--border-strong)', cursor: 'not-allowed' }}>
                  Download VEX
                </span>
                <StatusPill tone="bad" label="engine unreachable" variant="soft" />
              </>
            ) : (
              <>
                <a href="/api/reports/sbom" className="vs-button" data-variant="primary" style={{ ...exportBtn, background: 'var(--accent)', color: 'var(--accent-fg)', borderColor: 'var(--accent)' }}>
                  Download SBOM
                </a>
                <a href="/api/reports/vex" className="vs-button" data-variant="secondary" style={{ ...exportBtn, background: 'var(--surface-raised)', color: 'var(--text-primary)' }}>
                  Download VEX
                </a>
                <StatusPill
                  tone={anyProbed ? 'warn' : 'ok'}
                  label={anyProbed ? 'lifecycle: discovery' : 'lifecycle: operations'}
                />
              </>
            )}
          </div>
          {engineDown && (
            <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
              {engineMsg} SBOM and VEX are generated by the engine at request time, so exports are
              unavailable until this deployment can reach one (VECTASEC_ENGINE_URL).
            </p>
          )}
          <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
            {anyProbed
              ? 'Some versions here were read by an unauthenticated network probe, so the document declares the weaker `discovery` lifecycle phase rather than the flattering one.'
              : 'Every version was read by an authenticated connector, so the document declares the `operations` lifecycle phase.'}{' '}
            It also declares itself an incomplete inventory — a scanner sees the systems it was
            pointed at, never a whole software supply chain.
          </p>
          <p style={{ margin: '6px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
            The VEX document is separate on purpose: it carries what this estate <em>says</em>{' '}
            about each vulnerability — open findings as <code>in_triage</code>, suppressed ones as{' '}
            <code>not_affected</code> with the suppressing person&rsquo;s verbatim reason and the
            date that assessment lapses. Findings that could not be assessed are withheld rather
            than published as &ldquo;not affected&rdquo;, and the document says how many it withheld.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Licensing</CardTitle>
          <CardMeta>
            resolved against the version actually running — these terms changed mid-life for
            several of these products
          </CardMeta>
        </CardHeader>
        <CardBody pad={!licensing || licensing.components.length === 0}>
          {!licensing ? (
            <EmptyState
              tone="setup"
              title="Licensing needs the engine"
              description="This panel is resolved engine-side so the version-to-licence table has exactly one copy. Start the engine and reload."
            />
          ) : licensing.components.length === 0 ? (
            <EmptyState
              tone="setup"
              title="No versioned components yet"
              description="Licensing is derived from the version a connector read. Scan a system whose connector reports a product version."
            />
          ) : (
            <>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', padding: '0 0 12px' }}>
                <StatusPill
                  tone={licensing.summary.non_osi > 0 ? 'warn' : 'ok'}
                  label={
                    licensing.summary.non_osi > 0
                      ? `${licensing.summary.non_osi} not OSI-approved`
                      : 'all OSI-approved'
                  }
                />
                {licensing.summary.unknown > 0 && (
                  <StatusPill tone="neutral" label={`${licensing.summary.unknown} not in the table`} />
                )}
              </div>
              <Table density="relaxed" caption="Licence terms per running component version">
                <THead>
                  <TR>
                    <TH width="22%">Component</TH>
                    <TH width="34%">Terms</TH>
                    <TH width="16%">OSI</TH>
                    <TH width="28%">Source</TH>
                  </TR>
                </THead>
                <TBody>
                  {licensing.components.map((c) => (
                    <TR key={`${c.product}@${c.version}`}>
                      <TD mono>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) 0' }}>
                          <span aria-hidden="true" className="vs-icontile">
                            <IconForType type={c.product} />
                          </span>
                          <span style={{ display: 'grid', gap: 1, minWidth: 0 }}>
                            {c.product} {c.version}
                          </span>
                        </span>
                      </TD>
                      <TD>
                        {c.known ? (
                          <span>
                            {c.licenses.join(c.choice ? ' or ' : ' + ')}
                            {c.choice && (
                              <span style={{ color: 'var(--text-secondary)' }}> (your choice)</span>
                            )}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-secondary)' }}>
                            not in the verified table — no claim made
                          </span>
                        )}
                      </TD>
                      <TD>
                        {c.osi_approved === null ? (
                          <span style={{ color: 'var(--text-secondary)' }}>unknown</span>
                        ) : (
                          <StatusPill
                            tone={c.osi_approved ? 'ok' : 'warn'}
                            label={c.osi_approved ? 'open source' : 'source-available'}
                          />
                        )}
                      </TD>
                      <TD>
                        {c.source_url ? (
                          <a
                            href={c.source_url}
                            target="_blank"
                            rel="noreferrer"
                            style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-2xs)' }}
                          >
                            primary source ↗
                          </a>
                        ) : (
                          <span style={{ color: 'var(--text-secondary)' }}>—</span>
                        )}
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
              <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                Source-available terms (BUSL, SSPL, RSAL, Elastic) are perfectly legal to run —
                they are simply not OSI-approved open source, which is the distinction a licence
                review asks about. VectaSec does not file these as security findings: a licence is
                a contractual fact, not a vulnerability.
              </p>
            </>
          )}
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
            <Table density="relaxed" caption="Component versions running in the estate">
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
                      <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) 0' }}>
                        <span aria-hidden="true" className="vs-icontile">
                          <IconForType type={c.product} />
                        </span>
                        <span style={{ display: 'grid', gap: 1, minWidth: 0 }}>
                          <span style={{ fontWeight: 600 }}>{c.product}</span>
                        </span>
                      </span>
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
    </Page>
  );
}
