import Link from 'next/link';

import { createClient } from '@/lib/supabase/server';
import { canEdit, getOwnMembership } from '@/lib/role';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import {
  IconAlertTriangle,
  IconForType,
  IconLock,
  IconRadar,
  IconServer,
  IconUnlock,
} from '@/components/ui/icons';
import { Page } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { EstateTabs } from '../tabs';
import { ExposurePanel, type ExposureScanRow, type ExposureTargetRow } from './exposure-panel';
import { StatTile } from '@/components/ui/stat';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* Discovery — what is on the network, and which of it nobody is watching.
 *
 * The shadow list is the point of this page. Everything else in the console answers questions
 * about systems the operator named; this answers the one they could not have asked, because you
 * cannot request a scan of a broker you forgot you had.
 *
 * Two honesty rules are load-bearing here. Services are grouped by whether they are monitored,
 * so an empty shadow list reads as "nothing unmonitored was found" rather than "nothing exists".
 * And the coverage strip surfaces refused targets: a sweep that silently dropped half its scope
 * would otherwise render as a clean estate, which is the most dangerous lie this product could
 * tell.
 */

export const metadata = { title: 'Estate · Unmonitored · VectaSec' };

type ServiceRow = {
  id: string;
  name: string;
  ext_id: string;
  labels: Record<string, string> | null;
  raw: { evidence?: string[]; version?: string | null; version_inferred?: boolean } | null;
};

type SweepRow = {
  raw: {
    refusals?: string[];
    targets_probed?: number;
    hosts?: string[];
    services_found?: number;
    products?: string[];
  } | null;
};

/** One service as displayed: repeated observations of the same (product, address) across sweeps
 * collapse into a single row with a sighting count. Every underlying row keeps existing in the
 * data — this is presentation, not dedup of the record. */
type DisplayService = ServiceRow & { sightings: number };

export default async function DiscoveryPage() {
  const supabase = await createClient();
  const membership = await getOwnMembership();

  // RLS scopes reads to EVERY tenant the caller belongs to, not to the one the switcher
  // selected — so a consultant in two orgs would see both estates fused into one page while
  // the top bar named a single org. RLS stays the security boundary; this filter is the
  // SELECTION. Without it the page also disagrees with its own exports, which scope to the
  // active tenant.
  const tenantId = membership?.tenantId;
  const editable = canEdit(membership?.role);
  const scoped = <T,>(q: T): T =>
    (tenantId ? (q as { eq: (c: string, v: string) => T }).eq('tenant_id', tenantId) : q);

  // The free external exposure scan's own tables. Read separately and tolerated: a deployment
  // that has not applied the migration yet must still render the discovery page.
  const [exposureTargetsRes, exposureScansRes] = await Promise.all([
    scoped(supabase.from('exposure_targets').select('id, kind, value, token, verified_at, verify_method, created_at').order('created_at')),
    scoped(supabase.from('exposure_scans').select('id, target_id, status, started_at, finished_at, error, report').order('started_at', { ascending: false }).limit(50)),
  ]);
  const exposureAvailable = !exposureTargetsRes.error && !exposureScansRes.error;
  const exposurePanel = (
    <Card>
      <CardHeader>
        <CardTitle>External exposure scan</CardTitle>
        <CardMeta>what the internet sees · no credentials · ownership verified by DNS</CardMeta>
      </CardHeader>
      <CardBody>
        <ExposurePanel
          targets={(exposureTargetsRes.data ?? []) as unknown as ExposureTargetRow[]}
          scans={(exposureScansRes.data ?? []) as unknown as ExposureScanRow[]}
          editable={editable}
          available={exposureAvailable}
        />
      </CardBody>
    </Card>
  );

  const [servicesRes, sweepsRes, shadowRes] = await Promise.all([
    scoped(
      supabase
        .from('resources')
        .select('id, name, ext_id, labels, raw')
        .eq('kind', 'discovered_service')
        .order('name'),
    ),
    scoped(supabase.from('resources').select('raw').eq('kind', 'discovery_sweep')),
    // The shadow verdict lives on the finding, not the resource — it is a cross-connection
    // conclusion, so the finding is the only place it exists.
    scoped(
      supabase
        .from('findings')
        .select('id, resource_id, severity, assessment')
        .eq('rule_id', 'COVERAGE.SERVICE.UNMONITORED')
        .eq('status', 'open'),
    ),
  ]);

  // A failed query must not render as a clean estate. `?? []` alone would turn a dropped
  // connection or a missing migration into "Nothing discovered yet" — the single most
  // dangerous empty state this product can show.
  const loadError = servicesRes.error ?? sweepsRes.error ?? shadowRes.error;
  if (loadError) {
    return (
      <Page>
        <Head />
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load discovery" description={loadError.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const services = (servicesRes.data ?? []) as ServiceRow[];
  const sweeps = (sweepsRes.data ?? []) as SweepRow[];

  const shadowFindings = (shadowRes.data ?? []) as {
    id: string; resource_id: string; assessment: string;
  }[];
  // correlate.py writes this rule for TWO different verdicts: a confirmed shadow service
  // (assessment='assessed') and an unresolved question — "some connection's config named no
  // endpoint we could parse, so we cannot tell" (not_assessable). Rendering the second as a
  // red "unmonitored" pill would be the false positive the correlation layer was carefully
  // written to avoid, undone at the last step.
  const confirmedShadow = new Set(
    shadowFindings.filter((f) => f.assessment === 'assessed').map((f) => f.resource_id),
  );
  const uncertain = new Set(
    shadowFindings.filter((f) => f.assessment !== 'assessed').map((f) => f.resource_id),
  );

  const refusals = sweeps.flatMap((s) => s.raw?.refusals ?? []);
  const hosts = new Set(sweeps.flatMap((s) => s.raw?.hosts ?? []));
  const shadow = dedupe(services.filter((s) => confirmedShadow.has(s.id)));
  const unresolved = dedupe(
    services.filter((s) => uncertain.has(s.id) && !confirmedShadow.has(s.id)),
  );
  const monitored = dedupe(
    services.filter((s) => !confirmedShadow.has(s.id) && !uncertain.has(s.id)),
  );

  if (services.length === 0) {
    return (
      <Page>
        <Head />
        {exposurePanel}
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="Nothing discovered yet"
              description="Add a discovery connection with the hosts or CIDRs you are authorized to probe. VectaSec fingerprints middleware read-only and pre-authentication — it never sends a credential."
            />
            <p style={{ textAlign: 'center', margin: 0 }}>
              <Link href="/estate" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Go to Connections →
              </Link>
            </p>
          </CardBody>
        </Card>
      </Page>
    );
  }

  return (
    <Page>
      <Head
        meta={`${services.length} service${services.length === 1 ? '' : 's'} across ${hosts.size} host${hosts.size === 1 ? '' : 's'}`}
      />
      {exposurePanel}

      <div style={{ display: 'grid', gap: 'var(--space-3)', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))' }}>
        <Card hover>
          <CardBody>
            <StatTile label="Services found" value={services.length} icon={<IconServer size={13} />} sub="identified from the wire" />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Unmonitored"
              value={shadow.length}
              tone={shadow.length ? 'bad' : 'neutral'}
              icon={<IconAlertTriangle size={13} />}
              sub={shadow.length ? 'nobody is scanning these' : 'all matched a connection'}
            />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile label="Hosts probed" value={hosts.size} icon={<IconRadar size={13} />} sub="declared targets only" />
          </CardBody>
        </Card>
        <Card hover>
          <CardBody>
            <StatTile
              label="Targets refused"
              value={refusals.length}
              tone={refusals.length ? 'warn' : 'neutral'}
              icon={<IconUnlock size={13} />}
              sub={refusals.length ? 'never contacted — a coverage gap' : 'full declared scope probed'}
            />
          </CardBody>
        </Card>
      </div>

      {shadow.length > 0 && (
        <Card style={{ borderColor: 'color-mix(in srgb, var(--sev-critical-solid) 45%, transparent)' }}>
          <CardHeader>
            <CardTitle>Shadow middleware</CardTitle>
            <CardMeta>found on the network, matching no configured connection</CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <ServiceTable rows={shadow} shadow />
          </CardBody>
        </Card>
      )}

      {unresolved.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Monitoring status unknown</CardTitle>
            <CardMeta>
              these may already be monitored — no connection&apos;s configuration could be matched
              to them
            </CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <ServiceTable rows={unresolved} />
          </CardBody>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{shadow.length > 0 ? 'Monitored services' : 'Discovered services'}</CardTitle>
          <CardMeta>
            fingerprinted read-only and pre-authentication — no credential was ever sent
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {monitored.length === 0 ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState
                tone="setup"
                title="Every discovered service is unmonitored"
                description="None of what was found matches a configured connection."
              />
            </div>
          ) : (
            <ServiceTable rows={monitored} />
          )}
        </CardBody>
      </Card>

      {refusals.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Not probed</CardTitle>
            <CardMeta>these addresses were never contacted, so nothing is known about them</CardMeta>
          </CardHeader>
          <CardBody>
            <ul style={{ margin: 0, padding: 0, listStyle: 'none', display: 'grid', gap: 6 }}>
              {refusals.slice(0, 20).map((r, i) => (
                <li key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                  {r}
                </li>
              ))}
            </ul>
            <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
              This is a gap in coverage, not evidence that these addresses are clean.
            </p>
          </CardBody>
        </Card>
      )}
    </Page>
  );
}

function Head({ meta }: { meta?: string }) {
  return (
    <>
      <PageHeader
        title="Estate"
        description="Middleware found by probing the network, and which of it matches something you actually monitor — the shadow list."
        meta={meta}
      />
      <EstateTabs />
    </>
  );
}

/** Collapse repeated observations of the same (product, address) into one display row. Sweeps
 * re-observe the same listener every run; five identical rows read as five services, which
 * over-states the estate on the page whose job is honest coverage. */
function dedupe(rows: ServiceRow[]): DisplayService[] {
  const byKey = new Map<string, DisplayService>();
  for (const s of rows) {
    const key = `${s.labels?.product ?? ''}|${s.name}`;
    const existing = byKey.get(key);
    if (existing) existing.sightings += 1;
    else byKey.set(key, { ...s, sightings: 1 });
  }
  return [...byKey.values()];
}

/** address forms seen from sweeps: "127.0.0.1:6379". Split for the port chip; anything that
 * does not parse renders whole. */
function splitAddress(name: string): { host: string; port: string | null } {
  const m = name.match(/^(.+):(\d+)$/);
  return m ? { host: m[1], port: m[2] } : { host: name, port: null };
}

function ServiceTable({ rows, shadow = false }: { rows: DisplayService[]; shadow?: boolean }) {
  return (
    <Table density="relaxed" caption={shadow ? 'Unmonitored services' : 'Discovered services'}>
      <THead>
        <TR>
          <TH width="20%">Product</TH>
          <TH width="18%">Address</TH>
          <TH width="12%">Version</TH>
          <TH width="12%">Transport</TH>
          <TH width="38%">What the probe read</TH>
        </TR>
      </THead>
      <TBody>
        {rows.map((s) => {
          const labels = s.labels ?? {};
          const inferred = labels.version_inferred === 'true';
          const evidence = (s.raw?.evidence ?? [])[0] ?? '';
          const { host, port } = splitAddress(s.name);
          const plaintext = labels.transport !== 'tls';
          return (
            <TR key={s.id}>
              <TD>
                <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) 0' }}>
                  <span aria-hidden="true" className="vs-icontile">
                    <IconForType type={labels.product ?? ''} />
                  </span>
                  <span style={{ display: 'grid', gap: 2 }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{labels.product ?? '—'}</span>
                    {shadow ? (
                      <StatusPill tone="bad" label="unmonitored" />
                    ) : (
                      s.sightings > 1 && (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                          seen ×{s.sightings}
                        </span>
                      )
                    )}
                  </span>
                </span>
              </TD>
              <TD>
                <span style={{ display: 'inline-flex', alignItems: 'baseline', gap: 2, fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>
                  <span style={{ color: 'var(--text-primary)' }}>{host}</span>
                  {port && (
                    <span style={{ color: 'var(--text-muted)' }}>:{port}</span>
                  )}
                </span>
              </TD>
              <TD>
                {labels.version ? (
                  <span style={{ display: 'grid', gap: 1, justifyItems: 'start' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>
                      {labels.version}
                    </span>
                    {inferred && (
                      /* An inferred version drives CVE matching, so the fact that it was
                         derived rather than read must be visible, not buried in raw JSON. */
                      <span
                        title="Derived from the service's advertised protocol capabilities — no version string was disclosed."
                        style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', borderBottom: '1px dashed var(--border-strong)' }}
                      >
                        inferred
                      </span>
                    )}
                  </span>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>—</span>
                )}
              </TD>
              <TD>
                <span
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 'var(--space-1)',
                    padding: '1px var(--space-2)',
                    borderRadius: 'var(--radius-full)',
                    background: plaintext ? 'var(--sev-medium-bg)' : 'var(--sev-low-bg)',
                    border: `1px solid color-mix(in srgb, ${plaintext ? 'var(--sev-medium-solid)' : 'var(--sev-low-solid)'} 30%, transparent)`,
                    color: plaintext ? 'var(--sev-medium-fg)' : 'var(--sev-low-fg)',
                    fontSize: 'var(--text-2xs)',
                    fontWeight: 600,
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {plaintext ? <IconUnlock size={11} /> : <IconLock size={11} />}
                  {labels.transport ?? 'unknown'}
                </span>
              </TD>
              <TD>
                {evidence ? (
                  <span className="vs-evidence" style={{ margin: 'var(--space-2) 0' }}>
                    {evidence.length > 170 ? `${evidence.slice(0, 170)}…` : evidence}
                  </span>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>—</span>
                )}
              </TD>
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}
