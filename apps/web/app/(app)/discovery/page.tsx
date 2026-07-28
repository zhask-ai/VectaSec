import Link from 'next/link';

import { createClient } from '@/lib/supabase/server';
import { getOwnMembership } from '@/lib/role';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
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

export const metadata = { title: 'Discovery · VectaSec' };

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

export default async function DiscoveryPage() {
  const supabase = await createClient();
  const membership = await getOwnMembership();

  // RLS scopes reads to EVERY tenant the caller belongs to, not to the one the switcher
  // selected — so a consultant in two orgs would see both estates fused into one page while
  // the top bar named a single org. RLS stays the security boundary; this filter is the
  // SELECTION. Without it the page also disagrees with its own exports, which scope to the
  // active tenant.
  const tenantId = membership?.tenantId;
  const scoped = <T,>(q: T): T =>
    (tenantId ? (q as { eq: (c: string, v: string) => T }).eq('tenant_id', tenantId) : q);

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
      <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
        <Page />
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load discovery" description={loadError.message} />
          </CardBody>
        </Card>
      </div>
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
  const shadow = services.filter((s) => confirmedShadow.has(s.id));
  const unresolved = services.filter((s) => uncertain.has(s.id) && !confirmedShadow.has(s.id));
  const monitored = services.filter(
    (s) => !confirmedShadow.has(s.id) && !uncertain.has(s.id),
  );

  if (services.length === 0) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
        <Page />
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="Nothing discovered yet"
              description="Add a discovery connection with the hosts or CIDRs you are authorized to probe. VectaSec fingerprints middleware read-only and pre-authentication — it never sends a credential."
            />
            <p style={{ textAlign: 'center', margin: 0 }}>
              <Link href="/connections" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Go to Connections →
              </Link>
            </p>
          </CardBody>
        </Card>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <Page
        meta={`${services.length} service${services.length === 1 ? '' : 's'} across ${hosts.size} host${hosts.size === 1 ? '' : 's'}`}
      />

      <div style={{ display: 'grid', gap: 'var(--space-3)', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))' }}>
        <Stat label="Services found" value={services.length} hint="identified from the wire" />
        <Stat
          label="Unmonitored"
          value={shadow.length}
          hint={shadow.length ? 'nobody is scanning these' : 'all matched a connection'}
          tone={shadow.length ? 'bad' : 'ok'}
        />
        <Stat label="Hosts probed" value={hosts.size} hint="declared targets only" />
        <Stat
          label="Targets refused"
          value={refusals.length}
          hint={refusals.length ? 'never contacted — a coverage gap' : 'full declared scope probed'}
          tone={refusals.length ? 'warn' : 'ok'}
        />
      </div>

      {shadow.length > 0 && (
        <Card>
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
            <ul style={{ margin: 0, paddingLeft: '1.1rem', display: 'grid', gap: 6 }}>
              {refusals.slice(0, 20).map((r, i) => (
                <li key={i} style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
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
    </div>
  );
}

function Page({ meta }: { meta?: string }) {
  return (
    <PageHeader
      title="Discovery"
      description="Middleware found by probing the network, and which of it matches something you actually monitor."
      meta={meta}
    />
  );
}

function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: number;
  hint: string;
  tone?: 'ok' | 'warn' | 'bad';
}) {
  const color =
    tone === 'bad' ? 'var(--sev-critical-fg)' : tone === 'warn' ? 'var(--sev-medium-fg)' : undefined;
  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          {label}
        </div>
        <div data-numeric style={{ fontSize: 'var(--text-2xl, 28px)', fontWeight: 700, color }}>
          {value}
        </div>
        <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{hint}</div>
      </CardBody>
    </Card>
  );
}

function ServiceTable({ rows, shadow = false }: { rows: ServiceRow[]; shadow?: boolean }) {
  return (
    <Table density="default" caption={shadow ? 'Unmonitored services' : 'Discovered services'}>
      <THead>
        <TR>
          <TH width="18%">Product</TH>
          <TH width="20%">Address</TH>
          <TH width="14%">Version</TH>
          <TH width="12%">Transport</TH>
          <TH width="36%">What the probe read</TH>
        </TR>
      </THead>
      <TBody>
        {rows.map((s) => {
          const labels = s.labels ?? {};
          const inferred = labels.version_inferred === 'true';
          const evidence = (s.raw?.evidence ?? [])[0] ?? '';
          return (
            <TR key={s.id}>
              <TD>
                <span style={{ fontWeight: 600 }}>{labels.product ?? '—'}</span>
                {shadow && (
                  <div style={{ marginTop: 3 }}>
                    <StatusPill tone="bad" label="unmonitored" />
                  </div>
                )}
              </TD>
              <TD>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>
                  {s.name}
                </span>
              </TD>
              <TD>
                {labels.version ? (
                  <>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>
                      {labels.version}
                    </span>
                    {inferred && (
                      /* An inferred version drives CVE matching, so the fact that it was
                         derived rather than read must be visible, not buried in raw JSON. */
                      <div
                        title="Derived from the service's advertised protocol capabilities — no version string was disclosed."
                        style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', borderBottom: '1px dashed var(--border)', display: 'inline-block' }}
                      >
                        inferred
                      </div>
                    )}
                  </>
                ) : (
                  <span style={{ color: 'var(--text-muted)' }}>—</span>
                )}
              </TD>
              <TD>
                <StatusPill
                  tone={labels.transport === 'tls' ? 'ok' : 'warn'}
                  label={labels.transport ?? 'unknown'}
                />
              </TD>
              <TD>
                <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                  {evidence.length > 150 ? `${evidence.slice(0, 150)}…` : evidence}
                </span>
              </TD>
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}
