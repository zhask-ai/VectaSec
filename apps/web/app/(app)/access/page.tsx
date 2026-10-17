import Link from 'next/link';

import { createClient } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Severity } from '@/lib/types';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';
import { EmptyState } from '@/components/ui/empty-state';
import { IconBroadcast, IconForType, IconIdentity, IconKey, IconUnlock } from '@/components/ui/icons';
import { Page } from '@/components/ui/page';
import { PageHeader, SectionHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

import { IdentityDetailButton, type IdentityDetail } from './identity-detail';
import { IdentityFilters } from './identity-filters';
import { AccessTabs } from './tabs';

/* Access — the anchor page (docs/vectasec-smb-strategy-2026-10.md §2): every API key, service
 * account, broker user, ACL principal and OAuth client the connected systems ACCEPT, with who
 * owns it, when it was last used, how far it reaches and whether that reach is named like
 * sensitive data. Formerly "Identities"; absorbed the Runtime "last seen" signal and the Data
 * page's sensitivity lens as columns, because a buyer with no security team asks one question —
 * who can touch my data — not three.
 *
 * LAST SEEN is honest by construction. It is assembled from two independent sources and the row
 * says which: (a) `runtime_evidence` — the broker itself reported this principal connected
 * (RabbitMQ connections, Redis CLIENT LIST, NATS connz, PgBouncer, Kafka consumer groups), and
 * (b) a `last_used_at` label the connector derived from the provider's own telemetry (AWS IAM
 * Access Advisor / access-key last-used / CloudTrail). Where neither exists the cell says
 * "unknown", never "unused" — Kong and Kubernetes have no agentless last-used signal, and saying
 * "unused" there would be the exact lie §8 of the strategy warns about.
 *
 * This is the page a flat scanner cannot produce. The service accounts, API consumers, broker
 * users, ACL principals and OAuth clients from EVERY connected system, normalized into one model,
 * with their credentials and grants beside them — answering "who/what can act on our integration
 * layer, and what can they reach". Three lenses:
 *   1. Inventory      — every NHI across systems, filterable, with wildcard/external/default flags.
 *   2. Lifecycle lens — CREDENTIAL.LIFECYCLE.* findings grouped by risk, with an HONEST split
 *                       between a real finding and "not assessable" (the signal was never collected).
 *   3. Per-identity   — a drawer: credential metadata, grants, blast radius, open findings.
 *
 * Reads under RLS like every console page. It selects `labels` (the derived NHI labels carry types,
 * owner links, wildcard/scope flags — never secrets) and never `raw`. Credentials are METADATA: a
 * row proves a secret EXISTS and states its shape; it never holds the value.
 *
 * COUNTS caveat: unbounded PostgREST selects cap at Max Rows (~1000) on hosted, so the headline
 * total comes from an exact `head` count and the table is bounded by an explicit limit; when the
 * two disagree the table says so rather than silently truncating.
 */

export const metadata = { title: 'Access · VectaSec' };

const ROW_CAP = 1000;

type ResourceRow = {
  id: string;
  ext_id: string;
  name: string;
  labels: Record<string, string> | null;
  connections?: { type: string; name: string } | null;
};

type FindingRow = {
  rule_id: string; severity: Severity; status: string;
  // `not_assessable` is a value of `assessment`, NOT of `status` — filtering `status` for it
  // matched nothing, so the "Not assessable" panel below could never render and four live
  // coverage gaps were shown as real medium-severity findings instead.
  assessment: string | null;
  resource_id: string | null;
};

type EvidenceRow = { principal: string | null; source: string; last_seen: string };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

const SENS_RANK: Record<string, number> = { high: 0, medium: 1, low: 2 };
const IDLE_DAYS = 90; // mirrors detect/credential_lifecycle.py _IDLE_DAYS

/** Days since an ISO timestamp, or null when unparseable. */
function daysSince(iso: string): number | null {
  const t = new Date(iso).getTime();
  return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86_400_000);
}

function relative(iso: string): string {
  const d = daysSince(iso);
  if (d === null) return iso;
  if (d < 1) return 'today';
  if (d === 1) return 'yesterday';
  return `${d}d ago`;
}

function lbl(r: { labels: Record<string, string> | null }, k: string): string {
  return (r.labels ?? {})[k] ?? '';
}

function lblList(r: { labels: Record<string, string> | null }, k: string): string[] {
  const v = lbl(r, k);
  return v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : [];
}

function leaf(name: string): string {
  return String(name ?? '').split(':').pop() || String(name ?? '');
}

function one(v: string | string[] | undefined): string {
  return typeof v === 'string' ? v : '';
}

const DEFAULT_LEAVES = ['guest', 'anonymous', 'default', 'admin', 'administrator', 'root', 'public'];
function isDefault(name: string): boolean {
  return DEFAULT_LEAVES.includes(leaf(name).toLowerCase());
}

function scopeOf(idr: ResourceRow): IdentityDetail['scope'] {
  const e = lbl(idr, 'external');
  if (e === 'true') return 'external';
  if (e === 'false') return 'internal';
  const t = lbl(idr, 'identity_type').toLowerCase();
  if (t.includes('external')) return 'external';
  if (t.includes('internal') || t.includes('service') || t.includes('system')) return 'internal';
  return 'unknown';
}

const LIFECYCLE_LABEL: Record<string, string> = {
  STATIC_NO_ROTATION: 'Static — no rotation',
  NO_ROTATION: 'Static — no rotation',
  NO_EXPIRY: 'No expiry set',
  DEFAULT_ACTIVE: 'Default credential active',
  STALE: 'Stale — long unused',
  ORPHANED: 'Orphaned — no owner',
};
function ruleSuffix(ruleId: string): string {
  return String(ruleId ?? '').split('.').pop() || String(ruleId ?? '');
}
function prettyLifecycle(ruleId: string): string {
  const s = ruleSuffix(ruleId).toUpperCase();
  return LIFECYCLE_LABEL[s] ?? s.replace(/_/g, ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase());
}

type LifeAgg = { rule: string; suffix: string; severity: Severity; count: number; examples: string[] };
function aggregate(findings: FindingRow[], nameById: Map<string, string>): LifeAgg[] {
  const m = new Map<string, LifeAgg>();
  for (const f of findings) {
    const suffix = ruleSuffix(f.rule_id);
    const name = f.resource_id ? nameById.get(f.resource_id) ?? f.resource_id : '—';
    const ex = m.get(suffix);
    if (!ex) {
      m.set(suffix, { rule: f.rule_id, suffix, severity: f.severity, count: 1, examples: [name] });
    } else {
      ex.count += 1;
      if (SEVERITY_RANK[f.severity] < SEVERITY_RANK[ex.severity]) ex.severity = f.severity;
      if (ex.examples.length < 3 && !ex.examples.includes(name)) ex.examples.push(name);
    }
  }
  return [...m.values()].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

export default async function IdentitiesPage({ searchParams }: { searchParams: SearchParams }) {
  const sp = await searchParams;
  const fSystem = one(sp.system);
  const fType = one(sp.type);
  const fWildcard = one(sp.wildcard);
  const fSensitivity = one(sp.sensitivity);
  const fSeen = one(sp.seen);

  const supabase = await createClient();

  const [countRes, identitiesRes, credsRes, grantsRes, evidenceRes] = await Promise.all([
    supabase.from('resources').select('*', { count: 'exact', head: true }).eq('kind', 'identity'),
    supabase
      .from('resources')
      .select('id, ext_id, name, labels, connections(type, name)')
      .eq('kind', 'identity')
      .order('name')
      .limit(ROW_CAP),
    supabase.from('resources').select('id, ext_id, name, labels').eq('kind', 'credential').limit(ROW_CAP),
    supabase.from('resources').select('id, ext_id, name, labels').eq('kind', 'grant').limit(ROW_CAP),
    // The brokers' own account of who connected. Newest first and bounded; a principal's
    // newest sighting is what the register needs, and the full window lives on the Live tab.
    supabase.from('runtime_evidence').select('principal, source, last_seen').order('last_seen', { ascending: false }).limit(ROW_CAP),
  ]);

  // runtime_evidence is OPTIONAL input: a tenant with no runtime-capable connector has an empty
  // table, and a read error here must degrade to "unknown" cells, never hide the register.
  const evidence = (evidenceRes.error ? [] : (evidenceRes.data ?? [])) as unknown as EvidenceRow[];
  const seenByPrincipal = new Map<string, EvidenceRow>();
  for (const e of evidence) {
    if (!e.principal) continue;
    const key = e.principal.toLowerCase();
    if (!seenByPrincipal.has(key)) seenByPrincipal.set(key, e); // newest first already
  }

  const err = identitiesRes.error ?? credsRes.error ?? grantsRes.error;
  if (err) {
    return (
      <Page>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load identities" description={err.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const identities = (identitiesRes.data ?? []) as unknown as ResourceRow[];
  const creds = (credsRes.data ?? []) as unknown as ResourceRow[];
  const grants = (grantsRes.data ?? []) as unknown as ResourceRow[];
  const exactTotal = countRes.count ?? identities.length;

  if (identities.length === 0) {
    return (
      <Page>
        <SetupState />
      </Page>
    );
  }

  // Findings: open findings on any NHI resource (drives Risk + per-identity detail); and the
  // full CREDENTIAL.LIFECYCLE.* set (any status) so the lens can honour not_assessable.
  const nhiIds = [...identities, ...creds, ...grants].map((r) => r.id);
  const [openRes, lifecycleRes] = await Promise.all([
    supabase.from('findings').select('rule_id, severity, status, assessment, resource_id').eq('status', 'open').in('resource_id', nhiIds).limit(ROW_CAP),
    supabase.from('findings').select('rule_id, severity, status, assessment, resource_id').like('rule_id', 'CREDENTIAL.LIFECYCLE.%').limit(ROW_CAP),
  ]);

  const nameById = new Map<string, string>();
  for (const r of [...identities, ...creds, ...grants]) nameById.set(r.id, r.name);

  // Without this, a failed findings read prints the literal word "clean" in the Risk column for
  // every identity in the estate. It is not hypothetical: the query sends `.in('resource_id', …)`
  // with up to 3×ROW_CAP uuids — a ~110KB URL that PostgREST and proxies answer with 414 — and
  // the page's response to being unable to see any findings was to declare there were none.
  if (openRes.error || lifecycleRes.error) {
    const e = openRes.error ?? lifecycleRes.error!;
    return (
      <Page>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load identity risk"
              description={`${e.message} — no identity can be shown as clean while its findings are unreadable.`} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const openByResource = new Map<string, FindingRow[]>();
  for (const f of (openRes.data ?? []) as unknown as FindingRow[]) {
    if (!f.resource_id) continue;
    (openByResource.get(f.resource_id) ?? openByResource.set(f.resource_id, []).get(f.resource_id)!).push(f);
  }

  // Group credentials/grants under their identity ext_id (from labels, not raw).
  const credsByOwner = new Map<string, ResourceRow[]>();
  for (const c of creds) {
    const owner = lbl(c, 'owner');
    (credsByOwner.get(owner) ?? credsByOwner.set(owner, []).get(owner)!).push(c);
  }
  const grantsByIdentity = new Map<string, ResourceRow[]>();
  for (const g of grants) {
    const owner = lbl(g, 'identity');
    (grantsByIdentity.get(owner) ?? grantsByIdentity.set(owner, []).get(owner)!).push(g);
  }

  // Build the serializable per-identity detail (also the row model for the inventory table).
  const details: IdentityDetail[] = identities.map((idr) => {
    const myCreds = credsByOwner.get(idr.ext_id) ?? [];
    const myGrants = grantsByIdentity.get(idr.ext_id) ?? [];

    const findings: IdentityDetail['findings'] = [];
    let worst: Severity | null = null;
    let fk = 0;
    for (const r of [idr, ...myCreds, ...myGrants]) {
      for (const f of openByResource.get(r.id) ?? []) {
        findings.push({ id: `${idr.id}:${fk++}`, ruleId: f.rule_id, severity: f.severity, status: f.status, resource: nameById.get(r.id) ?? r.id });
        if (worst === null || SEVERITY_RANK[f.severity] < SEVERITY_RANK[worst]) worst = f.severity;
      }
    }
    findings.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

    // Last seen: the newest of (connector-derived last_used_at on the identity or any of its
    // credentials) and (the broker's runtime evidence for this principal). Absent both → unknown.
    const candidates: { at: string; source: string }[] = [];
    for (const r of [idr, ...myCreds]) {
      const v = lbl(r, 'last_used_at');
      if (v && v !== 'never') candidates.push({ at: v, source: lbl(r, 'last_used_source') || 'provider telemetry' });
    }
    const ev = seenByPrincipal.get(leaf(idr.name).toLowerCase()) ?? seenByPrincipal.get(idr.name.toLowerCase());
    if (ev) candidates.push({ at: ev.last_seen, source: `${ev.source} runtime evidence` });
    candidates.sort((a, b) => (a.at < b.at ? 1 : -1));
    const neverSignal = [idr, ...myCreds].some((r) => lbl(r, 'last_used_at') === 'never');
    const lastSeen: IdentityDetail['lastSeen'] = candidates[0]
      ? { state: 'seen', at: candidates[0].at, source: candidates[0].source }
      : neverSignal
        ? { state: 'never', at: null, source: 'provider telemetry' }
        : { state: 'unknown', at: null, source: '' };

    const sensitivity = myGrants
      .map((g) => lbl(g, 'sensitivity'))
      .filter((v) => v in SENS_RANK)
      .sort((a, b) => SENS_RANK[a] - SENS_RANK[b])[0] ?? '';

    return {
      id: idr.id,
      name: idr.name,
      system: lbl(idr, 'system'),
      identityType: lbl(idr, 'identity_type'),
      scope: scopeOf(idr),
      connector: idr.connections ?? null,
      isDefault: isDefault(idr.name) || lbl(idr, 'shared') === 'true',
      owner: lbl(idr, 'owner_label') || null,
      lastSeen,
      sensitivity,
      worst,
      findings,
      creds: myCreds.map((c) => {
        const hashing = lbl(c, 'hashing');
        return {
          id: c.id,
          label: lbl(c, 'credential_type') || 'credential',
          hashing,
          weak: ['md5', 'sha1'].includes(hashing),
          isDefault: lbl(c, 'default') === 'true',
        };
      }),
      grants: myGrants.map((g) => ({
        id: g.id,
        name: g.name,
        action: lbl(g, 'action'),
        resource: lbl(g, 'resource') || lbl(g, 'target') || lbl(g, 'pattern') || '',
        wildcard: lbl(g, 'wildcard') === 'true',
        dataClasses: lblList(g, 'data_classes'),
        sensitivity: lbl(g, 'sensitivity'),
      })),
    };
  });

  // Estate-wide KPIs (from the full set, not the filtered view).
  const systemsSet = new Set(details.map((d) => d.system).filter(Boolean));
  const wildcardGranted = details.filter((d) => d.grants.some((g) => g.wildcard)).length;
  const externalCount = details.filter((d) => d.scope === 'external').length;
  const defaultCount = details.filter((d) => d.isDefault).length;
  const isDormant = (d: IdentityDetail) =>
    d.lastSeen.state === 'never' || (d.lastSeen.state === 'seen' && (daysSince(d.lastSeen.at!) ?? 0) >= IDLE_DAYS);
  const dormantCount = details.filter(isDormant).length;
  const knownSeen = details.filter((d) => d.lastSeen.state !== 'unknown').length;
  const truncated = identities.length < exactTotal;

  // Filter options + filtered rows.
  const systemOptions = [...systemsSet].sort();
  const typeOptions = [...new Set(details.map((d) => d.identityType).filter(Boolean))].sort();
  const filtered = details.filter(
    (d) =>
      (!fSystem || d.system === fSystem) &&
      (!fType || d.identityType === fType) &&
      (fWildcard !== 'only' || d.grants.some((g) => g.wildcard)) &&
      (!fSensitivity || d.sensitivity === fSensitivity) &&
      (fSeen !== 'dormant' || isDormant(d)) &&
      (fSeen !== 'unknown' || d.lastSeen.state === 'unknown') &&
      (fSeen !== 'seen' || d.lastSeen.state === 'seen'),
  );
  const filtersActive = Boolean(fSystem || fType || fWildcard || fSensitivity || fSeen);

  // Lifecycle lens: split real findings (open) from not-assessable (a coverage gap, not a result).
  const lifecycle = (lifecycleRes.data ?? []) as unknown as FindingRow[];
  const lifeOpen = aggregate(
    lifecycle.filter((f) => f.status === 'open' && f.assessment !== 'not_assessable'), nameById);
  const lifeNA = aggregate(
    lifecycle.filter((f) => f.assessment === 'not_assessable'), nameById);

  return (
    <Page>
      <PageHeader
        title="Access"
        description="Every API key, service account, OAuth client and automation credential your connected systems accept — who owns it, when it was last used, what it can reach, and whether that reach is named like sensitive data."
        meta={`${exactTotal} identities · ${systemsSet.size} systems`}
      />
      <AccessTabs />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-3)' }}>
        <KpiCard>
          <StatTile label="Non-human identities" value={exactTotal} icon={<IconIdentity size={13} />} sub={`across ${systemsSet.size} system${systemsSet.size === 1 ? '' : 's'}`} />
        </KpiCard>
        <KpiCard>
          <StatTile label="Wildcard-granted" value={wildcardGranted} tone={wildcardGranted ? 'bad' : 'good'} icon={<IconKey size={13} />} sub="hold a blanket authorization" />
        </KpiCard>
        <KpiCard>
          <StatTile label="External" value={externalCount} tone={externalCount ? 'warn' : 'good'} icon={<IconBroadcast size={13} />} sub="principals from outside the estate" />
        </KpiCard>
        <KpiCard>
          <StatTile label="Shared / default" value={defaultCount} tone={defaultCount ? 'warn' : 'good'} icon={<IconUnlock size={13} />} sub="unattributable principals" />
        </KpiCard>
        <KpiCard>
          <StatTile
            label={`Dormant ${IDLE_DAYS}d+`}
            value={dormantCount}
            tone={dormantCount ? 'warn' : knownSeen ? 'good' : 'neutral'}
            icon={<IconIdentity size={13} />}
            sub={knownSeen ? `of ${knownSeen} with a last-used signal` : 'no last-used signal collected yet'}
          />
        </KpiCard>
      </div>

      {/* Lens 2 — Credential lifecycle, grouped by risk, honest about coverage. */}
      <Card>
        <CardHeader>
          <CardTitle>Credential lifecycle</CardTitle>
          <CardMeta>{creds.length} credentials assessed</CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {lifeOpen.length === 0 && lifeNA.length === 0 ? (
            <EmptyState
              tone="clean"
              title="No credential-lifecycle issues"
              description="No static, expiring, default, stale or orphaned credential findings across connected systems."
              meta={`${creds.length} credentials assessed`}
            />
          ) : (
            <>
              {lifeOpen.length > 0 && (
                <Table density="default" caption="Credential-lifecycle findings grouped by risk">
                  <THead>
                    <TR>
                      <TH width="26%">Issue</TH>
                      <TH width="8%">Severity</TH>
                      <TH width="26%">Rule</TH>
                      <TH width="10%" numeric>Credentials</TH>
                      <TH width="30%">Examples</TH>
                    </TR>
                  </THead>
                  <TBody>
                    {lifeOpen.map((a) => (
                      <TR key={a.suffix}>
                        <TD>{prettyLifecycle(a.rule)}</TD>
                        <TD>
                          <SeverityBadge severity={a.severity} variant="inline" />
                        </TD>
                        <TD>
                          <Chip mono>{a.rule}</Chip>
                        </TD>
                        <TD numeric>{a.count}</TD>
                        <TD>
                          <span style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {a.examples.map((e) => (
                              <Chip key={e} mono>{leaf(e)}</Chip>
                            ))}
                            {a.count > a.examples.length && (
                              <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>+{a.count - a.examples.length}</span>
                            )}
                          </span>
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              )}

              {lifeNA.length > 0 && (
                <div style={{ padding: 'var(--space-4)', borderTop: '1px solid var(--border)', display: 'grid', gap: 'var(--space-2)' }}>
                  <SectionHeader title="Not assessable" meta="a coverage gap, not a finding" />
                  <p style={{ margin: 0, maxWidth: '72ch', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
                    These checks could not run because the required signal is not collected for the source system — for
                    example, last-used timestamps are not exposed for a stale-credential check. This is neither a pass nor a
                    fail, and must not be read as &ldquo;clean&rdquo;.
                  </p>
                  <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
                    {lifeNA.map((a) => (
                      <li key={a.suffix} style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
                        <StatusPill tone="neutral" label="not assessable" />
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>{prettyLifecycle(a.rule)}</span>
                        <Chip mono>{a.rule}</Chip>
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                          {a.count} credential{a.count === 1 ? '' : 's'}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}
        </CardBody>
      </Card>

      {/* Lens 1 — Cross-system inventory. */}
      <Card>
        <CardHeader>
          <CardTitle>Identity inventory</CardTitle>
          <CardMeta>
            {filtersActive ? `${filtered.length} of ${identities.length} shown` : `${identities.length} identities · ${creds.length} credentials · ${grants.length} grants`}
            {truncated ? ` · showing first ${identities.length} of ${exactTotal}` : ''}
          </CardMeta>
        </CardHeader>
        <CardBody>
          <IdentityFilters
            systems={systemOptions}
            types={typeOptions}
            system={fSystem}
            type={fType}
            wildcard={fWildcard}
            sensitivity={fSensitivity}
            seen={fSeen}
          />
        </CardBody>
        <CardBody pad={false}>
          {filtered.length === 0 ? (
            <EmptyState
              tone="filtered"
              title="No identities match these filters"
              description="No non-human identity matches the current system, type and grant filters."
              action={
                <Link href="/access" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                  Clear filters
                </Link>
              }
            />
          ) : (
            <Table density="relaxed" caption="Non-human identities across all connected systems">
              <THead>
                <TR>
                  <TH width="20%">Identity</TH>
                  <TH width="8%">System</TH>
                  <TH width="10%">Type</TH>
                  <TH width="10%">Owner</TH>
                  <TH width="11%">Last seen</TH>
                  <TH width="9%">Sensitive data</TH>
                  <TH width="6%" numeric>Creds</TH>
                  <TH width="6%" numeric>Grants</TH>
                  <TH width="8%">Wildcard</TH>
                  <TH width="6%">Risk</TH>
                  <TH width="6%"><span className="vs-visually-hidden">Detail</span></TH>
                </TR>
              </THead>
              <TBody>
                {filtered.map((d) => (
                  <TR key={d.id}>
                    <TD>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) 0' }}>
                        <span aria-hidden="true" className="vs-icontile">
                          <IconForType type={d.identityType || 'identity'} />
                        </span>
                        <span style={{ display: 'grid', gap: 1, minWidth: 0 }}>
                          <span style={{ fontFamily: 'var(--font-mono)' }}>{leaf(d.name)}</span>
                          {d.connector && (
                            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                              {d.connector.type}/{d.connector.name}
                            </span>
                          )}
                        </span>
                      </span>
                    </TD>
                    <TD mono>{d.system || '—'}</TD>
                    <TD>
                      <span style={{ color: 'var(--text-secondary)' }}>{d.identityType || '—'}</span>
                      {d.isDefault && (
                        <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>default / shared</span>
                      )}
                    </TD>
                    <TD>
                      {d.owner ? (
                        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>{d.owner}</span>
                      ) : (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }} title="No owner tag or annotation on this principal">no owner</span>
                      )}
                      {d.scope === 'external' && (
                        <span style={{ display: 'block', marginTop: 2 }}>
                          <Chip tone="medium">external</Chip>
                        </span>
                      )}
                    </TD>
                    <TD>
                      <LastSeenCell seen={d.lastSeen} />
                    </TD>
                    <TD>
                      {d.sensitivity ? (
                        <DataClassChips classes={[...new Set(d.grants.flatMap((g) => g.dataClasses))].slice(0, 3)} sensitivity={d.sensitivity} />
                      ) : (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>—</span>
                      )}
                    </TD>
                    <TD numeric>{d.creds.length}</TD>
                    <TD numeric>{d.grants.length}</TD>
                    <TD>
                      {d.grants.some((g) => g.wildcard) ? (
                        <Chip tone="high">✳ wildcard</Chip>
                      ) : (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>—</span>
                      )}
                    </TD>
                    <TD>
                      {d.worst ? (
                        <SeverityBadge severity={d.worst} variant="inline" />
                      ) : (
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>clean</span>
                      )}
                    </TD>
                    <TD>
                      <IdentityDetailButton detail={d} />
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', maxWidth: 760 }}>
        “Last seen” is read from the brokers (connections, client lists, consumer groups) and from provider telemetry
        where a connector collects it (AWS IAM Access Advisor, access-key last-used, CloudTrail). Where neither exists
        the cell says unknown — never unused. Sensitivity is inferred from the names of what a grant reaches, not from
        payloads. Non-human identities are derived from what each connector already reads — Kafka ACL principals, Kong consumers,
        RabbitMQ users, Redis ACL users, MCP OAuth clients — and normalized into one model. Credentials shown are metadata
        only; VectaSec never reads or stores a secret value.
      </p>
    </Page>
  );
}

/** Last seen, with the state carried in words — "unknown" is a different fact from "never", and
 * a dormant principal is flagged in the medium hue plus text, never hue alone. */
function LastSeenCell({ seen }: { seen: IdentityDetail['lastSeen'] }) {
  if (seen.state === 'unknown') {
    return (
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }} title="No last-used signal is collected for this system (no runtime evidence, no provider telemetry)">
        unknown
      </span>
    );
  }
  if (seen.state === 'never') {
    return (
      <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, color: 'var(--sev-medium-fg)' }} title={`Reported never used · ${seen.source}`}>
        never used
      </span>
    );
  }
  const days = daysSince(seen.at!) ?? 0;
  const dormant = days >= IDLE_DAYS;
  return (
    <span style={{ display: 'grid', gap: 1 }} title={`${seen.at} · ${seen.source}`}>
      <span style={{ fontSize: 'var(--text-xs)', fontWeight: dormant ? 600 : 400, color: dormant ? 'var(--sev-medium-fg)' : 'var(--text-primary)' }}>
        {relative(seen.at!)}
        {dormant ? ' · dormant' : ''}
      </span>
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{seen.source}</span>
    </span>
  );
}

function KpiCard({ children }: { children: React.ReactNode }) {
  return (
    <Card hover>
      <CardBody>{children}</CardBody>
    </Card>
  );
}

function SetupState() {
  const sources = ['Kafka ACL principals', 'Kong consumers', 'RabbitMQ users', 'Redis ACL users', 'MCP OAuth clients'];
  return (
    <>
      <PageHeader
        title="Access"
        description="Every API key, service account and OAuth client that can act on your integration layer — in one register."
      />
      <AccessTabs />
      <Card>
        <CardBody>
          <EmptyState
            tone="setup"
            title="No non-human identities yet"
            description="Connect and scan a system with users, consumers, ACLs or OAuth clients and its identities appear here — normalized across systems, with their credentials, grants and reach."
            action={
              <Link href="/estate" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
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
