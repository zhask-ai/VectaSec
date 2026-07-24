import Link from 'next/link';

import { createClient } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Severity } from '@/lib/types';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* Non-Human Identities — the cross-system NHI inventory.
 *
 * This is the page a flat scanner cannot produce: the service accounts, API consumers, broker
 * users and OAuth clients from EVERY connected system, normalized into one model (identity.py),
 * with their credentials and grants beside them. It answers "who/what can act on our integration
 * layer, and what can they reach" — the question behind the OAuth-token supply-chain breaches.
 *
 * Reads under RLS like every console page. It selects `labels` (safe — the derived NHI labels
 * carry types and owner links, never secrets) and never `raw`. Credentials here are METADATA:
 * a credential row proves a secret EXISTS and states its shape; it never holds the secret.
 *
 * COUNTS caveat, same as the assets/connections pages: these reads are bounded by a LIMIT and an
 * unbounded PostgREST select caps at Max Rows on hosted. NHI counts are small at seed scale, but a
 * very large estate would need pagination — flagged, not silently truncated.
 */

export const metadata = { title: 'Identities · VectaSec' };

const LIMIT = 2000;

type Row = {
  id: string;
  ext_id: string;
  name: string;
  labels: Record<string, string> | null;
  connections: { type: string; name: string } | null;
};

type FindingRow = { severity: Severity; status: string; resource_id: string | null };

function lbl(r: { labels: Record<string, string> | null }, k: string): string {
  return (r.labels ?? {})[k] ?? '';
}

export default async function IdentitiesPage() {
  const supabase = await createClient();

  const [identitiesRes, credsRes, grantsRes] = await Promise.all([
    supabase.from('resources').select('id, ext_id, name, labels, connections(type, name)')
      .eq('kind', 'identity').order('name').limit(LIMIT),
    supabase.from('resources').select('id, ext_id, name, labels').eq('kind', 'credential').limit(LIMIT),
    supabase.from('resources').select('id, ext_id, name, labels').eq('kind', 'grant').limit(LIMIT),
  ]);

  const err = identitiesRes.error ?? credsRes.error ?? grantsRes.error;
  if (err) {
    return (
      <Page>
        <Card><CardBody>
          <EmptyState tone="error" title="Could not load identities" description={err.message} />
        </CardBody></Card>
      </Page>
    );
  }

  const identities = (identitiesRes.data ?? []) as unknown as Row[];
  const creds = (credsRes.data ?? []) as unknown as Row[];
  const grants = (grantsRes.data ?? []) as unknown as Row[];

  if (identities.length === 0) return <Page><SetupState /></Page>;

  // Open findings on any NHI resource, mapped resource_id -> worst severity.
  const nhiIds = [...identities, ...creds, ...grants].map((r) => r.id);
  const worstByResource = new Map<string, Severity>();
  if (nhiIds.length) {
    const fRes = await supabase.from('findings').select('severity, status, resource_id')
      .eq('status', 'open').in('resource_id', nhiIds).limit(LIMIT);
    for (const f of (fRes.data ?? []) as unknown as FindingRow[]) {
      if (!f.resource_id) continue;
      const cur = worstByResource.get(f.resource_id);
      if (!cur || SEVERITY_RANK[f.severity] < SEVERITY_RANK[cur]) worstByResource.set(f.resource_id, f.severity);
    }
  }

  // Group credentials/grants under their identity ext_id (from labels, not raw).
  const credsByOwner = new Map<string, Row[]>();
  for (const c of creds) {
    const owner = lbl(c, 'owner');
    (credsByOwner.get(owner) ?? credsByOwner.set(owner, []).get(owner)!).push(c);
  }
  const grantsByIdentity = new Map<string, Row[]>();
  for (const g of grants) {
    const owner = lbl(g, 'identity');
    (grantsByIdentity.get(owner) ?? grantsByIdentity.set(owner, []).get(owner)!).push(g);
  }

  const rows = identities.map((idr) => {
    const myCreds = credsByOwner.get(idr.ext_id) ?? [];
    const myGrants = grantsByIdentity.get(idr.ext_id) ?? [];
    let worst: Severity | null = null;
    for (const r of [idr, ...myCreds, ...myGrants]) {
      const s = worstByResource.get(r.id);
      if (s && (worst === null || SEVERITY_RANK[s] < SEVERITY_RANK[worst])) worst = s;
    }
    return { idr, creds: myCreds, grants: myGrants, worst };
  });

  // Summary signals — the NHI governance headline.
  const bySystem = new Map<string, number>();
  for (const idr of identities) bySystem.set(lbl(idr, 'system'), (bySystem.get(lbl(idr, 'system')) ?? 0) + 1);
  const wildcardGrants = grants.filter((g) => lbl(g, 'wildcard') === 'true').length;
  const defaultIdentities = rows.filter((r) => isDefault(r.idr.name)).length;
  const weakCreds = creds.filter((c) => ['md5', 'sha1'].includes(lbl(c, 'hashing'))).length;

  return (
    <Page>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 'var(--space-3)' }}>
        <Stat label="Non-human identities" value={identities.length}
          sub={[...bySystem.entries()].map(([s, n]) => `${n} ${s}`).join(' · ')} />
        <Stat label="Wildcard grants" value={wildcardGrants} tone={wildcardGrants ? 'bad' : 'ok'}
          sub="blanket authorizations" />
        <Stat label="Default / shared" value={defaultIdentities} tone={defaultIdentities ? 'warn' : 'ok'}
          sub="unattributable principals" />
        <Stat label="Weak-hashed secrets" value={weakCreds} tone={weakCreds ? 'warn' : 'ok'}
          sub="md5 / sha1 at rest" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Identity inventory</CardTitle>
          <CardMeta>{identities.length} identities · {creds.length} credentials · {grants.length} grants</CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          <Table density="default" caption="Non-human identities across all connected systems">
            <THead>
              <TR>
                <TH width="20%">Identity</TH>
                <TH width="10%">System</TH>
                <TH width="12%">Type</TH>
                <TH width="24%">Credentials</TH>
                <TH width="24%">Grants</TH>
                <TH width="10%">Risk</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map(({ idr, creds: myCreds, grants: myGrants, worst }) => (
                <TR key={idr.id}>
                  <TD>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{idr.name}</span>
                    {idr.connections && (
                      <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                        {idr.connections.type}/{idr.connections.name}
                      </span>
                    )}
                  </TD>
                  <TD mono>{lbl(idr, 'system')}</TD>
                  <TD>
                    <span style={{ color: 'var(--text-secondary)' }}>{lbl(idr, 'identity_type') || '—'}</span>
                    {isDefault(idr.name) && (
                      <span style={{ display: 'block', fontSize: 'var(--text-2xs)', color: 'var(--sev-medium-fg)' }}>
                        default / shared
                      </span>
                    )}
                  </TD>
                  <TD>
                    {myCreds.length === 0 ? (
                      <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>none readable</span>
                    ) : (
                      <span style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {myCreds.map((c) => <CredChip key={c.id} c={c} />)}
                      </span>
                    )}
                  </TD>
                  <TD>
                    {myGrants.length === 0 ? (
                      <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>none</span>
                    ) : (
                      <span style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {myGrants.slice(0, 6).map((g) => <GrantChip key={g.id} g={g} />)}
                        {myGrants.length > 6 && (
                          <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                            +{myGrants.length - 6}
                          </span>
                        )}
                      </span>
                    )}
                  </TD>
                  <TD>
                    {worst ? <SeverityBadge severity={worst} variant="inline" />
                      : <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>clean</span>}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </CardBody>
      </Card>

      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', maxWidth: 720 }}>
        Non-human identities are derived from what each connector already reads — Kafka ACL
        principals, Kong consumers, RabbitMQ users, Redis ACL users, MCP OAuth clients — and
        normalized into one model. Credentials shown are metadata only; VectaSec never reads or
        stores a secret value.
      </p>
    </Page>
  );
}

function isDefault(name: string): boolean {
  const leaf = (name || '').split(':').pop()!.toLowerCase();
  return ['guest', 'anonymous', 'default', 'admin', 'administrator', 'root', 'public'].includes(leaf);
}

function CredChip({ c }: { c: Row }) {
  const hashing = lbl(c, 'hashing');
  const weak = ['md5', 'sha1'].includes(hashing);
  const isDefaultPw = lbl(c, 'default') === 'true';
  const tone = weak || isDefaultPw ? 'var(--sev-medium-fg)' : 'var(--text-secondary)';
  return (
    <span title={`${lbl(c, 'credential_type')}${hashing && hashing !== 'unknown' ? ` · ${hashing}` : ''}`}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 3, border: `1px solid var(--border-interactive)`,
        borderRadius: 'var(--radius-sm)', padding: '1px 6px', fontSize: 'var(--text-2xs)', color: tone }}>
      {lbl(c, 'credential_type')}
      {weak && <span style={{ fontWeight: 700 }}>·{hashing}</span>}
      {isDefaultPw && <span style={{ fontWeight: 700 }}>·default</span>}
    </span>
  );
}

function GrantChip({ g }: { g: Row }) {
  const wildcard = lbl(g, 'wildcard') === 'true';
  return (
    <span title={g.name}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 3,
        border: `1px ${wildcard ? 'solid' : 'dashed'} ${wildcard ? 'var(--sev-high-fg)' : 'var(--border-interactive)'}`,
        borderRadius: 'var(--radius-sm)', padding: '1px 6px', fontSize: 'var(--text-2xs)',
        color: wildcard ? 'var(--sev-high-fg)' : 'var(--text-secondary)', fontWeight: wildcard ? 600 : 400,
        maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
      {wildcard && '✳ '}{lbl(g, 'action')}
    </span>
  );
}

function Stat({ label, value, sub, tone = 'neutral' }: {
  label: string; value: number; sub?: string; tone?: 'ok' | 'warn' | 'bad' | 'neutral';
}) {
  const color = { ok: 'var(--sev-low-fg)', warn: 'var(--sev-medium-fg)', bad: 'var(--sev-critical-fg)', neutral: 'var(--text-primary)' }[tone];
  return (
    <Card>
      <CardBody>
        <div style={{ fontSize: 'var(--text-2xs)', textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)', fontWeight: 600 }}>
          {label}
        </div>
        <div data-numeric style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color, lineHeight: 1.1, marginTop: 4 }}>
          {value}
        </div>
        {sub && <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>}
      </CardBody>
    </Card>
  );
}

function Page({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
        Identities
      </h1>
      {children}
    </div>
  );
}

function SetupState() {
  return (
    <Card><CardBody>
      <EmptyState tone="setup" title="No non-human identities yet"
        description="Connect and scan a system with users, consumers, ACLs or OAuth clients — Kafka, RabbitMQ, Kong, Redis or MCP — and its identities appear here, normalized across systems." />
      <p style={{ textAlign: 'center', margin: 0 }}>
        <Link href="/connections" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>Go to Connections →</Link>
      </p>
    </CardBody></Card>
  );
}
