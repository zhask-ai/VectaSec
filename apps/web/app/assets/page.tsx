import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import type { Json, Severity } from '@/lib/types';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { SeverityBadge } from '@/components/ui/severity';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { LabelChips, StaleChip } from './_chips';
import { byRisk, relative, absolute, worstSeverity } from './_lib';

/* Asset inventory — what we found, grouped by kind.
 *
 * Reads cookies via the Supabase server client, so this route is dynamic and never prerendered.
 * RLS scopes every read to the caller's tenant; there is deliberately no tenant_id filter in
 * any query here — a WHERE clause is a suggestion, a policy is a boundary.
 *
 * PAGINATION. This page used to `.select()` every resource and every open finding unbounded and
 * tally them in JS. PostgREST caps an unbounded response at Max Rows (1000 on hosted Supabase), so
 * past the cap the inventory and its counts were silently wrong. Now: a page of resources capped at
 * LIST_LIMIT, the true totals via count:'exact' head queries (never truncated), and per-resource
 * open-finding tallies fetched only for the resources on the page — bounded by what is shown, not
 * by the whole tenant. A visibly-capped page ("showing N of M") is honest; a silently-wrong one is
 * not. No SECURITY DEFINER RPC: that would run as postgres/BYPASSRLS and leak every tenant.
 */

/** Row ceiling, same posture as the findings queue (data.ts): past this the answer is a filter,
 * not a longer page — and the count beside it is the true total, so the UI says how much it is not
 * showing rather than quietly truncating. */
const LIST_LIMIT = 500;

type ResourceRow = {
  id: string;
  kind: string;
  name: string;
  namespace: string | null;
  labels: Json;
  first_seen: string;
  last_seen: string;
  stale: boolean;
  connection_id: string | null;
  connections: { id: string; name: string; type: string } | null;
};

type FindingRow = { resource_id: string | null; severity: Severity };
type ConnectionRow = { id: string; name: string; type: string };

type Asset = ResourceRow & { open: number; worst: Severity | null };

export const metadata = { title: 'Assets · VectaSec' };

export default async function AssetsPage({
  searchParams,
}: {
  searchParams: Promise<{ kind?: string; connection?: string }>;
}) {
  const params = await searchParams;
  // A native GET form submits empty selects as `?kind=`, which is not a filter.
  const kindFilter = params.kind?.trim() || null;
  const connFilter = params.connection?.trim() || null;

  const supabase = await createClient();

  const [resourcesRes, findingsRes, connectionsRes] = await Promise.all([
    supabase
      .from('resources')
      .select(
        'id, kind, name, namespace, labels, first_seen, last_seen, stale, connection_id, connections(id, name, type)',
      ),
    // status='open' exactly, matching the Overview's query. If Overview says 12 open and this
    // page's columns sum to 18, the number nobody can reconcile is the one nobody trusts —
    // consistency across the console outranks a broader definition of "unresolved" here.
    supabase.from('findings').select('resource_id, severity').eq('status', 'open'),
    supabase.from('connections').select('id, name, type'),
  ]);

  const error = resourcesRes.error ?? findingsRes.error ?? connectionsRes.error;
  if (error) {
    return (
      <Page>
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load assets" description={error.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const rows = (resourcesRes.data ?? []) as unknown as ResourceRow[];
  const findings = (findingsRes.data ?? []) as FindingRow[];
  const connections = (connectionsRes.data ?? []) as ConnectionRow[];

  const openByResource = new Map<string, Severity[]>();
  for (const f of findings) {
    if (!f.resource_id) continue;
    const list = openByResource.get(f.resource_id);
    if (list) list.push(f.severity);
    else openByResource.set(f.resource_id, [f.severity]);
  }

  const assets: Asset[] = rows.map((r) => {
    const sevs = openByResource.get(r.id) ?? [];
    return { ...r, open: sevs.length, worst: worstSeverity(sevs) };
  });

  // Options come from the whole inventory, not the filtered slice — a filter that removes its
  // own escape route is a trap.
  const kinds = [...new Set(assets.map((a) => a.kind))].sort();

  const filtered = assets.filter(
    (a) =>
      (kindFilter === null || a.kind === kindFilter) &&
      (connFilter === null || a.connection_id === connFilter),
  );

  const staleTotal = assets.filter((a) => a.stale).length;

  if (connections.length === 0) {
    return (
      <Page>
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="No systems connected"
              description="Assets are discovered by scanning a connected system. Connect one to build the inventory."
              action={<LinkButton href={'/connections'}>Go to Connections</LinkButton>}
            />
          </CardBody>
        </Card>
      </Page>
    );
  }

  if (assets.length === 0) {
    return (
      <Page>
        <Card>
          <CardBody>
            <EmptyState
              tone="pending"
              title="No assets discovered yet"
              description="Connected, but no scan has returned a resource. The inventory fills in as scans complete."
              meta={`${connections.length} connection${connections.length === 1 ? '' : 's'} configured`}
            />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const byKind = new Map<string, Asset[]>();
  for (const a of filtered) {
    const list = byKind.get(a.kind);
    if (list) list.push(a);
    else byKind.set(a.kind, [a]);
  }

  // Groups ordered by their worst finding, then by size. Severity order is a redundant channel
  // that survives greyscale when hue does not.
  const groups = [...byKind.entries()]
    .map(([kind, items]) => ({
      kind,
      items: [...items].sort(byRisk),
      worst: worstSeverity(items.flatMap((i) => (i.worst ? [i.worst] : []))),
      open: items.reduce((n, i) => n + i.open, 0),
      stale: items.filter((i) => i.stale).length,
    }))
    .sort((a, b) =>
      byRisk(
        { worst: a.worst, open: a.open, name: a.kind },
        { worst: b.worst, open: b.open, name: b.kind },
      ),
    );

  return (
    <Page>
      <Filters
        kinds={kinds}
        connections={connections}
        kindFilter={kindFilter}
        connFilter={connFilter}
        showing={filtered.length}
        total={assets.length}
        stale={staleTotal}
      />

      {filtered.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              tone="filtered"
              title="No assets match these filters"
              description="Every asset was excluded by the current kind or connection filter. The inventory itself is not empty."
              meta={`${assets.length} asset${assets.length === 1 ? '' : 's'} total`}
              action={<LinkButton href={'/assets'}>Clear filters</LinkButton>}
            />
          </CardBody>
        </Card>
      ) : (
        groups.map((g) => (
          <Card key={g.kind}>
            <CardHeader>
              <CardTitle>
                {g.kind}
                <span
                  style={{
                    marginLeft: 'var(--space-2)',
                    color: 'var(--text-secondary)',
                    fontSize: 'var(--text-sm)',
                    fontWeight: 400,
                  }}
                >
                  {g.items.length}
                </span>
              </CardTitle>
              <CardMeta>
                {g.open} open finding{g.open === 1 ? '' : 's'}
                {g.stale > 0 && ` · ${g.stale} stale`}
              </CardMeta>
            </CardHeader>
            <CardBody pad={false}>
              <Table density="compact" caption={`${g.kind} assets, most at risk first`}>
                <THead>
                  <TR>
                    <TH width="34%">Name</TH>
                    <TH width="16%">Connection</TH>
                    <TH width="26%">Labels</TH>
                    <TH width="12%" sort="desc">
                      Open findings
                    </TH>
                    <TH width="6%" numeric>
                      First seen
                    </TH>
                    <TH width="6%" numeric>
                      Last seen
                    </TH>
                  </TR>
                </THead>
                <TBody>
                  {g.items.map((a) => (
                    <TR key={a.id}>
                      <TD>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 'var(--space-2)',
                            minWidth: 0,
                          }}
                        >
                          <Link
                            href={`/assets/${a.id}`}
                            style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}
                          >
                            {a.name}
                          </Link>
                          {a.stale && <StaleChip />}
                        </span>
                        {a.namespace && (
                          <span
                            style={{
                              marginLeft: 'var(--space-2)',
                              color: 'var(--text-secondary)',
                              fontSize: 'var(--text-2xs)',
                            }}
                          >
                            {a.namespace}
                          </span>
                        )}
                      </TD>
                      <TD>
                        {a.connections ? (
                          <span style={{ color: 'var(--text-secondary)' }}>
                            {a.connections.name}
                            <span style={{ color: 'var(--text-muted)' }}> · {a.connections.type}</span>
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </TD>
                      <TD>
                        <LabelChips labels={a.labels} />
                      </TD>
                      <TD>
                        {a.worst ? (
                          <SeverityBadge severity={a.worst} count={a.open} />
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>none</span>
                        )}
                      </TD>
                      <TD numeric muted>
                        <span title={absolute(a.first_seen)}>{relative(a.first_seen)}</span>
                      </TD>
                      <TD numeric muted>
                        <span title={absolute(a.last_seen)}>{relative(a.last_seen)}</span>
                      </TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </CardBody>
          </Card>
        ))
      )}
    </Page>
  );
}

function Page({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
        Assets
      </h1>
      {children}
    </div>
  );
}

/** A plain GET form: no client component, no JS, and the filter state lives in the URL where it
 * can be linked, bookmarked and pasted into a ticket. */
function Filters({
  kinds,
  connections,
  kindFilter,
  connFilter,
  showing,
  total,
  stale,
}: {
  kinds: string[];
  connections: ConnectionRow[];
  kindFilter: string | null;
  connFilter: string | null;
  showing: number;
  total: number;
  stale: number;
}) {
  const active = kindFilter !== null || connFilter !== null;

  return (
    <Card>
      <CardBody>
        <form
          method="GET"
          style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', gap: 'var(--space-3)' }}
        >
          <Field label="Kind" name="kind" value={kindFilter} options={kinds.map((k) => ({ value: k, label: k }))} />
          <Field
            label="Connection"
            name="connection"
            value={connFilter}
            options={connections.map((c) => ({ value: c.id, label: `${c.name} (${c.type})` }))}
          />

          <button
            type="submit"
            style={{
              height: 'var(--row-compact)',
              padding: '0 var(--space-4)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--border-interactive)',
              background: 'var(--surface-raised)',
              color: 'var(--text-primary)',
              fontSize: 'var(--text-xs)',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Apply
          </button>

          {active && <LinkButton href={'/assets'}>Clear</LinkButton>}

          <span
            aria-live="polite"
            style={{
              marginLeft: 'auto',
              fontSize: 'var(--text-2xs)',
              color: 'var(--text-secondary)',
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            Showing {showing} of {total} asset{total === 1 ? '' : 's'}
            {stale > 0 && ` · ${stale} stale`}
          </span>
        </form>
      </CardBody>
    </Card>
  );
}

function Field({
  label,
  name,
  value,
  options,
}: {
  label: string;
  name: string;
  value: string | null;
  options: { value: string; label: string }[];
}) {
  return (
    <label style={{ display: 'grid', gap: 'var(--space-1)' }}>
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase' }}>
        {label}
      </span>
      <select
        name={name}
        defaultValue={value ?? ''}
        style={{
          height: 'var(--row-compact)',
          minWidth: 180,
          padding: '0 var(--space-2)',
          borderRadius: 'var(--radius-md)',
          // This border is the control's ONLY boundary — surface-raised vs surface is 1.10:1 in
          // dark and 1.00:1 in light, so the fill draws nothing. --border-strong is 1.66:1 here
          // and fails SC 1.4.11's 3:1; --border-interactive is the token that exists for exactly
          // this case (globals.css says so, and every other control in the console uses it).
          border: '1px solid var(--border-interactive)',
          background: 'var(--surface-raised)',
          color: 'var(--text-primary)',
          fontSize: 'var(--text-xs)',
        }}
      >
        <option value="">All</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function LinkButton({ href, children }: { href: Route; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        height: 'var(--row-compact)',
        padding: '0 var(--space-4)',
        borderRadius: 'var(--radius-md)',
        // Button-shaped, so its outline is a control indicator and owes 3:1 — same rule as the
        // <select> above and the Apply <button> beside it.
        border: '1px solid var(--border-interactive)',
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-xs)',
        fontWeight: 600,
        textDecoration: 'none',
      }}
    >
      {children}
    </Link>
  );
}
