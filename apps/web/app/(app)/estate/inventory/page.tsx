import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import type { Json, Severity } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { IconForType } from '@/components/ui/icons';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { EstateTabs } from '../tabs';
import { SeverityBadge } from '@/components/ui/severity';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { Toolbar, ToolbarField } from '@/components/ui/toolbar';
import { LabelChips, StaleChip } from './_chips';
import { byRisk, relative, absolute, worstSeverity } from './_lib';

/* Asset inventory — what we found, one dense risk-sorted table.
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

export const metadata = { title: 'Estate · Inventory · VectaSec' };

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

  // A page of resources + the EXACT filtered total in one query. count:'exact' is computed
  // server-side and is NOT truncated at Max Rows the way the row array (capped at LIST_LIMIT) is.
  // Ordered by recency so the cap is deterministic; the page is re-sorted by risk for display.
  let resourcesQ = supabase
    .from('resources')
    .select(
      'id, kind, name, namespace, labels, first_seen, last_seen, stale, connection_id, connections(id, name, type)',
      { count: 'exact' },
    )
    .order('last_seen', { ascending: false })
    .limit(LIST_LIMIT);
  if (kindFilter) resourcesQ = resourcesQ.eq('kind', kindFilter);
  if (connFilter) resourcesQ = resourcesQ.eq('connection_id', connFilter);

  // Exact stale total within the current filter — a head count, never a JS tally of a capped array.
  let staleQ = supabase.from('resources').select('id', { count: 'exact', head: true }).eq('stale', true);
  if (kindFilter) staleQ = staleQ.eq('kind', kindFilter);
  if (connFilter) staleQ = staleQ.eq('connection_id', connFilter);

  const [resourcesRes, staleRes, unfilteredRes, connectionsRes] = await Promise.all([
    resourcesQ,
    staleQ,
    // The unfiltered total, to tell "no assets at all" (onboarding) apart from "none match this
    // filter" (too narrow) — the two must never read alike in this console.
    supabase.from('resources').select('id', { count: 'exact', head: true }),
    supabase.from('connections').select('id, name, type').order('name'),
  ]);

  const error = resourcesRes.error ?? staleRes.error ?? unfilteredRes.error ?? connectionsRes.error;
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
  const connections = (connectionsRes.data ?? []) as ConnectionRow[];
  const total = resourcesRes.count ?? rows.length; // filtered total (M)
  const totalUnfiltered = unfilteredRes.count ?? 0;
  const staleTotal = staleRes.count ?? 0;

  if (connections.length === 0) {
    return (
      <Page>
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="No systems connected"
              description="Assets are discovered by scanning a connected system. Connect one to build the inventory."
              action={<LinkButton href={'/estate'}>Go to Connections</LinkButton>}
            />
          </CardBody>
        </Card>
      </Page>
    );
  }

  if (totalUnfiltered === 0) {
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

  // Open-finding tallies ONLY for the resources on this page: bounded by what is shown, never an
  // unbounded tenant-wide fetch. A single resource's open findings are bounded by the rulepack, so
  // even a full page stays far under Max Rows — the property that made the old tenant-wide select
  // silently wrong does not apply to a page-scoped `.in(...)`.
  const pageIds = rows.map((r) => r.id);
  const openByResource = new Map<string, Severity[]>();
  if (pageIds.length > 0) {
    // status='open' exactly, matching the Overview's query — consistency across the console
    // outranks a broader definition of "unresolved" here.
    const findingsRes = await supabase
      .from('findings')
      .select('resource_id, severity')
      .eq('status', 'open')
      .in('resource_id', pageIds);

    if (findingsRes.error) {
      return (
        <Page>
          <Card>
            <CardBody>
              <EmptyState tone="error" title="Could not load findings" description={findingsRes.error.message} />
            </CardBody>
          </Card>
        </Page>
      );
    }

    for (const f of (findingsRes.data ?? []) as FindingRow[]) {
      if (!f.resource_id) continue;
      const list = openByResource.get(f.resource_id);
      if (list) list.push(f.severity);
      else openByResource.set(f.resource_id, [f.severity]);
    }
  }

  const assets: Asset[] = rows.map((r) => {
    const sevs = openByResource.get(r.id) ?? [];
    return { ...r, open: sevs.length, worst: worstSeverity(sevs) };
  });

  // Kinds for the dropdown come from the page, unioned with the active kind so a filter never
  // removes its own escape route. Past the cap this list can be partial — the footer says so, and
  // there is no view to enumerate kinds exactly without an unbounded scan (and no RPC, which would
  // bypass RLS). A capped-but-honest dropdown beats a silently-wrong one.
  const kinds = [...new Set([...(kindFilter ? [kindFilter] : []), ...assets.map((a) => a.kind)])].sort();

  const shown = assets.length;
  const truncated = total > shown;

  // One flat table, globally risk-sorted: worst severity first, then most open findings, then
  // name. Kind moves from a group header to a column, so the whole estate ranks on one axis and
  // the most dangerous asset is always the top row — not buried inside whichever kind sorted first.
  const sorted = [...assets].sort(byRisk);

  const meta = `Showing ${shown} of ${total} asset${total === 1 ? '' : 's'}${
    shown < total ? ' — refine to see more' : ''
  }${staleTotal > 0 ? ` · ${staleTotal} stale` : ''}`;

  return (
    <Page meta={meta}>
      <Filters kinds={kinds} connections={connections} kindFilter={kindFilter} connFilter={connFilter} />

      {total === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              tone="filtered"
              title="No assets match these filters"
              description="Every asset was excluded by the current kind or connection filter. The inventory itself is not empty."
              meta={`${totalUnfiltered} asset${totalUnfiltered === 1 ? '' : 's'} total`}
              action={<LinkButton href={'/estate/inventory'}>Clear filters</LinkButton>}
            />
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Inventory</CardTitle>
            <CardMeta>
              {shown} of {total} shown · most at risk first
            </CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Asset inventory, most at risk first">
              <THead>
                <TR>
                  <TH width="24%">Name</TH>
                  <TH width="15%">Connection</TH>
                  <TH width="10%">Kind</TH>
                  <TH width="20%">Labels</TH>
                  <TH width="12%" sort="desc">
                    Open findings
                  </TH>
                  <TH width="9%" numeric>
                    First seen
                  </TH>
                  <TH width="9%" numeric>
                    Last seen
                  </TH>
                </TR>
              </THead>
              <TBody>
                {sorted.map((a) => (
                  <TR key={a.id}>
                    <TD>
                      <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-2) 0' }}>
                        <span aria-hidden="true" className="vs-icontile">
                          <IconForType type={a.kind} />
                        </span>
                        <span style={{ display: 'grid', gap: 1, minWidth: 0 }}>
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 'var(--space-2)',
                              minWidth: 0,
                            }}
                          >
                            <Link
                              href={`/estate/inventory/${a.id}`}
                              style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}
                            >
                              {a.name}
                            </Link>
                            {a.stale && <StaleChip />}
                          </span>
                          {a.namespace && (
                            <span
                              style={{
                                color: 'var(--text-secondary)',
                                fontSize: 'var(--text-2xs)',
                              }}
                            >
                              {a.namespace}
                            </span>
                          )}
                        </span>
                      </span>
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
                      <Chip mono>{a.kind}</Chip>
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

          {truncated && (
            <CardFooter>
              Showing the {shown} most recently seen of {total} matching asset
              {total === 1 ? '' : 's'}. Narrow by kind or connection to see the rest — beyond{' '}
              {LIST_LIMIT} rows the answer is a filter, not a longer page.
            </CardFooter>
          )}
        </Card>
      )}
    </Page>
  );
}

function Page({ children, meta }: { children: React.ReactNode; meta?: string }) {
  return (
    <PageShell>
      <PageHeader
        title="Estate"
        description="The inventory built from your connected systems — every resource a scan has returned."
        meta={meta}
      />
      <EstateTabs />
      {children}
    </PageShell>
  );
}

/** A plain GET form: no client component, no JS, and the filter state lives in the URL where it
 * can be linked, bookmarked and pasted into a ticket. The Toolbar is the design-system home for a
 * table's filter row — one row above the content, never a rail stealing the dense table's width. */
function Filters({
  kinds,
  connections,
  kindFilter,
  connFilter,
}: {
  kinds: string[];
  connections: ConnectionRow[];
  kindFilter: string | null;
  connFilter: string | null;
}) {
  const active = kindFilter !== null || connFilter !== null;

  return (
    <form method="GET">
      <Toolbar
        end={
          <>
            <Button type="submit" variant="secondary" size="sm">
              Apply
            </Button>
            {active && <LinkButton href={'/estate/inventory'}>Clear</LinkButton>}
          </>
        }
      >
        <ToolbarField label="Kind" htmlFor="filter-kind">
          <select id="filter-kind" name="kind" defaultValue={kindFilter ?? ''} style={controlStyle}>
            <option value="">All</option>
            {kinds.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
        </ToolbarField>
        <ToolbarField label="Connection" htmlFor="filter-connection">
          <select id="filter-connection" name="connection" defaultValue={connFilter ?? ''} style={controlStyle}>
            <option value="">All</option>
            {connections.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name} ({c.type})
              </option>
            ))}
          </select>
        </ToolbarField>
      </Toolbar>
    </form>
  );
}

// This border is the control's ONLY boundary — surface-raised vs surface is 1.10:1 in dark and
// 1.00:1 in light, so the fill draws nothing. --border-interactive is the token that exists for
// exactly this case (globals.css says so, and every other control in the console uses it).
const controlStyle: React.CSSProperties = {
  height: 'var(--row-compact)',
  minWidth: 160,
  padding: '0 var(--space-2)',
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border-interactive)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
};

function LinkButton({ href, children }: { href: Route; children: React.ReactNode }) {
  return (
    <Link
      href={href}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        height: 'var(--row-compact)',
        padding: '0 var(--space-3)',
        borderRadius: 'var(--radius-md)',
        // Button-shaped, so its outline is a control indicator and owes 3:1 — same rule as the
        // <select> above and the Apply <button> beside it.
        border: '1px solid var(--border-interactive)',
        background: 'var(--surface)',
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
