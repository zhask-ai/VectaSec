import Link from 'next/link';
import { notFound } from 'next/navigation';

import { createClient } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Json, type Severity, type FindingStatus } from '@/lib/types';
import { Breadcrumbs } from '@/components/ui/breadcrumbs';
import { canEdit, getOwnMembership } from '@/lib/role';
import { ResourceHistory } from '../../changes/history-cards';
import { UsageCard } from './usage-card';
import { OwnerCard } from './owner-card';
import { WhoCan } from './who-can';
import { AiReview } from './ai-review';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { IconForType } from '@/components/ui/icons';
import { Page } from '@/components/ui/page';
import { SeverityBadge } from '@/components/ui/severity';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import {
  BlastRadius,
  BlastRadiusExplorer,
  type GraphResource,
  type LayeredEdge,
  type Neighbour,
  type RiskIndex,
} from '../_blast-radius';
import { LabelChips, StaleChip } from '../_chips';
import { absolute, labelEntries, redactSecrets, relative, worstSeverity, type LayeredNode } from '../_lib';

/* Resource detail: what it is, what it says about itself, what is wrong with it, and what it
 * touches. RLS scopes every read; no query filters by tenant_id on purpose. */

/** The `id` segment is attacker-controlled and is interpolated into a PostgREST `or=(...)`
 * filter below, which takes a RAW filter string rather than a bound parameter. A crafted id
 * containing `,` or `.` could therefore append filter terms. RLS still bounds the blast to the
 * caller's own tenant, so this is not a cross-tenant hole — but "the policy would have caught
 * it" is not a reason to hand the parser attacker input. Reject anything that is not a UUID. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type ResourceRow = {
  id: string;
  kind: string;
  name: string;
  namespace: string | null;
  labels: Json;
  raw: Json;
  ext_id: string;
  first_seen: string;
  last_seen: string;
  stale: boolean;
  connection_id: string | null;
  connections: { id: string; name: string; type: string; mode: string } | null;
};

type FindingRow = {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  first_seen: string;
  last_seen: string;
};

type EdgeRow = {
  id: string;
  kind: string;
  labels: Json;
  src_resource_id: string;
  dst_resource_id: string;
};

export default async function AssetDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ [key: string]: string | string[] | undefined }>;
}) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();

  // Graph radius: 1 = direct edges (default), 2–3 = the explorer view. Anything else is 1 —
  // the URL is user input like any other.
  const sp = await searchParams;
  const radius = sp.radius === '2' ? 2 : sp.radius === '3' ? 3 : 1;

  const supabase = await createClient();
  // Courtesy only: the review action and the engine re-check the role themselves.
  const editable = canEdit((await getOwnMembership())?.role ?? null);

  const [resourceRes, findingsRes, edgesRes] = await Promise.all([
    supabase
      .from('resources')
      .select(
        'id, kind, name, namespace, labels, raw, ext_id, first_seen, last_seen, stale, connection_id, connections(id, name, type, mode)',
      )
      .eq('id', id)
      .maybeSingle(),
    supabase
      .from('findings')
      .select('id, rule_id, title, severity, status, first_seen, last_seen')
      .eq('resource_id', id),
    supabase
      .from('edges')
      .select('id, kind, labels, src_resource_id, dst_resource_id')
      .or(`src_resource_id.eq.${id},dst_resource_id.eq.${id}`),
  ]);

  // A missing row and a denied row are indistinguishable here, and that is correct: RLS returns
  // nothing either way, so the page cannot become an existence oracle for another tenant's ids.
  if (resourceRes.error || !resourceRes.data) notFound();

  const resource = resourceRes.data as unknown as ResourceRow;
  const findings = (findingsRes.data ?? []) as FindingRow[];
  const edges = (edgesRes.data ?? []) as EdgeRow[];

  const neighbourIds = [
    ...new Set(edges.map((e) => (e.src_resource_id === id ? e.dst_resource_id : e.src_resource_id))),
  ];

  // ── The graph's node set: signed hop distance from the focus. ──────────────────────────────
  // Level ±1 comes from the direct edges already fetched; radius 2–3 walks OUTWARD along
  // src→dst and INWARD along dst→src with one bounded query per side per level. Frontiers are
  // capped so a hub node cannot turn one page load into a full-graph crawl; the explorer says
  // in words whatever the caps dropped.
  const FRONTIER_CAP = 24;
  const dist = new Map<string, number>([[id, 0]]);
  const graphEdges = new Map<string, EdgeRow>(edges.map((e) => [e.id, e]));
  let inFrontier: string[] = [];
  let outFrontier: string[] = [];
  for (const e of edges) {
    if (e.dst_resource_id === id && !dist.has(e.src_resource_id)) {
      dist.set(e.src_resource_id, -1);
      inFrontier.push(e.src_resource_id);
    }
  }
  for (const e of edges) {
    if (e.src_resource_id === id && !dist.has(e.dst_resource_id)) {
      dist.set(e.dst_resource_id, 1);
      outFrontier.push(e.dst_resource_id);
    }
  }

  for (let hop = 2; hop <= radius; hop++) {
    const [outRes, inRes] = await Promise.all([
      outFrontier.length
        ? supabase
            .from('edges')
            .select('id, kind, labels, src_resource_id, dst_resource_id')
            .in('src_resource_id', outFrontier.slice(0, FRONTIER_CAP))
            .limit(200)
        : Promise.resolve({ data: [] as EdgeRow[], error: null }),
      inFrontier.length
        ? supabase
            .from('edges')
            .select('id, kind, labels, src_resource_id, dst_resource_id')
            .in('dst_resource_id', inFrontier.slice(0, FRONTIER_CAP))
            .limit(200)
        : Promise.resolve({ data: [] as EdgeRow[], error: null }),
    ]);
    const nextOut: string[] = [];
    const nextIn: string[] = [];
    for (const e of (outRes.data ?? []) as EdgeRow[]) {
      graphEdges.set(e.id, e);
      if (!dist.has(e.dst_resource_id)) {
        dist.set(e.dst_resource_id, hop);
        nextOut.push(e.dst_resource_id);
      }
    }
    for (const e of (inRes.data ?? []) as EdgeRow[]) {
      graphEdges.set(e.id, e);
      if (!dist.has(e.src_resource_id)) {
        dist.set(e.src_resource_id, -hop);
        nextIn.push(e.src_resource_id);
      }
    }
    outFrontier = nextOut;
    inFrontier = nextIn;
    if (!outFrontier.length && !inFrontier.length) break;
  }

  const graphIds = [...dist.keys()].filter((rid) => rid !== id);

  // Node identities AND their open-finding load in one round: the graph paints each node
  // with its risk badge, because "what this touches" matters most when what it touches is
  // itself on fire. A failed risk read degrades to badge-less nodes, never to a blank graph.
  const [nodesRes, riskRes] = await Promise.all([
    graphIds.length
      ? supabase.from('resources').select('id, kind, name, stale').in('id', graphIds.slice(0, 200))
      : Promise.resolve({ data: [], error: null }),
    graphIds.length
      ? supabase
          .from('findings')
          .select('resource_id, severity')
          .eq('status', 'open')
          .in('resource_id', [...graphIds.slice(0, 200), id])
      : Promise.resolve({ data: [], error: null }),
  ]);

  const byId = new Map<string, GraphResource>(
    ((nodesRes.data ?? []) as GraphResource[]).map((r) => [r.id, r]),
  );

  const risk: RiskIndex = {};
  {
    const grouped = new Map<string, Severity[]>();
    for (const row of (riskRes.data ?? []) as { resource_id: string; severity: Severity }[]) {
      const arr = grouped.get(row.resource_id);
      if (arr) arr.push(row.severity);
      else grouped.set(row.resource_id, [row.severity]);
    }
    for (const [rid, sevs] of grouped) {
      const worst = worstSeverity(sevs);
      if (worst) risk[rid] = { worst, open: sevs.length };
    }
  }

  const neighbours: Neighbour[] = edges
    .map((e) => {
      const outbound = e.src_resource_id === id;
      const otherId = outbound ? e.dst_resource_id : e.src_resource_id;
      return {
        edgeId: e.id,
        edgeKind: e.kind,
        direction: (outbound ? 'out' : 'in') as 'in' | 'out',
        resourceId: otherId,
        resource: byId.get(otherId) ?? null,
      };
    })
    .sort((a, b) => (a.resource?.name ?? '').localeCompare(b.resource?.name ?? ''));

  const focus: GraphResource = {
    id: resource.id,
    kind: resource.kind,
    name: resource.name,
    stale: resource.stale,
  };

  const open = findings.filter((f) => f.status === 'open');
  const sortedFindings = [...findings].sort(
    (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.title.localeCompare(b.title),
  );

  // The focus node wears its own risk badge, computed from the findings already loaded.
  const focusWorst = worstSeverity(open.map((f) => f.severity));
  if (focusWorst) risk[resource.id] = { worst: focusWorst, open: open.length };

  const inbound = neighbours.filter((n) => n.direction === 'in').length;
  const outbound = neighbours.length - inbound;

  return (
    <Page>
      <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
        <Breadcrumbs items={[{ label: 'Estate', href: '/estate' }, { label: 'Inventory', href: '/estate/inventory' }, { label: resource.name }]} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <span aria-hidden="true" className="vs-icontile" data-size="lg" data-tone="accent">
            <IconForType type={resource.kind} size={18} />
          </span>
          <h1
            style={{
              margin: 0,
              fontSize: 'var(--text-xl)',
              lineHeight: 'var(--leading-xl)',
              fontWeight: 640,
              fontFamily: 'var(--font-mono)',
              letterSpacing: '-0.01em',
              wordBreak: 'break-all',
            }}
          >
            {resource.name}
          </h1>
          {focusWorst && <SeverityBadge severity={focusWorst} count={open.length} />}
          {resource.stale && <StaleChip />}
        </div>
      </div>

      {/* Stale is the one fact that changes how every other fact on this page should be read,
          so it is stated once, loudly, above them — not left as a chip beside the title. */}
      {resource.stale && (
        <Card style={{ borderColor: 'var(--sev-medium-fg)' }}>
          <CardBody>
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
              <strong>This asset was not returned by the most recent scan.</strong> Everything below
              was last confirmed {relative(resource.last_seen)} ({absolute(resource.last_seen)}) and
              may no longer exist. A resource that disappears is itself worth explaining — it may
              have been deleted, renamed, or moved out of the collector&rsquo;s reach.
            </p>
          </CardBody>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Identity</CardTitle>
          <CardMeta>
            first seen {relative(resource.first_seen)} · last seen {relative(resource.last_seen)}
          </CardMeta>
        </CardHeader>
        <CardBody>
          <dl
            style={{
              display: 'grid',
              gridTemplateColumns: 'max-content 1fr',
              gap: 'var(--space-2) var(--space-5)',
              margin: 0,
              fontSize: 'var(--text-xs)',
              alignItems: 'baseline',
            }}
          >
            <Term>Kind</Term>
            <Def mono>{resource.kind}</Def>

            <Term>Namespace</Term>
            <Def mono muted={!resource.namespace}>{resource.namespace ?? '—'}</Def>

            <Term>Connection</Term>
            <Def>
              {resource.connections ? (
                <Link href={'/estate'} style={{ color: 'var(--text-primary)' }}>
                  {resource.connections.name}
                  <span style={{ color: 'var(--text-secondary)' }}>
                    {' '}
                    · {resource.connections.type} · {resource.connections.mode}
                  </span>
                </Link>
              ) : (
                <span style={{ color: 'var(--text-muted)' }}>— (connection removed)</span>
              )}
            </Def>

            <Term>External ID</Term>
            <Def mono>{resource.ext_id}</Def>

            <Term>First seen</Term>
            <Def mono>{absolute(resource.first_seen)}</Def>

            <Term>Last seen</Term>
            <Def mono>{absolute(resource.last_seen)}</Def>

            <Term>Labels</Term>
            <Def>
              <LabelChips labels={resource.labels} max={12} />
            </Def>
          </dl>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
          <CardMeta>
            {open.length} open of {findings.length}
          </CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {sortedFindings.length === 0 ? (
            <EmptyState
              tone="clean"
              title="No findings on this asset"
              description="Every rule that applies to this resource kind passed."
              meta={`last scanned ${relative(resource.last_seen)}`}
            />
          ) : (
            <Table density="compact" caption={`Findings on ${resource.name}, most severe first`}>
              <THead>
                <TR>
                  <TH width="10%" sort="desc">
                    Severity
                  </TH>
                  <TH width="44%">Title</TH>
                  <TH width="24%">Rule</TH>
                  <TH width="10%">Status</TH>
                  <TH width="12%" numeric>
                    Last seen
                  </TH>
                </TR>
              </THead>
              <TBody>
                {sortedFindings.map((f) => (
                  <TR key={f.id}>
                    <TD>
                      <SeverityBadge severity={f.severity} />
                    </TD>
                    <TD>{f.title}</TD>
                    <TD mono muted>
                      {f.rule_id}
                    </TD>
                    <TD>
                      <StatusText status={f.status} />
                    </TD>
                    <TD numeric muted>
                      <span title={absolute(f.last_seen)}>{relative(f.last_seen)}</span>
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
          <CardTitle>Blast radius</CardTitle>
          <CardMeta>
            {inbound} inbound · {outbound} outbound
            {radius === 1 ? ' · direct edges only' : ` · exploring ${radius} hops · ${graphIds.length} nodes`}
          </CardMeta>
        </CardHeader>
        <CardBody>
          {neighbours.length === 0 ? (
            <EmptyState
              tone="clean"
              title="No connected resources"
              description="No edge in this tenant references this resource. It is isolated as far as the last scan could see — which is not the same as isolated."
              meta={`scanned ${relative(resource.last_seen)}`}
            />
          ) : (
            <>
              {/* Radius control — URL state, so an explored view is shareable and the back
                  button walks the exploration. Click a node to refocus on it; widen the radius
                  to research from right here. */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', marginBottom: 'var(--space-3)', flexWrap: 'wrap' }}>
                <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginRight: 'var(--space-1)' }}>
                  Radius
                </span>
                {([1, 2, 3] as const).map((r) => (
                  <Link
                    key={r}
                    href={`/estate/inventory/${resource.id}${r === 1 ? '' : `?radius=${r}`}`}
                    className="vs-filterpill"
                    data-active={radius === r || undefined}
                    aria-current={radius === r ? 'true' : undefined}
                  >
                    {r === 1 ? 'Direct' : `${r} hops`}
                  </Link>
                ))}
                <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                  · every node is a link — click through to refocus
                </span>
              </div>
              {radius === 1 ? (
                <BlastRadius focus={focus} neighbours={neighbours} risk={risk} />
              ) : (
                <BlastRadiusExplorer
                  focus={focus}
                  nodes={graphIds
                    .map((rid): LayeredNode | null => {
                      const r = byId.get(rid);
                      const d = dist.get(rid);
                      return r && d !== undefined ? { ...r, d } : null;
                    })
                    .filter((n): n is LayeredNode => n !== null)}
                  edges={[...graphEdges.values()].map(
                    (e): LayeredEdge => ({ id: e.id, kind: e.kind, src: e.src_resource_id, dst: e.dst_resource_id }),
                  )}
                  risk={risk}
                />
              )}
              <div style={{ marginTop: 'var(--space-4)' }}>
                <Table density="compact" caption={`Resources directly connected to ${resource.name}`}>
                  <THead>
                    <TR>
                      <TH width="12%">Direction</TH>
                      <TH width="18%">Edge</TH>
                      <TH width="14%">Kind</TH>
                      <TH width="56%">Resource</TH>
                    </TR>
                  </THead>
                  <TBody>
                    {neighbours.map((n) => (
                      <TR key={n.edgeId}>
                        <TD>
                          <DirectionMark direction={n.direction} />
                        </TD>
                        <TD>
                          <Chip mono>{n.edgeKind}</Chip>
                        </TD>
                        <TD>
                          {n.resource ? (
                            <Chip mono>{n.resource.kind}</Chip>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </TD>
                        <TD>
                          {n.resource ? (
                            <span
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 'var(--space-2)',
                              }}
                            >
                              <Link
                                href={`/estate/inventory/${n.resource.id}`}
                                style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}
                              >
                                {n.resource.name}
                              </Link>
                              {n.resource.stale && <StaleChip />}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>
                              not readable ({n.resourceId})
                            </span>
                          )}
                        </TD>
                      </TR>
                    ))}
                  </TBody>
                </Table>
              </div>
            </>
          )}
        </CardBody>
      </Card>

      {resource.kind === 'identity' && (
        <OwnerCard
          resourceId={resource.id}
          extId={resource.ext_id}
          inferred={typeof (resource.labels as Record<string, unknown>)?.owner_label === 'string' ? ((resource.labels as Record<string, string>).owner_label as string) : null}
          editable={editable}
        />
      )}

      <WhoCan resourceId={resource.id} kind={resource.kind} />

      <UsageCard resourceId={resource.id} kind={resource.kind} />

      <ResourceHistory resourceId={resource.id} />

      <Card>
        <CardHeader>
          <CardTitle>AI review</CardTitle>
          <CardMeta>suggestions, not findings</CardMeta>
        </CardHeader>
        <CardBody>
          <AiReview resourceId={resource.id} editable={editable} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Raw configuration</CardTitle>
          <CardMeta>as collected · {relative(resource.last_seen)}</CardMeta>
        </CardHeader>
        <CardBody>
          {/* <details> rather than a client component: `raw` is a collector payload and the one
              genuinely sensitive object on this page. Native disclosure keeps it inside the RSC
              boundary, so it is never serialised into a client bundle's props. */}
          <details>
            <summary
              style={{
                cursor: 'pointer',
                fontSize: 'var(--text-xs)',
                color: 'var(--text-secondary)',
                userSelect: 'none',
              }}
            >
              Show the payload this resource was built from
            </summary>
            <pre
              style={{
                margin: 'var(--space-3) 0 0',
                padding: 'var(--space-3)',
                maxHeight: 520,
                overflow: 'auto',
                background: 'var(--bg)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'var(--text-2xs)',
                lineHeight: 'var(--leading-2xs)',
                color: 'var(--text-primary)',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {JSON.stringify(redactSecrets(resource.raw), null, 2)}
            </pre>
            <p
              style={{
                margin: 'var(--space-2) 0 0',
                fontSize: 'var(--text-2xs)',
                color: 'var(--text-secondary)',
              }}
            >
              Secret-looking string values are masked for display. Detectors ran against the
              unmasked payload, so nothing here changes what was or was not found.
            </p>
          </details>
        </CardBody>
      </Card>
    </Page>
  );
}

function Term({ children }: { children: React.ReactNode }) {
  return (
    <dt
      style={{
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
      }}
    >
      {children}
    </dt>
  );
}

function Def({
  children,
  mono = false,
  muted = false,
}: {
  children: React.ReactNode;
  mono?: boolean;
  muted?: boolean;
}) {
  return (
    <dd
      style={{
        margin: 0,
        fontFamily: mono ? 'var(--font-mono)' : 'inherit',
        color: muted ? 'var(--text-muted)' : 'var(--text-primary)',
        wordBreak: 'break-all',
      }}
    >
      {children}
    </dd>
  );
}

/** Direction is a word, not an arrow glyph alone — and the wording says what it MEANS for blast
 * radius ("reaches this" / "is reached by") rather than restating the column header. */
function DirectionMark({ direction }: { direction: 'in' | 'out' }) {
  const inbound = direction === 'in';
  return (
    <span
      title={inbound ? 'This resource is a destination of the edge' : 'This resource is the source of the edge'}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)', color: 'var(--text-secondary)' }}
    >
      <span aria-hidden="true" style={{ fontFamily: 'var(--font-mono)' }}>
        {inbound ? '→|' : '|→'}
      </span>
      {inbound ? 'inbound' : 'outbound'}
    </span>
  );
}

const STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  triaged: 'In progress',
  in_progress: 'In progress',
  resolved: 'Resolved',
  suppressed: 'Muted',
  accepted: 'Muted',
};

function StatusText({ status }: { status: FindingStatus }) {
  const muted = status === 'resolved' || status === 'suppressed' || status === 'accepted';
  return (
    <span style={{ color: muted ? 'var(--text-secondary)' : 'var(--text-primary)' }}>
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}
