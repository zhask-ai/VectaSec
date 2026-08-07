import type { Severity } from '@/lib/types';
import { IconForType } from '@/components/ui/icons';
import {
  clamp,
  COL_X,
  layoutColumns,
  layoutLayers,
  MAX_PER_SIDE,
  NODE_H,
  NODE_W,
  type LayeredNode,
} from './_lib';

/* Blast radius — the focus resource and its DIRECT edges, drawn as an inline-SVG graph on a
 * dot-lattice canvas (.vs-canvas): the security-graph register Wiz/Datadog readers expect.
 *
 * No graph library, deliberately: a force layout would need a client bundle and a CDN-ish
 * dependency on a page whose whole job is to be trustworthy, and it would animate nodes into
 * positions that mean nothing. This is a static two-column flow instead, and the columns carry
 * the meaning:
 *
 *     [ what can reach this ]  →  ( FOCUS )  →  [ what this can reach ]
 *
 * Direction is the entire point of a blast radius — "who can call me" and "what do I call" are
 * different security questions — so it is encoded by POSITION, repeated by the arrowheads, and
 * echoed by the animated flow along each edge (decorative; the dash rides an edge that already
 * points). Every neighbour node is a REAL LINK to its own asset page, and carries its open-
 * finding count as a severity-ringed badge, because "what it touches" matters most when what it
 * touches is itself on fire.
 *
 * The SVG is a SUMMARY, not the record: it caps each side and is aria-hidden, because the
 * neighbour TABLE beneath it is the authoritative, complete, screen-readable version. A picture
 * of a table must never be the only copy of the data.
 */

export type GraphResource = { id: string; kind: string; name: string; stale: boolean };

export type Neighbour = {
  edgeId: string;
  edgeKind: string;
  direction: 'in' | 'out';
  resourceId: string;
  /** null when the edge points at a row this tenant cannot read. Edges cascade on delete, so
   *  this should be unreachable — but `raw.get(...)`-style defensiveness applies to joins too. */
  resource: GraphResource | null;
};

/** Worst open severity + open count per resource id — the risk halo each node wears. */
export type RiskIndex = Record<string, { worst: Severity; open: number }>;

const FOCUS_GROW_X = 8;
const FOCUS_GROW_Y = 7;

function sevSolid(sev: Severity): string {
  return `var(--sev-${sev}-solid)`;
}

/** The icon tile + two text lines every node shares. Nested <svg> so the icon component can be
 * reused verbatim inside the graph. */
function NodeBody({
  x,
  y,
  w,
  h,
  title,
  subtitle,
  kind,
  focus = false,
}: {
  x: number;
  y: number;
  w: number;
  h: number;
  title: string;
  subtitle: string;
  kind: string;
  focus?: boolean;
}) {
  const tile = 26;
  const tx = x + 12;
  const ty = y + (h - tile) / 2;
  return (
    <>
      <rect x={tx} y={ty} width={tile} height={tile} rx={6} fill={focus ? 'var(--accent-soft)' : 'var(--bg)'} stroke="var(--border)" />
      <svg x={tx + 5} y={ty + 5} width={16} height={16} viewBox="0 0 24 24" style={{ color: focus ? 'var(--accent)' : 'var(--text-secondary)' }}>
        <IconForType type={kind} size={24} />
      </svg>
      <text x={tx + tile + 10} y={y + h / 2 - 3} fontSize="11.5" fill="var(--text-primary)" fontWeight={focus ? 700 : 600} fontFamily="var(--font-mono)">
        {clamp(title, focus ? 24 : 21)}
      </text>
      <text x={tx + tile + 10} y={y + h / 2 + 11} fontSize="10" fill="var(--text-muted)">
        {clamp(subtitle, 26)}
      </text>
    </>
  );
}

/** Open-findings badge pinned to a node's top-right corner: count in a severity-coloured ring.
 * Colour never stands alone — the count is the signal, the title carries the words, and the
 * findings table on the target page is one click away. */
function RiskBadge({ x, y, risk }: { x: number; y: number; risk: { worst: Severity; open: number } }) {
  const r = 9;
  return (
    <g aria-hidden="true">
      <title>{`${risk.open} open finding${risk.open === 1 ? '' : 's'} — worst ${risk.worst}`}</title>
      <circle cx={x} cy={y} r={r} fill="var(--surface-raised)" stroke={sevSolid(risk.worst)} strokeWidth="1.5" />
      <text x={x} y={y + 3.25} fontSize="9" fontWeight={700} textAnchor="middle" fill="var(--text-primary)">
        {risk.open > 99 ? '99+' : risk.open}
      </text>
    </g>
  );
}

function Node({
  x,
  y,
  resource,
  risk,
  href,
}: {
  x: number;
  y: number;
  resource: { name: string; kind: string; stale: boolean } | null;
  risk?: { worst: Severity; open: number };
  href?: string;
}) {
  const title = resource?.name ?? 'unreadable resource';
  const subtitle = resource ? `${resource.kind}${resource.stale ? ' · stale' : ''}` : 'no access';
  const body = (
    <g className={href ? 'vs-gnode' : undefined}>
      <rect
        className="vs-gnode-box"
        x={x}
        y={y}
        width={NODE_W}
        height={NODE_H}
        rx={12}
        fill="var(--surface-raised)"
        stroke={resource?.stale ? 'var(--sev-medium-solid)' : 'var(--border-strong)'}
        strokeWidth={1}
        // Stale is dashed AND says "stale" in the subtitle — the dash alone would be decoration.
        strokeDasharray={resource?.stale ? '5 4' : undefined}
        style={{ filter: 'drop-shadow(0 1px 2px rgb(0 0 0 / 0.07))' }}
      />
      <NodeBody x={x} y={y} w={NODE_W} h={NODE_H} title={title} subtitle={subtitle} kind={resource?.kind ?? ''} />
      {risk && risk.open > 0 && <RiskBadge x={x + NODE_W - 4} y={y + 4} risk={risk} />}
    </g>
  );
  // A neighbour that exists is a destination; SVG <a> keeps the whole card clickable without a
  // client component.
  return href ? <a href={href}>{body}</a> : body;
}

function FocusNode({
  x,
  y,
  focus,
  risk,
}: {
  x: number;
  y: number;
  focus: GraphResource;
  risk?: { worst: Severity; open: number };
}) {
  const fx = x - FOCUS_GROW_X;
  const fy = y - FOCUS_GROW_Y;
  const fw = NODE_W + FOCUS_GROW_X * 2;
  const fh = NODE_H + FOCUS_GROW_Y * 2;
  const ring = risk ? sevSolid(risk.worst) : 'var(--accent)';
  const cx = fx + fw / 2;
  const cy = fy + fh / 2;
  return (
    <g>
      {/* Breathing halo — the "you are here" of the graph. Decorative. */}
      <circle className="vs-ghalo" cx={cx} cy={cy} r={fh * 0.92} fill="none" stroke={ring} strokeOpacity="0.35" strokeWidth="1.25" />
      <circle cx={cx} cy={cy} r={fh * 0.7} fill="none" stroke={ring} strokeOpacity="0.14" strokeWidth="1" />
      <rect
        x={fx}
        y={fy}
        width={fw}
        height={fh}
        rx={14}
        fill="var(--surface-raised)"
        stroke={ring}
        strokeWidth={1.75}
        strokeDasharray={focus.stale ? '6 4' : undefined}
        style={{ filter: 'drop-shadow(0 4px 14px rgb(0 0 0 / 0.12))' }}
      />
      <NodeBody x={fx} y={fy} w={fw} h={fh} title={focus.name} subtitle={`${focus.kind}${focus.stale ? ' · stale' : ''} · this asset`} kind={focus.kind} focus />
      {risk && risk.open > 0 && <RiskBadge x={fx + fw - 4} y={fy + 4} risk={risk} />}
    </g>
  );
}

function Edge({
  from,
  to,
  label,
  fromW = NODE_W,
}: {
  from: { x: number; y: number };
  to: { x: number; y: number };
  label: string;
  fromW?: number;
}) {
  const x1 = from.x + fromW;
  const y1 = from.y + NODE_H / 2;
  const x2 = to.x;
  const y2 = to.y + NODE_H / 2;
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const bend = Math.min(56, Math.abs(x2 - x1) * 0.45);

  // 12 is not arbitrary: the connectors' whole edge-kind vocabulary tops out at 10 characters
  // (`permission`, `mcp_server`), so real labels never truncate and the cap only bounds a kind
  // nobody has written yet.
  const text = clamp(label, 12);
  // Rough advance for 9px mono; sizes the label pill.
  const labelW = text.length * 5.6 + 14;
  const d = `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`;

  return (
    <g>
      <path d={d} fill="none" stroke="var(--graph-edge)" strokeWidth="1.25" markerEnd="url(#vs-arrow)" />
      {/* The directional shimmer riding the edge. Same path, dashed, animated. */}
      <path className="vs-gedge-flow" d={d} fill="none" stroke="var(--accent)" strokeOpacity="0.55" strokeWidth="1.5" />
      <rect x={mx - labelW / 2} y={my - 9} width={labelW} height={18} rx={9} fill="var(--surface-raised)" stroke="var(--border-strong)" />
      <text x={mx} y={my + 3.25} fontSize="9" fill="var(--text-secondary)" fontFamily="var(--font-mono)" textAnchor="middle">
        {text}
      </text>
    </g>
  );
}

/** Ghost column when a side is empty: the absence of inbound edges is itself information. */
function GhostColumn({ x, y, label }: { x: number; y: number; label: string }) {
  return (
    <g aria-hidden="true">
      <rect x={x} y={y} width={NODE_W} height={NODE_H} rx={12} fill="none" stroke="var(--border-strong)" strokeDasharray="4 5" strokeOpacity="0.75" />
      <text x={x + NODE_W / 2} y={y + NODE_H / 2 + 3.5} fontSize="10" fill="var(--text-muted)" textAnchor="middle">
        {label}
      </text>
    </g>
  );
}

export function BlastRadius({
  focus,
  neighbours,
  risk = {},
}: {
  focus: GraphResource;
  neighbours: Neighbour[];
  /** Open-finding severity/count per resource id (focus included) — the badges nodes wear. */
  risk?: RiskIndex;
}) {
  const inbound = neighbours.filter((n) => n.direction === 'in');
  const outbound = neighbours.filter((n) => n.direction === 'out');

  const shownIn = inbound.slice(0, MAX_PER_SIDE);
  const shownOut = outbound.slice(0, MAX_PER_SIDE);
  const l = layoutColumns(shownIn.length, shownOut.length);
  const headerY = 18;

  return (
    <div style={{ width: '100%' }}>
      <div className="vs-canvas" style={{ overflowX: 'auto' }}>
        <svg
          viewBox={`0 0 ${l.width} ${l.height + headerY}`}
          // Responsive: fill the card, keep ratio, allow horizontal scroll under ~720px.
          style={{ display: 'block', width: '100%', minWidth: 720, height: 'auto' }}
          // The table below is the accessible copy; announcing a second, lossier version of the
          // same rows would only make the page longer to listen to.
          aria-hidden="true"
          focusable="false"
        >
          <defs>
            <marker id="vs-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 7 4 L 0 7 z" fill="var(--graph-edge)" />
            </marker>
          </defs>

          {/* Column captions — direction in words, not arrowheads alone. */}
          <g fontSize="9.5" fontWeight={600} letterSpacing="0.08em" fill="var(--text-muted)">
            <text x={COL_X.in} y={headerY - 4}>
              {`CAN REACH THIS · ${inbound.length}`}
            </text>
            <text x={COL_X.focus} y={headerY - 4}>
              FOCUS
            </text>
            <text x={COL_X.out} y={headerY - 4}>
              {`THIS CAN REACH · ${outbound.length}`}
            </text>
          </g>

          <g transform={`translate(0 ${headerY})`}>
            {shownIn.map((n, i) => (
              <Edge key={n.edgeId} from={l.inbound[i]} to={{ x: l.focus.x - FOCUS_GROW_X, y: l.focus.y }} label={n.edgeKind} />
            ))}
            {shownOut.map((n, i) => (
              <Edge key={n.edgeId} from={{ x: l.focus.x - FOCUS_GROW_X, y: l.focus.y }} to={l.outbound[i]} label={n.edgeKind} fromW={NODE_W + FOCUS_GROW_X * 2} />
            ))}

            {shownIn.length === 0 && (
              <GhostColumn x={COL_X.in} y={l.focus.y} label="nothing inbound observed" />
            )}
            {shownOut.length === 0 && (
              <GhostColumn x={COL_X.out} y={l.focus.y} label="nothing outbound observed" />
            )}

            {shownIn.map((n, i) => (
              <Node
                key={n.edgeId}
                x={l.inbound[i].x}
                y={l.inbound[i].y}
                resource={n.resource}
                risk={n.resource ? risk[n.resource.id] : undefined}
                href={n.resource ? `/assets/${n.resource.id}` : undefined}
              />
            ))}
            {shownOut.map((n, i) => (
              <Node
                key={n.edgeId}
                x={l.outbound[i].x}
                y={l.outbound[i].y}
                resource={n.resource}
                risk={n.resource ? risk[n.resource.id] : undefined}
                href={n.resource ? `/assets/${n.resource.id}` : undefined}
              />
            ))}

            <FocusNode x={l.focus.x} y={l.focus.y} focus={focus} risk={risk[focus.id]} />
          </g>
        </svg>
      </div>

      {(inbound.length > MAX_PER_SIDE || outbound.length > MAX_PER_SIDE) && (
        <p
          style={{
            margin: 'var(--space-2) 0 0',
            fontSize: 'var(--text-2xs)',
            color: 'var(--text-secondary)',
          }}
        >
          Diagram capped at {MAX_PER_SIDE} per side
          {inbound.length > MAX_PER_SIDE && ` (${inbound.length - MAX_PER_SIDE} more inbound)`}
          {outbound.length > MAX_PER_SIDE && ` (${outbound.length - MAX_PER_SIDE} more outbound)`}
          . The table below lists all {neighbours.length}.
        </p>
      )}
    </div>
  );
}

/* ── The explorer: the graph at radius ≥ 2 ────────────────────────────────
 * Columns by signed hop distance (… -2 · -1 · FOCUS · +1 · +2 …), every node still a link and
 * still wearing its risk badge — "see everything from here" without giving up click-and-go.
 * Edges are drawn between ADJACENT columns only (a BFS layering has no others on the shortest
 * path); lateral edges inside a hop set are counted and stated, never silently dropped. */

export type LayeredEdge = { id: string; kind: string; src: string; dst: string };

export function BlastRadiusExplorer({
  focus,
  nodes,
  edges,
  risk = {},
}: {
  focus: GraphResource;
  /** All non-focus nodes with their signed hop distance. */
  nodes: LayeredNode[];
  edges: LayeredEdge[];
  risk?: RiskIndex;
}) {
  const l = layoutLayers(nodes);
  const headerY = 18;
  const focusCol = l.cols.find((c) => c.d === 0)!;
  const focusPos = { x: focusCol.x, y: (l.height - NODE_H) / 2 };
  const pos = new Map(l.pos);
  pos.set(focus.id, focusPos);
  const dOf = new Map<string, number>(nodes.map((n) => [n.id, n.d]));
  dOf.set(focus.id, 0);

  // Only strictly FORWARD adjacent edges are drawn (src one column left of dst) — an arrow that
  // points against its edge's real direction would be a lie. Everything else is counted in words.
  const placed = (e: LayeredEdge) => pos.has(e.src) && pos.has(e.dst);
  const delta = (e: LayeredEdge) => (dOf.get(e.dst) ?? 0) - (dOf.get(e.src) ?? 0);
  const drawable = edges.filter((e) => placed(e) && delta(e) === 1);
  const lateral = edges.filter((e) => placed(e) && delta(e) === 0).length;
  const counterflow = edges.filter((e) => placed(e) && delta(e) === -1).length;
  const dropped = edges.length - drawable.length - lateral - counterflow;
  const capped = l.cols.filter((c) => c.total > c.shown);

  const colCaption = (d: number, shown: number, total: number) => {
    const more = total > shown ? ` (+${total - shown})` : '';
    if (d === 0) return 'FOCUS';
    const hops = Math.abs(d);
    return d < 0 ? `${hops} HOP${hops === 1 ? '' : 'S'} IN · ${total}${more}` : `${hops} HOP${hops === 1 ? '' : 'S'} OUT · ${total}${more}`;
  };

  return (
    <div style={{ width: '100%' }}>
      <div className="vs-canvas" style={{ overflowX: 'auto' }}>
        <svg
          viewBox={`0 0 ${l.width} ${l.height + headerY}`}
          style={{ display: 'block', width: '100%', minWidth: Math.min(1080, l.width), height: 'auto' }}
          aria-hidden="true"
          focusable="false"
        >
          <defs>
            <marker id="vs-arrow-x" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 1 L 7 4 L 0 7 z" fill="var(--graph-edge)" />
            </marker>
          </defs>

          <g fontSize="9.5" fontWeight={600} letterSpacing="0.08em" fill="var(--text-muted)">
            {l.cols.map((c) => (
              <text key={c.d} x={c.x} y={headerY - 4}>
                {colCaption(c.d, c.shown, c.total)}
              </text>
            ))}
          </g>

          <g transform={`translate(0 ${headerY})`}>
            {drawable.map((e) => {
              const a = pos.get(e.src)!;
              const b = pos.get(e.dst)!;
              const srcIsFocus = e.src === focus.id;
              const dstIsFocus = e.dst === focus.id;
              // The focus box is drawn grown; edges meet its grown border, not the layout rect.
              return (
                <Edge
                  key={e.id}
                  from={{ x: a.x - (srcIsFocus ? 8 : 0), y: a.y }}
                  to={{ x: b.x - (dstIsFocus ? 8 : 0), y: b.y }}
                  label={e.kind}
                  fromW={NODE_W + (srcIsFocus ? 16 : 0)}
                />
              );
            })}

            {nodes
              .filter((n) => pos.has(n.id))
              .map((n) => (
                <Node
                  key={n.id}
                  x={pos.get(n.id)!.x}
                  y={pos.get(n.id)!.y}
                  resource={n}
                  risk={risk[n.id]}
                  href={`/assets/${n.id}`}
                />
              ))}

            <FocusNode x={focusPos.x} y={focusPos.y} focus={focus} risk={risk[focus.id]} />
          </g>
        </svg>
      </div>

      {(capped.length > 0 || lateral > 0 || counterflow > 0 || dropped > 0) && (
        <p style={{ margin: 'var(--space-2) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          {capped.length > 0 &&
            `Columns capped at ${MAX_PER_SIDE} (${capped.map((c) => `${c.total - c.shown} more at ${c.d < 0 ? `${-c.d} in` : `${c.d} out`}`).join(', ')}). `}
          {lateral > 0 && `${lateral} lateral edge${lateral === 1 ? '' : 's'} within a hop set not drawn. `}
          {counterflow > 0 && `${counterflow} counter-flow edge${counterflow === 1 ? '' : 's'} not drawn. `}
          {dropped > 0 && `${dropped} edge${dropped === 1 ? '' : 's'} to capped nodes not drawn. `}
          The table below stays the record of direct edges.
        </p>
      )}
    </div>
  );
}
