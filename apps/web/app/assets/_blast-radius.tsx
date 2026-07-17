import { clamp, layoutColumns, MAX_PER_SIDE, NODE_H, NODE_W } from './_lib';

/* Blast radius — the focus resource and its DIRECT edges, drawn as inline SVG.
 *
 * No graph library, deliberately: a force layout would need a client bundle and a CDN-ish
 * dependency on a page whose whole job is to be trustworthy, and it would animate nodes into
 * positions that mean nothing. This is a static two-column flow instead, and the columns carry
 * the meaning:
 *
 *     [ what can reach this ]  →  ( FOCUS )  →  [ what this can reach ]
 *
 * Direction is the entire point of a blast radius — "who can call me" and "what do I call" are
 * different security questions — so it is encoded by POSITION and repeated by the arrowheads,
 * rather than resting on arrowheads alone. Both columns flow rightward, so one marker suffices.
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

function Node({
  x,
  y,
  title,
  subtitle,
  stale,
  focus = false,
}: {
  x: number;
  y: number;
  title: string;
  subtitle: string;
  stale: boolean;
  focus?: boolean;
}) {
  return (
    <g>
      <rect
        x={x}
        y={y}
        width={NODE_W}
        height={NODE_H}
        rx={4}
        fill={focus ? 'var(--surface-raised)' : 'var(--surface)'}
        stroke={stale ? 'var(--sev-medium-fg)' : focus ? 'var(--border-interactive)' : 'var(--border-strong)'}
        strokeWidth={focus ? 2 : 1}
        // Stale is dashed AND says "stale" in the subtitle — the dash alone would be decoration.
        strokeDasharray={stale ? '4 3' : undefined}
      />
      <text x={x + 10} y={y + 17} fontSize="11" fill="var(--text-primary)" fontWeight={focus ? 600 : 500}>
        {clamp(title, 22)}
      </text>
      <text x={x + 10} y={y + 30} fontSize="10" fill="var(--text-secondary)" fontFamily="var(--font-mono)">
        {clamp(subtitle, 24)}
      </text>
    </g>
  );
}

function Edge({
  from,
  to,
  label,
}: {
  from: { x: number; y: number };
  to: { x: number; y: number };
  label: string;
}) {
  const x1 = from.x + NODE_W;
  const y1 = from.y + NODE_H / 2;
  const x2 = to.x;
  const y2 = to.y + NODE_H / 2;
  const mx = (x1 + x2) / 2;

  // 12 is not arbitrary: the connectors' whole edge-kind vocabulary tops out at 10 characters
  // (`permission`, `mcp_server`), so real labels never truncate and the cap only bounds a kind
  // nobody has written yet. Raising it past ~14 would push the label into the node boxes,
  // since COL_GAP is 88px.
  const text = clamp(label, 12);
  // Rough advance for 9px mono. Only used to size the label's knockout, so being a few px
  // generous is harmless and being short would let the curve strike through the text.
  const labelW = text.length * 5.4 + 6;

  return (
    <g>
      <path
        d={`M ${x1} ${y1} C ${x1 + 36} ${y1}, ${x2 - 36} ${y2}, ${x2} ${y2}`}
        fill="none"
        stroke="var(--border-strong)"
        strokeWidth="1"
        markerEnd="url(#vs-arrow)"
      />
      {/* Knock the curve out from behind the label rather than nudging the label off the line. */}
      <rect x={mx - labelW / 2} y={y1 === y2 ? y1 - 6 : (y1 + y2) / 2 - 6} width={labelW} height={12} fill="var(--surface)" rx={2} />
      <text
        x={mx}
        y={(y1 + y2) / 2 + 3}
        fontSize="9"
        fill="var(--text-secondary)"
        fontFamily="var(--font-mono)"
        textAnchor="middle"
      >
        {text}
      </text>
    </g>
  );
}

export function BlastRadius({
  focus,
  neighbours,
}: {
  focus: GraphResource;
  neighbours: Neighbour[];
}) {
  const inbound = neighbours.filter((n) => n.direction === 'in');
  const outbound = neighbours.filter((n) => n.direction === 'out');

  const shownIn = inbound.slice(0, MAX_PER_SIDE);
  const shownOut = outbound.slice(0, MAX_PER_SIDE);
  const l = layoutColumns(shownIn.length, shownOut.length);

  return (
    <div style={{ overflowX: 'auto', width: '100%' }}>
      <svg
        viewBox={`0 0 ${l.width} ${l.height}`}
        width={l.width}
        height={l.height}
        // The table below is the accessible copy; announcing a second, lossier version of the
        // same rows would only make the page longer to listen to.
        aria-hidden="true"
        focusable="false"
        style={{ maxWidth: '100%', height: 'auto', display: 'block' }}
      >
        <defs>
          <marker id="vs-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 7 4 L 0 7 z" fill="var(--border-interactive)" />
          </marker>
        </defs>

        {shownIn.map((n, i) => (
          <Edge key={n.edgeId} from={l.inbound[i]} to={l.focus} label={n.edgeKind} />
        ))}
        {shownOut.map((n, i) => (
          <Edge key={n.edgeId} from={l.focus} to={l.outbound[i]} label={n.edgeKind} />
        ))}

        {shownIn.map((n, i) => (
          <Node
            key={n.edgeId}
            x={l.inbound[i].x}
            y={l.inbound[i].y}
            title={n.resource?.name ?? 'unreadable resource'}
            subtitle={n.resource ? `${n.resource.kind}${n.resource.stale ? ' · stale' : ''}` : 'no access'}
            stale={n.resource?.stale ?? false}
          />
        ))}
        {shownOut.map((n, i) => (
          <Node
            key={n.edgeId}
            x={l.outbound[i].x}
            y={l.outbound[i].y}
            title={n.resource?.name ?? 'unreadable resource'}
            subtitle={n.resource ? `${n.resource.kind}${n.resource.stale ? ' · stale' : ''}` : 'no access'}
            stale={n.resource?.stale ?? false}
          />
        ))}

        <Node
          x={l.focus.x}
          y={l.focus.y}
          title={focus.name}
          subtitle={`${focus.kind}${focus.stale ? ' · stale' : ''}`}
          stale={focus.stale}
          focus
        />
      </svg>

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
