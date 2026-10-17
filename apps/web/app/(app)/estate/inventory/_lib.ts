import type { Json, Severity } from '@/lib/types';
import { SEVERITY_RANK } from '@/lib/types';

/* Pure helpers for the asset views. No React, no Supabase — so they are testable without a
 * render or a network, which is why the graph layout lives here rather than in the SVG. */

export const REDACTED = '[redacted by console]';

/* Keys whose STRING values never reach the screen.
 *
 * The connector is the real boundary and the good ones already scrub (kong.py runs its own
 * _SECRET_KEY pass; kafka.py stores null for is_sensitive entries). This is the last mile:
 * `raw` is a free-form collector payload rendered verbatim, so a future connector that forgets
 * to scrub would publish a secret into this page's HTML. One regex here covers every connector
 * that will ever exist, including the ones nobody has written yet.
 *
 * Redacting at DISPLAY time is safe in a way redacting at COLLECTION time is not. kong.py
 * documents a real incident where an over-broad `credential` term matched the cors plugin's
 * `credentials` BOOLEAN and silently killed a rule. Nothing like that can happen here:
 * detectors have already run against the stored value long before this renders, so the worst
 * case is an analyst not seeing a value — and the key stays visible so they know to go look.
 */
const SECRET_KEY =
  /(password|passwd|secret|token|credential|apikey|api_key|private_key|_key$|^key$|authorization|salt)/i;

/** Mask secret-looking values in a collector payload, for display only.
 *
 * Only non-empty STRINGS are masked. A null/false/0 under a secret-looking key is itself
 * evidence — kafka.py deliberately stores null for every PASSWORD-typed broker config, and
 * masking that would invent a secret where the connector proved there was none. Same reason
 * the type guard makes the `credentials: true` class of false positive structurally impossible.
 */
export function redactSecrets(value: Json, key?: string): Json {
  if (Array.isArray(value)) {
    // Carry the parent key down: {"tokens": ["abc"]} must mask the elements, not just the key.
    return value.map((v) => redactSecrets(v, key));
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactSecrets(v, k)]));
  }
  if (typeof value === 'string' && value !== '' && key && SECRET_KEY.test(key)) {
    // kong.py already writes a literal "[redacted]". Keep its marker rather than overwriting it
    // with ours — who redacted a value is itself information.
    return value === '[redacted]' ? value : REDACTED;
  }
  return value;
}

/** Highest severity in a list, or null when empty. */
export function worstSeverity(severities: Severity[]): Severity | null {
  let worst: Severity | null = null;
  for (const s of severities) {
    if (worst === null || SEVERITY_RANK[s] < SEVERITY_RANK[worst]) worst = s;
  }
  return worst;
}

/** Sort key for "riskiest first": worst severity, then most findings, then name.
 * Returns a comparator result. Assets with no findings sort last but are NOT hidden. */
export function byRisk(
  a: { worst: Severity | null; open: number; name: string },
  b: { worst: Severity | null; open: number; name: string },
): number {
  const ra = a.worst === null ? 99 : SEVERITY_RANK[a.worst];
  const rb = b.worst === null ? 99 : SEVERITY_RANK[b.worst];
  if (ra !== rb) return ra - rb;
  if (a.open !== b.open) return b.open - a.open;
  return a.name.localeCompare(b.name);
}

export function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

/** Full timestamp for a title attribute — relative time is scannable, absolute time is evidence. */
export function absolute(iso: string): string {
  return new Date(iso).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

/** `labels` is jsonb and free-form: a connector may write nested values. Flatten to strings so
 * a chip never renders "[object Object]". */
export function labelEntries(labels: Json): [string, string][] {
  if (labels === null || typeof labels !== 'object' || Array.isArray(labels)) return [];
  return Object.entries(labels).map(([k, v]) => [
    k,
    typeof v === 'string' ? v : JSON.stringify(v),
  ]);
}

export function clamp(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}

/* ── Blast-radius geometry ─────────────────────────────────────────────────
 * Lives here rather than beside the SVG so it can be exercised without a React render —
 * it is arithmetic, and arithmetic that decides whether nodes overlap is worth checking.
 */

export const NODE_W = 196;
export const NODE_H = 56;
export const GAP_Y = 16;
/** Room for the curve and its edge-kind label. */
export const COL_GAP = 128;
export const PAD = 28;
/** Past ~10 a side the fan is unreadable and the table is the better tool. */
export const MAX_PER_SIDE = 10;

export const GRAPH_WIDTH = NODE_W * 3 + COL_GAP * 2 + PAD * 2;
export const COL_X = { in: PAD, focus: PAD + NODE_W + COL_GAP, out: PAD + (NODE_W + COL_GAP) * 2 };

export type Placed = { x: number; y: number };

export type GraphLayout = {
  width: number;
  height: number;
  inbound: Placed[];
  outbound: Placed[];
  focus: Placed;
};

/* ── Multi-hop (explorer) layout ──────────────────────────────────────────
 * Columns by signed hop distance from the focus: … -2, -1, [0], +1, +2 …
 * Negative = reaches the focus (inbound side), positive = reached by it. Pure and capped:
 * each column shows at most MAX_PER_SIDE nodes and reports its true total, so the SVG can
 * say what it dropped instead of silently pretending completeness. */

export type LayeredNode = { id: string; kind: string; name: string; stale: boolean; d: number };

export type LayeredLayout = {
  width: number;
  height: number;
  /** Placed positions per node id — only for nodes that made the per-column cap. */
  pos: Map<string, Placed>;
  cols: { d: number; x: number; shown: number; total: number }[];
};

export function layoutLayers(nodes: LayeredNode[]): LayeredLayout {
  const byCol = new Map<number, LayeredNode[]>();
  for (const n of nodes) {
    const arr = byCol.get(n.d);
    if (arr) arr.push(n);
    else byCol.set(n.d, [n]);
  }
  if (!byCol.has(0)) byCol.set(0, []);
  const ds = [...byCol.keys()].sort((a, b) => a - b);

  const shownByCol = ds.map((d) => {
    const all = byCol.get(d)!;
    // Focus column is never capped (it holds exactly the focus); risky-first would need
    // risk here — name order keeps the layout pure and stable instead.
    const shown = d === 0 ? all : all.slice(0, MAX_PER_SIDE);
    return { d, all, shown };
  });

  const rows = Math.max(...shownByCol.map((c) => c.shown.length), 1);
  const innerH = rows * NODE_H + (rows - 1) * GAP_Y;
  const width = PAD * 2 + ds.length * NODE_W + (ds.length - 1) * COL_GAP;

  const pos = new Map<string, Placed>();
  const cols = shownByCol.map(({ d, all, shown }, idx) => {
    const x = PAD + idx * (NODE_W + COL_GAP);
    const colH = shown.length * NODE_H + (shown.length - 1) * GAP_Y;
    const startY = PAD + (innerH - colH) / 2;
    shown.forEach((n, i) => pos.set(n.id, { x, y: startY + i * (NODE_H + GAP_Y) }));
    if (d === 0 && shown.length === 0) {
      // The focus is placed by the caller at the column centre.
    }
    return { d, x, shown: shown.length, total: all.length };
  });

  return { width, height: innerH + PAD * 2, pos, cols };
}

/** Pure layout: y-positions per column, each column centred as a group so the focus node sits
 * on the visual axis however lopsided the two sides are. */
export function layoutColumns(nIn: number, nOut: number): GraphLayout {
  const rows = Math.max(nIn, nOut, 1);
  const innerH = rows * NODE_H + (rows - 1) * GAP_Y;

  const column = (n: number, x: number): Placed[] => {
    const colH = n * NODE_H + (n - 1) * GAP_Y;
    const startY = PAD + (innerH - colH) / 2;
    return Array.from({ length: n }, (_, i) => ({ x, y: startY + i * (NODE_H + GAP_Y) }));
  };

  return {
    width: GRAPH_WIDTH,
    height: innerH + PAD * 2,
    inbound: column(nIn, COL_X.in),
    outbound: column(nOut, COL_X.out),
    focus: { x: COL_X.focus, y: PAD + innerH / 2 - NODE_H / 2 },
  };
}
