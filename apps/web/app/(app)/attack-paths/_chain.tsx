import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';

/* The attack-chain visual language, shared.
 *
 * Extracted from the attack-paths board so the SAME chain renders on a finding's detail page —
 * "Full evidence →" must land on the visualization it promised, not on a wall of prose that
 * makes the reader rebuild the chain in their head. Server-safe (no hooks); the animated rail
 * is CSS (globals.css .vs-gedge-flow), neutralised by prefers-reduced-motion.
 *
 * THE PARSER: an ATTACKPATH observation's claim carries the engine's cited chain in the
 * `graph_engine.Hop.cite()` grammar —
 *   `lead: [kind 'name' (ext_id): signal] -> [kind (ext_id): signal] — trailer`
 * and `source_ref` is a jsonb OBJECT, never a display string. Hops come from parsing that
 * grammar; roles come from the signal text first (a broker hop's signal SAYS "exposed"), the
 * cited kind second. Everything degrades: a claim with no brackets renders as a single hop.
 */

export type HopKind = 'exposure' | 'privilege' | 'sensitive' | 'generic';

export type Hop = {
  kind: HopKind;
  factor: string;
  /** The signal read at this hop — the engine's own words. */
  detail: string;
  /** The resource this hop cites: kind + name + ext_id where parseable. */
  citedKind: string;
  citedName: string;
  citedRef: string;
  dataClasses: string[];
  sensitivity: string;
};

export const FACTOR_LABEL: Record<HopKind, string> = {
  exposure: 'Exposed surface',
  privilege: 'Over-privileged NHI',
  sensitive: 'Sensitive data',
  generic: 'Factor',
};

export function classifyText(text: string): HopKind {
  const t = text.toLowerCase();
  if (/(expos|public|internet|external|reachable|ingress|listener|plaintext|anonymous|unauth|\bopen\b)/.test(t)) return 'exposure';
  if (/(wildcard|over-?priv|privileg|grant|permission|\bacl\b|\brole\b|scope|authoriz|admin|\ballow\b|\*)/.test(t)) return 'privilege';
  if (/(sensitive|classif|named like|pci|phi|pii|secret|confidential|payment|personal|financial)/.test(t)) return 'sensitive';
  return 'generic';
}

/** Resource-kind → hop role, mirroring graph_engine's Hop.role vocabulary. The signal text wins
 * over the kind; the kind catches terse signals. */
export function classifyHop(kind: string, signal: string): HopKind {
  const bySignal = classifyText(signal);
  if (bySignal !== 'generic') return bySignal;
  const k = kind.toLowerCase();
  if (/(identity|principal|user|nhi)/.test(k)) return 'privilege';
  if (/(grant|acl|permission|role|policy)/.test(k)) return 'privilege';
  if (/(broker|listener|gateway|server|endpoint|surface)/.test(k)) return 'exposure';
  if (/(topic|queue|stream|exchange|subject|keyspace|channel|route|service|mcp_tool)/.test(k)) return 'sensitive';
  return 'generic';
}

export function dataClassesFrom(text: string): string[] {
  const t = text.toLowerCase();
  const out: string[] = [];
  if (/pci|payment|\bcard\b/.test(t)) out.push('pci');
  if (/phi|health|patient/.test(t)) out.push('phi');
  if (/pii|personal|customer|\bemail\b|\bssn\b/.test(t)) out.push('pii');
  if (/secret|token|\bkey\b|credential/.test(t)) out.push('secrets');
  if (/financial|invoice|ledger|transaction/.test(t)) out.push('financial');
  if (/\bauth\b|oauth|session/.test(t)) out.push('auth');
  return [...new Set(out)];
}

export function makeHop(kind: HopKind, detail: string, cited: { kind?: string; name?: string; ref?: string }): Hop {
  const basis = `${detail} ${cited.name ?? ''} ${cited.ref ?? ''}`;
  return {
    kind,
    factor: FACTOR_LABEL[kind],
    detail: detail || '—',
    citedKind: cited.kind ?? '',
    citedName: cited.name ?? '',
    citedRef: cited.ref ?? '',
    dataClasses: kind === 'sensitive' ? dataClassesFrom(basis) : [],
    sensitivity: 'high',
  };
}

/** Parse the engine's cite grammar out of one claim. Returns null when the claim carries no
 * bracketed hops (not an attack-path cite). */
export function hopsFromClaim(claim: string): { hops: Hop[]; trailer: string | null } | null {
  const segments = [...claim.matchAll(/\[([^\[\]]+)\]/g)].map((m) => m[1]);
  if (segments.length === 0) return null;

  const hops = segments.map((seg) => {
    // `kind 'name' (ext_id): signal` — name and ext_id both optional in principle.
    const m = seg.match(/^(.*?)\s*\(([^()]*)\)\s*:\s*(.*)$/s);
    if (!m) {
      const kind = classifyText(seg);
      return makeHop(kind, seg.trim(), {});
    }
    const [, labelPart, extId, signal] = m;
    const nameMatch = labelPart.match(/^(\S+)\s+'(.*)'$/s);
    const kindWord = nameMatch ? nameMatch[1] : labelPart.trim();
    const name = nameMatch ? nameMatch[2] : '';
    const role = classifyHop(kindWord, signal);
    return makeHop(role, signal.trim(), { kind: kindWord, name, ref: extId });
  });

  // "— this chain could NOT be confirmed: reason" rides after the last bracket on
  // not-assessable paths; surface it as the chain note rather than losing it.
  const after = claim.slice(claim.lastIndexOf(']') + 1).trim();
  const trailer = after.startsWith('—') || after.startsWith('-') ? after.replace(/^[—-]\s*/, '') : null;

  return { hops, trailer };
}

/** The chain out of a set of observation claims: repeated scans append identical observations,
 * so identical claims dedupe and the first parseable cite wins. Null when none parses. */
export function chainFromClaims(claims: string[]): { hops: Hop[]; trailer: string | null } | null {
  for (const claim of [...new Set(claims.filter(Boolean))]) {
    const parsed = hopsFromClaim(claim);
    if (parsed) return parsed;
  }
  return null;
}

function leaf(name: string): string {
  return String(name ?? '').split(':').pop() || String(name ?? '');
}

// ── The visualization ─────────────────────────────────────────────────────────────────────────────

const KIND_COLOR: Record<HopKind, string> = {
  exposure: 'var(--sev-high-solid)',
  privilege: 'var(--sev-medium-solid)',
  sensitive: 'var(--sev-critical-solid)',
  generic: 'var(--border-strong)',
};
const KIND_FG: Record<HopKind, string> = {
  exposure: 'var(--sev-high-fg)',
  privilege: 'var(--sev-medium-fg)',
  sensitive: 'var(--sev-critical-fg)',
  generic: 'var(--text-secondary)',
};
const KIND_BG: Record<HopKind, string> = {
  exposure: 'var(--sev-high-bg)',
  privilege: 'var(--sev-medium-bg)',
  sensitive: 'var(--sev-critical-bg)',
  generic: 'var(--sev-info-bg)',
};

export function AttackChain({ hops, note }: { hops: Hop[]; note: string | null }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <ol
        aria-label={`Attack chain, ${hops.length} hop${hops.length === 1 ? '' : 's'}`}
        style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', alignItems: 'stretch', gap: 'var(--space-2) 0' }}
      >
        {hops.map((hop, i) => (
          <li key={i} style={{ display: 'flex', alignItems: 'center', flex: '1 1 240px', minWidth: 0 }} aria-label={`Hop ${i + 1}, ${hop.factor}`}>
            {i > 0 && <Connector />}
            <HopNode hop={hop} index={i + 1} />
          </li>
        ))}
      </ol>
      {note && (
        <p style={{ margin: 0, display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
          <span aria-hidden="true" style={{ color: 'var(--sev-medium-fg)' }}>&#9432;</span>
          {note}
        </p>
      )}
    </div>
  );
}

/** The rail between hops: a directional flow, drawn not implied. */
function Connector() {
  return (
    <svg
      width="36"
      height="18"
      viewBox="0 0 36 18"
      fill="none"
      aria-hidden="true"
      className="vs-hop-rail"
      style={{ margin: '0 var(--space-1)' }}
    >
      <line x1="1" y1="9" x2="29" y2="9" stroke="currentColor" strokeWidth="1.5" />
      <line className="vs-gedge-flow" x1="1" y1="9" x2="29" y2="9" stroke="var(--accent)" strokeOpacity="0.6" strokeWidth="1.75" />
      <path d="M29 4.5l6 4.5-6 4.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function HopNode({ hop, index }: { hop: Hop; index: number }) {
  return (
    <div
      className="vs-hop"
      style={{ '--vs-hop-color': KIND_COLOR[hop.kind], flex: '1 1 auto', minWidth: 0 } as React.CSSProperties}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', minWidth: 0 }}>
        <span
          aria-hidden="true"
          style={{
            display: 'grid',
            placeItems: 'center',
            width: 24,
            height: 24,
            flexShrink: 0,
            borderRadius: 'var(--radius-full)',
            background: KIND_BG[hop.kind],
            border: `1px solid color-mix(in srgb, ${KIND_COLOR[hop.kind]} 40%, transparent)`,
            color: KIND_FG[hop.kind],
          }}
        >
          <HopGlyph kind={hop.kind} />
        </span>
        <span style={{ display: 'grid', gap: 0, minWidth: 0 }}>
          <span style={{ fontSize: 'var(--text-2xs)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 700, color: KIND_FG[hop.kind], whiteSpace: 'nowrap' }}>
            {hop.factor}
          </span>
          <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
            hop {index}
            {hop.citedKind && <> · {hop.citedKind}</>}
          </span>
        </span>
      </div>

      {(hop.citedName || hop.citedRef) && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {hop.citedName ? (
            <Chip mono title={hop.citedRef || undefined}>
              {leaf(hop.citedName)}
            </Chip>
          ) : (
            <Chip mono title={hop.citedRef}>
              {leaf(hop.citedRef)}
            </Chip>
          )}
        </div>
      )}

      <p
        style={{
          margin: 0,
          fontSize: 'var(--text-xs)',
          lineHeight: 'var(--leading-xs)',
          color: 'var(--text-secondary)',
          overflowWrap: 'anywhere',
        }}
      >
        {hop.detail}
      </p>

      {hop.kind === 'sensitive' && hop.dataClasses.length > 0 && (
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          <DataClassChips classes={hop.dataClasses} sensitivity={hop.sensitivity} signals={hop.citedName || hop.citedRef} />
        </div>
      )}
    </div>
  );
}

function HopGlyph({ kind }: { kind: HopKind }) {
  const common = { width: 13, height: 13, viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, 'aria-hidden': true } as const;
  switch (kind) {
    case 'exposure': // broadcast — a reachable surface
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="1.75" fill="currentColor" stroke="none" />
          <path d="M4.6 4.6a4.8 4.8 0 0 0 0 6.8M11.4 4.6a4.8 4.8 0 0 1 0 6.8" strokeLinecap="round" />
        </svg>
      );
    case 'privilege': // key — an over-broad grant
      return (
        <svg {...common}>
          <circle cx="6" cy="6" r="3" />
          <path d="M8.2 8.2l4.3 4.3M10.6 10.6l1.4-1.4" strokeLinecap="round" />
        </svg>
      );
    case 'sensitive': // lock — sensitive data
      return (
        <svg {...common}>
          <rect x="3.5" y="7" width="9" height="6" rx="1" />
          <path d="M5.5 7V5.2a2.5 2.5 0 0 1 5 0V7" strokeLinecap="round" />
        </svg>
      );
    default: // generic
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="2.5" fill="currentColor" stroke="none" />
        </svg>
      );
  }
}
