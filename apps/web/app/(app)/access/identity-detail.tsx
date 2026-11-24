'use client';

import { useState, type ReactNode } from 'react';

import type { Severity } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';
import { Drawer } from '@/components/ui/drawer';
import { SeverityBadge } from '@/components/ui/severity';
import { StatusPill } from '@/components/ui/status-pill';

/* Per-identity detail — the in-flow companion to the inventory (DESIGN §3: a drawer, not a route,
 * because the inventory is the analyst's place and one identity is a glance, not a destination).
 *
 * Everything here arrives as serializable props from the server page — no function props cross the
 * boundary. Credentials are METADATA ONLY: type, hashing, "present" — never a secret value. The
 * blast radius is derived from each grant's own scope labels (grant -> resource reach), and is
 * honest about wildcard grants being unbounded. Findings cite the rule that fired and the resource
 * it fired on.
 */

export type CredMeta = {
  id: string;
  /** credential_type label: password / api_key / token / mtls … */
  label: string;
  hashing: string;
  weak: boolean;
  isDefault: boolean;
};

export type GrantMeta = {
  id: string;
  /** full grant descriptor (the evidence string) */
  name: string;
  action: string;
  /** target resource / pattern from labels, '' when only the descriptor is known */
  resource: string;
  wildcard: boolean;
  dataClasses: string[];
  sensitivity: string;
};

export type FindingMeta = {
  id: string;
  ruleId: string;
  severity: Severity;
  status: string;
  /** resource the finding fired on — the citation */
  resource: string;
};

export type IdentityDetail = {
  id: string;
  name: string;
  system: string;
  identityType: string;
  scope: 'external' | 'internal' | 'unknown';
  connector: { type: string; name: string } | null;
  isDefault: boolean;
  /** Owner: confirmed by a person (identity_owners) or inferred from a tag / annotation. */
  owner: string | null;
  /** When a person last confirmed the owner; null when the owner is only inferred or unknown. */
  ownerVerifiedAt: string | null;
  /** Last-seen signal, with its provenance. `unknown` = no source collects it for this system. */
  lastSeen: { state: 'seen' | 'never' | 'unknown'; at: string | null; source: string };
  /** Highest naming-inferred sensitivity across this identity's grants ('' when none). */
  sensitivity: string;
  /** A grant reaches a resource the connector flagged as internet-reachable. */
  exposed: boolean;
  /** Manifests (from a connected repo) in which this principal's name appears — never a secret. */
  inGit: string[];
  /** Held by an automation / AI-agent platform (n8n, Zapier, Workato, MCP …). */
  automation: boolean;
  worst: Severity | null;
  creds: CredMeta[];
  grants: GrantMeta[];
  findings: FindingMeta[];
};

const SCOPE_LABEL: Record<IdentityDetail['scope'], string> = {
  external: 'external principal',
  internal: 'internal principal',
  unknown: 'origin not classified',
};

function leaf(name: string): string {
  return String(name ?? '').split(':').pop() || String(name ?? '');
}

type Reached = { resource: string; wildcard: boolean; dataClasses: string[]; sensitivity: string };

function dedupeReached(grants: GrantMeta[]): Reached[] {
  const m = new Map<string, Reached>();
  for (const g of grants) {
    const key = g.resource || g.name;
    const ex = m.get(key);
    if (!ex) {
      m.set(key, { resource: key, wildcard: g.wildcard, dataClasses: [...g.dataClasses], sensitivity: g.sensitivity });
    } else {
      ex.wildcard = ex.wildcard || g.wildcard;
      if (g.dataClasses.length) ex.dataClasses = [...new Set([...ex.dataClasses, ...g.dataClasses])];
      if (!ex.sensitivity) ex.sensitivity = g.sensitivity;
    }
  }
  return [...m.values()];
}

export function IdentityDetailButton({ detail }: { detail: IdentityDetail }) {
  const [open, setOpen] = useState(false);
  const d = detail;
  const reached = dedupeReached(d.grants);
  const wildcardReach = reached.some((r) => r.wildcard);

  return (
    <>
      <Button variant="secondary" size="sm" onClick={() => setOpen(true)} aria-label={`View detail for ${leaf(d.name)}`}>
        Details
      </Button>

      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        title={leaf(d.name)}
        description={`${d.system || 'unknown system'} · ${d.identityType || 'unclassified'} · ${SCOPE_LABEL[d.scope]}`}
      >
        {/* Overview — the normalized identity, with provenance chips. */}
        <Section title="Identity" meta={d.worst ? undefined : 'no open findings'}>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <Chip mono>{d.name}</Chip>
            {d.system && <Chip>{d.system}</Chip>}
            {d.identityType && <Chip tone="info">{d.identityType}</Chip>}
            {d.scope === 'external' && <Chip tone="medium">external</Chip>}
            {d.scope === 'internal' && <Chip>internal</Chip>}
            {d.isDefault && <Chip tone="medium" inferred title="Default / shared principal — unattributable">default / shared</Chip>}
            {d.worst && <SeverityBadge severity={d.worst} />}
          </div>
          {d.connector && (
            <p style={metaLine}>
              Observed on connector <span style={{ fontFamily: 'var(--font-mono)' }}>{d.connector.type}/{d.connector.name}</span>
            </p>
          )}
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 'var(--space-2)' }}>
            {d.exposed && <Chip tone="high">reaches an exposed surface</Chip>}
            {d.inGit.length > 0 && <Chip tone="medium" title={d.inGit.join(', ')}>named in {d.inGit.length} manifest{d.inGit.length === 1 ? '' : 's'}</Chip>}
            {d.automation && <Chip tone="info">held by an automation</Chip>}
          </div>
          <p style={metaLine}>
            Owner: {d.owner ?? 'no owner tag'}
            {d.ownerVerifiedAt ? ` (confirmed ${d.ownerVerifiedAt.slice(0, 10)})` : d.owner ? ' (inferred)' : ''} · Last seen:{' '}
            {d.lastSeen.state === 'seen'
              ? `${d.lastSeen.at} (${d.lastSeen.source})`
              : d.lastSeen.state === 'never'
                ? 'reported never used'
                : 'unknown — no source collects it for this system'}
          </p>
        </Section>

        {/* Credentials — METADATA ONLY. A row proves a secret exists and states its shape. */}
        <Section title="Credentials" meta="metadata only — never a secret value">
          {d.creds.length === 0 ? (
            <p style={emptyLine}>No credentials are readable for this identity.</p>
          ) : (
            <ul style={listReset}>
              {d.creds.map((c) => (
                <li key={c.id} style={rowItem}>
                  <Chip mono>{c.label || 'credential'}</Chip>
                  {c.hashing && c.hashing !== 'unknown' && (
                    <Chip tone={c.weak ? 'medium' : 'neutral'} title={c.weak ? 'Weak hash at rest' : undefined}>
                      {c.hashing}
                    </Chip>
                  )}
                  {c.isDefault && <Chip tone="medium">default</Chip>}
                  <StatusPill tone="neutral" label="present" />
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Grants — resource + permission + wildcard. */}
        <Section title="Grants" meta={`${d.grants.length} authorization${d.grants.length === 1 ? '' : 's'}`}>
          {d.grants.length === 0 ? (
            <p style={emptyLine}>No grants recorded for this identity.</p>
          ) : (
            <ul style={listReset}>
              {d.grants.map((g) => (
                <li key={g.id} style={rowItem}>
                  <Chip tone={g.wildcard ? 'high' : 'neutral'}>{g.wildcard ? '✳ ' : ''}{g.action || 'grant'}</Chip>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {g.resource || g.name}
                  </span>
                  {g.wildcard && <Chip tone="high" inferred title="Blanket authorization">wildcard</Chip>}
                </li>
              ))}
            </ul>
          )}
        </Section>

        {/* Blast radius — reach derived from grant scope, honest about wildcards. The graph is
            the glance (identity → what its grants land on); the list below stays the record. */}
        <Section title="Blast radius" meta="inferred from grant scope">
          {reached.length === 0 ? (
            <p style={emptyLine}>Nothing reachable from recorded grants.</p>
          ) : (
            <>
              <ReachGraph name={leaf(d.name)} identityType={d.identityType} reached={reached} worst={d.worst} />
              <ul style={listReset}>
                {reached.map((r) => (
                  <li key={r.resource} style={rowItem}>
                    {r.wildcard && <Chip tone="high">✳ wildcard</Chip>}
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)', color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {r.resource}
                    </span>
                    <DataClassChips classes={r.dataClasses} sensitivity={r.sensitivity || 'none'} />
                  </li>
                ))}
              </ul>
              {wildcardReach && (
                <p style={metaLine}>
                  A wildcard grant reaches every current and future resource that matches its pattern — its blast radius is
                  unbounded, not the count above.
                </p>
              )}
            </>
          )}
        </Section>

        {/* Open findings — cite the rule + the resource. */}
        <Section title="Open findings" meta={`${d.findings.length} open`}>
          {d.findings.length === 0 ? (
            <p style={emptyLine}>No open findings on this identity, its credentials or its grants.</p>
          ) : (
            <ul style={listReset}>
              {d.findings.map((f) => (
                <li key={f.id} style={{ ...rowItem, alignItems: 'baseline' }}>
                  <SeverityBadge severity={f.severity} variant="inline" />
                  <Chip mono>{f.ruleId}</Chip>
                  <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                    on <span style={{ fontFamily: 'var(--font-mono)' }}>{leaf(f.resource)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      </Drawer>
    </>
  );
}

/* — the reach graph — */

/** Identity → reached resources, in the console's graph language (dot canvas, rounded nodes,
 * directional flow). Wildcard edges are dashed and hot because their reach is a PATTERN, not
 * the drawn set — the note under the list says so in words. Capped; the list is complete. */
const REACH_CAP = 7;

function ReachGraph({
  name,
  identityType,
  reached,
  worst,
}: {
  name: string;
  identityType: string;
  reached: Reached[];
  worst: Severity | null;
}) {
  const shown = reached.slice(0, REACH_CAP);
  const W = 470;
  const idW = 138;
  const idH = 46;
  const tW = 196;
  const tH = 36;
  const gapY = 10;
  const pad = 14;
  const rightX = W - pad - tW;
  const colH = shown.length * tH + (shown.length - 1) * gapY;
  const H = Math.max(idH, colH) + pad * 2;
  const idY = pad + (Math.max(idH, colH) - idH) / 2;
  const startY = pad + (Math.max(idH, colH) - colH) / 2;
  const ring = worst ? `var(--sev-${worst}-solid)` : 'var(--accent)';

  return (
    <div className="vs-canvas" style={{ marginBottom: 'var(--space-3)', overflowX: 'auto' }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ display: 'block', width: '100%', minWidth: 420, height: 'auto' }} aria-hidden="true" focusable="false">
        <defs>
          <marker id="vs-reach-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse">
            <path d="M 0 1 L 7 4 L 0 7 z" fill="var(--graph-edge)" />
          </marker>
        </defs>

        {shown.map((r, i) => {
          const y = startY + i * (tH + gapY);
          const x1 = pad + idW;
          const y1 = idY + idH / 2;
          const x2 = rightX;
          const y2 = y + tH / 2;
          const bend = 40;
          const d = `M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`;
          const hot = r.wildcard;
          return (
            <g key={r.resource}>
              <path
                d={d}
                fill="none"
                stroke={hot ? 'var(--sev-critical-solid)' : 'var(--graph-edge)'}
                strokeOpacity={hot ? 0.7 : 1}
                strokeWidth="1.25"
                strokeDasharray={hot ? '5 4' : undefined}
                markerEnd="url(#vs-reach-arrow)"
              />
              <path className="vs-gedge-flow" d={d} fill="none" stroke={hot ? 'var(--sev-critical-solid)' : 'var(--accent)'} strokeOpacity="0.5" strokeWidth="1.5" />
              <rect x={x2} y={y} width={tW} height={tH} rx={10} fill="var(--surface-raised)" stroke={hot ? 'var(--sev-critical-solid)' : 'var(--border-strong)'} strokeDasharray={hot ? '5 4' : undefined} />
              <text x={x2 + 12} y={y + tH / 2 - 2} fontSize="10.5" fontWeight={600} fill="var(--text-primary)" fontFamily="var(--font-mono)">
                {r.resource.length > 24 ? `${r.resource.slice(0, 23)}…` : r.resource}
              </text>
              <text x={x2 + 12} y={y + tH / 2 + 11} fontSize="9" fill={hot ? 'var(--sev-critical-fg)' : 'var(--text-muted)'}>
                {hot ? 'wildcard — pattern, not a list' : r.dataClasses.length ? r.dataClasses.join(' · ') : 'reached by grant'}
              </text>
            </g>
          );
        })}

        <rect x={pad} y={idY} width={idW} height={idH} rx={12} fill="var(--surface-raised)" stroke={ring} strokeWidth="1.5" style={{ filter: 'drop-shadow(0 2px 8px rgb(0 0 0 / 0.1))' }} />
        <text x={pad + 12} y={idY + idH / 2 - 2} fontSize="11" fontWeight={700} fill="var(--text-primary)" fontFamily="var(--font-mono)">
          {name.length > 15 ? `${name.slice(0, 14)}…` : name}
        </text>
        <text x={pad + 12} y={idY + idH / 2 + 11} fontSize="9" fill="var(--text-muted)">
          {identityType || 'identity'}
        </text>
      </svg>
      {reached.length > REACH_CAP && (
        <p style={{ margin: 'var(--space-1) var(--space-3) var(--space-2)', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          Showing {REACH_CAP} of {reached.length} — the list below is complete.
        </p>
      )}
    </div>
  );
}

/* — local presentational bits — */

function Section({ title, meta, children }: { title: string; meta?: string; children: ReactNode }) {
  return (
    <section style={{ padding: 'var(--space-3) 0', borderTop: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 'var(--space-2)', marginBottom: 'var(--space-2)' }}>
        <h3 style={{ margin: 0, fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
          {title}
        </h3>
        {meta && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{meta}</span>}
      </div>
      {children}
    </section>
  );
}

const listReset = { listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' } as const;
const rowItem = { display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap', minWidth: 0 } as const;
const emptyLine = { margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' } as const;
const metaLine = { margin: 'var(--space-2) 0 0', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' } as const;
