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

        {/* Blast radius — reach derived from grant scope, honest about wildcards. */}
        <Section title="Blast radius" meta="inferred from grant scope">
          {reached.length === 0 ? (
            <p style={emptyLine}>Nothing reachable from recorded grants.</p>
          ) : (
            <>
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
