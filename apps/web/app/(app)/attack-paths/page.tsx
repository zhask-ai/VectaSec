import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import { SEVERITY_RANK, type Severity } from '@/lib/types';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader, SectionHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatTile } from '@/components/ui/stat';
import { StatusPill } from '@/components/ui/status-pill';

/* Attack paths — VectaSec's flagship differentiator, the toxic-combination correlation engine made
 * visible. A flat scanner emits N independent findings; the value here is the CORRELATION: when an
 * exposed surface, an over-privileged non-human identity, and sensitive data line up on ONE resource
 * graph, that co-occurrence is an exploitable path, not three tolerable weaknesses.
 *
 * Reads under RLS like every console page. It selects `findings` where rule_id like 'ATTACKPATH.%',
 * joins their `observations` (each observation's claim/source_ref names a hop) and the `resources`
 * they cite for context, then renders each path HOP-BY-HOP as a visual chain:
 *   exposed surface  →  over-privileged NHI  →  sensitive data
 *
 * HONESTY (DESIGN law 3): the engine correlates AUTHORIZATION + HOSTING within a single scan. It does
 * not prove network lineage or runtime reachability — deep multi-hop lineage awaits the CDC
 * connectors. Where a finding carries no per-hop evidence, the chain is reconstructed from the rule's
 * definition and SAYS SO rather than pretending to proof. Empty ≠ clean ≠ error.
 *
 * COUNTS caveat (as Identities): unbounded PostgREST selects cap at Max Rows (~1000), so headline
 * totals come from exact `head` counts and the board is bounded by an explicit limit; a truncation
 * note appears when the two disagree.
 */

export const metadata = { title: 'Attack paths · VectaSec' };

const ROW_CAP = 1000;

// ── Data shapes (cast from loosely-typed PostgREST rows, as Identities does) ──────────────────────

type Labels = Record<string, unknown> | null;

type FindingRow = {
  id: string;
  rule_id: string;
  severity: Severity;
  status: string;
  resource_id: string | null;
  labels: Labels;
  raw: unknown;
  created_at?: string | null;
};

type ObservationRow = {
  id: string;
  finding_id: string;
  claim: string | null;
  source_ref: string | null;
};

type ResourceRow = { id: string; ext_id: string; name: string; kind: string; labels: Labels };

type HopKind = 'exposure' | 'privilege' | 'sensitive' | 'generic';
type ChainSource = 'observations' | 'raw' | 'fallback';

type Hop = {
  kind: HopKind;
  factor: string;
  detail: string;
  cited: string;
  dataClasses: string[];
  sensitivity: string;
};

type AttackPath = {
  id: string;
  ruleId: string;
  archetypeKey: string;
  archetypeLabel: string;
  blurb: string;
  severity: Severity;
  status: string;
  system: string;
  resourceName: string;
  hops: Hop[];
  chainSource: ChainSource;
  chainNote: string | null;
  when: string | null;
};

// ── The three toxic-combination archetypes the engine emits ───────────────────────────────────────

const ARCHETYPE: Record<string, { label: string; blurb: string; factors: string[]; kinds: HopKind[] }> = {
  EXPOSED_NHI_SENSITIVE: {
    label: 'Exposed NHI reaches sensitive data',
    blurb:
      'The full triad — an externally reachable surface fronts a non-human identity whose grants reach data classified sensitive by naming. Any one factor is tolerable; together they form a path.',
    factors: ['Exposed surface', 'Over-privileged NHI', 'Sensitive data'],
    kinds: ['exposure', 'privilege', 'sensitive'],
  },
  PUBLIC_OVERPRIVILEGED: {
    label: 'Public + over-privileged',
    blurb: 'An externally reachable surface is served by an identity holding a broad, wildcard grant.',
    factors: ['Exposed surface', 'Wildcard grant'],
    kinds: ['exposure', 'privilege'],
  },
  SENSITIVE_ON_EXPOSED: {
    label: 'Sensitive data on an exposed surface',
    blurb:
      'A resource classified sensitive by naming sits on a surface reachable from outside the trust boundary.',
    factors: ['Sensitive data', 'Exposed surface'],
    kinds: ['sensitive', 'exposure'],
  },
};

const FACTOR_LABEL: Record<HopKind, string> = {
  exposure: 'Exposed surface',
  privilege: 'Over-privileged NHI',
  sensitive: 'Sensitive data',
  generic: 'Factor',
};

const KIND_RANK: Record<HopKind, number> = { exposure: 0, privilege: 1, sensitive: 2, generic: 3 };
const KIND_COLOR: Record<HopKind, string> = {
  exposure: 'var(--sev-high-fg)',
  privilege: 'var(--sev-medium-fg)',
  sensitive: 'var(--sev-critical-fg)',
  generic: 'var(--text-secondary)',
};

const GROUPS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const GROUP_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

// ── Pure helpers ──────────────────────────────────────────────────────────────────────────────────

function lbl(labels: Labels, k: string): string {
  const v = labels ? labels[k] : undefined;
  return v == null ? '' : String(v);
}
function ruleSuffix(ruleId: string): string {
  return String(ruleId ?? '').split('.').pop() || String(ruleId ?? '');
}
function leaf(name: string): string {
  return String(name ?? '').split(':').pop() || String(name ?? '');
}
function normSev(s: string): Severity {
  return (SEVERITY_RANK as Record<string, number>)[s] !== undefined ? (s as Severity) : 'info';
}
function prettyKey(key: string): string {
  return key.replace(/_/g, ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase());
}

function classifyHop(text: string): HopKind {
  const t = text.toLowerCase();
  if (/(wildcard|over-?priv|privileg|grant|permission|\bacl\b|\brole\b|scope|authoriz|admin|\*)/.test(t)) return 'privilege';
  if (/(expos|public|internet|external|reachable|ingress|listener|endpoint|anonymous|unauth|\bopen\b)/.test(t)) return 'exposure';
  if (/(sensitive|classif|pci|phi|pii|secret|confidential|payment|personal|financial)/.test(t)) return 'sensitive';
  return 'generic';
}

function dataClassesFrom(text: string): string[] {
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

function makeHop(text: string, ref: string, detail?: string): Hop {
  const basis = `${text} ${ref}`;
  const kind = classifyHop(basis);
  return {
    kind,
    factor: FACTOR_LABEL[kind],
    detail: (detail ?? text) || ref || '—',
    cited: ref,
    dataClasses: kind === 'sensitive' ? dataClassesFrom(basis) : [],
    sensitivity: 'high',
  };
}

function hopFromObservation(o: ObservationRow): Hop {
  const claim = o.claim ?? '';
  const ref = o.source_ref ?? '';
  return makeHop(claim || ref, ref, claim || undefined);
}

/** Best-effort structured chain out of the finding's raw evidence blob (shape unknown, so tolerant). */
function hopsFromRaw(raw: unknown): { text: string; ref: string }[] | null {
  if (!raw || typeof raw !== 'object') return null;
  const r = raw as Record<string, unknown>;
  const cand = r.chain ?? r.hops ?? r.path ?? r.steps;
  if (!Array.isArray(cand) || cand.length === 0) return null;
  const hops = cand
    .map((el) => {
      if (typeof el === 'string') return { text: el, ref: '' };
      if (el && typeof el === 'object') {
        const o = el as Record<string, unknown>;
        const text = String(o.claim ?? o.label ?? o.factor ?? o.description ?? o.step ?? '');
        const ref = String(o.resource ?? o.source_ref ?? o.ref ?? o.target ?? o.name ?? '');
        return { text, ref };
      }
      return { text: String(el), ref: '' };
    })
    .filter((h) => h.text || h.ref);
  return hops.length ? hops : null;
}

function archetypeHop(factor: string, kind: HopKind, res: ResourceRow | undefined, f: FindingRow): Hop {
  const cited = res?.name ?? lbl(f.labels, 'resource');
  return {
    kind,
    factor,
    detail: `${factor} — from the rule definition`,
    cited,
    dataClasses: kind === 'sensitive' ? dataClassesFrom(`${factor} ${cited} ${lbl(f.labels, 'data_classes')}`) : [],
    sensitivity: 'high',
  };
}

/** The heart of the page: turn one finding + its observations into an ordered, honest hop chain. */
function buildPath(f: FindingRow, obs: ObservationRow[], resById: Map<string, ResourceRow>): AttackPath {
  const key = ruleSuffix(f.rule_id);
  const arch = ARCHETYPE[key];
  const res = f.resource_id ? resById.get(f.resource_id) : undefined;
  const system = lbl(f.labels, 'system') || (res ? lbl(res.labels, 'system') : '');
  const resourceName = lbl(f.labels, 'resource') || (res ? res.name : '') || (f.resource_id ?? '');

  let hops: Hop[] = [];
  let chainSource: ChainSource = 'fallback';
  let chainNote: string | null = null;

  if (obs.length) {
    // Primary path: each observation IS a hop. Reorder into the canonical attack direction only when
    // every hop classified cleanly; otherwise keep recorded order and say the roles are inferred.
    hops = obs.map(hopFromObservation);
    const allKnown = hops.every((h) => h.kind !== 'generic');
    if (allKnown && hops.length > 1) {
      hops = [...hops].sort((a, b) => KIND_RANK[a.kind] - KIND_RANK[b.kind]);
    } else if (!allKnown) {
      chainNote = 'Hops are shown in the order recorded; factor roles are inferred from the evidence text, not asserted by the engine.';
    }
    chainSource = 'observations';
  } else {
    const rawHops = hopsFromRaw(f.raw);
    if (rawHops) {
      hops = rawHops.map((rh) => makeHop(rh.text, rh.ref));
      chainSource = 'raw';
      chainNote = 'Chain read from the finding’s recorded evidence rather than discrete observations.';
    } else if (arch) {
      hops = arch.factors.map((factor, i) => archetypeHop(factor, arch.kinds[i], res, f));
      chainSource = 'fallback';
      chainNote = 'No per-hop evidence was recorded on this finding — the chain is reconstructed from the rule’s definition and is not proven hop-by-hop.';
    } else {
      hops = [makeHop(f.rule_id, resourceName)];
      chainSource = 'fallback';
      chainNote = 'No structured chain was recorded for this finding.';
    }
  }

  return {
    id: f.id,
    ruleId: f.rule_id,
    archetypeKey: key,
    archetypeLabel: arch?.label ?? prettyKey(key),
    blurb: arch?.blurb ?? '',
    severity: normSev(f.severity),
    status: f.status,
    system,
    resourceName,
    hops,
    chainSource,
    chainNote,
    when: f.created_at ?? null,
  };
}

// ── Page ──────────────────────────────────────────────────────────────────────────────────────────

export default async function AttackPathsPage() {
  const supabase = await createClient();

  // `.eq('status','open')` on all three: without it the "Attack paths" and "Critical — full
  // triad" tiles counted resolved and suppressed rows and rendered them tone="bad", so
  // suppressing a path left the alarming number unchanged. The per-card StatusPill was the
  // only honest signal on the page.
  const [countRes, triadRes, resourceCountRes, findingsRes] = await Promise.all([
    supabase.from('findings').select('*', { count: 'exact', head: true }).like('rule_id', 'ATTACKPATH.%').eq('status', 'open'),
    supabase.from('findings').select('*', { count: 'exact', head: true }).eq('rule_id', 'ATTACKPATH.EXPOSED_NHI_SENSITIVE').eq('status', 'open'),
    supabase.from('resources').select('*', { count: 'exact', head: true }),
    supabase.from('findings').select('*').like('rule_id', 'ATTACKPATH.%').eq('status', 'open').limit(ROW_CAP),
  ]);

  if (findingsRes.error) {
    return (
      <Page>
        <PageHeader title="Attack paths" description={HEAD_DESC} />
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load attack paths" description={findingsRes.error.message} />
          </CardBody>
        </Card>
      </Page>
    );
  }

  const findingRows = (findingsRes.data ?? []) as unknown as FindingRow[];
  const totalCount = countRes.count ?? findingRows.length;
  const triadCount = triadRes.count ?? findingRows.filter((f) => ruleSuffix(f.rule_id) === 'EXPOSED_NHI_SENSITIVE').length;
  const resourceCount = resourceCountRes.count ?? 0;

  if (findingRows.length === 0) {
    return resourceCount === 0 ? <SetupState /> : <CleanState resourceCount={resourceCount} />;
  }

  // Second round: hop evidence (observations) + cited resources for context.
  const findingIds = findingRows.map((f) => f.id);
  const resourceIds = [...new Set(findingRows.map((f) => f.resource_id).filter((x): x is string => Boolean(x)))];
  const [obsRes, resRes] = await Promise.all([
    supabase.from('observations').select('*').in('finding_id', findingIds).limit(ROW_CAP),
    supabase.from('resources').select('id, ext_id, name, kind, labels').in('id', resourceIds).limit(ROW_CAP),
  ]);

  // A failed observation read is degraded, not fatal — fall back to definition-reconstructed chains
  // (each such card says so) rather than blanking the flagship page.
  const observations = (obsRes.error ? [] : obsRes.data ?? []) as unknown as ObservationRow[];
  const resourceList = (resRes.error ? [] : resRes.data ?? []) as unknown as ResourceRow[];
  const obsMissing = Boolean(obsRes.error);

  const obsByFinding = new Map<string, ObservationRow[]>();
  for (const o of observations) {
    const arr = obsByFinding.get(o.finding_id);
    if (arr) arr.push(o);
    else obsByFinding.set(o.finding_id, [o]);
  }
  const resById = new Map<string, ResourceRow>();
  for (const r of resourceList) resById.set(r.id, r);

  const paths = findingRows
    .map((f) => buildPath(f, obsByFinding.get(f.id) ?? [], resById))
    .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);

  const byType: Record<string, number> = {};
  for (const p of paths) byType[p.archetypeKey] = (byType[p.archetypeKey] ?? 0) + 1;
  const typeCount = Object.keys(byType).length;

  const truncated = findingRows.length < totalCount;
  const latest = paths.map((p) => p.when).filter((w): w is string => Boolean(w)).sort().pop();
  const asOf = latest ? ` · as of ${String(latest).slice(0, 10)}` : '';

  return (
    <Page>
      <PageHeader
        title="Attack paths"
        description={HEAD_DESC}
        meta={`${totalCount} path${totalCount === 1 ? '' : 's'} · ${typeCount} type${typeCount === 1 ? '' : 's'}${truncated ? ` · showing first ${findingRows.length}` : ''}${asOf}`}
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 'var(--space-3)' }}>
        <KpiCard>
          <StatTile label="Attack paths" value={totalCount} tone={totalCount ? 'bad' : 'good'} sub="toxic combinations correlated" />
        </KpiCard>
        <KpiCard>
          <StatTile
            label="Critical — full triad"
            value={triadCount}
            tone={triadCount ? 'bad' : 'good'}
            sub="exposed → over-privileged NHI → sensitive"
          />
        </KpiCard>
        <KpiCard>
          <StatTile
            label="Public + over-privileged"
            value={byType.PUBLIC_OVERPRIVILEGED ?? 0}
            tone={byType.PUBLIC_OVERPRIVILEGED ? 'warn' : 'good'}
            sub="exposed surface, wildcard grant"
          />
        </KpiCard>
        <KpiCard>
          <StatTile
            label="Sensitive on exposed"
            value={byType.SENSITIVE_ON_EXPOSED ?? 0}
            tone={byType.SENSITIVE_ON_EXPOSED ? 'warn' : 'good'}
            sub="sensitive data, reachable surface"
          />
        </KpiCard>
      </div>

      <Explainer />

      {obsMissing && (
        <Card>
          <CardBody>
            <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--sev-medium-fg)' }}>
              Per-hop evidence could not be read this load, so the chains below are reconstructed from each rule’s
              definition rather than from discrete observations. This is a degraded view, not a clean one.
            </p>
          </CardBody>
        </Card>
      )}

      {GROUPS.map((sev) => {
        const group = paths.filter((p) => p.severity === sev);
        if (group.length === 0) return null;
        return (
          <section key={sev} style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <SectionHeader title={GROUP_LABEL[sev]} meta={`${group.length} path${group.length === 1 ? '' : 's'}`} />
            {group.map((p) => (
              <AttackPathCard key={p.id} path={p} />
            ))}
          </section>
        );
      })}
    </Page>
  );
}

const HEAD_DESC =
  'Where an exposed surface, an over-privileged non-human identity and sensitive data line up on one resource graph — the correlation a flat scanner cannot make. Each path is shown hop by hop.';

// ── Attack-path card ──────────────────────────────────────────────────────────────────────────────

function AttackPathCard({ path }: { path: AttackPath }) {
  const isTriad = path.archetypeKey === 'EXPOSED_NHI_SENSITIVE';
  return (
    <Card>
      <CardHeader>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', minWidth: 0, flexWrap: 'wrap' }}>
          <CardTitle>{path.archetypeLabel}</CardTitle>
          <Chip mono>{path.ruleId}</Chip>
          {isTriad && <Chip tone="high">toxic combination</Chip>}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexShrink: 0 }}>
          <SeverityBadge severity={path.severity} />
          <StatusPill tone={path.status === 'open' ? 'bad' : 'neutral'} label={path.status || 'open'} />
        </div>
      </CardHeader>

      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
            <Field label="System">{path.system ? <Chip>{path.system}</Chip> : <Muted>unknown</Muted>}</Field>
            <Field label="Resource">
              {path.resourceName ? <Chip mono>{leaf(path.resourceName)}</Chip> : <Muted>unknown</Muted>}
            </Field>
          </div>

          {path.blurb && (
            <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
              {path.blurb}
            </p>
          )}

          <ChainPath hops={path.hops} note={path.chainNote} />
        </div>
      </CardBody>

      <CardFooter>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <StatusPill tone={path.chainSource === 'observations' ? 'info' : 'neutral'} label={SOURCE_LABEL[path.chainSource]} />
            <CardMeta>
              {path.hops.length} hop{path.hops.length === 1 ? '' : 's'}
              {path.when ? ` · ${String(path.when).slice(0, 10)}` : ''}
            </CardMeta>
          </span>
          <Link
            href={`/findings/${path.id}` as Route}
            style={{ fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--sev-low-fg)' }}
          >
            Full evidence &rarr;
          </Link>
        </div>
      </CardFooter>
    </Card>
  );
}

const SOURCE_LABEL: Record<ChainSource, string> = {
  observations: 'from observations',
  raw: 'from evidence',
  fallback: 'from rule definition',
};

// ── The centerpiece: hop-by-hop chain visualization ───────────────────────────────────────────────

function ChainPath({ hops, note }: { hops: Hop[]; note: string | null }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <ol
        aria-label={`Attack chain, ${hops.length} hop${hops.length === 1 ? '' : 's'}`}
        style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 'var(--space-1)' }}
      >
        {hops.map((hop, i) => (
          <li key={i} style={{ display: 'flex', alignItems: 'center' }} aria-label={`Hop ${i + 1}, ${hop.factor}`}>
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

function Connector() {
  return (
    <svg
      width="30"
      height="12"
      viewBox="0 0 30 12"
      fill="none"
      aria-hidden="true"
      style={{ color: 'var(--text-muted)', flexShrink: 0, margin: '0 var(--space-1)' }}
    >
      <line x1="0" y1="6" x2="24" y2="6" stroke="currentColor" strokeWidth="1.5" />
      <path d="M24 2l5 4-5 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function HopNode({ hop, index }: { hop: Hop; index: number }) {
  const color = KIND_COLOR[hop.kind];
  return (
    <div
      style={{
        flex: '0 1 220px',
        minWidth: 190,
        display: 'grid',
        gap: 'var(--space-2)',
        padding: 'var(--space-3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        background: 'var(--surface-raised)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', minWidth: 0 }}>
        <span
          aria-hidden="true"
          style={{
            display: 'grid',
            placeItems: 'center',
            width: 20,
            height: 20,
            flexShrink: 0,
            borderRadius: 'var(--radius-full)',
            border: '1px solid var(--border-interactive)',
            fontSize: 'var(--text-2xs)',
            fontWeight: 600,
            color: 'var(--text-primary)',
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {index}
        </span>
        <span style={{ display: 'inline-flex', color, flexShrink: 0 }}>
          <HopGlyph kind={hop.kind} />
        </span>
        <span style={{ fontSize: 'var(--text-2xs)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600, color, whiteSpace: 'nowrap' }}>
          {hop.factor}
        </span>
      </div>

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

      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {hop.kind === 'sensitive' && hop.dataClasses.length > 0 ? (
          <DataClassChips classes={hop.dataClasses} sensitivity={hop.sensitivity} signals={hop.cited} />
        ) : hop.cited ? (
          <Chip mono title={hop.cited}>{leaf(hop.cited)}</Chip>
        ) : (
          <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>no cited resource</span>
        )}
      </div>
    </div>
  );
}

function HopGlyph({ kind }: { kind: HopKind }) {
  const common = { width: 14, height: 14, viewBox: '0 0 16 16', fill: 'none', stroke: 'currentColor', strokeWidth: 1.5, 'aria-hidden': true } as const;
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

// ── Explainer (honest about scope) ────────────────────────────────────────────────────────────────

function Explainer() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>How to read a toxic combination</CardTitle>
        <StatusPill tone="neutral" label="correlation, not proven lineage" />
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)', maxWidth: '84ch' }}>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
            On their own, an exposed listener, a wildcard grant, or a sensitively named topic are each routine — the queue is
            full of them. A <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>toxic combination</strong> is when
            they line up on <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>one path</strong>: an outside-reachable
            surface, fronted by an identity that is over-privileged, whose reach lands on data classified sensitive. That
            co-occurrence is the finding a flat, per-check scanner structurally cannot produce.
          </p>
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-secondary)' }}>
            <span style={{ color: 'var(--sev-medium-fg)', fontWeight: 600 }}>The honest limit.</span> VectaSec correlates{' '}
            <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>authorization and hosting</strong> observed within a
            single scan — it establishes that these factors sit on the same resource graph. It does{' '}
            <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>not</strong> prove network lineage or runtime
            reachability between the hops; deep, multi-hop data lineage across systems awaits the change-data-capture (CDC)
            connectors. Sensitivity classes are inferred from naming (the dashed chips), never from payload inspection. Read
            each chain as &ldquo;these factors co-occur and warrant investigation&rdquo;, not as a proven exploit.
          </p>
        </div>
      </CardBody>
    </Card>
  );
}

// ── Small layout helpers ──────────────────────────────────────────────────────────────────────────

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
      <span style={{ fontSize: 'var(--text-2xs)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600, color: 'var(--text-secondary)' }}>
        {label}
      </span>
      {children}
    </span>
  );
}

function Muted({ children }: { children: React.ReactNode }) {
  return <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{children}</span>;
}

function KpiCard({ children }: { children: React.ReactNode }) {
  return (
    <Card>
      <CardBody>{children}</CardBody>
    </Card>
  );
}

function Page({ children }: { children: React.ReactNode }) {
  return <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>{children}</div>;
}

// ── Honest empty states ───────────────────────────────────────────────────────────────────────────

function SetupState() {
  return (
    <Page>
      <PageHeader
        title="Attack paths"
        description="Where an exposed surface, an over-privileged non-human identity and sensitive data line up on one resource graph."
      />
      <Card>
        <CardBody>
          <EmptyState
            tone="setup"
            title="No scan yet"
            description="Attack paths are correlated across what the connectors read. Connect and scan a system and any toxic combinations — exposure, over-privilege and sensitive data lined up on one path — surface here."
            action={
              <Link href="/connections" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Go to Connections &rarr;
              </Link>
            }
          />
        </CardBody>
      </Card>
    </Page>
  );
}

function CleanState({ resourceCount }: { resourceCount: number }) {
  return (
    <Page>
      <PageHeader
        title="Attack paths"
        description="Where an exposed surface, an over-privileged non-human identity and sensitive data line up on one resource graph."
      />
      <Explainer />
      <Card>
        <CardBody>
          <EmptyState
            tone="clean"
            title="No attack paths detected"
            description="The correlation engine found no toxic combination — no path where an exposed surface, an over-privileged identity and sensitive data co-occur on the same resource graph."
            meta={`${resourceCount} resource${resourceCount === 1 ? '' : 's'} assessed`}
            action={
              <Link href="/findings" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Review all findings &rarr;
              </Link>
            }
          />
        </CardBody>
      </Card>
    </Page>
  );
}
