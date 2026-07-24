import { Fragment, type ReactNode } from 'react';

import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { DataClassChips } from '@/components/ui/data-class';
import type { FindingDetail } from '../data';

/* Type-specific detail panels — a structured view of what the finding is, keyed off the rule_id
 * prefix.
 *
 * HONESTY IS THE CONTRACT. Every field here is read from data VectaSec actually collected: each
 * observation's `source_ref` (the immutable evidence ledger) and the resource's `labels` (the
 * tagging layer). Nothing is fetched live, nothing is inferred, and a field that was not recorded
 * is simply not shown — the panel never fabricates a CVSS score or an EPSS probability to fill a
 * gap. The raw claims these facts came from are the cited evidence directly below the panel, so a
 * reader can always check a value by eye.
 *
 * `source_ref` shapes vary by detector (VectaSec has no generated types for them), so extraction
 * is defensive: several candidate key names per field, and only-render-if-present. When a finding
 * carries no structured metadata at all, the panel says so plainly rather than rendering blank.
 */

// ── Fact extraction ─────────────────────────────────────────────────────────
// A case-insensitive lookup built from the finding's own facts. Observations are the most
// specific (per-finding) source, so they are added first and win over the resource-wide labels.
type Facts = Map<string, unknown>;

function factsOf(finding: FindingDetail): Facts {
  const m = new Map<string, unknown>();
  const add = (obj: Record<string, unknown> | null | undefined) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [k, v] of Object.entries(obj)) {
      if (v === null || v === undefined) continue;
      const key = k.toLowerCase();
      if (!m.has(key)) m.set(key, v); // first writer (an observation) wins over a label
    }
  };
  for (const o of finding.evidence) add(o.sourceRef);
  add(finding.labels);
  return m;
}

function str(f: Facts, ...keys: string[]): string | null {
  for (const k of keys) {
    const v = f.get(k.toLowerCase());
    if (typeof v === 'string' && v.trim()) return v.trim();
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
  }
  return null;
}

function num(f: Facts, ...keys: string[]): number | null {
  for (const k of keys) {
    const v = f.get(k.toLowerCase());
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  }
  return null;
}

function bool(f: Facts, ...keys: string[]): boolean | null {
  for (const k of keys) {
    const v = f.get(k.toLowerCase());
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number') return v !== 0;
    if (typeof v === 'string') {
      const s = v.trim().toLowerCase();
      if (['true', 'yes', '1', 'y'].includes(s)) return true;
      if (['false', 'no', '0', 'n'].includes(s)) return false;
    }
  }
  return null;
}

function list(f: Facts, ...keys: string[]): string[] | null {
  for (const k of keys) {
    const v = f.get(k.toLowerCase());
    if (Array.isArray(v)) {
      const out = v
        .map((x) => (typeof x === 'string' ? x : typeof x === 'object' && x ? JSON.stringify(x) : String(x)))
        .filter(Boolean);
      if (out.length) return out;
    }
    if (typeof v === 'string' && v.includes(',')) {
      const out = v.split(',').map((s) => s.trim()).filter(Boolean);
      if (out.length) return out;
    }
  }
  return null;
}

function rawList(f: Facts, ...keys: string[]): unknown[] | null {
  for (const k of keys) {
    const v = f.get(k.toLowerCase());
    if (Array.isArray(v) && v.length) return v;
  }
  return null;
}

// ── Panel chrome ─────────────────────────────────────────────────────────────
function Panel({ title, meta, children }: { title: string; meta?: ReactNode; children: ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {meta && <CardMeta>{meta}</CardMeta>}
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>{children}</div>
      </CardBody>
    </Card>
  );
}

function KeyVals({ rows }: { rows: { label: string; value: ReactNode }[] }) {
  const shown = rows.filter((r) => r.value !== null && r.value !== undefined);
  if (!shown.length) return null;
  return (
    <dl
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(120px, max-content) 1fr',
        gap: 'var(--space-2) var(--space-4)',
        margin: 0,
        fontSize: 'var(--text-sm)',
      }}
    >
      {shown.map((r) => (
        <Fragment key={r.label}>
          <dt
            style={{
              fontSize: 'var(--text-2xs)',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              color: 'var(--text-secondary)',
              alignSelf: 'center',
            }}
          >
            {r.label}
          </dt>
          <dd style={{ margin: 0, color: 'var(--text-primary)', minWidth: 0 }}>{r.value}</dd>
        </Fragment>
      ))}
    </dl>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return <code style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{children}</code>;
}

/** Every panel closes with the same honest footer: these fields are read, not invented. */
function GroundingNote() {
  return (
    <p style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-muted)' }}>
      Read from this finding&apos;s cited evidence and resource labels — VectaSec shows the values it collected and does
      not fetch or infer ones that were not recorded.
    </p>
  );
}

function NoStructured({ kind }: { kind: string }) {
  return (
    <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)', maxWidth: '72ch' }}>
      No structured {kind} metadata was recorded with this finding. The finding is still grounded in the observations
      below — see the cited evidence for the raw facts the detector read.
    </p>
  );
}

/** A subtle key/value resource reference from a source_ref-style object. */
function refResource(ref: Record<string, unknown>): string | null {
  const get = (k: string) => {
    const v = ref[k] ?? ref[k.toLowerCase()];
    return typeof v === 'string' && v.trim() ? v.trim() : typeof v === 'number' ? String(v) : null;
  };
  const kind = get('kind') ?? get('type');
  const name = get('name') ?? get('resource') ?? get('ext_id') ?? get('id') ?? get('target');
  if (kind && name) return `${kind} ${name}`;
  return name ?? kind ?? null;
}

// ── CVE.* ────────────────────────────────────────────────────────────────────
function cvssBand(score: number): { word: string; tone: 'high' | 'medium' | 'low' | 'info' } {
  if (score >= 9) return { word: 'Critical', tone: 'high' };
  if (score >= 7) return { word: 'High', tone: 'high' };
  if (score >= 4) return { word: 'Medium', tone: 'medium' };
  if (score > 0) return { word: 'Low', tone: 'low' };
  return { word: 'None', tone: 'info' };
}

function CvePanel({ facts }: { facts: Facts }) {
  const cve = str(facts, 'cve', 'cve_id', 'cveid', 'vuln_id', 'vulnerability_id');
  const cvss = num(facts, 'cvss', 'cvss_score', 'cvss_v3', 'cvss3', 'cvss_base_score', 'base_score');
  const vector = str(facts, 'cvss_vector', 'cvss_v3_vector', 'vector');
  const kev = bool(facts, 'kev', 'in_kev', 'known_exploited', 'cisa_kev');
  const epss = num(facts, 'epss', 'epss_score', 'epss_probability');
  const source = str(facts, 'source', 'advisory', 'advisory_id', 'ghsa', 'feed');
  const pkg = str(facts, 'package', 'component', 'artifact', 'purl', 'product');
  const installed = str(facts, 'installed_version', 'current_version', 'affected_version', 'version');
  const fixed = str(facts, 'fixed_version', 'fixed_in', 'fix_version', 'patched_version');
  const published = str(facts, 'published', 'published_at', 'disclosed', 'disclosed_at');

  const cveId = cve && /^CVE-\d{4}-\d{3,}$/i.test(cve) ? cve.toUpperCase() : cve;
  const band = cvss !== null ? cvssBand(cvss) : null;
  // EPSS is a 0..1 probability; some feeds already give a percentage. Normalise for display only.
  const epssPct = epss !== null ? (epss <= 1 ? epss * 100 : epss) : null;
  const anyStructured =
    cveId || cvss !== null || kev !== null || epss !== null || source || pkg || fixed || vector || published;

  return (
    <Panel title="Vulnerability (CVE)" meta="from the vulnerability feed">
      {cveId && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)' }}>
            {cveId}
          </span>
          {kev === true && <KevBadge />}
          {band && (
            <Chip tone={band.tone}>
              CVSS {cvss!.toFixed(1)} · {band.word}
            </Chip>
          )}
          {epssPct !== null && (
            <Chip tone={epssPct >= 10 ? 'high' : 'neutral'} title="EPSS — modelled probability of exploitation in the next 30 days">
              EPSS {epssPct.toFixed(epssPct >= 10 ? 0 : 1)}%
            </Chip>
          )}
        </div>
      )}

      {kev === true && (
        <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--sev-critical-fg)', maxWidth: '80ch' }}>
          On CISA&apos;s Known Exploited Vulnerabilities list — this is being exploited in the wild now, which outranks its
          CVSS score for prioritisation.
        </p>
      )}

      <KeyVals
        rows={[
          { label: 'Affected', value: pkg ? <Mono>{pkg}</Mono> : null },
          { label: 'Installed', value: installed ? <Mono>{installed}</Mono> : null },
          {
            label: 'Fixed in',
            value: fixed ? (
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Mono>{fixed}</Mono>
                <Chip tone="low">upgrade target</Chip>
              </span>
            ) : null,
          },
          { label: 'CVSS vector', value: vector ? <Mono>{vector}</Mono> : null },
          {
            label: 'EPSS',
            value: epssPct !== null ? `${epssPct.toFixed(2)}% chance of exploitation (next 30 days)` : null,
          },
          { label: 'Source', value: source },
          { label: 'Published', value: published },
        ]}
      />

      {!anyStructured && <NoStructured kind="CVE" />}
      <GroundingNote />
    </Panel>
  );
}

function KevBadge() {
  return (
    <span
      title="CISA Known Exploited Vulnerabilities catalog"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        padding: '2px var(--space-2)',
        border: '1px solid var(--sev-critical-solid)',
        background: 'var(--sev-critical-bg)',
        color: 'var(--sev-critical-fg)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-2xs)',
        fontWeight: 700,
        letterSpacing: '0.04em',
      }}
    >
      CISA KEV · actively exploited
    </span>
  );
}

// ── TLS.* ────────────────────────────────────────────────────────────────────
function TlsPanel({ facts }: { facts: Facts }) {
  const proto = str(facts, 'protocol', 'tls_version', 'protocol_version', 'version');
  const cipher = str(facts, 'cipher', 'cipher_suite', 'ciphersuite');
  const cn = str(facts, 'subject', 'subject_cn', 'common_name', 'cn');
  const issuer = str(facts, 'issuer', 'issuer_cn', 'ca');
  const notAfter = str(facts, 'not_after', 'valid_to', 'expires', 'expiry', 'cert_expiry');
  const notBefore = str(facts, 'not_before', 'valid_from', 'issued');
  const keyBits = num(facts, 'key_bits', 'key_size', 'key_length', 'bits');
  const sigAlg = str(facts, 'sig_alg', 'signature_algorithm', 'signature_alg');
  const selfSigned = bool(facts, 'self_signed', 'selfsigned');
  const sans = list(facts, 'san', 'sans', 'subject_alt_names', 'alt_names', 'dns_names');

  const weakProto = proto ? /ssl|tls\s*1\.0|tls\s*1\.1|(^|[^.\d])1\.[01]([^.\d]|$)/i.test(proto) : false;
  const anyStructured =
    proto || cipher || cn || issuer || notAfter || notBefore || keyBits !== null || sigAlg || selfSigned !== null || sans;

  return (
    <Panel title="TLS / certificate" meta="from the transport handshake and certificate">
      {(weakProto || selfSigned === true) && (
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          {weakProto && <Chip tone="high">Deprecated protocol — {proto}</Chip>}
          {selfSigned === true && <Chip tone="medium">Self-signed certificate</Chip>}
        </div>
      )}

      <KeyVals
        rows={[
          { label: 'Protocol', value: proto ? <Mono>{proto}</Mono> : null },
          { label: 'Cipher', value: cipher ? <Mono>{cipher}</Mono> : null },
          { label: 'Subject', value: cn ? <Mono>{cn}</Mono> : null },
          { label: 'Issuer', value: issuer },
          { label: 'Key', value: keyBits !== null ? `${keyBits}-bit` : null },
          { label: 'Signature', value: sigAlg ? <Mono>{sigAlg}</Mono> : null },
          { label: 'Valid from', value: notBefore },
          { label: 'Expires', value: notAfter },
          {
            label: 'SANs',
            value: sans ? (
              <span style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                {sans.slice(0, 12).map((s) => (
                  <Chip key={s} mono>
                    {s}
                  </Chip>
                ))}
                {sans.length > 12 && <span style={{ color: 'var(--text-secondary)' }}>+{sans.length - 12} more</span>}
              </span>
            ) : null,
          },
        ]}
      />

      {!anyStructured && <NoStructured kind="TLS" />}
      <GroundingNote />
    </Panel>
  );
}

// ── ATTACKPATH.* ─────────────────────────────────────────────────────────────
type Hop = { label: string | null; resource: string | null; obsId?: string; obsN?: number };

function normalizeHop(h: unknown, i: number): Hop {
  if (typeof h === 'string') return { label: h, resource: null };
  if (h && typeof h === 'object') {
    const o = h as Record<string, unknown>;
    const label =
      (typeof o.label === 'string' && o.label) ||
      (typeof o.claim === 'string' && o.claim) ||
      (typeof o.step === 'string' && o.step) ||
      (typeof o.reason === 'string' && o.reason) ||
      (typeof o.description === 'string' && o.description) ||
      null;
    return { label: label || `Hop ${i + 1}`, resource: refResource(o) };
  }
  return { label: String(h), resource: null };
}

function AttackPathPanel({ finding, facts }: { finding: FindingDetail; facts: Facts }) {
  const raw = rawList(facts, 'path', 'chain', 'hops', 'steps', 'edges', 'nodes');
  // Prefer an explicit path array; otherwise treat each observation as one observed hop — which is
  // exactly what an attack-path detector emits (one edge per observation, in order).
  const hops: Hop[] =
    raw && raw.length
      ? raw.map(normalizeHop)
      : finding.evidence.map((o, i) => ({
          label: o.claim,
          resource: refResource(o.sourceRef),
          obsId: o.id,
          obsN: i + 1,
        }));

  return (
    <Panel title="Attack path" meta={`toxic combination · ${hops.length} hop${hops.length === 1 ? '' : 's'}`}>
      <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)', maxWidth: '80ch' }}>
        Each hop below is a real relationship VectaSec observed. Individually benign, together they chain into a path an
        attacker could walk — which is why this is a finding and its parts are not.
      </p>

      {hops.length === 0 ? (
        <NoStructured kind="attack-path" />
      ) : (
        <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 0 }}>
          {hops.map((hop, i) => (
            <li key={hop.obsId ?? i} style={{ display: 'grid', gridTemplateColumns: '24px 1fr', gap: 'var(--space-2)' }}>
              {/* The rail: a numbered node with a connector line to the next hop. */}
              <div style={{ display: 'grid', justifyItems: 'center', gap: 2 }}>
                <span
                  data-numeric
                  style={{
                    display: 'grid',
                    placeItems: 'center',
                    width: 22,
                    height: 22,
                    borderRadius: 'var(--radius-full)',
                    border: '1px solid var(--border-interactive)',
                    background: 'var(--surface-raised)',
                    fontSize: 'var(--text-2xs)',
                    fontWeight: 600,
                    color: 'var(--text-primary)',
                  }}
                >
                  {i + 1}
                </span>
                {i < hops.length - 1 && <span aria-hidden="true" style={{ width: 1, flex: 1, minHeight: 12, background: 'var(--border-strong)' }} />}
              </div>

              <div style={{ paddingBottom: i < hops.length - 1 ? 'var(--space-3)' : 0, minWidth: 0 }}>
                {hop.resource && (
                  <div style={{ marginBottom: 2 }}>
                    <Chip mono>{hop.resource}</Chip>
                  </div>
                )}
                <div style={{ fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-primary)' }}>
                  {hop.label}
                </div>
                {hop.obsId && hop.obsN !== undefined && (
                  <a
                    href={`#obs-${hop.obsId}`}
                    style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-low-fg)', textDecoration: 'none' }}
                  >
                    cited by observation [{hop.obsN}]
                  </a>
                )}
              </div>
            </li>
          ))}
        </ol>
      )}

      <GroundingNote />
    </Panel>
  );
}

// ── NHI.* / CREDENTIAL.LIFECYCLE.* ───────────────────────────────────────────
function IdentityPanel({ facts }: { facts: Facts }) {
  const principal = str(facts, 'principal', 'identity', 'service_account', 'sa', 'subject', 'client_id', 'username', 'name');
  const idType = str(facts, 'identity_type', 'principal_type', 'account_type');
  const credType = str(facts, 'credential_type', 'secret_type', 'key_type', 'auth_type');
  const created = str(facts, 'created', 'created_at', 'issued_at', 'first_seen');
  const lastUsed = str(facts, 'last_used', 'last_used_at', 'last_activity', 'last_auth');
  const lastRotated = str(facts, 'last_rotated', 'rotated_at', 'last_rotation');
  const ageDays = num(facts, 'age_days', 'key_age_days', 'credential_age_days', 'age');
  const grants = list(facts, 'grants', 'scopes', 'permissions', 'roles', 'privileges', 'entitlements');
  const privileged = bool(facts, 'privileged', 'admin', 'is_admin', 'wildcard', 'over_privileged');

  const anyStructured =
    principal || idType || credType || created || lastUsed || lastRotated || ageDays !== null || grants || privileged !== null;

  return (
    <Panel title="Identity & credential" meta="non-human identity · grants and lifecycle">
      {(privileged === true) && (
        <div>
          <Chip tone="high">Over-privileged / wildcard grant</Chip>
        </div>
      )}

      <KeyVals
        rows={[
          { label: 'Principal', value: principal ? <Mono>{principal}</Mono> : null },
          { label: 'Type', value: idType },
          { label: 'Credential', value: credType },
          { label: 'Created', value: created },
          { label: 'Last used', value: lastUsed },
          { label: 'Last rotated', value: lastRotated },
          { label: 'Age', value: ageDays !== null ? `${ageDays} day${ageDays === 1 ? '' : 's'}` : null },
        ]}
      />

      {grants && (
        <div style={{ display: 'grid', gap: 'var(--space-1)' }}>
          <span style={{ fontSize: 'var(--text-2xs)', letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
            Grants ({grants.length})
          </span>
          <div style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
            {grants.slice(0, 24).map((g) => (
              <Chip key={g} mono tone={/\*|admin|owner|root|all/i.test(g) ? 'high' : 'neutral'}>
                {g}
              </Chip>
            ))}
            {grants.length > 24 && <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>+{grants.length - 24} more</span>}
          </div>
        </div>
      )}

      {!anyStructured && <NoStructured kind="identity" />}
      <GroundingNote />
    </Panel>
  );
}

// ── DATA.* ───────────────────────────────────────────────────────────────────
function DataPanel({ facts }: { facts: Facts }) {
  const classes = list(facts, 'data_classes', 'classes', 'classification', 'data_class');
  const sensitivity = str(facts, 'sensitivity', 'data_sensitivity') ?? 'none';
  const signals = str(facts, 'data_signals', 'signals', 'matched', 'match', 'matched_signals');

  return (
    <Panel title="Data classification" meta="inferred from resource naming, not payload inspection">
      {classes && classes.length ? (
        <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
          <DataClassChips classes={classes.map((c) => c.toLowerCase())} sensitivity={sensitivity} signals={signals ?? undefined} />
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)', maxWidth: '80ch' }}>
            VectaSec reads configuration, not payloads — these classes are inferred from the resource&apos;s name (the dashed
            border is the tell), never proven from content.{signals ? ` Matched: ${signals}.` : ''}
          </p>
        </div>
      ) : (
        <NoStructured kind="data-classification" />
      )}
      <GroundingNote />
    </Panel>
  );
}

// ── Dispatcher ───────────────────────────────────────────────────────────────
/** Render the panel(s) matching this finding's rule_id prefix. Returns null for rules with no
 * specialised view — the generic header, evidence and remediation already cover those. */
export function TypePanels({ finding }: { finding: FindingDetail }) {
  const rid = finding.ruleId.toUpperCase();
  const facts = factsOf(finding);

  if (rid.startsWith('CVE')) return <CvePanel facts={facts} />;
  if (rid.startsWith('TLS')) return <TlsPanel facts={facts} />;
  if (rid.startsWith('ATTACKPATH')) return <AttackPathPanel finding={finding} facts={facts} />;
  if (rid.startsWith('NHI') || rid.startsWith('CREDENTIAL')) return <IdentityPanel facts={facts} />;
  if (rid.startsWith('DATA')) return <DataPanel facts={facts} />;
  return null;
}
