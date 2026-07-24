import Link from 'next/link';
import { notFound } from 'next/navigation';

import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { SeverityBadge } from '@/components/ui/severity';
import { canEdit, getOwnMembership, getRoleInTenant } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { NotAssessedBadge } from '../assessment';
import { getActionContext, getFinding, type EvidenceItem, type FindingDetail, type TriageView } from '../data';
import { shortId } from '../format';
import { systemHref, systemOf } from '../query';
import { StatusPill } from '../status';
import { ActionsPanel, TriageButton } from './actions-panel';
import { CopyButton } from './copy';
import { TypePanels } from './panels';

/* The finding detail — the page that has to earn trust.
 *
 * Its structure is an argument, and the order is the argument: what we found, then THE EXACT
 * BYTES WE READ, and only then anything generated about them. Evidence sits above triage on
 * purpose. If the AI section were first, a reader would anchor on the narrative and treat the
 * observations as supporting material; the product's actual claim is the reverse — the
 * observations are the finding, and the narrative is a convenience that has to cite them.
 */

// getFinding is called here AND in the page. React's request-level dedup collapses them into
// one query — `cache()` around the Supabase client plus identical arguments — so the title does
// not cost a second round trip.
export async function generateMetadata({ params }: PageProps<'/findings/[id]'>) {
  const { id } = await params;
  const finding = await getFinding(id);
  return { title: finding ? `${finding.ruleId} · VectaSec` : 'Finding · VectaSec' };
}

export default async function FindingPage({ params }: PageProps<'/findings/[id]'>) {
  const { id } = await params;

  // A [param] folder is an arbitrary string from the URL. Rejecting a non-uuid here keeps a
  // malformed id from reaching PostgREST as a type error we would have to interpret.
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) notFound();

  const finding = await getFinding(id);
  // Null covers "does not exist" and "exists in a tenant you cannot see" — RLS makes them the
  // same answer, and that is correct: a 404 that differs from a 403 is a cross-tenant oracle
  // that confirms an id exists.
  if (!finding) notFound();

  // getClaims, not getVerifiedUser: this is a read, and the only use is to decide whether the
  // assignee uuid is "you". The actions re-verify properly on their own.
  const claims = await getClaims();
  const currentUserId = typeof claims?.sub === 'string' ? claims.sub : null;

  // Role decides which controls render. This is courtesy, not the check — the Server Actions
  // re-derive the role from tenant_members before touching the engine. The tenant comes from
  // getActionContext (an RLS-scoped read of this finding), because FindingDetail deliberately
  // does not carry tenant_id; falling back to the caller's sole membership covers the odd
  // orphaned row.
  const ctx = await getActionContext(id);
  const role = ctx
    ? await getRoleInTenant(ctx.tenantId)
    : ((await getOwnMembership())?.role ?? null);
  const editable = canEdit(role);

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1200 }}>
      <Link href="/findings" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        ← Findings
      </Link>

      <Header finding={finding} />

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(240px, 300px)', gap: 'var(--space-4)', alignItems: 'start' }}>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          {/* Type-specific structured view, keyed off the rule_id prefix (CVE/TLS/ATTACKPATH/
              NHI/CREDENTIAL/DATA). It sits above the raw evidence because it is "what we found"
              in structured form — but every field it shows is read from the observations and
              labels below, never fetched or invented. Renders nothing for rules with no
              specialised panel. */}
          <TypePanels finding={finding} />
          <Evidence items={finding.evidence} finding={finding} />
          <Triage finding={finding} editable={editable} />
          <Remediation finding={finding} />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Actions</CardTitle>
          </CardHeader>
          <CardBody>
            {editable ? (
              <ActionsPanel
                findingId={finding.id}
                status={finding.uiStatus}
                assignee={finding.assignee}
                currentUserId={currentUserId}
                resourceKind={finding.resource?.kind ?? null}
                resourceName={finding.resource?.name ?? null}
                ruleId={finding.ruleId}
              />
            ) : (
              // Absent, not disabled: the honest statement of why, instead of a rail of dead
              // controls that answer every click with a refusal.
              <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
                Your role is view-only. Changing status, assignment or suppressions needs an
                editor or admin role — ask a tenant admin.
              </p>
            )}
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

function Header({ finding }: { finding: FindingDetail }) {
  const r = finding.resource;
  const gap = finding.assessment === 'not_assessable';

  return (
    <Card>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            {/* A coverage gap wears the neutral mark, not a severity: it is not a vulnerability. */}
            {gap ? <NotAssessedBadge /> : <SeverityBadge severity={finding.severity} />}
            <StatusPill status={finding.uiStatus} />
            <code style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{finding.ruleId}</code>
            <Link
              href={systemHref(systemOf(finding.ruleId))}
              style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}
            >
              {systemOf(finding.ruleId)}
            </Link>
          </div>

          <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
            {finding.title}
          </h1>

          {/* The coverage-gap callout. Stated once, plainly, and neutrally bordered (never a
              severity colour): this is "we could not check", which is neither a vulnerability nor a
              clean pass, and reading it as either would be the failure this state exists to prevent. */}
          {gap && (
            <div
              style={{
                display: 'grid',
                gap: 'var(--space-1)',
                padding: 'var(--space-3)',
                border: '1px dashed var(--border-interactive)',
                borderRadius: 'var(--radius-md)',
                background: 'var(--bg)',
              }}
            >
              <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                This is a coverage gap, not a vulnerability.
              </strong>
              <span style={{ fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)', maxWidth: '80ch' }}>
                The detector could not read what it needed to check this rule, so we cannot say whether
                it passes or fails — only that it was not assessed.
                {finding.assessmentReason?.trim()
                  ? ` Reason: ${finding.assessmentReason}`
                  : ' No reason was recorded.'}
              </span>
            </div>
          )}

          {finding.detail && (
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)', maxWidth: '80ch' }}>
              {finding.detail}
            </p>
          )}

          <dl style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-5)', margin: 0, fontSize: 'var(--text-xs)' }}>
            <Meta label="Resource">
              {r ? (
                <span style={{ display: 'inline-flex', gap: 'var(--space-1)', alignItems: 'baseline' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{r.kind}</span>
                  <code>{r.name}</code>
                  {r.namespace && <span style={{ color: 'var(--text-secondary)' }}>· {r.namespace}</span>}
                </span>
              ) : (
                // findings.resource_id is nullable and survives its resource being deleted.
                <span style={{ color: 'var(--text-secondary)' }}>No resource — it may have been removed</span>
              )}
            </Meta>

            {r?.connectionName && (
              <Meta label="Connection">
                <span style={{ color: 'var(--text-secondary)' }}>{r.connectionType}</span> {r.connectionName}
              </Meta>
            )}

            <Meta label="First seen">
              <time dateTime={finding.firstSeenIso}>{finding.firstSeenIso}</time>{' '}
              <span style={{ color: 'var(--text-secondary)' }}>({finding.firstSeenLabel})</span>
            </Meta>

            <Meta label="Last seen">
              <time dateTime={finding.lastSeenIso}>{finding.lastSeenIso}</time>{' '}
              <span style={{ color: 'var(--text-secondary)' }}>({finding.lastSeenLabel})</span>
            </Meta>
          </dl>

          {/* The fingerprint is the dedup key: same fingerprint = same row across every scan,
              last_seen updated in place. It is also the AI cache key. Worth surfacing — it is
              the id a customer or a support engineer can correlate on. */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>Fingerprint</span>
            <code style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{finding.fingerprint}</code>
            <CopyButton text={finding.fingerprint} label="Copy" />
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

function Meta({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt style={{ fontSize: 'var(--text-2xs)', letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
        {label}
      </dt>
      <dd style={{ margin: '2px 0 0', fontSize: 'var(--text-xs)' }}>{children}</dd>
    </div>
  );
}

/* ── Evidence ─────────────────────────────────────────────────────────────
 * The differentiator. Most tools describe the problem; this shows the exact bytes.
 *
 * The claim is rendered verbatim in monospace and is never summarised, truncated, or
 * reformatted: it is a fact read from the target, written to an immutable ledger, and it is the
 * only thing the AI is allowed to cite. Evidence in a proportional font does not read as
 * evidence — and evidence that has been "tidied" is not evidence at all.
 *
 * Numbering is 1-based in observed_at order, which is exactly the order and numbering ai.py
 * hands the model (`select … order by observed_at`, `[{i}] {claim}`). So [2] here is [2] there.
 * That alignment is not cosmetic: it is what lets a reader check a citation by eye. */
function Evidence({ items, finding }: { items: EvidenceItem[]; finding: FindingDetail }) {
  const cited = new Set(finding.triage?.citedObservationIds ?? []);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence</CardTitle>
        <CardMeta>What we read from your system · {items.length} observation{items.length === 1 ? '' : 's'}</CardMeta>
      </CardHeader>

      <CardBody>
        {items.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
            No observations are attached to this finding. A finding with no evidence cannot be triaged by the AI
            layer — the engine refuses rather than inventing a rationale — and it should be treated as unverified.
          </p>
        ) : (
          <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
            {items.map((o, i) => (
              <Observation key={o.id} item={o} n={i + 1} cited={cited.has(o.id)} />
            ))}
          </ol>
        )}
      </CardBody>
    </Card>
  );
}

function Observation({ item, n, cited }: { item: EvidenceItem; n: number; cited: boolean }) {
  const refs = Object.entries(item.sourceRef).filter(([, v]) => v !== null && v !== undefined);

  return (
    <li
      // The anchor the triage citation chips link to.
      id={`obs-${item.id}`}
      style={{
        display: 'grid',
        gap: 'var(--space-2)',
        padding: 'var(--space-3)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        background: 'var(--bg)',
        scrollMarginTop: 'var(--space-5)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <span data-numeric style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, color: 'var(--text-secondary)' }}>
          [{n}]
        </span>
        <code style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>{shortId('obs', item.id)}</code>
        <time dateTime={item.observedAtIso} style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          observed {item.observedAtIso}
        </time>
        {cited && (
          <span
            style={{
              fontSize: 'var(--text-2xs)',
              color: 'var(--sev-low-fg)',
              border: '1px solid var(--border-strong)',
              borderRadius: 'var(--radius-full)',
              padding: '0 var(--space-2)',
            }}
          >
            cited by triage
          </span>
        )}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)' }}>
          <CopyButton text={item.id} label="Copy ID" />
        </span>
      </div>

      {/* The literal claim. Verbatim, monospace, wrapping preserved. */}
      <pre
        style={{
          margin: 0,
          padding: 'var(--space-3)',
          background: 'var(--surface-raised)',
          borderRadius: 'var(--radius-sm)',
          borderLeft: '2px solid var(--border-interactive)',
          fontSize: 'var(--text-xs)',
          lineHeight: 'var(--leading-sm)',
          color: 'var(--text-primary)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          overflowX: 'auto',
        }}
      >
        {item.claim}
      </pre>

      <div style={{ display: 'flex', gap: 'var(--space-4)', flexWrap: 'wrap', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        {refs.map(([k, v]) => (
          <span key={k}>
            <span style={{ opacity: 0.8 }}>{k}</span>{' '}
            <code style={{ fontSize: 'var(--text-2xs)' }}>
              {typeof v === 'object' ? JSON.stringify(v) : String(v)}
            </code>
          </span>
        ))}
        {/* A claim that could be edited after the fact is not evidence. This is a real
            guarantee, not a slogan: an UPDATE on observations is rejected by a database
            trigger (observations_append_only). Worded precisely — DELETE is still permitted so
            offboarding and FK cascades work, so this says "never modified", not "never
            removed". */}
        <span style={{ marginLeft: 'auto' }}>Immutable ✓ never modified since write</span>
      </div>
    </li>
  );
}

/* ── AI triage ────────────────────────────────────────────────────────────
 * Fenced and labelled. The user must always know which pixels are deterministic (the finding,
 * the evidence above) and which are generated — that boundary IS the product's integrity made
 * visible, so it gets a border and a chip rather than a footnote. */
function Triage({ finding, editable }: { finding: FindingDetail; editable: boolean }) {
  const t = finding.triage;

  if (!t) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Triage</CardTitle>
          <CardMeta>Not generated yet</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-3)', justifyItems: 'start' }}>
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', maxWidth: '64ch' }}>
              {finding.evidence.length === 0
                ? 'This finding has no observations, so it cannot be triaged. The engine refuses to generate a rationale it cannot ground in evidence.'
                : editable
                  ? 'Generate a grounded explanation of this finding. Every claim it makes must cite one of the observations above, or the database rejects it.'
                  : 'No triage has been generated. Generating one needs an editor or admin role.'}
            </p>
            {editable && <TriageButton findingId={finding.id} disabled={finding.evidence.length === 0} />}
          </div>
        </CardBody>
      </Card>
    );
  }

  const citedCount = t.citedObservationIds.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Why this matters</CardTitle>
        <CardMeta>
          generated {t.createdAtLabel} · cites {citedCount} of {finding.evidence.length} observation
          {finding.evidence.length === 1 ? '' : 's'}
        </CardMeta>
      </CardHeader>

      <CardBody>
        <div
          style={{
            display: 'grid',
            gap: 'var(--space-3)',
            padding: 'var(--space-3)',
            // The fence. Everything inside this border is generated; everything outside was read.
            border: `1px ${t.isAi ? 'solid' : 'dashed'} var(--border-strong)`,
            borderRadius: 'var(--radius-md)',
            background: 'var(--bg)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
            <ProvenanceChip triage={t} />
            <PriorityChip priority={t.priority} />
            {/* A word, never a percentage: "73% confident" is unfalsifiable theatre. The
                citation count and the evidence itself are the checkable confidence signal. */}
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
              confidence {t.confidence}
            </span>
          </div>

          {/* Priority provenance, stated honestly. When a rule's severity floor overrode the
              model's own priority, say so and name both numbers — a P0 the model did not choose is
              still deterministic, and hiding that would let the model take credit for a rule's call. */}
          <PriorityFloorNote triage={t} />

          <Prose>{t.summary}</Prose>
          <Field label="Business risk">{t.businessRisk}</Field>
          <Field label="Exploitability">{t.exploitability}</Field>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap', paddingTop: 'var(--space-2)', borderTop: '1px solid var(--border)' }}>
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>Grounded in</span>
            {t.citedObservationIds.map((obsId) => {
              const idx = finding.evidence.findIndex((e) => e.id === obsId);
              // A citation whose observation is not on this finding would mean the ledger and
              // the output disagree. It cannot normally happen (the engine range-checks every
              // citation and Postgres refuses to commit an uncited output), so show it loudly
              // rather than dropping it — a silently-hidden citation is the one failure mode
              // that would make this whole section a lie.
              if (idx === -1) {
                return (
                  <span key={obsId} style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
                    [?] unknown observation {shortId('obs', obsId)}
                  </span>
                );
              }
              return <CitationChip key={obsId} n={idx + 1} obsId={obsId} />;
            })}
            {citedCount === 0 && (
              <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
                No citations recorded — do not rely on this text.
              </span>
            )}
          </div>
        </div>

        {/* An honest limit, stated where it matters. The engine stores citations per OUTPUT
            (ai_output_evidence), not per sentence, so this section can truthfully say which
            observations the whole triage rests on but not which sentence rests on which. Faking
            per-sentence markers would be the exact anti-pattern this product exists to avoid:
            attribution that looks more precise than it is. */}
        <p style={{ margin: 'var(--space-2) 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          Citations are recorded for this output as a whole. Claim-level attribution needs the engine to store a
          per-sentence mapping, which it does not yet.
        </p>
      </CardBody>
    </Card>
  );
}

/** The label that must never be wrong. `rule-based-fallback` is a deterministic template built
 * from the observation — calling it AI would misattribute both its authorship and its
 * reliability, in the one place this product cannot afford either. */
function ProvenanceChip({ triage }: { triage: TriageView }) {
  const ai = triage.isAi;

  return (
    <span
      title={ai ? `Model: ${triage.model}` : 'Generated by a deterministic template, not a model'}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-1)',
        padding: '1px var(--space-2)',
        border: `1px ${ai ? 'solid' : 'dashed'} var(--border-interactive)`,
        borderRadius: 'var(--radius-full)',
        fontSize: 'var(--text-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        color: ai ? 'var(--sev-low-fg)' : 'var(--text-secondary)',
      }}
    >
      {ai ? 'AI · grounded' : 'Deterministic · rule-based'}
      <span className="vs-visually-hidden">
        {ai
          ? `. Generated by model ${triage.model}, and every claim cites an observation.`
          : '. Not AI-authored: the model was unavailable, so this was assembled from the evidence by a fixed template.'}
      </span>
    </span>
  );
}

/** Priority is a property of THIS occurrence; severity is a property of the rule. Conflating
 * them is why teams drown in criticals, so the label says which one this is. */
function PriorityChip({ priority }: { priority: string }) {
  return (
    <span
      style={{
        padding: '1px var(--space-2)',
        border: '1px solid var(--border-strong)',
        borderRadius: 'var(--radius-full)',
        fontSize: 'var(--text-2xs)',
        fontWeight: 600,
        color: 'var(--text-primary)',
      }}
    >
      triage priority {priority}
    </span>
  );
}

/** The honest account of a floored priority. Priority is a property of THIS occurrence; the rule's
 * severity floor is deterministic, not the model's judgement, so when it lifts the priority the UI
 * names both numbers rather than presenting the raised value as the model's own. Absent on older
 * triage rows (read defensively upstream), so this renders nothing unless the floor was recorded. */
function PriorityFloorNote({ triage }: { triage: TriageView }) {
  if (!triage.priorityFloorApplied) return null;

  return (
    <p style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
      Priority <strong style={{ color: 'var(--text-primary)' }}>{triage.priority}</strong>
      {triage.modelPriority
        ? ` — raised from the model's ${triage.modelPriority} by the rule's severity floor.`
        : " — raised above the model's own priority by the rule's severity floor."}
    </p>
  );
}

function CitationChip({ n, obsId }: { n: number; obsId: string }) {
  return (
    <a
      href={`#obs-${obsId}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0 var(--space-2)',
        border: '1px solid var(--border-interactive)',
        borderRadius: 'var(--radius-sm)',
        fontSize: 'var(--text-2xs)',
        fontVariantNumeric: 'tabular-nums',
        color: 'var(--sev-low-fg)',
        textDecoration: 'none',
      }}
    >
      [{n}]
      <span className="vs-visually-hidden"> jump to observation {n}</span>
    </a>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'grid', gap: '2px' }}>
      <span style={{ fontSize: 'var(--text-2xs)', letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
        {label}
      </span>
      <Prose>{children}</Prose>
    </div>
  );
}

function Prose({ children }: { children: React.ReactNode }) {
  return (
    <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-primary)', maxWidth: '80ch' }}>
      {children}
    </p>
  );
}

function Remediation({ finding }: { finding: FindingDetail }) {
  if (!finding.remediation) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Remediation</CardTitle>
        <CopyButton text={finding.remediation} label="Copy remediation" />
      </CardHeader>
      <CardBody>
        {/* <pre>, not <p>: remediation is written by the detector and routinely contains config
            keys and commands. Reflowing it would break a value someone is about to paste. */}
        <pre
          style={{
            margin: 0,
            padding: 'var(--space-3)',
            background: 'var(--bg)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-sm)',
            fontSize: 'var(--text-xs)',
            lineHeight: 'var(--leading-sm)',
            color: 'var(--text-primary)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
            overflowX: 'auto',
          }}
        >
          {finding.remediation}
        </pre>
      </CardBody>
    </Card>
  );
}
