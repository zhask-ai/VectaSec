import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { StatusPill } from '@/components/ui/status-pill';
import type { FindingDetail } from '../data';
import { CopyButton } from './copy';
import { VerifyButton } from './verify-button';

/* Guided fix + Verify — the remediation loop (docs/vectasec-smb-strategy-2026-10.md §4 item 3).
 *
 * The engine's GET /findings/{id}/fix returns, for rules in its fix library, exact per-system
 * steps and copy-paste snippets (CLI / Terraform / Helm / console) templated with this
 * resource's own names, plus the rule's free-text remediation as the fallback. The console
 * renders what the engine returned and nothing more: no snippet is composed here, so a wrong
 * command is a library bug with a test behind it, not a layout accident.
 *
 * The verify state also comes from the engine rather than from a Supabase column, so this page
 * keeps working on a database that has not yet applied the verify-loop migration.
 */

type Snippet = { kind: string; title: string; body: string };
type Fix = { summary: string; steps: string[]; snippets: Snippet[]; verify_hint: string; read_only_note?: string | null };
type FixResponse = {
  finding_id: string;
  rule_id: string;
  remediation: string | null;
  fix: Fix | null;
  verify?: { requested_at: string | null; verified_at: string | null; verified_scan_id: string | null } | null;
};

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

const KIND_LABEL: Record<string, string> = {
  cli: 'CLI',
  terraform: 'Terraform',
  helm: 'Helm',
  console: 'Console steps',
  config: 'Config',
  sql: 'SQL',
};

export async function GuidedFix({ finding, editable }: { finding: FindingDetail; editable: boolean }) {
  const [membership, user] = await Promise.all([getOwnMembership(), getVerifiedUser()]);
  const res =
    membership && user
      ? await engineGet<FixResponse>(`/findings/${finding.id}/fix`, { tenantId: membership.tenantId, actor: user.id })
      : null;
  const data = res && res.ok ? res.data : null;
  const fix = data?.fix ?? null;
  const verify = data?.verify ?? null;
  const freeText = data?.remediation ?? finding.remediation;
  const resolved = finding.status === 'resolved';
  const canVerify = editable && !resolved && finding.assessment !== 'not_assessable' && Boolean(finding.resource);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Guided fix</CardTitle>
        <CardMeta>
          {fix ? 'exact steps for this system · read-only product, you apply them' : res && !res.ok ? 'engine unavailable — rule text only' : 'rule text · no per-system snippet yet'}
        </CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          {verify?.verified_at && (
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              <StatusPill tone="ok" label="verified fixed" />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                A rescan {relative(verify.verified_at)} no longer saw this issue; the finding was resolved automatically and the
                verification is in the audit trail.
              </span>
            </div>
          )}

          {fix ? (
            <>
              <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-primary)' }}>{fix.summary}</p>
              {fix.steps.length > 0 && (
                <ol style={{ margin: 0, paddingLeft: '1.25em', display: 'grid', gap: 'var(--space-1)', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-primary)' }}>
                  {fix.steps.map((st, i) => (
                    <li key={i}>{st}</li>
                  ))}
                </ol>
              )}
              {fix.snippets.map((sn, i) => (
                <div key={i} style={{ display: 'grid', gap: 'var(--space-1)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-2)' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                      <Chip mono>{KIND_LABEL[sn.kind] ?? sn.kind}</Chip>
                      <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-primary)' }}>{sn.title}</span>
                    </span>
                    <CopyButton text={sn.body} label="Copy" />
                  </div>
                  <pre style={preStyle}>{sn.body}</pre>
                </div>
              ))}
              {fix.read_only_note && (
                <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{fix.read_only_note}</p>
              )}
            </>
          ) : (
            freeText && (
              <div style={{ display: 'grid', gap: 'var(--space-1)' }}>
                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <CopyButton text={freeText} label="Copy remediation" />
                </div>
                <pre style={preStyle}>{freeText}</pre>
              </div>
            )
          )}

          {canVerify && (
            <div style={{ display: 'grid', gap: 'var(--space-2)', paddingTop: 'var(--space-2)', borderTop: '1px solid var(--border)' }}>
              <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                Verify
              </span>
              <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
                {fix?.verify_hint ?? 'A rescan re-reads this system; if the rule no longer fires on this resource, the finding is resolved automatically.'}
              </p>
              <VerifyButton findingId={finding.id} pendingSince={verify?.requested_at ? relative(verify.requested_at) : null} />
            </div>
          )}
        </div>
      </CardBody>
      {fix && freeText && (
        <CardFooter>
          <details>
            <summary style={{ cursor: 'pointer' }}>Rule text</summary>
            <pre style={{ ...preStyle, marginTop: 'var(--space-2)' }}>{freeText}</pre>
          </details>
        </CardFooter>
      )}
    </Card>
  );
}

const preStyle: React.CSSProperties = {
  margin: 0,
  padding: 'var(--space-3)',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-sm)',
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-xs)',
  lineHeight: 'var(--leading-sm)',
  color: 'var(--text-primary)',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
  overflowX: 'auto',
};
