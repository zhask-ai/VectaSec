import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { StatusPill, type StatusTone } from '@/components/ui/status-pill';
import type { FindingDetail } from '../data';
import { ProveButton } from './prove-button';

/* Proof mode — "misconfigured" becomes "proven reachable", with a transcript.
 *
 * The engine (proof.py) makes ONE read-only request that any client makes before it logs in,
 * against this finding's own target, and stores what came back. This card shows the exact
 * action before the button is pressed, and every attempt after.
 *
 * Renders nothing when the rule has no safe proof and none was ever attempted: most rules
 * cannot be demonstrated without sending a credential or changing something, and a greyed-out
 * "Prove it" on every finding would teach people to ignore the one that works.
 *
 * FOUR VERDICTS, and the wording keeps them apart: "unreachable" must never read as "safe".
 */

type Proof = {
  id: string;
  verdict: 'proven' | 'not_reproduced' | 'unreachable' | 'unsupported';
  action: string;
  target: string | null;
  transcript: string[];
  reason: string | null;
  duration_ms: number;
  created_at: string;
};

type ProofResponse = {
  available: boolean;
  supported: boolean;
  action: string | null;
  proofs: Proof[];
};

const VERDICT: Record<Proof['verdict'], { label: string; tone: StatusTone; says: string }> = {
  proven: {
    label: 'Proven reachable',
    tone: 'bad',
    says: 'The request succeeded without any credential. Anyone who can reach this address can do the same.',
  },
  not_reproduced: {
    label: 'Not reproduced',
    tone: 'ok',
    says: 'The target answered and did not let the unauthenticated request through.',
  },
  unreachable: {
    label: 'Could not reach it',
    tone: 'neutral',
    says: 'This neither proves nor rules out the finding. It only means the engine has no network path to the target.',
  },
  unsupported: { label: 'No safe proof', tone: 'neutral', says: 'Nothing was sent.' },
};

function stamp(iso: string): string {
  return new Date(iso).toISOString().slice(0, 16).replace('T', ' ');
}

export async function ProofCard({ finding, editable }: { finding: FindingDetail; editable: boolean }) {
  const [membership, user] = await Promise.all([getOwnMembership(), getVerifiedUser()]);
  if (!membership || !user) return null;
  const res = await engineGet<ProofResponse>(`/findings/${finding.id}/proof`, {
    tenantId: membership.tenantId,
    actor: user.id,
  });
  // Engine down or the table not migrated: this is an addition to a page that already works.
  if (!res.ok || !res.data.available) return null;
  const { supported, action, proofs } = res.data;
  if (!supported && proofs.length === 0) return null;

  const latest = proofs[0] ?? null;
  const earlier = proofs.slice(1);
  const v = latest ? VERDICT[latest.verdict] : null;
  const p: React.CSSProperties = { margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' };

  return (
    <Card accent={latest?.verdict === 'proven'}>
      <CardHeader>
        <CardTitle>Proof</CardTitle>
        <CardMeta>
          {latest ? `last checked ${stamp(latest.created_at)} UTC` : 'not checked yet'}
        </CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          {latest && v && (
            <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
              <span style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', alignItems: 'center' }}>
                <StatusPill tone={v.tone} variant="soft" label={v.label} />
                {latest.target && (
                  <code style={{ fontSize: 'var(--text-xs)' }}>{latest.target}</code>
                )}
              </span>
              <p style={p}>{latest.reason ?? v.says}</p>
              {latest.transcript.length > 0 && (
                <ol
                  aria-label="What the target returned"
                  style={{
                    margin: 0,
                    padding: 'var(--space-3)',
                    listStyle: 'none',
                    display: 'grid',
                    gap: 'var(--space-1)',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border)',
                    background: 'var(--surface-raised)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 'var(--text-2xs)',
                    overflowWrap: 'anywhere',
                  }}
                >
                  {latest.transcript.map((line, i) => (
                    <li key={i}>{line}</li>
                  ))}
                </ol>
              )}
            </div>
          )}

          {supported && action && (
            <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
              <p style={{ ...p, color: 'var(--text-secondary)' }}>
                <strong style={{ color: 'var(--text-primary)' }}>What the check does:</strong> {action}
              </p>
              {editable ? (
                <ProveButton findingId={finding.id} again={latest !== null} />
              ) : (
                <p style={{ ...p, color: 'var(--text-secondary)' }}>Running it needs an editor or admin role.</p>
              )}
            </div>
          )}

          {earlier.length > 0 && (
            <details>
              <summary style={{ cursor: 'pointer', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                {earlier.length} earlier check{earlier.length === 1 ? '' : 's'}
              </summary>
              <ul style={{ listStyle: 'none', margin: 'var(--space-2) 0 0', padding: 0, display: 'grid', gap: 'var(--space-1)', fontSize: 'var(--text-2xs)' }}>
                {earlier.map((e) => (
                  <li key={e.id} style={{ display: 'flex', gap: 'var(--space-2)', color: 'var(--text-secondary)' }}>
                    <time dateTime={e.created_at}>{stamp(e.created_at)}</time>
                    <span style={{ color: 'var(--text-primary)' }}>{VERDICT[e.verdict].label}</span>
                    {e.target && <code>{e.target}</code>}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      </CardBody>
      <CardFooter>
        One request, sent from the VectaSec engine to the address this connection already uses.
        No credential is ever tried, including default ones, and nothing is written.
      </CardFooter>
    </Card>
  );
}
