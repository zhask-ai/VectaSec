import Link from 'next/link';
import type { Route } from 'next';

import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { StatusPill } from '@/components/ui/status-pill';

/* "Explain these changes" — the Time machine read back in plain words (engine:
 * assistant.explain_changes). Rendered only when the URL asks for it (?explain=1), so opening
 * the History tab never spends a model call on its own. Every sentence the model writes must
 * cite recorded changes; anything that does not is dropped by the engine before it gets here. */

type Src = { n: number; text: string; link: string | null };
type Explain = {
  summary: string;
  look_at: { what: string; why: string; sources: Src[] }[];
  ai_used: boolean;
  note: string;
  changes_considered: number;
};

export async function ExplainCard({ days }: { days: number }) {
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const res = await engineGet<Explain>(`/assistant/explain-changes?days=${Math.min(days, 90)}`, {
    tenantId: membership.tenantId,
    actor,
  }, 90_000);
  if (!res.ok) return null;
  const d = res.data;
  return (
    <Card accent>
      <CardHeader>
        <CardTitle>What these changes mean</CardTitle>
        <CardMeta>{d.changes_considered} change{d.changes_considered === 1 ? '' : 's'} read</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <span>
            {d.ai_used ? (
              <StatusPill tone="info" variant="soft" label="Written by AI from the recorded changes" />
            ) : (
              <StatusPill tone="neutral" label="No AI used" />
            )}
          </span>
          <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)' }}>{d.summary}</p>
          {d.note && <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{d.note}</p>}
          {d.look_at.length > 0 && (
            <ol style={{ margin: 0, paddingLeft: 'var(--space-5)', display: 'grid', gap: 'var(--space-2)', fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' }}>
              {d.look_at.map((i, k) => (
                <li key={k}>
                  <strong>{i.what}</strong> {i.why}{' '}
                  {i.sources.map((s) =>
                    s.link ? (
                      <Link key={s.n} href={s.link as Route} title={s.text} style={{ marginRight: 6 }}>
                        record {s.n}
                      </Link>
                    ) : null,
                  )}
                </li>
              ))}
            </ol>
          )}
        </div>
      </CardBody>
      <CardFooter>
        The explanation can only restate and relate changes listed below. It does not know who made
        a change or why unless the system recorded it.
      </CardFooter>
    </Card>
  );
}
