import Link from 'next/link';
import type { Route } from 'next';

import { engineGet, enginePost } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Button } from '@/components/ui/button';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill } from '@/components/ui/status-pill';

/* Ask — a plain-language question about this workspace, answered from stored facts.
 *
 * The engine (assistant.py) builds a numbered fact sheet from what scans stored, picks the facts
 * relevant to the question, and lets a model answer ONLY from them, citing each by number. An
 * answer that cites nothing, or cites a fact that was not sent, is discarded and the page shows
 * a plain search of the same facts instead. So every sentence here can be followed to a record.
 *
 * A GET form: the question lives in the URL, so an answer can be linked from a ticket. The page
 * says when AI was not used and why, and never shows a model's text without its sources.
 */

type Source = { n: number; text: string; link: string | null; kind: string };
type Answer = {
  question: string;
  answer: string;
  sources: Source[];
  not_known: string;
  confidence: 'high' | 'medium' | 'low';
  follow_ups: string[];
  ai_used: boolean;
  model: string | null;
  note: string;
  facts_considered: number;
};

export const metadata = { title: 'Ask · VectaSec' };

const STARTERS = [
  'What are the three most urgent things to fix, and why?',
  'Which identities have wildcard access?',
  'What changed in the last week that I should look at?',
  'Where is sensitive data, and who can reach it?',
  'Which systems have never been scanned or have gaps?',
  'What would an attacker reach first from the internet?',
];

const askHref = (q: string) => `/ask?q=${encodeURIComponent(q)}` as Route;

export default async function AskPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const q = ((await searchParams).q ?? '').trim().slice(0, 500);
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const auth = { tenantId: membership.tenantId, actor };

  const [statusRes, res] = await Promise.all([
    engineGet<{ ai_available: boolean }>('/assistant/status', auth),
    q.length >= 3 ? enginePost<Answer>('/assistant/ask', { question: q }, auth, 90_000) : Promise.resolve(null),
  ]);
  const aiOn = statusRes.ok && statusRes.data.ai_available;

  return (
    <PageShell>
      <PageHeader
        title="Ask"
        description="Ask about your systems in plain words. Every answer is built from stored scan records and links to them."
      />

      <Card accent>
        <CardBody>
          <form method="GET" style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'center' }}>
            <label htmlFor="ask-q" className="vs-visually-hidden">
              Your question
            </label>
            <input
              id="ask-q"
              name="q"
              defaultValue={q}
              required
              minLength={3}
              maxLength={500}
              autoComplete="off"
              placeholder="Which identities can write to payments?"
              style={{
                flex: '1 1 320px',
                minWidth: 0,
                height: 'var(--row-default)',
                padding: '0 var(--space-3)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-interactive)',
                background: 'var(--surface-raised)',
                color: 'var(--text-primary)',
                fontSize: 'var(--text-sm)',
              }}
            />
            <Button type="submit" variant="primary" size="sm">
              Ask
            </Button>
          </form>
        </CardBody>
        <CardFooter>
          {aiOn
            ? 'AI writes the answer only from numbered records the scanner stored, and must cite them. An answer that does not is discarded.'
            : 'No working AI provider is configured, so questions run as a plain search of stored records. Set a valid ANTHROPIC_API_KEY, OPENAI_API_KEY or GEMINI_API_KEY for the engine to get written answers.'}
        </CardFooter>
      </Card>

      {!res ? (
        <Card>
          <CardHeader>
            <CardTitle>Try one of these</CardTitle>
          </CardHeader>
          <CardBody>
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
              {STARTERS.map((s) => (
                <li key={s}>
                  <Link href={askHref(s)} style={{ fontSize: 'var(--text-sm)' }}>
                    {s}
                  </Link>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      ) : !res.ok ? (
        <Card>
          <CardBody>
            <EmptyState tone="error" title="The question could not be answered" description={res.message} />
          </CardBody>
        </Card>
      ) : (
        <AnswerView a={res.data} />
      )}
    </PageShell>
  );
}

function AnswerView({ a }: { a: Answer }) {
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>{a.question}</CardTitle>
          <CardMeta>
            {a.facts_considered} record{a.facts_considered === 1 ? '' : 's'} considered
          </CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
            <span style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
              {a.ai_used ? (
                <>
                  <StatusPill tone="info" variant="soft" label="Written by AI from the records below" />
                  <Chip title="How sure the model says it is, given the records">{a.confidence} confidence</Chip>
                </>
              ) : (
                <StatusPill tone="neutral" label="Plain search, no AI" />
              )}
            </span>
            {a.note && (
              <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{a.note}</p>
            )}
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', whiteSpace: 'pre-wrap' }}>
              {a.answer}
            </p>
            {a.not_known && (
              <p style={{ margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
                <strong style={{ color: 'var(--text-primary)' }}>Not known from the records:</strong> {a.not_known}
              </p>
            )}
          </div>
        </CardBody>
      </Card>

      {a.sources.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{a.ai_used ? 'The records this answer rests on' : 'Matching records'}</CardTitle>
            <CardMeta>{a.sources.length}</CardMeta>
          </CardHeader>
          <CardBody>
            <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
              {a.sources.map((s) => (
                <li key={s.n} style={{ display: 'grid', gridTemplateColumns: 'auto minmax(0, 1fr)', gap: 'var(--space-3)', alignItems: 'baseline' }}>
                  <Chip mono>{s.kind}</Chip>
                  <span style={{ fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' }}>
                    {s.text}{' '}
                    {s.link && (
                      <Link href={s.link as Route} style={{ whiteSpace: 'nowrap' }}>
                        Open
                      </Link>
                    )}
                  </span>
                </li>
              ))}
            </ol>
          </CardBody>
        </Card>
      )}

      {a.follow_ups.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Ask next</CardTitle>
          </CardHeader>
          <CardBody>
            <span style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
              {a.follow_ups.map((f) => (
                <Link key={f} href={askHref(f)} style={{ fontSize: 'var(--text-xs)' }}>
                  {f}
                </Link>
              ))}
            </span>
          </CardBody>
        </Card>
      )}
    </>
  );
}
