'use client';

import { useActionState } from 'react';

import { reviewResourceAction, type ReviewState } from './review-action';

/* AI review of this resource's stored configuration (engine: assistant.review_resource).
 *
 * The model proposes issues the rules did not raise; each proposal has to quote the exact config
 * path and value it rests on, and the engine drops any proposal whose quote is not really there.
 * What is shown is a SUGGESTION for a person to check. It is not a finding and never changes the
 * posture score or a compliance result, and the card says so every time. */

const SEV: Record<string, string> = { high: 'var(--sev-high-fg)', medium: 'var(--sev-medium-fg)', low: 'var(--text-secondary)' };

export function AiReview({ resourceId, editable }: { resourceId: string; editable: boolean }) {
  const [state, action, pending] = useActionState<ReviewState, FormData>(reviewResourceAction, null);
  const r = state?.ok ? state.result : undefined;
  const small: React.CSSProperties = { margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' };
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <p style={{ ...small, color: 'var(--text-secondary)' }}>
        Ask a model to read this resource&apos;s stored configuration for problems the rules do not
        cover: risky combinations, text aimed at AI agents, over-broad access. Each suggestion must
        quote the setting it rests on, and unquotable ones are discarded.
      </p>
      <form action={action}>
        <input type="hidden" name="resourceId" value={resourceId} />
        <button
          type="submit"
          className="vs-button"
          data-variant="secondary"
          disabled={pending || !editable}
          aria-busy={pending || undefined}
          style={{
            border: '1px solid var(--border-interactive)',
            borderRadius: 'var(--radius-md)',
            background: 'var(--surface-raised)',
            color: 'var(--text-primary)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            padding: '0 var(--space-3)',
            height: 'var(--row-default)',
            cursor: pending || !editable ? 'not-allowed' : 'pointer',
            opacity: pending || !editable ? 0.6 : 1,
          }}
        >
          {pending ? 'Reading the configuration…' : r ? 'Review again' : 'Review with AI'}
        </button>
      </form>
      {!editable && <p style={{ ...small, color: 'var(--text-secondary)' }}>Running a review needs an editor or admin role.</p>}
      {state && !state.ok && (
        <p role="alert" style={{ ...small, color: 'var(--sev-critical-fg)' }}>
          {state.message}
        </p>
      )}
      {r && (
        <div role="status" style={{ display: 'grid', gap: 'var(--space-3)' }}>
          {r.note && <p style={{ ...small, color: 'var(--text-secondary)' }}>{r.note}</p>}
          {r.ai_used && r.suggestions.length === 0 && (
            <p style={small}>
              Nothing beyond what the rules already raise.
              {r.discarded > 0 ? ` ${r.discarded} suggestion(s) were discarded because their quoted evidence was not in the configuration.` : ''}
            </p>
          )}
          {r.suggestions.length > 0 && (
            <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-4)' }}>
              {r.suggestions.map((s, i) => (
                <li key={i} style={{ display: 'grid', gap: 'var(--space-1)', minWidth: 0 }}>
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600 }}>
                    <span style={{ color: SEV[s.severity], fontSize: 'var(--text-2xs)', textTransform: 'uppercase', letterSpacing: '0.04em', marginRight: 8 }}>
                      {s.severity} · suggested
                    </span>
                    {s.title}
                  </span>
                  <span style={small}>{s.why}</span>
                  <code style={{ fontSize: 'var(--text-2xs)', overflowWrap: 'anywhere', color: 'var(--text-secondary)' }}>
                    {s.evidence_path} = {s.evidence_value}
                  </code>
                  {s.check && (
                    <span style={{ ...small, color: 'var(--text-secondary)' }}>
                      <strong style={{ color: 'var(--text-primary)' }}>Check first:</strong> {s.check}
                    </span>
                  )}
                </li>
              ))}
            </ol>
          )}
          {r.suggestions.length > 0 && r.discarded > 0 && (
            <p style={{ ...small, color: 'var(--text-muted)' }}>
              {r.discarded} more suggestion(s) were discarded: their quoted evidence was not in the configuration.
            </p>
          )}
          <p style={{ ...small, color: 'var(--text-muted)' }}>{r.disclaimer}</p>
        </div>
      )}
    </div>
  );
}
