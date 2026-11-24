'use client';

import { useActionState } from 'react';

import { createBriefAction, type ActionState } from './actions';

/* The advisory form. Four fields at most, because on the day nobody fills in twelve: what, what
 * kind, which versions, and a link for whoever reads the brief later. */

const control: React.CSSProperties = {
  height: 'var(--row-default)',
  padding: '0 var(--space-2)',
  borderRadius: 'var(--radius-md)',
  border: '1px solid var(--border-interactive)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  width: '100%',
  minWidth: 0,
};

const label: React.CSSProperties = {
  display: 'grid',
  gap: 'var(--space-1)',
  fontSize: 'var(--text-2xs)',
  fontWeight: 600,
  color: 'var(--text-secondary)',
  minWidth: 0,
};

export function BriefForm({ systems, editable }: { systems: string[]; editable: boolean }) {
  const [state, action, pending] = useActionState<ActionState, FormData>(createBriefAction, null);
  return (
    <form action={action} style={{ display: 'grid', gap: 'var(--space-3)' }}>
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))',
          gap: 'var(--space-3)',
          alignItems: 'end',
        }}
      >
        <label style={label}>
          Product or vendor
          <input
            name="product"
            list="breach-systems"
            placeholder="n8n, redis, kong, zapier…"
            required
            maxLength={100}
            autoComplete="off"
            style={control}
          />
          <datalist id="breach-systems">
            {systems.map((s) => (
              <option key={s} value={s} />
            ))}
          </datalist>
        </label>
        <label style={label}>
          What happened
          <select name="kind" defaultValue="vulnerability" style={control}>
            <option value="vulnerability">A vulnerability in the product</option>
            <option value="vendor_breach">The vendor was breached</option>
          </select>
        </label>
        <label style={label}>
          Affected versions (optional)
          <input name="affected" placeholder="<1.121.0   or   >=7.0, <7.2.5" maxLength={100} style={control} />
        </label>
        <label style={label}>
          Title (optional)
          <input name="title" placeholder="n8n unauthenticated RCE" maxLength={200} style={control} />
        </label>
        <label style={label}>
          Advisory link (optional)
          <input name="reference" type="url" placeholder="https://…" maxLength={500} style={control} />
        </label>
      </div>
      <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'center', flexWrap: 'wrap' }}>
        <button
          type="submit"
          className="vs-button"
          data-variant="primary"
          disabled={pending || !editable}
          aria-busy={pending || undefined}
          style={{
            border: '1px solid var(--accent)',
            borderRadius: 'var(--radius-md)',
            background: 'var(--accent)',
            color: 'var(--accent-fg)',
            fontSize: 'var(--text-xs)',
            fontWeight: 600,
            padding: '0 var(--space-4)',
            height: 'var(--row-default)',
            cursor: pending || !editable ? 'not-allowed' : 'pointer',
            opacity: pending || !editable ? 0.6 : 1,
          }}
        >
          {pending ? 'Matching…' : 'Am I affected?'}
        </button>
        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          {editable
            ? 'Answers from stored scan results. No system is contacted.'
            : 'Running a brief needs an editor or admin role.'}
        </span>
        {state && !state.ok && (
          <span role="alert" style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
            {state.message}
          </span>
        )}
      </div>
    </form>
  );
}
