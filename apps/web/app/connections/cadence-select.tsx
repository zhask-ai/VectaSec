'use client';

import { useActionState } from 'react';

import { setCadenceAction, type ActionState } from './actions';

/* The recurring-scan cadence control, living next to the cadence display in the Last scan
 * cell. A <form> around a Server Action like every other mutation here: works without JS,
 * re-verifies role and row ownership server-side, nothing optimistic — the engine owns the
 * write and the page re-renders from the revalidated read.
 *
 * The select is uncontrolled with defaultValue + key: after the action lands, revalidatePath
 * re-renders the row with the new `current`, and the key remounts the select so the DOM state
 * (which React 19 resets after a form action anyway) can never disagree with the database. */

const CHOICES: { value: string; label: string }[] = [
  { value: 'off', label: 'off' },
  { value: '30', label: 'every 30m' },
  { value: '60', label: 'every 1h' },
  { value: '360', label: 'every 6h' },
  { value: '1440', label: 'every 24h' },
  { value: '10080', label: 'every 7d' },
];

export function CadenceSelect({
  connectionId,
  current,
}: {
  connectionId: string;
  /** scan_interval_minutes as stored; null = point-in-time only. */
  current: number | null;
}) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(setCadenceAction, null);
  const currentValue = current === null ? 'off' : String(current);

  return (
    <form
      action={formAction}
      style={{ display: 'flex', gap: 'var(--space-1)', alignItems: 'center', flexWrap: 'wrap', marginTop: '2px' }}
    >
      <input type="hidden" name="connectionId" value={connectionId} />
      <label htmlFor={`cadence-${connectionId}`} className="vs-visually-hidden">
        Recurring scan cadence
      </label>
      <select
        id={`cadence-${connectionId}`}
        key={currentValue}
        name="interval"
        defaultValue={currentValue}
        disabled={pending}
        title="How often this connection is rescanned automatically"
        style={{
          border: '1px solid var(--border-interactive)',
          borderRadius: 'var(--radius-md)',
          background: 'var(--bg)',
          color: 'var(--text-primary)',
          fontSize: 'var(--text-2xs)',
          padding: '0 var(--space-1)',
          height: 'var(--row-compact)',
        }}
      >
        {CHOICES.map((c) => (
          <option key={c.value} value={c.value}>
            {c.value === 'off' ? 'rescan: off' : `rescan ${c.label}`}
          </option>
        ))}
      </select>
      <button
        type="submit"
        disabled={pending}
        aria-busy={pending || undefined}
        style={{
          border: '1px solid var(--border-interactive)',
          borderRadius: 'var(--radius-md)',
          background: 'var(--surface-raised)',
          color: 'var(--text-primary)',
          fontSize: 'var(--text-2xs)',
          fontWeight: 500,
          padding: '0 var(--space-2)',
          height: 'var(--row-compact)',
          cursor: 'pointer',
          whiteSpace: 'nowrap',
          opacity: pending ? 0.55 : 1,
        }}
      >
        {pending ? 'Saving…' : 'Set'}
      </button>
      {state && (
        <span
          role="status"
          style={{
            flexBasis: '100%',
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
          }}
        >
          {state.message}
        </span>
      )}
    </form>
  );
}
