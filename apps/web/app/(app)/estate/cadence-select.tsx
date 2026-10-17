'use client';

import { useActionState } from 'react';

import { setCadenceAction, type ActionState } from './actions';

/* The recurring-scan cadence control, living in the Last scan cell. A <form> around a Server
 * Action like every other mutation here: works without JS, re-verifies role and row ownership
 * server-side, nothing optimistic — the engine owns the write and the page re-renders from the
 * revalidated read.
 *
 * Visually it is now a quiet chip-select that AUTO-SUBMITS on change (the tenant switcher's
 * pattern) — the old select + "Set" button pair took two clicks and a full control row for a
 * setting most rows never touch. A hidden submit keeps the no-JS path posting.
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
      style={{ display: 'flex', gap: 'var(--space-1)', alignItems: 'center', flexWrap: 'wrap', marginTop: 2 }}
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
        className="vs-chipselect"
        onChange={(e) => e.currentTarget.form?.requestSubmit()}
      >
        {CHOICES.map((c) => (
          <option key={c.value} value={c.value}>
            {c.value === 'off' ? 'rescan: off' : `rescan ${c.label}`}
          </option>
        ))}
      </select>
      {/* No-JS fallback: without an onChange runtime this is the only way to post. Hidden from
          pointer users (the select submits itself), visible to keyboard flows via focus. */}
      <noscript>
        <button type="submit" className="vs-actionbtn">
          Set
        </button>
      </noscript>
      {pending && (
        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }} aria-live="polite">
          Saving…
        </span>
      )}
      {state && !pending && !state.ok && (
        <span
          role="status"
          style={{
            flexBasis: '100%',
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            color: 'var(--sev-critical-fg)',
          }}
        >
          {state.message}
        </span>
      )}
    </form>
  );
}
