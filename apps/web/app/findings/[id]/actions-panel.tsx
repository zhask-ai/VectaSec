'use client';

import { useActionState, useState } from 'react';

import type { UiStatus } from '@/lib/types';
import {
  assignAction,
  setStatusAction,
  suppressAction,
  triageAction,
  type ActionState,
} from '../actions';

/* Actions.
 *
 * Every one is a <form> around a Server Action, so each works without JavaScript and each
 * re-verifies the caller server-side (see actions.ts — proxy coverage proves nothing about a
 * direct POST). useActionState gives the pending state and the result message; nothing here is
 * optimistic, because the engine is the only thing that knows whether the write landed and
 * showing "Resolved" for a change that never committed is the one lie a security console
 * cannot afford.
 *
 * The engine may be unreachable. That is a normal state, not an exception: findings, evidence
 * and triage all come from Supabase and are unaffected, so a failure here says so and the page
 * keeps working.
 */

const STATUS_CHOICES: { value: string; label: string; hint: string }[] = [
  { value: 'open', label: 'Open', hint: 'Nobody has looked at this yet.' },
  { value: 'triaged', label: 'Triaged', hint: 'Assessed, not yet being worked.' },
  { value: 'in_progress', label: 'In progress', hint: 'Someone is fixing it now.' },
  { value: 'resolved', label: 'Resolved', hint: 'Fixed. Verify with a re-scan.' },
  { value: 'accepted', label: 'Accepted', hint: 'Known and deliberately not being fixed.' },
];

export function ActionsPanel({
  findingId,
  status,
  assignee,
  currentUserId,
  resourceKind,
  resourceName,
  ruleId,
}: {
  findingId: string;
  status: UiStatus;
  assignee: string | null;
  currentUserId: string | null;
  resourceKind: string | null;
  resourceName: string | null;
  ruleId: string;
}) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-5)' }}>
      <StatusForm findingId={findingId} status={status} />
      <AssignForm findingId={findingId} assignee={assignee} currentUserId={currentUserId} />
      <SuppressForm
        findingId={findingId}
        ruleId={ruleId}
        resourceKind={resourceKind}
        resourceName={resourceName}
      />
    </div>
  );
}

function StatusForm({ findingId, status }: { findingId: string; status: UiStatus }) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(setStatusAction, null);
  const [choice, setChoice] = useState<string>(status === 'muted' ? 'accepted' : status === 'in_progress' ? 'in_progress' : status);

  return (
    <form action={formAction} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <input type="hidden" name="findingId" value={findingId} />
      <SectionLabel htmlFor="status-select">Status</SectionLabel>

      <select
        id="status-select"
        name="status"
        value={choice}
        onChange={(e) => setChoice(e.target.value)}
        style={selectStyle}
      >
        {STATUS_CHOICES.map((s) => (
          <option key={s.value} value={s.value}>
            {s.label}
          </option>
        ))}
      </select>
      <Hint>{STATUS_CHOICES.find((s) => s.value === choice)?.hint}</Hint>

      <label htmlFor="status-note" className="vs-visually-hidden">
        Note explaining this status change
      </label>
      <textarea
        id="status-note"
        name="note"
        rows={2}
        placeholder="Why (optional) — goes to the audit log"
        style={{ ...selectStyle, height: 'auto', padding: 'var(--space-2)', resize: 'vertical', fontFamily: 'inherit' }}
      />
      {/* The note lives only in audit_log: it explains a state CHANGE, so a column on findings
          would be overwritten by the next one. Saying where it goes is what makes people write
          a useful one. */}

      <Button pending={pending}>Update status</Button>
      <Result state={state} />
    </form>
  );
}

function AssignForm({
  findingId,
  assignee,
  currentUserId,
}: {
  findingId: string;
  assignee: string | null;
  currentUserId: string | null;
}) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(assignAction, null);
  const mine = assignee !== null && assignee === currentUserId;

  return (
    <form action={formAction} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <input type="hidden" name="findingId" value={findingId} />
      <SectionLabel>Assignee</SectionLabel>

      <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        {assignee === null ? 'Unassigned' : mine ? 'You' : <code style={{ fontSize: 'var(--text-2xs)' }}>{assignee}</code>}
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <Button pending={pending} name="intent" value="me" disabled={mine}>
          Assign to me
        </Button>
        <Button pending={pending} name="intent" value="none" disabled={assignee === null}>
          Unassign
        </Button>
      </div>

      {/* Honest about a real limit rather than shipping a picker that lists uuids: tenant_members
          is readable only for your OWN row (RLS: user_id = auth.uid()) and the schema has no
          display names anywhere, so there is nothing to pick from yet. */}
      <Hint>Assigning to a colleague needs a user directory the schema does not have yet.</Hint>
      <Result state={state} />
    </form>
  );
}

function SuppressForm({
  findingId,
  ruleId,
  resourceKind,
  resourceName,
}: {
  findingId: string;
  ruleId: string;
  resourceKind: string | null;
  resourceName: string | null;
}) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(suppressAction, null);
  const [open, setOpen] = useState(false);
  const [expires, setExpires] = useState('90');

  if (!open) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
        <SectionLabel>Suppress</SectionLabel>
        <Button pending={false} onClick={() => setOpen(true)} type="button">
          Suppress this rule…
        </Button>
        <Hint>Requires a reason. Muted is a view, not a void — suppressed findings stay visible under the Muted filter.</Hint>
      </div>
    );
  }

  return (
    <form action={formAction} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <input type="hidden" name="findingId" value={findingId} />
      <SectionLabel htmlFor="suppress-scope">Suppress {ruleId}</SectionLabel>

      {/* Only these three scopes exist because they are the only ones the scanner matches:
          {} tenant-wide, {ext_id}, or {kind} (scan.py `_is_suppressed`). Offering a scope the
          scanner cannot match would create a suppression the user believes is in force. */}
      <select id="suppress-scope" name="scope" defaultValue="resource" style={selectStyle}>
        <option value="resource" disabled={!resourceName}>
          This resource only{resourceName ? ` (${resourceName})` : ' — none on this finding'}
        </option>
        <option value="kind" disabled={!resourceKind}>
          Every {resourceKind ?? 'resource'} in this tenant
        </option>
        <option value="tenant">Everywhere in this tenant</option>
      </select>

      <label htmlFor="suppress-reason" className="vs-visually-hidden">
        Reason for suppressing
      </label>
      <textarea
        id="suppress-reason"
        name="reason"
        rows={3}
        required
        placeholder="Why is this acceptable? The next analyst will read this."
        style={{ ...selectStyle, height: 'auto', padding: 'var(--space-2)', resize: 'vertical', fontFamily: 'inherit' }}
      />

      <label htmlFor="suppress-expires" className="vs-visually-hidden">
        Expires after
      </label>
      <select
        id="suppress-expires"
        name="expires"
        value={expires}
        onChange={(e) => setExpires(e.target.value)}
        style={selectStyle}
      >
        <option value="30">Expires in 30 days</option>
        <option value="60">Expires in 60 days</option>
        <option value="90">Expires in 90 days</option>
        {/* Permanent mutes are how a posture tool rots into theatre. "Never" stays available —
            hiding it would just push people to 90-day mutes they renew forever — but it is last,
            labelled, and never the default. */}
        <option value="never">Never expires — not recommended</option>
      </select>
      {expires === 'never' && (
        <Hint tone="warn">
          A permanent suppression is never reviewed again unless someone goes looking for it.
        </Hint>
      )}

      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        <Button pending={pending}>Create suppression</Button>
        <Button pending={false} type="button" onClick={() => setOpen(false)}>
          Cancel
        </Button>
      </div>
      <Hint>Applies at the next scan — this finding keeps its current status until then.</Hint>
      <Result state={state} />
    </form>
  );
}

/** Generate the triage. Separate from ActionsPanel because it belongs next to the (absent) AI
 * section, not in the actions rail. */
export function TriageButton({ findingId, disabled }: { findingId: string; disabled?: boolean }) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(triageAction, null);

  return (
    <form action={formAction} style={{ display: 'grid', gap: 'var(--space-2)', justifyItems: 'start' }}>
      <input type="hidden" name="findingId" value={findingId} />
      <Button pending={pending} disabled={disabled}>
        {pending ? 'Triaging…' : 'Run AI triage'}
      </Button>
      <Result state={state} />
    </form>
  );
}

/* ── Primitives ───────────────────────────────────────────────────────────
 * Local to the findings routes. The design system has no button or input yet, and adding one
 * from here would be another agent's component invented in the wrong file. These stay small,
 * use only tokens, and should be deleted the day components/ui grows the real thing. */

const selectStyle: React.CSSProperties = {
  // --border-interactive, not --border: for a control whose outline is its only visual
  // indicator, --border's 1.38:1 fails SC 1.4.11. globals.css flags this as the most-missed
  // bug in dark design systems.
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  padding: '0 var(--space-2)',
  height: 'var(--row-default)',
  width: '100%',
};

function SectionLabel({ children, htmlFor }: { children: React.ReactNode; htmlFor?: string }) {
  return (
    <label
      htmlFor={htmlFor}
      style={{
        fontSize: 'var(--text-2xs)',
        fontWeight: 600,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        color: 'var(--text-secondary)',
      }}
    >
      {children}
    </label>
  );
}

function Hint({ children, tone }: { children: React.ReactNode; tone?: 'warn' }) {
  return (
    <p
      style={{
        margin: 0,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        color: tone === 'warn' ? 'var(--sev-medium-fg)' : 'var(--text-secondary)',
      }}
    >
      {children}
    </p>
  );
}

function Button({
  children,
  pending,
  disabled,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { pending: boolean }) {
  return (
    <button
      {...rest}
      disabled={pending || disabled}
      aria-busy={pending || undefined}
      style={{
        border: '1px solid var(--border-interactive)',
        borderRadius: 'var(--radius-md)',
        background: 'var(--surface-raised)',
        color: 'var(--text-primary)',
        fontSize: 'var(--text-xs)',
        fontWeight: 500,
        padding: '0 var(--space-3)',
        height: 'var(--row-compact)',
        cursor: pending || disabled ? 'default' : 'pointer',
        opacity: pending || disabled ? 0.55 : 1,
        whiteSpace: 'nowrap',
      }}
    >
      {children}
    </button>
  );
}

/** role="status": the result of an action must be announced, not just coloured. */
function Result({ state }: { state: ActionState }) {
  if (!state) return null;

  return (
    <p
      role="status"
      style={{
        margin: 0,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        // --text-secondary on failure, never --text-muted: this sits on --surface-raised where
        // muted is 4.37:1 and fails.
        color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
      }}
    >
      {state.ok ? '' : 'Not applied — '}
      {state.message}
    </p>
  );
}
