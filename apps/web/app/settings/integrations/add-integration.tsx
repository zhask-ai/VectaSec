'use client';

import { useActionState, useEffect, useRef, useState } from 'react';

import { INTEGRATION_TYPES, integrationSpecFor } from './integration-fields';
import { addIntegrationAction, type ActionState } from './actions';

/* The add-integration form. Same construction as connections/add-connection, including the
 * React 19 quirk it exists to dodge: the submitted `type` is a hidden input bound to the SAME
 * state that decides which config fields render — never the radio group's DOM state, which
 * React resets after the action runs and which could then disagree with the fields on screen
 * (submitting slack's type with jira's cfg_ keys). One source of truth.
 *
 * Secret fields are password inputs, autocomplete off, cleared (not echoed) after any submit. */

export function AddIntegration() {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(addIntegrationAction, null);
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<string>(INTEGRATION_TYPES[0].type);
  const formRef = useRef<HTMLFormElement>(null);

  // Collapse on success; revalidatePath has already refreshed the list under us.
  useEffect(() => {
    if (state?.ok) {
      setOpen(false);
      formRef.current?.reset();
    }
  }, [state]);

  const spec = integrationSpecFor(type) ?? INTEGRATION_TYPES[0];

  if (!open) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-2)', justifyItems: 'start' }}>
        <button type="button" onClick={() => setOpen(true)} style={primaryButtonStyle}>
          + Add an integration
        </button>
        <Result state={state} />
      </div>
    );
  }

  return (
    <form ref={formRef} action={formAction} style={{ display: 'grid', gap: 'var(--space-3)', maxWidth: 560 }}>
      <input type="hidden" name="type" value={type} />

      <fieldset style={{ border: 0, margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
        <legend style={labelStyle}>Where should findings go?</legend>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
          {INTEGRATION_TYPES.map((c) => {
            const selected = c.type === type;
            return (
              <label
                key={c.type}
                style={{
                  display: 'grid',
                  gap: '2px',
                  padding: 'var(--space-3)',
                  border: `1px solid ${selected ? 'var(--text-secondary)' : 'var(--border-interactive)'}`,
                  borderRadius: 'var(--radius-md)',
                  background: selected ? 'var(--surface-raised)' : 'var(--surface)',
                  cursor: 'pointer',
                }}
              >
                {/* Unnamed on purpose: purely the visual/a11y control; the hidden input submits. */}
                <input
                  type="radio"
                  name="type_picker"
                  value={c.type}
                  checked={selected}
                  onChange={() => setType(c.type)}
                  style={{ position: 'absolute', opacity: 0, pointerEvents: 'none' }}
                />
                <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
                  <span aria-hidden="true" style={{ marginRight: 'var(--space-1)', color: 'var(--text-secondary)' }}>{c.glyph}</span>
                  {c.label}
                </span>
                <span style={{ fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
                  {c.blurb}
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>

      <div style={{ display: 'grid', gap: 'var(--space-1)' }}>
        <label htmlFor="integration-name" style={labelStyle}>
          Name
        </label>
        <input
          id="integration-name"
          name="name"
          required
          maxLength={120}
          placeholder={`e.g. ${spec.type}-secops`}
          autoComplete="off"
          style={inputStyle}
        />
        <Hint>How this destination appears in routing rules.</Hint>
      </div>

      {/* key= remounts the block on type change so a Slack URL never lingers in a Jira form. */}
      <div key={spec.type} style={{ display: 'grid', gap: 'var(--space-3)' }}>
        {spec.fields.map((f) => (
          <div key={f.key} style={{ display: 'grid', gap: 'var(--space-1)' }}>
            <label htmlFor={`icfg-${f.key}`} style={labelStyle}>
              {f.label}
              {!f.required && <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}> — optional</span>}
            </label>
            {/* Secret fields are never HTML-required: on a re-save of an existing integration
                (upsert on type+name) an empty secret means "keep the stored one" — the engine
                enforces presence on a genuine create and its message is shown verbatim. */}
            <input
              id={`icfg-${f.key}`}
              name={`cfg_${f.key}`}
              type={f.secret ? 'password' : 'text'}
              required={f.required && !f.secret}
              placeholder={f.placeholder}
              autoComplete={f.secret ? 'new-password' : 'off'}
              spellCheck={false}
              style={inputStyle}
            />
            {f.help && <Hint>{f.help}</Hint>}
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        <button type="submit" disabled={pending} aria-busy={pending || undefined} style={{ ...primaryButtonStyle, opacity: pending ? 0.55 : 1 }}>
          {pending ? 'Adding…' : `Add ${spec.label}`}
        </button>
        <button type="button" onClick={() => setOpen(false)} style={buttonStyle}>
          Cancel
        </button>
      </div>

      <Hint>
        Secrets are stored server-side and are never shown again in this console — not in the list,
        not after a failed submit.
      </Hint>
      <Result state={state} />
    </form>
  );
}

/* ── Primitives (tokens only) ─────────────────────────────────────────────── */

const inputStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  padding: '0 var(--space-2)',
  height: 'var(--row-default)',
  width: '100%',
};

const buttonStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--surface-raised)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  fontWeight: 500,
  padding: '0 var(--space-3)',
  height: 'var(--row-compact)',
  cursor: 'pointer',
  whiteSpace: 'nowrap',
};

const primaryButtonStyle: React.CSSProperties = {
  ...buttonStyle,
  height: 'var(--row-default)',
  fontWeight: 600,
};

const labelStyle: React.CSSProperties = {
  fontSize: 'var(--text-2xs)',
  fontWeight: 600,
  letterSpacing: '0.04em',
  textTransform: 'uppercase',
  color: 'var(--text-secondary)',
};

function Hint({ children }: { children: React.ReactNode }) {
  return (
    <p style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
      {children}
    </p>
  );
}

function Result({ state }: { state: ActionState }) {
  if (!state) return null;
  return (
    <p
      role="status"
      style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}
    >
      {state.ok ? '' : 'Not applied — '}
      {state.message}
    </p>
  );
}
