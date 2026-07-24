'use client';

import { useActionState, useEffect, useRef, useState } from 'react';

import { CONNECTORS, specFor } from './connector-fields';
import { addConnectionAction, type ActionState } from './actions';

/* The connect form — the reason this console exists ends up flowing through here: pick a
 * system, say how to reach it, get a scan queued.
 *
 * A <form> around a Server Action (works without JS, re-verifies server-side). Nothing is
 * optimistic: the engine validates the config against the connector's declared fields and is
 * the only thing that knows whether the connection was written.
 *
 * Credentials: secret fields are password inputs with autocomplete off. They are POSTed to
 * the Server Action over the app origin and forwarded server-side to the engine — they never
 * touch Supabase from the browser and are never echoed back after a failed submit (the form
 * clears them like a login form would).
 */

export function AddConnection() {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(addConnectionAction, null);
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<string>(CONNECTORS[0].type);
  const formRef = useRef<HTMLFormElement>(null);

  // Collapse on success; the action's revalidatePath has already refreshed the table under us.
  useEffect(() => {
    if (state?.ok) {
      setOpen(false);
      formRef.current?.reset();
    }
  }, [state]);

  const spec = specFor(type) ?? CONNECTORS[0];

  if (!open) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-2)', justifyItems: 'start' }}>
        <button type="button" onClick={() => setOpen(true)} style={primaryButtonStyle}>
          + Connect a system
        </button>
        <Result state={state} />
      </div>
    );
  }

  return (
    <form ref={formRef} action={formAction} style={{ display: 'grid', gap: 'var(--space-3)', maxWidth: 560 }}>
      {/* The submitted type is THIS hidden input — bound to the same state that decides which
          config fields render — never the radio group's DOM state. React 19 resets a form's
          DOM after its action runs, and a DOM-read type could then disagree with the fields
          on screen (submitting kafka's type with rabbitmq's cfg_ keys). One source of truth. */}
      <input type="hidden" name="type" value={type} />

      {/* Type picker: one card per connector, the honest sentence + check count on each. */}
      <fieldset style={{ border: 0, margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
        <legend style={labelStyle}>What are you connecting?</legend>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
          {CONNECTORS.map((c) => {
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
                {/* Unnamed on purpose: purely the visual/a11y control. The hidden input above
                    is what submits. */}
                <input
                  type="radio"
                  name="type_picker"
                  value={c.type}
                  checked={selected}
                  onChange={() => setType(c.type)}
                  style={{ position: 'absolute', opacity: 0, pointerEvents: 'none' }}
                />
                <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {c.label}
                  </span>
                  <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }} data-numeric>
                    {c.rules} checks
                  </span>
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
        <label htmlFor="conn-name" style={labelStyle}>
          Name
        </label>
        <input
          id="conn-name"
          name="name"
          required
          maxLength={120}
          placeholder={`e.g. prod-${spec.type}`}
          autoComplete="off"
          style={inputStyle}
        />
        <Hint>How this system appears everywhere in VectaSec.</Hint>
      </div>

      {/* The per-connector fields, straight from the spec. key= remounts the block on type
          change so a Kafka bootstrap never lingers in a RabbitMQ form. */}
      <div key={spec.type} style={{ display: 'grid', gap: 'var(--space-3)' }}>
        {spec.fields.map((f) => (
          <div key={f.key} style={{ display: 'grid', gap: 'var(--space-1)' }}>
            <label htmlFor={`cfg-${f.key}`} style={labelStyle}>
              {f.label}
              {!f.required && (
                <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}> — optional</span>
              )}
            </label>
            <input
              id={`cfg-${f.key}`}
              name={`cfg_${f.key}`}
              type={f.secret ? 'password' : 'text'}
              required={f.required}
              placeholder={f.placeholder}
              autoComplete={f.secret ? 'new-password' : 'off'}
              spellCheck={false}
              style={inputStyle}
            />
            {f.help && <Hint>{f.help}</Hint>}
          </div>
        ))}
      </div>

      <label
        style={{
          display: 'flex',
          gap: 'var(--space-2)',
          alignItems: 'center',
          fontSize: 'var(--text-xs)',
          color: 'var(--text-primary)',
        }}
      >
        <input type="checkbox" name="scanNow" defaultChecked />
        Run the first scan as soon as it is connected
      </label>

      <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
        <button type="submit" disabled={pending} aria-busy={pending || undefined} style={{ ...primaryButtonStyle, opacity: pending ? 0.55 : 1 }}>
          {pending ? 'Connecting…' : `Connect ${spec.label}`}
        </button>
        <button type="button" onClick={() => setOpen(false)} style={buttonStyle}>
          Cancel
        </button>
      </div>

      <Hint>
        Read-only: VectaSec inspects configuration and never writes to the target. Credentials are
        stored server-side and are not readable from this browser session afterwards.
      </Hint>
      <Result state={state} />
    </form>
  );
}

/* ── Primitives (tokens only; mirror compliance/attest-control until ui/ grows these) ──── */

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
      style={{
        margin: 0,
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)',
      }}
    >
      {state.ok ? '' : 'Not applied — '}
      {state.message}
    </p>
  );
}
