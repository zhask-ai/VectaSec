'use client';

import { useActionState, useEffect, useMemo, useRef, useState } from 'react';

import { Drawer } from '@/components/ui/drawer';
import { IconSearch } from '@/components/ui/icons';
import { CONNECTORS, specFor, type ConnectorSpec } from './connector-fields';
import { addConnectionAction, type ActionState } from './actions';

/* The connect flow — the reason this console exists ends up flowing through here: pick a
 * system, say how to reach it, get a scan queued.
 *
 * THIS IS A DRAWER, AND IT IS TWO STEPS, because the registry has 37 connectors. The previous
 * version expanded all 37 as cards inline at the FOOT of the connections page, so connecting
 * anything meant: scroll past the table, click, scroll past 37 cards, then scroll again to the
 * fields. Depth beats length here — a searchable list, then only the chosen connector's fields.
 * The trigger lives in the page header, so the entry point never moves as the table grows.
 *
 * A <form> around a Server Action (works without JS, re-verifies server-side). Nothing is
 * optimistic: the engine validates the config against the connector's declared fields and is
 * the only thing that knows whether the connection was written.
 *
 * Credentials: secret fields are password inputs with autocomplete off. They are POSTed to the
 * Server Action over the app origin and forwarded server-side to the engine — they never touch
 * Supabase from the browser and are never echoed back after a failed submit.
 */

const FORM_ID = 'vs-connect-form';

export function ConnectDrawer({ label = '+ Connect a system' }: { label?: string }) {
  const [open, setOpen] = useState(false);
  const [picked, setPicked] = useState<ConnectorSpec | null>(null);
  const [state, formAction, pending] = useActionState<ActionState, FormData>(addConnectionAction, null);
  const formRef = useRef<HTMLFormElement>(null);

  // Collapse on success; the action's revalidatePath has already refreshed the table under us.
  useEffect(() => {
    if (state?.ok) {
      setOpen(false);
      setPicked(null);
      formRef.current?.reset();
    }
  }, [state]);

  function close() {
    setOpen(false);
    setPicked(null);
  }

  return (
    <>
      <button type="button" onClick={() => setOpen(true)} style={primaryButtonStyle}>
        {label}
      </button>

      {/* The failure message belongs beside the trigger too: the drawer stays open on error,
          but if the user closed it the result must not vanish silently. */}
      {!open && state && !state.ok && (
        <span role="status" style={{ fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
          Not applied — {state.message}
        </span>
      )}

      <Drawer
        open={open}
        onClose={close}
        width={520}
        title={picked ? `Connect ${picked.label}` : 'Connect a system'}
        description={
          picked
            ? picked.blurb
            : `VectaSec reads configuration only — it never writes to the target. ${CONNECTORS.length} connectors available.`
        }
        footer={
          // width:100% so "Change system" sits left against the drawer footer's flex-end.
          picked ? (
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
              <button type="button" onClick={() => setPicked(null)} style={buttonStyle}>
                ← Change system
              </button>
              <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
                <button type="button" onClick={close} style={buttonStyle}>
                  Cancel
                </button>
                {/* form= reaches the <form> across the DOM, so the primary action can live in
                    the drawer's sticky footer instead of scrolling away with the fields. */}
                <button
                  type="submit"
                  form={FORM_ID}
                  disabled={pending}
                  aria-busy={pending || undefined}
                  style={{ ...primaryButtonStyle, opacity: pending ? 0.55 : 1 }}
                >
                  {pending ? 'Connecting…' : `Connect ${picked.label}`}
                </button>
              </div>
            </div>
          ) : null
        }
      >
        {picked ? (
          <ConfigStep spec={picked} formAction={formAction} formRef={formRef} state={state} />
        ) : (
          <PickStep onPick={setPicked} />
        )}
      </Drawer>
    </>
  );
}

/* ── Step 1: pick a connector ──────────────────────────────────────────────────────────── */

function PickStep({ onPick }: { onPick: (s: ConnectorSpec) => void }) {
  const [q, setQ] = useState('');

  // Search is the primary affordance at 37 items; the list is alphabetical so an unsearched
  // scan is at least predictable. Matching includes the blurb, so "queue" finds the brokers
  // even though none of them are called that.
  const matches = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const all = [...CONNECTORS].sort((a, b) => a.label.localeCompare(b.label));
    if (!needle) return all;
    return all.filter((c) =>
      `${c.label} ${c.type} ${c.blurb}`.toLowerCase().includes(needle),
    );
  }, [q]);

  return (
    <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
      <div style={{ position: 'relative' }}>
        <span
          aria-hidden="true"
          style={{
            position: 'absolute',
            left: 'var(--space-2)',
            top: '50%',
            transform: 'translateY(-50%)',
            display: 'inline-flex',
            color: 'var(--text-muted)',
          }}
        >
          <IconSearch size={14} />
        </span>
        <input
          type="search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={`Search ${CONNECTORS.length} connectors…`}
          aria-label="Search connectors"
          autoFocus
          style={{ ...inputStyle, paddingLeft: 30 }}
        />
      </div>

      {matches.length === 0 ? (
        <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
          No connector matches “{q}”. VectaSec assesses the integration layer — brokers, gateways,
          iPaaS and MCP servers. If yours is missing, the roadmap on Coverage names what is not
          supported yet.
        </p>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-1)' }}>
          {matches.map((c) => (
            <li key={c.type}>
              <button type="button" onClick={() => onPick(c)} style={pickRowStyle}>
                <span style={{ display: 'grid', gap: 2, minWidth: 0 }}>
                  <span style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
                    <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
                      {c.label}
                    </span>
                    <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                      {c.rules} checks
                    </span>
                  </span>
                  <span
                    style={{
                      fontSize: 'var(--text-2xs)',
                      lineHeight: 'var(--leading-2xs)',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {c.blurb}
                  </span>
                </span>
                <span aria-hidden="true" style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
                  →
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      <details>
        <summary style={{ cursor: 'pointer', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
          Prefer the CLI?
        </summary>
        <div style={{ marginTop: 'var(--space-2)' }}>
          <ConnectSnippet />
        </div>
      </details>
    </div>
  );
}

/* ── Step 2: the chosen connector's fields ─────────────────────────────────────────────── */

function ConfigStep({
  spec,
  formAction,
  formRef,
  state,
}: {
  spec: ConnectorSpec;
  formAction: (payload: FormData) => void;
  formRef: React.RefObject<HTMLFormElement | null>;
  state: ActionState;
}) {
  return (
    <form id={FORM_ID} ref={formRef} action={formAction} style={{ display: 'grid', gap: 'var(--space-3)' }}>
      {/* The submitted type is THIS hidden input — bound to the same state that decides which
          config fields render — never a DOM read. React 19 resets a form's DOM after its action
          runs, and a DOM-read type could then disagree with the fields on screen. */}
      <input type="hidden" name="type" value={spec.type} />

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
          autoFocus
          style={inputStyle}
        />
        <Hint>How this system appears everywhere in VectaSec.</Hint>
      </div>

      {/* Per-connector fields, straight from the spec. key= remounts the block on type change so
          a Kafka bootstrap never lingers in a RabbitMQ form. */}
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

      <Hint>
        Read-only: VectaSec inspects configuration and never writes to the target. Credentials are
        stored server-side and are not readable from this browser session afterwards.
      </Hint>

      {state && !state.ok && (
        <p
          role="status"
          style={{
            margin: 0,
            padding: 'var(--space-2) var(--space-3)',
            borderRadius: 'var(--radius-md)',
            background: 'var(--sev-critical-bg)',
            border: '1px solid var(--sev-critical-fg)',
            fontSize: 'var(--text-2xs)',
            lineHeight: 'var(--leading-2xs)',
            color: 'var(--sev-critical-fg)',
          }}
        >
          Not applied — {state.message}
        </p>
      )}
    </form>
  );
}

/** The CLI path — same result as the form, from wherever the target is reachable. Kept for
 * operators whose broker is only reachable from a bastion the browser isn't on. */
function ConnectSnippet() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        Run the engine CLI where the system is reachable. It reads; it never writes to the target.
      </p>
      <pre
        style={{
          margin: 0,
          padding: 'var(--space-3)',
          background: 'var(--bg)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-md)',
          fontFamily: 'var(--font-mono)',
          fontSize: 'var(--text-2xs)',
          lineHeight: 'var(--leading-sm)',
          color: 'var(--text-primary)',
          overflowX: 'auto',
        }}
      >
        <span style={{ color: 'var(--text-muted)' }}># save a connection, then scan it by name</span>
        {'\n'}vectasec connections add --type kafka --name prod-kafka --bootstrap broker-1:9092
        {'\n'}vectasec scan --connection prod-kafka
      </pre>
    </div>
  );
}

/* ── Primitives (tokens only) ──────────────────────────────────────────────────────────── */

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
  background: 'var(--accent)',
  color: 'var(--accent-fg)',
  borderColor: 'var(--border-interactive)',
};

const pickRowStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: 'var(--space-3)',
  width: '100%',
  textAlign: 'left',
  padding: 'var(--space-3)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--surface)',
  cursor: 'pointer',
  font: 'inherit',
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
