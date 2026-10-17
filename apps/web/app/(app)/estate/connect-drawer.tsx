'use client';

import { useActionState, useEffect, useMemo, useRef, useState } from 'react';

import { Drawer } from '@/components/ui/drawer';
import { IconSearch } from '@/components/ui/icons';
import { CONNECTORS, specFor, type ConnectorSpec } from './connector-fields';
import { CARD_OF, SHELF, SWEEP_TYPE, onShelf } from './shelf';
import { addConnectionAction, type ActionState } from './actions';

/* The connect flow — the reason this console exists ends up flowing through here: pick a
 * system, say how to reach it, get a scan queued.
 *
 * THIS IS A DRAWER, AND IT IS TWO STEPS, because the registry has 39 connectors. The previous
 * version expanded all of them as cards inline at the FOOT of the connections page, so connecting
 * anything meant: scroll past the table, click, scroll past 39 cards, then scroll again to the
 * fields. Depth beats length here — the twelve-card SHELF (estate/shelf.ts) first, everything
 * else under an "Enterprise, on request" toggle, then only the chosen connector's fields. Search
 * spans both tiers, so an operator who knows they run Solace is never told it is unsupported.
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
      <button type="button" onClick={() => setOpen(true)} className="vs-button" data-variant="primary" style={primaryButtonStyle}>
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
                  className="vs-button"
                  data-variant="primary"
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
  const [enterprise, setEnterprise] = useState(false);
  // A multi-type card (Kafka → Apache Kafka / Confluent / Redpanda) opens its variants inline
  // rather than guessing; a single-type card picks straight away.
  const [expanded, setExpanded] = useState<string | null>(null);

  const byType = useMemo(() => new Map(CONNECTORS.map((c) => [c.type, c])), []);
  const shelfCards = useMemo(() => SHELF.filter((card) => card.types.some((t) => byType.has(t))), [byType]);
  const enterpriseSpecs = useMemo(
    () => CONNECTORS.filter((c) => !onShelf(c.type) && c.type !== SWEEP_TYPE).sort((a, b) => a.label.localeCompare(b.label)),
    [],
  );
  const sweep = byType.get(SWEEP_TYPE) ?? null;

  // Search spans BOTH tiers — the tier is a default, not a capability claim. Matching includes
  // the blurb, so "queue" finds the brokers even though none of them are called that.
  const needle = q.trim().toLowerCase();
  const matches = useMemo(() => {
    if (!needle) return null;
    return [...CONNECTORS]
      .sort((a, b) => a.label.localeCompare(b.label))
      .filter((c) => `${c.label} ${c.type} ${c.blurb} ${CARD_OF[c.type]?.label ?? ''}`.toLowerCase().includes(needle));
  }, [needle]);

  function pickType(type: string) {
    const spec = byType.get(type);
    if (spec) onPick(spec);
  }

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
          placeholder={`Search all ${CONNECTORS.length} connectors…`}
          aria-label="Search connectors"
          autoFocus
          style={{ ...inputStyle, paddingLeft: 30 }}
        />
      </div>

      {matches ? (
        matches.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            No connector matches “{q}”. VectaSec assesses the integration layer — brokers, gateways,
            iPaaS and MCP servers. If yours is missing, the catalogue on “What we can assess” names what
            is not supported yet.
          </p>
        ) : (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-1)' }}>
            {matches.map((c) => (
              <li key={c.type}>
                <SpecRow spec={c} onPick={() => onPick(c)} tier={onShelf(c.type) ? null : c.type === SWEEP_TYPE ? 'sweep' : 'enterprise'} />
              </li>
            ))}
          </ul>
        )
      ) : (
        <>
          {/* Tier 1 — the shelf. */}
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-1)' }}>
            {shelfCards.map((card) => {
              const single = card.types.length === 1 ? byType.get(card.types[0]) : null;
              const open = expanded === card.id;
              return (
                <li key={card.id}>
                  <button
                    type="button"
                    onClick={() => (single ? onPick(single) : setExpanded(open ? null : card.id))}
                    aria-expanded={single ? undefined : open}
                    style={pickRowStyle}
                  >
                    <span style={{ display: 'grid', gap: 2, minWidth: 0 }}>
                      <span style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)' }}>
                        <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>{card.label}</span>
                        <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>
                          {card.types.reduce((n, t) => n + (byType.get(t)?.rules ?? 0), 0)} checks
                        </span>
                      </span>
                      <span style={{ fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>{card.blurb}</span>
                    </span>
                    <span aria-hidden="true" style={{ color: 'var(--text-muted)', flexShrink: 0 }}>
                      {single ? '→' : open ? '▾' : '▸'}
                    </span>
                  </button>
                  {!single && open && (
                    <ul style={{ listStyle: 'none', margin: 'var(--space-1) 0 0 var(--space-4)', padding: 0, display: 'grid', gap: 'var(--space-1)' }}>
                      {card.types.map((t) => {
                        const spec = byType.get(t);
                        return spec ? (
                          <li key={t}>
                            <SpecRow spec={spec} onPick={() => pickType(t)} tier={null} />
                          </li>
                        ) : null;
                      })}
                      {card.note && (
                        <li style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', padding: '0 var(--space-2)' }}>{card.note}</li>
                      )}
                    </ul>
                  )}
                </li>
              );
            })}
          </ul>

          {/* The free external scan — not a system, so not a tier. */}
          {sweep && (
            <SpecRow spec={sweep} onPick={() => onPick(sweep)} tier="sweep" />
          )}

          {/* Tier 2 — everything else the engine supports, on request. */}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
            <button
              type="button"
              onClick={() => setEnterprise((v) => !v)}
              aria-expanded={enterprise}
              style={{ ...buttonStyle, width: '100%', justifyContent: 'space-between', display: 'flex', alignItems: 'center' }}
            >
              <span>
                Enterprise, on request
                <span data-numeric style={{ marginLeft: 'var(--space-2)', fontWeight: 400, color: 'var(--text-muted)' }}>
                  {enterpriseSpecs.length} more connectors
                </span>
              </span>
              <span aria-hidden="true" style={{ color: 'var(--text-muted)' }}>{enterprise ? '▾' : '▸'}</span>
            </button>
            {enterprise && (
              <>
                <p style={{ margin: 'var(--space-2) 0', fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>
                  Fully supported and scanned the same way — IBM MQ, Solace, MuleSoft, Boomi, Workato, Vault,
                  Keycloak, NATS, Pulsar and the rest. They are off the shelf only because most teams new to
                  cloud do not run them.
                </p>
                <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-1)' }}>
                  {enterpriseSpecs.map((c) => (
                    <li key={c.type}>
                      <SpecRow spec={c} onPick={() => onPick(c)} tier={null} />
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        </>
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

/** One connector as a pick row: label, check count, blurb, and — when it matters — which tier
 * it came from, so a search hit from the enterprise tier says so. */
function SpecRow({ spec, onPick, tier }: { spec: ConnectorSpec; onPick: () => void; tier: 'enterprise' | 'sweep' | null }) {
  return (
    <button type="button" onClick={onPick} style={pickRowStyle}>
      <span style={{ display: 'grid', gap: 2, minWidth: 0 }}>
        <span style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>{spec.label}</span>
          <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>{spec.rules} checks</span>
          {tier === 'enterprise' && (
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>· enterprise, on request</span>
          )}
          {tier === 'sweep' && (
            <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>· free external scan, no credentials</span>
          )}
        </span>
        <span style={{ fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: 'var(--text-secondary)' }}>{spec.blurb}</span>
      </span>
      <span aria-hidden="true" style={{ color: 'var(--text-muted)', flexShrink: 0 }}>→</span>
    </button>
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
  borderColor: 'var(--accent)',
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
