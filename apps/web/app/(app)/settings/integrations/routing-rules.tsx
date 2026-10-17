'use client';

import { useActionState, useEffect, useRef } from 'react';

import { CONNECTORS } from '../../estate/connector-fields';
import { addRoutingRuleAction, deleteRoutingRuleAction, type ActionState } from './actions';

/* Routing rules — "findings at or above this severity (optionally from this connector type)
 * go to that integration". The add form and the per-rule remove, both Server-Action forms. */

const SEVERITY_CHOICES: { value: string; label: string }[] = [
  { value: 'critical', label: 'critical only' },
  { value: 'high', label: 'high and above' },
  { value: 'medium', label: 'medium and above' },
  { value: 'low', label: 'low and above' },
  { value: 'info', label: 'everything (info and above)' },
];

// Derived from the connector catalogue so a dropped-in connector is routable with no list to
// edit here — hardcoding this list once stranded 35 connector types (redis included).
const CONNECTOR_CHOICES: { value: string; label: string }[] = [
  { value: '', label: 'any connector' },
  ...[...CONNECTORS]
    .sort((a, b) => a.label.localeCompare(b.label))
    .map((c) => ({ value: c.type, label: `${c.label} only` })),
];

export function AddRoutingRule({ integrations }: { integrations: { id: string; name: string; type: string }[] }) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(addRoutingRuleAction, null);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state?.ok) formRef.current?.reset();
  }, [state]);

  if (integrations.length === 0) {
    return (
      <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
        Add an integration first — a routing rule needs a destination.
      </p>
    );
  }

  return (
    <form ref={formRef} action={formAction} style={{ display: 'grid', gap: 'var(--space-2)' }}>
      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'end' }}>
        <Labeled id="rule-severity" label="Deliver findings">
          <select id="rule-severity" name="minSeverity" defaultValue="high" style={selectStyle}>
            {SEVERITY_CHOICES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </Labeled>

        <Labeled id="rule-connector" label="From">
          <select id="rule-connector" name="connectorType" defaultValue="" style={selectStyle}>
            {CONNECTOR_CHOICES.map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        </Labeled>

        <Labeled id="rule-destination" label="To">
          <select id="rule-destination" name="integrationId" required style={selectStyle}>
            {integrations.map((i) => (
              <option key={i.id} value={i.id}>
                {i.name} ({i.type})
              </option>
            ))}
          </select>
        </Labeled>

        <button type="submit" disabled={pending} aria-busy={pending || undefined} style={{ ...btn, height: 'var(--row-default)', fontWeight: 600, opacity: pending ? 0.55 : 1 }}>
          {pending ? 'Adding…' : 'Add rule'}
        </button>
      </div>

      {/* The weekly digest rides the same routing rule: new credentials, newly exposed, newly
          unused, fixed — the five numbers on the Overview, once a week, to this destination. */}
      <label style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>
        <input type="checkbox" name="weeklyDigest" value="1" defaultChecked />
        Also send the weekly digest to this destination
      </label>

      {state && (
        <p role="status" style={{ margin: 0, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-2xs)', color: state.ok ? 'var(--text-secondary)' : 'var(--sev-critical-fg)' }}>
          {state.ok ? '' : 'Not applied — '}
          {state.message}
        </p>
      )}
    </form>
  );
}

export function RemoveRuleButton({ ruleId }: { ruleId: string }) {
  const [state, formAction, pending] = useActionState<ActionState, FormData>(deleteRoutingRuleAction, null);

  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
      <form action={formAction} style={{ display: 'contents' }}>
        <input type="hidden" name="ruleId" value={ruleId} />
        <button type="submit" disabled={pending} aria-busy={pending || undefined} style={{ ...btn, opacity: pending ? 0.55 : 1 }}>
          {pending ? 'Removing…' : 'Remove'}
        </button>
      </form>
      {state && !state.ok && (
        <p role="status" style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--sev-critical-fg)' }}>
          {state.message}
        </p>
      )}
    </div>
  );
}

function Labeled({ id, label, children }: { id: string; label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)' }}>
      <label htmlFor={id} style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
        {label}
      </label>
      {children}
    </div>
  );
}

const selectStyle: React.CSSProperties = {
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  background: 'var(--bg)',
  color: 'var(--text-primary)',
  fontSize: 'var(--text-xs)',
  padding: '0 var(--space-2)',
  height: 'var(--row-default)',
};

const btn: React.CSSProperties = {
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
};
