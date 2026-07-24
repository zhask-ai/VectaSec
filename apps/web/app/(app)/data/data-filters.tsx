'use client';

import { usePathname, useRouter } from 'next/navigation';
import type { Route } from 'next';
import type { CSSProperties, ReactNode } from 'react';

/* Inventory filters for the sensitive-data surface. Filter state lives in the URL (DESIGN §5:
 * searchParams, not useState, so a filtered view is shareable) — this island only writes to it. It
 * receives the current values and the option lists as plain props; no function crosses the server
 * boundary. The server reads the same params and does the filtering, so the URL is the single
 * source of truth.
 */

const CLASS_LABEL: Record<string, string> = {
  pci: 'PCI',
  phi: 'PHI',
  pii: 'PII',
  secrets: 'Secrets',
  financial: 'Financial',
  auth: 'Auth',
};

const SENSITIVITY_LABEL: Record<string, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export function DataFilters({
  classes,
  sensitivities,
  systems,
  dataClass,
  sensitivity,
  system,
}: {
  classes: string[];
  sensitivities: string[];
  systems: string[];
  dataClass: string;
  sensitivity: string;
  system: string;
}) {
  const router = useRouter();
  const pathname = usePathname();

  function hrefFor(overrides: Partial<{ class: string; sensitivity: string; system: string }>): Route {
    const merged = { class: dataClass, sensitivity, system, ...overrides };
    const next = new URLSearchParams();
    if (merged.class) next.set('class', merged.class);
    if (merged.sensitivity) next.set('sensitivity', merged.sensitivity);
    if (merged.system) next.set('system', merged.system);
    const qs = next.toString();
    return (qs ? `${pathname}?${qs}` : pathname) as Route;
  }

  const active = Boolean(dataClass || sensitivity || system);

  return (
    <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
      <Field label="Data class">
        <select
          value={dataClass}
          onChange={(e) => router.push(hrefFor({ class: e.target.value }))}
          style={selectStyle}
          aria-label="Filter by data class"
        >
          <option value="">All classes</option>
          {classes.map((c) => (
            <option key={c} value={c}>
              {CLASS_LABEL[c] ?? c.toUpperCase()}
            </option>
          ))}
        </select>
      </Field>

      <Field label="Sensitivity">
        <select
          value={sensitivity}
          onChange={(e) => router.push(hrefFor({ sensitivity: e.target.value }))}
          style={selectStyle}
          aria-label="Filter by sensitivity"
        >
          <option value="">All sensitivity</option>
          {sensitivities.map((s) => (
            <option key={s} value={s}>
              {SENSITIVITY_LABEL[s] ?? s}
            </option>
          ))}
        </select>
      </Field>

      <Field label="System">
        <select
          value={system}
          onChange={(e) => router.push(hrefFor({ system: e.target.value }))}
          style={selectStyle}
          aria-label="Filter by system"
        >
          <option value="">All systems</option>
          {systems.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </Field>

      {active && (
        <button type="button" onClick={() => router.push(hrefFor({ class: '', sensitivity: '', system: '' }))} style={clearStyle}>
          Clear filters
        </button>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label style={{ display: 'grid', gap: 4 }}>
      <span style={{ fontSize: 'var(--text-2xs)', fontWeight: 600, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
        {label}
      </span>
      {children}
    </label>
  );
}

const selectStyle: CSSProperties = {
  height: 'var(--row-compact)',
  padding: '0 var(--space-2)',
  minWidth: 160,
  background: 'var(--surface)',
  color: 'var(--text-primary)',
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  fontFamily: 'inherit',
  fontSize: 'var(--text-xs)',
  cursor: 'pointer',
};

const clearStyle: CSSProperties = {
  height: 'var(--row-compact)',
  padding: '0 var(--space-3)',
  background: 'transparent',
  color: 'var(--text-secondary)',
  border: '1px solid var(--border-interactive)',
  borderRadius: 'var(--radius-md)',
  fontFamily: 'inherit',
  fontSize: 'var(--text-xs)',
  cursor: 'pointer',
};
