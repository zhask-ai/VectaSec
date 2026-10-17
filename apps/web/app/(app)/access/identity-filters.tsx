'use client';

import { usePathname, useRouter } from 'next/navigation';
import type { Route } from 'next';
import type { CSSProperties, ReactNode } from 'react';

/* Inventory filters. Filter state lives in the URL (DESIGN §5: searchParams, not useState, so a
 * filtered view is shareable) — this island only writes to it. It receives the current values and
 * the option lists as plain props; no function crosses the server boundary. The server reads the
 * same params and does the filtering, so the URL is the single source of truth.
 */

const WILDCARD_OPTIONS = [
  { value: '', label: 'All grants' },
  { value: 'only', label: 'Wildcard-granted only' },
];

const SENSITIVITY_OPTIONS = [
  { value: '', label: 'Any' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
];

const SEEN_OPTIONS = [
  { value: '', label: 'Any' },
  { value: 'dormant', label: 'Dormant 90d+ or never used' },
  { value: 'seen', label: 'Seen recently' },
  { value: 'unknown', label: 'No last-used signal' },
];

type FilterState = { system: string; type: string; wildcard: string; sensitivity: string; seen: string };

export function IdentityFilters({
  systems,
  types,
  system,
  type,
  wildcard,
  sensitivity,
  seen,
}: {
  systems: string[];
  types: string[];
  system: string;
  type: string;
  wildcard: string;
  sensitivity: string;
  seen: string;
}) {
  const router = useRouter();
  const pathname = usePathname();

  function hrefFor(overrides: Partial<FilterState>): Route {
    const merged: FilterState = { system, type, wildcard, sensitivity, seen, ...overrides };
    const next = new URLSearchParams();
    if (merged.system) next.set('system', merged.system);
    if (merged.type) next.set('type', merged.type);
    if (merged.wildcard) next.set('wildcard', merged.wildcard);
    if (merged.sensitivity) next.set('sensitivity', merged.sensitivity);
    if (merged.seen) next.set('seen', merged.seen);
    const qs = next.toString();
    return (qs ? `${pathname}?${qs}` : pathname) as Route;
  }

  const active = Boolean(system || type || wildcard || sensitivity || seen);

  return (
    <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
      <Field label="System">
        <select value={system} onChange={(e) => router.push(hrefFor({ system: e.target.value }))} style={selectStyle} aria-label="Filter by system">
          <option value="">All systems</option>
          {systems.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </Field>

      <Field label="Identity type">
        <select value={type} onChange={(e) => router.push(hrefFor({ type: e.target.value }))} style={selectStyle} aria-label="Filter by identity type">
          <option value="">All types</option>
          {types.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </Field>

      <Field label="Grants">
        <select value={wildcard} onChange={(e) => router.push(hrefFor({ wildcard: e.target.value }))} style={selectStyle} aria-label="Filter by wildcard grants">
          {WILDCARD_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </Field>

      <Field label="Sensitive data">
        <select value={sensitivity} onChange={(e) => router.push(hrefFor({ sensitivity: e.target.value }))} style={selectStyle} aria-label="Filter by inferred data sensitivity of what the identity reaches">
          {SENSITIVITY_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </Field>

      <Field label="Last seen">
        <select value={seen} onChange={(e) => router.push(hrefFor({ seen: e.target.value }))} style={selectStyle} aria-label="Filter by last-seen state">
          {SEEN_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>
      </Field>

      {active && (
        <button type="button" onClick={() => router.push(hrefFor({ system: '', type: '', wildcard: '', sensitivity: '', seen: '' }))} style={clearStyle}>
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
