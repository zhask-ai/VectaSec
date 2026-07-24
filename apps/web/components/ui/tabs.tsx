'use client';

import { useId, useState, type ReactNode } from 'react';

/* Tabs — an in-page tablist for switching between panels WITHOUT navigating (e.g. a finding's
 * Evidence / Remediation / Activity, an asset's Config / Graph). This is the local-state kind.
 *
 * It is deliberately NOT the settings tab strip: those tabs are ROUTES (each a URL you can link
 * to), and route tabs must stay <Link>s so they are shareable and server-rendered — see
 * app/settings/tabs.tsx, which this does not replace. Reach for this only when the panels are not
 * worth their own URL.
 *
 * Keyboard model follows the WAI-ARIA tabs pattern: ←/→ move focus between tabs (roving
 * tabindex), the panel is labelled by its tab, and only the active tab is in the tab order.
 */

export type TabItem = { id: string; label: ReactNode; content: ReactNode; disabled?: boolean };

export function Tabs({ items, initial, 'aria-label': ariaLabel }: { items: TabItem[]; initial?: string; 'aria-label': string }) {
  const base = useId();
  const firstEnabled = items.find((i) => !i.disabled)?.id ?? items[0]?.id;
  const [active, setActive] = useState(initial ?? firstEnabled);

  const onKeyDown = (e: React.KeyboardEvent) => {
    const enabled = items.filter((i) => !i.disabled);
    const idx = enabled.findIndex((i) => i.id === active);
    if (idx === -1) return;
    let next = idx;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (idx + 1) % enabled.length;
    else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (idx - 1 + enabled.length) % enabled.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = enabled.length - 1;
    else return;
    e.preventDefault();
    const id = enabled[next].id;
    setActive(id);
    document.getElementById(`${base}-tab-${id}`)?.focus();
  };

  return (
    <div>
      <div
        role="tablist"
        aria-label={ariaLabel}
        onKeyDown={onKeyDown}
        style={{ display: 'flex', gap: 'var(--space-1)', borderBottom: '1px solid var(--border)' }}
      >
        {items.map((item) => {
          const selected = item.id === active;
          return (
            <button
              key={item.id}
              id={`${base}-tab-${item.id}`}
              role="tab"
              type="button"
              aria-selected={selected}
              aria-controls={`${base}-panel-${item.id}`}
              tabIndex={selected ? 0 : -1}
              disabled={item.disabled}
              onClick={() => setActive(item.id)}
              style={{
                appearance: 'none',
                background: 'transparent',
                border: 0,
                borderBottom: `2px solid ${selected ? 'var(--text-primary)' : 'transparent'}`,
                marginBottom: -1,
                padding: '0 var(--space-3)',
                height: 'var(--row-default)',
                color: item.disabled ? 'var(--text-muted)' : selected ? 'var(--text-primary)' : 'var(--text-secondary)',
                fontFamily: 'inherit',
                fontSize: 'var(--text-sm)',
                fontWeight: selected ? 600 : 500,
                cursor: item.disabled ? 'not-allowed' : 'pointer',
              }}
            >
              {item.label}
            </button>
          );
        })}
      </div>
      {items.map((item) => (
        <div
          key={item.id}
          id={`${base}-panel-${item.id}`}
          role="tabpanel"
          aria-labelledby={`${base}-tab-${item.id}`}
          hidden={item.id !== active}
          tabIndex={0}
          style={{ paddingTop: 'var(--space-4)', outline: 'none' }}
        >
          {item.id === active && item.content}
        </div>
      ))}
    </div>
  );
}
