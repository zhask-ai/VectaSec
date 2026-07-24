'use client';

import type { Route } from 'next';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

/* The settings tab strip. Client-side only for usePathname — the active tab must be marked
 * (aria-current) and a server component cannot know the path without opting the whole
 * subtree into per-request dynamic APIs it does not otherwise need. */

const TABS: { href: Route; label: string; exact?: boolean }[] = [
  { href: '/settings', label: 'General', exact: true },
  { href: '/settings/members', label: 'Members' },
  { href: '/settings/integrations', label: 'Integrations' },
];

export function SettingsTabs() {
  const pathname = usePathname();

  return (
    <nav aria-label="Settings sections" style={{ borderBottom: '1px solid var(--border)' }}>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', gap: 'var(--space-1)' }}>
        {TABS.map((tab) => {
          const active = tab.exact ? pathname === tab.href : pathname.startsWith(tab.href);
          return (
            <li key={tab.href}>
              <Link
                href={tab.href}
                aria-current={active ? 'page' : undefined}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  height: 'var(--row-default)',
                  padding: '0 var(--space-3)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: active ? 600 : 400,
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                  textDecoration: 'none',
                  borderBottom: `2px solid ${active ? 'var(--text-primary)' : 'transparent'}`,
                  marginBottom: -1,
                }}
              >
                {tab.label}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
