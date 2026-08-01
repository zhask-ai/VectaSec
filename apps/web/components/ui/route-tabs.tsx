'use client';

import type { Route } from 'next';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';

/* A ROUTE tab strip: each tab is a real URL, server-rendered and shareable. Use this when the
 * panels are separate pages that happen to belong to one section (Systems' Connected/Coverage,
 * Settings' General/Members/Integrations).
 *
 * It is the counterpart to components/ui/tabs.tsx, which switches panels with local state and
 * never touches the URL — reach for that only when a panel is not worth a link.
 *
 * Client-side for usePathname alone: the active tab must carry aria-current, and a server
 * component cannot know the path without opting its whole subtree into per-request dynamic
 * APIs it does not otherwise need.
 */

export type RouteTab = { href: Route; label: string; badge?: ReactNode; exact?: boolean };

export function RouteTabs({ tabs, 'aria-label': ariaLabel }: { tabs: RouteTab[]; 'aria-label': string }) {
  const pathname = usePathname();

  return (
    <nav aria-label={ariaLabel} style={{ borderBottom: '1px solid var(--border)' }}>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', gap: 'var(--space-1)' }}>
        {tabs.map((tab) => {
          const active = tab.exact ? pathname === tab.href : pathname.startsWith(tab.href);
          return (
            <li key={tab.href}>
              <Link
                href={tab.href}
                aria-current={active ? 'page' : undefined}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-2)',
                  height: 'var(--row-default)',
                  padding: '0 var(--space-3)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: active ? 600 : 400,
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                  textDecoration: 'none',
                  borderBottom: `2px solid ${active ? 'var(--accent)' : 'transparent'}`,
                  marginBottom: -1,
                }}
              >
                {tab.label}
                {tab.badge != null && (
                  <span
                    data-numeric
                    style={{
                      fontSize: 'var(--text-2xs)',
                      color: 'var(--text-muted)',
                      fontWeight: 500,
                    }}
                  >
                    {tab.badge}
                  </span>
                )}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
