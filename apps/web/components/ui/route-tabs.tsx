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

  // Styling lives in globals.css (.vs-rtabs): hover states, the sliding underline and the
  // horizontal scroll a long strip needs at narrow widths cannot be inline styles.
  return (
    <nav aria-label={ariaLabel} className="vs-rtabs">
      <ul className="vs-rtabs-list">
        {tabs.map((tab) => {
          const active = tab.exact ? pathname === tab.href : pathname.startsWith(tab.href);
          return (
            <li key={tab.href}>
              <Link href={tab.href} aria-current={active ? 'page' : undefined} className="vs-rtab">
                {tab.label}
                {tab.badge != null && (
                  <span data-numeric style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', fontWeight: 500 }}>
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
