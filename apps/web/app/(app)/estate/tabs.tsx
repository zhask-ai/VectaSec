import type { Route } from 'next';

import { RouteTabs } from '@/components/ui/route-tabs';

/* The Estate tab strip — one section, five views of one subject: what is connected, what is on
 * the network but unmonitored, what each scan returned, how that changed between scans (the Time
 * machine), and what the engine could assess if asked.
 * Four former sidebar entries (Connections, Discovery, Assets, Systems) collapsed into this strip,
 * because all four answer "what systems?" and a buyer should not have to choose before knowing
 * the difference. RouteTabs is the client half (usePathname → aria-current); this file only names
 * the routes, so it stays a server module and every page in the section can import it. */

const TABS: { href: Route; label: string; exact?: boolean }[] = [
  { href: '/estate', label: 'Connected', exact: true },
  { href: '/estate/changes', label: 'Time machine' },
  { href: '/estate/inventory', label: 'Inventory' },
  { href: '/estate/unmonitored', label: 'Unmonitored' },
  { href: '/estate/catalogue', label: 'What we can assess' },
];

export function EstateTabs() {
  return <RouteTabs aria-label="Estate views" tabs={TABS} />;
}
