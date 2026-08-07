import type { Route } from 'next';

import { RouteTabs } from '@/components/ui/route-tabs';

/* The settings tab strip — the shared RouteTabs over the settings routes. RouteTabs is the
 * client component (usePathname marks the active tab with aria-current); this file only names
 * the routes, so it stays a server module. */

const TABS: { href: Route; label: string; exact?: boolean }[] = [
  { href: '/settings', label: 'General', exact: true },
  { href: '/settings/members', label: 'Members' },
  { href: '/settings/integrations', label: 'Integrations' },
];

export function SettingsTabs() {
  return <RouteTabs aria-label="Settings sections" tabs={TABS} />;
}
