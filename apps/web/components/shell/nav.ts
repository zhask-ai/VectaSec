import type { Route } from 'next';

import {
  IconOverview,
  IconFindings,
  IconSystems,
  IconIdentities,
  IconCompliance,
  IconSettings,
  type IconProps,
  IconZap,
} from '@/components/ui/icons';

/* The navigation model, shared by the sidebar (ShellChrome) and the command palette, so the two
 * can never list different places. */

export type NavItem = {
  href: Route;
  label: string;
  Icon: (p: IconProps) => React.JSX.Element;
  exact?: boolean;
  /** Sibling routes that belong to this item — a section whose tabs are separate routes must
   * stay highlighted on every one of them, or the sidebar denies where the user is. */
  also?: Route[];
  /** Every view of the section, listed under it in the sidebar. The first entry is the
   * section's own landing route. Kept in step with the section's tab strip (tabs.tsx). */
  children?: { href: Route; label: string }[];
};

export const NAV_ITEMS: NavItem[] = [
  { href: '/', label: 'Overview', Icon: IconOverview, exact: true },
  { href: '/ask', label: 'Ask', Icon: IconZap },
  {
    href: '/findings',
    label: 'Findings',
    Icon: IconFindings,
    children: [
      { href: '/findings', label: 'All findings' },
      { href: '/findings/paths', label: 'Attack paths' },
      { href: '/findings/breach-day', label: 'Breach day' },
      { href: '/findings/canaries', label: 'Canaries' },
    ],
  },
  {
    href: '/access',
    label: 'Access',
    Icon: IconIdentities,
    children: [
      { href: '/access', label: 'Who can touch what' },
      { href: '/access/right-size', label: 'Least privilege' },
      { href: '/access/leaver', label: 'Leavers' },
      { href: '/access/flows', label: 'Data & AI agents' },
      { href: '/access/live', label: 'Live connections' },
    ],
  },
  {
    href: '/estate',
    label: 'Estate',
    Icon: IconSystems,
    children: [
      { href: '/estate', label: 'Connected' },
      { href: '/estate/changes', label: 'Time machine' },
      { href: '/estate/inventory', label: 'Inventory' },
      { href: '/estate/unmonitored', label: 'Unmonitored' },
      { href: '/estate/catalogue', label: 'What we can assess' },
    ],
  },
  {
    href: '/compliance',
    label: 'Compliance',
    Icon: IconCompliance,
    children: [
      { href: '/compliance', label: 'Controls' },
      { href: '/compliance/benchmark', label: 'Benchmark' },
      { href: '/compliance/reports', label: 'Reports & exports' },
    ],
  },
];

export const SETTINGS_ITEM: NavItem = { href: '/settings', label: 'Settings', Icon: IconSettings };

// The operator's view — rendered only for super admins (courtesy; every /admin page and the
// definer functions behind it re-check server-side).
export const PLATFORM_ITEMS: NavItem[] = [
  { href: '/admin', label: 'Organizations', Icon: IconSystems, exact: true },
  { href: '/admin/users', label: 'Users', Icon: IconIdentities },
];

export function isActive(pathname: string, item: NavItem): boolean {
  const under = (base: string) => pathname === base || pathname.startsWith(`${base}/`);
  if (item.exact) return pathname === item.href;
  return under(item.href) || (item.also?.some(under) ?? false);
}

