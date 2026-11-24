import type { Route } from 'next';

import { RouteTabs } from '@/components/ui/route-tabs';

/* The Access tab strip. The register is the anchor view — every credential the connected systems
 * accept. "Live connections" is the former Runtime page: who is connected right now, and how long
 * we have been watching, which is the evidence behind the register's "last seen" column. */

const TABS: { href: Route; label: string; exact?: boolean }[] = [
  { href: '/access', label: 'Who can touch what', exact: true },
  { href: '/access/right-size', label: 'Least privilege' },
  { href: '/access/leaver', label: 'Leavers' },
  { href: '/access/flows', label: 'Data & AI agents' },
  { href: '/access/live', label: 'Live connections' },
];

export function AccessTabs() {
  return <RouteTabs aria-label="Access views" tabs={TABS} />;
}
