import type { Route } from 'next';

import { RouteTabs } from '@/components/ui/route-tabs';

/* The Findings tab strip. Attack paths used to be a sidebar item of their own; they are the best
 * finding the engine produces, not a separate product, so they sit here as "Priority paths". */

const TABS: { href: Route; label: string; exact?: boolean }[] = [
  { href: '/findings', label: 'All findings', exact: true },
  { href: '/findings/paths', label: 'Priority paths' },
];

export function FindingsTabs() {
  return <RouteTabs aria-label="Findings views" tabs={TABS} />;
}
