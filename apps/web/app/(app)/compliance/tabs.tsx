import type { Route } from 'next';

import { RouteTabs } from '@/components/ui/route-tabs';

/* The Compliance tab strip: the controls table, and the documents an auditor asks for — the
 * evidence bundle, SBOM, VEX and the licensing inventory (formerly the Supply chain page). */

const TABS: { href: Route; label: string; exact?: boolean }[] = [
  { href: '/compliance', label: 'Controls', exact: true },
  { href: '/compliance/benchmark', label: 'Benchmark' },
  { href: '/compliance/reports', label: 'Reports & exports' },
];

export function ComplianceTabs() {
  return <RouteTabs aria-label="Compliance views" tabs={TABS} />;
}
