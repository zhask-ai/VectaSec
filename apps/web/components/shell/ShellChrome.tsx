'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import type { Route } from 'next';
import { usePathname } from 'next/navigation';

import { ScanStrip } from '@/components/ScanStrip';
import { createClient } from '@/lib/supabase/client';
import { switchTenantAction } from '@/app/(app)/tenant-actions';
import { gradeColor, type Posture } from '@/lib/posture';
import {
  IconOverview,
  IconFindings,
  IconSystems,
  IconIdentities,
  IconData,
  IconAssets,
  IconAttackPaths,
  IconCompliance,
  IconScans,
  IconSettings,
  IconMenu,
  IconClose,
  type IconProps,
} from '@/components/ui/icons';
import { ThemeToggle } from './ThemeToggle';
import { GlobalSearch } from './GlobalSearch';
import { UserMenu } from './UserMenu';

/* The app shell — the persistent chrome every authed route inherits: a grouped left sidebar, a
 * top bar (tenant, search, live posture, theme, account), and the main region.
 *
 * It is a CLIENT component for exactly two reasons — the active nav item needs usePathname, and
 * the mobile drawer needs open-state shared between the top-bar hamburger and the sidebar. Nothing
 * data-bearing lives here: the (app) layout resolves tenant / posture / role under RLS on the
 * server and passes them down as plain props, and the server-rendered pages arrive as `children`
 * through this boundary untouched. So the shell stays a frame, and the pages stay server work.
 *
 * The nav is defined here (not passed in) so the icon components never have to cross the RSC
 * boundary. Order is deliberate: Overview ("what do I do now") and Findings (the workhorse) sit
 * above the fold; Inventory is the estate; Assurance is the auditor's view; Operations is the tail
 * you visit when you asked for work, not where you live. Settings is tenant admin, pinned to the
 * bottom and shown to admins only — hiding it is coherence, not security (every settings page and
 * action re-checks the role server-side; RLS is the boundary).
 */

type NavItem = {
  href: Route;
  label: string;
  Icon: (p: IconProps) => React.JSX.Element;
  exact?: boolean;
  /** Sibling routes that belong to this item — a section whose tabs are separate routes must
   * stay highlighted on every one of them, or the sidebar denies where the user is. */
  also?: Route[];
};

const NAV_GROUPS: { label?: string; items: NavItem[] }[] = [
  {
    items: [
      { href: '/', label: 'Overview', Icon: IconOverview, exact: true },
      { href: '/findings', label: 'Findings', Icon: IconFindings },
    ],
  },
  {
    label: 'Inventory',
    items: [
      // ONE entry for the estate. Connected (/connections) and Coverage (/systems) are tabs of
      // that one section, not rival sidebar items: both answer "what systems?", and two
      // near-synonymous nav labels made the reader choose before they knew the difference.
      // Landing on /connections because the operational view is where an operator lives; the
      // catalogue is reference, one tab away.
      { href: '/connections', label: 'Systems', Icon: IconSystems, also: ['/systems'] },
      // Discovery sits with Inventory rather than Operations: its output is estate, and its
      // headline finding — middleware nobody monitors — is an inventory gap, not a scan result.
      { href: '/discovery', label: 'Discovery', Icon: IconScans },
      { href: '/identities', label: 'Identities', Icon: IconIdentities },
      { href: '/data', label: 'Data', Icon: IconData },
      { href: '/assets', label: 'Assets', Icon: IconAssets },
    ],
  },
  {
    label: 'Assurance',
    items: [
      { href: '/attack-paths', label: 'Attack paths', Icon: IconAttackPaths },
      { href: '/runtime', label: 'Runtime', Icon: IconOverview },
      { href: '/supply-chain', label: 'Supply chain', Icon: IconSystems },
      { href: '/compliance', label: 'Compliance', Icon: IconCompliance },
    ],
  },
  {
    label: 'Operations',
    items: [{ href: '/scans', label: 'Scans', Icon: IconScans }],
  },
];

const SETTINGS_ITEM: NavItem = { href: '/settings', label: 'Settings', Icon: IconSettings };

// The operator's view — rendered only for super admins (courtesy; every /admin page and the
// definer functions behind it re-check server-side).
const PLATFORM_ITEMS: NavItem[] = [
  { href: '/admin', label: 'Organizations', Icon: IconSystems, exact: true },
  { href: '/admin/users', label: 'Users', Icon: IconIdentities },
];

function isActive(pathname: string, item: NavItem): boolean {
  const under = (base: string) => pathname === base || pathname.startsWith(`${base}/`);
  if (item.exact) return pathname === item.href;
  return under(item.href) || (item.also?.some(under) ?? false);
}

export function ShellChrome({
  tenantName,
  posture,
  isAdmin,
  isSuperAdmin = false,
  userEmail,
  memberships = [],
  activeTenantId = null,
  children,
}: {
  tenantName: string;
  posture: Posture | null;
  isAdmin: boolean;
  isSuperAdmin?: boolean;
  userEmail: string | null;
  memberships?: { tenantId: string; tenantName: string }[];
  activeTenantId?: string | null;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close the drawer on navigation — a menu that stays open over the page you just opened is a
  // trap, especially on the small screens where this drawer exists at all.
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  // Presence heartbeat: touch profiles.last_seen_at once a minute while a tab is open. The
  // admin panel's "online" is this timestamp being fresh — presence by polling, like every
  // other liveness in the console. Errors ignored on purpose (pre-migration DBs, offline).
  useEffect(() => {
    const supabase = createClient();
    const beat = () => {
      void supabase.rpc('touch_last_seen').then(
        () => {},
        () => {},
      );
    };
    beat();
    const t = setInterval(beat, 60_000);
    return () => clearInterval(t);
  }, []);

  const NavList = () => (
    <nav aria-label="Primary" className="vs-nav">
      {NAV_GROUPS.map((group, gi) => (
        <div key={gi} className="vs-nav-group">
          {group.label && <div className="vs-nav-group-label">{group.label}</div>}
          <ul className="vs-nav-list">
            {group.items.map((item) => {
              const active = isActive(pathname, item);
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className="vs-navitem"
                    data-active={active || undefined}
                    aria-current={active ? 'page' : undefined}
                    onClick={() => setMobileOpen(false)}
                  >
                    <span aria-hidden="true" className="vs-navitem-icon">
                      <item.Icon size={18} />
                    </span>
                    <span className="vs-nav-label">{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}

      {isSuperAdmin && (
        <div className="vs-nav-group">
          <div className="vs-nav-group-label">Platform</div>
          <ul className="vs-nav-list">
            {PLATFORM_ITEMS.map((item) => {
              const active = isActive(pathname, item);
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className="vs-navitem"
                    data-active={active || undefined}
                    aria-current={active ? 'page' : undefined}
                    onClick={() => setMobileOpen(false)}
                  >
                    <span aria-hidden="true" className="vs-navitem-icon">
                      <item.Icon size={18} />
                    </span>
                    <span className="vs-nav-label">{item.label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {isAdmin && (
        <div className="vs-nav-group vs-nav-group-pinned">
          <ul className="vs-nav-list">
            <li>
              <Link
                href={SETTINGS_ITEM.href}
                className="vs-navitem"
                data-active={isActive(pathname, SETTINGS_ITEM) || undefined}
                aria-current={isActive(pathname, SETTINGS_ITEM) ? 'page' : undefined}
                onClick={() => setMobileOpen(false)}
              >
                <span aria-hidden="true" className="vs-navitem-icon">
                  <SETTINGS_ITEM.Icon size={18} />
                </span>
                <span className="vs-nav-label">{SETTINGS_ITEM.label}</span>
              </Link>
            </li>
          </ul>
        </div>
      )}
    </nav>
  );

  return (
    <div className="vs-shell">
      <a href="#main" className="vs-skip-link">
        Skip to content
      </a>

      {/* Brand — its own grid cell above the sidebar on desktop; folded into the top bar on mobile. */}
      <div className="vs-brand">
        <Link href="/" className="vs-brand-link" aria-label="VectaSec — Overview">
          <BrandMark />
          <span className="vs-brand-word">VectaSec</span>
        </Link>
      </div>

      <header className="vs-topbar">
        <div className="vs-topbar-left">
          <button
            type="button"
            className="vs-iconbtn vs-menu-btn"
            aria-label={mobileOpen ? 'Close navigation' : 'Open navigation'}
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen((v) => !v)}
          >
            {mobileOpen ? <IconClose size={18} /> : <IconMenu size={18} />}
          </button>
          <Link href="/" className="vs-brand-link vs-brand-mobile" aria-label="VectaSec — Overview">
            <BrandMark />
          </Link>
          {memberships.length > 1 ? (
            <form action={switchTenantAction}>
              <select
                name="tenant"
                aria-label="Switch organization"
                className="vs-tenant"
                value={activeTenantId ?? memberships[0]?.tenantId}
                onChange={(e) => e.currentTarget.form?.requestSubmit()}
                style={{
                  background: 'var(--surface)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-interactive)',
                  borderRadius: 'var(--radius-sm, 6px)',
                  padding: '3px 6px',
                  fontSize: 'var(--text-sm)',
                }}
              >
                {memberships.map((m) => (
                  <option key={m.tenantId} value={m.tenantId}>
                    {m.tenantName}
                  </option>
                ))}
              </select>
            </form>
          ) : (
            <span className="vs-tenant" title={tenantName}>
              {tenantName}
            </span>
          )}
          <div className="vs-topbar-search">
            <GlobalSearch />
          </div>
        </div>

        <div className="vs-topbar-right">
          <ScanStrip />
          {posture && <PostureChip posture={posture} />}
          <ThemeToggle />
          <UserMenu email={userEmail} tenantName={tenantName} />
        </div>
      </header>

      {/* Sidebar — a rail on desktop, an icon rail on tablet, an off-canvas drawer on mobile. */}
      <aside className="vs-sidebar" data-open={mobileOpen || undefined}>
        <NavList />
      </aside>

      {mobileOpen && <div className="vs-scrim" onClick={() => setMobileOpen(false)} aria-hidden="true" />}

      <main id="main" className="vs-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}

/** Live posture score, always paired with its A–F grade (never colour alone) and coloured by the
 * grade token, so it reads on the same scale as everything else. Links to Overview, where the
 * number is shown next to the counts it is computed from. */
function PostureChip({ posture }: { posture: Posture }) {
  const color = gradeColor(posture.grade);
  return (
    <Link href="/" className="vs-posture-chip" title={`Posture ${posture.score} (grade ${posture.grade})`}>
      <span className="vs-posture-label">Posture</span>
      <span data-numeric className="vs-posture-score" style={{ color }}>
        {posture.score}
      </span>
      <span className="vs-posture-grade" style={{ color, borderColor: color }}>
        {posture.grade}
      </span>
    </Link>
  );
}

/** The wordmark's geometric mark: a rounded tile with an integration-graph glyph — two nodes and
 * the edge between them, the thing VectaSec actually maps. Accent fill, both themes. */
function BrandMark() {
  return (
    <span aria-hidden="true" className="vs-brand-mark">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
        <path d="M7 8.5l5 3 5-3M7 15.5l5-3 5 3" stroke="var(--accent-fg)" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="7" cy="8.5" r="2.1" fill="var(--accent-fg)" />
        <circle cx="17" cy="15.5" r="2.1" fill="var(--accent-fg)" />
      </svg>
    </span>
  );
}
