'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import type { Route } from 'next';
import { usePathname } from 'next/navigation';

import { ScanStrip } from '@/components/ScanStrip';
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

type NavItem = { href: Route; label: string; Icon: (p: IconProps) => React.JSX.Element; exact?: boolean };

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
      { href: '/connections', label: 'Systems', Icon: IconSystems },
      { href: '/identities', label: 'Identities', Icon: IconIdentities },
      { href: '/data', label: 'Data', Icon: IconData },
      { href: '/assets', label: 'Assets', Icon: IconAssets },
    ],
  },
  {
    label: 'Assurance',
    items: [
      { href: '/attack-paths', label: 'Attack paths', Icon: IconAttackPaths },
      { href: '/compliance', label: 'Compliance', Icon: IconCompliance },
    ],
  },
  {
    label: 'Operations',
    items: [{ href: '/scans', label: 'Scans', Icon: IconScans }],
  },
];

const SETTINGS_ITEM: NavItem = { href: '/settings', label: 'Settings', Icon: IconSettings };

function isActive(pathname: string, item: NavItem): boolean {
  if (item.exact) return pathname === item.href;
  return pathname === item.href || pathname.startsWith(`${item.href}/`);
}

export function ShellChrome({
  tenantName,
  posture,
  isAdmin,
  userEmail,
  children,
}: {
  tenantName: string;
  posture: Posture | null;
  isAdmin: boolean;
  userEmail: string | null;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close the drawer on navigation — a menu that stays open over the page you just opened is a
  // trap, especially on the small screens where this drawer exists at all.
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

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
          <span className="vs-tenant" title={tenantName}>
            {tenantName}
          </span>
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
