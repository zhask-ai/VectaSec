'use client';

import { Suspense, useEffect, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

import { ScanStrip } from '@/components/ScanStrip';
import { createClient } from '@/lib/supabase/client';
import { switchTenantAction } from '@/app/(app)/tenant-actions';
import { gradeColor, type Posture } from '@/lib/posture';
import { IconChevronRight, IconMenu, IconClose } from '@/components/ui/icons';
import { NAV_ITEMS, PLATFORM_ITEMS, SETTINGS_ITEM, isActive, type NavItem } from './nav';
import { CommandPalette } from './CommandPalette';
import { NavProgress } from './NavProgress';
import { ThemeToggle } from './ThemeToggle';
import { UserMenu } from './UserMenu';

/* The app shell — the persistent chrome every authed route inherits: a six-item left sidebar, a
 * top bar (tenant, search, live posture, theme, account), and the main region.
 *
 * It is a CLIENT component for exactly two reasons — the active nav item needs usePathname, and
 * the mobile drawer needs open-state shared between the top-bar hamburger and the sidebar. Nothing
 * data-bearing lives here: the (app) layout resolves tenant / posture / role under RLS on the
 * server and passes them down as plain props, and the server-rendered pages arrive as `children`
 * through this boundary untouched. So the shell stays a frame, and the pages stay server work.
 *
 * SIX ITEMS, NO GROUPS. The previous shell had fifteen entries in four groups, and prospect
 * feedback (docs/vectasec-smb-strategy-2026-10.md §1, §3) was blunt about what that did: a buyer
 * with no security team could not find the one thing only this product shows them. The
 * consolidation is:
 *
 *   Overview     — what do I do now.
 *   Findings     — the queue; attack paths are its "Priority paths" tab, CVE/EOL a facet.
 *   Access       — the anchor: every API key / service account / OAuth client the connected
 *                  systems accept, with owner, last used, sensitivity. Absorbs Identities,
 *                  Runtime (last seen / live connections) and the Data lens (a column, not a page).
 *   Estate       — Connected / Unmonitored / Inventory / What we can assess. Absorbs Connections,
 *                  Discovery, Assets and the Systems catalogue; scan history is a drawer per row.
 *   Compliance   — controls, plus "Reports & exports" (SBOM / VEX / licensing / evidence bundle).
 *   Settings     — tenant admin, pinned to the bottom, admins only (a courtesy, not a boundary:
 *                  every settings page and action re-checks the role server-side).
 *
 * The old routes still resolve — next.config.ts redirects each to its new home — so a pasted link
 * never breaks. The nav is defined here (not passed in) so the icon components never cross the
 * RSC boundary.
 */

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

  // Which sections are expanded in the sidebar. A section opens by default while you are in it;
  // an explicit open/close is remembered per browser. Read after mount so the server render and
  // the first client render agree (no hydration mismatch).
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('vs-nav-expanded') || '{}');
      if (saved && typeof saved === 'object') setExpanded(saved);
    } catch {
      /* private mode or corrupt value: defaults apply */
    }
  }, []);
  const toggle = (href: string, open: boolean) => {
    setExpanded((prev) => {
      const next = { ...prev, [href]: !open };
      try {
        localStorage.setItem('vs-nav-expanded', JSON.stringify(next));
      } catch {
        /* not persisted: fine */
      }
      return next;
    });
  };

  // Built as an element, not an inner component: an inner component is a new type every render,
  // which remounts the whole list and kills the expand/collapse transition mid-flight.
  const navList = (
    <nav aria-label="Primary" className="vs-nav">
      <div className="vs-nav-group">
        <ul className="vs-nav-list">
          {NAV_ITEMS.map((item: NavItem) => {
            const active = isActive(pathname, item);
            const open = item.children ? (expanded[item.href] ?? active) : false;
            const subId = `vs-navsub-${item.label.toLowerCase()}`;
            return (
              <li key={item.href}>
                <div className="vs-navrow">
                  <Link
                    href={item.href}
                    className="vs-navitem"
                    data-active={active || undefined}
                    aria-current={active && pathname === item.href ? 'page' : undefined}
                    onClick={() => setMobileOpen(false)}
                  >
                    <span aria-hidden="true" className="vs-navitem-icon">
                      <item.Icon size={18} />
                    </span>
                    <span className="vs-nav-label">{item.label}</span>
                  </Link>
                  {item.children && (
                    <button
                      type="button"
                      className="vs-navtoggle"
                      aria-expanded={open}
                      aria-controls={subId}
                      aria-label={`${open ? 'Collapse' : 'Expand'} ${item.label}`}
                      onClick={() => toggle(item.href, open)}
                    >
                      <IconChevronRight size={14} />
                    </button>
                  )}
                </div>
                {item.children && (
                  <div className="vs-navsub-wrap" data-open={open || undefined}>
                    <ul className="vs-navsub-list" id={subId} inert={!open}>
                      {item.children.map((child) => {
                        // The landing route is active only on itself; a deeper route also on
                        // its own sub-pages (a finding, a resource).
                        const landing = child.href === item.href;
                        const deeper = item.children!.some(
                          (c) => c.href !== item.href && (pathname === c.href || pathname.startsWith(`${c.href}/`)),
                        );
                        const childActive = landing
                          ? active && !deeper
                          : pathname === child.href || pathname.startsWith(`${child.href}/`);
                        return (
                          <li key={child.href}>
                            <Link
                              href={child.href}
                              className="vs-navsub"
                              data-active={childActive || undefined}
                              aria-current={childActive ? 'page' : undefined}
                              onClick={() => setMobileOpen(false)}
                            >
                              {child.label}
                            </Link>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </div>

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

      <Suspense fallback={null}>
        <NavProgress />
      </Suspense>
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
          {/* The tenant wears a mark, not just a word — the org you are acting in is the single
              most important piece of context in a multi-tenant console. */}
          <span aria-hidden="true" className="vs-tenant-mark">
            {(tenantName || 'V').slice(0, 1).toUpperCase()}
          </span>
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
            <CommandPalette admin={isSuperAdmin} />
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
        {navList}
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
