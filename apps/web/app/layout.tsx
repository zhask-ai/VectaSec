import type { Metadata, Route } from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'VectaSec',
  description: 'Integration-layer security posture',
};

/* The console shell. Nav order is deliberate: Overview answers "what do I do now", Findings is
 * the workhorse, everything after is reference. Compliance sits high because it is the
 * budget-holder's view, not the analyst's.
 *
 * Other agents own the pages behind these routes; this file owns only the frame.
 *
 * `typedRoutes` is ON (next.config.ts) so a typo'd or dead href is a build error — worth
 * keeping for a console where nav correctness matters. The cast below is the one deliberate
 * exception: every route except / and /login is still unbuilt, so it cannot typecheck yet.
 * As each page lands, DELETE its cast — the moment all five resolve, remove `as Route`
 * entirely and let the compiler guard the nav. */
const NAV: { href: Route; label: string }[] = [
  { href: '/', label: 'Overview' },
  { href: '/findings' as Route, label: 'Findings' },
  { href: '/assets' as Route, label: 'Assets' },
  { href: '/compliance' as Route, label: 'Compliance' },
  { href: '/connections' as Route, label: 'Connections' },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {/* First stop on a keyboard tab: an analyst working a queue should never tab through
            five nav links to reach the table. */}
        <a
          href="#main"
          className="vs-visually-hidden"
          style={{ position: 'absolute', top: 'var(--space-2)', left: 'var(--space-2)' }}
        >
          Skip to content
        </a>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'var(--sidebar-width) 1fr',
            gridTemplateRows: 'var(--topbar-height) 1fr',
            gridTemplateAreas: '"brand topbar" "sidebar main"',
            minHeight: '100dvh',
          }}
        >
          <div
            style={{
              gridArea: 'brand',
              display: 'flex',
              alignItems: 'center',
              padding: '0 var(--space-4)',
              borderBottom: '1px solid var(--border)',
              borderRight: '1px solid var(--border)',
              background: 'var(--surface)',
              fontWeight: 600,
              letterSpacing: '-0.01em',
            }}
          >
            VectaSec
          </div>

          <header
            style={{
              gridArea: 'topbar',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'flex-end',
              gap: 'var(--space-3)',
              padding: '0 var(--space-4)',
              borderBottom: '1px solid var(--border)',
              background: 'var(--surface)',
              fontSize: 'var(--text-xs)',
              color: 'var(--text-secondary)',
            }}
          >
            {/* Scan progress is ambient — a strip here, never a modal. A scan must never block
                the console. */}
            <span id="vs-scan-strip" />
          </header>

          <nav
            aria-label="Main"
            style={{
              gridArea: 'sidebar',
              borderRight: '1px solid var(--border)',
              background: 'var(--surface)',
              padding: 'var(--space-3) var(--space-2)',
            }}
          >
            <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '2px' }}>
              {NAV.map((item) => (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      height: 'var(--row-compact)',
                      padding: '0 var(--space-3)',
                      borderRadius: 'var(--radius-md)',
                      color: 'var(--text-secondary)',
                      fontSize: 'var(--text-sm)',
                      textDecoration: 'none',
                    }}
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>

          <main id="main" style={{ gridArea: 'main', padding: 'var(--space-5)', minWidth: 0 }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
