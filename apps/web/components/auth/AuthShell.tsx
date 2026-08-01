'use client';

/* Shared frame for every unauthenticated screen (/login, /signup, /forgot-password,
 * /welcome): the kaveo auth layout, re-themed. Form pane on the left — brand lockup top-left,
 * theme toggle top-right, the form centred at max-w-sm — and the VectaSec info panel on the
 * right, hidden below 1024px so the form comes first on mobile.
 *
 * The panel is the product pitch (eyebrow, headline, value prop, three proof points, a stats
 * row, standing tagline) on an invariant brand-navy surface with a dotted grid and one soft
 * glow — the direct analogue of kaveo's scarlet panel, speaking VectaSec blue. It is
 * aria-hidden: decorative; the form carries the real content.
 *
 * Styling lives in app/auth.css (.vs-auth-*) — class-based, so the contrast source-audit's
 * control-border rule sees no inline styles to misread, and every colour is a token or lives
 * in the stylesheet.
 */
import Link from 'next/link';

import { ThemeToggle } from '@/components/shell/ThemeToggle';
import { IconData, IconFindings, IconIdentities, type IconProps } from '@/components/ui/icons';

/** What VectaSec offers — three proof points. */
const POINTS: { icon: (p: IconProps) => React.JSX.Element; title: string; body: string }[] = [
  {
    icon: IconFindings,
    title: 'Evidence-first findings',
    body: 'Every finding carries the observation that proves it — nothing to take on faith.',
  },
  {
    icon: IconIdentities,
    title: 'Non-human identities, inventoried',
    body: 'Service accounts, keys and OAuth grants mapped across every connector.',
  },
  {
    icon: IconData,
    title: 'Least-privilege connectors',
    body: 'Read-only scopes only — VectaSec can see your posture, never change it.',
  },
];

/** Proof in numbers. */
const STATS: { value: string; label: string }[] = [
  { value: '85', label: 'detectors' },
  { value: '5', label: 'connectors' },
  { value: '0', label: 'write scopes' },
];

function BrandLockup() {
  return (
    <Link href="/login" className="vs-auth-lockup" aria-label="VectaSec home">
      <span className="vs-auth-lockup-mark">
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M12 3l8 4v5c0 4.5-3.2 7.6-8 9-4.8-1.4-8-4.5-8-9V7z" />
          <path d="M8.5 11.5l2.5 2.5 4.5-4.5" />
        </svg>
      </span>
      <span>
        <span className="vs-auth-lockup-word" style={{ display: 'block' }}>
          VECTASEC
        </span>
        <span className="vs-auth-lockup-sub" style={{ display: 'block' }}>
          integration-layer security
        </span>
      </span>
    </Link>
  );
}

function InfoPanel() {
  return (
    <aside className="vs-auth-panel" aria-hidden="true">
      <div className="vs-auth-panel-grid" />
      <div className="vs-auth-panel-glow" />

      <div className="vs-auth-panel-body">
        <div className="vs-auth-panel-main">
          <div className="vs-auth-panel-inner">
            <div className="vs-auth-eyebrow">
              <span className="vs-auth-eyebrow-chip">
                <IconFindings size={12} />
              </span>
              VectaSec · security posture console
            </div>

            <div>
              <h2 className="vs-auth-headline">Know exactly what your integrations can do.</h2>
              <p className="vs-auth-panel-prop">
                Continuous security posture for the integration layer — OAuth grants, non-human
                identities and data exposure across your SaaS stack, scored with evidence
                attached to every finding.
              </p>
            </div>

            <ul className="vs-auth-points">
              {POINTS.map(({ icon: Icon, title, body }) => (
                <li key={title} className="vs-auth-point">
                  <span className="vs-auth-point-icon">
                    <Icon size={16} />
                  </span>
                  <div>
                    <p className="vs-auth-point-title">{title}</p>
                    <p className="vs-auth-point-body">{body}</p>
                  </div>
                </li>
              ))}
            </ul>

            <dl className="vs-auth-stats">
              {STATS.map(({ value, label }) => (
                <div key={label}>
                  <dt className="vs-auth-stat-value">{value}</dt>
                  <dd className="vs-auth-stat-label">{label}</dd>
                </div>
              ))}
            </dl>

            <p className="vs-auth-panel-note">
              Posture is rescored on every sync into a single grade your team can track, with
              tenant isolation enforced by row-level security — the same console, SaaS or
              on-prem.
            </p>
          </div>
        </div>

        <p className="vs-auth-tagline">
          Evidence-first findings · least-privilege reads · RLS tenant isolation
        </p>
      </div>
    </aside>
  );
}

export function AuthShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="vs-auth">
      <div className="vs-auth-pane">
        <header className="vs-auth-pane-head">
          <BrandLockup />
          <ThemeToggle />
        </header>

        <main className="vs-auth-pane-center">
          <div className="vs-auth-formbox">{children}</div>
        </main>
      </div>

      <InfoPanel />
    </div>
  );
}
