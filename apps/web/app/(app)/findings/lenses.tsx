import Link from 'next/link';
import type { Route } from 'next';

import { findingsHref, type FindingFilters } from './query';

/* Lenses — the three families that used to be pages of their own, now one row of quick filters
 * above the queue. Each is a plain link that sets the `system` facet (the first dotted segment of
 * rule_id), so it composes with every other filter and is a URL you can paste. Nothing here is a
 * new query: SUPPLY.* is the CVE / EOL family the Supply-chain page listed, CREDENTIAL.* is the
 * lifecycle pack the Access register summarises, ATTACKPATH.* has its own tab beside this one. */

const LENSES: { system: string; label: string; hint: string }[] = [
  { system: 'SUPPLY', label: 'Supply chain · CVE / EOL', hint: 'Known vulnerabilities, end-of-life branches and manifest findings' },
  { system: 'CREDENTIAL', label: 'Credential lifecycle', hint: 'Stale, never-used, default and non-expiring credentials' },
  { system: 'NHI', label: 'Over-broad access', hint: 'Wildcard grants and shared or default principals' },
];

export function Lenses({ filters }: { filters: FindingFilters }) {
  return (
    <nav aria-label="Finding lenses" style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
      <span
        style={{
          fontSize: 'var(--text-2xs)',
          fontWeight: 600,
          letterSpacing: '0.04em',
          textTransform: 'uppercase',
          color: 'var(--text-secondary)',
        }}
      >
        Lens
      </span>
      {LENSES.map((l) => {
        const active = filters.system === l.system;
        const href: Route = active
          ? findingsHref({ ...filters, system: null })
          : findingsHref({ ...filters, system: l.system });
        return (
          <Link
            key={l.system}
            href={href}
            className="vs-filterpill"
            data-active={active || undefined}
            aria-current={active ? 'true' : undefined}
            title={l.hint}
          >
            {l.label}
          </Link>
        );
      })}
    </nav>
  );
}
