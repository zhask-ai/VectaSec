import Link from 'next/link';
import type { Route } from 'next';
import { IconChevronRight } from './icons';

/* Breadcrumbs — the trail back out of a detail view (a finding, an asset). The console is broad
 * and shallow by design, so this appears only where there IS depth: findings/[id], assets/[id].
 * On a top-level section it would be a single dead crumb, which is noise, so those pages simply
 * do not render it.
 *
 * The last crumb is the current page: it is text, not a link (aria-current="page"), because a
 * link to where you already are is a small lie. Every earlier crumb is a real, typed Route —
 * typedRoutes makes a dead trail a build error.
 */

export type Crumb = { label: string; href?: Route };

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb">
      <ol
        style={{
          listStyle: 'none',
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 'var(--space-1)',
          margin: 0,
          padding: 0,
          fontSize: 'var(--text-2xs)',
        }}
      >
        {items.map((item, i) => {
          const last = i === items.length - 1;
          return (
            <li key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)', minWidth: 0 }}>
              {item.href && !last ? (
                <Link
                  href={item.href}
                  style={{ color: 'var(--text-secondary)', textDecoration: 'none', whiteSpace: 'nowrap' }}
                >
                  {item.label}
                </Link>
              ) : (
                <span
                  aria-current={last ? 'page' : undefined}
                  style={{
                    color: last ? 'var(--text-primary)' : 'var(--text-secondary)',
                    fontWeight: last ? 600 : 400,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {item.label}
                </span>
              )}
              {!last && (
                <span aria-hidden="true" style={{ color: 'var(--text-muted)', display: 'inline-flex' }}>
                  <IconChevronRight size={12} />
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
