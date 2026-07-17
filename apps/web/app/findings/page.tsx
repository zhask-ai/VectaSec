import Link from 'next/link';

import { LiveFindings } from '@/components/LiveFindings';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { getFindingsView, LIST_LIMIT } from './data';
import { FindingsTable } from './findings-table';
import { Filters } from './filters';
import { hasActiveFilters, parseFilters, toSearchParams } from './query';

/* The findings queue.
 *
 * A Server Component: the query, the grouping and the sort all happen here, and the client gets
 * a DTO. Filter state arrives in searchParams — so this route is dynamic, never prerendered,
 * and a filtered view is a URL an analyst can paste into Slack.
 *
 * Reads run under RLS as `authenticated`. There is no tenant filter anywhere in the DAL, and
 * that is the design: the policy is the boundary.
 */

export const metadata = { title: 'Findings · VectaSec' };

// PageProps<'/findings'> is generated from the route tree, so params/searchParams cannot drift
// from the actual route. Hand-writing the shape would compile happily against a route that no
// longer exists.
export default async function FindingsPage({ searchParams }: PageProps<'/findings'>) {
  const sp = await searchParams;
  const filters = parseFilters(sp);
  const view = await getFindingsView(filters);
  const filtered = hasActiveFilters(filters);

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
            Findings
          </h1>
          {/* The live island. A small client component in an otherwise server-rendered queue: it
              shows a "N new" pill only when a genuinely novel finding is inserted (findings dedupe
              by fingerprint, so an INSERT is new), and refreshing is opt-in — it never re-sorts the
              table under the analyst's cursor. Degrades to nothing when Realtime is not authorized;
              the page is already correct without it. */}
          {view.state === 'ok' && view.tenantId && <LiveFindings tenantId={view.tenantId} />}
        </div>
        {filtered && (
          <Link href="/findings" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            Clear filters
          </Link>
        )}
      </div>

      {view.state === 'error' && <ErrorPanel message={view.message} />}

      {view.state === 'no-connections' && (
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="Connect your first system"
              description="VectaSec scans the integration layer — Kafka, Kong, RabbitMQ, MCP. Nothing is connected yet, so there is nothing to find."
            />
          </CardBody>
        </Card>
      )}

      {view.state === 'never-scanned' && (
        <Card>
          <CardBody>
            <EmptyState
              tone="pending"
              title="Connected. First scan pending."
              description="Collection has not run yet. Findings appear here once the first scan completes."
              meta={`${view.connections} connection${view.connections === 1 ? '' : 's'} configured`}
            />
          </CardBody>
        </Card>
      )}

      {view.state === 'ok' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 200px) minmax(0, 1fr)', gap: 'var(--space-4)', alignItems: 'start' }}>
          <Filters filters={filters} facets={view.facets} assessmentFacet={view.assessmentFacet} total={view.total} />

          <Card>
            <CardHeader>
              <CardTitle>
                {view.groups.length} rule{view.groups.length === 1 ? '' : 's'}
              </CardTitle>
              {/* Provenance, always. An unlabelled count is an untrustworthy count, and a stale
                  view with no "as of" reads as fresh. */}
              <CardMeta>
                {view.total} finding{view.total === 1 ? '' : 's'}
                {view.scannedAtLabel ? ` · scanned ${view.scannedAtLabel}` : ''}
              </CardMeta>
            </CardHeader>

            <CardBody pad={false}>
              {/* Three zero states, not two, and the third is the one everyone gets wrong.
                  "Your filter is too narrow" is only true if there is something to filter — so a
                  tenant with NO findings at all reads as clean even with filters set, because
                  that is the fact. Telling a clean tenant "no matches" implies findings exist
                  behind the filter; telling a filtered view "you are secure" implies the
                  opposite. In a security tool both are the same bug. */}
              {view.total === 0 && filtered && view.tenantHasFindings && (
                <EmptyState
                  tone="filtered"
                  title="No findings match these filters"
                  description="Findings exist in this tenant, but none match the current severity, status, and rule filters."
                  action={
                    <Link href="/findings" style={{ fontSize: 'var(--text-sm)', color: 'var(--sev-low-fg)' }}>
                      Clear filters
                    </Link>
                  }
                />
              )}

              {view.total === 0 && (!filtered || !view.tenantHasFindings) && (
                <EmptyState
                  tone="clean"
                  title="No findings"
                  description={
                    filtered
                      ? 'Every rule passed on the last scan of every connected system. Filters are active, but there is nothing to filter.'
                      : 'Every rule passed on the last scan of every connected system.'
                  }
                  // Provenance is required here: a zero with no "what was scanned, and when"
                  // reads as broken rather than as clean.
                  meta={
                    view.scannedAtLabel
                      ? `${view.connections} connection${view.connections === 1 ? '' : 's'} scanned ${view.scannedAtLabel}`
                      : `${view.connections} connection${view.connections === 1 ? '' : 's'}`
                  }
                />
              )}

              {view.total > 0 && view.groups.length === 0 && (
                // total counts every matching row; groups only holds the page we fetched. If
                // one is zero and the other is not, the pairing is broken — say so instead of
                // rendering an empty table that looks like "clean".
                <ErrorPanel message="The findings count and the findings themselves disagree. This is a bug in the console, not a clean result — please report it." />
              )}

              {view.groups.length > 0 && (
                // Remount on a filter change: expansion state describes the previous result set
                // and carrying it across a new query is how a row appears already-expanded for
                // no reason the user can explain.
                <FindingsTable key={toSearchParams(filters)} groups={view.groups} />
              )}
            </CardBody>

            {view.truncated && (
              <CardFooter>
                Showing the {view.shown} most recent of {view.total} matching findings. Narrow the filters to see
                the rest — beyond {LIST_LIMIT} rows the answer is a filter, not a longer page.
              </CardFooter>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}

/** Not an <EmptyState tone="error">, which now exists and is what the other pages use: this one
 * is an inline banner rather than a centred card-filling zero-state, and it is also used at the
 * count/rows-disagree site above, which is not an empty state at all. Same guarantees either
 * way — role="alert", and it says in words that a failed read is not a result of zero. Telling
 * an analyst their estate is empty because Postgres was unreachable is the single worst thing
 * this page could say. */
function ErrorPanel({ message }: { message: string }) {
  return (
    <div
      role="alert"
      style={{
        display: 'grid',
        gap: 'var(--space-1)',
        padding: 'var(--space-4)',
        border: '1px solid var(--sev-critical-solid)',
        borderRadius: 'var(--radius-md)',
        background: 'var(--sev-critical-bg)',
      }}
    >
      <strong style={{ fontSize: 'var(--text-sm)', color: 'var(--sev-critical-fg)' }}>
        Could not load findings
      </strong>
      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{message}</span>
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
        This is a failure to read, not a clean result. Do not read it as "no findings".
      </span>
    </div>
  );
}
