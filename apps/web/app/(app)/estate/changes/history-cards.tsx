import Link from 'next/link';
import type { Route } from 'next';

import { createClient } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { ChangeChip, ChangeWindow, FieldDiff, stamp, type ChangeRow } from './_parts';

/* The Time machine on the two pages where the question is asked about ONE thing:
 *
 *   ResourceHistory  (resource page)  "what has happened to this resource?"
 *   OpenedWhen       (finding page)   "when did this open, and what changed to open it?"
 *
 * Both read `resource_changes` under RLS. Both render NOTHING when the table cannot be read
 * (a database without migration 20261123000001): these are additions to pages that already
 * work, and a missing history must not put an error card on them. The History tab is where
 * that state is explained.
 */

const COLS =
  'id, resource_id, connection_id, kind, name, change, fields, field_count, actor, prev_seen_at, observed_at';

const SCAN_SLACK_MS = 15 * 60_000;

export async function ResourceHistory({ resourceId }: { resourceId: string }) {
  const supabase = await createClient();
  const res = await supabase
    .from('resource_changes')
    .select(COLS, { count: 'exact' })
    .eq('resource_id', resourceId)
    .order('observed_at', { ascending: false })
    .limit(15);
  if (res.error) return null;
  const rows = (res.data ?? []) as unknown as ChangeRow[];
  const total = res.count ?? rows.length;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change history</CardTitle>
        <CardMeta>{total === 0 ? 'none recorded' : `${total} change${total === 1 ? '' : 's'} · newest first`}</CardMeta>
      </CardHeader>
      <CardBody>
        {rows.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            No scan has seen this resource change since history started. The configuration below is
            what every scan since then returned.
          </p>
        ) : (
          <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-4)' }}>
            {rows.map((r) => (
              <li
                key={r.id}
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'minmax(120px, 160px) minmax(0, 1fr)',
                  gap: 'var(--space-4)',
                  alignItems: 'start',
                }}
              >
                <span style={{ display: 'grid', gap: 'var(--space-1)', justifyItems: 'start' }}>
                  <ChangeChip change={r.change} />
                  <ChangeWindow row={r} />
                </span>
                <span style={{ display: 'grid', gap: 'var(--space-1)', minWidth: 0 }}>
                  <FieldDiff row={r} lead={4} />
                  {r.actor && (
                    <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>by {r.actor}</span>
                  )}
                </span>
              </li>
            ))}
          </ol>
        )}
      </CardBody>
      {total > rows.length && (
        <CardFooter>
          Showing the newest {rows.length} of {total}.{' '}
          <Link href={'/estate/changes?days=365' as Route}>Open History</Link> for the rest.
        </CardFooter>
      )}
    </Card>
  );
}

/** "When did this open". Three honest answers, in order of how much we can prove:
 *
 *  1. The scan that first raised the finding also recorded a configuration change on the same
 *     resource → show that change: it happened in that window and is the likely cause.
 *  2. The resource itself first appeared in that scan → it was like this when it was created
 *     or when VectaSec first saw it; there is no "before" to compare.
 *  3. Neither → the finding appeared with no recorded configuration change (a new rule, a
 *     change in something the scan does not diff, or history not yet on). Say so.
 */
export async function OpenedWhen({ findingId }: { findingId: string }) {
  const supabase = await createClient();
  const fRes = await supabase
    .from('findings')
    .select('first_seen, resource_id, resources(first_seen, connection_id)')
    .eq('id', findingId)
    .maybeSingle();
  if (fRes.error || !fRes.data) return null;
  const f = fRes.data as unknown as {
    first_seen: string;
    resource_id: string | null;
    resources: { first_seen: string; connection_id: string | null } | null;
  };
  if (!f.resource_id) return null;

  const t = new Date(f.first_seen).getTime();
  const lo = new Date(t - SCAN_SLACK_MS).toISOString();
  const hi = new Date(t + SCAN_SLACK_MS).toISOString();

  const [changeRes, prevScanRes] = await Promise.all([
    supabase
      .from('resource_changes')
      .select(COLS)
      .eq('resource_id', f.resource_id)
      .gte('observed_at', lo)
      .lte('observed_at', hi)
      .order('observed_at', { ascending: false })
      .limit(1),
    f.resources?.connection_id
      ? supabase
          .from('scans')
          .select('finished_at')
          .eq('connection_id', f.resources.connection_id)
          .eq('status', 'done')
          .lt('finished_at', lo)
          .order('finished_at', { ascending: false })
          .limit(1)
      : Promise.resolve({ data: [], error: null }),
  ]);
  if (changeRes.error) return null;

  const change = ((changeRes.data ?? []) as unknown as ChangeRow[])[0] ?? null;
  const prevScan = ((prevScanRes.data ?? []) as { finished_at: string | null }[])[0]?.finished_at ?? null;
  const bornWithIt =
    f.resources !== null && Math.abs(new Date(f.resources.first_seen).getTime() - t) <= SCAN_SLACK_MS;

  const p: React.CSSProperties = { margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' };

  return (
    <Card>
      <CardHeader>
        <CardTitle>When this opened</CardTitle>
        <CardMeta>first raised {stamp(f.first_seen)} UTC</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          {change && change.change !== 'added' ? (
            <>
              <p style={p}>
                The scan that first raised this finding also saw this resource&apos;s configuration
                change. It happened{' '}
                {change.prev_seen_at ? (
                  <>
                    between <strong>{stamp(change.prev_seen_at)}</strong> and{' '}
                    <strong>{stamp(change.observed_at)}</strong> UTC
                  </>
                ) : (
                  <>
                    by <strong>{stamp(change.observed_at)}</strong> UTC
                  </>
                )}
                {change.actor ? <> and the system names <strong>{change.actor}</strong> as the editor</> : null}.
              </p>
              <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'start' }}>
                <ChangeChip change={change.change} />
                <FieldDiff row={change} lead={5} />
              </div>
            </>
          ) : bornWithIt || change?.change === 'added' ? (
            <p style={p}>
              This resource was first seen in the same scan that raised the finding, so it has been
              like this for as long as VectaSec has seen it.
              {prevScan ? (
                <>
                  {' '}
                  The scan before that, at <strong>{stamp(prevScan)}</strong> UTC, did not return the
                  resource: it was created or exposed between those two scans.
                </>
              ) : (
                <> That was the first scan of this connection, so when it was created is not known.</>
              )}
            </p>
          ) : (
            <p style={p}>
              No configuration change was recorded on this resource in the scan that first raised
              the finding.
              {prevScan ? (
                <>
                  {' '}
                  The previous scan finished at <strong>{stamp(prevScan)}</strong> UTC without raising
                  it.
                </>
              ) : null}{' '}
              The cause may be a rule added since, a setting the scan reads but does not compare, or
              history that started after this date.
            </p>
          )}
        </div>
      </CardBody>
      <CardFooter>
        From scan-to-scan comparison, not the system&apos;s audit log.{' '}
        <Link href={`/estate/inventory/${f.resource_id}` as Route}>Full history of this resource</Link>
      </CardFooter>
    </Card>
  );
}
