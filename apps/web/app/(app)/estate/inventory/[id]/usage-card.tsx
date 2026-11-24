import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* "Seen using this" — who the runtime evidence saw using this resource, first and last sighting
 * (engine: impact.usage_history). The auditor question operators say they cannot answer: "who
 * consumed from this topic last quarter". Shown only for kinds that can carry usage, and always
 * with the observation window, because "not seen" before the window began means nothing. */

type Row = { principal: string; peer_host: string; first_seen: string; last_seen: string; observed_scans: number; via: string };
type Usage = { supported: boolean; rows: Row[]; principals: string[]; observation_started_at: string | null; note: string };

const KINDS = new Set(['topic', 'vhost', 'redis_server', 'nats_server', 'pgbouncer_pool', 'pgbouncer_database', 'queue']);
const day = (iso: string | null) => (iso ? new Date(iso).toISOString().slice(0, 10) : 'never');

export async function UsageCard({ resourceId, kind }: { resourceId: string; kind: string }) {
  if (!KINDS.has(kind)) return null;
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const res = await engineGet<Usage>(`/access/usage/${resourceId}`, { tenantId: membership.tenantId, actor });
  if (!res.ok || !res.data.supported) return null;
  const d = res.data;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Seen using this</CardTitle>
        <CardMeta>
          {d.principals.length} client{d.principals.length === 1 ? '' : 's'} · watched since {day(d.observation_started_at)}
        </CardMeta>
      </CardHeader>
      <CardBody pad={d.rows.length === 0}>
        {d.rows.length === 0 ? (
          <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
            No client has been seen using it since {day(d.observation_started_at)}.
          </p>
        ) : (
          <Table density="compact" caption="Clients seen using this resource">
            <THead>
              <TR>
                <TH width="30%">Who</TH>
                <TH width="20%">From</TH>
                <TH width="14%">First seen</TH>
                <TH width="14%">Last seen</TH>
                <TH width="10%" numeric>
                  Scans
                </TH>
                <TH width="12%">How</TH>
              </TR>
            </THead>
            <TBody>
              {d.rows.map((r, i) => (
                <TR key={i}>
                  <TD mono>{r.principal}</TD>
                  <TD muted>{r.peer_host || '—'}</TD>
                  <TD muted>{day(r.first_seen)}</TD>
                  <TD muted>{day(r.last_seen)}</TD>
                  <TD numeric>{r.observed_scans}</TD>
                  <TD muted>{r.via}</TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </CardBody>
      <CardFooter>
        {d.note}{' '}
        <a href={`/api/reports/usage?id=${resourceId}`}>Download for an auditor (CSV)</a>
      </CardFooter>
    </Card>
  );
}
