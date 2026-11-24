import { createClient } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { StatusPill } from '@/components/ui/status-pill';
import { OwnerForm } from './owner-form';

/* Owner of a machine identity, and when a person last confirmed it.
 *
 * Operators' loudest complaint is that nobody can say who owns a key, so nobody dares remove it.
 * A scan can only infer an owner (a tag, a creator field). This card shows what was confirmed,
 * by whom and when, and lets an editor confirm or change it; re-confirming refreshes "last
 * verified", which is what an access review asks for. */

const day = (iso: string) => new Date(iso).toISOString().slice(0, 10);

export async function OwnerCard({ resourceId, extId, inferred, editable }: { resourceId: string; extId: string; inferred: string | null; editable: boolean }) {
  const supabase = await createClient();
  const res = await supabase.from('identity_owners').select('owner, note, verified_at').eq('identity_ext_id', extId).maybeSingle();
  if (res.error) return null; // table not migrated yet: the page works without the card
  const c = res.data as { owner: string; note: string; verified_at: string } | null;
  const stale = c ? Date.now() - new Date(c.verified_at).getTime() > 90 * 86_400_000 : false;

  return (
    <Card accent={!c}>
      <CardHeader>
        <CardTitle>Owner</CardTitle>
        <CardMeta>{c ? `last verified ${day(c.verified_at)}` : 'not confirmed'}</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
          <span style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
            {c ? (
              <>
                <strong style={{ fontSize: 'var(--text-sm)' }}>{c.owner}</strong>
                <StatusPill tone={stale ? 'warn' : 'ok'} variant="soft" label={stale ? 'Re-confirm: over 90 days' : 'Confirmed'} />
              </>
            ) : inferred ? (
              <>
                <strong style={{ fontSize: 'var(--text-sm)' }}>{inferred}</strong>
                <StatusPill tone="neutral" label="Inferred from a tag, not confirmed" />
              </>
            ) : (
              <StatusPill tone="warn" variant="soft" label="Nobody is recorded as owning this" />
            )}
          </span>
          {c?.note && <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>{c.note}</p>}
          <OwnerForm resourceId={resourceId} current={c?.owner ?? inferred ?? ''} editable={editable} confirmed={!!c} />
        </div>
      </CardBody>
      <CardFooter>
        Confirmed owners appear in the access register, the leaver report and breach-day rotation
        lists. Every change is recorded in the audit log.
      </CardFooter>
    </Card>
  );
}
