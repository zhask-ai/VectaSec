'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import type { RealtimeChannel } from '@supabase/supabase-js';

import { createClient } from '@/lib/supabase/client';

/* The live layer: a small client island for an otherwise server-rendered queue.
 *
 * ── Why a pill and not an auto-refresh ────────────────────────────────────────────────────
 * It would be one line shorter to call router.refresh() on every INSERT. Don't. An analyst
 * working a queue is reading a sorted table; re-sorting it under their cursor loses their
 * place and — because the row they were about to click moves — invites a click on the wrong
 * finding. In a tool whose actions are suppressions and triage decisions, that is a real
 * misfire, not a cosmetic annoyance. The pill defers the disruption to a moment the analyst
 * chooses. Interruption is opt-in.
 *
 * ── Why INSERT is exactly "new" ───────────────────────────────────────────────────────────
 * Findings dedupe by fingerprint: the same issue seen on a later scan UPDATEs `last_seen` on
 * the existing row and never inserts a second one (see lib/types.ts, supabase/migrations).
 * So an INSERT on this table is a genuinely novel finding, and "N new findings" is literally
 * true rather than approximately true. That property is what makes this component honest —
 * if the dedupe contract ever changes, this count silently becomes a lie, so the two must be
 * read together.
 *
 * ── Realtime authorization, and failing silently ──────────────────────────────────────────
 * This needs TWO things that are not in the migrations as of this build:
 *
 *   1. `findings` must be in the `supabase_realtime` publication:
 *        alter publication supabase_realtime add table findings;
 *   2. Realtime authorization must permit the subscriber. The channel below is private, so
 *      Realtime checks an RLS policy on `realtime.messages` for the topic — a table-level
 *      SELECT policy on `findings` is NOT sufficient on its own.
 *
 * Without both, the channel never reaches SUBSCRIBED and this component renders nothing,
 * forever. That is the intended behaviour and it is why there is no error state: the live
 * layer is an enhancement over a page that is already correct without it. A console for
 * security engineers must never show a red banner about its own websocket next to the
 * findings it is reporting — the user cannot tell our infrastructure problem from their
 * security problem, and we would be spending their alarm on ourselves.
 *
 * ── Mounting ──────────────────────────────────────────────────────────────────────────────
 * This file is owned separately from app/findings/page.tsx. To mount it, that page (a Server
 * Component) resolves the tenant under RLS and passes the id down:
 *
 *     const supabase = await createClient();
 *     const { data } = await supabase.from('tenants').select('id').limit(1);
 *     // …in the page header, beside the title:
 *     {data?.[0] && <LiveFindings tenantId={data[0].id} />}
 *
 * `tenants` is RLS-scoped to the caller's memberships, so this cannot name a foreign tenant.
 * The id is not a secret — it is already the filter on every row the page renders — but it is
 * the only thing that should cross to the client here: never pass the row.
 */

export function LiveFindings({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (!tenantId) return;

    const supabase = createClient();
    let cancelled = false;
    let channel: RealtimeChannel | null = null;

    void (async () => {
      // A private channel is authorized per-subscriber, so the socket needs the user's token
      // before it joins — after subscribe() is too late. setAuth() with no argument re-reads
      // the current session rather than pinning a token that would go stale on refresh.
      try {
        await supabase.realtime.setAuth();
      } catch {
        // No token, no live layer. The page is already correct without one.
        return;
      }
      if (cancelled) return;

      channel = supabase
        .channel(`findings:${tenantId}`, { config: { private: true } })
        .on(
          'postgres_changes',
          {
            event: 'INSERT',
            schema: 'public',
            table: 'findings',
            // Defence in depth, not the boundary: Realtime's own authorization is what keeps
            // another tenant's rows off this socket. This filter just spares us the traffic.
            filter: `tenant_id=eq.${tenantId}`,
          },
          () => {
            if (!cancelled) setCount((n) => n + 1);
          },
        )
        .subscribe();
      // No status callback on purpose: CHANNEL_ERROR and TIMED_OUT are the expected states
      // when Realtime authorization is not configured, and there is nothing to tell the user.
    })();

    return () => {
      cancelled = true;
      if (channel) void supabase.removeChannel(channel);
    };
  }, [tenantId]);

  return (
    // The live region wraps the conditional, not the pill: an aria-live element must exist in
    // the DOM before the text arrives, or the announcement is missed.
    <div aria-live="polite" aria-atomic="true">
      {count > 0 && (
        <button
          type="button"
          onClick={() => {
            // Reset first: refresh() is async, and any finding that lands between the request
            // and the re-render still deserves to be counted rather than swallowed.
            setCount(0);
            router.refresh();
          }}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 'var(--space-2)',
            height: 'var(--row-compact)',
            padding: '0 var(--space-3)',
            // --border-interactive is the only border token that clears SC 1.4.11's 3:1, and
            // it is the sole non-text indicator that this is a control.
            border: '1px solid var(--border-interactive)',
            borderRadius: 'var(--radius-full)',
            background: 'var(--surface-raised)',
            // --text-secondary, never --text-muted: muted is 4.37:1 on --surface-raised.
            color: 'var(--text-primary)',
            fontFamily: 'inherit',
            fontSize: 'var(--text-xs)',
            lineHeight: 'var(--leading-xs)',
            fontWeight: 500,
            cursor: 'pointer',
          }}
        >
          <span
            aria-hidden="true"
            style={{
              width: 6,
              height: 6,
              borderRadius: 'var(--radius-full)',
              background: 'var(--sev-low-solid)',
            }}
          />
          <span data-numeric>
            {count} new finding{count === 1 ? '' : 's'}
          </span>
          <span style={{ color: 'var(--text-secondary)' }}>· refresh</span>
        </button>
      )}
    </div>
  );
}
