'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

/* Polling refresh for pages that are WATCHING something move (a queued scan becoming
 * running becoming done). Renders nothing.
 *
 * This is the deliberate opposite of LiveFindings' pill: an analyst reading a findings queue
 * must not have the table re-sorted under their cursor, but a human who just clicked
 * "Scan now" is *waiting* — for them, silent staleness is the failure mode, not motion. So
 * the server component decides: it mounts this only while something is actually in flight
 * (`active`), and the page goes back to fully static the render after the last scan lands.
 *
 * Polling, not Realtime, on purpose: it needs no publication, no realtime.messages policy,
 * and it cannot fail silently — the exact traps LiveFindings documents. Refresh is skipped
 * while the tab is hidden; the one on return catches everything missed.
 */
export function AutoRefresh({ active, intervalMs = 3000 }: { active: boolean; intervalMs?: number }) {
  const router = useRouter();

  useEffect(() => {
    if (!active) return;

    const tick = () => {
      if (!document.hidden) router.refresh();
    };
    const id = setInterval(tick, intervalMs);
    document.addEventListener('visibilitychange', tick);
    return () => {
      clearInterval(id);
      document.removeEventListener('visibilitychange', tick);
    };
  }, [active, intervalMs, router]);

  return null;
}
