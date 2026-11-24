'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';

import { createClient } from '@/lib/supabase/client';

/* The ambient scan indicator in the topbar — layout.tsx reserves this spot with the note
 * "a strip here, never a modal. A scan must never block the console."
 *
 * A small polling island: every few seconds it asks Supabase (under RLS — the browser can
 * only ever see its own tenant's scans) for queued/running scans and names what is in
 * flight. When the last active scan finishes it refreshes the current route once, so
 * whatever page you are on picks up the results without being asked — this is the "watch it
 * land" half of clicking Scan now from anywhere.
 *
 * Failure mode is silence, same contract as LiveFindings: the strip is an enhancement over
 * pages that are already correct without it, and a security console must not spend a user's
 * alarm on its own plumbing.
 */

type ActiveScan = {
  id: string;
  status: string;
  connections: { name: string; type: string } | null;
};

const POLL_MS = 4000;
const STALE_AFTER_MS = 6 * 60 * 60 * 1000;

export function ScanStrip() {
  const router = useRouter();
  const [active, setActive] = useState<ActiveScan[]>([]);
  const hadActive = useRef(false);

  useEffect(() => {
    const supabase = createClient();
    let cancelled = false;

    const poll = async () => {
      if (document.hidden) return;
      // Only scans from the last few hours. A job queued for a collector that never came back
      // stays 'queued' for ever; without this window the bar says "scanning" for months.
      const freshSince = new Date(Date.now() - STALE_AFTER_MS).toISOString();
      const { data, error } = await supabase
        .from('scans')
        .select('id, status, connections(name, type)')
        .in('status', ['queued', 'running'])
        .gte('started_at', freshSince)
        .order('started_at', { ascending: false })
        .limit(5);
      if (cancelled || error) return;

      const scans = (data ?? []) as unknown as ActiveScan[];
      setActive(scans);

      // Falling edge: something WAS running and now nothing is — the moment results exist.
      if (hadActive.current && scans.length === 0) router.refresh();
      hadActive.current = scans.length > 0;
    };

    void poll();
    const id = setInterval(() => void poll(), POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [router]);

  if (active.length === 0) return null;

  const label =
    active.length === 1
      ? `${active[0].status === 'queued' ? 'queued' : 'scanning'} ${active[0].connections ? `${active[0].connections.type}/${active[0].connections.name}` : '…'}`
      : `${active.length} scans in flight`;

  return (
    <span
      aria-live="polite"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 'var(--space-2)',
        fontSize: 'var(--text-2xs)',
        color: 'var(--text-secondary)',
        whiteSpace: 'nowrap',
        maxWidth: 220,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
      }}
      title={label}
    >
      <span
        aria-hidden="true"
        style={{
          width: 6,
          height: 6,
          borderRadius: 'var(--radius-full)',
          background: 'var(--sev-medium-fg)',
          animation: 'vs-pulse 1.2s ease-in-out infinite',
        }}
      />
      {label}
      <style>{`@keyframes vs-pulse { 0%,100% { opacity: 1 } 50% { opacity: 0.25 } }`}</style>
    </span>
  );
}
