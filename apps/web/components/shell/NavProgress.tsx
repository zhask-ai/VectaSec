'use client';

import { useEffect, useRef, useState } from 'react';
import { usePathname, useSearchParams } from 'next/navigation';

/* A thin progress bar at the top of the window while a page is loading.
 *
 * The App Router has no navigation events, so this listens for what starts a navigation (a
 * click on a same-origin link to a different URL, a GET form submit) and finishes when the
 * pathname or query changes. A safety timeout clears it if a navigation is cancelled. Purely
 * visual and aria-hidden: screen readers get the new page's heading, not a bar. */
export function NavProgress() {
  const pathname = usePathname();
  const search = useSearchParams();
  const [state, setState] = useState<'idle' | 'loading' | 'done'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const start = () => {
      setState('loading');
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setState('done'), 12_000);
    };
    const onClick = (e: MouseEvent) => {
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const a = (e.target as HTMLElement | null)?.closest('a');
      if (!a || a.target === '_blank' || a.hasAttribute('download')) return;
      const href = a.getAttribute('href');
      if (!href || href.startsWith('#') || href.startsWith('/api/')) return;
      const url = new URL(a.href, location.href);
      if (url.origin !== location.origin) return;
      if (url.pathname === location.pathname && url.search === location.search) return;
      start();
    };
    const onSubmit = (e: SubmitEvent) => {
      const f = e.target as HTMLFormElement;
      if (!e.defaultPrevented && (f.method || 'get').toLowerCase() === 'get' && !f.getAttribute('action')?.startsWith('/api/')) start();
    };
    document.addEventListener('click', onClick, true);
    document.addEventListener('submit', onSubmit, true);
    return () => {
      document.removeEventListener('click', onClick, true);
      document.removeEventListener('submit', onSubmit, true);
    };
  }, []);

  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    setState((s) => (s === 'loading' ? 'done' : s));
  }, [pathname, search]);

  return <div className="vs-progress" data-state={state} aria-hidden="true" />;
}
