'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { IconSearch } from '@/components/ui/icons';

/* Global search affordance in the top bar.
 *
 * Scoped to what exists today: the findings queue already understands a `rule` prefix filter and
 * carries it in the URL, so search here routes to `/findings?rule=<q>` — a real, shareable query,
 * not a fake command palette that does nothing. When a cross-entity search backend lands, this is
 * the single seam a page agent widens; until then it is honest about being a findings jump.
 *
 * ⌘K / Ctrl-K focuses it from anywhere, which is the muscle memory analysts arrive with. It is a
 * real <form> with a labelled <input>, so it works by keyboard and submits on Enter.
 */

export function GlobalSearch() {
  const router = useRouter();
  const [value, setValue] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <form
      role="search"
      onSubmit={(e) => {
        e.preventDefault();
        const q = value.trim();
        router.push(q ? `/findings?rule=${encodeURIComponent(q)}` : '/findings');
      }}
      className="vs-search"
    >
      <label htmlFor="vs-global-search" className="vs-visually-hidden">
        Search findings by rule
      </label>
      <span aria-hidden="true" className="vs-search-icon">
        <IconSearch size={15} />
      </span>
      <input
        id="vs-global-search"
        ref={inputRef}
        type="search"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Search rules…"
        autoComplete="off"
        spellCheck={false}
        className="vs-search-input"
      />
      <kbd aria-hidden="true" className="vs-search-kbd">
        ⌘K
      </kbd>
    </form>
  );
}
