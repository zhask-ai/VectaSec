'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { Route } from 'next';
import { useRouter } from 'next/navigation';

import { IconArrowUpRight, IconFindings, IconSearch, IconZap } from '@/components/ui/icons';
import { NAV_ITEMS, PLATFORM_ITEMS, SETTINGS_ITEM } from './nav';

/* ⌘K command palette — go anywhere, or act on what you typed.
 *
 * Three kinds of entries, in this order:
 *   1. Ask AI about the text you typed (the Ask page, cited answers).
 *   2. Search findings by rule for the text (the findings queue's real `rule` filter).
 *   3. Every page in the console, filtered by a forgiving match on its name and section.
 *
 * Keyboard first: ⌘K / Ctrl-K or "/" opens it, arrows move, Enter goes, Esc closes. Focus is
 * trapped inside while open and returned to whatever had it before. The top-bar trigger is a
 * real button with the shortcut shown, so it is discoverable by mouse too. */

type Entry = { id: string; label: string; hint: string; href: string; kind: 'page' | 'search' | 'ask' };

const PAGES: Entry[] = [
  ...NAV_ITEMS.flatMap((item) =>
    item.children
      ? item.children.map((c) => ({
          id: c.href,
          label: c.href === item.href ? `${item.label}: ${c.label}` : c.label,
          hint: item.label,
          href: c.href,
          kind: 'page' as const,
        }))
      : [{ id: item.href, label: item.label, hint: 'Page', href: item.href, kind: 'page' as const }],
  ),
  { id: SETTINGS_ITEM.href, label: 'Settings', hint: 'Workspace', href: SETTINGS_ITEM.href, kind: 'page' },
  { id: '/settings/members', label: 'Members and roles', hint: 'Settings', href: '/settings/members', kind: 'page' },
  { id: '/settings/integrations', label: 'Integrations and alerts', hint: 'Settings', href: '/settings/integrations', kind: 'page' },
];
const ADMIN_PAGES: Entry[] = PLATFORM_ITEMS.map((p) => ({ id: p.href, label: p.label, hint: 'Platform', href: p.href, kind: 'page' as const }));

/** Subsequence match with a score: consecutive letters and word starts rank higher. */
function score(text: string, query: string): number {
  const t = text.toLowerCase();
  const q = query.toLowerCase().trim();
  if (!q) return 1;
  if (t.includes(q)) return 100 - t.indexOf(q);
  let ti = 0;
  let s = 0;
  for (const ch of q) {
    const at = t.indexOf(ch, ti);
    if (at < 0) return 0;
    s += at === ti ? 3 : 1;
    if (at === 0 || t[at - 1] === ' ') s += 2;
    ti = at + 1;
  }
  return s;
}

export function CommandPalette({ admin = false }: { admin?: boolean }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const returnTo = useRef<HTMLElement | null>(null);

  const close = useCallback(() => {
    setOpen(false);
    setQuery('');
    setCursor(0);
    returnTo.current?.focus?.();
  }, []);

  const show = useCallback(() => {
    returnTo.current = document.activeElement as HTMLElement | null;
    setOpen(true);
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      // The target is the window or document when nothing is focused, and neither has .closest().
      const typing = e.target instanceof Element && !!e.target.closest('input, textarea, select, [contenteditable="true"]');
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (open) close();
        else show();
      } else if (e.key === '/' && !typing && !open) {
        e.preventDefault();
        show();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, close, show]);

  useEffect(() => {
    if (open) requestAnimationFrame(() => inputRef.current?.focus());
  }, [open]);

  const entries = useMemo<Entry[]>(() => {
    const q = query.trim();
    const pages = [...PAGES, ...(admin ? ADMIN_PAGES : [])]
      .map((p) => ({ p, s: Math.max(score(p.label, q), score(`${p.hint} ${p.label}`, q) - 1) }))
      .filter((x) => x.s > 0)
      .sort((a, b) => b.s - a.s)
      .map((x) => x.p);
    if (!q) return pages;
    const actions: Entry[] = [
      { id: 'ask', label: `Ask: “${q}”`, hint: 'Answered from your stored records', href: `/ask?q=${encodeURIComponent(q)}`, kind: 'ask' },
      { id: 'search', label: `Findings matching “${q}”`, hint: 'Search by rule', href: `/findings?rule=${encodeURIComponent(q)}`, kind: 'search' },
    ];
    // When the text names a page ("leav" → Leavers), going there is the likely intent; when it
    // reads like a question or a rule id, the actions come first.
    const namesAPage = pages.length > 0 && score(pages[0].label, q) >= 90 && !q.includes(' ');
    return namesAPage ? [...pages, ...actions] : [...actions, ...pages];
  }, [query, admin]);

  useEffect(() => setCursor(0), [query]);
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [cursor]);

  const go = (e: Entry | undefined) => {
    if (!e) return;
    close();
    router.push(e.href as Route);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setCursor((c) => Math.min(c + 1, entries.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setCursor((c) => Math.max(c - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      go(entries[cursor]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      close();
    } else if (e.key === 'Tab') {
      e.preventDefault(); // focus stays in the palette while it is open
    }
  };

  // Groups follow the order `entries` chose, so the highlighted first row is always on top.
  const groups: { title: string; items: Entry[] }[] = [];
  for (const e of entries) {
    const title = e.kind === 'page' ? 'Go to' : 'Actions';
    const last = groups[groups.length - 1];
    if (last && last.title === title) last.items.push(e);
    else groups.push({ title, items: [e] });
  }

  return (
    <>
      <button type="button" className="vs-search" onClick={show} aria-haspopup="dialog" aria-label="Search and go to (Command K)">
        <span aria-hidden="true" className="vs-search-icon">
          <IconSearch size={15} />
        </span>
        <span className="vs-search-input" style={{ display: 'flex', alignItems: 'center' }}>
          Search, ask or jump to…
        </span>
        <kbd aria-hidden="true" className="vs-search-kbd">
          ⌘K
        </kbd>
      </button>

      {open &&
        createPortal(
        <div className="vs-cmdk-scrim" onMouseDown={(e) => e.target === e.currentTarget && close()}>
          <div className="vs-cmdk" role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={onKeyDown}>
            <div className="vs-cmdk-input">
              <IconSearch size={18} />
              <input
                ref={inputRef}
                autoFocus
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Type a page, a rule, or a question…"
                aria-label="Search"
                aria-controls="vs-cmdk-list"
                aria-activedescendant={entries[cursor] ? `vs-cmdk-${cursor}` : undefined}
                autoComplete="off"
                spellCheck={false}
              />
            </div>
            <ul className="vs-cmdk-list" id="vs-cmdk-list" role="listbox" ref={listRef}>
              {entries.length === 0 && <li className="vs-cmdk-empty">Nothing matches. Press Esc to close.</li>}
              {groups.map((g) => (
                <li key={g.title} role="presentation">
                  <div className="vs-cmdk-group" aria-hidden="true">
                    {g.title}
                  </div>
                  <ul role="group" aria-label={g.title} style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                    {g.items.map((e) => {
                      const i = entries.indexOf(e);
                      return (
                        <li
                          key={e.id}
                          id={`vs-cmdk-${i}`}
                          role="option"
                          aria-selected={i === cursor}
                          className="vs-cmdk-item"
                          onMouseMove={() => i !== cursor && setCursor(i)}
                          onClick={() => go(e)}
                        >
                          <span className="vs-cmdk-item-icon" aria-hidden="true">
                            {e.kind === 'ask' ? <IconZap size={14} /> : e.kind === 'search' ? <IconFindings size={14} /> : <IconArrowUpRight size={14} />}
                          </span>
                          <span style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.label}</span>
                          <span className="vs-cmdk-item-hint">{e.hint}</span>
                        </li>
                      );
                    })}
                  </ul>
                </li>
              ))}
            </ul>
            <div className="vs-cmdk-foot" aria-hidden="true">
              <span>
                <kbd>↑</kbd>
                <kbd>↓</kbd>move
              </span>
              <span>
                <kbd>↵</kbd>open
              </span>
              <span>
                <kbd>esc</kbd>close
              </span>
              <span style={{ marginLeft: 'auto' }}>
                <kbd>/</kbd>opens this from anywhere
              </span>
            </div>
          </div>
        </div>,
          // Rendered at the document root: the top bar has a backdrop blur, which makes it the
          // containing block for fixed children, so in place the palette sat under the page.
          document.body,
        )}
    </>
  );
}
