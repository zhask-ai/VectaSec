'use client';

import { useEffect, useState } from 'react';
import { IconSun, IconMoon } from '@/components/ui/icons';

/* Theme toggle. Light is the default; this flips to an EXPLICIT choice that wins over
 * prefers-color-scheme both ways, and persists it.
 *
 * The mechanism is a single attribute on <html>: `data-theme="light" | "dark"`. globals.css keys
 * both the explicit override and the `prefers-color-scheme` media query off it, so setting the
 * attribute is the whole switch. The value is mirrored to localStorage under `vs-theme`, and an
 * inline script in the root layout applies it BEFORE first paint — without that, an explicit-dark
 * user would see a white flash on every load. That script is the reason this component can render
 * a stable initial icon and correct it after mount without a layout shift.
 */

type Theme = 'light' | 'dark';

function effectiveTheme(): Theme {
  const attr = document.documentElement.dataset.theme;
  if (attr === 'light' || attr === 'dark') return attr;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export function ThemeToggle() {
  // Initial render matches the light default (SSR has no data-theme); corrected on mount.
  const [theme, setTheme] = useState<Theme>('light');
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setTheme(effectiveTheme());
    setMounted(true);
  }, []);

  const toggle = () => {
    const next: Theme = theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem('vs-theme', next);
    } catch {
      // Private mode / disabled storage: the toggle still works for this session.
    }
    setTheme(next);
  };

  const goingTo = theme === 'dark' ? 'light' : 'dark';

  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={`Switch to ${goingTo} theme`}
      title={`Switch to ${goingTo} theme`}
      className="vs-iconbtn"
    >
      {/* Before mount, show the light-default icon; after mount it reflects the real theme. */}
      <span aria-hidden="true" style={{ display: 'inline-flex' }}>
        {mounted && theme === 'dark' ? <IconSun size={16} /> : <IconMoon size={16} />}
      </span>
    </button>
  );
}
