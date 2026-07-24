'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import { IconSignOut, IconChevronDown } from '@/components/ui/icons';

/* User menu — identity + sign out in the top-right.
 *
 * Sign-out is the one auth WRITE the console does from the browser (the login form is the other).
 * It clears the Supabase session cookie via the browser client, then router.replace('/login') and
 * refresh() so the Server Components re-run without a session and proxy.ts keeps the user out.
 * There is no client-side "am I allowed" check here — RLS and proxy are the guarantee; this button
 * only ends the session.
 *
 * A menu, not a bare button, because it is where account/tenant affordances will accrete (switch
 * tenant, profile). Today it holds identity + sign out, and closes on Escape or outside click like
 * any menu should.
 */

export function UserMenu({ email, tenantName }: { email: string | null; tenantName: string }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const initials = (email ?? '?')
    .replace(/@.*/, '')
    .split(/[.\-_]/)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? '')
    .join('') || '?';

  const signOut = async () => {
    setBusy(true);
    try {
      await createClient().auth.signOut();
    } catch {
      // Even if the network call fails, send them to /login; proxy re-checks the session there.
    }
    router.replace('/login');
    router.refresh();
  };

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="vs-usermenu-trigger"
      >
        <span aria-hidden="true" className="vs-avatar">
          {initials}
        </span>
        <span className="vs-usermenu-email">{email ?? 'Account'}</span>
        <span aria-hidden="true" style={{ display: 'inline-flex', color: 'var(--text-muted)' }}>
          <IconChevronDown size={14} />
        </span>
      </button>

      {open && (
        <div
          role="menu"
          aria-label="Account"
          style={{
            position: 'absolute',
            top: 'calc(100% + 6px)',
            right: 0,
            zIndex: 'var(--z-overlay)',
            minWidth: 220,
            background: 'var(--surface-raised)',
            border: '1px solid var(--border-strong)',
            borderRadius: 'var(--radius-md)',
            boxShadow: 'var(--shadow-popover)',
            overflow: 'hidden',
          }}
        >
          <div style={{ padding: 'var(--space-3)', borderBottom: '1px solid var(--border)' }}>
            <div style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
              {tenantName}
            </div>
            <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', marginTop: 2, wordBreak: 'break-all' }}>
              {email ?? 'Signed in'}
            </div>
          </div>
          <button
            type="button"
            role="menuitem"
            onClick={signOut}
            disabled={busy}
            className="vs-menuitem"
          >
            <span aria-hidden="true" style={{ display: 'inline-flex' }}>
              <IconSignOut size={16} />
            </span>
            {busy ? 'Signing out…' : 'Sign out'}
          </button>
        </div>
      )}
    </div>
  );
}
