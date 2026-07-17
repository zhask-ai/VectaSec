'use client';

/* Sign-in. Deliberately email+password only: SSO/SAML is an enterprise-tier concern and a magic-link
 * flow needs mail infrastructure we do not have yet. Keep this boring.
 *
 * The session lands in cookies via @supabase/ssr's browser client, and proxy.ts refreshes it on
 * subsequent requests. Authorization itself is never decided here — RLS is the guarantee.
 */
import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { createClient } from '@/lib/supabase/client';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);

    const supabase = createClient();
    const { error } = await supabase.auth.signInWithPassword({ email, password });

    if (error) {
      // Never reflect *why* it failed (unknown user vs wrong password) — that is a user-enumeration
      // oracle on a security product's own front door.
      setError('Invalid email or password.');
      setBusy(false);
      return;
    }
    // refresh() so the Server Components re-run with the new session cookie attached.
    router.replace('/');
    router.refresh();
  }

  const field: React.CSSProperties = {
    width: '100%',
    padding: '8px 10px',
    background: 'var(--surface)',
    color: 'var(--text-primary)',
    // --border fails SC 1.4.11's 3:1 for controls; --border-interactive is the token that passes.
    border: '1px solid var(--border-interactive)',
    borderRadius: 'var(--radius-sm, 6px)',
    fontSize: 'var(--text-sm)',
  };

  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '60dvh' }}>
      <Card style={{ width: 360 }}>
        <CardHeader>
          <CardTitle>Sign in</CardTitle>
        </CardHeader>
        <CardBody>
          <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12 }}>
            <div style={{ display: 'grid', gap: 6 }}>
              <label htmlFor="email" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                autoComplete="username"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                style={field}
              />
            </div>
            <div style={{ display: 'grid', gap: 6 }}>
              <label htmlFor="password" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={field}
              />
            </div>

            {error && (
              // role=alert so it is announced; colour is not the only signal — the text says it.
              // --sev-critical-fg, with no var() fallback: a fallback hex is what let the old
              // `var(--sev-high-text, #FF9A9E)` here ship a colour that never re-themed and sat
              // at 2.03:1 on the light-mode card. A token that does not resolve should break
              // loudly in review, not silently paint an unreadable literal.
              <p role="alert" style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--sev-critical-fg)' }}>
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={busy}
              style={{
                padding: '9px 12px',
                background: busy ? 'var(--surface-raised)' : 'var(--accent)',
                color: busy ? 'var(--text-secondary)' : 'var(--accent-fg)',
                border: '1px solid var(--border-interactive)',
                borderRadius: 'var(--radius-sm, 6px)',
                fontSize: 'var(--text-sm)',
                fontWeight: 600,
                cursor: busy ? 'default' : 'pointer',
              }}
            >
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}
