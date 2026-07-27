'use client';

/* Set-a-password, for arrivals whose session exists but whose password does not: invited
 * members (the engine's GoTrue invite) and recovery links. Skipping is allowed — the session
 * works without it — but then the invite link is their only way back in, so the page says so.
 */
import { useState } from 'react';
import { useRouter } from 'next/navigation';

import { createClient } from '@/lib/supabase/client';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';

export default function WelcomePage() {
  const router = useRouter();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    setBusy(true);
    setError(null);
    const supabase = createClient();
    const { error } = await supabase.auth.updateUser({ password });
    if (error) {
      setError(error.message);
      setBusy(false);
      return;
    }
    router.replace('/');
    router.refresh();
  }

  const field: React.CSSProperties = {
    width: '100%',
    padding: '8px 10px',
    background: 'var(--surface)',
    color: 'var(--text-primary)',
    border: '1px solid var(--border-interactive)',
    borderRadius: 'var(--radius-sm, 6px)',
    fontSize: 'var(--text-sm)',
  };

  return (
    <div style={{ display: 'grid', placeItems: 'center', minHeight: '60dvh' }}>
      <Card style={{ width: 380 }}>
        <CardHeader>
          <CardTitle>Welcome — set your password</CardTitle>
        </CardHeader>
        <CardBody>
          <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12 }}>
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
              You are signed in via your email link. Set a password now so you can sign in again
              later without it.
            </p>
            <div style={{ display: 'grid', gap: 6 }}>
              <label htmlFor="password" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                New password
              </label>
              <input
                id="password"
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={field}
              />
            </div>
            <div style={{ display: 'grid', gap: 6 }}>
              <label htmlFor="confirm" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                Confirm password
              </label>
              <input
                id="confirm"
                type="password"
                required
                minLength={8}
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                style={field}
              />
            </div>

            {error && (
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
              {busy ? 'Saving…' : 'Save and continue'}
            </button>
            <button
              type="button"
              onClick={() => {
                router.replace('/');
                router.refresh();
              }}
              style={{
                padding: '6px 12px',
                background: 'transparent',
                color: 'var(--text-secondary)',
                border: 'none',
                fontSize: 'var(--text-2xs)',
                cursor: 'pointer',
              }}
            >
              Skip for now
            </button>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}
