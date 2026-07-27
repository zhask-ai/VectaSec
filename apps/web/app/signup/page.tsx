'use client';

/* Self-serve signup. Email+password or Google; either way the user lands authed and the
 * (app) layout routes anyone without an organization to /onboarding to create one.
 *
 * With email confirmations ON (the Supabase default) signUp returns no session — the user
 * gets a confirmation link that lands on /auth/callback. The page says so honestly instead
 * of leaving a dead spinner. With confirmations OFF there is a session immediately and we
 * go straight to onboarding.
 */
import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

import { createClient } from '@/lib/supabase/client';
import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { AuthDivider, GoogleButton } from '@/components/auth/OAuthButtons';

export default function SignupPage() {
  const router = useRouter();
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmSent, setConfirmSent] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);

    const supabase = createClient();
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: `${window.location.origin}/auth/callback`,
        data: fullName.trim() ? { full_name: fullName.trim() } : undefined,
      },
    });

    if (error) {
      setError(error.message);
      setBusy(false);
      return;
    }
    if (data.session) {
      router.replace('/onboarding');
      router.refresh();
      return;
    }
    // No session: confirmations are on, the email is out. (Also the shape Supabase returns
    // for an already-registered address — deliberately indistinguishable, no enumeration.)
    setConfirmSent(true);
    setBusy(false);
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
          <CardTitle>Create your account</CardTitle>
        </CardHeader>
        <CardBody>
          {confirmSent ? (
            <div style={{ display: 'grid', gap: 10 }}>
              <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
                Check your email. We sent a confirmation link to{' '}
                <strong style={{ overflowWrap: 'anywhere' }}>{email}</strong> — open it in this
                browser and you will land signed in, ready to name your organization.
              </p>
              <p style={{ margin: 0, fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                Nothing arriving? Check spam, or try signing in — the address may already have an
                account.
              </p>
            </div>
          ) : (
            <div style={{ display: 'grid', gap: 14 }}>
              <GoogleButton label="Continue with Google" />
              <AuthDivider />
              <form onSubmit={onSubmit} style={{ display: 'grid', gap: 12 }}>
                <div style={{ display: 'grid', gap: 6 }}>
                  <label htmlFor="name" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                    Your name <span style={{ color: 'var(--text-muted)' }}>(optional)</span>
                  </label>
                  <input
                    id="name"
                    type="text"
                    autoComplete="name"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    style={field}
                  />
                </div>
                <div style={{ display: 'grid', gap: 6 }}>
                  <label htmlFor="email" style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                    Work email
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
                    minLength={8}
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
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
                  {busy ? 'Creating account…' : 'Create account'}
                </button>
              </form>
              <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                Already have an account?{' '}
                <Link href="/login" style={{ color: 'var(--text-primary)' }}>
                  Sign in
                </Link>
              </p>
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
