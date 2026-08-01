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
import { AuthShell } from '@/components/auth/AuthShell';
import { AuthAlert, PasswordField, SubmitButton, TextField } from '@/components/auth/fields';
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

  return (
    <AuthShell>
      {confirmSent ? (
        <div className="vs-auth-mailbox">
          <span className="vs-auth-mailbox-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <rect x="3" y="5" width="18" height="14" rx="2" />
              <path d="M3.5 7l8.5 6 8.5-6" />
            </svg>
          </span>
          <h1 className="vs-auth-title" style={{ margin: 0 }}>
            Check your inbox
          </h1>
          <p className="vs-auth-sub" style={{ margin: 0 }}>
            We sent a confirmation link to{' '}
            <strong style={{ color: 'var(--text-primary)', overflowWrap: 'anywhere' }}>{email}</strong>.
            Open it in this browser and you will land signed in, ready to name your organization.
          </p>
          <p className="vs-auth-help" style={{ margin: 0 }}>
            Nothing arriving? Check spam, or{' '}
            <Link href="/login" className="vs-auth-link">
              try signing in
            </Link>{' '}
            — the address may already have an account.
          </p>
        </div>
      ) : (
        <>
          <h1 className="vs-auth-title">Create your account</h1>
          <p className="vs-auth-sub">
            Connect your stack and get your first posture score in minutes.
          </p>

          <GoogleButton label="Continue with Google" />
          <AuthDivider label="or continue with email" />

          <form onSubmit={onSubmit}>
            <TextField
              label={
                <>
                  Your name <span style={{ color: 'var(--text-muted)', fontWeight: 400 }}>(optional)</span>
                </>
              }
              type="text"
              autoComplete="name"
              placeholder="Ada Lovelace"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
            />
            <TextField
              label="Work email"
              type="email"
              required
              autoComplete="username"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <PasswordField
              label="Password"
              required
              minLength={8}
              autoComplete="new-password"
              placeholder="At least 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              showStrength
              help="At least 8 characters."
            />

            {error && <AuthAlert tone="error">{error}</AuthAlert>}

            <SubmitButton busy={busy} busyLabel="Creating account…">
              Create account
            </SubmitButton>
          </form>

          <p className="vs-auth-switch">
            Already have an account?{' '}
            <Link href="/login" className="vs-auth-link">
              Sign in
            </Link>
          </p>
        </>
      )}
    </AuthShell>
  );
}
