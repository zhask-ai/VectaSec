'use client';

/* Password recovery. resetPasswordForEmail sends a link that lands on /auth/callback with
 * type=recovery, which already routes to /welcome to set the new password — the flow existed
 * end-to-end; this page is just the missing front door.
 *
 * The sent-state copy is deliberately conditional ("if an account exists…"): confirming which
 * addresses have accounts is a user-enumeration oracle, same rule as the login error. The one
 * error worth surfacing verbatim is Supabase's rate limit — that is honest feedback about the
 * requester, not about the address.
 */
import { useState } from 'react';
import Link from 'next/link';

import { createClient } from '@/lib/supabase/client';
import { AuthShell } from '@/components/auth/AuthShell';
import { AuthAlert, SubmitButton, TextField } from '@/components/auth/fields';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);

    const supabase = createClient();
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/auth/callback`,
    });

    if (error) {
      setError(error.message);
      setBusy(false);
      return;
    }
    setSent(true);
    setBusy(false);
  }

  return (
    <AuthShell>
      {sent ? (
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
            If an account exists for{' '}
            <strong style={{ color: 'var(--text-primary)', overflowWrap: 'anywhere' }}>{email}</strong>,
            a reset link is on its way. Open it in this browser to set a new password.
          </p>
          <p className="vs-auth-help" style={{ margin: 0 }}>
            Nothing after a few minutes? Check spam, then try again.
          </p>
          <Link href="/login" className="vs-auth-link" style={{ fontSize: 'var(--text-sm)' }}>
            ← Back to sign in
          </Link>
        </div>
      ) : (
        <>
          <h1 className="vs-auth-title">Reset your password</h1>
          <p className="vs-auth-sub">
            Enter the email you signed up with and we&rsquo;ll send you a link to set a new one.
          </p>

          <form onSubmit={onSubmit}>
            <TextField
              label="Email"
              type="email"
              required
              autoComplete="username"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />

            {error && <AuthAlert tone="error">{error}</AuthAlert>}

            <SubmitButton busy={busy} busyLabel="Sending link…">
              Send reset link
            </SubmitButton>
          </form>

          <p className="vs-auth-switch">
            Remembered it?{' '}
            <Link href="/login" className="vs-auth-link">
              Back to sign in
            </Link>
          </p>
        </>
      )}
    </AuthShell>
  );
}
