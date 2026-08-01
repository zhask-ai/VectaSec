'use client';

/* Sign-in: email+password or Google. SSO/SAML stays an enterprise-tier concern; magic links
 * still need mail infrastructure we do not have. Keep the LOGIC boring — the polish is CSS.
 *
 * The session lands in cookies via @supabase/ssr's browser client, and proxy.ts refreshes it on
 * subsequent requests. Authorization itself is never decided here — RLS is the guarantee.
 *
 * /auth/callback bounces its failures here as ?error=link|oauth; that read needs
 * useSearchParams, which in a client page must sit under Suspense to keep the route
 * statically prerenderable.
 */
import { Suspense, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';

import { createClient } from '@/lib/supabase/client';
import { AuthShell } from '@/components/auth/AuthShell';
import { AuthAlert, PasswordField, SubmitButton, TextField } from '@/components/auth/fields';
import { AuthDivider, GoogleButton } from '@/components/auth/OAuthButtons';

const CALLBACK_ERRORS: Record<string, string> = {
  link: 'That email link is invalid or has expired. Request a fresh one below.',
  oauth: "Google sign-in didn't complete. Please try again.",
};

function LoginForm() {
  const router = useRouter();
  const search = useSearchParams();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Shown until the first submit/dismissal — a stale "link expired" over a fresh attempt is noise.
  const callbackError = !error && !busy ? CALLBACK_ERRORS[search.get('error') ?? ''] : undefined;

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
    // Fire-and-forget sign-in notification: the session cookie is set, so the route can
    // identify the user. keepalive lets the request survive the navigation below; auth must
    // never wait on (or fail because of) mail.
    void fetch('/api/notify-signin', { method: 'POST', keepalive: true });

    // refresh() so the Server Components re-run with the new session cookie attached.
    router.replace('/');
    router.refresh();
  }

  return (
    <>
      <h1 className="vs-auth-title">Welcome back</h1>
      <p className="vs-auth-sub">Good to see you again. Sign in to your VectaSec console.</p>

      {callbackError && <AuthAlert tone="info">{callbackError}</AuthAlert>}

      <GoogleButton label="Continue with Google" />
      <AuthDivider label="or sign in with email" />

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
        <PasswordField
          label="Password"
          required
          autoComplete="current-password"
          placeholder="Your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          hint={
            <Link href="/forgot-password" className="vs-auth-link" style={{ fontSize: 'var(--text-xs)' }}>
              Forgot password?
            </Link>
          }
        />

        {error && <AuthAlert tone="error">{error}</AuthAlert>}

        <SubmitButton busy={busy} busyLabel="Signing in…">
          Sign in
        </SubmitButton>
      </form>

      <p className="vs-auth-switch">
        New to VectaSec?{' '}
        <Link href="/signup" className="vs-auth-link">
          Create an account
        </Link>
      </p>
    </>
  );
}

export default function LoginPage() {
  return (
    <AuthShell>
      <Suspense>
        <LoginForm />
      </Suspense>
    </AuthShell>
  );
}
