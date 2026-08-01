'use client';

/* Set-a-password, for arrivals whose session exists but whose password does not: invited
 * members (the engine's GoTrue invite) and recovery links. Skipping is allowed — the session
 * works without it — but then the invite link is their only way back in, so the page says so.
 */
import { useState } from 'react';
import { useRouter } from 'next/navigation';

import { createClient } from '@/lib/supabase/client';
import { AuthShell } from '@/components/auth/AuthShell';
import { AuthAlert, PasswordField, SubmitButton } from '@/components/auth/fields';

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

  function skip() {
    router.replace('/');
    router.refresh();
  }

  return (
    <AuthShell>
      <h1 className="vs-auth-title">Set your password</h1>
      <p className="vs-auth-sub">
        You are signed in via your email link. Set a password so you can sign in without it
        next time.
      </p>

      <form onSubmit={onSubmit}>
        <PasswordField
          label="New password"
          required
          minLength={8}
          autoComplete="new-password"
          placeholder="At least 8 characters"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          showStrength
          help="At least 8 characters."
        />
        <PasswordField
          label="Confirm password"
          required
          minLength={8}
          autoComplete="new-password"
          placeholder="Repeat your new password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />

        {error && <AuthAlert tone="error">{error}</AuthAlert>}

        <SubmitButton busy={busy} busyLabel="Saving…">
          Save and continue
        </SubmitButton>
      </form>

      <p className="vs-auth-switch">
        <button
          type="button"
          onClick={skip}
          className="vs-auth-link"
          style={{ background: 'transparent', border: 0, padding: 0, font: 'inherit', cursor: 'pointer' }}
        >
          Skip for now
        </button>
      </p>
    </AuthShell>
  );
}
