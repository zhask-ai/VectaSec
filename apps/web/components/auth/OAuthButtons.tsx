'use client';

import { useState } from 'react';

import { createClient } from '@/lib/supabase/client';

/* Google sign-in, shared by /login and /signup. signInWithOAuth sends the browser to Google
 * and back to /auth/callback?code=…, where the session cookie is written; authorization is
 * still RLS's job. If the provider is not enabled in the Supabase dashboard the error surfaces
 * verbatim — better an honest "provider is not enabled" than a dead button.
 */
export function GoogleButton({ label }: { label: string }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onClick() {
    setBusy(true);
    setError(null);
    const supabase = createClient();
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: `${window.location.origin}/auth/callback` },
    });
    if (error) {
      setError(error.message);
      setBusy(false);
    }
    // On success the browser navigates away; no state to reset.
  }

  return (
    <div style={{ display: 'grid', gap: 8 }}>
      <button
        type="button"
        onClick={onClick}
        disabled={busy}
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 8,
          padding: '9px 12px',
          background: 'var(--surface)',
          color: 'var(--text-primary)',
          border: '1px solid var(--border-interactive)',
          borderRadius: 'var(--radius-sm, 6px)',
          fontSize: 'var(--text-sm)',
          fontWeight: 600,
          cursor: busy ? 'default' : 'pointer',
        }}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true">
          <path
            fill="#4285F4"
            d="M23.5 12.27c0-.85-.08-1.66-.22-2.45H12v4.64h6.46a5.53 5.53 0 0 1-2.4 3.62v3h3.88c2.27-2.1 3.56-5.18 3.56-8.81z"
          />
          <path
            fill="#34A853"
            d="M12 24c3.24 0 5.96-1.07 7.94-2.91l-3.88-3c-1.08.72-2.46 1.15-4.06 1.15-3.12 0-5.77-2.1-6.71-4.94H1.28v3.1A12 12 0 0 0 12 24z"
          />
          <path
            fill="#FBBC05"
            d="M5.29 14.3a7.2 7.2 0 0 1 0-4.6V6.6H1.28a12 12 0 0 0 0 10.8l4-3.1z"
          />
          <path
            fill="#EA4335"
            d="M12 4.76c1.76 0 3.34.6 4.58 1.8l3.44-3.44A11.98 11.98 0 0 0 12 0 12 12 0 0 0 1.28 6.6l4.01 3.1C6.23 6.87 8.88 4.76 12 4.76z"
          />
        </svg>
        {busy ? 'Redirecting…' : label}
      </button>
      {error && (
        <p role="alert" style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--sev-critical-fg)' }}>
          {error}
        </p>
      )}
    </div>
  );
}

/** The "——— or ———" separator between the OAuth button and the email form. */
export function AuthDivider() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }} aria-hidden="true">
      <span style={{ flex: 1, height: 1, background: 'var(--border)' }} />
      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-muted)' }}>or</span>
      <span style={{ flex: 1, height: 1, background: 'var(--border)' }} />
    </div>
  );
}
