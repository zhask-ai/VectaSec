import { NextResponse } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';

import { createClient } from '@/lib/supabase/server';

/* The single landing pad for every auth link: OAuth redirects (?code=, PKCE), and the email
 * links Supabase sends for signup confirmation, invites and recovery (?token_hash=&type=).
 *
 * Route handlers may write cookies, so the session lands here and the redirect target renders
 * already signed in. Invite and recovery arrivals go to /welcome to set a password — an
 * invited user has a session but no password, and without this page they could never sign in
 * again once it expires. Everything else goes to `next` (default /), and the (app) layout
 * routes users without an organization to /onboarding from there.
 */
export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const tokenHash = url.searchParams.get('token_hash');
  const type = url.searchParams.get('type') as EmailOtpType | null;

  // Open-redirect guard: `next` must be a path on this origin, never an absolute URL.
  const rawNext = url.searchParams.get('next') ?? '';
  const fallback = type === 'invite' || type === 'recovery' ? '/welcome' : '/';
  const next = rawNext.startsWith('/') && !rawNext.startsWith('//') ? rawNext : fallback;

  const supabase = await createClient();

  if (tokenHash && type) {
    const { error } = await supabase.auth.verifyOtp({ type, token_hash: tokenHash });
    if (error) return NextResponse.redirect(new URL('/login?error=link', url.origin));
    return NextResponse.redirect(new URL(next, url.origin));
  }
  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) return NextResponse.redirect(new URL('/login?error=oauth', url.origin));
    return NextResponse.redirect(new URL(next, url.origin));
  }
  return NextResponse.redirect(new URL('/login', url.origin));
}
