import { NextResponse } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';

import { createClient } from '@/lib/supabase/server';
import { sendSignInNotification } from '@/lib/email';

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

  // Open-redirect guard. String prefix checks are NOT sufficient here: the WHATWG URL parser
  // treats a backslash as a path separator, so `/\evil.com` and `/\/evil.com` both resolve to
  // `https://evil.com/` while passing a `startsWith('/') && !startsWith('//')` test. The attack
  // is real — the whole `next` value travels inside a same-origin `emailRedirectTo`, so
  // Supabase's allow-list passes it, the victim authenticates for real, and lands on a clone.
  //
  // So resolve it against our own origin and keep it ONLY if it stayed there. Parsing is the
  // check; anything the parser sends elsewhere is discarded.
  const rawNext = url.searchParams.get('next') ?? '';
  const fallback = type === 'invite' || type === 'recovery' ? '/welcome' : '/';
  let next = fallback;
  if (rawNext) {
    try {
      const resolved = new URL(rawNext, url.origin);
      if (resolved.origin === url.origin) next = resolved.pathname + resolved.search;
    } catch {
      next = fallback;
    }
  }

  const supabase = await createClient();

  if (tokenHash && type) {
    const { error } = await supabase.auth.verifyOtp({ type, token_hash: tokenHash });
    if (error) return NextResponse.redirect(new URL('/login?error=link', url.origin));
    return NextResponse.redirect(new URL(next, url.origin));
  }
  if (code) {
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) return NextResponse.redirect(new URL('/login?error=oauth', url.origin));
    // OAuth sign-in notification, sent from here because this is where the flow completes
    // server-side. Only the ?code= path notifies: token_hash arrivals ARE email links
    // (confirmation/recovery/invite) — "you signed in" mail about the mail they just clicked
    // would be noise. sendSignInNotification never throws, so the redirect cannot fail.
    const { data } = await supabase.auth.getUser();
    if (data.user?.email) await sendSignInNotification(data.user.email, url.origin);
    return NextResponse.redirect(new URL(next, url.origin));
  }
  return NextResponse.redirect(new URL('/login', url.origin));
}
