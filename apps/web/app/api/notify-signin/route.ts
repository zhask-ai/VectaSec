import { NextResponse } from 'next/server';

import { createClient } from '@/lib/supabase/server';
import { sendSignInNotification } from '@/lib/email';

/* Sign-in notification trigger for PASSWORD logins. The login page fires a fire-and-forget
 * POST here right after signInWithPassword succeeds — by then the session cookie is set, so
 * this handler can read the user server-side. (OAuth logins get their notification directly
 * in /auth/callback, which already runs on the server; this route exists only because the
 * password flow completes in the browser, where the Resend key must never go.)
 *
 * The session IS the authorization: no body is read, the recipient is always the session's
 * own verified email, and an anonymous caller gets a 401 and no mail. Nothing here can be
 * pointed at an arbitrary address, so it is not a mail-bomb primitive — the worst a caller
 * can do is email themselves.
 */
export async function POST(request: Request) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  if (!user?.email) {
    return NextResponse.json({ error: 'unauthenticated' }, { status: 401 });
  }

  await sendSignInNotification(user.email, new URL(request.url).origin);
  return new NextResponse(null, { status: 204 });
}
