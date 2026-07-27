import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

/* Auth session refresh.
 *
 * NOTE ON THE FILENAME: this is `proxy.ts`, not `middleware.ts`. Next.js 16 deprecated and
 * renamed the middleware convention to proxy (both names still resolve in 16.2.10, but
 * middleware is the deprecated one). Every Supabase SSR tutorial online still says
 * middleware.ts — they predate the rename. If you need to move an existing project:
 *   npx @next/codemod@canary middleware-to-proxy .
 * The `runtime` config option does not exist in a proxy file and throws if set.
 *
 * The rename is a design instruction, not just a rename: "proxy" implies a network boundary
 * in front of the app, and Vercel explicitly recommends this file "be used as a last resort".
 * So it does exactly one thing — refresh the token and redirect anonymous users. Nothing else
 * belongs here.
 *
 * THIS IS NOT AN AUTHORIZATION BOUNDARY. Server Functions are POSTs to the route where they
 * are used, so a matcher change or moving an action to another route silently removes proxy
 * coverage — with no test failing. Re-verify auth inside every Server Action; rely on RLS for
 * the actual guarantee.
 */
export async function proxy(request: NextRequest) {
  let response = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll: () => request.cookies.getAll(),
        setAll: (cookiesToSet) => {
          for (const { name, value } of cookiesToSet) request.cookies.set(name, value);
          response = NextResponse.next({ request });
          for (const { name, value, options } of cookiesToSet) {
            response.cookies.set(name, value, options);
          }
        },
      },
    },
  );

  // getClaims verifies the JWT signature (locally via WebCrypto with asymmetric keys).
  // NOT getSession(): on the server it only reads the cookie and "isn't guaranteed to
  // revalidate the Auth token".
  const { data } = await supabase.auth.getClaims();

  const publicPaths = ['/login', '/signup', '/auth'];
  const isPublic = publicPaths.some((p) => request.nextUrl.pathname.startsWith(p));
  if (!data?.claims && !isPublic) {
    const login = new URL('/login', request.url);
    return NextResponse.redirect(login);
  }

  // A session cookie must never be cached by a CDN and handed to the next visitor.
  response.headers.set('Cache-Control', 'private, no-store, max-age=0, must-revalidate');

  return response;
}

export const config = {
  // Without a matcher this runs on EVERY request, including _next/static and public/, and the
  // redirect above would block CSS/JS/images from loading.
  //
  // Caveat: _next/data routes still run this even though they look excluded. That is
  // deliberate upstream behaviour — it stops you protecting a page but forgetting its data route.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|login|signup|auth).*)'],
};
