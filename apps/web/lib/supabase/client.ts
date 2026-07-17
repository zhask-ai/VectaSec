'use client';

import { createBrowserClient } from '@supabase/ssr';

/* Browser client. Only for things that genuinely cannot be server-rendered: Realtime
 * subscriptions (scan progress, live findings) and auth form submission.
 *
 * Everything else should be a Server Component reading through lib/supabase/server.ts —
 * filter state belongs in searchParams, not useState, so views stay shareable and the query
 * runs in Postgres. Reaching for this client to get live updates is the most common App
 * Router regression: keep Realtime a small island inside an RSC shell, don't convert the
 * page.
 *
 * The anon key is public by design; RLS is what protects the data, and the browser role has
 * SELECT-only policies scoped to the user's tenant. */
export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
  );
}
