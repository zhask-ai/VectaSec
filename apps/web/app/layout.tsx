import type { Metadata } from 'next';
import Script from 'next/script';
import { Inter } from 'next/font/google';
import './globals.css';
import './auth.css';

/* Inter, self-hosted by next/font at build time — no runtime fetch to Google, so the
 * "self-contained" rule holds. Exposed as a CSS variable and consumed ONLY by the auth
 * screens (auth.css); the console keeps the system stack. */
const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
  axes: ['opsz'],
});

/* The ROOT layout — deliberately minimal. It owns <html>/<body>, the global stylesheet, and one
 * job beyond that: apply the saved theme BEFORE first paint.
 *
 * It does NOT render the app shell. The sidebar + top bar live in app/(app)/layout.tsx, which
 * wraps only the authed routes inside the (app) route group. /login sits OUTSIDE that group, so it
 * gets this bare frame and keeps its own centred layout — a sign-in screen with a full console
 * chrome around an empty session would be both wrong and a small information leak.
 *
 * THE THEME SCRIPT runs before hydration (next/script `beforeInteractive`), reading `vs-theme`
 * from localStorage and stamping data-theme on <html>. Without it, a user who chose dark would see
 * a white flash on every load (the server has no way to know their choice — it is client state).
 * beforeInteractive is the blessed way to run this pre-paint without React's "script inside a
 * component" warning; a raw <script> in the tree logs that on every render. It only ever SETS an
 * explicit choice — absence of the attribute correctly falls through to prefers-color-scheme — and
 * it touches an <html> attribute React does not manage, so it causes no hydration mismatch.
 * suppressHydrationWarning guards the attribute the script may add.
 */

export const metadata: Metadata = {
  title: 'VectaSec',
  description: 'Integration-layer security posture',
};

const THEME_INIT = `(function(){try{var t=localStorage.getItem('vs-theme');if(t==='light'||t==='dark'){document.documentElement.dataset.theme=t;}}catch(e){}})();`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning className={inter.variable}>
      <body>
        <Script id="vs-theme-init" strategy="beforeInteractive">
          {THEME_INIT}
        </Script>
        {children}
      </body>
    </html>
  );
}
