import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // The floating dev badge sat on top of the sidebar's lower items. Errors still surface in the
  // dev overlay; only the always-on indicator is hidden.
  devIndicators: false,
  typedRoutes: true,
  // The console went from fifteen navigation items to six (docs/vectasec-smb-strategy-2026-10.md
  // §3). Every old route keeps resolving so a link pasted into a ticket or a Slack thread last
  // month still lands somewhere sensible. Temporary (307) on purpose: a permanent redirect is
  // cached by browsers for a year, and a route we later want back would be unreachable.
  async redirects() {
    return [
      { source: '/connections', destination: '/estate', permanent: false },
      { source: '/systems', destination: '/estate/catalogue', permanent: false },
      { source: '/discovery', destination: '/estate/unmonitored', permanent: false },
      { source: '/assets', destination: '/estate/inventory', permanent: false },
      { source: '/assets/:id', destination: '/estate/inventory/:id', permanent: false },
      { source: '/identities', destination: '/access', permanent: false },
      { source: '/runtime', destination: '/access/live', permanent: false },
      { source: '/data', destination: '/access', permanent: false },
      { source: '/attack-paths', destination: '/findings/paths', permanent: false },
      { source: '/scans', destination: '/estate', permanent: false },
      { source: '/supply-chain', destination: '/compliance/reports', permanent: false },
    ];
  },
  // The console is read-only over RLS and renders customer config; nothing here should ever
  // be framed or MIME-sniffed by a third party.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
        ],
      },
    ];
  },
};

export default nextConfig;
