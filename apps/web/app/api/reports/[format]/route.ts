/* Report/evidence export download proxy.
 *
 * The browser cannot call the engine directly (the engine token is a server-only secret and the
 * engine binds localhost). This route handler verifies the signed-in user, derives the tenant from
 * an RLS-read membership row (never the request), calls the engine's /reports/{format} with the
 * bearer token + tenant/actor headers, and streams the file back as a download. Read-only: it
 * exports data the user can already see under RLS.
 */
import type { NextRequest } from 'next/server';
import { getVerifiedUser } from '@/lib/supabase/server';
import { getOwnMembership } from '@/lib/role';

const ENGINE_URL = process.env.VECTASEC_ENGINE_URL ?? 'http://127.0.0.1:8000';

const FORMATS: Record<string, { path: string; filename: string; type: string }> = {
  oscal: { path: '/reports/oscal', filename: 'vectasec-oscal.json', type: 'application/json' },
  csv: { path: '/reports/csv', filename: 'vectasec-findings.csv', type: 'text/csv' },
  summary: { path: '/reports/summary', filename: 'vectasec-report.md', type: 'text/markdown' },
  // CycloneDX carries its spec version in the media type; consumers (Dependency-Track, Trivy,
  // Grype) sniff on it, so it must not be flattened to application/json.
  sbom: {
    path: '/reports/sbom',
    filename: 'vectasec-sbom.cdx.json',
    type: 'application/vnd.cyclonedx+json; version=1.6',
  },
  // VEX is a separate download, not a section of the SBOM: the inventory changes when the
  // estate does, the assessments change whenever a human rules on a finding, and consumers
  // ingest them on different cadences.
  vex: {
    path: '/reports/vex',
    filename: 'vectasec-vex.cdx.json',
    type: 'application/vnd.cyclonedx+json; version=1.6',
  },
};

export async function GET(_req: NextRequest, ctx: { params: Promise<{ format: string }> }) {
  const { format } = await ctx.params;
  const spec = FORMATS[format];
  if (!spec) return new Response('Unknown report format.', { status: 404 });

  const user = await getVerifiedUser();
  if (!user) return new Response('Not signed in.', { status: 401 });
  const membership = await getOwnMembership();
  if (!membership) return new Response('No tenant membership.', { status: 403 });

  let res: Response;
  try {
    res = await fetch(`${ENGINE_URL}${spec.path}`, {
      headers: {
        Authorization: `Bearer ${process.env.VECTASEC_ENGINE_TOKEN ?? ''}`,
        'X-VectaSec-Tenant': membership.tenantId,
        'X-VectaSec-Actor': user.id,
      },
      cache: 'no-store',
    });
  } catch {
    return new Response('The reporting engine is unreachable.', { status: 502 });
  }
  if (!res.ok) {
    return new Response(`Report generation failed (HTTP ${res.status}).`, { status: 502 });
  }

  const body = await res.text();
  const formatted = spec.type === 'application/json' ? JSON.stringify(JSON.parse(body), null, 2) : body;
  return new Response(formatted, {
    headers: {
      'Content-Type': spec.type,
      'Content-Disposition': `attachment; filename="${spec.filename}"`,
      'Cache-Control': 'no-store',
    },
  });
}
