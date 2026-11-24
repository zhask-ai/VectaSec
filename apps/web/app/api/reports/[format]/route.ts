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

const FORMATS: Record<string, { path: string; filename: string; type: string; window?: boolean; id?: boolean; person?: boolean; system?: boolean }> = {
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
  // The auditor's access register — every identity the connected systems accept, with owner,
  // last used, grants and the SOC 2 / ISO 27001 / PCI controls each row is evidence for.
  'register-csv': { path: '/reports/access-register?format=csv', filename: 'vectasec-access-register.csv', type: 'text/csv' },
  'register-md': { path: '/reports/access-register?format=md', filename: 'vectasec-access-register.md', type: 'text/markdown' },
  // The Time machine's access-and-change report. The window is the caller's (?days= or
  // ?since=&until=), forwarded below after validation.
  'changes-csv': { path: '/reports/changes?format=csv', filename: 'vectasec-change-report.csv', type: 'text/csv', window: true },
  'changes-md': { path: '/reports/changes?format=md', filename: 'vectasec-change-report.md', type: 'text/markdown', window: true },
  // A stored Breach-day brief; ?id= names which one (uuid, validated below).
  // Who was seen using one resource (?id=), for auditors.
  usage: { path: '/access/usage/ID?format=csv', filename: 'vectasec-usage.csv', type: 'text/csv', id: true },
  'breach-brief': { path: '/reports/breach-brief?x=1', filename: 'vectasec-breach-brief.md', type: 'text/markdown', id: true },
  // The Leaver report for one person (?person=, forwarded url-encoded, length-capped below).
  leaver: { path: '/people/report?format=md', filename: 'vectasec-leaver-report.md', type: 'text/markdown', person: true },
  // One system's Integration-Layer Benchmark (?system=, optionally &blank=1).
  benchmark: { path: '/reports/benchmark?x=1', filename: 'vectasec-benchmark.md', type: 'text/markdown', system: true },
  vex: {
    path: '/reports/vex',
    filename: 'vectasec-vex.cdx.json',
    type: 'application/vnd.cyclonedx+json; version=1.6',
  },
};

/** The only query the browser may add, and only for reports that take a window: whole days, or
 * ISO dates. Anything else is dropped rather than forwarded to the engine. */
function windowQuery(req: NextRequest): string {
  const q = req.nextUrl.searchParams;
  const out = new URLSearchParams();
  const days = q.get('days');
  if (days && /^\d{1,3}$/.test(days)) out.set('days', days);
  for (const key of ['since', 'until']) {
    const v = q.get(key);
    if (v && /^\d{4}-\d{2}-\d{2}(T[\d:.]+(Z|[+-]\d{2}:\d{2})?)?$/.test(v)) out.set(key, v);
  }
  const text = out.toString();
  return text ? `&${text}` : '';
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ format: string }> }) {
  const { format } = await ctx.params;
  const spec = FORMATS[format];
  if (!spec) return new Response('Unknown report format.', { status: 404 });
  let path = spec.window ? `${spec.path}${windowQuery(req)}` : spec.path;
  let filename = spec.filename;
  if (spec.system) {
    const system = req.nextUrl.searchParams.get('system') ?? '';
    if (!/^[a-z0-9_]{1,32}$/.test(system)) return new Response('Unknown system.', { status: 404 });
    const blank = req.nextUrl.searchParams.get('blank') === '1';
    path = `${spec.path}&system=${system}${blank ? '&blank=true' : ''}`;
    filename = `vectasec-benchmark-${system}${blank ? '' : '-assessment'}.md`;
  }
  if (spec.person) {
    const person = (req.nextUrl.searchParams.get('person') ?? '').trim();
    if (!person || person.length > 200) return new Response('Name a person.', { status: 400 });
    path = `${spec.path}&person=${encodeURIComponent(person)}`;
  }
  if (spec.id) {
    const id = req.nextUrl.searchParams.get('id') ?? '';
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
      return new Response('Unknown report.', { status: 404 });
    }
    path = spec.path.includes('/ID?') ? spec.path.replace('/ID?', `/${id}?`) : `${spec.path}&id=${id}`;
  }

  const user = await getVerifiedUser();
  if (!user) return new Response('Not signed in.', { status: 401 });
  const membership = await getOwnMembership();
  if (!membership) return new Response('No tenant membership.', { status: 403 });

  let res: Response;
  try {
    res = await fetch(`${ENGINE_URL}${path}`, {
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
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'no-store',
    },
  });
}
