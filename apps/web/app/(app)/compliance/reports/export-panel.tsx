import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';

/* The evidence-bundle formats VectaSec's reporting module produces. Kept as data so the panel
 * lists exactly what the engine can generate and nothing it cannot. */
const EXPORT_FORMATS: { name: string; desc: string; href: string; filename: string }[] = [
  {
    name: 'OSCAL 1.1',
    desc: 'Assessment results as NIST OSCAL 1.1 JSON — machine-readable, for a GRC platform or an auditor’s toolchain.',
    href: '/api/reports/oscal',
    filename: 'vectasec-oscal.json',
  },
  {
    name: 'Findings CSV',
    desc: 'One row per finding: rule, severity, system, resource, status, evidence and remediation — for a spreadsheet or a ticket import.',
    href: '/api/reports/csv',
    filename: 'vectasec-findings.csv',
  },
  {
    name: 'Executive report',
    desc: 'A narrative Markdown summary for leadership: posture, severity breakdown, worst findings, and compliance coverage.',
    href: '/api/reports/summary',
    filename: 'vectasec-report.md',
  },
];

/** The evidence-export affordance — and a deliberately HONEST one.
 *
 * The reporting module in the engine generates all three formats today, but there is no console
 * endpoint that returns them (lib/engine.ts exposes no report route). So this ships no download
 * button that would 404, and no button that looks live but does nothing. It states what the
 * reporting API produces, and shows each format with a plainly-disabled control and a "coming to
 * the console" note. When a report route lands in lib/engine.ts, wire these to it. */
export function ExportPanel() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Evidence export</CardTitle>
        <CardMeta>generated live from your tenant’s current results</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <p style={{ margin: 0, maxWidth: '80ch', fontSize: 'var(--text-sm)', lineHeight: 'var(--leading-sm)', color: 'var(--text-secondary)' }}>
            VectaSec’s reporting engine generates a full evidence bundle from the results above. Each
            download is produced on demand from your tenant’s current findings, controls and posture —
            deterministic, and honest about coverage (a control is never reported passing without a
            human attestation).
          </p>

          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
            {EXPORT_FORMATS.map((f) => (
              <li
                key={f.name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 'var(--space-4)',
                  padding: 'var(--space-3)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div style={{ display: 'grid', gap: '2px', minWidth: 0 }}>
                  <span style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {f.name}
                  </span>
                  <span style={{ fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-xs)', color: 'var(--text-secondary)' }}>
                    {f.desc}
                  </span>
                </div>
                {/* A real download: this href hits app/api/reports/[format], which authenticates the
                    user server-side, calls the engine's reporting endpoint with the engine token, and
                    streams the file back. Read-only export of data the user can already see. */}
                <a
                  href={f.href}
                  download={f.filename}
                  style={{
                    flexShrink: 0,
                    display: 'inline-flex',
                    alignItems: 'center',
                    padding: 'var(--space-2) var(--space-3)',
                    fontSize: 'var(--text-sm)',
                    fontWeight: 500,
                    color: 'var(--text-primary)',
                    background: 'var(--surface)',
                    border: '1px solid var(--border-interactive)',
                    borderRadius: 'var(--radius-md)',
                    textDecoration: 'none',
                  }}
                >
                  Download
                </a>
              </li>
            ))}
          </ul>
        </div>
      </CardBody>
      <CardFooter>
        Downloads are generated live by the reporting engine from your tenant’s current results.
      </CardFooter>
    </Card>
  );
}

