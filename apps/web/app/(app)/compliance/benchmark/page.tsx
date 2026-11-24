import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { ComplianceTabs } from '../tabs';

/* Compliance · Benchmark — the VectaSec Integration-Layer Benchmark (engine: benchmark.py).
 *
 * No CIS Benchmark exists for Kafka, RabbitMQ, Redis, NATS, Kong or n8n. This is a numbered
 * control list per system, generated from the product's own detectors, with this workspace's
 * result against it and a document to hand to an auditor or a customer.
 *
 * A control is a pass only when the system was scanned and the check could be evaluated.
 * "Not assessed" and "not connected" are shown as what they are and never add to the score.
 */

type System = {
  key: string;
  title: string;
  scanned: boolean;
  controls: number;
  score: number | null;
  counts: { pass: number; fail: number; not_assessed: number; not_scanned: number };
};
type Resp = { version: string; systems: System[] };

export const metadata = { title: 'Compliance · Benchmark · VectaSec' };

export default async function BenchmarkPage() {
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const res = await engineGet<Resp>('/benchmark', { tenantId: membership.tenantId, actor }, 20_000);

  return (
    <PageShell>
      <PageHeader
        title="Compliance"
        description="A published, numbered hardening benchmark for the systems that have none, and your result against it."
      />
      <ComplianceTabs />
      {!res.ok ? (
        <Card>
          <CardBody>
            <EmptyState tone="error" title="The benchmark is unavailable" description={res.message} />
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Integration-Layer Benchmark</CardTitle>
            <CardMeta>
              version {res.data.version} · {res.data.systems.reduce((n, s) => n + s.controls, 0)} controls ·{' '}
              {res.data.systems.length} systems
            </CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Benchmark result per system">
              <THead>
                <TR>
                  <TH width="24%">System</TH>
                  <TH width="14%">Status</TH>
                  <TH width="9%" numeric>
                    Score
                  </TH>
                  <TH width="9%" numeric>
                    Pass
                  </TH>
                  <TH width="9%" numeric>
                    Fail
                  </TH>
                  <TH width="11%" numeric>
                    Not assessed
                  </TH>
                  <TH width="24%">Documents</TH>
                </TR>
              </THead>
              <TBody>
                {res.data.systems.map((s) => (
                  <TR key={s.key}>
                    <TD>
                      <span style={{ display: 'grid', gap: 2, padding: 'var(--space-2) 0' }}>
                        <span style={{ fontWeight: 600 }}>{s.title}</span>
                        <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-2xs)' }}>
                          {s.controls} controls
                        </span>
                      </span>
                    </TD>
                    <TD>
                      {!s.scanned ? (
                        <StatusPill tone="neutral" label="Not connected" />
                      ) : s.counts.fail > 0 ? (
                        <StatusPill tone="bad" variant="soft" label={`${s.counts.fail} failing`} />
                      ) : (
                        <StatusPill tone="ok" variant="soft" label="No failures" />
                      )}
                    </TD>
                    <TD numeric>{s.score === null ? '—' : `${s.score}%`}</TD>
                    <TD numeric muted>
                      {s.scanned ? s.counts.pass : '—'}
                    </TD>
                    <TD numeric>{s.scanned ? s.counts.fail : '—'}</TD>
                    <TD numeric muted>
                      {s.scanned ? s.counts.not_assessed : '—'}
                    </TD>
                    <TD>
                      <span style={{ display: 'inline-flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                        {s.scanned && (
                          <a
                            href={`/api/reports/benchmark?system=${s.key}`}
                            className="vs-actionbtn"
                            title={`${s.title} benchmark filled in with your results`}
                          >
                            Your assessment
                          </a>
                        )}
                        <a
                          href={`/api/reports/benchmark?system=${s.key}&blank=1`}
                          className="vs-actionbtn"
                          title={`The ${s.title} benchmark as a blank document`}
                        >
                          Benchmark
                        </a>
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
          <CardFooter>
            Published by VectaSec because no CIS Benchmark exists for these systems. Generated from
            the product&apos;s detectors, so every control is one that is checked. Score is pass ÷
            (pass + fail); controls the scan could not evaluate are not counted either way.
          </CardFooter>
        </Card>
      )}
    </PageShell>
  );
}
