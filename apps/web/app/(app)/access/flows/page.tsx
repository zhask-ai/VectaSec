import Link from 'next/link';
import type { Route } from 'next';

import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import type { Severity } from '@/lib/types';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { EmptyState } from '@/components/ui/empty-state';
import { Page as PageShell } from '@/components/ui/page';
import { PageHeader } from '@/components/ui/page-header';
import { SeverityBadge } from '@/components/ui/severity';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { AccessTabs } from '../tabs';

/* Access · Data & agents (engine: flows.py).
 *
 * Three views of one question, "where can data go that it should not?":
 *   Toxic flows   automations joining a sensitive or anonymous source to an outside destination
 *   Agent reach   what each MCP server's tools can do, and which of your systems they name
 *   Data map      sensitive topics / queues / routes and how many identities can reach them
 *
 * Most of this is inference and the page shows it: every flow and every reach edge carries its
 * basis, inferred items use the dashed chip, and a system VectaSec is not connected to is
 * marked as such instead of being left off.
 */

type Flow = {
  resource_id: string;
  workflow: string;
  system: string;
  pattern: string;
  severity: Severity;
  source: string;
  sink: string;
  why: string;
  basis: string;
  enabled: boolean;
  owner: string;
};
type Reach = { target: string; kind: string; connected: boolean; resource_id?: string; sensitivity?: string; tools: string[]; access: string; basis: string };
type Agent = {
  resource_id: string;
  server: string;
  endpoint: string;
  public: boolean;
  plaintext: boolean;
  open_findings: number;
  tools: number;
  write_tools: number;
  exec_tools: number;
  reaches: Reach[];
};
type DataRow = {
  resource_id: string;
  name: string;
  kind: string;
  connection: string;
  system: string;
  classes: string[];
  sensitivity: string;
  direct_readers: number;
  wildcard_readers: number;
  external_readers: number;
};
type Resp = {
  toxic_flows: Flow[];
  toxic_total: number;
  agents: Agent[];
  data_map: DataRow[];
  coverage: { automation_systems: string[]; mcp_servers: number };
  scope_note: string;
};

export const metadata = { title: 'Access · Data & agents · VectaSec' };

const PATTERN: Record<string, string> = {
  anonymous_to_system: 'Anyone → your system',
  anonymous_to_code: 'Anyone → runs code',
  sensitive_to_llm: 'Business data → AI model',
  sensitive_to_external: 'Business data → outside',
};
const mono: React.CSSProperties = { fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' };

export default async function FlowsPage() {
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const res = await engineGet<Resp>('/access/flows', { tenantId: membership.tenantId, actor }, 20_000);

  const frame = (children: React.ReactNode) => (
    <PageShell>
      <PageHeader
        title="Access"
        description="Where sensitive data can leave through automations, what AI agents can reach, and who can read what."
      />
      <AccessTabs />
      {children}
    </PageShell>
  );
  if (!res.ok) {
    return frame(
      <Card>
        <CardBody>
          <EmptyState tone="error" title="This view is unavailable" description={res.message} />
        </CardBody>
      </Card>,
    );
  }
  const d = res.data;

  return frame(
    <>
      <Card>
        <CardHeader>
          <CardTitle>Toxic flows</CardTitle>
          <CardMeta>
            {d.toxic_flows.length}
            {d.toxic_total > d.toxic_flows.length ? ` of ${d.toxic_total}` : ''} · enabled first, worst first
          </CardMeta>
        </CardHeader>
        <CardBody pad={d.toxic_flows.length === 0}>
          {d.toxic_flows.length === 0 ? (
            <EmptyState
              tone={d.coverage.automation_systems.length ? 'clean' : 'setup'}
              title={d.coverage.automation_systems.length ? 'No toxic flow found' : 'No automation tool connected'}
              description={
                d.coverage.automation_systems.length
                  ? `Checked workflows in ${d.coverage.automation_systems.join(', ')}. None joins an anonymous or sensitive source to an outside destination.`
                  : 'Connect Zapier or n8n to see workflows that join a sensitive or anonymous source to an outside destination.'
              }
            />
          ) : (
            <Table density="compact" caption="Automations that join a risky source to a risky destination">
              <THead>
                <TR>
                  <TH width="11%">Severity</TH>
                  <TH width="23%">Workflow</TH>
                  <TH width="18%">Pattern</TH>
                  <TH width="24%">From → to</TH>
                  <TH width="24%">Why it matters</TH>
                </TR>
              </THead>
              <TBody>
                {d.toxic_flows.map((f, i) => (
                  <TR key={`${f.resource_id}-${f.pattern}-${i}`}>
                    <TD>
                      <SeverityBadge severity={f.severity} />
                    </TD>
                    <TD>
                      <span style={{ display: 'grid', gap: 2, padding: 'var(--space-2) 0', minWidth: 0 }}>
                        <Link href={`/estate/inventory/${f.resource_id}` as Route} style={{ color: 'var(--text-primary)', overflowWrap: 'anywhere' }}>
                          {f.workflow}
                        </Link>
                        <span style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                          <Chip mono>{f.system}</Chip>
                          {!f.enabled && <Chip>disabled</Chip>}
                        </span>
                      </span>
                    </TD>
                    <TD>{PATTERN[f.pattern] ?? f.pattern}</TD>
                    <TD>
                      <span style={{ ...mono, fontSize: 'var(--text-2xs)' }}>
                        {f.source} <span aria-hidden="true">→</span>
                        <span className="vs-visually-hidden"> to </span> {f.sink}
                      </span>
                    </TD>
                    <TD>
                      <span style={{ display: 'grid', gap: 2, fontSize: 'var(--text-2xs)', lineHeight: 'var(--leading-sm)' }}>
                        <span>{f.why}</span>
                        <span style={{ color: 'var(--text-muted)' }}>{f.basis}</span>
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>What AI agents can reach</CardTitle>
          <CardMeta>{d.agents.length} MCP server{d.agents.length === 1 ? '' : 's'}</CardMeta>
        </CardHeader>
        <CardBody>
          {d.agents.length === 0 ? (
            <EmptyState
              tone="setup"
              title="No MCP server connected"
              description="Connect an MCP server to see what its tools can do and which of your systems they name."
            />
          ) : (
            <div style={{ display: 'grid', gap: 'var(--space-5)' }}>
              {d.agents.map((a) => (
                <section key={a.resource_id} style={{ display: 'grid', gap: 'var(--space-2)' }}>
                  <span style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center' }}>
                    <Link href={`/estate/inventory/${a.resource_id}` as Route} style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                      {a.server}
                    </Link>
                    {a.public && <StatusPill tone="warn" variant="soft" label="Public address" />}
                    {a.plaintext && <StatusPill tone="bad" variant="soft" label="No TLS" />}
                    <Chip>{a.tools} tools</Chip>
                    {a.write_tools > 0 && <Chip tone="medium">{a.write_tools} can write</Chip>}
                    {a.exec_tools > 0 && <Chip tone="high">{a.exec_tools} can run code</Chip>}
                    {a.open_findings > 0 && <Chip tone="high">{a.open_findings} open findings</Chip>}
                  </span>
                  {a.reaches.length === 0 ? (
                    <p style={{ margin: 0, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
                      No tool names a system or resource VectaSec recognises. That is not proof it reaches nothing.
                    </p>
                  ) : (
                    <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' }}>
                      {a.reaches.map((r, i) => (
                        <li key={i} style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'baseline', fontSize: 'var(--text-xs)' }}>
                          <Chip inferred mono title={r.basis}>
                            {r.access === 'unknown' ? 'access unknown' : `can ${r.access}`}
                          </Chip>
                          {r.resource_id ? (
                            <Link href={`/estate/inventory/${r.resource_id}` as Route} style={mono}>
                              {r.target}
                            </Link>
                          ) : (
                            <span style={mono}>{r.target}</span>
                          )}
                          <span style={{ color: 'var(--text-secondary)' }}>
                            {r.kind === 'system' ? (r.connected ? 'a system you have connected' : 'not connected to VectaSec') : r.kind}
                            {r.sensitivity ? ` · ${r.sensitivity} sensitivity` : ''}
                          </span>
                          <span style={{ color: 'var(--text-muted)' }}>via {r.tools.join(', ')}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
              ))}
            </div>
          )}
        </CardBody>
        <CardFooter>
          An MCP server does not publish what it connects to. Reach is inferred from each tool&apos;s
          name, description and declared annotations; dashed chips mark it as inferred.
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Sensitive data and who can reach it</CardTitle>
          <CardMeta>{d.data_map.length} resource{d.data_map.length === 1 ? '' : 's'} · most sensitive first</CardMeta>
        </CardHeader>
        <CardBody pad={d.data_map.length === 0}>
          {d.data_map.length === 0 ? (
            <EmptyState
              tone="pending"
              title="No sensitive data resource identified"
              description="Topics, queues, routes and keyspaces are classified from their names and labels. None has matched a sensitive class yet."
            />
          ) : (
            <Table density="compact" caption="Sensitive data resources and their readers">
              <THead>
                <TR>
                  <TH width="28%">Resource</TH>
                  <TH width="18%">Connection</TH>
                  <TH width="24%">Data classes (inferred)</TH>
                  <TH width="10%" numeric>
                    Named
                  </TH>
                  <TH width="10%" numeric>
                    Wildcard
                  </TH>
                  <TH width="10%" numeric>
                    External
                  </TH>
                </TR>
              </THead>
              <TBody>
                {d.data_map.map((r) => (
                  <TR key={r.resource_id}>
                    <TD>
                      <span style={{ display: 'grid', gap: 2, padding: 'var(--space-2) 0', minWidth: 0 }}>
                        <Link href={`/estate/inventory/${r.resource_id}` as Route} style={{ ...mono, color: 'var(--text-primary)' }}>
                          {r.name}
                        </Link>
                        <span>
                          <Chip mono>{r.kind}</Chip>
                        </span>
                      </span>
                    </TD>
                    <TD muted>
                      {r.connection} · {r.system}
                    </TD>
                    <TD>
                      <span style={{ display: 'flex', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                        {r.classes.map((c) => (
                          <Chip key={c} inferred>
                            {c}
                          </Chip>
                        ))}
                      </span>
                    </TD>
                    <TD numeric>{r.direct_readers}</TD>
                    <TD numeric>{r.wildcard_readers}</TD>
                    <TD numeric>
                      {r.external_readers > 0 ? <strong>{r.external_readers}</strong> : <span style={{ color: 'var(--text-muted)' }}>0</span>}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardBody>
        <CardFooter>
          Named = identities with a grant on this resource. Wildcard = identities whose wildcard
          grant in the same system covers it. External = of those, parties outside your
          organisation. {d.scope_note}
        </CardFooter>
      </Card>
    </>,
  );
}
