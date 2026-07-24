import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { engineGet } from '@/lib/engine';
import { getOwnMembership, isAdmin } from '@/lib/role';
import { createClient, getClaims } from '@/lib/supabase/server';
import { AddIntegration } from './add-integration';
import { integrationSpecFor } from './integration-fields';
import { IntegrationRowActions } from './integration-row';
import { AddRoutingRule, RemoveRuleButton } from './routing-rules';

/* Settings · Integrations — where findings are delivered, and the rules that decide which.
 *
 * Read from the engine (there is no Supabase mirror for integrations), written only through
 * it. Config is NEVER rendered: it holds webhook URLs with embedded tokens and API tokens.
 * The list shows type + name and nothing else — a secret that is never fetched into this
 * page cannot be leaked by a later refactor.
 */

export const metadata = { title: 'Integrations · VectaSec' };

/* The engine returns more (config, enabled, has_credentials, secret_keys) — typed narrow on
 * purpose: config holds nothing secret (secrets are vaulted) but rendering none of it keeps
 * this page leak-proof by construction. */
type IntegrationRow = { id: string; type: string; name: string };
type RoutingRuleRow = {
  id: string;
  name: string | null;
  match: {
    min_severity?: string;
    connector_types?: string[];
    rule_prefixes?: string[];
    notify_on?: string[];
  };
  enabled: boolean;
  // LEFT JOIN on the engine side: fields are null if the integration vanished.
  integration: { id: string | null; type: string | null; name: string | null };
};
type DeliveryRow = {
  id: string;
  integration_id: string | null;
  event: string;
  findings_count: number;
  status: string;
  error: string | null;
  created_at: string;
};

export default async function IntegrationsPage() {
  // Page-level gate — the layout hides the render, but this segment executes and fetches
  // regardless of the layout, so the fetches must sit behind the role check.
  const membership = await getOwnMembership();
  if (!isAdmin(membership?.role) || !membership) return null;

  const claims = await getClaims();
  const currentUserId = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!currentUserId) return null;

  const auth = { tenantId: membership.tenantId, actor: currentUserId };
  const supabase = await createClient();
  const [integrationsRes, rulesRes, deliveriesRes] = await Promise.all([
    // The engine wraps its lists: {integrations: [...]}, {routing_rules: [...]}.
    engineGet<{ integrations: IntegrationRow[] }>('/integrations', auth),
    engineGet<{ routing_rules: RoutingRuleRow[] }>('/routing-rules', auth),
    // Delivery history is Supabase-read (SELECT-only under RLS, engine is the only writer).
    // Bounded: last 20 rows, named columns only.
    supabase
      .from('notification_deliveries')
      .select('id, integration_id, event, findings_count, status, error, created_at')
      .order('created_at', { ascending: false })
      .limit(20),
  ]);

  const integrations = integrationsRes.ok ? integrationsRes.data.integrations : [];
  const rules = rulesRes.ok ? rulesRes.data.routing_rules : [];
  const deliveries = (deliveriesRes.error ? [] : (deliveriesRes.data ?? [])) as DeliveryRow[];

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <Card>
        <CardHeader>
          <CardTitle>Integrations</CardTitle>
          <CardMeta>
            {integrationsRes.ok
              ? `${integrations.length} destination${integrations.length === 1 ? '' : 's'}`
              : 'unavailable'}
          </CardMeta>
        </CardHeader>
        <CardBody pad={!integrationsRes.ok || integrations.length === 0}>
          {!integrationsRes.ok ? (
            <EmptyState
              tone="error"
              title="Could not load integrations"
              description={`${integrationsRes.message} Existing deliveries are unaffected — this is only the management view.`}
            />
          ) : integrations.length === 0 ? (
            <EmptyState
              tone="setup"
              title="No integrations yet"
              description="Findings stay in the console until a destination exists. Add Slack, a webhook, email, Jira or a SIEM collector below, then point a routing rule at it."
            />
          ) : (
            <Table density="default" caption="Configured alert destinations">
              <THead>
                <TR>
                  <TH width="30%">Name</TH>
                  <TH width="18%">Type</TH>
                  <TH>Actions</TH>
                </TR>
              </THead>
              <TBody>
                {integrations.map((i) => {
                  const spec = integrationSpecFor(i.type);
                  return (
                    <TR key={i.id}>
                      <TD>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)' }}>{i.name}</span>
                      </TD>
                      <TD>
                        <span aria-hidden="true" style={{ color: 'var(--text-secondary)', marginRight: 'var(--space-1)' }}>
                          {spec?.glyph ?? '·'}
                        </span>
                        {spec?.label ?? i.type}
                      </TD>
                      <TD>
                        <IntegrationRowActions integrationId={i.id} name={i.name} />
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Add an integration</CardTitle>
          <CardMeta>secrets are stored server-side, never shown again</CardMeta>
        </CardHeader>
        <CardBody>
          <AddIntegration />
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Routing rules</CardTitle>
          <CardMeta>
            {rulesRes.ok ? `${rules.length} rule${rules.length === 1 ? '' : 's'}` : 'unavailable'}
          </CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
            {!rulesRes.ok ? (
              <EmptyState
                tone="error"
                title="Could not load routing rules"
                description={rulesRes.message}
              />
            ) : rules.length === 0 ? (
              <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', maxWidth: '64ch' }}>
                No rules yet — nothing is delivered anywhere. A rule says: findings at or above a
                severity (optionally from one connector type) go to an integration.
              </p>
            ) : (
              <Table density="compact" caption="Delivery routing rules">
                <THead>
                  <TR>
                    <TH width="24%">Min severity</TH>
                    <TH width="24%">Connector filter</TH>
                    <TH width="32%">Destination</TH>
                    <TH>Remove</TH>
                  </TR>
                </THead>
                <TBody>
                  {rules.map((r) => {
                    const connectors = r.match.connector_types ?? [];
                    return (
                      <TR key={r.id}>
                        {/* No min_severity in match = the rule routes every severity. */}
                        <TD mono>
                          {r.match.min_severity ? (
                            `${r.match.min_severity}+`
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>all</span>
                          )}
                        </TD>
                        <TD>
                          {connectors.length > 0 ? (
                            connectors.join(', ')
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>any</span>
                          )}
                        </TD>
                        <TD>
                          {r.integration.id ? (
                            `${r.integration.name} (${r.integration.type})`
                          ) : (
                            // A rule whose integration vanished delivers nowhere; say so
                            // rather than showing a blank that reads as fine.
                            <span style={{ color: 'var(--sev-medium-fg)' }}>
                              integration missing — delivers nowhere
                            </span>
                          )}
                        </TD>
                        <TD>
                          <RemoveRuleButton ruleId={r.id} />
                        </TD>
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            )}

            <AddRoutingRule integrations={integrations} />
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent deliveries</CardTitle>
          <CardMeta>last {deliveries.length === 20 ? '20' : deliveries.length} attempts, tests included</CardMeta>
        </CardHeader>
        <CardBody pad={deliveries.length === 0}>
          {deliveries.length === 0 ? (
            <p style={{ margin: 0, fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', maxWidth: '64ch' }}>
              Nothing sent yet. Every attempt — scan-triggered or a Test click — lands here with
              its outcome, so “did the alert arrive?” has an answer.
            </p>
          ) : (
            <Table density="compact" caption="Recent notification delivery attempts">
              <THead>
                <TR>
                  <TH width="22%">When</TH>
                  <TH width="26%">Destination</TH>
                  <TH width="16%">Event</TH>
                  <TH width="12%">Findings</TH>
                  <TH>Outcome</TH>
                </TR>
              </THead>
              <TBody>
                {deliveries.map((d) => {
                  const dest = integrations.find((i) => i.id === d.integration_id);
                  return (
                    <TR key={d.id}>
                      <TD mono>{new Date(d.created_at).toISOString().slice(0, 16).replace('T', ' ')}</TD>
                      <TD>
                        {dest ? (
                          `${dest.name} (${dest.type})`
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>removed integration</span>
                        )}
                      </TD>
                      <TD mono>{d.event}</TD>
                      <TD mono>{d.findings_count}</TD>
                      <TD>
                        {d.status === 'sent' ? (
                          <StatusPill tone="ok" label="sent" />
                        ) : (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 'var(--space-1)', flexWrap: 'wrap' }}>
                            <StatusPill tone="bad" label="error" />
                            {d.error && <span style={{ color: 'var(--sev-critical-fg)' }}>{d.error}</span>}
                          </span>
                        )}
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
