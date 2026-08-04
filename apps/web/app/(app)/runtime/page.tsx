import { createClient } from '@/lib/supabase/server';
import { AutoRefresh } from '@/components/AutoRefresh';
import { Card, CardBody, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { EmptyState } from '@/components/ui/empty-state';
import { PageHeader } from '@/components/ui/page-header';
import { StatusPill } from '@/components/ui/status-pill';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';

/* Runtime evidence — who is actually using the estate, not who is permitted to.
 *
 * Deliberately NOT called "validation". Gartner's Adversarial Exposure Validation defines that
 * word as safely executing an attack to prove it works; we observe, we do not exploit, and
 * borrowing the term would misrepresent what the number means to anyone fluent in the category.
 *
 * The hardest thing to render honestly on this page is ABSENCE. A principal we have never seen
 * might be idle, or might run quarterly while we sample hourly, or might have been busy during
 * a week our collector was broken. So the observation window is shown as a real number with a
 * real start date, and until it is long enough the page says the question is unanswered rather
 * than implying the answer is "unused".
 */

export const metadata = { title: 'Runtime · VectaSec' };

// Both mirror runtime_evidence.py. If they drift, this page and the engine disagree
// about whether an identity may be called unused.
const MIN_WINDOW_DAYS = 14;
const MIN_SCANS = 20;

// Mirrors runtime_evidence.RUNTIME_SOURCES — which connector types can see live clients AT
// ALL, and what they read. This is a capability, not an observation, and the distinction is
// the point: a Kong connection has no live-client API in the product, while a Kafka connection
// with no consumer groups genuinely observed nothing. Rendering one empty panel for both tells
// an operator something false about their coverage. Absent from this map = no runtime source.
//
// `attributes` mirrors the engine's gate on RUNTIME.GRANT.NEVER_OBSERVED: only a source that
// names an AUTHENTICATED principal can support "this identity was never used". Kafka's
// client.id is self-asserted, so no identity is ever reported unused from it — and this page
// has to say so, or the Identities view looks unexplainably quiet for a Kafka estate.
const RUNTIME_SOURCES: Record<string, { reads: string; attributes: boolean }> = {
  rabbitmq: { reads: 'GET /api/connections — principal, vhost, peer, SASL mechanism, TLS', attributes: true },
  redis: { reads: 'CLIENT LIST + ACL LOG — connected clients and their denials', attributes: true },
  nats: { reads: 'GET /connz?auth=1 — live connections with their authenticated account', attributes: true },
  pgbouncer: { reads: 'SHOW CLIENTS — pooled sessions and the user each authenticated as', attributes: true },
  kafka: {
    reads: 'DescribeConsumerGroups — consumer members only; producers are invisible, per-client transport is not reported, and the client.id is self-asserted rather than an authenticated identity',
    attributes: false,
  },
};

type ClientRow = {
  id: string;
  name: string;
  labels: Record<string, string> | null;
  raw: {
    principal?: string | null;
    principal_known?: boolean;
    peer_host?: string;
    connections?: number;
    auth_mechanisms?: string[];
    commands?: string[];
    tls_all?: boolean | null;
    observed_via?: string;
  } | null;
};

type DenialRow = {
  id: string;
  name: string;
  labels: Record<string, string> | null;
  raw: { principal?: string; reason?: string; denials?: number; peer_hosts?: string[] } | null;
};

type EvidenceRow = {
  principal: string | null;
  source: string;
  peer_host: string | null;
  first_seen: string;
  last_seen: string;
  observed_scans: number;
};

function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

function daysSince(iso: string): number {
  return (Date.now() - new Date(iso).getTime()) / 86_400_000;
}

export default async function RuntimePage() {
  const supabase = await createClient();

  const [clientsRes, denialsRes, evidenceRes, connectionsRes, scansRes] = await Promise.all([
    supabase.from('resources').select('id, name, labels, raw').eq('kind', 'runtime_client').order('name'),
    supabase.from('resources').select('id, name, labels, raw').eq('kind', 'access_denial').order('name'),
    supabase
      .from('runtime_evidence')
      .select('principal, source, peer_host, first_seen, last_seen, observed_scans')
      .order('last_seen', { ascending: false })
      .limit(200),
    supabase
      .from('connections')
      .select('id, name, type, runtime_observation_started_at'),
    supabase.from('scans').select('id', { count: 'exact', head: true }).eq('status', 'done'),
  ]);

  const clients = (clientsRes.data ?? []) as ClientRow[];
  const denials = (denialsRes.data ?? []) as DenialRow[];
  const evidence = (evidenceRes.data ?? []) as EvidenceRow[];
  const connections = (connectionsRes.data ?? []) as {
    id: string; name: string; type: string; runtime_observation_started_at: string | null;
  }[];
  const completedScans = scansRes.count ?? 0;

  // A failed query must not render as "no runtime evidence yet" — that empty state reads as
  // a reassuring fact when it is actually a broken read.
  const loadError = clientsRes.error ?? denialsRes.error ?? evidenceRes.error;
  if (loadError) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
        <Head />
        <Card>
          <CardBody>
            <EmptyState tone="error" title="Could not load runtime evidence"
                        description={loadError.message} />
          </CardBody>
        </Card>
      </div>
    );
  }

  // The window comes from `connections.runtime_observation_started_at` — the same value the
  // engine measures against — NOT from the earliest first_seen in this page's rows. Those rows
  // are a `.limit(200)` slice ordered by last_seen, so on a busy tenant the oldest evidence is
  // dropped and the derived window shrinks arbitrarily. That let this page claim "window
  // sufficient" while the engine was filing not-assessable, which is the one disagreement a
  // page about epistemics must never have with its own backend.
  const windowStart = connections.reduce<string | null>(
    (earliest, c) =>
      c.runtime_observation_started_at &&
      (!earliest || c.runtime_observation_started_at < earliest)
        ? c.runtime_observation_started_at
        : earliest,
    null,
  );
  const windowDays = windowStart ? daysSince(windowStart) : 0;
  // BOTH thresholds, mirroring runtime_evidence.py. Days alone is not the engine's test.
  const windowReady =
    windowStart !== null && windowDays >= MIN_WINDOW_DAYS && completedScans >= MIN_SCANS;
  const principals = new Set(evidence.map((e) => e.principal).filter(Boolean));

  if (clients.length === 0 && evidence.length === 0) {
    return (
      <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
        <Head />
        <Card>
          <CardBody>
            <EmptyState
              tone="setup"
              title="No runtime evidence yet"
              description="Runtime evidence comes from the systems themselves — RabbitMQ's connections API, Redis' CLIENT LIST, NATS' /connz, PgBouncer's SHOW CLIENTS and Kafka's consumer-group members each name who is connected right now. No sensor or agent is required; scan any of those connections and this fills in."
              meta={`runtime sources: ${Object.keys(RUNTIME_SOURCES).join(' · ')}`}
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <AutoRefresh active />
      <Head meta={`${clients.length} live client group${clients.length === 1 ? '' : 's'}`} />

      {/* Coverage first, deliberately: every number below it means nothing without it. */}
      <Card>
        <CardHeader>
          <CardTitle>Observation window</CardTitle>
          <CardMeta>what this page is entitled to claim</CardMeta>
        </CardHeader>
        <CardBody>
          <div style={{ display: 'flex', gap: 'var(--space-4)', flexWrap: 'wrap', alignItems: 'baseline' }}>
            <div>
              <span data-numeric style={{ fontSize: 'var(--text-2xl, 28px)', fontWeight: 700 }}>
                {windowStart ? windowDays.toFixed(1) : '0'}
              </span>{' '}
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                days observed
              </span>
            </div>
            <div>
              <span data-numeric style={{ fontSize: 'var(--text-2xl, 28px)', fontWeight: 700 }}>
                {principals.size}
              </span>{' '}
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                distinct principals seen
              </span>
            </div>
            <StatusPill
              tone={windowReady ? 'ok' : 'warn'}
              label={windowReady ? 'window sufficient' : 'window too short'}
            />
          </div>
          <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
            {windowReady
              ? `Identities never seen across ${completedScans} scans over ${windowDays.toFixed(0)} days are reported as unused in the findings queue. This is sampled evidence, not metering — a job that runs less often than the window could still be legitimate.`
              : `Absence of evidence is not evidence of absence. No identity is reported as unused until this reaches ${MIN_WINDOW_DAYS} days across ${MIN_SCANS} completed scans (currently ${windowDays.toFixed(1)} days, ${completedScans} scans) — an unseen principal may simply run on a schedule longer than we have been watching.`}
          </p>
        </CardBody>
      </Card>

      {/* Which of THIS tenant's connections can produce runtime evidence at all. Without it,
          a Kong estate reads the panels above as "nothing is talking to our systems" when the
          truth is "we cannot see what is talking to them" — opposite conclusions. */}
      <Card>
        <CardHeader>
          <CardTitle>Runtime coverage</CardTitle>
          <CardMeta>
            which connected systems can report live clients — and which cannot be asked
          </CardMeta>
        </CardHeader>
        <CardBody pad={connections.length === 0}>
          {connections.length === 0 ? (
            <EmptyState
              tone="setup"
              title="No systems connected"
              description="Runtime evidence is read from connected systems. Connect one whose connector has a live-client source."
            />
          ) : (
            <>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', padding: '0 0 12px' }}>
                <StatusPill
                  tone="ok"
                  label={`${connections.filter((c) => RUNTIME_SOURCES[c.type]).length} of ${connections.length} can be observed`}
                />
                {connections.some((c) => !RUNTIME_SOURCES[c.type]) && (
                  <StatusPill
                    tone="neutral"
                    label={`${connections.filter((c) => !RUNTIME_SOURCES[c.type]).length} have no runtime source`}
                  />
                )}
              </div>
              <Table density="compact" caption="Runtime evidence availability per connection">
                <THead>
                  <TR>
                    <TH width="20%">Connection</TH>
                    <TH width="12%">Type</TH>
                    <TH width="18%">Status</TH>
                    <TH width="50%">What is read</TH>
                  </TR>
                </THead>
                <TBody>
                  {[...connections]
                    .sort((a, b) =>
                      Number(Boolean(RUNTIME_SOURCES[b.type])) - Number(Boolean(RUNTIME_SOURCES[a.type])) ||
                      a.name.localeCompare(b.name),
                    )
                    .map((c) => {
                      const source = RUNTIME_SOURCES[c.type];
                      const observing = Boolean(c.runtime_observation_started_at);
                      return (
                        <TR key={c.id}>
                          <TD>{c.name}</TD>
                          <TD mono>{c.type}</TD>
                          <TD>
                            <div style={{ display: 'grid', gap: 4, justifyItems: 'start' }}>
                              {!source ? (
                                <StatusPill tone="neutral" label="no runtime source" />
                              ) : observing ? (
                                <StatusPill tone="ok" label="observing" />
                              ) : (
                                <StatusPill tone="warn" label="capable · nothing seen yet" />
                              )}
                              {source && !source.attributes && (
                                <StatusPill tone="neutral" label="cannot attribute identities" />
                              )}
                            </div>
                          </TD>
                          <TD muted>
                            {source?.reads ?? 'This system exposes no live-client API that VectaSec can read. Nothing here is evidence about its usage.'}
                          </TD>
                        </TR>
                      );
                    })}
                </TBody>
              </Table>
              <p style={{ margin: '10px 0 0', fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                &ldquo;No runtime source&rdquo; and &ldquo;nothing seen yet&rdquo; are different
                answers. The first is a permanent property of that system&rsquo;s API and no
                amount of scanning changes it; the second closes as the window fills. Where a
                source reports sessions it cannot attribute to an authenticated principal —
                Kafka&rsquo;s consumer groups carry a self-asserted <code>client.id</code>, not
                an identity — no identity is ever reported unused from it.
              </p>
            </>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Live clients</CardTitle>
          <CardMeta>read from the brokers&apos; own APIs — no sensor, no agent</CardMeta>
        </CardHeader>
        <CardBody pad={false}>
          {clients.length === 0 ? (
            <div style={{ padding: 'var(--space-4)' }}>
              <EmptyState
                tone="setup"
                title="Nothing connected at the last scan"
                description="This means nothing was connected in the instants we looked — not that the broker is unused."
              />
            </div>
          ) : (
            <Table density="default" caption="Clients connected at the last scan">
              <THead>
                <TR>
                  <TH width="22%">Principal</TH>
                  <TH width="18%">From</TH>
                  <TH width="10%" numeric>Conns</TH>
                  <TH width="16%">Transport</TH>
                  <TH width="34%">Observed</TH>
                </TR>
              </THead>
              <TBody>
                {clients.map((c) => {
                  const raw = c.raw ?? {};
                  const labels = c.labels ?? {};
                  const unattributed = raw.principal_known === false;
                  const cleartext =
                    (raw.auth_mechanisms ?? []).some((m) =>
                      ['PLAIN', 'AMQPLAIN', 'LOGIN'].includes(String(m).toUpperCase()),
                    ) && raw.tls_all !== true;
                  return (
                    <TR key={c.id}>
                      <TD>
                        <span style={{ fontWeight: 600 }}>
                          {raw.principal ?? (
                            <span style={{ color: 'var(--text-muted)' }}>unattributed</span>
                          )}
                        </span>
                        {unattributed && (
                          <div style={{ marginTop: 3 }}>
                            <StatusPill tone="warn" label="no principal" />
                          </div>
                        )}
                      </TD>
                      <TD>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>
                          {raw.peer_host ?? '—'}
                        </span>
                      </TD>
                      <TD numeric>{raw.connections ?? 1}</TD>
                      <TD>
                        {cleartext ? (
                          <StatusPill tone="bad" label="cleartext auth" />
                        ) : (
                          <StatusPill
                            tone={raw.tls_all === true ? 'ok' : 'neutral'}
                            label={raw.tls_all === true ? 'tls' : (labels.source ?? 'observed')}
                          />
                        )}
                      </TD>
                      <TD>
                        <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                          {raw.observed_via ?? '—'}
                          {(raw.auth_mechanisms ?? []).length > 0 &&
                            ` · ${(raw.auth_mechanisms ?? []).join(', ')}`}
                          {(raw.commands ?? []).length > 0 &&
                            ` · commands: ${(raw.commands ?? []).slice(0, 4).join(', ')}`}
                        </span>
                      </TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardBody>
      </Card>

      {denials.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Access denials</CardTitle>
            <CardMeta>
              refused authentications and permission failures — the credential-stuffing signal
            </CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="default" caption="Denied access attempts">
              <THead>
                <TR>
                  <TH width="26%">Principal</TH>
                  <TH width="18%">Reason</TH>
                  <TH width="14%" numeric>Denials</TH>
                  <TH width="42%">From</TH>
                </TR>
              </THead>
              <TBody>
                {denials.map((d) => (
                  <TR key={d.id}>
                    <TD>
                      <span style={{ fontWeight: 600 }}>{d.raw?.principal ?? '—'}</span>
                    </TD>
                    <TD>
                      <StatusPill
                        tone={d.raw?.reason === 'auth' ? 'bad' : 'warn'}
                        label={d.raw?.reason ?? 'unknown'}
                      />
                    </TD>
                    <TD numeric>{d.raw?.denials ?? 0}</TD>
                    <TD>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-2xs)' }}>
                        {(d.raw?.peer_hosts ?? []).join(', ') || '—'}
                      </span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      )}

      {evidence.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Accumulated evidence</CardTitle>
            <CardMeta>
              {evidence.length} principal/source pair{evidence.length === 1 ? '' : 's'} · counts are
              scans that saw the activity, never messages
            </CardMeta>
          </CardHeader>
          <CardBody pad={false}>
            <Table density="compact" caption="Runtime evidence accumulated across scans">
              <THead>
                <TR>
                  <TH width="24%">Principal</TH>
                  <TH width="24%">Source</TH>
                  <TH width="16%">First seen</TH>
                  <TH width="16%">Last seen</TH>
                  <TH width="20%" numeric>Scans that saw it</TH>
                </TR>
              </THead>
              <TBody>
                {evidence.slice(0, 50).map((e, i) => (
                  <TR key={`${e.principal}-${e.source}-${i}`}>
                    <TD>
                      <span style={{ fontWeight: 600 }}>
                        {e.principal ?? <span style={{ color: 'var(--text-muted)' }}>unattributed</span>}
                      </span>
                    </TD>
                    <TD>
                      <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
                        {e.source}
                      </span>
                    </TD>
                    <TD>{relative(e.first_seen)}</TD>
                    <TD>{relative(e.last_seen)}</TD>
                    <TD numeric>{e.observed_scans}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function Head({ meta }: { meta?: string }) {
  return (
    <PageHeader
      title="Runtime evidence"
      description="Who is actually using the estate right now, read from the brokers themselves. Observation, not exploitation — and explicit about how long it has been watching."
      meta={meta}
    />
  );
}
