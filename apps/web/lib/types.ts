/* TS mirrors of the DB tables (supabase/migrations/*).
 *
 * These describe ROWS as Postgres stores them. They are deliberately NOT what the console
 * ships to the browser: `resources.raw` and `connections.config` are collector payloads and
 * credential refs, so a row must be narrowed to a DTO before it crosses to a client component.
 * See lib/supabase/server.ts.
 *
 * The browser role is SELECT-only on every table (no INSERT/UPDATE/DELETE policy is granted
 * to `authenticated` anywhere) — mutations go through the engine API. So there are no Insert/
 * Update variants here on purpose; adding them would imply a capability the DB refuses.
 */

/** Severity is a property of the RULE. Priority is a property of the occurrence — keep separate. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** The six DB states. The UI collapses these to four (see UiStatus) — the DB keeps all six. */
export type FindingStatus =
  | 'open'
  | 'triaged'
  | 'in_progress'
  | 'resolved'
  | 'suppressed'
  | 'accepted';

/** `triaged` vs `in_progress` and `resolved`/`accepted`/`suppressed` are not distinguishable
 * to an analyst mid-queue. Collapse for display only; never write these back. */
export type UiStatus = 'open' | 'in_progress' | 'resolved' | 'muted';

export const UI_STATUS_OF: Record<FindingStatus, UiStatus> = {
  open: 'open',
  triaged: 'in_progress',
  in_progress: 'in_progress',
  resolved: 'resolved',
  suppressed: 'muted',
  accepted: 'muted',
};

export type ScanStatus = 'queued' | 'running' | 'done' | 'error';
export type ConnectionMode = 'collector' | 'cloud';
export type CollectorStatus = 'pending' | 'active' | 'degraded' | 'offline';
export type ControlStatus = 'pass' | 'fail' | 'unknown' | 'not_applicable';
export type MemberRole = 'owner' | 'admin' | 'analyst' | 'viewer';
export type AiOutputKind = 'triage' | 'remediate' | 'answer' | 'summary';

export type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

export interface Tenant {
  id: string;
  name: string;
  plan: string;
  region: string | null;
  created_at: string;
}

export interface TenantMember {
  tenant_id: string;
  user_id: string;
  role: MemberRole;
  created_at: string;
}

export interface Connection {
  id: string;
  tenant_id: string;
  /** kafka|kong|rabbitmq|istio|mulesoft|mcp… — open-ended: connectors self-register in the engine. */
  type: string;
  name: string;
  mode: ConnectionMode;
  status: string;
  /** May carry credential *references*. Never ship wholesale to a client component. */
  config: Json;
  created_at: string;
  last_scanned_at: string | null;
  collector_id: string | null;
  /** Vault ref (cloud) or null (the Collector holds creds locally). Never a secret itself. */
  creds_ref: string | null;
  rate_limit: Json;
}

export interface Resource {
  id: string;
  tenant_id: string;
  connection_id: string | null;
  /** broker|topic|route|service|acl… */
  kind: string;
  name: string;
  namespace: string | null;
  labels: Json;
  /** The raw collector payload. A genuine leak risk — narrow to a DTO before the client. */
  raw: Json;
  /** The connector's stable id; the join key for the whole graph. */
  ext_id: string;
  first_seen: string;
  last_seen: string;
  stale: boolean;
}

export interface Edge {
  id: string;
  tenant_id: string;
  src_resource_id: string;
  dst_resource_id: string;
  kind: string;
  labels: Json;
}

export interface Scan {
  id: string;
  tenant_id: string;
  connection_id: string | null;
  status: ScanStatus;
  started_at: string;
  finished_at: string | null;
  stats: Json;
}

export interface Finding {
  id: string;
  tenant_id: string;
  scan_id: string | null;
  resource_id: string | null;
  rule_id: string;
  /** Dedups the same issue across scans. Same fingerprint = same row, last_seen updates —
   * never a new row. Grouping by rule_id across assets is a different concept. */
  fingerprint: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  assignee: string | null;
  due_at: string | null;
  remediation: string | null;
  detail: string | null;
  first_seen: string;
  last_seen: string;
}

/** A row in the immutable evidence ledger. UPDATE is rejected by a DB trigger — the claim can
 * never be rewritten, which is what makes it evidence. The only thing the AI may cite. */
export interface Observation {
  id: string;
  tenant_id: string;
  finding_id: string | null;
  resource_id: string | null;
  /** A fact read from the target ("allow.everyone.if.no.acl.found = true"), never a conclusion. */
  claim: string;
  source_ref: Json;
  observed_at: string;
}

export interface Control {
  id: string;
  tenant_id: string;
  /** PCI_DSS_4_0_1|DORA|HIPAA|NIS2 */
  framework: string;
  control_id: string;
  title: string;
  requirement: string | null;
  status: ControlStatus;
  failing_finding_ids: Json;
  evaluated_at: string | null;
}

/** Cannot exist in a committed transaction without ≥1 linked observation — a deferred
 * constraint trigger enforces the citation gate in Postgres, not in app code. */
export interface AiOutput {
  id: string;
  tenant_id: string;
  scan_id: string | null;
  finding_id: string | null;
  kind: AiOutputKind;
  content: string;
  /** Cache key: same fingerprint => reuse, which keeps LLM cost flat. */
  fingerprint: string;
  model: string | null;
  created_at: string;
}

export interface AiOutputEvidence {
  ai_output_id: string;
  observation_id: string;
}

export interface Collector {
  id: string;
  tenant_id: string;
  name: string;
  status: CollectorStatus;
  version: string | null;
  last_heartbeat: string | null;
  created_at: string;
}

export interface Suppression {
  id: string;
  tenant_id: string;
  rule_id: string;
  /** {} = tenant-wide; else {resource_id|kind|name_glob}. */
  scope: Json;
  /** Required by the schema: an exception without a reason is a landmine for the next analyst. */
  reason: string;
  /** null = permanent. Discouraged — surface it in the UI rather than hiding it. */
  expires_at: string | null;
  created_by: string | null;
  created_at: string;
}

export interface AuditLogEntry {
  id: string;
  tenant_id: string;
  /** user uuid | 'engine' | 'collector:<id>' */
  actor: string;
  action: string;
  target: string | null;
  detail: Json;
  at: string;
}

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Order is itself an accessibility channel — position carries meaning when hue cannot.
 * Sort severity descending by default. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type SeverityCounts = Record<Severity, number>;
