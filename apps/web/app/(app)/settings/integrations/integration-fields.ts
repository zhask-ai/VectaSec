/* The integration-form vocabulary: where findings can be delivered and what each destination
 * needs. Mirrors the engine's integration registry the same way connections/connector-fields
 * mirrors its connector registry, and for the same reason: the form must render (and say what
 * it would accept) while the engine is down. The engine re-validates every submission; drift
 * here costs a round trip and an error message, never a wrong write.
 *
 * `secret` fields render as password inputs, travel browser → Server Action → engine, and are
 * NEVER echoed back — not in the list view, not after a failed submit. A webhook URL with an
 * embedded token is a credential and is treated as one.
 */

export type IntegrationField = {
  key: string;
  label: string;
  required?: boolean;
  secret?: boolean;
  placeholder?: string;
  help?: string;
};

export type IntegrationSpec = {
  type: 'slack' | 'teams' | 'webhook' | 'email' | 'jira' | 'siem';
  label: string;
  /** One honest sentence for the picker. */
  blurb: string;
  /** A text glyph, not an imported logo: no external assets, works in both themes. */
  glyph: string;
  fields: IntegrationField[];
};

export const INTEGRATION_TYPES: IntegrationSpec[] = [
  {
    type: 'slack',
    label: 'Slack',
    blurb: 'Post findings to a channel via an incoming-webhook URL.',
    glyph: '#',
    fields: [
      {
        key: 'webhook_url',
        label: 'Incoming webhook URL',
        required: true,
        secret: true,
        placeholder: 'https://hooks.slack.com/services/…',
        help: 'Slack: app settings → Incoming Webhooks. The URL embeds a token, so it is stored server-side and never shown again.',
      },
    ],
  },
  {
    type: 'teams',
    label: 'Microsoft Teams',
    blurb: 'Post findings to a Teams channel as an Adaptive Card via an incoming-webhook URL.',
    glyph: '⊞',
    fields: [
      {
        key: 'webhook_url',
        label: 'Incoming webhook URL',
        required: true,
        secret: true,
        placeholder: 'https://….logic.azure.com/workflows/… or https://….webhook.office.com/…',
        help: 'Teams: Workflows → "Post to a channel when a webhook request is received" (or a legacy Incoming Webhook connector). The URL embeds a signature, so it is stored server-side and never shown again.',
      },
    ],
  },
  {
    type: 'webhook',
    label: 'Webhook',
    blurb: 'POST findings as JSON to any HTTPS endpoint you run.',
    glyph: '⇥',
    fields: [
      {
        key: 'url',
        label: 'Endpoint URL',
        required: true,
        // The engine vaults this (notify.INTEGRATION_SECRET_KEYS["webhook"] includes "url"), so
        // rendering it as a plain text input contradicted this file's own header — and made
        // re-saving a webhook demand a URL the console could not show, while the success
        // message promised that blanks were left unchanged.
        secret: true,
        placeholder: 'https://alerts.example.com/vectasec',
      },
      {
        key: 'hmac_secret',
        label: 'Signing secret',
        secret: true,
        placeholder: 'optional',
        help: 'If set, deliveries are HMAC-signed so your endpoint can verify they came from VectaSec.',
      },
    ],
  },
  {
    type: 'email',
    label: 'Email',
    blurb: 'Send finding notifications to one or more addresses.',
    glyph: '@',
    fields: [
      {
        key: 'to',
        label: 'Recipients',
        required: true,
        placeholder: 'oncall@example.com, secops@example.com',
        help: 'Comma-separated addresses.',
      },
    ],
  },
  {
    type: 'jira',
    label: 'Jira',
    blurb: 'File findings as issues in a Jira Cloud project.',
    glyph: '◻',
    fields: [
      { key: 'base_url', label: 'Jira base URL', required: true, placeholder: 'https://yourteam.atlassian.net' },
      { key: 'project_key', label: 'Project key', required: true, placeholder: 'SEC' },
      { key: 'email', label: 'Account email', required: true, placeholder: 'bot@example.com' },
      {
        key: 'api_token',
        label: 'API token',
        required: true,
        secret: true,
        help: 'An Atlassian API token for that account. Stored server-side, never shown again.',
      },
      { key: 'issue_type', label: 'Issue type', placeholder: 'Task (default)' },
    ],
  },
  {
    type: 'siem',
    label: 'SIEM',
    blurb: 'Forward findings to a SIEM HTTP collector (Splunk HEC, Sentinel, …).',
    glyph: '≡',
    fields: [
      {
        key: 'url',
        label: 'Collector URL',
        required: true,
        secret: true,
        placeholder: 'https://splunk.example.com:8088/services/collector',
        help: 'Collector URLs routinely embed tokens, so the whole URL is treated as a secret.',
      },
      {
        key: 'token',
        label: 'Bearer token',
        secret: true,
        placeholder: 'optional',
        help: 'Sent as an Authorization bearer if the collector requires one.',
      },
    ],
  },
];

export function integrationSpecFor(type: string): IntegrationSpec | null {
  return INTEGRATION_TYPES.find((s) => s.type === type) ?? null;
}
