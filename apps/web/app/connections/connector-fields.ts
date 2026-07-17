/* The connect-form vocabulary: which systems can be connected and what a human must supply.
 *
 * This MIRRORS the engine's registry (services/engine/src/vectasec/registry.py
 * CONNECTOR_FIELDS, served at GET /connectors) rather than fetching it, deliberately: the
 * form must render — and say what it *would* accept — while the engine is down, because
 * "what can VectaSec see" is a question the console answers even when nothing can be
 * changed. The engine re-validates every submission against its own spec, so drift here can
 * cost a round trip and an error message, never a wrong write. If you add a connector,
 * update both (the engine's is authoritative).
 *
 * `secret` fields render as password inputs and are never echoed back into the form after a
 * failed submit. They travel: browser → Server Action → engine → connections.config (jsonb).
 * They are never written to Supabase by the browser and never SELECTed by any console page —
 * the browser role cannot read `config` at all in practice because no query asks for it.
 */

export type ConnectorField = {
  key: string;
  label: string;
  required?: boolean;
  secret?: boolean;
  placeholder?: string;
  help?: string;
};

export type ConnectorSpec = {
  type: string;
  label: string;
  /** One honest sentence for the picker — what connecting this actually inspects. */
  blurb: string;
  /** Detector count, stated in the picker ("20 checks"). Keep in sync with `vectasec rules`. */
  rules: number;
  fields: ConnectorField[];
};

export const CONNECTORS: ConnectorSpec[] = [
  {
    type: 'kafka',
    label: 'Apache Kafka',
    blurb: 'Brokers, topics, ACLs — listener security, authorization, durability posture.',
    rules: 20,
    fields: [
      {
        key: 'bootstrap',
        label: 'Bootstrap servers',
        required: true,
        placeholder: 'broker-1:9092,broker-2:9092',
        help: 'Comma-separated host:port list the engine or worker can reach. Read-only AdminClient — nothing is written to the cluster.',
      },
    ],
  },
  {
    type: 'rabbitmq',
    label: 'RabbitMQ',
    blurb: 'Management API — users, vhosts, TLS, guest access, policy posture.',
    rules: 18,
    fields: [
      {
        key: 'url',
        label: 'Management API URL',
        required: true,
        placeholder: 'http://localhost:15672',
        help: 'RabbitMQ management plugin base URL. GETs only.',
      },
      {
        key: 'username',
        label: 'Username',
        required: true,
        help: "A user with the read-only 'monitoring' tag is enough.",
      },
      { key: 'password', label: 'Password', required: true, secret: true },
    ],
  },
  {
    type: 'kong',
    label: 'Kong Gateway',
    blurb: 'Admin API — routes, services, plugins, consumer credentials, exposure.',
    rules: 16,
    fields: [
      {
        key: 'url',
        label: 'Admin API URL',
        required: true,
        placeholder: 'http://localhost:8001',
        help: 'Kong Admin API base URL. GETs only.',
      },
      {
        key: 'admin_token',
        label: 'Admin token',
        secret: true,
        help: 'Kong-Admin-Token for RBAC-enabled gateways — use a read-only role.',
      },
    ],
  },
  {
    type: 'mcp',
    label: 'MCP server',
    blurb: 'Model Context Protocol servers and agent gateways — transport, auth, tool surface.',
    rules: 19,
    fields: [
      {
        key: 'url',
        label: 'MCP endpoint',
        required: true,
        placeholder: 'https://mcp.example.com/mcp',
        help: 'Streamable HTTP endpoint of the MCP server or gateway.',
      },
      {
        key: 'token',
        label: 'Bearer token',
        secret: true,
        help: 'Only if the server requires auth. Passive checks by default.',
      },
    ],
  },
];

export function specFor(type: string): ConnectorSpec | undefined {
  return CONNECTORS.find((c) => c.type === type);
}
