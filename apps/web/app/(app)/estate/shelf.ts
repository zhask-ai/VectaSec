/* The connector SHELF — what the catalogue and the connect dialog show by default.
 *
 * The engine registers 39 connectors and every one stays scannable. What changes here is only
 * what a first-session buyer sees: docs/vectasec-smb-strategy-2026-10.md §3 scored the catalogue
 * against "does an SMB new to cloud recognise this in the first ten minutes", and twelve cards
 * passed. The rest are real, supported and one toggle away under "Enterprise, on request" —
 * hidden, not removed, because a thirty-nine-card wall was the single clearest reason prospects
 * read the product as a smaller Wiz rather than the one thing only it does.
 *
 * A card can front SEVERAL connector types (Kafka fronts kafka / confluent / redpanda; the API
 * contract card fronts openapi / graphql). The engine, the Server Action and connector-fields.ts
 * still speak in connector types; a card is presentation, and picking one resolves to a type
 * before anything is submitted. Nothing in this file touches the engine registry.
 */

export type ShelfCard = {
  id: string;
  label: string;
  /** One honest sentence: what connecting this reads, in the buyer's words. */
  blurb: string;
  /** Connector types this card fronts, in the order they are offered. */
  types: string[];
  /** Where a related system lives when it is NOT one of this card's types. */
  note?: string;
};

export const SHELF: ShelfCard[] = [
  { id: 'aws', label: 'AWS', types: ['aws'], blurb: 'One read-only role: SQS, SNS, EventBridge, MSK and API Gateway — who can reach them, and which IAM users and roles have gone unused.', note: 'Includes Amazon MSK and API Gateway.' },
  { id: 'gcp', label: 'Google Cloud', types: ['gcp'], blurb: 'Pub/Sub and Apigee through a read-only service account: public bindings, push endpoints without auth, missing CMEK.' },
  { id: 'azure', label: 'Azure', types: ['azure'], blurb: 'Service Bus, Event Hubs, API Management and Logic Apps through a Reader app registration: SAS keys, open triggers, legacy TLS.' },
  { id: 'k8s', label: 'Kubernetes & service mesh', types: ['k8s'], blurb: 'One cluster read: Istio / Linkerd mTLS posture, Gateway API and Ingress exposure, RBAC and service-account tokens.' },
  { id: 'kafka', label: 'Kafka', types: ['kafka', 'confluent', 'redpanda'], blurb: 'Listeners, SASL/TLS, ACLs and super-users — Apache Kafka, Confluent Cloud or Redpanda. Amazon MSK comes in through the AWS card.', note: 'Apache Kafka · Confluent Cloud · Redpanda · (MSK via AWS)' },
  { id: 'rabbitmq', label: 'RabbitMQ', types: ['rabbitmq'], blurb: 'Users, vhost permissions, guest/guest, plaintext AMQP, management API over HTTP, end-of-life branches.' },
  { id: 'redis', label: 'Redis', types: ['redis'], blurb: 'No-password access, ACL users, TLS, dangerous commands and internet-reachable instances.' },
  { id: 'kong', label: 'Kong & API Gateway', types: ['kong'], blurb: 'Routes with no auth plugin, consumer credentials, an unauthenticated admin API, missing rate limits. AWS API Gateway comes in through the AWS card.', note: 'AWS API Gateway via the AWS card' },
  { id: 'n8n', label: 'n8n automations', types: ['n8n'], blurb: 'Which workflows hold which credentials, public webhooks, and the unauthenticated-RCE releases.' },
  { id: 'mcp', label: 'MCP servers & AI agents', types: ['mcp'], blurb: 'Which agent gateways hold which credentials: OAuth discovery, PKCE, unauthenticated endpoints, the exposed tool surface.' },
  { id: 'api', label: 'OpenAPI & GraphQL', types: ['openapi', 'graphql'], blurb: 'The API contract itself: operations with no security scheme, introspection left on, over-permissive schemas.' },
  { id: 'iac', label: 'Repos & manifests', types: ['iac'], blurb: 'Compose files, Helm charts and Terraform: the one source that can see a broker credential also committed to git.' },
];

/** Connector types a shelf card fronts, type → card. */
export const CARD_OF: Record<string, ShelfCard> = Object.fromEntries(SHELF.flatMap((c) => c.types.map((t): [string, ShelfCard] => [t, c])));

export function onShelf(type: string): boolean {
  return type in CARD_OF;
}

/** The network sweep is not a system you connect — it is the free external exposure scan that
 * feeds the Unmonitored tab. It is listed beside the shelf rather than tiered either way. */
export const SWEEP_TYPE = 'discovery';
