import { engineGet } from '@/lib/engine';
import { getOwnMembership } from '@/lib/role';
import { getClaims } from '@/lib/supabase/server';
import { Card, CardBody, CardFooter, CardHeader, CardMeta, CardTitle } from '@/components/ui/card';
import { Chip } from '@/components/ui/chip';
import { StatusPill } from '@/components/ui/status-pill';

/* "Who can actually reach this" — effective access, evaluated with the system's own rules
 * (engine: effective.py). Kafka topics: ACL evaluation with deny precedence, super users and the
 * allow.everyone trap. RabbitMQ vhosts: permission regexes and administrator escalation. Redis
 * servers: the default user and each user's real command rules. Renders nothing for other kinds. */

type Row = { principal: string; via: string };
type Kafka = { system: 'kafka'; assessable: boolean; readers: Row[]; writers: Row[]; everyone_read: boolean | null; everyone_write: boolean | null; reason: string; caveats: string[] };
type Perm = { scope: 'all' | 'some' | 'none'; pattern: string; unanchored?: boolean };
type Rabbit = {
  system: 'rabbitmq';
  users: { user: string; tags: string[]; read: Perm; write: Perm; configure: Perm; can_grant_itself_anything: boolean }[];
  read_everything: string[];
  administrators: string[];
  reason: string;
  caveats: string[];
};
type RedisUser = { user: string; enabled: boolean; nopass: boolean; commands_known: boolean; all_keys: boolean; key_restricted: boolean; risky: { command: string; effect: string }[]; keyless_bypass: boolean; self_escalation: boolean; anonymous: boolean };
type Redis = { system: 'redis'; users: RedisUser[]; anonymous_access: boolean; exposed_bind: boolean; protected_mode: boolean; reason: string; caveats: string[] };
type Resp = ({ supported: false } | ({ supported: true } & (Kafka | Rabbit | Redis)));

const KINDS = new Set(['topic', 'vhost', 'redis_server']);
const small: React.CSSProperties = { margin: 0, fontSize: 'var(--text-xs)', lineHeight: 'var(--leading-sm)' };

export async function WhoCan({ resourceId, kind }: { resourceId: string; kind: string }) {
  if (!KINDS.has(kind)) return null;
  const [membership, claims] = await Promise.all([getOwnMembership(), getClaims()]);
  const actor = typeof claims?.sub === 'string' ? claims.sub : null;
  if (!membership || !actor) return null;
  const res = await engineGet<Resp>(`/access/who-can/${resourceId}`, { tenantId: membership.tenantId, actor });
  if (!res.ok || !res.data.supported) return null;
  const d = res.data;

  return (
    <Card accent>
      <CardHeader>
        <CardTitle>Who can actually reach this</CardTitle>
        <CardMeta>evaluated with {d.system === 'kafka' ? "Kafka's ACL rules" : d.system === 'rabbitmq' ? "RabbitMQ's permission rules" : "Redis's ACL rules"}</CardMeta>
      </CardHeader>
      <CardBody>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          {d.system === 'kafka' && <KafkaView d={d} />}
          {d.system === 'rabbitmq' && <RabbitView d={d} />}
          {d.system === 'redis' && <RedisView d={d} />}
        </div>
      </CardBody>
      <CardFooter>{d.caveats.join(' ')}</CardFooter>
    </Card>
  );
}

function List({ title, rows }: { title: string; rows: Row[] }) {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-1)' }}>
      <p style={{ ...small, fontWeight: 600 }}>{title}</p>
      {rows.length === 0 ? (
        <p style={{ ...small, color: 'var(--text-secondary)' }}>Nobody beyond what is stated above.</p>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 2 }}>
          {rows.map((r, i) => (
            <li key={i} style={{ ...small, display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
              <code>{r.principal}</code>
              <span style={{ color: 'var(--text-secondary)' }}>{r.via}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function KafkaView({ d }: { d: Kafka }) {
  return (
    <>
      <span style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        {!d.assessable ? (
          <StatusPill tone="neutral" label="Unknown: ACLs could not be read" />
        ) : d.everyone_read ? (
          <StatusPill tone="bad" variant="soft" label="Every client can read it" />
        ) : (
          <StatusPill tone="ok" variant="soft" label="Only the principals below can read it" />
        )}
        {d.assessable && d.everyone_write && <StatusPill tone="bad" variant="soft" label="Every client can write it" />}
      </span>
      <p style={small}>{d.reason}</p>
      {d.assessable && (
        <>
          <List title="Can read" rows={d.readers} />
          <List title="Can write" rows={d.writers} />
        </>
      )}
    </>
  );
}

function scopeText(p: Perm): string {
  if (p.scope === 'all') return 'everything';
  if (p.scope === 'none') return 'nothing';
  return `names matching ${p.pattern}${p.unanchored ? ' (unanchored)' : ''}`;
}

function RabbitView({ d }: { d: Rabbit }) {
  return (
    <>
      <span style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        {d.read_everything.length > 0 && <StatusPill tone="warn" variant="soft" label={`${d.read_everything.length} can consume every queue`} />}
        {d.administrators.length > 0 && <StatusPill tone="warn" variant="soft" label={`${d.administrators.length} administrator(s)`} />}
      </span>
      <p style={small}>{d.reason}</p>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
        {d.users.map((u) => (
          <li key={u.user} style={{ display: 'grid', gap: 2 }}>
            <span style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              <code style={{ fontSize: 'var(--text-xs)' }}>{u.user}</code>
              {u.tags.map((t) => (
                <Chip key={t} tone={t === 'administrator' ? 'high' : 'neutral'}>
                  {t}
                </Chip>
              ))}
            </span>
            <span style={small}>
              Consume: {scopeText(u.read)} · Publish: {scopeText(u.write)} · Declare or delete: {scopeText(u.configure)}
              {u.can_grant_itself_anything && ' · can give itself any permission'}
            </span>
          </li>
        ))}
      </ul>
    </>
  );
}

function RedisView({ d }: { d: Redis }) {
  return (
    <>
      <span style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        {d.anonymous_access ? (
          <StatusPill tone="bad" variant="soft" label="Anyone who connects is logged in" />
        ) : (
          <StatusPill tone="ok" variant="soft" label="Login required" />
        )}
        {d.exposed_bind && <StatusPill tone="warn" variant="soft" label="Listens beyond this machine" />}
      </span>
      <p style={small}>{d.reason}</p>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
        {d.users.map((u) => (
          <li key={u.user} style={{ display: 'grid', gap: 2 }}>
            <span style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap' }}>
              <code style={{ fontSize: 'var(--text-xs)' }}>{u.user}</code>
              {!u.enabled && <Chip>disabled</Chip>}
              {u.nopass && u.enabled && <Chip tone="high">no password</Chip>}
              <Chip>{u.all_keys ? 'all keys' : u.key_restricted ? 'some keys' : 'no keys'}</Chip>
              {u.keyless_bypass && <Chip tone="high">key fence can be bypassed</Chip>}
              {u.self_escalation && <Chip tone="high">can raise its own rights</Chip>}
            </span>
            {!u.commands_known ? (
              <span style={{ ...small, color: 'var(--text-secondary)' }}>Command rules not stored by the last scan; rescan to evaluate.</span>
            ) : u.risky.length > 0 ? (
              <span style={small}>Can {u.risky.map((r) => `${r.effect} (${r.command})`).join('; ')}.</span>
            ) : (
              <span style={{ ...small, color: 'var(--text-secondary)' }}>None of the high-impact commands are allowed.</span>
            )}
          </li>
        ))}
      </ul>
    </>
  );
}
