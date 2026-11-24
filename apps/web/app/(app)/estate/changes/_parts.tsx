import type { Json } from '@/lib/types';
import { Chip, type ChipTone } from '@/components/ui/chip';

/* Shared pieces of the Time machine: the change chip and the before → after field list.
 * Server components, no state — used by the History tab, the resource page and the finding page.
 *
 * A change row comes from `resource_changes` (migration 20261123000001), written by the engine
 * inside each scan. The engine has already masked secret-looking values and dropped telemetry,
 * so what is here is safe to render as stored. */

export type ChangeKind = 'added' | 'removed' | 'modified' | 'returned';

export type ChangeField = { path: string; before: Json; after: Json; op?: string };

export type ChangeRow = {
  id: string;
  resource_id: string | null;
  connection_id: string | null;
  kind: string;
  name: string;
  change: ChangeKind;
  fields: ChangeField[] | null;
  field_count: number;
  actor: string | null;
  prev_seen_at: string | null;
  observed_at: string;
};

/* Glyph + word + tone: the change type never rides on colour alone (DESIGN.md law 2). Removed
 * and modified are tinted because they are the two an owner has to look at; added and returned
 * are quieter. */
const CHANGE: Record<ChangeKind, { glyph: string; label: string; tone: ChipTone; title: string }> = {
  added: { glyph: '+', label: 'Added', tone: 'low', title: 'First returned by this scan' },
  removed: { glyph: '−', label: 'Removed', tone: 'medium', title: 'No longer returned by the scan' },
  modified: { glyph: '~', label: 'Modified', tone: 'high', title: 'Configuration differs from the previous scan' },
  returned: { glyph: '↺', label: 'Returned', tone: 'info', title: 'Was gone, and the scan returned it again' },
};

export const CHANGE_KINDS: ChangeKind[] = ['modified', 'added', 'removed', 'returned'];

export function changeLabel(change: ChangeKind): string {
  return CHANGE[change]?.label ?? change;
}

export function ChangeChip({ change }: { change: ChangeKind }) {
  const c = CHANGE[change] ?? { glyph: '?', label: change, tone: 'neutral' as ChipTone, title: '' };
  return (
    <Chip tone={c.tone} title={c.title}>
      <span aria-hidden="true" style={{ fontFamily: 'var(--font-mono)', marginRight: 4 }}>
        {c.glyph}
      </span>
      {c.label}
    </Chip>
  );
}

export function showValue(v: Json): string {
  if (v === null || v === undefined) return 'not set';
  if (typeof v === 'string') return v === '' ? '(empty)' : v;
  return JSON.stringify(v);
}

const valueStyle: React.CSSProperties = {
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-2xs)',
  overflowWrap: 'anywhere',
};

function FieldLine({ f }: { f: ChangeField }) {
  const isSet = f.op === 'set';
  return (
    <li style={{ display: 'grid', gap: 2, minWidth: 0 }}>
      <code style={{ ...valueStyle, color: 'var(--text-secondary)' }}>{f.path || '(value)'}</code>
      <span style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-2)', alignItems: 'baseline', minWidth: 0 }}>
        <span style={{ ...valueStyle, color: 'var(--text-muted)', textDecoration: 'line-through' }}>
          <span className="vs-visually-hidden">{isSet ? 'removed: ' : 'before: '}</span>
          {isSet && <span aria-hidden="true">− </span>}
          {showValue(f.before)}
        </span>
        <span aria-hidden="true" style={{ color: 'var(--text-muted)' }}>
          →
        </span>
        <span style={{ ...valueStyle, color: 'var(--text-primary)' }}>
          <span className="vs-visually-hidden">{isSet ? 'added: ' : 'after: '}</span>
          {isSet && <span aria-hidden="true">+ </span>}
          {showValue(f.after)}
        </span>
      </span>
    </li>
  );
}

/** The changed fields of one change. The first `lead` are always visible; the rest sit behind
 * a native <details>, so the row stays scannable and nothing needs JavaScript. */
export function FieldDiff({ row, lead = 2 }: { row: Pick<ChangeRow, 'change' | 'fields' | 'field_count'>; lead?: number }) {
  const fields = Array.isArray(row.fields) ? row.fields : [];
  if (fields.length === 0) {
    const text =
      row.change === 'added'
        ? 'New since the previous scan.'
        : row.change === 'removed'
          ? 'The scan no longer returns it. Deleted, renamed, or no longer readable.'
          : row.change === 'returned'
            ? 'Back with the same configuration it had before.'
            : 'No field detail was recorded.';
    return <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>{text}</span>;
  }
  const head = fields.slice(0, lead);
  const rest = fields.slice(lead);
  const hidden = Math.max(0, row.field_count - fields.length);
  const list: React.CSSProperties = { listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-2)' };
  return (
    <div style={{ display: 'grid', gap: 'var(--space-2)', minWidth: 0 }}>
      <ul style={list}>
        {head.map((f, i) => (
          <FieldLine key={`${f.path}-${i}`} f={f} />
        ))}
      </ul>
      {rest.length > 0 && (
        <details>
          <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 'var(--text-2xs)' }}>
            {rest.length} more changed field{rest.length === 1 ? '' : 's'}
          </summary>
          <ul style={{ ...list, marginTop: 'var(--space-2)' }}>
            {rest.map((f, i) => (
              <FieldLine key={`${f.path}-${i}`} f={f} />
            ))}
          </ul>
        </details>
      )}
      {hidden > 0 && (
        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-2xs)' }}>
          {hidden} more not stored. The export has the same cap.
        </span>
      )}
    </div>
  );
}

/** "2026-11-23 08:14" in UTC — the console shows evidence times in UTC everywhere. */
export function stamp(iso: string | null): string {
  if (!iso) return 'unknown';
  return new Date(iso).toISOString().slice(0, 16).replace('T', ' ');
}

export function dayOf(iso: string): string {
  return new Date(iso).toISOString().slice(0, 10);
}

export function timeOf(iso: string): string {
  return new Date(iso).toISOString().slice(11, 16);
}

/** The window a change happened in: after the last scan that saw the old state, and no later
 * than the scan that saw the new one. This is all a polling scanner can prove, so it is said
 * in exactly those words. */
export function ChangeWindow({ row }: { row: Pick<ChangeRow, 'prev_seen_at' | 'observed_at'> }) {
  return (
    <span style={{ fontSize: 'var(--text-2xs)', color: 'var(--text-secondary)' }}>
      {row.prev_seen_at ? (
        <>
          after <time dateTime={row.prev_seen_at}>{stamp(row.prev_seen_at)}</time>
          <br />
          by <time dateTime={row.observed_at}>{stamp(row.observed_at)}</time>
        </>
      ) : (
        <>
          by <time dateTime={row.observed_at}>{stamp(row.observed_at)}</time>
        </>
      )}
    </span>
  );
}
