import type { Route } from 'next';

import { SEVERITIES, type Severity, type UiStatus } from '@/lib/types';

/* Filter vocabulary — shared by the server (data.ts builds the query from it) and the client
 * (filters.tsx builds hrefs from it). Deliberately NOT in the DAL: data.ts is `server-only`,
 * and a client component that needs a status label must not be the reason that boundary bends.
 *
 * Filter state lives in the URL, never in useState. Analysts paste views into Slack, and a
 * filtered view that cannot be linked gets screenshotted instead. It also means the server does
 * the filtering, so there is no client-side refetch waterfall.
 */

export type FindingFilters = {
  severity: Severity[];
  status: UiStatus[];
  /** First dotted segment of rule_id — "KAFKA", "KONG". See `systemOf`. */
  system: string | null;
  /** Free-text rule_id prefix. */
  rule: string | null;
};

export const UI_STATUSES: readonly UiStatus[] = ['open', 'in_progress', 'resolved', 'muted'];

export const UI_STATUS_LABEL: Record<UiStatus, string> = {
  open: 'Open',
  in_progress: 'In progress',
  resolved: 'Resolved',
  muted: 'Muted',
};

/** The system a rule belongs to is the first dotted segment of its id:
 * KAFKA.LISTENER.PLAINTEXT -> KAFKA. Derived from the rule_id rather than joined through
 * resources -> connections.type on purpose: it needs no join, it survives a finding whose
 * resource row was deleted, and every detector in the engine's registry already follows the
 * convention. */
export function systemOf(ruleId: string): string {
  return ruleId.split('.')[0] || ruleId;
}

/** rule_ids are `[A-Z0-9._-]` across every detector, so input is stripped to that charset before
 * it reaches a query. That removes `%` (a LIKE wildcard), `*` (PostgREST's alias for it), and
 * the commas, parens and quotes that are PostgREST filter syntax. Nothing legitimate is lost —
 * no rule_id contains any of them.
 *
 * `_` SURVIVES, and it is a single-character LIKE wildcard. That is deliberate, not an
 * oversight: rule_ids genuinely contain underscores (KONG.ADMIN.LISTEN_WILDCARD), so escaping
 * it is the only alternative to stripping the character out of half the ids in the product.
 * The consequence is that a filter of `LISTEN_WILD` also matches a hypothetical `LISTENXWILD`.
 * Harmless, and harmless in the safe direction: it can only ever show MORE rows than asked,
 * never fewer, and RLS still bounds them to the caller's own tenant. A filter that silently
 * hides a finding would be the bug; one that shows a neighbouring rule is not.
 *
 * (The escape — `\_` — is left undone on purpose: it could not be verified end-to-end through
 * PostgREST here, and an escape that the layer mangles would break exact matching, which is the
 * common case. Worth revisiting with a seeded tenant.) */
export function sanitizeRule(raw: string): string {
  return raw.toUpperCase().replace(/[^A-Z0-9._-]/g, '').slice(0, 120);
}

/** Parse filters out of searchParams. Unknown values are dropped rather than rejected: a
 * hand-edited or stale URL should degrade to a broader view, never to an error page. */
export function parseFilters(sp: Record<string, string | string[] | undefined>): FindingFilters {
  const many = (v: string | string[] | undefined): string[] =>
    v === undefined ? [] : (Array.isArray(v) ? v : [v]).flatMap((s) => s.split(',')).filter(Boolean);

  const one = (v: string | string[] | undefined): string | null => {
    const s = Array.isArray(v) ? v[0] : v;
    return s?.trim() ? s.trim() : null;
  };

  const systemRaw = one(sp.system);
  const ruleRaw = one(sp.rule);

  return {
    severity: many(sp.severity).filter((s): s is Severity => (SEVERITIES as readonly string[]).includes(s)),
    status: many(sp.status).filter((s): s is UiStatus => (UI_STATUSES as readonly string[]).includes(s)),
    system: systemRaw ? sanitizeRule(systemRaw) || null : null,
    rule: ruleRaw ? sanitizeRule(ruleRaw) || null : null,
  };
}

export function hasActiveFilters(f: FindingFilters): boolean {
  return f.severity.length > 0 || f.status.length > 0 || f.system !== null || f.rule !== null;
}

/** Serialize filters back to a query string. Empty facets are omitted rather than written as
 * `severity=` so a default view has a clean, copyable URL. */
export function toSearchParams(f: FindingFilters): string {
  const p = new URLSearchParams();
  if (f.severity.length) p.set('severity', f.severity.join(','));
  if (f.status.length) p.set('status', f.status.join(','));
  if (f.system) p.set('system', f.system);
  if (f.rule) p.set('rule', f.rule);
  const s = p.toString();
  return s ? `?${s}` : '';
}

/** Toggle one value in a multi-select facet. */
export function toggle<T>(list: readonly T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

/* ── Route helpers ────────────────────────────────────────────────────────
 * `typedRoutes` is on, and it cannot verify a URL assembled at runtime: a `string` id inhabits
 * `''` and `'a/b'`, neither of which is a legal slug, so TypeScript is right to reject
 * `/findings/${id}`. The assertion is genuine knowledge — these ids are uuids straight out of
 * Postgres — but it is still an assertion, so both live HERE rather than at a dozen call sites.
 * Two casts in one file can be audited; `as Route` sprinkled through the JSX cannot.
 *
 * This is a different case from the `as Route` in layout.tsx, which existed only because those
 * routes were unbuilt. That one can be deleted; these cannot — no amount of route generation
 * makes a runtime string statically checkable. */

export function findingHref(id: string): Route {
  return `/findings/${id}` as Route;
}

export function findingsHref(f: FindingFilters): Route {
  return `/findings${toSearchParams(f)}` as Route;
}

export function systemHref(system: string): Route {
  return `/findings?system=${encodeURIComponent(system)}` as Route;
}
