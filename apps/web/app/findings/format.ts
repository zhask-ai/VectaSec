/* Time formatting for the findings views.
 *
 * These run on the SERVER and the result crosses to the client as a plain string. A relative
 * label recomputed during hydration would disagree with the one rendered at request time —
 * and in a console whose entire claim is "this is what we read from your system, at this
 * time", a timestamp that flickers on hydration undermines the thing being sold.
 *
 * Absolute times are UTC with an explicit Z. Never the viewer's locale: an analyst correlating
 * this against a broker log is reading UTC, and an unlabelled local timestamp is how two
 * people compare two different moments and agree.
 */

/** "2h ago". Coarse on purpose — precision here is false; `absolute()` carries the truth. */
export function relative(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (mins < 0) return 'just now'; // clock skew between the collector and us — never print "in 3m"
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
  return `${Math.floor(mins / 1440)}d ago`;
}

/** "2026-07-17 04:12:33Z" — the form that goes in a ticket or an audit export. */
export function absolute(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso; // never silently render "Invalid Date" as evidence
  return `${d.toISOString().slice(0, 19).replace('T', ' ')}Z`;
}

/** Short form of a uuid for display — "obs_8fa2c" style. The full id is always available to
 * copy; this is for scanning a column, not for quoting back to us. */
export function shortId(prefix: string, id: string): string {
  return `${prefix}_${id.replace(/-/g, '').slice(0, 5)}`;
}
