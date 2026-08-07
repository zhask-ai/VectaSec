import type { ReactNode } from 'react';

/* The route-body scaffold. Every (app) page renders its bands inside one of these: a single
 * max-width grid with the console rhythm and the staggered entrance settle (.vs-page in
 * globals.css — opacity/transform only, neutralised by prefers-reduced-motion).
 *
 * Extracted because every route hand-rolled the same
 * `<div style={{ display:'grid', gap:'var(--space-4)', maxWidth:1280 }}>` — and a premium feel
 * is mostly CONSISTENCY: one rhythm, applied everywhere, including the motion. */

export function Page({ children }: { children: ReactNode }) {
  return <div className="vs-page">{children}</div>;
}
