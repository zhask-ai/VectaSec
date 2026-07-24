import type { Severity, SeverityCounts } from '@/lib/types';

/* Posture score — one interpretable number from the open findings.
 *
 * A score is a heuristic, and this codebase does not do magic numbers, so the formula is simple,
 * documented, and always shown next to the raw counts it came from (the Overview never prints the
 * score alone). `info` findings are excluded: they are notes, not risk. The weighting reflects
 * exploitability, and the asymptotic shape means the score degrades gracefully rather than
 * slamming to zero on the first few criticals — a security team needs to see the number MOVE as
 * they remediate, not sit pinned at 0.
 *
 *   weighted = 10·crit + 4·high + 1.5·med + 0.5·low
 *   score    = round(100 · (1 − weighted / (weighted + 40)))   ∈ [1, 100]
 *
 * The engine documents the same formula for `vectasec posture` so the CLI and console agree.
 */

const WEIGHTS: Record<Severity, number> = { critical: 10, high: 4, medium: 1.5, low: 0.5, info: 0 };

export type Posture = { score: number; grade: 'A' | 'B' | 'C' | 'D' | 'F'; weighted: number };

export function postureScore(counts: SeverityCounts): Posture {
  const weighted =
    counts.critical * WEIGHTS.critical +
    counts.high * WEIGHTS.high +
    counts.medium * WEIGHTS.medium +
    counts.low * WEIGHTS.low;
  const score = weighted === 0 ? 100 : Math.max(1, Math.round(100 * (1 - weighted / (weighted + 40))));
  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, weighted };
}

export function gradeColor(grade: Posture['grade']): string {
  return {
    A: 'var(--sev-low-fg)',
    B: 'var(--sev-low-fg)',
    C: 'var(--sev-medium-fg)',
    D: 'var(--sev-high-fg)',
    F: 'var(--sev-critical-fg)',
  }[grade];
}
