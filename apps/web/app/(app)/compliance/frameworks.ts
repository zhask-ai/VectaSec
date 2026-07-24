import type { ControlStatus } from '@/lib/types';

/* Framework metadata and the scoring rule.
 *
 * Everything here exists to stop the console from claiming more than the scan can prove.
 * The two rules come from docs/research/compliance-mapping.md §0 and they are load-bearing:
 *
 *   1. A finding can prove FAIL. A finding's ABSENCE can never prove PASS. The mapping engine
 *      (compliance/map.py::evaluate) only ever emits fail/unknown/not_applicable — there is no
 *      argument or flag that makes a clean scan write `pass`. Nor is there an attestation
 *      mechanism yet, so today NOTHING can write a `pass` and this table cannot contain one.
 *      `pass` is still handled below because the DB column is free text and an attestation
 *      path is the intended future writer — but if a `pass` ever appears here, it did not come
 *      from a clean scan.
 *      This is why `unknown` is excluded from the score's denominator rather than folded into
 *      it: counting unevaluated controls as passing is the exact dishonesty this product
 *      exists to refuse, and counting them as failing is the same lie in the other direction —
 *      it claims knowledge we do not have.
 *
 *   2. Every mapping is conditional on scope, and scope is a property of the asset/tenant, not
 *      of the rule. `not_applicable` means a scope gate was not satisfied — the control is out
 *      of scope, not a gap. Hence it is excluded from coverage too.
 */

/** How much weight a mapping can carry. Surfaced in the UI per framework, because a console
 * that renders PCI 8.6.2 and NIS2 21(2)(i) with identical confidence is lying by layout. */
export type Fidelity = 'direct' | 'evidence' | 'indicative';

export const FIDELITY: Record<Fidelity, { label: string; note: string }> = {
  direct: {
    label: 'Direct citation',
    note: "Control ids and requirement text are the framework's own. A failing control cites the text it fails.",
  },
  evidence: {
    label: 'Evidence only',
    note: 'The framework states principles, not testable controls. These rows are evidence feeding your own risk-management framework — they are not a verdict against the regulation.',
  },
  indicative: {
    label: 'Indicative',
    note: 'Mapped to a text your entity is not directly bound by. Read as direction, not as a compliance result.',
  },
};

export interface FrameworkMeta {
  label: string;
  version: string;
  fidelity: Fidelity;
  /** Who the framework applies to. Shown because a control result is meaningless without it. */
  scope: string;
  /** The thing a vendor would omit. Every one of these is sourced from
   *  docs/research/compliance-mapping.md; do not soften them to make a demo look better. */
  caveat: string;
}

/* Order is the brief's, which is also roughly the order of defensibility: PCI and DORA are
 * where the strong claims are, NIS2 is the weakest and sits last. */
export const FRAMEWORK_ORDER = ['PCI_DSS_4_0_1', 'DORA', 'HIPAA', 'NIS2'] as const;

export const FRAMEWORKS: Record<string, FrameworkMeta> = {
  PCI_DSS_4_0_1: {
    label: 'PCI DSS',
    version: '4.0.1',
    fidelity: 'direct',
    scope:
      'Applies to system components in, connected to, or that could affect the security of the CDE. Assets without the CDE scope tag are reported out of scope, not passing.',
    caveat:
      'Requirement text is reproduced from a public vendor responsibility matrix, not from the PCI SSC standard itself — the official PDF sits behind a click-through agreement. Diff the quoted text against the Document Library copy before relying on any of this in an assessment.',
  },
  DORA: {
    label: 'DORA',
    version: 'Regulation (EU) 2022/2554',
    fidelity: 'evidence',
    scope: 'Applies to in-scope financial entities, for assets supporting an ICT function.',
    caveat:
      'DORA articles are principles, not testable controls — there is no official "DORA 9.4.3". Any sub-paragraph identifier below is VectaSec\'s, not the Regulation\'s. DORA compliance is assessed against the ICT risk-management framework Article 6 requires you to write; these rows are evidence for that framework and do not pass or fail the article itself.',
  },
  HIPAA: {
    label: 'HIPAA Security Rule',
    version: '45 CFR 164.312',
    fidelity: 'direct',
    scope: 'Applies to ePHI. §164.312(a)(1) and (d) reach software programs and entities, not only people.',
    caveat:
      'The encryption specifications in §164.312 are Addressable, not Required: a covered entity may document why one is not reasonable and appropriate and implement an equivalent alternative instead. A failing control here is therefore not automatically a violation. Evaluated against the rule in force — the January 2025 NPRM is still a proposed rule and is not applied.',
  },
  NIS2: {
    label: 'NIS2',
    version: 'Directive (EU) 2022/2555',
    fidelity: 'indicative',
    scope: 'Applies to essential and important entities in the covered sectors.',
    caveat:
      'NIS2 is a Directive: the binding text is 27 national transpositions, not the Directive. These controls map to Article 21(2) of the Directive as a stable spine — they are not your national implementation, and as of this build several Member States have not completed transposition at all.',
  },
};

/** A framework the engine emitted that this build has no metadata for. Rendered rather than
 * dropped — silently hiding a framework's results is worse than admitting we lack the notes. */
export function metaFor(framework: string): FrameworkMeta {
  return (
    FRAMEWORKS[framework] ?? {
      label: framework,
      version: 'unrecognised framework',
      fidelity: 'indicative',
      scope: 'Scope unknown to this build of the console.',
      caveat:
        'This console has no mapping notes for this framework, so it cannot tell you how much weight these results carry. Treat them as unverified.',
    }
  );
}

/** The DB column is `text`, not an enum — the TS type is a mirror, not a guarantee. An
 * unrecognised value becomes `unknown`, never `pass`: resolving ambiguity in the optimistic
 * direction is precisely how a compliance score becomes a lie. */
export function normalizeStatus(raw: unknown): ControlStatus {
  return raw === 'pass' || raw === 'fail' || raw === 'not_applicable' ? raw : 'unknown';
}

export type Tally = Record<ControlStatus, number>;

export interface Score {
  tally: Tally;
  /** Controls with a determinate result: pass + fail. The ONLY honest denominator. */
  evaluated: number;
  /** evaluated + unknown. Excludes not_applicable — out of scope is not a coverage gap. */
  inScope: number;
  /** pass / evaluated. `null` when nothing is evaluated: 0/0 is not 100%, and rendering it as
   *  a number at all would invent a result. */
  ratio: number | null;
  /** evaluated / inScope. The number that keeps `ratio` honest — never show one without the
   *  other. A 100% score over 2 of 200 controls is not a 100% score. */
  coverage: number | null;
}

export function score(statuses: ControlStatus[]): Score {
  const tally: Tally = { pass: 0, fail: 0, unknown: 0, not_applicable: 0 };
  for (const s of statuses) tally[s] += 1;

  const evaluated = tally.pass + tally.fail;
  const inScope = evaluated + tally.unknown;

  return {
    tally,
    evaluated,
    inScope,
    ratio: evaluated > 0 ? tally.pass / evaluated : null,
    coverage: inScope > 0 ? evaluated / inScope : null,
  };
}

export function pct(v: number): string {
  return `${Math.round(v * 100)}%`;
}

/* Control ids are dotted numerics ("7.2.5", "10.2.1.2") and CFR cites ("164.312(a)(1)").
 * A lexicographic sort puts 10.2.1 above 7.2.5, which reads as a broken table to the one
 * audience that reads control ids for a living. Compare digit runs numerically, the rest as
 * text. */
export function compareControlId(a: string, b: string): number {
  const ta = a.match(/\d+|\D+/g) ?? [];
  const tb = b.match(/\d+|\D+/g) ?? [];

  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i];
    const y = tb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;

    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

/* Reading order for the table. `unknown` sits SECOND, above pass — an unevaluated control is
 * a live gap and burying it under the passes is how a coverage problem stays invisible. */
export const STATUS_RANK: Record<ControlStatus, number> = {
  fail: 0,
  unknown: 1,
  pass: 2,
  not_applicable: 3,
};
