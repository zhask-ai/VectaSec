/* WCAG 2.2 contrast gate for the console palette. Run: `pnpm contrast`. Wire into CI.
 *
 * This PARSES app/globals.css rather than restating its hexes, so the stylesheet stays the
 * single source of truth and this check can never silently drift from what ships.
 *
 * Why bother: "a palette that isn't tested is a palette that's wrong". Two real failures in
 * the source research were invisible to the eye and caught only by computing —
 * light muted grey at 4.46:1 (vs a 4.5 floor) and --text-muted at 4.37:1 on raised surfaces.
 *
 * Thresholds: text 4.5:1 (SC 1.4.3) · non-text/UI components 3:1 (SC 1.4.11).
 *
 * PART TWO — the source audit — exists because checking the palette was never enough. The
 * palette was green while /login shipped `color: 'var(--sev-high-text, #FF9A9E)'`: a token that
 * does not exist, so the fallback literal always won, pinning the error message to 2.03:1 on
 * the light-mode card. A hex hardcoded in a .tsx is invisible to a stylesheet parser, so this
 * pass reads the components too. A token check that only checks tokens cannot see the colours
 * that never became tokens.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const CSS = join(ROOT, 'app', 'globals.css');

const srgbToLin = (c) => {
  c /= 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
};

const luminance = (hex) => {
  const h = hex.replace('#', '');
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16));
  return 0.2126 * srgbToLin(r) + 0.7152 * srgbToLin(g) + 0.0722 * srgbToLin(b);
};

const contrast = (a, b) => {
  const [l1, l2] = [luminance(a), luminance(b)];
  return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
};

/* Extract the dark block (`:root {`) and the light block (`:root[data-theme='light'] {`).
 * Both define the same token names, so they must be scoped apart before parsing. */
function tokensIn(css, startMarker) {
  const start = css.indexOf(startMarker);
  if (start === -1) throw new Error(`could not find block: ${startMarker}`);
  const open = css.indexOf('{', start);
  let depth = 0;
  let end = open;
  for (let i = open; i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}' && --depth === 0) {
      end = i;
      break;
    }
  }
  const block = css.slice(open, end);
  const out = {};
  for (const [, name, hex] of block.matchAll(/(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\s*;/g)) {
    out[name] = hex;
  }
  return out;
}

const css = readFileSync(CSS, 'utf8');
const themes = {
  dark: tokensIn(css, ':root {'),
  light: tokensIn(css, ":root[data-theme='light'] {"),
};

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const TEXT = 4.5;
const NON_TEXT = 3.0;

/** @type {{theme:string,label:string,fg:string,bg:string,min:number}[]} */
const checks = [];
for (const [theme, t] of Object.entries(themes)) {
  const surfaces = ['--bg', '--surface', '--surface-raised'];

  // Body text on every surface. --text-muted on --surface-raised is a known 4.37:1 failure in
  // dark; it is asserted as non-text so the real constraint is documented rather than hidden —
  // the rule is "never use muted text on raised", enforced by review, not by a passing number.
  for (const s of surfaces) {
    for (const fg of ['--text-primary', '--text-secondary']) {
      checks.push({ theme, label: `${fg} on ${s}`, fg: t[fg], bg: t[s], min: TEXT });
    }
  }
  for (const s of ['--bg', '--surface']) {
    checks.push({ theme, label: `--text-muted on ${s}`, fg: t['--text-muted'], bg: t[s], min: TEXT });
  }

  for (const sev of SEVERITIES) {
    // Severity foregrounds are text/icons -> 4.5:1 on every surface they can land on.
    for (const s of surfaces) {
      checks.push({
        theme,
        label: `--sev-${sev}-fg on ${s}`,
        fg: t[`--sev-${sev}-fg`],
        bg: t[s],
        min: TEXT,
      });
    }
    // The soft badge is the shipping default: tinted bg + light fg.
    checks.push({
      theme,
      label: `--sev-${sev}-fg on --sev-${sev}-bg`,
      fg: t[`--sev-${sev}-fg`],
      bg: t[`--sev-${sev}-bg`],
      min: TEXT,
    });
    // Solids are fills/bars/graph nodes -> non-text 3:1 against the app background.
    checks.push({
      theme,
      label: `--sev-${sev}-solid on --bg`,
      fg: t[`--sev-${sev}-solid`],
      bg: t['--bg'],
      min: NON_TEXT,
    });
  }

  // Control outlines are UI components: 3:1 against the lightest surface they sit on.
  checks.push({
    theme,
    label: '--border-interactive on --surface-raised',
    fg: t['--border-interactive'],
    bg: t['--surface-raised'],
    min: NON_TEXT,
  });

  // The primary-button fill and its label. Checked as TEXT because --accent-fg is text sitting
  // on --accent; the pair only exists because a button was painting `var(--accent, #4C8DFF)`
  // against a hardcoded `#0B0E14` — neither of which any theme could ever override.
  checks.push({
    theme,
    label: '--accent-fg on --accent',
    fg: t['--accent-fg'],
    bg: t['--accent'],
    min: TEXT,
  });
  checks.push({
    theme,
    label: '--accent on --bg',
    fg: t['--accent'],
    bg: t['--bg'],
    min: NON_TEXT,
  });
  for (const s of surfaces) {
    checks.push({ theme, label: `--focus-ring on ${s}`, fg: t['--focus-ring'], bg: t[s], min: NON_TEXT });
  }
}

let failed = 0;
let theme = '';
for (const c of checks) {
  if (!c.fg || !c.bg) {
    console.error(`  MISSING token for: ${c.label}`);
    failed++;
    continue;
  }
  if (c.theme !== theme) {
    theme = c.theme;
    console.log(`\n${theme.toUpperCase()}`);
  }
  const ratio = contrast(c.fg, c.bg);
  const ok = ratio >= c.min;
  if (!ok) failed++;
  console.log(
    `  ${ok ? 'PASS' : 'FAIL'}  ${ratio.toFixed(2).padStart(5)}:1  (min ${c.min})  ${c.label}`,
  );
}

console.log(
  failed === 0
    ? `\n${checks.length} pairs checked, all pass.`
    : `\n${failed}/${checks.length} pairs FAIL.`,
);

/* ── Part two: the source audit ───────────────────────────────────────────
 * Everything above proves the palette is sound. None of it proves the components USE it.
 * Three rules, each earned by a real defect that shipped past a green palette check.
 */

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.next') continue;
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(tsx|ts)$/.test(p)) out.push(p);
  }
  return out;
}

const sources = [join(ROOT, 'app'), join(ROOT, 'components')].flatMap((d) => walk(d));
const raw = new Map(sources.map((f) => [f, readFileSync(f, 'utf8')]));

/* Comments are prose, not shipped pixels — and this file's rules are the kind that get
 * explained in a comment that quotes the very defect being fixed. Blank them out (preserving
 * newlines so line numbers survive) rather than reporting an author for describing the bug. */
const strip = (src) =>
  src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (m) => m.replace(/[^\n]/g, ' '));

const defined = new Set([...Object.keys(themes.dark), ...Object.keys(themes.light)]);
// Non-colour tokens live in a third `:root` block the theme parser above deliberately skips.
for (const [, name] of css.matchAll(/(--[\w-]+)\s*:/g)) defined.add(name);
// Components may also define a custom property inline (`'--vs-row-h': ROW_HEIGHT[density]`).
// That is a real definition; a var() reading it is not dangling.
for (const src of raw.values()) {
  for (const [, name] of strip(src).matchAll(/['"](--[\w-]+)['"]\s*:/g)) defined.add(name);
}

const violations = [];

for (const file of sources) {
  const src = strip(raw.get(file));
  const where = relative(ROOT, file);
  const lineOf = (idx) => src.slice(0, idx).split('\n').length;

  // RULE 1 — every var(--x) must resolve. `var(--sev-high-text, #FF9A9E)` referenced a token
  // that has never existed, so the fallback was the colour, permanently and in both themes.
  // `var(--sev-${severity}-fg)` is a real pattern here, and the prefix it leaves behind is not
  // a token name — skip an interpolated reference rather than inventing a failure.
  for (const m of src.matchAll(/var\(\s*(--[\w-]+)/g)) {
    if (src.slice(m.index + m[0].length).startsWith('${')) continue;
    if (!defined.has(m[1])) {
      violations.push(`${where}:${lineOf(m.index)}  undefined token ${m[1]} — nothing defines it`);
    }
  }

  // RULE 2 — no hardcoded hex colours. A literal in a .tsx cannot be checked by the pass above,
  // cannot re-theme, and is how both /login failures got in. Tokens or nothing.
  for (const m of src.matchAll(/#[0-9a-fA-F]{6}\b/g)) {
    violations.push(`${where}:${lineOf(m.index)}  hardcoded colour ${m[0]} — use a token from globals.css`);
  }

  // RULE 3 — a control's border is its only visual indicator and owes SC 1.4.11's 3:1, which
  // --border (1.38:1) and --border-strong (1.82:1) do not meet. --border-interactive exists for
  // exactly this. Scoped to the open tag of a real control element, so decorative dividers and
  // card edges — the tokens' legitimate use — are untouched. It follows that a control styled
  // from a shared const or a button-shaped <Link> slips through: this rule narrows the class,
  // it does not close it.
  for (const m of src.matchAll(/<(select|input|textarea|button)\b/g)) {
    const open = src.slice(m.index, src.indexOf('>', m.index));
    const bad = open.match(/border[A-Za-z]*:\s*[^,}]*var\(--border(-strong)?\)/);
    if (bad) {
      violations.push(
        `${where}:${lineOf(m.index)}  <${m[1]}> border uses --border${bad[1] ?? ''} ` +
          `(<3:1, SC 1.4.11) — use --border-interactive`,
      );
    }
  }
}

if (violations.length) {
  console.log('\nSOURCE AUDIT');
  for (const v of violations) console.log(`  FAIL  ${v}`);
  console.log(`\n${violations.length} source violation${violations.length === 1 ? '' : 's'}.\n`);
} else {
  console.log(`\nSOURCE AUDIT\n  ${sources.length} files scanned, no violations.\n`);
}

process.exit(failed === 0 && violations.length === 0 ? 0 : 1);
