# VectaSec console — design system

The foundation every page builds on. Register: **Linear / Vercel / Datadog-grade security
console** — dense, precise, calm, high-contrast. Not consumer-flashy. This is a security-posture
product, so **information density, legibility, and honesty** outrank decoration.

Three laws hold across everything below:

1. **Tokens or nothing.** No hardcoded hex in any `.tsx`/`.ts`. Every colour is a CSS variable from
   `app/globals.css`. `pnpm contrast` fails the build on a literal, a dangling `var()`, or a
   control border weaker than 3:1. It parses `globals.css` (the single source of truth) _and_
   audits every component.
2. **Colour is never the only signal.** Severity and status always carry a **shape + label** too
   (WCAG SC 1.4.1). Greyscale the screen and it must still read.
3. **Say what is true.** Empty ≠ error ≠ clean ≠ filtered. Inferred ≠ proven. A number with no
   provenance ("as of…") reads as untrustworthy; a stale one with none reads as fresh. Primitives
   below make the honest choice the easy one.

Verify after any change: `pnpm typecheck && pnpm build && pnpm contrast` must all be green.

---

## 1. Tokens (`app/globals.css`)

**Theme-aware, light-default.** Light lives in `:root`; dark in `:root[data-theme='dark']` and in a
`@media (prefers-color-scheme: dark)` copy scoped to `:root:not([data-theme='light'])`. An explicit
`data-theme` on `<html>` (set by the top-bar toggle, persisted to `localStorage['vs-theme']`, applied
pre-paint by a script in the root layout) **wins both ways**. Consume tokens by name — never assume a
theme.

### Surfaces & elevation
Elevation is a **hairline border + a whisper of shadow**, never a heavy drop.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | `#f9f9f7` | `#0d0d0d` | page |
| `--surface` | `#fcfcfb` | `#1a1a19` | cards |
| `--surface-raised` | `#ffffff` | `#232322` | popovers, hover/selected rows |
| `--border` | `rgba(11,11,11,.10)` | `rgba(255,255,255,.10)` | hairline dividers/edges (decorative) |
| `--border-strong` | `rgba(11,11,11,.16)` | `rgba(255,255,255,.16)` | slightly heavier divider |
| `--border-interactive` | `#77766f` | `#7a7970` | **any control outline** (clears 3:1) |
| `--grid` | `#e1e0d9` | `#2c2c2a` | recessive chart gridlines |
| `--shadow-sm` / `--shadow-popover` | — | — | default card / raised card + overlays |

> A control whose only visual indicator is its border (`<input>`, `<select>`, `<button>`, unchecked
> box) **must** use `--border-interactive`. `--border`/`--border-strong` are hairlines below 3:1 and
> are for decoration only — the source audit enforces this on control tags.

### Ink
`--text-primary` (`#0b0b0b`/`#fff`), `--text-secondary` (`#52514e`/`#c3c2b7`),
`--text-muted` (`#6b6a64`/`#898781`). Muted is still **real text** (4.5:1) — use it for timestamps
and provenance, not for anything a user must act on.

### Severity — the reserved status axis
Never themed away, always with icon + label. **Three roles per level** (one hex can't serve all):

- `--sev-{level}-fg` — text/icons on a surface (4.5:1). Darkens on light because bright orange/amber
  can't be read as text on off-white — the icon+label carry the level, hue only supports.
- `--sev-{level}-solid` — fills, bars, marks, graph nodes (3:1). The **canonical hue** lives here:
  critical `#d03b3b`, high `#ec835a`, medium `#fab219`, low `#2a78d6` (blue), info `#898781`.
- `--sev-{level}-bg` — soft tint behind `-fg` in a chip.

Levels: `critical high medium low info`. Order is itself a channel — sort by `SEVERITY_RANK`
(`lib/types.ts`), critical first.

### Categorical — charts only
`--cat-1 … --cat-8`, **fixed order, never cycled**, never used for status. Reach for them only in
`components/charts/*`. A 9th series is a design smell (group the tail into "other").
Order: blue, aqua, yellow, green, violet, red, magenta, orange.

### Type, space, motion
- Sizes `--text-2xs`(11)…`--text-4xl`(40). Everything below 24px clears 4.5:1. Gain density by
  shrinking **padding, never type**. 11px is the floor (meta only).
- `--font-ui` (system sans, self-contained) / `--font-mono` (evidence: IDs, config, fingerprints,
  claims). Numeric columns/metrics get `tabular-nums` (add `data-numeric` or use a `<table>`).
- Spacing `--space-1..8` (4px base). Rows `--row-compact/default/relaxed` = 32/40/48. Radii
  `--radius-sm/md/lg/xl` = 3/5/8/12 + `--radius-full`. Motion `--motion-fast`(120ms)/
  `--motion-standard`(200ms) with `--ease-standard`/`--ease-out`. All motion is killed under
  `prefers-reduced-motion`.

---

## 2. App shell (`components/shell/*`, `app/(app)/layout.tsx`)

Authed routes live in the **`(app)` route group** and inherit `ShellChrome`: a grouped left sidebar,
a top bar (tenant · global search · live posture chip · theme toggle · account menu), and a scrolling
main. `/login` sits **outside** the group on the minimal root layout — it keeps its own centred card,
no chrome.

- **Responsive:** full rail (desktop) → icon-only rail (tablet, labels stay in the a11y tree) →
  off-canvas drawer (mobile, top bar stays above it). Body never scrolls horizontally.
- **Nav order** (grouped): Overview, Findings · _Inventory:_ Systems (`/connections`), Identities,
  Data, Assets · _Assurance:_ Attack paths, Compliance · _Operations:_ Scans · Settings (admin-only,
  pinned bottom). "Systems" is the connectors/coverage view (`/connections`); Data and Attack paths
  are honest placeholder pages until their agent ships.
- **Where page content goes:** each route renders its own single `<h1>` (via `PageHeader`) and body
  inside `.vs-main`. The shell is the frame; do not add another sidebar/top bar.

---

## 3. Primitives (`components/ui/*`)

All typed, token-only, keyboard-accessible, visible focus rings. Import from `@/components/ui/…`.

### Layout & headers
```tsx
import { PageHeader, SectionHeader } from '@/components/ui/page-header';
<PageHeader title="Findings" description="The triage queue."
  meta="6 systems · scanned 4m ago" actions={<Button variant="primary">Scan now</Button>} />
<SectionHeader title="Coverage" meta="what we could not assess" />
```
`PageHeader` owns the route's only `<h1>`. `SectionHeader` is an `<h2>` band label — never the sole
heading.

### Card (existing, restyled)
```tsx
import { Card, CardHeader, CardTitle, CardMeta, CardBody, CardFooter } from '@/components/ui/card';
<Card><CardHeader><CardTitle>Open findings</CardTitle><CardMeta>updated 4m ago</CardMeta></CardHeader>
  <CardBody pad={false}>{/* tables use pad={false} */}</CardBody></Card>
```
`raised` lifts to `--surface-raised` + popover shadow. `CardMeta` is for provenance — use it.

### Button
```tsx
import { Button } from '@/components/ui/button';
<Button variant="primary">Connect</Button>      // the ONE affirmative action per view
<Button variant="secondary">Cancel</Button>     // neutral default
<Button variant="ghost" icon={<IconSearch/>}>Export</Button>
<Button variant="danger">Suppress</Button>      // destructive — still confirm separately
```
Variants: `primary | secondary | ghost | danger`; sizes `sm | md`. It is a `<button>` — for
navigation wrap a `next/link` instead (a button that navigates is an a11y bug).

### Severity & status (icon + label + colour)
```tsx
import { SeverityBadge } from '@/components/ui/severity';     // existing — the reserved risk axis
<SeverityBadge severity="critical" />                         // tinted pill (default)
<SeverityBadge severity="high" variant="inline" count={7} /> // dense cell; count groups occurrences

import { StatusPill } from '@/components/ui/status-pill';     // operational, non-severity states
<StatusPill tone="ok" label="done" />
<StatusPill tone="warn" label="running" pulse />              // in-flight
```
`StatusPill` tones: `ok warn bad info neutral`, each with its own shape. Use for scan/connection/
control status — **not** for severity (that's `SeverityBadge`) and **not** for neutral tags
(that's `Chip`).

### Metadata & data-classification
```tsx
import { Chip } from '@/components/ui/chip';
<Chip mono>KAFKA.ACL.001</Chip>                       // neutral metadata / rule id
<Chip tone="high" inferred title="matched: pci:payments">PCI</Chip>  // dashed = inferred, not proven

import { DataClassChips } from '@/components/ui/data-class';  // existing — inferred data classes
```
Dashed border = "derived from naming, not proven" — the house tell (`DataClassChips` established it).

### KPI / metric
```tsx
import { StatTile } from '@/components/ui/stat';
<StatTile label="Open criticals" value={12} tone="bad"
  delta={{ value: 3, goodDirection: 'down', label: 'wk' }} sub="across 6 systems" />
```
Big tabular value + label; optional delta with **arrow + signed number** (survives greyscale).
`goodDirection` says which way is healthy — a rising breach count must never colour green.

### Tables (existing)
```tsx
import { Table, THead, TBody, TR, TH, TD } from '@/components/ui/table';
<Table density="compact" caption="Findings queue">
  <THead><TR><TH>Rule</TH><TH numeric sort="desc">Count</TH></TR></THead>
  <TBody><TR><TD mono>KAFKA.ACL</TD><TD numeric>7</TD></TR></TBody></Table>
```
Dense (32/40/48 rows), sticky header, hairline dividers (no zebra), `overflow-x` auto container,
`numeric` right-aligns + tabular. Skeletons must match density (see below) to avoid CLS.

### Toolbar / filter bar
```tsx
import { Toolbar, ToolbarField, ToolbarDivider } from '@/components/ui/toolbar';
<Toolbar end={<Button variant="ghost">Export</Button>}>
  <ToolbarField label="Severity">{/* control */}</ToolbarField></Toolbar>
```
Filters in **one row above** the content. (Findings' faceted left rail is the deliberate exception —
many multi-select facets earn a rail.)

### Overlays & navigation-in-place
```tsx
import { Drawer } from '@/components/ui/drawer';      // right slide-over: finding/asset detail in context
import { Tabs } from '@/components/ui/tabs';           // in-page panels (NOT routes — routes stay <Link>s)
import { Tooltip } from '@/components/ui/tooltip';     // hover+focus supplement, never load-bearing info
import { Breadcrumbs } from '@/components/ui/breadcrumbs'; // only on detail routes (…/[id])
```
`Drawer` is a real modal dialog: focus trap, Escape/scrim close, focus restore, body-scroll lock.
Deep links stay real routes (`findings/[id]`); the drawer is the in-flow companion.

### Meters
```tsx
import { Meter, ProgressRing } from '@/components/ui/meter';
<Meter value={68} label="Coverage" tone="good" />
<ProgressRing value={posture.score} color={gradeColor(posture.grade)}
  center={<PostureNumeralAndGrade/>} />   // posture gauge — always show the numeral + A–F grade
```

### Empty states & skeletons (existing)
```tsx
import { EmptyState } from '@/components/ui/empty-state';   // tone REQUIRED
import { Skeleton, SkeletonRows } from '@/components/ui/skeleton';
```
`tone`: `setup | pending | clean | filtered | error`. `clean` ≠ `filtered` ≠ `error` — a security
tool must never render a failed read as "nothing found". `clean` owes `meta` (what/when scanned).
`SkeletonRows` density must equal the real table's.

### Icons
```tsx
import { IconFindings, IconSearch, /* … */ } from '@/components/ui/icons';
```
Inline SVG, 24×24, 1.5px stroke, `currentColor` — theme-correct for free, `aria-hidden` by default.
Icon-only controls need an `aria-label`.

---

## 4. Charts (`components/charts/*`)

Dependency-free SVG, theme-aware, **dataviz non-negotiables**: one axis carries scale; categorical
hues in fixed order (never cycled, never for status); status reserved + icon + label; gridlines
recessive (`--grid`) and under the marks; all text an ink token, never a series colour; every chart
carries a text alternative (SVG `<title>` + a visually-hidden `<table>` via `ChartTable`).

```tsx
import { Sparkline } from '@/components/charts/Sparkline';    // single trend; observed y-domain + endpoint labels
import { SeverityBar } from '@/components/charts/SeverityBar'; // stacked severity mix (the one chart using status colour)
import { Donut } from '@/components/charts/Donut';            // nominal distribution (by system/kind), categorical palette
import { categorical, Legend, ChartTable } from '@/components/charts/utils';
```
`SeverityBar` legends with `SeverityBadge` (shape+word+count). `Donut` hole holds the total; a legend
is mandatory. `Sparkline` prints first→last values so a zoomed domain can't mislead. Legend required
for ≥2 series.

---

## 5. Layout conventions

- One `<h1>` per route (`PageHeader`). Page body in a `display:grid; gap:var(--space-4)` column with a
  sensible `maxWidth` (~1080–1280).
- Provenance everywhere: every count/panel says what it's from and as-of when (`CardMeta`,
  `PageHeader meta`).
- Server-first: read under RLS in a Server Component; keep interactive bits (`'use client'`) small
  islands. Filter state belongs in `searchParams`, not `useState`, so views stay shareable.
- `typedRoutes` is ON — every `href` is checked; a dead route is a build error. Reference only real
  routes.
