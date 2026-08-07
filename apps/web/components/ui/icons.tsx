import type { SVGProps } from 'react';

/* The inline-SVG icon set. No icon library ships to the browser — a security console should not
 * pull a font or a runtime for its chrome, and inline SVG is the only way to guarantee a mark
 * renders identically everywhere (a glyph font can silently fall back to a box, dropping a
 * redundancy channel without anyone noticing — the same reason SeverityBadge draws its shapes).
 *
 * Every icon is a 24×24, 1.5px stroke, `currentColor` mark: it inherits the text colour of its
 * context, so it is theme-correct for free and never needs its own colour token. Icons are
 * decorative by default (aria-hidden); the label beside them carries meaning. Pass a `title` only
 * when an icon is the SOLE control content (e.g. an icon-only button), and give that button an
 * aria-label instead — do not rely on the icon to name it.
 */

export type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 16, children, ...rest }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {children}
    </svg>
  );
}

/* ── Navigation ─────────────────────────────────────────────────────────── */

export const IconOverview = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="3" width="7" height="9" rx="1" />
    <rect x="14" y="3" width="7" height="5" rx="1" />
    <rect x="14" y="12" width="7" height="9" rx="1" />
    <rect x="3" y="16" width="7" height="5" rx="1" />
  </Svg>
);

export const IconFindings = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3l8 4v5c0 4.5-3.2 7.6-8 9-4.8-1.4-8-4.5-8-9V7z" />
    <path d="M12 9v3.5" />
    <path d="M12 15.5h.01" />
  </Svg>
);

export const IconSystems = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="4" width="18" height="6" rx="1.5" />
    <rect x="3" y="14" width="18" height="6" rx="1.5" />
    <path d="M7 7h.01M7 17h.01" />
  </Svg>
);

export const IconIdentities = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="9" cy="8" r="3.2" />
    <path d="M3.5 20a5.5 5.5 0 0 1 11 0" />
    <path d="M15.5 8.5l2.2 2.2a2 2 0 1 0 1.4-1.4L16.9 7" />
  </Svg>
);

export const IconData = (p: IconProps) => (
  <Svg {...p}>
    <ellipse cx="12" cy="5.5" rx="7" ry="2.8" />
    <path d="M5 5.5v6c0 1.55 3.13 2.8 7 2.8s7-1.25 7-2.8v-6" />
    <path d="M5 11.5v6c0 1.55 3.13 2.8 7 2.8s7-1.25 7-2.8v-6" />
  </Svg>
);

export const IconAssets = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" />
    <path d="M12 3v9m0 0l8-4.5M12 12l-8-4.5" />
  </Svg>
);

export const IconAttackPaths = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="6" cy="6" r="2.5" />
    <circle cx="18" cy="18" r="2.5" />
    <circle cx="18" cy="6" r="2.5" />
    <path d="M8.5 6H15.5M6 8.5v4A5.5 5.5 0 0 0 11.5 18h4" />
  </Svg>
);

export const IconCompliance = (p: IconProps) => (
  <Svg {...p}>
    <rect x="5" y="3.5" width="14" height="17" rx="2" />
    <path d="M9 3.5h6v2.5H9z" />
    <path d="M8.5 13l2.2 2.2L15.5 10.5" />
  </Svg>
);

export const IconScans = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 12L17 8" />
    <path d="M12 3.5v2M12 18.5v2M3.5 12h2M18.5 12h2" />
  </Svg>
);

export const IconSettings = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="3" />
    <path d="M12 2.5v2.2M12 19.3v2.2M4.2 4.2l1.6 1.6M18.2 18.2l1.6 1.6M2.5 12h2.2M19.3 12h2.2M4.2 19.8l1.6-1.6M18.2 5.8l1.6-1.6" />
  </Svg>
);

/* ── UI / chrome ────────────────────────────────────────────────────────── */

export const IconSearch = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-3.5-3.5" />
  </Svg>
);

export const IconSun = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2.5v2.5M12 19v2.5M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M2.5 12H5M19 12h2.5M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8" />
  </Svg>
);

export const IconMoon = (p: IconProps) => (
  <Svg {...p}>
    <path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z" />
  </Svg>
);

export const IconMenu = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 6h16M4 12h16M4 18h16" />
  </Svg>
);

export const IconClose = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 6l12 12M18 6L6 18" />
  </Svg>
);

export const IconChevronDown = (p: IconProps) => (
  <Svg {...p}>
    <path d="M6 9l6 6 6-6" />
  </Svg>
);

export const IconChevronRight = (p: IconProps) => (
  <Svg {...p}>
    <path d="M9 6l6 6-6 6" />
  </Svg>
);

export const IconArrowUpRight = (p: IconProps) => (
  <Svg {...p}>
    <path d="M7 17L17 7M8 7h9v9" />
  </Svg>
);

export const IconArrowUp = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 19V5M6 11l6-6 6 6" />
  </Svg>
);

export const IconArrowDown = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 5v14M6 13l6 6 6-6" />
  </Svg>
);

export const IconSignOut = (p: IconProps) => (
  <Svg {...p}>
    <path d="M15 5.5H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9" />
    <path d="M14 12h7m0 0l-3-3m3 3l-3 3" />
  </Svg>
);

export const IconUser = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="8" r="3.5" />
    <path d="M5 20a7 7 0 0 1 14 0" />
  </Svg>
);

export const IconCheck = (p: IconProps) => (
  <Svg {...p}>
    <path d="M5 12.5l4.5 4.5L19 7" />
  </Svg>
);

export const IconInfo = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 11v5M12 8h.01" />
  </Svg>
);

/* ── Actions ────────────────────────────────────────────────────────────── */

export const IconPlay = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8 5.5v13l11-6.5z" />
  </Svg>
);

export const IconZap = (p: IconProps) => (
  <Svg {...p}>
    <path d="M13 2.5L4.5 13.5H11l-1 8L18.5 10.5H12z" />
  </Svg>
);

export const IconTrash = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13" />
    <path d="M10 11v5M14 11v5" />
  </Svg>
);

export const IconRefresh = (p: IconProps) => (
  <Svg {...p}>
    <path d="M20 12a8 8 0 1 1-2.34-5.66" />
    <path d="M20 3v4h-4" />
  </Svg>
);

export const IconExternal = (p: IconProps) => (
  <Svg {...p}>
    <path d="M13 5h6v6M19 5l-8.5 8.5" />
    <path d="M19 14.5V18a1.5 1.5 0 0 1-1.5 1.5H6A1.5 1.5 0 0 1 4.5 18V6.5A1.5 1.5 0 0 1 6 5h3.5" />
  </Svg>
);

/* ── Domain marks (resource kinds, hop roles, transports) ──────────────── */

export const IconBroadcast = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="2" fill="currentColor" stroke="none" />
    <path d="M7.5 7.5a6.4 6.4 0 0 0 0 9M16.5 7.5a6.4 6.4 0 0 1 0 9M4.6 4.6a10.5 10.5 0 0 0 0 14.8M19.4 4.6a10.5 10.5 0 0 1 0 14.8" />
  </Svg>
);

export const IconKey = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="8" cy="8.5" r="4" />
    <path d="M11 11.5l8 8M16.5 17l2.2-2.2M13.8 14.3l2-2" />
  </Svg>
);

export const IconLock = (p: IconProps) => (
  <Svg {...p}>
    <rect x="5" y="10.5" width="14" height="9.5" rx="1.8" />
    <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    <path d="M12 14.5v2" />
  </Svg>
);

export const IconUnlock = (p: IconProps) => (
  <Svg {...p}>
    <rect x="5" y="10.5" width="14" height="9.5" rx="1.8" />
    <path d="M8 10.5V7.5a4 4 0 0 1 7.87-1" />
    <path d="M12 14.5v2" />
  </Svg>
);

export const IconDatabase = (p: IconProps) => (
  <Svg {...p}>
    <ellipse cx="12" cy="5.5" rx="7.5" ry="2.8" />
    <path d="M4.5 5.5v13c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8v-13" />
    <path d="M4.5 12c0 1.55 3.36 2.8 7.5 2.8s7.5-1.25 7.5-2.8" />
  </Svg>
);

export const IconServer = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3.5" y="4" width="17" height="6.5" rx="1.5" />
    <rect x="3.5" y="13.5" width="17" height="6.5" rx="1.5" />
    <path d="M7 7.25h.01M7 16.75h.01M10.5 7.25h3M10.5 16.75h3" />
  </Svg>
);

export const IconQueue = (p: IconProps) => (
  <Svg {...p}>
    <rect x="3" y="9.5" width="5" height="5" rx="1" />
    <rect x="9.5" y="9.5" width="5" height="5" rx="1" />
    <rect x="16" y="9.5" width="5" height="5" rx="1" />
    <path d="M3.5 5.5h17M3.5 18.5h17" />
  </Svg>
);

export const IconTopic = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 6.5h16M4 12h16M4 17.5h9" />
    <circle cx="18.5" cy="17.5" r="2.5" />
  </Svg>
);

export const IconGateway = (p: IconProps) => (
  <Svg {...p}>
    <path d="M4 20V8.5L12 4l8 4.5V20" />
    <path d="M9 20v-6.5a3 3 0 0 1 6 0V20" />
  </Svg>
);

export const IconPlug = (p: IconProps) => (
  <Svg {...p}>
    <path d="M9 3.5V8M15 3.5V8" />
    <path d="M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0z" />
    <path d="M12 17v3.5" />
  </Svg>
);

export const IconRadar = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <circle cx="12" cy="12" r="4.75" />
    <circle cx="12" cy="12" r="1.1" fill="currentColor" stroke="none" />
    <path d="M12 12l6-6" />
  </Svg>
);

export const IconBraces = (p: IconProps) => (
  <Svg {...p}>
    <path d="M8.5 4.5c-2 0-2.5 1-2.5 2.5v2.5c0 1.5-.7 2.5-2 2.5 1.3 0 2 1 2 2.5V17c0 1.5.5 2.5 2.5 2.5" />
    <path d="M15.5 4.5c2 0 2.5 1 2.5 2.5v2.5c0 1.5.7 2.5 2 2.5-1.3 0-2 1-2 2.5V17c0 1.5-.5 2.5-2.5 2.5" />
  </Svg>
);

export const IconFileCode = (p: IconProps) => (
  <Svg {...p}>
    <path d="M14 3.5H7a1.5 1.5 0 0 0-1.5 1.5v14A1.5 1.5 0 0 0 7 20.5h10a1.5 1.5 0 0 0 1.5-1.5V8z" />
    <path d="M14 3.5V8h4.5" />
    <path d="M10 12l-2 2 2 2M14 12l2 2-2 2" />
  </Svg>
);

export const IconIdentity = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="9" r="3.2" />
    <path d="M6 19.5a6 6 0 0 1 12 0" />
    <circle cx="12" cy="12" r="9.5" />
  </Svg>
);

export const IconAlertTriangle = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3.5L21.5 20h-19z" />
    <path d="M12 10v4M12 17h.01" />
  </Svg>
);

export const IconShieldCheck = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3l8 4v5c0 4.5-3.2 7.6-8 9-4.8-1.4-8-4.5-8-9V7z" />
    <path d="M8.8 12.2l2.2 2.2 4.2-4.6" />
  </Svg>
);

export const IconClock = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" />
    <path d="M12 7.5V12l3 2" />
  </Svg>
);

export const IconLayers = (p: IconProps) => (
  <Svg {...p}>
    <path d="M12 3.5l9 4.5-9 4.5-9-4.5z" />
    <path d="M3 12.5l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5" />
  </Svg>
);

export const IconActivity = (p: IconProps) => (
  <Svg {...p}>
    <path d="M3 12h3.5l2.5-6.5 4 13 2.5-6.5H21" />
  </Svg>
);

export const IconRoutePath = (p: IconProps) => (
  <Svg {...p}>
    <circle cx="5.5" cy="18.5" r="2.5" />
    <circle cx="18.5" cy="5.5" r="2.5" />
    <path d="M8 18.5h6a4 4 0 0 0 4-4v-1M16 5.5h-6a4 4 0 0 0-4 4v1" />
  </Svg>
);

/** Map a connector / resource type string to a domain mark. Fingerprinty, not exhaustive —
 * anything unrecognised gets the box glyph so a new connector never renders blank. */
export function IconForType({ type, size = 15 }: { type: string; size?: number }) {
  const t = type.toLowerCase();
  if (/(kafka|pulsar|kinesis|topic|stream)/.test(t)) return <IconTopic size={size} />;
  if (/(rabbit|amqp|sqs|queue|activemq|nats|exchange)/.test(t)) return <IconQueue size={size} />;
  if (/(redis|memcache|keyspace|cache|db|database|postgres|mysql|mongo)/.test(t)) return <IconDatabase size={size} />;
  if (/(kong|gateway|apigee|nginx|traefik|envoy|route)/.test(t)) return <IconGateway size={size} />;
  if (/(openapi|swagger|api)/.test(t)) return <IconBraces size={size} />;
  if (/(iac|terraform|compose|helm|manifest|yaml)/.test(t)) return <IconFileCode size={size} />;
  if (/(discovery|sweep|probe|scan)/.test(t)) return <IconRadar size={size} />;
  if (/(mcp|plugin|connector|integration)/.test(t)) return <IconPlug size={size} />;
  if (/(identity|principal|user|nhi|service.?account)/.test(t)) return <IconIdentity size={size} />;
  if (/(grant|acl|permission|role|policy)/.test(t)) return <IconKey size={size} />;
  if (/(broker|server|host|node|listener)/.test(t)) return <IconServer size={size} />;
  return <IconAssets size={size} />;
}
