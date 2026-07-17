import type { ReactNode, CSSProperties } from 'react';

/* Card. A container, not a layout engine — it does not manage grids or its own width.
 * Elevation is a lighter surface in dark and a shadow in light; --surface-raised and
 * --shadow-popover already encode that inversion, so `raised` works in both themes. */

export function Card({
  children,
  raised = false,
  style,
}: {
  children: ReactNode;
  raised?: boolean;
  style?: CSSProperties;
}) {
  return (
    <section
      style={{
        background: raised ? 'var(--surface-raised)' : 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-md)',
        boxShadow: raised ? 'var(--shadow-popover)' : 'none',
        ...style,
      }}
    >
      {children}
    </section>
  );
}

export function CardHeader({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 'var(--space-3)',
        padding: 'var(--space-3) var(--space-4)',
        borderBottom: '1px solid var(--border)',
      }}
    >
      {children}
    </div>
  );
}

export function CardTitle({ children }: { children: ReactNode }) {
  return (
    <h2
      style={{
        margin: 0,
        fontSize: 'var(--text-lg)',
        lineHeight: 'var(--leading-lg)',
        fontWeight: 600,
        color: 'var(--text-primary)',
      }}
    >
      {children}
    </h2>
  );
}

/** Provenance line — "Updated 4m ago", "observed 04:12Z", collector + scan id.
 * An empty panel with no provenance reads as broken; a stale one reads as fresh. Say when. */
export function CardMeta({ children }: { children: ReactNode }) {
  return (
    <span
      style={{
        fontSize: 'var(--text-2xs)',
        lineHeight: 'var(--leading-2xs)',
        color: 'var(--text-muted)',
        fontVariantNumeric: 'tabular-nums',
      }}
    >
      {children}
    </span>
  );
}

export function CardBody({ children, pad = true }: { children: ReactNode; pad?: boolean }) {
  // pad={false} for tables, which bring their own cell padding and want to bleed to the edge.
  return <div style={{ padding: pad ? 'var(--space-4)' : 0 }}>{children}</div>;
}

export function CardFooter({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        padding: 'var(--space-2) var(--space-4)',
        borderTop: '1px solid var(--border)',
        fontSize: 'var(--text-xs)',
        color: 'var(--text-secondary)',
      }}
    >
      {children}
    </div>
  );
}
