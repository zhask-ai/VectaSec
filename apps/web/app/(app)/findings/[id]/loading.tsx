import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

/* Loading state for the detail page.
 *
 * The skeleton mirrors the real hierarchy — header, evidence, triage, actions rail — so the
 * page does not rearrange itself when data lands. It deliberately does NOT show a placeholder
 * where the evidence blocks go in a way that implies a count: the number of observations is the
 * one thing on this page a reader might take from a skeleton as fact.
 */
export default function LoadingFinding() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1200 }}>
      <Skeleton width={80} height={12} />

      <Card>
        <CardBody>
          <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
            <Skeleton width={220} height={16} />
            <Skeleton width="60%" height={24} />
            <Skeleton width="40%" height={12} />
          </div>
        </CardBody>
      </Card>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(240px, 300px)', gap: 'var(--space-4)', alignItems: 'start' }}>
        <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <Card>
            <CardHeader>
              <CardTitle>Evidence</CardTitle>
            </CardHeader>
            <CardBody>
              <div role="status" aria-label="Loading evidence" style={{ display: 'grid', gap: 'var(--space-3)' }}>
                <span className="vs-visually-hidden">Loading…</span>
                <Skeleton height={72} radius="var(--radius-md)" />
                <Skeleton height={72} radius="var(--radius-md)" />
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Why this matters</CardTitle>
            </CardHeader>
            <CardBody>
              <div style={{ display: 'grid', gap: 'var(--space-2)' }}>
                <Skeleton height={12} />
                <Skeleton width="90%" height={12} />
                <Skeleton width="70%" height={12} />
              </div>
            </CardBody>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Actions</CardTitle>
          </CardHeader>
          <CardBody>
            <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
              <Skeleton height={40} radius="var(--radius-md)" />
              <Skeleton height={40} radius="var(--radius-md)" />
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
