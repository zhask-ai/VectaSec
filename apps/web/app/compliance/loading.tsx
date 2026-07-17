import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton, SkeletonRows } from '@/components/ui/skeleton';

/* Streamed while the controls + findings reads resolve.
 *
 * `density="relaxed"` and the column widths MUST track the real table in page.tsx — a skeleton
 * whose rows are the wrong height moves the page when data lands, which is the one thing a
 * skeleton exists to prevent.
 *
 * Two cards, not four: guessing a count would flash a layout that then collapses. Two is the
 * floor of what a tenant with any compliance data has.
 */
export default function Loading() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-5)', maxWidth: 1200 }}>
      <h1
        style={{
          margin: 0,
          fontSize: 'var(--text-xl)',
          lineHeight: 'var(--leading-xl)',
          fontWeight: 600,
        }}
      >
        Compliance
      </h1>

      {[0, 1].map((i) => (
        <Card key={i}>
          <CardHeader>
            <CardTitle>
              <Skeleton width={180} height={16} />
            </CardTitle>
          </CardHeader>
          <CardBody>
            <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
              <Skeleton width={220} height={32} />
              <Skeleton height={8} radius="var(--radius-full)" />
            </div>
          </CardBody>
          <SkeletonRows
            count={5}
            density="relaxed"
            columns={[{ width: '140px' }, { width: '120px' }, { width: '30%' }, { width: '34%' }]}
          />
        </Card>
      ))}
    </div>
  );
}
