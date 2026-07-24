import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton, SkeletonRows } from '@/components/ui/skeleton';

/* Streamed while the controls + findings reads resolve.
 *
 * `density="relaxed"` and the column widths MUST track the real table in page.tsx — a skeleton
 * whose rows are the wrong height moves the page when data lands, which is the one thing a
 * skeleton exists to prevent.
 *
 * The KPI strip IS skeletoned (it is always five tiles — deterministic), but the framework
 * OVERVIEW grid is not: its card count varies by tenant, and guessing it would flash a layout that
 * then collapses. Same reason there are two detail cards, not four — two is the floor of what a
 * tenant with any compliance data has.
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

      {/* KPI band — five tiles, always. */}
      <Card>
        <CardBody>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
              gap: 'var(--space-4)',
            }}
          >
            {[0, 1, 2, 3, 4].map((i) => (
              <div key={i} style={{ display: 'grid', gap: 'var(--space-1)' }}>
                <Skeleton width={72} height={11} />
                <Skeleton width={56} height={28} />
              </div>
            ))}
          </div>
        </CardBody>
      </Card>

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
