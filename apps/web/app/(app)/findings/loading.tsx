import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton, SkeletonRows } from '@/components/ui/skeleton';

/* Loading state for the queue.
 *
 * `density="compact"` MUST match FindingsTable's density. If skeleton rows are not exactly the
 * final row height the page jumps when data lands (CLS) — which defeats the entire reason to
 * use a skeleton instead of a spinner. The column widths mirror the real header for the same
 * reason: a skeleton says "here is what is coming", and it should not be wrong about it.
 */
export default function LoadingFindings() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)' }}>
      <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
        Findings
      </h1>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 200px) minmax(0, 1fr)', gap: 'var(--space-4)', alignItems: 'start' }}>
        <div aria-hidden="true" style={{ display: 'grid', gap: 'var(--space-4)' }}>
          <Skeleton height={32} />
          <Skeleton height={120} />
          <Skeleton height={100} />
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Findings</CardTitle>
          </CardHeader>
          <CardBody pad={false}>
            <SkeletonRows
              count={12}
              density="compact"
              columns={[{ width: '96px' }, { width: '18%' }, { width: '30%' }, { width: '14%' }, { width: '64px' }]}
            />
          </CardBody>
        </Card>
      </div>
    </div>
  );
}
