import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { SkeletonRows } from '@/components/ui/skeleton';

/* Column widths mirror the real header; density matches the real table (see
 * findings/loading.tsx for why both must). */
export default function LoadingScans() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <h1 style={{ margin: 0, fontSize: 'var(--text-xl)', lineHeight: 'var(--leading-xl)', fontWeight: 600 }}>
        Scans
      </h1>
      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
        </CardHeader>
        <CardBody pad={false}>
          <SkeletonRows
            count={8}
            density="default"
            columns={[
              { width: '10%' },
              { width: '22%' },
              { width: '14%' },
              { width: '8%' },
              { width: '8%' },
              { width: '8%' },
              { width: '16%' },
            ]}
          />
        </CardBody>
      </Card>
    </div>
  );
}
