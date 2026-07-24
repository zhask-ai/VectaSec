import { Card, CardBody, CardHeader, CardTitle } from '@/components/ui/card';
import { PageHeader } from '@/components/ui/page-header';
import { SkeletonRows } from '@/components/ui/skeleton';

/* Column widths mirror the real header; density matches the real table (see
 * findings/loading.tsx for why both must). */
export default function LoadingScans() {
  return (
    <div style={{ display: 'grid', gap: 'var(--space-4)', maxWidth: 1280 }}>
      <PageHeader
        title="Scans"
        description="Every scan run, newest first — what each one saw and whether it landed."
      />
      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
        </CardHeader>
        <CardBody pad={false}>
          <SkeletonRows
            count={8}
            density="default"
            columns={[
              { width: '12%' },
              { width: '24%' },
              { width: '16%' },
              { width: '10%' },
              { width: '10%' },
              { width: '10%' },
              { width: '18%' },
            ]}
          />
        </CardBody>
      </Card>
    </div>
  );
}
