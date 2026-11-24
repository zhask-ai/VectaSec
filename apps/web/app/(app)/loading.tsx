/* The loading state every console page inherits unless it has its own: the page header, a tab
 * strip, a row of stat tiles and a card, drawn as skeletons in the same rhythm as a real page
 * (.vs-page), so content arrives in place instead of pushing the layout around. */
export default function Loading() {
  const tile = (
    <div className="vs-card" style={{ padding: 'var(--space-5)', display: 'grid', gap: 'var(--space-3)' }}>
      <span className="vs-skel" style={{ width: '45%', height: 10 }} />
      <span className="vs-skel" style={{ width: 56, height: 26 }} />
      <span className="vs-skel" style={{ width: '70%', height: 10 }} />
    </div>
  );
  return (
    <div className="vs-page" aria-busy="true" aria-label="Loading">
      <div style={{ display: 'grid', gap: 'var(--space-3)' }}>
        <span className="vs-skel" style={{ width: 180, height: 26 }} />
        <span className="vs-skel" style={{ width: 'min(560px, 90%)', height: 12 }} />
      </div>
      <div style={{ display: 'flex', gap: 'var(--space-5)', borderBottom: '1px solid var(--border)', paddingBottom: 'var(--space-3)' }}>
        {[96, 120, 80, 110].map((w) => (
          <span key={w} className="vs-skel" style={{ width: w, height: 12 }} />
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 'var(--space-4)' }}>
        {tile}
        {tile}
        {tile}
        {tile}
      </div>
      <div className="vs-card" style={{ padding: 'var(--space-5)', display: 'grid', gap: 'var(--space-4)' }}>
        <span className="vs-skel" style={{ width: 160, height: 14 }} />
        {[92, 86, 95, 78, 88].map((w, i) => (
          <span key={i} className="vs-skel" style={{ width: `${w}%`, height: 12 }} />
        ))}
      </div>
      <span className="vs-visually-hidden" role="status">
        Loading
      </span>
    </div>
  );
}
