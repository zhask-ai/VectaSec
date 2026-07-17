'use client';

import { useState } from 'react';

/* Copy-to-clipboard.
 *
 * The text is ALWAYS rendered as selectable text by the caller; this button is a shortcut, not
 * the only way to get the value. navigator.clipboard is undefined on insecure origins and can
 * be denied by permission policy, so a page that only offered this button would strand those
 * users with an unselectable value — which for an observation id (the thing a customer quotes
 * back to us) would be a real failure.
 */

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setState('copied');
      setTimeout(() => setState('idle'), 1500);
    } catch {
      // Denied or unavailable. Say so — a button that silently does nothing is worse than one
      // that admits it cannot.
      setState('failed');
    }
  };

  return (
    <button
      type="button"
      onClick={copy}
      style={{
        border: '1px solid var(--border-interactive)',
        borderRadius: 'var(--radius-sm)',
        background: 'transparent',
        color: 'var(--text-secondary)',
        fontSize: 'var(--text-2xs)',
        padding: '2px var(--space-2)',
        cursor: 'pointer',
        whiteSpace: 'nowrap',
      }}
    >
      {state === 'copied' ? 'Copied' : state === 'failed' ? 'Select it manually' : label}
      <span role="status" className="vs-visually-hidden">
        {state === 'copied' ? 'Copied to clipboard' : state === 'failed' ? 'Copy failed — select the text manually' : ''}
      </span>
    </button>
  );
}
