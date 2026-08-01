'use client';

/* Form primitives shared by the auth screens. Class-styled from globals.css (.vs-auth-*) so
 * the contrast source-audit sees no inline control borders and every colour stays a token.
 *
 * PasswordField owns two bits of local truth the browser will not surface for the user:
 *  - visibility: a show/hide toggle (type swap only — the value never leaves the input), and
 *  - Caps Lock: read off the KEYBOARD EVENT's modifier state, the only place it exists.
 * The optional strength meter is advisory UI, never validation — the server's policy is the
 * policy; this just stops "password1" feeling fine while it is typed.
 */
import { useId, useState } from 'react';

export function TextField({
  label,
  hint,
  help,
  ...input
}: React.InputHTMLAttributes<HTMLInputElement> & {
  label: React.ReactNode;
  hint?: React.ReactNode;
  help?: React.ReactNode;
}) {
  const id = useId();
  return (
    <div className="vs-auth-field">
      <label className="vs-auth-label" htmlFor={id}>
        <span>{label}</span>
        {hint}
      </label>
      <input id={id} className="vs-auth-input" {...input} />
      {help && <span className="vs-auth-help">{help}</span>}
    </div>
  );
}

/* Length + variety, three levels. Deliberately crude — a meter that argues with the user is
 * worse than none. 0 is rendered as an empty track. */
function strengthOf(pw: string): 0 | 1 | 2 | 3 {
  if (!pw) return 0;
  const variety = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (pw.length >= 12 && variety >= 3) return 3;
  if (pw.length >= 8 && variety >= 2) return 2;
  return 1;
}
const STRENGTH_LABEL = ['', 'Weak password', 'Decent password', 'Strong password'] as const;

export function PasswordField({
  label,
  hint,
  help,
  showStrength = false,
  value,
  ...input
}: React.InputHTMLAttributes<HTMLInputElement> & {
  label: React.ReactNode;
  hint?: React.ReactNode;
  help?: React.ReactNode;
  showStrength?: boolean;
  value: string;
}) {
  const id = useId();
  const [visible, setVisible] = useState(false);
  const [caps, setCaps] = useState(false);
  const level = showStrength ? strengthOf(value) : 0;

  return (
    <div className="vs-auth-field">
      <label className="vs-auth-label" htmlFor={id}>
        <span>{label}</span>
        {hint}
      </label>
      <div className="vs-auth-inputwrap">
        <input
          id={id}
          className="vs-auth-input"
          type={visible ? 'text' : 'password'}
          value={value}
          onKeyDown={(e) => setCaps(e.getModifierState('CapsLock'))}
          onKeyUp={(e) => setCaps(e.getModifierState('CapsLock'))}
          onBlur={() => setCaps(false)}
          {...input}
        />
        <button
          type="button"
          className="vs-auth-eye"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? 'Hide password' : 'Show password'}
          title={visible ? 'Hide password' : 'Show password'}
        >
          {visible ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M3 3l18 18" />
              <path d="M10.6 10.7a2.5 2.5 0 0 0 3.5 3.5" />
              <path d="M9.8 5.1A9.8 9.8 0 0 1 12 4.8c4.5 0 8.2 2.9 9.7 7.2a11.6 11.6 0 0 1-2.7 4.2M6.3 6.4A11.4 11.4 0 0 0 2.3 12c1.5 4.3 5.2 7.2 9.7 7.2 1.3 0 2.6-.2 3.7-.7" />
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M2.3 12C3.8 7.7 7.5 4.8 12 4.8s8.2 2.9 9.7 7.2c-1.5 4.3-5.2 7.2-9.7 7.2S3.8 16.3 2.3 12z" />
              <circle cx="12" cy="12" r="2.6" />
            </svg>
          )}
        </button>
      </div>
      {caps && (
        <span className="vs-auth-hint" role="status">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M12 3l9 9h-5v6h-8v-6H3z" />
          </svg>
          Caps Lock is on
        </span>
      )}
      {showStrength && (
        <>
          <div className="vs-auth-strength" data-level={level} aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <span className="vs-auth-help">{value ? STRENGTH_LABEL[level] : help}</span>
        </>
      )}
      {!showStrength && help && <span className="vs-auth-help">{help}</span>}
    </div>
  );
}

export function SubmitButton({
  busy,
  busyLabel,
  children,
}: {
  busy: boolean;
  busyLabel: string;
  children: React.ReactNode;
}) {
  return (
    <button type="submit" className="vs-auth-primary" disabled={busy}>
      {busy && <span className="vs-auth-spinner" aria-hidden="true" />}
      {busy ? busyLabel : children}
    </button>
  );
}

export function AuthAlert({
  tone,
  children,
}: {
  tone: 'error' | 'info';
  children: React.ReactNode;
}) {
  return (
    // role=alert so it is announced on arrival; the icon + text carry the tone, never colour alone.
    <div className="vs-auth-alert" data-tone={tone} role="alert">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        {tone === 'error' ? (
          <>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 7.5v5.5" />
            <path d="M12 16.5h.01" />
          </>
        ) : (
          <>
            <circle cx="12" cy="12" r="9" />
            <path d="M12 11v5" />
            <path d="M12 7.5h.01" />
          </>
        )}
      </svg>
      <span>{children}</span>
    </div>
  );
}
