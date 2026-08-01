import 'server-only';

/* Transactional mail via Resend's HTTP API — one fetch, no SDK dependency.
 *
 * Configuration is two server-only env vars (apps/web/.env.local): RESEND_API_KEY and
 * EMAIL_FROM. When either is missing this module is a LOGGED NO-OP: sign-in must never fail,
 * slow down, or behave differently because mail is unconfigured — a fresh clone with no key
 * still logs in fine. The same rule holds for send failures: Resend being down (or the free
 * tier's test sender refusing a recipient — onboarding@resend.dev only delivers to the
 * account owner's own inbox) is logged and swallowed, never surfaced to the user mid-auth.
 *
 * Note this covers only the emails the APP sends (e.g. the sign-in notification). The auth
 * emails Supabase sends before login — confirmation, recovery, invite — are configured
 * separately as custom SMTP in the Supabase dashboard, pointed at the same Resend account.
 */

const RESEND_API = 'https://api.resend.com/emails';

async function send(to: string, subject: string, html: string, text: string): Promise<void> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM;
  if (!key || !from) {
    console.warn('[email] RESEND_API_KEY / EMAIL_FROM not set — skipping:', subject);
    return;
  }
  try {
    const res = await fetch(RESEND_API, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to, subject, html, text }),
    });
    if (!res.ok) {
      console.error('[email] resend rejected send:', res.status, await res.text());
    }
  } catch (err) {
    console.error('[email] send failed:', err);
  }
}

/**
 * "New sign-in to your account" — sent after every successful password or OAuth sign-in.
 * Deliberately sparse: a timestamp and a reset link, no IP/device claims we cannot stand
 * behind from here. `origin` is the request origin, so the link works in dev and prod alike.
 *
 * The markup mirrors docs/email-templates/ (tables, fully inline styles, no images, literal
 * hex): those constraints come from email clients, not taste, and they apply here too. If the
 * brand accent moves in globals.css, it must be updated in both places — email cannot read a
 * CSS variable, so the duplication is real and deliberate.
 */
export async function sendSignInNotification(to: string, origin: string): Promise<void> {
  const when = new Date().toUTCString();
  const resetUrl = `${origin}/forgot-password`;
  await send(
    to,
    'New sign-in to your VectaSec account',
    `<div style="display:none;max-height:0;overflow:hidden;mso-hide:all;">
  Your VectaSec account was just signed in to on ${when}.
</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;background:#f2f2f0;padding:44px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <tr>
    <td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;max-width:520px;background:#ffffff;border-radius:16px;overflow:hidden;box-shadow:0 1px 2px rgba(16,12,32,0.04),0 12px 32px rgba(16,12,32,0.08);">
        <tr>
          <td bgcolor="#4c1d95" style="background-color:#4c1d95;background-image:linear-gradient(135deg,#6d28d9 0%,#4c1d95 55%,#2e1065 100%);padding:26px 36px;">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
              <tr>
                <td width="34" height="34" align="center" valign="middle" style="width:34px;height:34px;background:#ffffff;border-radius:9px;color:#4c1d95;font-size:17px;font-weight:700;line-height:34px;text-align:center;">V</td>
                <td style="padding-left:12px;">
                  <div style="font-size:15px;font-weight:700;letter-spacing:0.18em;color:#ffffff;line-height:1.2;">VECTASEC</div>
                  <div style="font-size:11px;color:#c9b8f5;line-height:1.4;padding-top:2px;">integration-layer security posture</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:36px;">
            <h1 style="margin:0 0 12px;font-size:25px;line-height:1.25;font-weight:600;letter-spacing:-0.025em;color:#0b0b0b;">New sign-in to your account</h1>
            <p style="margin:0 0 22px;font-size:15px;line-height:1.65;color:#52514e;">
              Your VectaSec account <strong style="color:#0b0b0b;">${to}</strong> was just signed in to.
            </p>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;background:#faf9f7;border:1px solid #ececea;border-radius:11px;margin-bottom:26px;">
              <tr>
                <td style="padding:14px 16px;">
                  <div style="font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#8a8880;">Signed in at</div>
                  <div style="font-size:14px;color:#0b0b0b;padding-top:3px;">${when}</div>
                </td>
              </tr>
            </table>
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;background:#f7f5ff;border:1px solid #e6dffb;border-radius:11px;">
              <tr>
                <td style="padding:14px 16px;font-size:12.5px;line-height:1.6;color:#5b5570;">
                  <strong style="color:#3f2d70;">Wasn&rsquo;t you?</strong> Reset your password now:<br />
                  <a href="${resetUrl}" style="color:#6d28d9;word-break:break-all;text-decoration:none;">${resetUrl}</a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;max-width:520px;">
        <tr>
          <td align="center" style="padding:22px 16px 0;">
            <div style="font-size:11.5px;line-height:1.6;color:#8a8880;">
              VectaSec &middot; continuous security posture for the integration layer
            </div>
            <div style="font-size:11px;line-height:1.6;color:#a3a099;padding-top:4px;">
              This is an automated message &mdash; please don&rsquo;t reply.
            </div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>`,
    `Your VectaSec account ${to} was just signed in to at ${when}. If this was you, no action is needed. If it wasn't, reset your password: ${resetUrl}`,
  );
}
