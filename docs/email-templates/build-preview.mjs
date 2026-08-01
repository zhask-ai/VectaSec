/* Renders every VectaSec auth email into one gallery page, with Supabase's template
 * variables replaced by realistic sample values so the preview reads like a real inbox.
 * The sign-in notification is extracted from lib/email.ts rather than copied, so the preview
 * cannot drift from what actually ships. */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO = '/Users/chintu/Documents/GitHub/Zhask/VectaSec';
const TPL = join(REPO, 'docs/email-templates');
const OUT = process.argv[2];

const SAMPLE_URL =
  'https://evuyyttvmffxtxmaxpjo.supabase.co/auth/v1/verify?token=8f3c2e91b4&type=invite&redirect_to=https://vecta-sec-web.vercel.app/auth/callback';

const fill = (html) =>
  html
    .replace(/\{\{\s*\.ConfirmationURL\s*\}\}/g, SAMPLE_URL)
    .replace(/\{\{\s*\.NewEmail\s*\}\}/g, 'dishanth@vectasec.com')
    .replace(/\{\{\s*\.Email\s*\}\}/g, 'dchinnappa@vibrantinc.com')
    .replace(/<!--[\s\S]*?-->/g, '');

const files = [
  ['confirm-signup.html', 'Confirm signup', 'Confirm your VectaSec account'],
  ['invite.html', 'Invite user', "You're invited to VectaSec"],
  ['reset-password.html', 'Reset password', 'Reset your VectaSec password'],
  ['magic-link.html', 'Magic Link', 'Your VectaSec sign-in link'],
  ['change-email.html', 'Change Email Address', 'Confirm your new email address'],
];

const sections = files.map(([file, name, subject]) => ({
  name,
  subject,
  source: `docs/email-templates/${file}`,
  html: fill(readFileSync(join(TPL, file), 'utf8')),
}));

// The app-sent notification lives inside a TS template literal; slice it out and bind its
// three interpolations to sample values.
const src = readFileSync(join(REPO, 'apps/web/lib/email.ts'), 'utf8');
const start = src.indexOf('`<div style="display:none');
const end = src.indexOf('</table>`', start);
if (start !== -1 && end !== -1) {
  const body = src
    .slice(start + 1, end + '</table>'.length)
    .replace(/\$\{to\}/g, 'dchinnappa@vibrantinc.com')
    .replace(/\$\{when\}/g, 'Tue, 28 Jul 2026 16:42:10 GMT')
    .replace(/\$\{resetUrl\}/g, 'https://vecta-sec-web.vercel.app/forgot-password');
  sections.push({
    name: 'Sign-in notification',
    subject: 'New sign-in to your VectaSec account',
    source: 'apps/web/lib/email.ts (sent by the app, not Supabase)',
    html: body,
  });
}

const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>VectaSec auth emails — preview</title>
<style>
  body { margin:0; background:#17161c; color:#e9e8ee;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif; }
  header { padding:36px 24px 8px; text-align:center; }
  h1 { margin:0 0 6px; font-size:22px; font-weight:600; letter-spacing:-0.02em; }
  header p { margin:0; font-size:13px; color:#9c99a8; }
  .item { padding:28px 16px 40px; }
  .meta { max-width:520px; margin:0 auto 14px; }
  .name { font-size:15px; font-weight:600; letter-spacing:-0.01em; }
  .subject { font-size:12.5px; color:#a89ff0; padding-top:3px; }
  .source { font-size:11px; color:#75727f; padding-top:2px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
  .frame { max-width:520px; margin:0 auto; border-radius:14px; overflow:hidden;
           box-shadow:0 18px 50px rgba(0,0,0,0.45); }
  .frame > table { margin:0 !important; }
  hr.sep { border:0; border-top:1px solid #2a2833; max-width:900px; margin:0 auto; }
</style></head>
<body>
<header>
  <h1>VectaSec auth emails</h1>
  <p>Rendered from the real templates, with sample values in place of Supabase's variables.</p>
</header>
${sections
  .map(
    (s) => `<div class="item">
  <div class="meta">
    <div class="name">${s.name}</div>
    <div class="subject">Subject: ${s.subject}</div>
    <div class="source">${s.source}</div>
  </div>
  <div class="frame">${s.html}</div>
</div>
<hr class="sep" />`,
  )
  .join('\n')}
</body></html>`;

writeFileSync(OUT, page);
console.log(`wrote ${OUT} — ${sections.length} emails`);
