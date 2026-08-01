# Auth email templates

Branded replacements for Supabase's default auth emails, matching the console's identity
(violet `#6d28d9`, warm off-white surfaces, Inter-style system stack).

## Where these go

Supabase dashboard → **Authentication → Emails → Templates**. Each file below maps to one
template; paste the file's contents into the "Message body" box for that template and save.
Subjects are listed beside each file — set those in the same form.

| File | Supabase template | Subject to use |
| --- | --- | --- |
| `confirm-signup.html` | Confirm signup | `Confirm your VectaSec account` |
| `invite.html` | Invite user | `You're invited to VectaSec` |
| `reset-password.html` | Reset password | `Reset your VectaSec password` |
| `magic-link.html` | Magic Link | `Your VectaSec sign-in link` |
| `change-email.html` | Change Email Address | `Confirm your new email address` |

## Previewing them

`_preview.html` renders all six emails (the five above plus the app-sent sign-in
notification) on one page with sample values in place of the template variables. Open it in a
browser. It is GENERATED — after editing any template, regenerate it rather than hand-editing:

```bash
node docs/email-templates/build-preview.mjs docs/email-templates/_preview.html
```

The generator slices the sign-in notification straight out of `apps/web/lib/email.ts` instead
of keeping a copy, so the preview cannot silently drift from what actually ships.

## Why they are written this way

Email clients are not browsers. Gmail strips `<style>` blocks and external CSS, Outlook
renders through Word's HTML engine, and neither supports CSS variables, flexbox, or inline
SVG. So these templates deliberately use the boring-but-universal subset:

- **Tables for layout**, not flex or grid.
- **Every style inline** on the element it affects — no `<style>` block to strip.
- **No images and no SVG.** The mark is a rounded table cell with a letter, which renders
  identically everywhere and needs no hosting (and no image-blocking warning).
- **Hex colours, not tokens.** `var(--accent)` cannot resolve in an email; the violet is
  written literally. If the brand accent changes in `globals.css`, update it here too — that
  duplication is unavoidable, so it is documented rather than hidden.
- **Light-mode colours only.** Dark-mode email support is inconsistent across clients; a
  light card reads correctly in both.
- **A plain-text URL under every button**, because some clients suppress the styled link.

## Supabase template variables

`{{ .ConfirmationURL }}` is the action link and is already wired to `/auth/callback` by the
redirect settings. Also available: `{{ .Email }}`, `{{ .NewEmail }}` (change-email only),
`{{ .SiteURL }}`, `{{ .Token }}` (6-digit code), `{{ .TokenHash }}`.

## Sender note

While `EMAIL_FROM` is `onboarding@resend.dev`, Resend delivers **only** to the address that
owns the Resend account, and Gmail marks the mail "External". Both disappear once a real
domain is verified in Resend and the sender becomes e.g. `security@vectasec.com`.
