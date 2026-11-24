'use server';

import { enginePost } from '@/lib/engine';
import { canEdit, getOwnMembership } from '@/lib/role';
import { getVerifiedUser } from '@/lib/supabase/server';

export type Suggestion = {
  title: string;
  why: string;
  severity: 'high' | 'medium' | 'low';
  evidence_path: string;
  evidence_value: string;
  check: string;
};
export type Review = { suggestions: Suggestion[]; discarded: number; ai_used: boolean; note: string; disclaimer: string };
export type ReviewState = { ok: boolean; message: string; result?: Review } | null;

/* Runs the AI review for one resource. The engine re-checks the role, reads the configuration
 * itself (nothing from the browser is sent to the model) and verifies every quote. */
export async function reviewResourceAction(_prev: ReviewState, form: FormData): Promise<ReviewState> {
  const id = String(form.get('resourceId') ?? '');
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return { ok: false, message: 'Unknown resource.' };
  }
  const [user, membership] = await Promise.all([getVerifiedUser(), getOwnMembership()]);
  if (!user || !membership || !canEdit(membership.role)) {
    return { ok: false, message: 'You are not signed in or your role is view-only. No review was run.' };
  }
  const res = await enginePost<Review>(`/assistant/review/${id}`, {}, { tenantId: membership.tenantId, actor: user.id }, 120_000);
  if (!res.ok) return { ok: false, message: res.message };
  return { ok: true, message: '', result: res.data };
}
