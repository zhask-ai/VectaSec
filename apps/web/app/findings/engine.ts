import 'server-only';

/* The engine API client.
 *
 * WHY THIS IS SERVER-ONLY, and why the URL is not NEXT_PUBLIC:
 *
 * The engine authenticates with two self-asserted headers — X-VectaSec-Tenant and
 * X-VectaSec-Actor — and does not verify membership (api/main.py `principal`, which says so
 * itself and binds to localhost for that reason). If the browser called the engine directly,
 * every user would be able to name any tenant and any actor: cross-tenant writes and a
 * forgeable audit trail, from the devtools console, with no exploit needed.
 *
 * So the console is the thing that makes those headers trustworthy. Callers never pass a
 * tenant; it is derived from a row RLS already agreed the user can see (getFindingTenant), and
 * the actor is the id from a server-confirmed getUser(). The browser cannot reach this file,
 * cannot see this URL, and cannot influence either header.
 *
 * When the engine grows real JWT verification (its own TODO(auth)), this indirection stops
 * being load-bearing — but it should stay anyway: it is also what keeps the engine off the
 * public network.
 */

const ENGINE_URL = process.env.VECTASEC_ENGINE_URL ?? 'http://127.0.0.1:8000';

/** How long to wait on the engine before calling it unreachable.
 *
 * Deliberately short. Every caller is a human who clicked a button and is watching a spinner;
 * the default fetch timeout would leave them staring at it. Triage is the exception — it can
 * call an LLM — and passes its own. */
const DEFAULT_TIMEOUT_MS = 8_000;

export type EngineResult<T> = { ok: true; data: T } | { ok: false; message: string };

export async function enginePost<T>(
  path: string,
  body: unknown,
  auth: { tenantId: string; actor: string },
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<EngineResult<T>> {
  try {
    const res = await fetch(`${ENGINE_URL}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-VectaSec-Tenant': auth.tenantId,
        'X-VectaSec-Actor': auth.actor,
      },
      body: JSON.stringify(body),
      cache: 'no-store',
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!res.ok) return { ok: false, message: await readError(res) };
    return { ok: true, data: (await res.json()) as T };
  } catch (e) {
    // The console must stay useful when the engine is down: findings, evidence and triage all
    // read from Supabase and are unaffected. Only actions are, so only actions say so.
    const reason = e instanceof Error && e.name === 'TimeoutError' ? 'did not respond in time' : 'is unreachable';
    return { ok: false, message: `The engine ${reason}. Findings and evidence are unaffected; this action was not applied.` };
  }
}

/** FastAPI reports validation failures as `{detail: [...]}` and deliberate refusals as
 * `{detail: "..."}`. Both are worth showing verbatim — the engine's refusals are written for a
 * human ("reason is required: a suppression nobody explained cannot be reviewed") and
 * paraphrasing them here would lose that. */
async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { detail?: unknown };
    const d = body.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) {
      const msgs = d
        .map((x) => (typeof x === 'object' && x && 'msg' in x ? String((x as { msg: unknown }).msg) : null))
        .filter(Boolean);
      if (msgs.length) return msgs.join('; ');
    }
  } catch {
    // Not JSON — a proxy error page, most likely. Fall through to the status line.
  }
  return `The engine rejected this action (HTTP ${res.status}).`;
}
