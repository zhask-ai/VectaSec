"""Weekly digest — what changed in the estate since the last one (strategy §4 item 9).

A buyer with no security team does not open a console between scans. The digest is the one
message a week that keeps them engaged: new findings, what got fixed, new credentials, what
became reachable, what turned out to be unused, how many scans ran and failed, the posture
score and its move, and — because this product never hides what it could not see — how many
findings are coverage gaps (`not_assessable`).

Split the same way report.py is: `compose_digest` reads the window from the DB and returns a
plain dict; `render_digest_text` / `render_digest_slack` are pure, deterministic renderers over
that dict; `send_digest` is the only function with side effects (deliveries + the `digests`
row). Every SQL statement here starts with a `/* digest:<section> */` tag so a test's fake
cursor can dispatch on it without parsing SQL.

Honest "fixed": a finding counts as fixed in the window only when a human (or Verify) moved it
to `resolved` — audit_log rows with action finding.status / finding.verified and detail.to =
'resolved'. A finding that merely stopped being re-seen is NOT fixed; nothing closes it, and
the digest does not pretend otherwise.

Scheduling: this is a plain CLI command, so any scheduler works. A crontab line for Monday
08:00 UTC across every tenant:

    0 8 * * 1  cd /opt/vectasec/services/engine && uv run vectasec digest --all >> /var/log/vectasec-digest.log 2>&1

(or `POST /digests/run` from the console for one tenant, on demand.)
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from .notify import deliver, rule_wants
from .creds import resolve_secrets, runtime_config
from .redact import safe_error

log = logging.getLogger(__name__)

DIGEST_EVENT = "weekly_digest"
# Destination types a digest is routed to. Jira (one ticket per digest) and SIEM (OCSF is a
# per-finding shape) make no sense for a summary.
DIGEST_TYPES = ("slack", "teams", "email", "webhook", "vanta", "drata")
DEFAULT_WINDOW = timedelta(days=7)
TOP_N = 5

_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _iso(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _as_dt(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ── compose ───────────────────────────────────────────────────────────────
def compose_digest(cur, tenant_id: str, since, until) -> dict:
    """Read one tenant's window [since, until) into the digest dict (shape below). Pure with
    respect to its inputs: the same rows give the same dict; no clock is read here."""
    since_dt, until_dt = _as_dt(since), _as_dt(until)
    window = (tenant_id, since_dt, until_dt)

    # new findings (first observed in the window), open or not — what appeared is the news
    cur.execute(
        """/* digest:new_findings */
           select f.severity, f.rule_id, f.title, r.name, f.assessment
             from findings f left join resources r on r.id = f.resource_id
            where f.tenant_id = %s and f.first_seen >= %s and f.first_seen < %s
            order by case f.severity when 'critical' then 0 when 'high' then 1
                     when 'medium' then 2 when 'low' then 3 else 4 end, f.rule_id, r.name""",
        window,
    )
    new_rows = cur.fetchall()
    by_sev = {s: 0 for s in _SEVERITIES}
    new_not_assessable = 0
    top_new = []
    for sev, rule_id, title, rname, assessment in new_rows:
        if assessment == "not_assessable":
            new_not_assessable += 1
            continue
        by_sev[sev if sev in by_sev else "info"] += 1
        if len(top_new) < TOP_N:
            top_new.append({"severity": sev, "rule_id": rule_id, "title": title,
                            "resource": rname or ""})
    new_total = sum(by_sev.values())

    cur.execute(
        """/* digest:fixed */
           select a.target, f.rule_id, f.title, a.at
             from audit_log a left join findings f on f.id::text = a.target
            where a.tenant_id = %s and a.at >= %s and a.at < %s
              and a.action in ('finding.status', 'finding.verified')
              and a.detail->>'to' = 'resolved'
            order by a.at desc""",
        window,
    )
    fixed_rows = cur.fetchall()
    fixed_ids = []
    fixed_top = []
    for target, rule_id, title, at in fixed_rows:
        if target in fixed_ids:
            continue
        fixed_ids.append(target)
        if len(fixed_top) < TOP_N:
            fixed_top.append({"finding_id": target, "rule_id": rule_id or "",
                              "title": title or "", "at": _iso(at)})

    cur.execute(
        """/* digest:new_credentials */
           select name, labels->>'system', labels->>'credential_type'
             from resources
            where tenant_id = %s and kind = 'credential'
              and first_seen >= %s and first_seen < %s
            order by labels->>'system', name""",
        window,
    )
    cred_rows = cur.fetchall()
    by_system: dict[str, int] = {}
    for _name, system, _ctype in cred_rows:
        by_system[system or "unknown"] = by_system.get(system or "unknown", 0) + 1
    new_credentials = {
        "total": len(cred_rows),
        "by_system": dict(sorted(by_system.items())),
        "sample": [{"name": n, "system": s or "unknown", "credential_type": c or "unknown"}
                   for n, s, c in cred_rows[:TOP_N]],
    }

    cur.execute(
        """/* digest:newly_exposed */
           select f.severity, f.rule_id, f.title, r.name
             from findings f left join resources r on r.id = f.resource_id
            where f.tenant_id = %s and f.first_seen >= %s and f.first_seen < %s
              and f.rule_id like 'ATTACKPATH.%%' and f.assessment = 'assessed'
            order by case f.severity when 'critical' then 0 when 'high' then 1
                     when 'medium' then 2 when 'low' then 3 else 4 end, f.rule_id, r.name""",
        window,
    )
    exposed_rows = cur.fetchall()

    cur.execute(
        """/* digest:newly_unused */
           select f.severity, f.rule_id, f.title, r.name
             from findings f left join resources r on r.id = f.resource_id
            where f.tenant_id = %s and f.first_seen >= %s and f.first_seen < %s
              and f.rule_id = 'CREDENTIAL.LIFECYCLE.NEVER_USED' and f.assessment = 'assessed'
            order by r.name""",
        window,
    )
    unused_rows = cur.fetchall()

    cur.execute(
        """/* digest:scans */
           select count(*), count(*) filter (where status = 'error')
             from scans where tenant_id = %s and started_at >= %s and started_at < %s""",
        window,
    )
    scans_total, scans_failed = cur.fetchone() or (0, 0)

    cur.execute(
        """/* digest:posture_latest */
           select score, taken_at from posture_snapshots
            where tenant_id = %s and taken_at < %s
            order by taken_at desc limit 1""",
        (tenant_id, until_dt),
    )
    latest = cur.fetchone()
    cur.execute(
        """/* digest:posture_baseline */
           select score, taken_at from posture_snapshots
            where tenant_id = %s and taken_at <= %s
            order by taken_at desc limit 1""",
        (tenant_id, since_dt),
    )
    baseline = cur.fetchone()
    if baseline is None:
        # Nothing before the window: the earliest snapshot inside it is the nearest to `since`.
        cur.execute(
            """/* digest:posture_earliest */
               select score, taken_at from posture_snapshots
                where tenant_id = %s and taken_at >= %s and taken_at < %s
                order by taken_at asc limit 1""",
            window,
        )
        baseline = cur.fetchone()
    posture = {
        "score": latest[0] if latest else None,
        "taken_at": _iso(latest[1]) if latest else "",
        "previous_score": baseline[0] if baseline else None,
        "previous_taken_at": _iso(baseline[1]) if baseline else "",
        "delta": (int(latest[0]) - int(baseline[0])) if latest and baseline else None,
    }

    cur.execute(
        """/* digest:unknowns */
           select count(*) from findings
            where tenant_id = %s and status = 'open' and assessment = 'not_assessable'""",
        (tenant_id,),
    )
    row = cur.fetchone()
    not_assessable_open = int(row[0]) if row else 0

    return {
        "tenant_id": tenant_id,
        "period_start": _iso(since_dt),
        "period_end": _iso(until_dt),
        "new_findings": {"total": new_total, "by_severity": by_sev, "top": top_new},
        "fixed": {"total": len(fixed_ids), "top": fixed_top},
        "new_credentials": new_credentials,
        "newly_exposed": {"total": len(exposed_rows),
                          "top": [{"severity": s, "rule_id": r, "title": t, "resource": n or ""}
                                  for s, r, t, n in exposed_rows[:TOP_N]]},
        "newly_unused": {"total": len(unused_rows),
                         "top": [{"severity": s, "rule_id": r, "title": t, "resource": n or ""}
                                 for s, r, t, n in unused_rows[:TOP_N]]},
        "scans": {"total": int(scans_total or 0), "failed": int(scans_failed or 0)},
        "posture": posture,
        "unknowns": {"not_assessable_open": not_assessable_open,
                     "new_not_assessable": new_not_assessable},
    }


# ── render (pure) ─────────────────────────────────────────────────────────
def _period(d: dict) -> str:
    return f"{str(d.get('period_start') or '')[:10]} → {str(d.get('period_end') or '')[:10]}"


def _sev_line(by_sev: dict) -> str:
    parts = [f"{by_sev.get(s, 0)} {s}" for s in _SEVERITIES if by_sev.get(s, 0)]
    return ", ".join(parts) if parts else "none"


def _posture_line(p: dict) -> str:
    if p.get("score") is None:
        return "no posture snapshot yet"
    text = f"{p['score']}/100"
    delta = p.get("delta")
    if delta is None:
        return text + " (no earlier snapshot to compare)"
    sign = f"+{delta}" if delta > 0 else str(delta)
    word = "improved" if delta > 0 else "declined" if delta < 0 else "unchanged"
    return f"{text} ({sign} vs {p.get('previous_score')}, {word})"


def _item(f: dict) -> str:
    where = f" — {f['resource']}" if f.get("resource") else ""
    sev = f"[{f['severity']}] " if f.get("severity") else ""
    return f"{sev}{f.get('rule_id') or ''}: {f.get('title') or ''}{where}"


def render_digest_text(d: dict) -> str:
    """Plain-text rendering shared by Slack fallback text, Teams, email and the CLI."""
    nf = d.get("new_findings") or {}
    fx = d.get("fixed") or {}
    nc = d.get("new_credentials") or {}
    ne = d.get("newly_exposed") or {}
    nu = d.get("newly_unused") or {}
    sc = d.get("scans") or {}
    un = d.get("unknowns") or {}
    lines = [f"VectaSec weekly digest {_period(d)}", ""]
    lines.append(f"Posture: {_posture_line(d.get('posture') or {})}")
    lines.append(f"Scans: {sc.get('total', 0)} run, {sc.get('failed', 0)} failed")
    lines.append("")
    lines.append(f"New findings: {nf.get('total', 0)} ({_sev_line(nf.get('by_severity') or {})})")
    for f in nf.get("top") or []:
        lines.append(f"  • {_item(f)}")
    lines.append(f"Fixed: {fx.get('total', 0)} finding(s) moved to resolved")
    for f in fx.get("top") or []:
        lines.append(f"  • {f.get('rule_id') or ''}: {f.get('title') or ''}")
    lines.append(f"New credentials: {nc.get('total', 0)}"
                 + (" (" + ", ".join(f"{n} {s}" for s, n in (nc.get("by_system") or {}).items()) + ")"
                    if nc.get("by_system") else ""))
    for c in nc.get("sample") or []:
        lines.append(f"  • {c.get('system')}: {c.get('name')} ({c.get('credential_type')})")
    lines.append(f"Newly exposed: {ne.get('total', 0)} attack path(s)")
    for f in ne.get("top") or []:
        lines.append(f"  • {_item(f)}")
    lines.append(f"Newly unused: {nu.get('total', 0)} credential(s) with a confirmed never-used signal")
    for f in nu.get("top") or []:
        lines.append(f"  • {_item(f)}")
    lines.append("")
    lines.append(f"Unknowns: {un.get('not_assessable_open', 0)} open finding(s) are coverage gaps "
                 f"(not assessable), {un.get('new_not_assessable', 0)} new this week — "
                 "these are things VectaSec could not read, not failures.")
    return "\n".join(lines)


def render_digest_slack(d: dict) -> dict:
    """Slack Block Kit payload: header + fields + one section per non-empty list. `text` is
    the plain rendering so notification previews and non-Block clients still read."""
    nf = d.get("new_findings") or {}
    fx = d.get("fixed") or {}
    nc = d.get("new_credentials") or {}
    ne = d.get("newly_exposed") or {}
    nu = d.get("newly_unused") or {}
    sc = d.get("scans") or {}
    un = d.get("unknowns") or {}
    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text",
                                    "text": f"VectaSec weekly digest {_period(d)}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Posture*\n{_posture_line(d.get('posture') or {})}"},
            {"type": "mrkdwn", "text": f"*Scans*\n{sc.get('total', 0)} run, {sc.get('failed', 0)} failed"},
            {"type": "mrkdwn", "text": f"*New findings*\n{nf.get('total', 0)} ({_sev_line(nf.get('by_severity') or {})})"},
            {"type": "mrkdwn", "text": f"*Fixed*\n{fx.get('total', 0)}"},
            {"type": "mrkdwn", "text": f"*New credentials*\n{nc.get('total', 0)}"},
            {"type": "mrkdwn", "text": f"*Newly exposed*\n{ne.get('total', 0)}"},
            {"type": "mrkdwn", "text": f"*Newly unused*\n{nu.get('total', 0)}"},
            {"type": "mrkdwn", "text": f"*Coverage gaps*\n{un.get('not_assessable_open', 0)} open"},
        ]},
    ]

    def section(title: str, items: list[str]) -> None:
        if items:
            blocks.append({"type": "section", "text": {
                "type": "mrkdwn", "text": f"*{title}*\n" + "\n".join(f"• {i}" for i in items)}})

    section("Top new findings", [_item(f) for f in nf.get("top") or []])
    section("Fixed", [f"{f.get('rule_id') or ''}: {f.get('title') or ''}" for f in fx.get("top") or []])
    section("New credentials", [f"{c.get('system')}: {c.get('name')} ({c.get('credential_type')})"
                                for c in nc.get("sample") or []])
    section("Newly exposed", [_item(f) for f in ne.get("top") or []])
    section("Newly unused", [_item(f) for f in nu.get("top") or []])
    blocks.append({"type": "context", "elements": [{
        "type": "mrkdwn",
        "text": f"{un.get('new_not_assessable', 0)} new finding(s) this week were not assessable — "
                "coverage gaps, not failures. Unknown is not unused."}]})
    return {"text": render_digest_text(d), "blocks": blocks}


# ── send ──────────────────────────────────────────────────────────────────
def _last_period_end(cur, tenant_id: str):
    cur.execute(
        """/* digest:last_period_end */
           select max(period_end) from digests where tenant_id = %s""",
        (tenant_id,),
    )
    row = cur.fetchone()
    return row[0] if row else None


def send_digest(conn, tenant_id: str, *, since=None, until=None, client=None) -> dict:
    """Compose the window, deliver to every enabled routing rule whose notify_on names
    weekly_digest (destination types DIGEST_TYPES), record the run in `digests`.

    Per-destination isolation, as in notify_scan: one failing destination is recorded in
    delivered_to with its (redacted) error and the rest still go out. Returns
    {"id", "digest", "delivered_to": [...]}. Raises only when the DB itself fails."""
    until_dt = _as_dt(until) if until is not None else datetime.now(timezone.utc)
    with conn.cursor() as cur:
        if since is not None:
            since_dt = _as_dt(since)
        else:
            last = _last_period_end(cur, tenant_id)
            since_dt = _as_dt(last) if last else until_dt - DEFAULT_WINDOW
        digest = compose_digest(cur, tenant_id, since_dt, until_dt)

        cur.execute(
            """/* digest:rules */
               select r.id::text, r.match, i.id::text, i.type, i.name, i.config, i.creds_ref
                 from routing_rules r join integrations i on i.id = r.integration_id
                where r.tenant_id = %s and i.enabled and coalesce(r.enabled, true)""",
            (tenant_id,),
        )
        rules = cur.fetchall()

        delivered_to: list[dict] = []
        seen_integrations: set[str] = set()
        event = {"kind": DIGEST_EVENT, "tenant_id": tenant_id, "scan_id": None,
                 "connection": {"type": "vectasec", "name": "weekly-digest"},
                 "findings": [], "error": None, "digest": digest}
        for rule_id, match, iid, itype, iname, iconfig, creds_ref in rules:
            match = match if isinstance(match, dict) else {}
            if not rule_wants(match, DIGEST_EVENT) or itype not in DIGEST_TYPES:
                continue
            if iid in seen_integrations:
                continue                      # two rules on one hook = one digest, not two
            seen_integrations.add(iid)
            try:
                merged = runtime_config(iconfig or {}, resolve_secrets(cur, creds_ref))
                deliver(itype, merged, event, client=client)
                status, err = "sent", None
            except Exception as e:
                status, err = "error", safe_error(e)
                log.warning("digest: %s/%s failed for tenant %s: %s", itype, iname, tenant_id, err)
            delivered_to.append({"integration_id": iid, "name": iname, "type": itype,
                                 "rule_id": rule_id, "status": status, "error": err})

        cur.execute(
            """/* digest:insert */
               insert into digests (tenant_id, period_start, period_end, delivered_to, summary)
               values (%s,%s,%s,%s,%s) returning id::text""",
            (tenant_id, since_dt, until_dt, json.dumps(delivered_to, default=str),
             json.dumps(digest, default=str)),
        )
        row = cur.fetchone()
        digest_id = row[0] if row else None
    if not getattr(conn, "autocommit", False):
        conn.commit()
    return {"id": digest_id, "digest": digest, "delivered_to": delivered_to}


def list_digests(cur, tenant_id: str, limit: int = 12) -> list[dict]:
    cur.execute(
        """/* digest:list */
           select id::text, period_start, period_end, delivered_to, summary, created_at
             from digests where tenant_id = %s order by created_at desc limit %s""",
        (tenant_id, limit),
    )
    return [{"id": r[0], "period_start": _iso(r[1]), "period_end": _iso(r[2]),
             "delivered_to": r[3] or [], "summary": r[4] or {}, "created_at": _iso(r[5])}
            for r in cur.fetchall()]


def tenant_ids(cur) -> list[str]:
    cur.execute("/* digest:tenants */ select id::text from tenants order by created_at")
    return [r[0] for r in cur.fetchall()]


__all__ = ["compose_digest", "render_digest_text", "render_digest_slack", "send_digest",
           "list_digests", "tenant_ids", "DIGEST_EVENT", "DIGEST_TYPES"]
