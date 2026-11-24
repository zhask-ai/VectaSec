"""The Time machine: configuration history from scan snapshots.

`resources` holds only the latest state a scan returned. This module turns each scan into a
history entry by comparing what the connection looked like BEFORE the scan's upsert with what
the scan collected, and writing one `resource_changes` row per resource that was added, removed,
came back, or changed configuration (migration 20261123000001).

Three things are built on that table:

  record_changes()   called from both persist paths in scan.py, inside the scan transaction.
  as_of()            "what did this estate look like on a date": posture, open findings and
                     inventory size at that moment, and what has changed since.
  change_report()    the exportable access-and-change report (CSV / Markdown) for a reviewer
                     whose system has no usable audit log on the plan they pay for.

WHAT THIS IS NOT. A scanner that polls proves WHAT changed and the window it changed in (between
the last scan that saw the old state and the scan that saw the new one). It knows WHO only where
the system's API returns an author field. It is not the system's audit log and the report says
so in its own text — a security product must not let a reviewer assume more than it can prove.

NOISE. Raw payloads carry telemetry beside configuration (connection counts, last-used
timestamps, offsets). Diffing those would make a busy broker look like a changed one on every
scan, so `_is_volatile` drops them. The filter is a heuristic over key names; it errs towards
keeping a field, because a missed change is worse here than a noisy one. `updated_at` /
`modified_at` are deliberately KEPT: on systems where the scan cannot read the body of a
workflow, a moved `updated_at` is the only evidence that it was edited.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

__all__ = [
    "diff_resource", "load_previous", "record_changes", "as_of", "load_changes",
    "change_report", "to_changes_csv", "to_changes_markdown",
    "MAX_FIELDS", "MAX_VALUE_CHARS", "SKIP_KINDS",
]

MAX_FIELDS = 40          # changed fields stored per change row; field_count keeps the true total
MAX_VALUE_CHARS = 240    # a before/after value longer than this is truncated
MAX_DEPTH = 8
REPORT_MAX_CHANGES = 5000
AS_OF_MAX_FINDINGS = 5000
REDACTED = "[redacted]"

# Kinds that are observations of the moment, not configuration. Their coming and going is what
# runtime_evidence.py tracks; here it would drown the real changes.
SKIP_KINDS = frozenset({"runtime_client"})

# Same idea as the console's display-time mask (apps/web/.../inventory/_lib.ts): connectors are
# the real boundary and store no secret material, this is the last mile for one that forgets.
_SECRET_KEY = re.compile(
    r"(password|passwd|secret|token|credential|apikey|api_key|private_key|_key$|^key$|authorization|salt)",
    re.I)

_KEEP = re.compile(
    r"^(last_)?(updated|modified|changed|edited|rotated|rotation)(_at|_on|_time|_date)?$", re.I)
_VOLATILE = re.compile(
    r"^(last_|earliest_|latest_|days_|seconds_since|observed_|collected_|scanned_|fetched_|checked_)"
    r"|^(uptime|lag|idle_since|connect_time|server_time|timestamp|now|age|age_days|age_seconds)$"
    r"|_(uptime|lag|rate|age_days|age_seconds)$"
    r"|(^|_)(connection|consumer|client|message|msg|channel|session|subscriber|run|execution|task|"
    r"used_by|live_client|runtime_client)s?_count$"
    r"|^(connections|consumers|clients|channels|sessions|subscribers|offsets?|messages(_.*)?|"
    r"bytes|stats|metrics|message_stats|runtime_observed_via)$"
    r"|^(mem|memory|fd|sockets|proc|disk|cpu)_(used|free|alarm|usage).*$"
    r"|_(in|until|since)_days$|_days_(left|ago)$|(^|_)(bytes|msgs)_(in|out|total|ready)$",
    re.I)

_ACTOR_KEYS = ("updated_by", "modified_by", "last_modified_by", "changed_by", "last_editor",
               "updatedBy", "modifiedBy", "lastModifiedBy", "editor")
_CREATOR_KEYS = ("created_by", "creator", "createdBy", "author")


_META_KEYS = frozenset(_ACTOR_KEYS + _CREATOR_KEYS)


def _is_volatile(key: str) -> bool:
    if _KEEP.match(key):
        return False
    if key in _META_KEYS:
        # Who edited it is reported in the change row's `actor`, not as a changed field: an
        # author that differs while nothing else does is not a configuration change.
        return True
    return bool(_VOLATILE.search(key))


def _scalar(v: Any) -> bool:
    return v is None or isinstance(v, (str, int, float, bool))


def _clip(v: Any, key: str) -> Any:
    """A value fit to store: secret-looking strings masked, long values truncated."""
    if isinstance(v, str) and v and _SECRET_KEY.search(key or ""):
        return REDACTED
    if _scalar(v):
        if isinstance(v, str) and len(v) > MAX_VALUE_CHARS:
            return v[:MAX_VALUE_CHARS] + "… (truncated)"
        return v
    text = json.dumps(_mask(v, key), sort_keys=True, default=str)
    if len(text) > MAX_VALUE_CHARS:
        return text[:MAX_VALUE_CHARS] + "… (truncated)"
    return _mask(v, key)


def _mask(v: Any, key: str = "") -> Any:
    if isinstance(v, dict):
        return {k: _mask(x, str(k)) for k, x in v.items()}
    if isinstance(v, list):
        return [_mask(x, key) for x in v]
    if isinstance(v, str) and v and _SECRET_KEY.search(key or ""):
        return REDACTED
    return v


def _keyed(items: list) -> Optional[dict]:
    """A list of dicts as {identity: dict} when every element names itself the same way, so an
    element is compared with ITS earlier self rather than with whatever sat at the same index."""
    for field in ("id", "name", "ext_id", "key", "arn"):
        if all(isinstance(x, dict) and _scalar(x.get(field)) and x.get(field) is not None
               for x in items):
            out = {str(x[field]): x for x in items}
            if len(out) == len(items):
                return out
    return None


def _empty(v: Any) -> bool:
    return v is None or v == [] or v == {} or v == ""


def _diff(old: Any, new: Any, path: str, key: str, out: list, depth: int = 0,
          derived: bool = False) -> None:
    if old == new:
        return
    # "Not there" and "there but empty" are the same configuration. Without this, a connector
    # that starts collecting a new (empty) field marks every resource as modified.
    if _empty(old) and _empty(new):
        return
    if isinstance(old, dict) and isinstance(new, dict) and depth < MAX_DEPTH:
        for k in sorted(set(old) | set(new), key=str):
            ks = str(k)
            if _is_volatile(ks):
                continue
            # A key VectaSec itself derives that simply did not exist in the older record is a
            # newer engine computing more, not a change to the customer's system.
            if derived and k not in old:
                continue
            _diff(old.get(k), new.get(k), f"{path}.{ks}" if path else ks, ks, out, depth + 1, derived)
        return
    if isinstance(old, list) and isinstance(new, list):
        if all(_scalar(x) for x in old) and all(_scalar(x) for x in new):
            # Order is rarely meaningful in a collected list and often unstable; report the
            # membership change, and nothing at all for a pure reorder.
            so, sn = {json.dumps(x) for x in old}, {json.dumps(x) for x in new}
            if so == sn:
                return
            removed = sorted(json.loads(x) for x in so - sn) if so - sn else []
            added = sorted(json.loads(x) for x in sn - so) if sn - so else []
            secret = bool(_SECRET_KEY.search(key or ""))
            out.append({"path": path, "op": "set",
                        "before": [REDACTED] * len(removed) if secret else _clip(removed, ""),
                        "after": [REDACTED] * len(added) if secret else _clip(added, "")})
            return
        ko, kn = _keyed(old), _keyed(new)
        if ko is not None and kn is not None and depth < MAX_DEPTH:
            _diff(ko, kn, path, key, out, depth + 1)
            return
    before, after = _clip(old, key), _clip(new, key)
    if before == after == REDACTED:
        before, after = "[redacted: previous value]", "[redacted: new value]"
    out.append({"path": path, "before": before, "after": after})


DERIVED_KINDS = frozenset({"identity", "credential", "grant"})


def diff_resource(old_labels: Optional[dict], old_raw: Optional[dict],
                  new_labels: Optional[dict], new_raw: Optional[dict],
                  *, compare_raw: bool = True, derived_raw: bool = False) -> list[dict]:
    """Changed fields between two states of one resource as [{path, before, after}].

    Labels are compared under the `labels.` prefix. `compare_raw=False` is the collector path:
    raw configuration never leaves the customer's network, so only labels can be compared.
    """
    out: list[dict] = []
    # Labels are always VectaSec's own derivation; raw is the system's config, except for the
    # kinds VectaSec derives entirely (identity / credential / grant).
    _diff(old_labels or {}, new_labels or {}, "labels", "", out, derived=True)
    if compare_raw:
        _diff(old_raw or {}, new_raw or {}, "", "", out, derived=derived_raw)
    return out


def _actor(labels: Optional[dict], raw: Optional[dict], keys: Iterable[str]) -> Optional[str]:
    for src in (raw or {}, labels or {}):
        if not isinstance(src, dict):
            continue
        for k in keys:
            v = src.get(k)
            if isinstance(v, dict):
                v = v.get("email") or v.get("name") or v.get("id")
            if isinstance(v, (str, int)) and str(v).strip():
                return str(v)[:200]
    return None


# ── Recording (called from scan.py) ───────────────────────────────────────

def load_previous(cur, connection_id: str) -> dict:
    """ext_id -> the state the connection's resources are in BEFORE this scan overwrites them."""
    cur.execute(
        """select ext_id, id, kind, name, labels, raw, stale, last_seen
             from resources where connection_id = %s""",
        (connection_id,),
    )
    out: dict = {}
    for row in cur.fetchall() or []:
        if not row or len(row) < 8:
            continue
        ext_id, rid, kind, name, labels, raw, stale, last_seen = row[:8]
        out[ext_id] = {"id": rid, "kind": kind, "name": name, "labels": labels or {},
                       "raw": raw or {}, "stale": bool(stale), "last_seen": last_seen}
    return out


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)


def record_changes(cur, tenant_id: str, connection_id: str, scan_id: str, previous: dict,
                   current: Iterable[Any], ext_to_id: dict, *, compare_raw: bool = True) -> dict:
    """Write one resource_changes row per resource that differs from `previous`.

    `current` is the scan's resources — contracts.Resource objects or the collector's dicts.
    Returns counts for the scan's stats. A connection with no previous resources is a baseline:
    nothing is written, because "everything was added" is the inventory, not a change.
    """
    stats = {"added": 0, "removed": 0, "modified": 0, "returned": 0}
    if not previous:
        return {**stats, "baseline": True}

    prev_scan_at = max((p["last_seen"] for p in previous.values() if p.get("last_seen")),
                       default=None)

    def write(change, ext_id, kind, name, rid, fields, actor, prev_seen):
        cur.execute(
            """insert into resource_changes
                 (tenant_id, connection_id, resource_id, scan_id, kind, name, ext_id,
                  change, fields, field_count, actor, prev_seen_at)
               values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (tenant_id, connection_id, rid, scan_id, kind, name, ext_id, change,
             json.dumps(fields[:MAX_FIELDS], default=str), len(fields), actor, prev_seen),
        )
        stats[change] += 1

    seen: set = set()
    for r in current:
        ext_id, kind = _attr(r, "ext_id"), _attr(r, "kind")
        if ext_id is None or kind in SKIP_KINDS:
            if ext_id is not None:
                seen.add(ext_id)
            continue
        seen.add(ext_id)
        name = _attr(r, "name") or ext_id
        labels, raw = _attr(r, "labels") or {}, _attr(r, "raw") or {}
        rid = ext_to_id.get(ext_id)
        prev = previous.get(ext_id)
        if prev is None:
            write("added", ext_id, kind, name, rid, [],
                  _actor(labels, raw, _CREATOR_KEYS + _ACTOR_KEYS), prev_scan_at)
            continue
        fields = diff_resource(prev["labels"], prev["raw"], labels, raw, compare_raw=compare_raw,
                               derived_raw=kind in DERIVED_KINDS)
        if prev["stale"]:
            write("returned", ext_id, kind, name, rid, fields,
                  _actor(labels, raw, _ACTOR_KEYS), prev["last_seen"])
        elif fields:
            write("modified", ext_id, kind, name, rid, fields,
                  _actor(labels, raw, _ACTOR_KEYS), prev["last_seen"])

    for ext_id, prev in previous.items():
        if ext_id in seen or prev["stale"] or prev["kind"] in SKIP_KINDS:
            continue
        write("removed", ext_id, prev["kind"], prev["name"], prev["id"], [], None,
              prev["last_seen"])
    return stats


# ── Reading ───────────────────────────────────────────────────────────────

def _dt(value) -> Optional[datetime]:
    if value is None or isinstance(value, datetime):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    d = datetime.fromisoformat(text)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _iso(value) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


_SEVERITIES = ("critical", "high", "medium", "low", "info")
# Statuses that count as "still a problem" on the date asked about. Matches the Overview, which
# counts status='open'; triaged / in_progress are shown beside it rather than folded in.
_STATUS_EVENTS = ("finding.status", "finding.verified")


def _status_at(current: str, events: list[tuple], at: datetime) -> str:
    """A finding's status at `at`, replayed from the audit trail.

    events: (when, action, detail) ascending. The last status change at or before `at` decides;
    with none, the `from` of the first change after `at` is what it was before anyone touched
    it; with no change at all, the current status has always been the status.
    """
    last_before = None
    first_after = None
    for when, action, detail in events:
        if when <= at:
            last_before = (action, detail)
        elif first_after is None:
            first_after = (action, detail)
    if last_before is not None:
        action, detail = last_before
        return "resolved" if action == "finding.verified" else (detail or {}).get("to") or current
    if first_after is not None:
        action, detail = first_after
        prev = (detail or {}).get("previous_status" if action == "finding.verified" else "from")
        return prev or "open"
    return current


def as_of(cur, tenant_id: str, at) -> dict:
    """The estate as the scans had recorded it at `at`.

    Honest limits, all returned in `caveats` so the console can show them: the posture score is
    the nearest snapshot at or before the date (none before the first scan); finding status is
    replayed from the audit trail, so a suppression that came and went without a human status
    change is not replayed; inventory size counts resources first seen by then and not gone
    before then.
    """
    at = _dt(at)
    caveats: list[str] = []

    cur.execute("select min(started_at) from scans where tenant_id = %s and status = 'done'",
                (tenant_id,))
    row = cur.fetchone()
    first_scan = row[0] if row else None

    cur.execute(
        """select taken_at, score, critical_count, high_count, medium_count, low_count, findings_total
             from posture_snapshots where tenant_id = %s and taken_at <= %s
            order by taken_at desc limit 1""",
        (tenant_id, at),
    )
    row = cur.fetchone()
    posture = None
    if row:
        posture = {"taken_at": _iso(row[0]), "score": row[1], "critical": row[2], "high": row[3],
                   "medium": row[4], "low": row[5], "findings_total": row[6]}
    else:
        caveats.append("No posture snapshot exists at or before this date.")

    cur.execute(
        """select count(*) from resources
            where tenant_id = %s and first_seen <= %s and (not stale or last_seen >= %s)""",
        (tenant_id, at, at),
    )
    row = cur.fetchone()
    resources_total = int(row[0]) if row else 0

    cur.execute(
        """select f.id::text, f.rule_id, f.title, f.severity, f.status, f.first_seen,
                  r.name, c.name, c.type
             from findings f
             left join resources r on r.id = f.resource_id
             left join connections c on c.id = r.connection_id
            where f.tenant_id = %s and f.first_seen <= %s
            order by f.first_seen limit %s""",
        (tenant_id, at, AS_OF_MAX_FINDINGS + 1),
    )
    rows = cur.fetchall() or []
    if len(rows) > AS_OF_MAX_FINDINGS:
        rows = rows[:AS_OF_MAX_FINDINGS]
        caveats.append(f"More than {AS_OF_MAX_FINDINGS} findings existed; counts cover the oldest "
                       f"{AS_OF_MAX_FINDINGS}.")

    events: dict[str, list] = {}
    ids = [r[0] for r in rows]
    if ids:
        cur.execute(
            """select target, at, action, detail from audit_log
                where tenant_id = %s and action = any(%s) and target = any(%s)
                order by at""",
            (tenant_id, list(_STATUS_EVENTS), ids),
        )
        for target, when, action, detail in cur.fetchall() or []:
            events.setdefault(target, []).append((when, action, detail or {}))

    by_severity = {s: 0 for s in _SEVERITIES}
    by_status: dict[str, int] = {}
    open_then: list[dict] = []
    for fid, rule_id, title, severity, status, first_seen, rname, cname, ctype in rows:
        then = _status_at(status, events.get(fid, []), at)
        by_status[then] = by_status.get(then, 0) + 1
        if then != "open":
            continue
        by_severity[severity] = by_severity.get(severity, 0) + 1
        open_then.append({"id": fid, "rule_id": rule_id, "title": title, "severity": severity,
                          "status_now": status, "first_seen": _iso(first_seen),
                          "resource": rname, "connection": cname, "system": ctype})
    rank = {s: i for i, s in enumerate(_SEVERITIES)}
    open_then.sort(key=lambda f: (rank.get(f["severity"], 9), f["first_seen"] or ""))

    cur.execute(
        """select change, count(*) from resource_changes
            where tenant_id = %s and observed_at > %s group by change""",
        (tenant_id, at),
    )
    since = {"added": 0, "removed": 0, "modified": 0, "returned": 0}
    for change, n in cur.fetchall() or []:
        since[change] = int(n)

    if first_scan is not None and at < first_scan:
        caveats.append("This date is before the first completed scan; nothing was recorded yet.")
    caveats.append("Finding status is replayed from the audit trail; inventory and configuration "
                   "come from scans, so anything that changed and changed back between two scans "
                   "is not visible.")
    return {
        "at": _iso(at),
        "first_scan_at": _iso(first_scan),
        "posture": posture,
        "resources_total": resources_total,
        "open_by_severity": by_severity,
        "open_total": len(open_then),
        "status_counts": by_status,
        "open_findings": open_then[:200],
        "still_open_now": sum(1 for f in open_then if f["status_now"] == "open"),
        "changes_since": since,
        "caveats": caveats,
    }


def load_changes(cur, tenant_id: str, since, until, limit: int = REPORT_MAX_CHANGES) -> list[dict]:
    cur.execute(
        """select rc.observed_at, rc.prev_seen_at, c.type, c.name, rc.kind, rc.name, rc.ext_id,
                  rc.change, rc.fields, rc.field_count, rc.actor
             from resource_changes rc
             left join connections c on c.id = rc.connection_id
            where rc.tenant_id = %s and rc.observed_at > %s and rc.observed_at <= %s
            order by rc.observed_at desc limit %s""",
        (tenant_id, _dt(since), _dt(until), limit),
    )
    out = []
    for r in cur.fetchall() or []:
        out.append({"observed_at": _iso(r[0]), "prev_seen_at": _iso(r[1]), "system": r[2] or "",
                    "connection": r[3] or "", "kind": r[4], "name": r[5], "ext_id": r[6],
                    "change": r[7], "fields": r[8] or [], "field_count": int(r[9] or 0),
                    "actor": r[10]})
    return out


def change_report(cur, tenant_id: str, since, until) -> dict:
    """Everything the change report prints, for the window (since, until]."""
    since, until = _dt(since), _dt(until)
    changes = load_changes(cur, tenant_id, since, until, REPORT_MAX_CHANGES + 1)
    truncated = len(changes) > REPORT_MAX_CHANGES
    changes = changes[:REPORT_MAX_CHANGES]

    cur.execute(
        """select f.first_seen, f.severity, f.rule_id, f.title, f.status, r.name, c.name
             from findings f
             left join resources r on r.id = f.resource_id
             left join connections c on c.id = r.connection_id
            where f.tenant_id = %s and f.first_seen > %s and f.first_seen <= %s
            order by f.first_seen desc limit 2000""",
        (tenant_id, since, until),
    )
    opened = [{"first_seen": _iso(r[0]), "severity": r[1], "rule_id": r[2], "title": r[3],
               "status": r[4], "resource": r[5] or "", "connection": r[6] or ""}
              for r in cur.fetchall() or []]

    cur.execute(
        """select a.at, a.actor, a.action, a.detail, f.rule_id, f.title
             from audit_log a
             left join findings f on f.id::text = a.target and f.tenant_id = a.tenant_id
            where a.tenant_id = %s and a.action = any(%s) and a.at > %s and a.at <= %s
            order by a.at desc limit 2000""",
        (tenant_id, list(_STATUS_EVENTS), since, until),
    )
    status_changes = []
    for at, actor, action, detail, rule_id, title in cur.fetchall() or []:
        detail = detail or {}
        verified = action == "finding.verified"
        status_changes.append({
            "at": _iso(at), "actor": actor, "rule_id": rule_id or "", "title": title or "",
            "from": detail.get("previous_status" if verified else "from") or "",
            "to": "resolved (verified by rescan)" if verified else detail.get("to") or "",
            "note": detail.get("note") or ""})

    cur.execute(
        """select c.name, c.type, count(*), min(s.started_at), max(s.started_at)
             from scans s join connections c on c.id = s.connection_id
            where s.tenant_id = %s and s.status = 'done'
              and s.started_at > %s and s.started_at <= %s
            group by c.name, c.type order by c.name""",
        (tenant_id, since, until),
    )
    scans = [{"connection": r[0], "system": r[1], "scans": int(r[2]),
              "first": _iso(r[3]), "last": _iso(r[4])} for r in cur.fetchall() or []]

    cur.execute("select name from tenants where id = %s", (tenant_id,))
    row = cur.fetchone()
    counts = {"added": 0, "removed": 0, "modified": 0, "returned": 0}
    for c in changes:
        counts[c["change"]] = counts.get(c["change"], 0) + 1
    return {"tenant": row[0] if row else "VectaSec tenant", "since": _iso(since),
            "until": _iso(until), "changes": changes, "counts": counts, "truncated": truncated,
            "findings_opened": opened, "status_changes": status_changes, "scans": scans}


# ── Rendering ─────────────────────────────────────────────────────────────

SCOPE_NOTE = (
    "This report is built from scheduled read-only scans. It shows what changed and the two "
    "scans the change happened between. It names who made a change only where the system's "
    "API returns an author. It is not the system's own audit log: a change made and undone "
    "between two scans is not recorded.")


def _show(v: Any) -> str:
    if v is None:
        return "(not set)"
    if isinstance(v, str):
        return v
    return json.dumps(v, sort_keys=True, default=str)


_CSV_HEADER = ["observed_at", "previous_scan_at", "system", "connection", "kind", "resource",
               "change", "field", "before", "after", "changed_by"]


def to_changes_csv(report: dict) -> str:
    """One row per changed field; a change with no field detail (added / removed) is one row."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(_CSV_HEADER)
    for c in report["changes"]:
        base = [c["observed_at"], c["prev_seen_at"] or "", c["system"], c["connection"],
                c["kind"], c["name"], c["change"]]
        who = c["actor"] or "not exposed by the system"
        if not c["fields"]:
            w.writerow(base + ["", "", "", who])
        for f in c["fields"]:
            w.writerow(base + [f.get("path", ""), _show(f.get("before")), _show(f.get("after")), who])
    if report.get("truncated"):
        buf.write(f"# truncated at {REPORT_MAX_CHANGES} changes; narrow the window for the rest\n")
    return buf.getvalue()


def _cell(text: Any) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _day(iso: Optional[str]) -> str:
    return (iso or "")[:16].replace("T", " ")


def to_changes_markdown(report: dict, *, generated_at: str) -> str:
    c = report["counts"]
    lines = [
        f"# Access and change report: {report['tenant']}",
        "",
        f"Window: {_day(report['since'])} to {_day(report['until'])} (UTC). "
        f"Generated {_day(generated_at)} UTC by VectaSec.",
        "",
        f"> {SCOPE_NOTE}",
        "",
        "## Summary",
        "",
        f"- Configuration changes recorded: {len(report['changes'])} "
        f"({c['modified']} modified, {c['added']} added, {c['removed']} removed, "
        f"{c['returned']} returned)",
        f"- Findings opened in the window: {len(report['findings_opened'])}",
        f"- Finding status changes in the window: {len(report['status_changes'])}",
        "",
        "## Scan coverage",
        "",
    ]
    if report["scans"]:
        lines += ["| Connection | System | Completed scans | First | Last |", "|---|---|---|---|---|"]
        lines += [f"| {_cell(s['connection'])} | {_cell(s['system'])} | {s['scans']} | "
                  f"{_day(s['first'])} | {_day(s['last'])} |" for s in report["scans"]]
    else:
        lines.append("No scan completed in this window, so no change could have been recorded.")

    lines += ["", "## Configuration changes", ""]
    if not report["changes"]:
        lines.append("No configuration change was recorded in this window.")
    for ch in report["changes"]:
        who = ch["actor"] or "not exposed by the system"
        lines += [
            f"### {ch['change'].capitalize()}: {ch['name']} ({ch['kind']})",
            "",
            f"- Connection: {ch['connection']} ({ch['system']})",
            f"- Seen changed at: {_day(ch['observed_at'])}",
            f"- Previous state last seen: {_day(ch['prev_seen_at']) or 'unknown'}",
            f"- Changed by: {who}",
        ]
        if ch["fields"]:
            lines += ["", "| Field | Before | After |", "|---|---|---|"]
            lines += [f"| `{_cell(f.get('path', ''))}` | {_cell(_show(f.get('before')))} | "
                      f"{_cell(_show(f.get('after')))} |" for f in ch["fields"]]
            if ch["field_count"] > len(ch["fields"]):
                lines.append(f"\n{ch['field_count'] - len(ch['fields'])} more changed fields not shown.")
        lines.append("")
    if report.get("truncated"):
        lines.append(f"_Truncated at {REPORT_MAX_CHANGES} changes; narrow the window for the rest._")

    lines += ["", "## Findings opened", ""]
    if report["findings_opened"]:
        lines += ["| First seen | Severity | Rule | Resource | Connection | Status now |",
                  "|---|---|---|---|---|---|"]
        lines += [f"| {_day(f['first_seen'])} | {f['severity']} | `{_cell(f['rule_id'])}` | "
                  f"{_cell(f['resource'])} | {_cell(f['connection'])} | {f['status']} |"
                  for f in report["findings_opened"]]
    else:
        lines.append("No finding was first seen in this window.")

    lines += ["", "## Finding status changes", ""]
    if report["status_changes"]:
        lines += ["| When | By | Rule | From | To | Note |", "|---|---|---|---|---|---|"]
        lines += [f"| {_day(s['at'])} | {_cell(s['actor'])} | `{_cell(s['rule_id'])}` | "
                  f"{_cell(s['from'])} | {_cell(s['to'])} | {_cell(s['note'])} |"
                  for s in report["status_changes"]]
    else:
        lines.append("No finding changed status in this window.")
    return "\n".join(lines) + "\n"
