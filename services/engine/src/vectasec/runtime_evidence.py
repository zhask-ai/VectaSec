"""Windowed runtime evidence — the only place allowed to reason about ABSENCE.

Two jobs, both run after a scan persists:

  1. RECORD. Fold this scan's `runtime_client` resources into `runtime_evidence`, so the
     product accumulates "we saw principal P using connection C" across time.
  2. REASON. Compare the identities and grants a connection DECLARES against the principals
     actually seen, and report the ones never observed — but only once the observation window
     is long enough for that silence to mean anything.

The second job is the valuable one and the easy one to get wrong. Market research says no
competitor makes a windowed negative-evidence claim at this layer, and the reason is that it is
epistemically hard: a principal we never saw might be idle, might run quarterly, might have
been busy during an outage in our own collector. So this module refuses to make the claim
cheaply. It requires:

  * a window that actually elapsed (`MIN_WINDOW_DAYS` since observation began on THAT
    connection, not since the tenant signed up), and
  * a minimum number of scans that actually looked (`MIN_SCANS`), so a window with one
    successful scan in it cannot masquerade as continuous coverage,

and when either is missing it files a NOT-ASSESSABLE finding that says so. Everything it emits
states the window and the sample count inline, because "unused" without "over what period,
sampled how often" is a claim a reader cannot check.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import NamedTuple

from .scan import _active_suppressions, _is_suppressed, fingerprint

# The claim "this has not been used" needs a window long enough to survive a weekly batch job.
MIN_WINDOW_DAYS = 14
# …and enough successful samples inside it that the silence is not just our own downtime.
MIN_SCANS = 20

RULE_UNUSED = "RUNTIME.GRANT.NEVER_OBSERVED"
RULE_UNUSED_TITLE = "Declared identity has never been observed in use"

# Kinds that represent "an identity that could be used", per connector. Compared against the
# principals runtime evidence actually saw.
_IDENTITY_KINDS = ("user", "redis_user", "identity")

# Which connector types can produce runtime evidence AT ALL, and what they read to get it.
#
# This is a CAPABILITY statement, deliberately separate from the empirical "has this connection
# ever produced a runtime_client" check below. The two answer different questions, and an empty
# evidence table renders them identically: a Kong connection has no live-client source in the
# product at all, while a Kafka connection with no consumer groups genuinely observed nothing.
# "Cannot see" and "saw nothing" are opposite claims, and a UI that shows one blank panel for
# both is telling the operator something false about their coverage.
#
# Each entry states the read AND its scope limit, because the limits are load-bearing: Kafka's
# consumer-group view cannot see producers, so "no clients observed" from Kafka never means
# "nothing is talking to this cluster".
#
# `attributes` is the load-bearing flag for RUNTIME.GRANT.NEVER_OBSERVED. It answers one narrow
# question — does this source name an AUTHENTICATED principal? — and only a source that does can
# support a claim of the form "identity X was never seen". Kafka's DescribeConsumerGroups
# reports a `client.id` that any client may assert freely; treating that as an identity would
# make both halves wrong (a session attributed to whoever claimed the name, and every real
# principal reported unused).
class RuntimeSource(NamedTuple):
    reads: str
    attributes: bool


RUNTIME_SOURCES: dict[str, RuntimeSource] = {
    "rabbitmq": RuntimeSource(
        "GET /api/connections — every live AMQP/management connection, with its "
        "principal, vhost, peer address, SASL mechanism and TLS state.", attributes=True),
    "redis": RuntimeSource(
        "CLIENT LIST + ACL LOG — connected clients and the ACL denials they triggered.",
        attributes=True),
    "nats": RuntimeSource(
        "GET /connz?auth=1 — live connections with their authenticated account.",
        attributes=True),
    "pgbouncer": RuntimeSource(
        "SHOW CLIENTS — every pooled client session and the user it authenticated as.",
        attributes=True),
    "kafka": RuntimeSource(
        "DescribeConsumerGroups — consumer group members only. Producers are invisible to "
        "this API, per-client transport is not reported, and the reported client.id is "
        "self-asserted rather than an authenticated identity.", attributes=False),
}


def runtime_source_for(connector_type: str) -> str | None:
    """What this connector type reads for runtime evidence, or None when it has no source.

    None is a real, publishable answer — "this system cannot tell us who is connected" is a
    coverage fact the operator needs, not a blank to be filled in later.
    """
    source = RUNTIME_SOURCES.get((connector_type or "").lower())
    return source.reads if source else None


def runtime_source_attributes(connector_type: str) -> bool | None:
    """Can this source attribute a session to an authenticated principal? None = no source.

    Declared here rather than inferred from the data on purpose. Inferring it — "have we ever
    seen a non-null principal on this connection?" — fails OPEN: one anomalous row (a manual
    insert, a connector that changes what it emits, evidence left behind by an older version)
    would re-enable an unused-identity claim on a source that can never support one. A guard
    against fabricated findings has to fail closed, so the capability is stated, not observed.
    """
    source = RUNTIME_SOURCES.get((connector_type or "").lower())
    return source.attributes if source else None


def record_runtime(conn, tenant_id: str, connection_id: str, scan_id: str) -> dict:
    """Fold this scan's runtime_client resources into the accumulating evidence table."""
    stats = {"clients": 0, "principals": 0}
    with conn.cursor() as cur:
        cur.execute(
            """select labels, raw from resources
                where tenant_id = %s and connection_id = %s and kind = 'runtime_client'
                  -- WITHOUT THIS the headline feature is dead on arrival: a principal that
                  -- connected once in March is re-upserted with last_seen=now() on every scan
                  -- forever, so assess_unused's "observed" set never shrinks and nothing is
                  -- ever reported as unused. Resources are marked stale, not deleted.
                  and coalesce(stale, false) = false""",
            (tenant_id, connection_id),
        )
        rows = cur.fetchall()

        # Stamp the start of observation the first time this connection produces runtime data.
        # Every later claim about silence is measured from here, never from an earlier date.
        cur.execute(
            """update connections
                  set runtime_observation_started_at = coalesce(
                        runtime_observation_started_at, now())
                where id = %s and %s > 0""",
            (connection_id, len(rows)),
        )

        principals: set[str] = set()
        for labels, raw in rows:
            labels, raw = labels or {}, raw or {}
            principal = raw.get("principal")
            source = str(labels.get("source") or raw.get("observed_via") or "unknown")
            peer = raw.get("peer_host")
            resource_ext = raw.get("vhost") or raw.get("server_ext")
            stats["clients"] += 1
            if principal:
                principals.add(str(principal))
            cur.execute(
                """insert into runtime_evidence
                     (tenant_id, connection_id, principal, resource_ext, source, peer_host,
                      detail)
                   values (%s,%s,%s,%s,%s,%s,%s)
                   on conflict (tenant_id, connection_id, coalesce(principal, ''),
                                coalesce(resource_ext, ''), source, coalesce(peer_host, ''))
                   do update set last_seen = now(),
                                 observed_scans = runtime_evidence.observed_scans + 1,
                                 detail = excluded.detail""",
                (tenant_id, connection_id, principal, resource_ext, source, peer,
                 json.dumps({"connections": raw.get("connections"),
                             "commands": raw.get("commands"),
                             "auth_mechanisms": raw.get("auth_mechanisms"),
                             "scan_id": str(scan_id)})),
            )
        stats["principals"] = len(principals)
    return stats


def _window(cur, connection_id: str) -> tuple[float | None, int]:
    """(days observed, successful scans) for this connection. Days is None when observation
    has not started — which is a different answer from zero days."""
    cur.execute(
        """select extract(epoch from (now() - runtime_observation_started_at)) / 86400.0
             from connections where id = %s""",
        (connection_id,),
    )
    row = cur.fetchone()
    days = float(row[0]) if row and row[0] is not None else None
    # Only scans that ran AFTER observation began could have seen anything. Counting every
    # completed scan since the connection was created lets a long history of pre-observation
    # scans masquerade as continuous coverage — exactly what MIN_SCANS exists to prevent.
    cur.execute(
        """select count(*) from scans s
             where s.connection_id = %s and s.status = 'done'
               and s.started_at >= (select c.runtime_observation_started_at
                                      from connections c where c.id = %s)""",
        (connection_id, connection_id),
    )
    scans = int((cur.fetchone() or [0])[0])
    return days, scans


def assess_unused(conn, tenant_id: str, connection_id: str, scan_id: str) -> dict:
    """Report declared identities that runtime evidence has never seen in use.

    Emits exactly one of two things per connection:
      * findings naming the never-observed identities, when the window justifies it, or
      * a single NOT-ASSESSABLE finding explaining why the window does not, so a young
        connection reads as "not yet known" instead of silently clean.
    """
    stats = {"declared": 0, "observed": 0, "never_observed": 0, "window_days": None,
             "assessable": False, "runtime_source": False, "runtime_capable": None}
    with conn.cursor() as cur:
        # Record the CAPABILITY separately from the observation, so a scan's stats can tell the
        # console which of the two silences this is. Without it, "Kong has no live-client API"
        # and "Kafka has one and saw nobody" both surface as an empty panel.
        cur.execute("select type from connections where id = %s", (connection_id,))
        ctype = (cur.fetchone() or [None])[0]
        stats["runtime_capable"] = runtime_source_for(ctype) is not None
        stats["connector_type"] = ctype

        # Only some connectors can observe runtime at all — see RUNTIME_SOURCES above. For Kong,
        # MCP and the rest, identity.py still derives `identity` resources, so without this
        # guard every one of those connections files "runtime observation has not started" on
        # EVERY scan, forever, with no path to ever becoming assessable. A finding nobody can
        # ever close is noise that teaches people to ignore the rule; silence is the honest
        # answer where no runtime source exists.
        cur.execute(
            """select exists (
                 select 1 from runtime_evidence
                  where tenant_id = %s and connection_id = %s
                 union all
                 select 1 from resources
                  where tenant_id = %s and connection_id = %s and kind = 'runtime_client')""",
            (tenant_id, connection_id, tenant_id, connection_id),
        )
        if not (cur.fetchone() or [False])[0]:
            return stats
        stats["runtime_source"] = True
        cur.execute(
            """select id, ext_id, kind, name from resources
                where tenant_id = %s and connection_id = %s and kind = any(%s)
                  and coalesce(stale, false) = false
                -- ORDER matters: the coverage-gap finding below is fingerprinted on
                -- declared[0].ext_id, and Postgres row order is not stable across scans. An
                -- unordered read mints a NEW open finding every scan, forever.
                order by ext_id""",
            (tenant_id, connection_id, list(_IDENTITY_KINDS)),
        )
        declared = cur.fetchall()
        if not declared:
            return stats
        stats["declared"] = len(declared)

        cur.execute(
            """select distinct principal from runtime_evidence
                where tenant_id = %s and connection_id = %s and principal is not null""",
            (tenant_id, connection_id),
        )
        observed = {str(r[0]).lower() for r in cur.fetchall()}
        stats["observed"] = len(observed)

        # ATTRIBUTABLE evidence is a stricter requirement than evidence, and the difference is
        # the whole claim. Kafka's DescribeConsumerGroups reports a self-asserted `client.id`,
        # never an authenticated principal, so a Kafka connection accumulates real runtime rows
        # whose `principal` is permanently NULL. Left unguarded, such a connection satisfies the
        # window and then reports EVERY declared ACL identity as "never observed in use" — a
        # confident claim built on a source that structurally cannot support it, about identities
        # that may well be in constant use. Where nothing is attributable, the honest output is
        # the coverage gap, not the accusation.
        #
        # TWO separate gates, because they are different facts with different remedies:
        #   * `can_attribute` is DECLARED (RUNTIME_SOURCES). It fails closed — no row in the
        #     evidence table can talk a non-attributing source into supporting the claim.
        #   * `attributable` is OBSERVED. It covers an attributing source that has genuinely not
        #     seen a principal yet, which is a gap that closes on its own.
        cur.execute(
            """select count(*) from runtime_evidence
                where tenant_id = %s and connection_id = %s""",
            (tenant_id, connection_id),
        )
        evidence_rows = int((cur.fetchone() or [0])[0])
        can_attribute = runtime_source_attributes(ctype)
        attributable = bool(observed) or evidence_rows == 0
        stats["source_attributes"] = can_attribute
        stats["attributable"] = attributable and can_attribute is not False

        supps = _active_suppressions(cur, tenant_id)
        days, scans = _window(cur, connection_id)
        stats["window_days"] = round(days, 1) if days is not None else None
        assessable = (stats["attributable"] and days is not None
                      and days >= MIN_WINDOW_DAYS and scans >= MIN_SCANS)
        stats["assessable"] = assessable

        never = [(rid, ext, kind, name) for rid, ext, kind, name in declared
                 if str(name).lower() not in observed]
        stats["never_observed"] = len(never) if assessable else 0

        if not assessable:
            # ONE honest gap, not N confident claims. Filed against the connection's own
            # identity set so it appears next to them in the console.
            rid, ext, _kind, _name = declared[0]
            # `structural` is the permanent kind: the API itself does not name a principal, so
            # no amount of watching converts this into evidence about an identity.
            structural = can_attribute is False
            if structural:
                why = (f"this connector's runtime source cannot attribute a session to an "
                       f"authenticated identity — {runtime_source_for(ctype) or 'the source'} "
                       f"So silence about a principal here is a property of the API, not "
                       f"evidence about that principal"
                       + (f" ({evidence_rows} client session(s) recorded, none attributable)"
                          if evidence_rows else ""))
            elif not attributable:
                why = (f"{evidence_rows} client session(s) have been recorded on this connection "
                       f"but none has yet named a principal, so there is nothing to compare the "
                       f"declared identities against")
            elif days is None:
                why = "runtime observation has not started on this connection"
            else:
                why = (f"the observation window is {days:.1f} day(s) over {scans} completed "
                       f"scan(s), short of the {MIN_WINDOW_DAYS}-day / {MIN_SCANS}-scan minimum")
            _write_finding(
                cur, tenant_id, scan_id, connection_id, rid, ext,
                severity="info",
                observation=(f"{len(declared)} declared identit(ies) on this connection; "
                             f"{len(observed)} distinct principal(s) have been observed in use. "
                             f"No unused-identity claim is made because {why}"),
                detail=("Absence of evidence is not evidence of absence. A principal that has "
                        "not been seen may simply run on a schedule longer than our window, or "
                        "during a period when collection was failing. This finding records the "
                        "coverage that exists so far, and nothing more."
                        + (" This particular gap does NOT close with time: the limit is what the "
                           "system's API discloses, not how long we have watched it."
                           if structural else "")),
                # Telling someone to keep scanning would be a lie where the ceiling is the API
                # itself — the gap would never close and the advice would never stop repeating.
                # Only the STRUCTURAL case gets that treatment: a source that can attribute and
                # simply has not yet is exactly the case where waiting is the right advice.
                remediation=(
                    ("Unused-identity analysis needs authenticated per-client attribution, which "
                     "this system's runtime API does not provide. To get it, enable an "
                     "authenticated listener whose audit or connection log names the principal "
                     "(for Kafka, broker authorizer logs), or review these identities against "
                     "the grants and ownership records instead.")
                    if structural else
                    ("Keep this connection scanning on a schedule. Once the window "
                     f"reaches {MIN_WINDOW_DAYS} days across {MIN_SCANS} scans, "
                     "never-observed identities will be reported individually.")),
                assessment="not_assessable",
                reason=why,
                extra={"declared": len(declared), "observed": len(observed),
                       "window_days": stats["window_days"], "scans": scans,
                       "source_attributes": can_attribute,
                       "evidence_rows": evidence_rows},
                supps=supps,
            )
            return stats

        for rid, ext, kind, name in never:
            _write_finding(
                cur, tenant_id, scan_id, connection_id, rid, ext,
                severity="medium",
                observation=(f"the identity {name!r} ({kind}) is declared on this connection "
                             f"but has not been observed in use in any of {scans} completed "
                             f"scans over {days:.0f} days; {len(observed)} other principal(s) "
                             f"were seen in that window"),
                detail=("An identity nobody uses is an identity nobody will notice being used. "
                        "This is sampled evidence, not metered: it means we never caught it "
                        "connected, across the window and sample count stated above. A "
                        "quarterly batch job could still be legitimate — check before removing."),
                remediation=(f"Confirm with the owning team that {name!r} is genuinely unused, "
                             "then disable it and remove its grants. If it is a scheduled job "
                             "that runs less often than the window, record that so the finding "
                             "can be accepted rather than re-raised."),
                assessment="assessed",
                reason=None,
                extra={"window_days": round(days, 1), "scans": scans,
                       "observed_principals": sorted(observed)[:20]},
                supps=supps, kind=kind,
            )
    return stats


def _write_finding(cur, tenant_id, scan_id, connection_id, resource_id, ext_id, *,
                   severity, observation, detail, remediation, assessment, reason, extra,
                   supps=None, kind="identity"):
    """One finding plus its citation, in the caller's transaction — same contract the scan
    spine keeps, so a finding can never exist without the evidence that justifies it."""
    # Without this the suppression UI is a no-op for this rule: _persist_scan re-evaluates
    # suppressions for every other rule on every scan, but this layer writes findings itself.
    suppressed = _is_suppressed(supps or [], RULE_UNUSED,
                                SimpleNamespace(ext_id=ext_id or "connection", kind=kind))
    fp = fingerprint(tenant_id, str(connection_id), RULE_UNUSED, ext_id or "connection")
    cur.execute(
        """insert into findings
             (tenant_id, scan_id, resource_id, rule_id, fingerprint, title, severity,
              status, remediation, detail, assessment, assessment_reason)
           values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           on conflict (tenant_id, fingerprint) do update
              set last_seen = now(), scan_id = excluded.scan_id,
                  severity = excluded.severity, detail = excluded.detail,
                  assessment = excluded.assessment,
                  assessment_reason = excluded.assessment_reason,
                      -- Status must be RE-EVALUATED here, not written on INSERT only. An
                      -- INSERT-only status runs once in a finding's life, so suppressing an
                      -- EXISTING finding did nothing (verified: it stayed 'open') and an
                      -- expires_at could never restore it. Same case expression as
                      -- _persist_scan, and for the same reason — it never overwrites a status
                      -- a HUMAN set (resolved/triaged/in_progress/accepted).
                      status = case
                        when excluded.status = 'suppressed'
                              and findings.status in ('open','suppressed') then 'suppressed'
                        when findings.status = 'suppressed'
                              and excluded.status <> 'suppressed' then 'open'
                        else findings.status
                      end
           returning id""",
        (tenant_id, scan_id, resource_id, RULE_UNUSED, fp, RULE_UNUSED_TITLE, severity,
         "suppressed" if suppressed else "open",
         remediation, detail, assessment, reason),
    )
    finding_id = cur.fetchone()[0]
    cur.execute(
        """insert into observations (tenant_id, finding_id, resource_id, claim, source_ref)
           values (%s,%s,%s,%s,%s)""",
        (tenant_id, finding_id, resource_id, observation,
         json.dumps({"rule_id": RULE_UNUSED, "resource": ext_id, "scan_id": str(scan_id),
                     "evidence_type": "runtime_window", **(extra or {})})),
    )
