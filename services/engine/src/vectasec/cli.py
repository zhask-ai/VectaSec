"""`vectasec` CLI — the operator-facing entry point.

    vectasec connections                    # what is connected, how healthy
    vectasec connections add --type kafka --name prod --bootstrap b-1:9092
    vectasec connections test prod
    vectasec scan --connection prod         # rescan from the saved config
    vectasec scan --type kafka --bootstrap localhost:9092   # ad-hoc
    vectasec scans                          # scan history
    vectasec rules
    vectasec findings
    vectasec doctor
    vectasec worker
"""
import argparse
import json
import logging
import sys

from .config import load_env, settings
from .registry import CONNECTORS, CONNECTOR_FIELDS, DETECTORS, validate_config
from . import connect as _connect   # noqa: F401  — auto-register connectors
from . import detect as _detect     # noqa: F401  — auto-register detectors

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m",
             "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"
DIM = "\033[2m"


def _c(sev: str) -> str:
    return SEV_COLOR.get(sev, "")


def config_from_args(args) -> dict:
    """Assemble a connector config from CLI flags. Pure — unit-tested.

    The named flags cover every field a connector declares (registry.CONNECTOR_FIELDS);
    `--set key=value` covers the long tail (`timeout`, `verify_tls`, `active_probes`, …)
    without a flag per knob. Values stay strings; connectors coerce what they read."""
    config: dict = {}
    for flag, key in (("bootstrap", "bootstrap"), ("url", "url"), ("token", "token"),
                      ("admin_token", "admin_token"), ("username", "username"),
                      ("password", "password"), ("host", "host"), ("port", "port")):
        v = getattr(args, flag, None)
        if v:
            config[key] = v
    for pair in getattr(args, "set", None) or []:
        if "=" not in pair:
            raise SystemExit(f"--set expects key=value, got {pair!r}")
        k, v = pair.split("=", 1)
        config[k.strip()] = v
    return config


def _load_connection(cur, tenant: str, name: str, type_: str | None = None):
    """Resolve a saved connection by name (+type when the name is ambiguous).
    Returns (id, type, name, config, mode, creds_ref) or exits with the available names.
    config is the PUBLIC config — secret fields live in Vault behind creds_ref."""
    if type_:
        cur.execute("select id, type, name, config, mode, creds_ref from connections "
                    "where tenant_id=%s and name=%s and type=%s", (tenant, name, type_))
    else:
        cur.execute("select id, type, name, config, mode, creds_ref from connections "
                    "where tenant_id=%s and name=%s", (tenant, name))
    rows = cur.fetchall()
    if not rows:
        cur.execute("select type, name from connections where tenant_id=%s order by name", (tenant,))
        have = ", ".join(f"{t}/{n}" for t, n in cur.fetchall()) or "none"
        raise SystemExit(f"no connection named {name!r} (have: {have})")
    if len(rows) > 1:
        types = ", ".join(sorted(r[1] for r in rows))
        raise SystemExit(f"{name!r} exists for several types ({types}) — add --type")
    return rows[0]


def cmd_scan(args) -> int:
    from .scan import run_scan

    tenant = args.tenant or settings.demo_tenant

    if args.connection:
        # Rescan a saved connection: config (credentials included) comes from the DB, the
        # same rows the console and worker use — one source of truth for "how to reach it".
        from .db import connect
        with connect() as conn, conn.cursor() as cur:
            # The stored config is the public half; run_scan resolves creds_ref from Vault
            # itself, so no secret needs to round-trip through the CLI here.
            _, type_, name, config, _mode, _ref = _load_connection(cur, tenant, args.connection, args.type)
    else:
        if not args.type:
            raise SystemExit("pass --type for an ad-hoc scan, or --connection for a saved one")
        type_, name, config = args.type, args.name, config_from_args(args)

    print(f"{DIM}scanning {type_} ({config.get('bootstrap') or config.get('url') or name}){RESET}")
    stats = run_scan(type_, config, tenant_id=tenant, connection_name=name)

    print(f"\n  resources    {stats['resources']}")
    print(f"  edges        {stats['edges']}")
    print(f"  findings     {stats['findings']}"
          + (f" ({stats['suppressed']} suppressed)" if stats.get("suppressed") else ""))
    print(f"  observations {stats['observations']}")
    print(f"  detectors    {stats['detectors_run']} run in {stats['duration_ms']}ms")
    if stats.get("detector_errors"):
        print(f"\n  {SEV_COLOR['high']}detector errors:{RESET}")
        for e in stats["detector_errors"]:
            print(f"    {e}")
    print(f"\n{DIM}scan {stats['scan_id']}{RESET}")

    if args.json:
        print(json.dumps(stats, indent=2))
    return 0


def cmd_rules(args) -> int:
    """Show the loaded rulepack — the product's IP, so make it inspectable."""
    if not DETECTORS:
        print("no detectors registered")
        return 1
    by_prefix: dict[str, list] = {}
    for d in DETECTORS:
        by_prefix.setdefault(d.rule_id.split(".")[0], []).append(d)

    total = 0
    for prefix in sorted(by_prefix):
        ds = sorted(by_prefix[prefix], key=lambda d: (SEV_ORDER.get(d.severity, 9), d.rule_id))
        print(f"\n{prefix}  {DIM}({len(ds)} rules){RESET}")
        for d in ds:
            total += 1
            kinds = ",".join(d.kinds)
            print(f"  {_c(d.severity)}{d.severity:<8}{RESET} {d.rule_id:<38} {DIM}{kinds:<14}{RESET} {d.title}")
    print(f"\n{DIM}{total} rules across {len(by_prefix)} systems · {len(CONNECTORS)} connectors: "
          f"{', '.join(sorted(CONNECTORS))}{RESET}")
    return 0


def cmd_findings(args) -> int:
    from .db import connect

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select f.severity, f.rule_id, f.title, f.status, r.name, r.kind,
                      (select count(*) from observations o where o.finding_id = f.id)
               from findings f left join resources r on r.id = f.resource_id
               where f.tenant_id = %s
               order by case f.severity when 'critical' then 0 when 'high' then 1
                                        when 'medium' then 2 when 'low' then 3 else 4 end,
                        f.rule_id""",
            (tenant,),
        )
        rows = cur.fetchall()

    if not rows:
        print("no findings — run `vectasec scan` first")
        return 0

    print(f"\n{len(rows)} findings\n")
    for sev, rule, title, status, rname, rkind, nobs in rows:
        st = "" if status == "open" else f" {DIM}[{status}]{RESET}"
        tgt = f"{rkind}/{rname}" if rname else "-"
        print(f"  {_c(sev)}{sev:<8}{RESET} {rule:<36} {DIM}{tgt:<24}{RESET} {title}{st}"
              f"  {DIM}({nobs} evidence){RESET}")

    counts: dict[str, int] = {}
    for r in rows:
        counts[r[0]] = counts.get(r[0], 0) + 1
    summary = "  ".join(f"{_c(s)}{counts[s]} {s}{RESET}"
                        for s in sorted(counts, key=lambda x: SEV_ORDER.get(x, 9)))
    print(f"\n  {summary}\n")
    return 0


def _fmt_ts(ts) -> str:
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "never"


def cmd_connections_list(args) -> int:
    """The estate: every connected system, its health, and what scanning it has produced."""
    from .db import connect

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select c.type, c.name, c.mode, c.status, c.last_scanned_at,
                      (select count(*) from resources r where r.connection_id = c.id),
                      (select count(*) from findings f join resources r on r.id = f.resource_id
                        where r.connection_id = c.id and f.status = 'open'),
                      (select s.status from scans s where s.connection_id = c.id
                        order by s.started_at desc limit 1)
               from connections c where c.tenant_id = %s order by c.name""",
            (tenant,),
        )
        rows = cur.fetchall()

    if not rows:
        print("no connections — `vectasec connections add --type kafka --name dev "
              "--bootstrap localhost:9092`, or connect one in the console")
        return 0

    print(f"\n{len(rows)} connection(s)\n")
    print(f"  {'TYPE':<10} {'NAME':<24} {'MODE':<10} {'STATUS':<8} {'LAST SCAN':<18} "
          f"{'RESOURCES':>9}  {'OPEN':>4}")
    for type_, name, mode, status, last, n_res, n_open, scan_status in rows:
        st = scan_status or status
        col = SEV_COLOR["high"] if st == "error" else (SEV_COLOR["medium"] if st in ("queued", "running") else "")
        open_col = SEV_COLOR["high"] if n_open else DIM
        print(f"  {type_:<10} {name:<24} {mode:<10} {col}{st:<8}{RESET} "
              f"{_fmt_ts(last):<18} {n_res:>9}  {open_col}{n_open:>4}{RESET}")
    print(f"\n{DIM}scan one: vectasec scan --connection <name>{RESET}\n")
    return 0


def cmd_connections_add(args) -> int:
    """Save a connection without scanning it. Same validation the console form gets."""
    from .db import connect
    from .scan import ensure_connection_with_creds

    config = config_from_args(args)
    problems = validate_config(args.type, config)
    if problems:
        for p in problems:
            print(f"  {SEV_COLOR['high']}{p}{RESET}")
        fields = ", ".join(f"--{f.key.replace('_', '-')}" if f.key in
                           ("bootstrap", "url", "token", "admin_token", "username", "password")
                           else f"--set {f.key}=…" for f in CONNECTOR_FIELDS.get(args.type, []))
        if fields:
            print(f"\n{DIM}{args.type} takes: {fields}{RESET}")
        return 1

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cur.execute("select id from connections where tenant_id=%s and type=%s and name=%s",
                        (tenant, args.type, args.name))
            existed = cur.fetchone() is not None
            # Declared-secret fields go to Vault (creds_ref); config keeps metadata only.
            cid, _public, _ref = ensure_connection_with_creds(
                cur, tenant, args.type, args.name, config, mode=args.mode)
            # Keys only, never values — config carries credentials, audit_log is append-only.
            cur.execute(
                """insert into audit_log (tenant_id, actor, action, target, detail)
                   values (%s,'cli',%s,%s,%s)""",
                (tenant, "connection.updated" if existed else "connection.created", str(cid),
                 json.dumps({"type": args.type, "name": args.name, "mode": args.mode,
                             "config_keys": sorted(config)})),
            )
        conn.commit()

    print(f"{'updated' if existed else 'created'} {args.type}/{args.name} ({cid})")
    print(f"{DIM}next: vectasec connections test {args.name}   ·   "
          f"vectasec scan --connection {args.name}{RESET}")
    return 0


def cmd_connections_test(args) -> int:
    """Run the connector against the saved config and say what a scan would see."""
    from .db import connect

    from .creds import resolve_secrets, runtime_config

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn, conn.cursor() as cur:
        cid, type_, name, config, _mode, creds_ref = _load_connection(cur, tenant, args.name, args.type)
        # Merge Vault secrets in memory only, for this one collect — never printed, never stored.
        config = runtime_config(config or {}, resolve_secrets(cur, creds_ref))

    print(f"{DIM}testing {type_}/{name}…{RESET}")
    try:
        collected = CONNECTORS[type_](config or {})
    except (Exception, SystemExit) as e:
        print(f"  {SEV_COLOR['high']}unreachable: {type(e).__name__}: {e}{RESET}")
        with connect() as conn, conn.cursor() as cur:
            cur.execute("update connections set status='error' where id=%s", (cid,))
            conn.commit()
        return 1

    kinds: dict[str, int] = {}
    for r in collected.resources:
        kinds[r.kind] = kinds.get(r.kind, 0) + 1
    print(f"  ok — {len(collected.resources)} resources "
          f"({', '.join(f'{n} {k}' for k, n in sorted(kinds.items()))})")
    with connect() as conn, conn.cursor() as cur:
        cur.execute("update connections set status='active' where id=%s", (cid,))
        conn.commit()
    return 0


def cmd_connections_rm(args) -> int:
    """Delete a connection and everything collected through it (scan history survives)."""
    from .db import connect

    from .creds import delete_secret

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn:
        conn.autocommit = False
        with conn.cursor() as cur:
            cid, type_, name, _config, _mode, creds_ref = _load_connection(cur, tenant, args.name, args.type)
            cur.execute("select count(*) from resources where connection_id=%s", (cid,))
            n_res = cur.fetchone()[0]
            cur.execute("""select count(*) from findings f join resources r on r.id=f.resource_id
                           where r.connection_id=%s""", (cid,))
            n_find = cur.fetchone()[0]

            if not args.yes:
                print(f"would delete {type_}/{name}: {n_res} resources, {n_find} findings "
                      f"(scan history is kept). Re-run with --yes.")
                conn.rollback()
                return 1

            cur.execute(
                """insert into audit_log (tenant_id, actor, action, target, detail)
                   values (%s,'cli','connection.deleted',%s,%s)""",
                (tenant, str(cid), json.dumps({"type": type_, "name": name,
                                               "resources": n_res, "findings": n_find})),
            )
            cur.execute("delete from connections where id=%s and tenant_id=%s", (cid, tenant))
            # The Vault secret goes with its connection — an orphaned credential is pure risk.
            delete_secret(cur, creds_ref)
        conn.commit()

    print(f"deleted {type_}/{name} ({n_res} resources, {n_find} findings)")
    return 0


def cmd_scans(args) -> int:
    """Scan history — the other half of "I clicked Scan now, what happened"."""
    from .db import connect

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """select s.id, coalesce(c.type, '-'), coalesce(c.name, '(deleted)'),
                      s.status, s.started_at, s.finished_at, s.stats
               from scans s left join connections c on c.id = s.connection_id
               where s.tenant_id = %s order by s.started_at desc limit %s""",
            (tenant, args.limit),
        )
        rows = cur.fetchall()

    if not rows:
        print("no scans yet — `vectasec scan --connection <name>` or Scan now in the console")
        return 0

    print(f"\n{len(rows)} scan(s)\n")
    for sid, type_, name, status, started, finished, stats in rows:
        stats = stats or {}
        dur = f"{stats.get('duration_ms')}ms" if stats.get("duration_ms") is not None else (
            "…" if status in ("queued", "running") else "-")
        col = {"error": SEV_COLOR["high"], "running": SEV_COLOR["medium"],
               "queued": DIM}.get(status, "")
        tail = (f"{stats.get('findings', '-')} findings · {stats.get('resources', '-')} resources"
                if status == "done" else (stats.get("error", "")[:60] if status == "error" else ""))
        print(f"  {col}{status:<8}{RESET} {type_ + '/' + name:<28} "
              f"{started.strftime('%m-%d %H:%M:%S'):<15} {dur:>8}  {DIM}{tail}{RESET}")
    print()
    return 0


def cmd_identities(args) -> int:
    """The non-human identity inventory — the same cross-system view the console's /identities
    page shows, from the normalized identity/credential/grant resources."""
    from .db import connect

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select ext_id, name, labels from resources where tenant_id=%s and kind='identity' order by name", (tenant,))
        identities = cur.fetchall()
        cur.execute("select labels->>'owner', labels->>'credential_type', labels->>'hashing', labels->>'default' from resources where tenant_id=%s and kind='credential'", (tenant,))
        creds = cur.fetchall()
        cur.execute("select labels->>'identity', labels->>'action', labels->>'wildcard' from resources where tenant_id=%s and kind='grant'", (tenant,))
        grants = cur.fetchall()

    if not identities:
        print("no non-human identities yet — scan a system with users/consumers/ACLs/OAuth")
        return 0

    creds_by, grants_by = {}, {}
    for owner, ctype, hashing, isdef in creds:
        creds_by.setdefault(owner, []).append((ctype, hashing, isdef))
    for ident, action, wild in grants:
        grants_by.setdefault(ident, []).append((action, wild == "true"))

    wildcard_total = sum(1 for _, _, w in grants for _ in [0] if w == "true")
    print(f"\n{len(identities)} non-human identit(y/ies) · {len(creds)} credentials · {len(grants)} grants "
          f"· {SEV_COLOR['high']}{wildcard_total} wildcard{RESET}\n")
    for ext_id, name, labels in identities:
        system = (labels or {}).get("system", "?")
        itype = (labels or {}).get("identity_type", "?")
        mycreds = creds_by.get(ext_id, [])
        mygrants = grants_by.get(ext_id, [])
        cred_s = ", ".join(f"{c}{'/'+h if h and h!='unknown' else ''}{' DEFAULT' if d=='true' else ''}"
                           for c, h, d in mycreds) or f"{DIM}none readable{RESET}"
        wild = sum(1 for _, w in mygrants if w)
        grant_s = f"{len(mygrants)} grant(s)" + (f" {SEV_COLOR['high']}({wild} wildcard){RESET}" if wild else "")
        print(f"  {name:<28} {DIM}{system:<10}{RESET} {itype:<16} {grant_s:<28} creds: {cred_s}")
    print()
    return 0


_SEV_WEIGHT = {"critical": 10.0, "high": 4.0, "medium": 1.5, "low": 0.5, "info": 0.0}


def cmd_posture(args) -> int:
    """The posture score — one number from open findings, plus the breakdown it came from.
    Same formula as the console (lib/posture.ts): weighted = 10·crit+4·high+1.5·med+0.5·low,
    score = round(100·(1 − weighted/(weighted+40)))."""
    from .db import connect

    tenant = args.tenant or settings.demo_tenant
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select severity, count(*) from findings where tenant_id=%s and status='open' group by severity", (tenant,))
        counts = {s: n for s, n in cur.fetchall()}
        cur.execute("select count(*) from findings where tenant_id=%s and status='open' and assessment='not_assessable'", (tenant,))
        not_assessable = cur.fetchone()[0]
        cur.execute("select count(*) from resources where tenant_id=%s and kind='identity'", (tenant,))
        n_ident = cur.fetchone()[0]
        cur.execute("select count(*) from resources where tenant_id=%s and kind='grant' and labels->>'wildcard'='true'", (tenant,))
        n_wild = cur.fetchone()[0]
        cur.execute("select count(*) from resources where tenant_id=%s and labels->>'data_sensitivity'='high'", (tenant,))
        n_sensitive = cur.fetchone()[0]

    weighted = sum(_SEV_WEIGHT.get(s, 0) * n for s, n in counts.items())
    score = 100 if weighted == 0 else max(1, round(100 * (1 - weighted / (weighted + 40))))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    total = sum(counts.values())

    print(f"\n  posture score  {SEV_COLOR['critical'] if grade in 'DF' else SEV_COLOR['medium'] if grade=='C' else SEV_COLOR['low']}{score}  {grade}{RESET}"
          f"   {DIM}from {total} open finding(s){RESET}\n")
    for s in ("critical", "high", "medium", "low", "info"):
        n = counts.get(s, 0)
        print(f"    {_c(s)}{s:<8}{RESET} {n}")
    print(f"\n  {DIM}coverage gaps (not assessable): {not_assessable}{RESET}")
    print(f"  {DIM}non-human identities: {n_ident}  ·  wildcard grants: {n_wild}  ·  "
          f"sensitive-data assets: {n_sensitive}{RESET}\n")
    return 0


def cmd_doctor(args) -> int:
    """Check the engine's wiring — the first thing to run when something is wrong."""
    ok = True

    print("engine")
    print(f"  connectors  {len(CONNECTORS)}  ({', '.join(sorted(CONNECTORS)) or 'none'})")
    print(f"  detectors   {len(DETECTORS)}")
    if not CONNECTORS or not DETECTORS:
        ok = False

    print("\ndatabase")
    if not settings.database_url:
        print("  DATABASE_URL not set (check .env)")
        return 1
    try:
        from .db import connect
        with connect() as conn, conn.cursor() as cur:
            cur.execute("select count(*) from information_schema.tables where table_schema='public'")
            print(f"  connected · {cur.fetchone()[0]} tables")
            cur.execute("select count(*) from findings")
            f = cur.fetchone()[0]
            cur.execute("select count(*) from observations")
            o = cur.fetchone()[0]
            cur.execute("select count(*) from resources")
            print(f"  {cur.fetchone()[0]} resources · {f} findings · {o} observations")
            cur.execute("select extname from pg_extension where extname in ('pgmq','pg_cron')")
            ext = sorted(r[0] for r in cur.fetchall())
            print(f"  extensions: {', '.join(ext) if ext else 'MISSING pgmq/pg_cron'}")
            if len(ext) < 2:
                ok = False

            # The #1 "why is my scan stuck" answer: jobs waiting with no worker draining them.
            print("\nscan queue")
            try:
                cur.execute("select queue_length from pgmq.metrics('vectasec_scans')")
                depth = cur.fetchone()[0]
                cur.execute("select count(*) filter (where status='queued'),"
                            "       count(*) filter (where status='running') from scans")
                n_q, n_r = cur.fetchone()
                print(f"  {depth} message(s) waiting · {n_q} scan(s) queued · {n_r} running")
                if depth or n_q:
                    print(f"  {DIM}a queued scan needs `vectasec worker` running to execute{RESET}")
            except Exception as e:
                print(f"  could not read queue: {type(e).__name__}: {e}")
                ok = False

            # The evidence ledger's tamper-evidence is worth exactly as much as somebody
            # checking it. The hash chain has existed since migration 006 and NOTHING has
            # ever called verify_ledger() — so the product has been claiming "tamper-evident"
            # on the strength of a function no code path invokes (STATUS.md gap 4).
            #
            # Opt-in via --verify-ledger because it walks every hashed observation: cheap on a
            # demo tenant, a full table scan on a real one. `doctor` must stay fast enough that
            # people actually run it.
            if getattr(args, "verify_ledger", False):
                print("\nevidence ledger")
                try:
                    cur.execute("select count(*) from observations where row_hash is not null")
                    hashed = cur.fetchone()[0]
                    cur.execute("select finding_id, observation_id, reason from verify_ledger()")
                    breaks = cur.fetchall()
                    if breaks:
                        # A tamper report is not a warning. Print every row: the whole point is
                        # that someone can act on exactly which claim was rewritten.
                        print(f"  {len(breaks)} TAMPER(S) DETECTED across {hashed} hashed "
                              "observation(s):")
                        for finding_id, obs_id, reason in breaks[:20]:
                            print(f"    finding {finding_id} · observation {obs_id} · {reason}")
                        if len(breaks) > 20:
                            print(f"    … and {len(breaks) - 20} more")
                        ok = False
                    else:
                        print(f"  chain intact · {hashed} hashed observation(s) verified")
                        if hashed == 0:
                            print(f"  {DIM}nothing to verify yet: no observation carries a "
                                  f"hash{RESET}")
                except Exception as e:
                    print(f"  could not verify: {type(e).__name__}: {e}")
                    ok = False
            else:
                print(f"\n{DIM}evidence ledger not checked — run with --verify-ledger to "
                      f"recompute the hash chain{RESET}")
    except Exception as e:
        print(f"  FAILED: {type(e).__name__}: {e}")
        ok = False

    print(f"\n{'ok' if ok else 'PROBLEMS FOUND'}")
    return 0 if ok else 1


def cmd_worker(args) -> int:
    """Drain the pgmq scan queue: adopt each queued scan and run it (STATUS.md gaps 0, 2).

    A long-running process, so it logs (to stderr) rather than printing to a console someone is
    reading interactively. `--once` drains and exits (tests/CI); `--reap-only` just ages out
    stuck 'running' scans and exits.
    """
    from .worker import run_worker

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run_worker(once=args.once, reap_only=args.reap_only)
    return 0


def main() -> int:
    # Here and not at import: an operator running `vectasec` opts into the ambient `.env`; a
    # process that merely imports vectasec (the collector, for fingerprint()) does not. See
    # config.py.
    load_env()

    p = argparse.ArgumentParser(prog="vectasec", description="VectaSec engine — integration-layer security posture")
    sub = p.add_subparsers(dest="cmd", required=True)

    def config_flags(sp) -> None:
        sp.add_argument("--bootstrap", help="kafka bootstrap servers")
        sp.add_argument("--url", help="base url (kong/rabbitmq/mcp)")
        sp.add_argument("--host", help="host (redis)")
        sp.add_argument("--port", help="port (redis)")
        sp.add_argument("--token", help="bearer token (mcp)")
        sp.add_argument("--admin-token", dest="admin_token", help="admin token (kong)")
        sp.add_argument("--username")
        sp.add_argument("--password")
        sp.add_argument("--set", action="append", metavar="KEY=VALUE",
                        help="extra config (timeout=30, verify_tls=false, …); repeatable")

    s = sub.add_parser("scan", help="scan a system — saved connection or ad-hoc")
    s.add_argument("--connection", help="scan a SAVED connection by name (config from the DB)")
    s.add_argument("--type", help=f"connector type ({', '.join(sorted(CONNECTORS)) or 'none loaded'})")
    config_flags(s)
    s.add_argument("--tenant", help="tenant uuid (defaults to demo tenant)")
    s.add_argument("--name", help="connection name for an ad-hoc scan")
    s.add_argument("--json", action="store_true", help="print stats as json")
    s.set_defaults(fn=cmd_scan)

    c = sub.add_parser("connections", help="list, add, test or remove connections")
    c.add_argument("--tenant", help="tenant uuid (defaults to demo tenant)")
    c.set_defaults(fn=cmd_connections_list)
    csub = c.add_subparsers(dest="subcmd")

    cl = csub.add_parser("list", help="list connections (the default)")
    cl.add_argument("--tenant")
    cl.set_defaults(fn=cmd_connections_list)

    ca = csub.add_parser("add", help="save a connection without scanning it")
    ca.add_argument("--type", required=True, help=f"({', '.join(sorted(CONNECTORS))})")
    ca.add_argument("--name", required=True, help="a name you'll recognise — 'prod-kafka'")
    ca.add_argument("--mode", choices=["cloud", "collector"], default="cloud",
                    help="cloud: the worker reaches it. collector: an enrolled collector does")
    config_flags(ca)
    ca.add_argument("--tenant")
    ca.set_defaults(fn=cmd_connections_add)

    ct = csub.add_parser("test", help="check a saved connection is reachable")
    ct.add_argument("name")
    ct.add_argument("--type", help="disambiguate when the name exists for several types")
    ct.add_argument("--tenant")
    ct.set_defaults(fn=cmd_connections_test)

    cr = csub.add_parser("rm", help="delete a connection and its collected data")
    cr.add_argument("name")
    cr.add_argument("--type", help="disambiguate when the name exists for several types")
    cr.add_argument("--yes", action="store_true", help="actually delete (otherwise: dry run)")
    cr.add_argument("--tenant")
    cr.set_defaults(fn=cmd_connections_rm)

    sc = sub.add_parser("scans", help="scan history")
    sc.add_argument("--limit", type=int, default=20)
    sc.add_argument("--tenant")
    sc.set_defaults(fn=cmd_scans)

    idc = sub.add_parser("identities", help="non-human identity inventory (NHI)")
    idc.add_argument("--tenant")
    idc.set_defaults(fn=cmd_identities)

    po = sub.add_parser("posture", help="posture score + severity breakdown")
    po.add_argument("--tenant")
    po.set_defaults(fn=cmd_posture)

    r = sub.add_parser("rules", help="list the loaded rulepack")
    r.set_defaults(fn=cmd_rules)

    f = sub.add_parser("findings", help="list findings for a tenant")
    f.add_argument("--tenant")
    f.set_defaults(fn=cmd_findings)

    d = sub.add_parser("doctor", help="check engine wiring")
    d.add_argument("--verify-ledger", action="store_true",
                   help="recompute the evidence hash chain (verify_ledger). Walks every hashed "
                        "observation, so it is off by default — run it before telling anyone "
                        "the ledger is tamper-evident.")
    d.set_defaults(fn=cmd_doctor)

    w = sub.add_parser("worker", help="drain the scan queue (pgmq vectasec_scans) and reap stuck scans")
    w.add_argument("--once", action="store_true", help="drain the queue then exit (for tests/CI)")
    w.add_argument("--reap-only", action="store_true",
                   help="only age out stuck 'running' scans, then exit (touch no queue message)")
    w.set_defaults(fn=cmd_worker)

    args = p.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
