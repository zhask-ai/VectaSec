"""`vectasec` CLI — the operator-facing entry point.

    vectasec scan --type kafka --bootstrap localhost:9092
    vectasec rules
    vectasec findings
    vectasec doctor
"""
import argparse
import json
import logging
import sys

from .config import load_env, settings
from .registry import CONNECTORS, DETECTORS
from . import connect as _connect   # noqa: F401  — auto-register connectors
from . import detect as _detect     # noqa: F401  — auto-register detectors

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR = {"critical": "\033[1;91m", "high": "\033[91m", "medium": "\033[93m",
             "low": "\033[94m", "info": "\033[90m"}
RESET = "\033[0m"
DIM = "\033[2m"


def _c(sev: str) -> str:
    return SEV_COLOR.get(sev, "")


def cmd_scan(args) -> int:
    from .scan import run_scan

    config: dict = {}
    if args.bootstrap:
        config["bootstrap"] = args.bootstrap
    if args.url:
        config["url"] = args.url
    if args.token:
        config["token"] = args.token
    if args.username:
        config["username"] = args.username
    if args.password:
        config["password"] = args.password

    print(f"{DIM}scanning {args.type} ({config.get('bootstrap') or config.get('url')}){RESET}")
    stats = run_scan(args.type, config, tenant_id=args.tenant, connection_name=args.name)

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

    s = sub.add_parser("scan", help="scan a connected system")
    s.add_argument("--type", required=True, help=f"connector type ({', '.join(sorted(CONNECTORS)) or 'none loaded'})")
    s.add_argument("--bootstrap", help="kafka bootstrap servers")
    s.add_argument("--url", help="base url (kong/rabbitmq/mcp)")
    s.add_argument("--token", help="bearer token")
    s.add_argument("--username")
    s.add_argument("--password")
    s.add_argument("--tenant", help="tenant uuid (defaults to demo tenant)")
    s.add_argument("--name", help="connection name")
    s.add_argument("--json", action="store_true", help="print stats as json")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("rules", help="list the loaded rulepack")
    r.set_defaults(fn=cmd_rules)

    f = sub.add_parser("findings", help="list findings for a tenant")
    f.add_argument("--tenant")
    f.set_defaults(fn=cmd_findings)

    d = sub.add_parser("doctor", help="check engine wiring")
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
