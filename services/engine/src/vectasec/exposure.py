"""Free external exposure scan — the top-of-funnel product (strategy §2 "Free entry", §4 item 5).

A stranger enters a domain or an IP range, proves they own it, and gets a PUBLIC-SAFE report of
the middleware reachable from the internet: brokers, gateways, admin UIs, with CVE and EOL facts
attached. No credentials are ever asked for or sent — the probing is the `discovery` connector's
pre-auth fingerprinting (`discover/probes.py`), pointed outward.

Three disciplines, each enforced in this module rather than in the router:

  1. OWNERSHIP IS THE GATE. Nothing is probed until a DNS TXT record proves control of the
     domain, or every IP in a range resolves back to a verified domain. The discovery guardrail
     refuses public address space by default for exactly this reason (`targets.py` rule 2); the
     exposure scan is the one caller allowed to pass `allow_public=True`, and only because this
     module has already checked ownership.
  2. PUBLIC-SAFE OUTPUT. The report carries product, version, port, transport, an auth verdict,
     short evidence strings, and CVE/EOL facts. Never a full banner, never a credential, never
     a probe's raw payload. The report is designed to be forwarded to a stranger's CTO.
  3. BOUNDED. At most 32 hosts for a domain, /24 for a range, a hard wall-clock budget, and the
     connector's own middleware port set — this is not a port scanner.

Everything that can be pure is pure: the resolver and the sweep are injected so every branch
is testable without a network. The default resolver is stdlib-only (dnspython is not a
dependency of this engine and one TXT lookup does not justify adding it).
"""
from __future__ import annotations

import ipaddress
import os
import random
import re
import secrets
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FutTimeout
from datetime import date, datetime, timezone
from typing import Callable, Optional

from .cve_data import cves_for_product
from .detect.cve import _affected_fix, _parse_version
from .discover import resolve_scope, sweep as _real_sweep
from .discover.targets import DEFAULT_PORTS, Target
from .lifecycle import APPROACHING, END_OF_LIFE, SUPPORTED, support_status

# ── Constants ──────────────────────────────────────────────────────────────
TXT_PREFIX = "vectasec-verify="
VERIFY_SUBDOMAIN = "_vectasec"

# Hostnames where self-hosted middleware tends to live. Probed in addition to the apex, because
# "we only have a website" is the sentence that precedes finding rabbitmq.example.com on 15672.
MIDDLEWARE_HOSTNAMES: tuple[str, ...] = (
    "kafka", "broker", "mq", "rabbitmq", "redis", "api", "gateway", "kong",
    "n8n", "mcp", "admin", "queue", "events",
)
MAX_HOSTS = 32                 # a domain expands to at most this many addresses
MAX_CIDR_HOSTS = 256           # /24 — anything larger is a range that deserves a conversation
MAX_EVIDENCE_LEN = 120
MAX_EVIDENCE_ITEMS = 6
MAX_CVES = 5
SWEEP_MAX_WORKERS = 64

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
                          r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# Evidence strings that smell like a secret are dropped rather than truncated: a probe never
# sends credentials, but a service's own banner might echo a config line, and a public report
# is the wrong place to find out.
_SECRET_RE = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization)\s*[:=]",
                        re.IGNORECASE)

Resolver = Callable[[str, str], list[str]]   # (name, rtype in A|AAAA|TXT|PTR) -> values


# ── Tokens ─────────────────────────────────────────────────────────────────
def issue_token() -> str:
    """A URL-safe verification token: 32 random bytes, so a TXT record cannot be guessed."""
    return secrets.token_urlsafe(32)


def txt_record_for(token: str) -> str:
    return f"{TXT_PREFIX}{token}"


# ── Name normalisation / validation ────────────────────────────────────────
def normalize_domain(value: str) -> str:
    """Lower-case, no trailing dot, must look like a public hostname with at least one dot.
    Raises ValueError with a reason the user can act on."""
    d = str(value or "").strip().lower().rstrip(".")
    if not d:
        raise ValueError("domain is empty")
    try:
        ipaddress.ip_address(d)
    except ValueError:
        pass
    else:
        raise ValueError("that is an IP address — submit it with kind 'ip'")
    if not _HOSTNAME_RE.match(d):
        raise ValueError(f"{d!r} is not a valid domain name")
    return d


def normalize_ip_or_cidr(kind: str, value: str) -> str:
    """Validate an 'ip' or 'cidr' target. Private, loopback, link-local and reserved space is
    rejected: an exposure scan runs from the internet, and those ranges are not on it."""
    v = str(value or "").strip()
    if not v:
        raise ValueError("value is empty")
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as e:
            raise ValueError(f"{v!r} is not a valid IP address ({e})") from e
        if not ip.is_global:
            raise ValueError(f"{v} is not a public address — the exposure scan only probes "
                             "what the internet can reach")
        return str(ip)
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"{v!r} is not a valid CIDR ({e})") from e
        if net.num_addresses > MAX_CIDR_HOSTS:
            raise ValueError(f"{net} expands to {net.num_addresses} addresses — the free scan "
                             f"accepts /24 or smaller (at most {MAX_CIDR_HOSTS}). Split it.")
        if not net.is_global:
            raise ValueError(f"{net} is not public address space — the exposure scan only "
                             "probes what the internet can reach")
        return str(net)
    raise ValueError(f"unknown target kind {kind!r}")


def _cidr_hosts(cidr: str) -> list[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > MAX_CIDR_HOSTS:
        raise ValueError(f"{net} is larger than /24 ({net.num_addresses} addresses)")
    return [str(a) for a in (list(net.hosts()) or [net.network_address])]


# ── Default resolver (stdlib only) ─────────────────────────────────────────
_QTYPE = {"A": 1, "PTR": 12, "TXT": 16, "AAAA": 28}
_CNAME = 5


def _nameservers() -> list[str]:
    env = os.environ.get("VECTASEC_DNS_SERVER")
    if env:
        return [s.strip() for s in env.split(",") if s.strip()]
    servers: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    servers.append(parts[1])
    except OSError:
        pass
    # Public resolvers as a last resort so a container without resolv.conf still verifies.
    return servers or ["1.1.1.1", "8.8.8.8"]


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna") if label else b""
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name. Returns (name, offset after the name)."""
    labels: list[str] = []
    jumped = False
    end = off
    hops = 0
    while True:
        if off >= len(msg):
            raise ValueError("truncated name")
        ln = msg[off]
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            if hops > 64:
                raise ValueError("compression loop")
            continue
        off += 1
        if ln == 0:
            if not jumped:
                end = off
            break
        labels.append(msg[off:off + ln].decode("ascii", "replace"))
        off += ln
    return ".".join(labels).lower(), end


def _parse_answers(msg: bytes, qtype: int) -> list[str]:
    if len(msg) < 12:
        return []
    _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if flags & 0x000F not in (0, 3):      # NOERROR or NXDOMAIN; anything else is a resolver fault
        raise OSError(f"dns rcode {flags & 0xF}")
    off = 12
    for _ in range(qd):
        _, off = _read_name(msg, off)
        off += 4
    values: list[str] = []
    for _ in range(an):
        _, off = _read_name(msg, off)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == qtype:
            if qtype == _QTYPE["TXT"]:
                i, chunks = 0, []
                while i < len(rdata):
                    n = rdata[i]
                    chunks.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
                    i += 1 + n
                values.append("".join(chunks))
            elif qtype == _QTYPE["A"] and len(rdata) == 4:
                values.append(socket.inet_ntop(socket.AF_INET, rdata))
            elif qtype == _QTYPE["AAAA"] and len(rdata) == 16:
                values.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif qtype == _QTYPE["PTR"]:
                values.append(_read_name(msg, off)[0])
        off += rdlen
    return values


def _dns_query(name: str, rtype: str, timeout: float = 3.0) -> list[str]:
    """One UDP question to the system resolver (TCP retry when truncated). Raises OSError when
    no server answers — the caller decides whether that is 'no record' or 'could not check'."""
    qtype = _QTYPE[rtype]
    qid = random.randint(0, 0xFFFF)
    query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode_name(name) + \
        struct.pack("!HH", qtype, 1)
    last: Exception | None = None
    for server in _nameservers():
        fam = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(query, (server, 53))
                msg, _ = s.recvfrom(4096)
            if len(msg) < 12 or struct.unpack("!H", msg[:2])[0] != qid:
                continue
            if struct.unpack("!H", msg[2:4])[0] & 0x0200:      # TC: retry over TCP
                with socket.create_connection((server, 53), timeout=timeout) as t:
                    t.sendall(struct.pack("!H", len(query)) + query)
                    hdr = t.recv(2)
                    ln = struct.unpack("!H", hdr)[0] if len(hdr) == 2 else 0
                    buf = b""
                    while len(buf) < ln:
                        chunk = t.recv(ln - len(buf))
                        if not chunk:
                            break
                        buf += chunk
                    msg = buf
            return _parse_answers(msg, qtype)
        except (OSError, ValueError, struct.error) as e:
            last = e
            continue
    raise OSError(f"no DNS server answered for {name} {rtype}: {last}")


def _ptr_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


def default_resolver(name: str, rtype: str) -> list[str]:
    """A/AAAA through getaddrinfo (CNAME chains, /etc/hosts); PTR through gethostbyaddr with
    a DNS fallback; TXT through the minimal DNS client. Missing records -> []."""
    rtype = rtype.upper()
    if rtype in ("A", "AAAA"):
        fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
        try:
            infos = socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        return sorted({i[4][0] for i in infos})
    if rtype == "PTR":
        try:
            host, aliases, _ = socket.gethostbyaddr(name)
            # The alias list echoes the reverse name itself (`8.8.8.8.in-addr.arpa`) on some
            # libc's; it is not a hostname anyone owns, so it never counts as a PTR match.
            names = [h.lower().rstrip(".") for h in [host, *aliases] if h]
            return [h for h in names if not h.endswith((".in-addr.arpa", ".ip6.arpa"))]
        except (socket.herror, socket.gaierror, OSError):
            pass
        try:
            return _dns_query(_ptr_name(name), "PTR")
        except (OSError, ValueError):
            return []
    if rtype == "TXT":
        try:
            return _dns_query(name, "TXT")
        except (OSError, ValueError):
            return []
    raise ValueError(f"unsupported record type {rtype}")


def _lookup(resolver: Optional[Resolver], name: str, rtype: str) -> list[str]:
    r = resolver or default_resolver
    try:
        return [str(v) for v in (r(name, rtype) or [])]
    except Exception:                     # noqa: BLE001 - a resolver fault is "no record", never a crash
        return []


# ── Ownership verification ─────────────────────────────────────────────────
def domain_lookups(domain: str) -> list[str]:
    """Where verify_domain looks, so the API can tell the user exactly what was checked."""
    d = domain.strip().lower().rstrip(".")
    return [f"TXT {d}", f"TXT {VERIFY_SUBDOMAIN}.{d}"]


def verify_domain(domain: str, token: str, resolver: Optional[Resolver] = None) -> tuple[bool, str]:
    """True when the exact `vectasec-verify=<token>` TXT string is published on the apex or on
    `_vectasec.<domain>`. Returns (ok, detail): the record that matched, or why nothing did."""
    d = domain.strip().lower().rstrip(".")
    want = txt_record_for(token)
    seen_any = False
    for name in (d, f"{VERIFY_SUBDOMAIN}.{d}"):
        values = _lookup(resolver, name, "TXT")
        for v in values:
            seen_any = True
            if v.strip().strip('"') == want:
                return True, f"TXT {name}"
    if seen_any:
        return False, (f"TXT records exist but none equals {TXT_PREFIX}<token> on {d} or "
                       f"{VERIFY_SUBDOMAIN}.{d}")
    return False, f"no TXT record found on {d} or {VERIFY_SUBDOMAIN}.{d}"


def _under(name: str, domain: str) -> bool:
    name, domain = name.lower().rstrip("."), domain.lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def verify_ip(ip_or_cidr: str, verified_domains: list[str],
              resolver: Optional[Resolver] = None) -> tuple[bool, str]:
    """An IP or range is owned when EVERY address either reverse-resolves (PTR) to a verified
    domain or appears in a verified domain's A/AAAA records (apex or a middleware hostname).

    Returns (ok, method-or-reason): 'ptr' | 'a_record' when owned (the method that settled the
    last address, with 'ptr' preferred), else a sentence naming the first unowned address.
    Ranges wider than /24 are rejected before any lookup.
    """
    domains = [d.strip().lower().rstrip(".") for d in verified_domains if d and d.strip()]
    if not domains:
        return False, "no verified domain on this tenant — verify a domain first, then its IPs"
    try:
        if "/" in ip_or_cidr:
            hosts = _cidr_hosts(ip_or_cidr)
        else:
            hosts = [str(ipaddress.ip_address(ip_or_cidr))]
    except ValueError as e:
        return False, str(e)

    # A/AAAA of each verified domain and its middleware hostnames, gathered lazily: one PTR
    # hit per address is the cheap path and most ranges never need the forward table.
    forward: set[str] | None = None

    def forward_table() -> set[str]:
        nonlocal forward
        if forward is None:
            forward = set()
            for d in domains:
                for host in (d, *(f"{h}.{d}" for h in MIDDLEWARE_HOSTNAMES)):
                    for rt in ("A", "AAAA"):
                        forward.update(_lookup(resolver, host, rt))
        return forward

    methods: set[str] = set()
    for ip in hosts:
        ptrs = _lookup(resolver, ip, "PTR")
        if any(_under(p, d) for p in ptrs for d in domains):
            methods.add("ptr")
            continue
        if ip in forward_table():
            methods.add("a_record")
            continue
        return False, (f"{ip} neither reverse-resolves to a verified domain nor appears in one's "
                       f"A/AAAA records (verified: {', '.join(domains)})")
    return True, ("ptr" if "ptr" in methods else "a_record")


# ── Target expansion ───────────────────────────────────────────────────────
def expand_targets(kind: str, value: str, resolver: Optional[Resolver] = None) -> list[str]:
    """What the sweep will contact for one verified target: IP addresses only, deduplicated,
    capped. A domain expands to the A/AAAA of its apex plus the common middleware hostnames;
    a CIDR to its hosts; an IP to itself."""
    if kind == "ip":
        return [str(ipaddress.ip_address(value))]
    if kind == "cidr":
        return _cidr_hosts(value)
    if kind != "domain":
        raise ValueError(f"unknown target kind {kind!r}")

    d = value.strip().lower().rstrip(".")
    out: list[str] = []
    seen: set[str] = set()
    for host in (d, *(f"{h}.{d}" for h in MIDDLEWARE_HOSTNAMES)):
        for rt in ("A", "AAAA"):
            for ip in _lookup(resolver, host, rt):
                try:
                    ip = str(ipaddress.ip_address(ip))
                except ValueError:
                    continue
                if ip in seen:
                    continue
                seen.add(ip)
                out.append(ip)
                if len(out) >= MAX_HOSTS:
                    return out
    return out


# ── CVE / EOL attachment (pure, reusing the curated datasets) ──────────────
def attach_cves(product: str, version: Optional[str]) -> list[dict]:
    """Top CVEs (by CVSS) from the curated dataset whose affected range contains `version`.
    Public-safe fields only. Empty when the version is unknown — we never assert a CVE against
    a version we did not read."""
    parsed = _parse_version(version) if version else None
    if parsed is None:
        return []
    hits = []
    for cve in cves_for_product(product):
        fixed = _affected_fix(cve, parsed)
        if fixed is None:
            continue
        hits.append({
            "id": cve["cve_id"],
            "cvss": cve.get("cvss"),
            "summary": cve.get("title") or cve["cve_id"],
            "fixed_in": fixed,
            "kev": bool(cve.get("kev")),
            "source_url": cve.get("source_url"),
        })
    hits.sort(key=lambda h: (-(h["cvss"] or 0.0), h["id"]))
    return hits[:MAX_CVES]


def eol_status(product: str, version: Optional[str], today: Optional[date] = None) -> dict:
    """{'status': eol|approaching|supported|unknown, 'note': str} from the lifecycle table."""
    today = today or datetime.now(timezone.utc).date()
    s = support_status(product, version, today)
    status = s["status"]
    if status == END_OF_LIFE:
        return {"status": "eol",
                "note": f"{s['display']} {s['matched_branch']} reached end of life on {s['eol']}"
                        + (f"; nearest supported branch is {s['nearest_supported']}"
                           if s.get("nearest_supported") else ""),
                "source_url": s.get("source_url")}
    if status == APPROACHING:
        return {"status": "approaching",
                "note": f"{s['display']} {s['matched_branch']} reaches end of life on {s['eol']} "
                        f"({s['days']} days)",
                "source_url": s.get("source_url")}
    if status == SUPPORTED:
        note = (f"{s['display']} {s['matched_branch']} is supported"
                + (f" until {s['eol']}" if s.get("eol") else ""))
        return {"status": "supported", "note": note, "source_url": s.get("source_url")}
    reasons = {
        "no_version": "no version could be read from the wire",
        "unparseable_version": f"version {version!r} could not be parsed",
        "unknown_product": f"no lifecycle data is curated for {product}",
        "unknown_branch": f"no lifecycle row covers {product} {version}",
    }
    return {"status": "unknown", "note": reasons.get(status, status), "source_url": None}


# ── The scan ───────────────────────────────────────────────────────────────
def _auth_observed(signals: dict) -> str:
    if signals.get("anonymous_accepted") is True or signals.get("auth_required") is False:
        return "none"
    if signals.get("auth_required") is True:
        return "required"
    return "unknown"


def _safe_evidence(items) -> list[str]:
    out: list[str] = []
    for e in items or []:
        s = " ".join(str(e).split())
        if not s or _SECRET_RE.search(s):
            continue
        if len(s) > MAX_EVIDENCE_LEN:
            s = s[:MAX_EVIDENCE_LEN - 1] + "…"
        out.append(s)
        if len(out) >= MAX_EVIDENCE_ITEMS:
            break
    return out


def _default_sweep(targets: list[Target], timeout: float):
    return _real_sweep(targets, timeout=timeout, max_workers=SWEEP_MAX_WORKERS)


def _headline(services: list[dict]) -> str:
    n = len(services)
    if n == 0:
        return "No internet-reachable middleware services were identified on the probed hosts."
    noun = "service" if n == 1 else "services"
    crit = sum(1 for s in services if any((c.get("cvss") or 0) >= 9.0 for c in s["cves"]))
    any_cve = sum(1 for s in services if s["cves"])
    eol = sum(1 for s in services if s["eol"]["status"] == "eol")
    open_auth = sum(1 for s in services if s["auth_observed"] == "none")
    parts = [f"{n} internet-reachable middleware {noun}"]
    if crit:
        parts.append(f"{crit} with a known critical CVE")
    elif any_cve:
        parts.append(f"{any_cve} with a known CVE")
    if eol:
        parts.append(f"{eol} past end of life")
    if open_auth:
        parts.append(f"{open_auth} accepting unauthenticated access")
    return ", ".join(parts) + "."


def run_exposure_scan(targets: list[str], *, sweep=None, time_budget_s: float = 60.0,
                      now: Optional[datetime] = None, ports=None) -> dict:
    """Probe `targets` (IP addresses) on the discovery connector's middleware port set and
    return the public-safe report. `sweep(targets, timeout=...)` is injectable; the default is
    the real `discover.sweep`. Wall-clock is bounded by `time_budget_s`: the per-probe timeout
    is scaled to fit, and a sweep that still overruns is cut off and reported as partial."""
    now = now or datetime.now(timezone.utc)
    sweep_fn = sweep or _default_sweep
    port_list = tuple(ports) if ports else DEFAULT_PORTS

    scope = resolve_scope(targets, ports=port_list, allow_public=True, max_hosts=MAX_CIDR_HOSTS)
    refusals = list(scope.refusals)
    services: list[dict] = []
    partial = False

    if scope.targets:
        rounds = max(1, -(-len(scope.targets) // SWEEP_MAX_WORKERS))
        # Two probes may answer one port, so budget for two; never below 1s (a real handshake
        # needs that), never above the connector's own 3s default.
        timeout = max(1.0, min(3.0, time_budget_s / (rounds * 2)))
        pool = ThreadPoolExecutor(max_workers=1)
        fut = pool.submit(sweep_fn, scope.targets, timeout=timeout)
        try:
            found = fut.result(timeout=time_budget_s)
        except _FutTimeout:
            found = []
            partial = True
            refusals.append(f"sweep exceeded the {int(time_budget_s)}s budget and was cut off — "
                            "the report is partial; narrow the target or re-run")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        for d in found:
            r = d.result
            product = str(r.product or "").lower()
            version = r.version or None
            services.append({
                "host": d.target.host,
                "port": d.target.port,
                "product": product,
                "version": version,
                "version_inferred": bool(r.version_inferred),
                "transport": r.transport,
                "auth_observed": _auth_observed(r.signals or {}),
                "evidence": _safe_evidence(r.evidence),
                "cves": attach_cves(product, version),
                "eol": eol_status(product, version, now.date()),
            })
        services.sort(key=lambda s: (s["host"], s["port"]))

    return {
        "targets_probed": len(scope.targets),
        "hosts": sorted(scope.hosts),
        "ports": list(port_list),
        "services": services,
        "refusals": refusals,
        "partial": partial,
        "headline": _headline(services),
        "generated_at": now.isoformat(),
    }
