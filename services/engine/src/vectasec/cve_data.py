"""Curated CVE/KEV/EPSS dataset for the cross-fabric `detect/cve.py` enrichment pack.

This is a hand-verified, network-free snapshot. Every entry was sourced from the vendor
advisory and/or NVD (the `source_url`) at curation time (2026-07). It deliberately holds ONLY
CVEs whose product, affected range, fixed-in and CVSS could be confirmed against a primary
source — anything unverifiable was left out rather than guessed (see MODULE NOTES below).

Design contract
---------------
* Pure data + pure lookups. No network, no I/O, no clock. `detect/cve.py` maps a scanned
  resource's kind/labels to a `product` key here, then compares the version the connector read.
* `affected` is a list of half-open intervals ``[introduced, fixed)`` on a dotted version.
  A version is affected iff it falls inside ANY interval. `introduced` defaults to ``0``.
  We model exactly what the advisory states — a version OUTSIDE every declared interval is
  NOT asserted vulnerable (that is a clean pass for THIS CVE, never a guess).
* `kev` is CISA Known-Exploited truth at curation time; `detect/cve.py` escalates severity
  one tier when it is True. `epss` is left ``None`` unless a point value could be sourced —
  EPSS drifts daily and is not fabricated here.
* `cvss` is the CVSS v3.1 base score; `detect/cve.py` derives the base severity band from it.

MODULE NOTES (honesty ledger)
-----------------------------
* CVE-2025-49844 (Redis) is ALSO covered natively by ``detect/redis.py::REDIS.VERSION.RCE_CVE``
  with a per-series not-assessable nuance. The entry here is the cross-fabric enrichment view
  (KEV/EPSS/source/ATT&CK), filed under a different rule id, so the two do not collide.
* CVE-2023-46604 (ActiveMQ) is ALSO checked natively in ``connect/activemq.py``; same rationale.
* CVE-2024-32030 (Kafka-UI) is carried as a curated middleware CVE per the atlas, but NO
  connector currently emits a ``kafka-ui`` product signal, so it never fires today. It will
  the moment such a connector is added — the dataset is the forward-looking part.
* Dropped as unverifiable at curation time: a Kong Gateway CVE with a clean version range
  (the widely-cited "CVE-2024-32475" turned out to be an Envoy bug, not Kong), so Kong carries
  no dataset entry — ``detect/cve.py`` maps kong resources but finds nothing to assess, and
  stays silent rather than inventing a finding.
"""

# ── The dataset ────────────────────────────────────────────────────────────────
# Each entry: cve_id, product (lowercase key matched by detect/cve.py), title, cvss (v3.1 base),
# kev (CISA Known-Exploited), epss (point value or None), affected (list of {introduced?, fixed}),
# source_url (primary source), attack (MITRE ATT&CK technique ids), owasp (OWASP Top-10 ids).
CVES: list[dict] = [
    {
        "cve_id": "CVE-2025-49844",
        "product": "redis",
        "title": "Redis Lua use-after-free RCE (\"RediShell\")",
        "cvss": 10.0,
        "kev": False,   # CVSS 10.0 but no confirmed in-the-wild exploitation / CISA-KEV listing
                        # as of curation (Redis advisory + press, Oct 2025).
        "epss": None,
        "affected": [
            {"introduced": "6.2.0", "fixed": "6.2.20"},
            {"introduced": "7.2.0", "fixed": "7.2.11"},
            {"introduced": "7.4.0", "fixed": "7.4.6"},
            {"introduced": "8.0.0", "fixed": "8.0.4"},
            {"introduced": "8.2.0", "fixed": "8.2.2"},
        ],
        "source_url": "https://redis.io/blog/security-advisory-cve-2025-49844/",
        "attack": ["T1210", "T1059.006"],   # Exploitation of Remote Services; Command/Scripting: Lua
        "owasp": ["A06:2021"],              # Vulnerable and Outdated Components
    },
    {
        "cve_id": "CVE-2023-46604",
        "product": "activemq",
        "title": "Apache ActiveMQ OpenWire deserialization RCE",
        "cvss": 10.0,   # NVD CVSS v3.1 base 10.0 (some vendors cite 9.8).
        "kev": True,    # CISA KEV added 2023-11-02; exploited by ransomware (HelloKitty/TellYouThePass).
        "epss": None,
        "affected": [
            {"fixed": "5.15.16"},                        # all 5.15.x below the fix, and older 5.x
            {"introduced": "5.16.0", "fixed": "5.16.7"},
            {"introduced": "5.17.0", "fixed": "5.17.6"},
            {"introduced": "5.18.0", "fixed": "5.18.3"},
        ],
        "source_url": "https://activemq.apache.org/news/cve-2023-46604",
        "attack": ["T1210", "T1203"],       # Exploitation of Remote Services; Exploitation for Client Execution
        "owasp": ["A08:2021"],              # Software and Data Integrity Failures (insecure deserialization)
    },
    {
        "cve_id": "CVE-2023-34362",
        "product": "moveit",
        "title": "Progress MOVEit Transfer SQL injection (Cl0p / LemurLoot)",
        "cvss": 9.8,
        "kev": True,    # CISA KEV added 2023-06-02; mass-exploited zero-day.
        "epss": None,
        # Modeled on MOVEit's internal 13.x/14.x/15.x version numbering (what the banner reports).
        "affected": [
            {"fixed": "13.0.6"},                          # 2021.0.x below 2021.0.6, and older
            {"introduced": "13.1.0", "fixed": "13.1.4"},  # 2021.1.x
            {"introduced": "14.0.0", "fixed": "14.0.4"},  # 2022.0.x
            {"introduced": "14.1.0", "fixed": "14.1.5"},  # 2022.1.x
            {"introduced": "15.0.0", "fixed": "15.0.1"},  # 2023.0.x
        ],
        "source_url": "https://community.progress.com/s/article/MOVEit-Transfer-Critical-Vulnerability-31May2023",
        "attack": ["T1190"],                # Exploit Public-Facing Application
        "owasp": ["A03:2021"],              # Injection
    },
    {
        "cve_id": "CVE-2024-32030",
        "product": "kafka-ui",
        "title": "UI for Apache Kafka JMX/RMI deserialization RCE",
        "cvss": 8.1,
        "kev": False,
        "epss": None,
        "affected": [
            {"fixed": "0.7.2"},
        ],
        "source_url": "https://securitylab.github.com/advisories/GHSL-2023-229_GHSL-2023-230_kafka-ui/",
        "attack": ["T1210"],
        "owasp": ["A08:2021"],
    },
    {
        "cve_id": "CVE-2023-46118",
        "product": "rabbitmq",
        "title": "RabbitMQ HTTP API unbounded request body DoS",
        "cvss": 4.9,
        "kev": False,
        "epss": None,
        "affected": [
            {"introduced": "3.11.0", "fixed": "3.11.24"},
            {"introduced": "3.12.0", "fixed": "3.12.7"},
        ],
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-46118",
        "attack": ["T1499.003"],            # Endpoint Denial of Service: Application Exhaustion Flood
        "owasp": ["A06:2021"],
    },
    {
        "cve_id": "CVE-2024-45216",
        "product": "solr",
        "title": "Apache Solr PKIAuthenticationPlugin authentication bypass",
        "cvss": 9.8,
        "kev": False,
        "epss": None,
        "affected": [
            {"introduced": "5.3.0", "fixed": "8.11.4"},
            {"introduced": "9.0.0", "fixed": "9.7.0"},
        ],
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-45216",
        "attack": ["T1190", "T1078"],       # Exploit Public-Facing App; Valid Accounts (auth bypass)
        "owasp": ["A07:2021"],              # Identification and Authentication Failures
    },
    {
        "cve_id": "CVE-2018-1002105",
        "product": "kubernetes",
        "title": "Kubernetes kube-apiserver proxy request privilege escalation",
        "cvss": 9.8,
        "kev": False,
        "epss": None,
        "affected": [
            {"fixed": "1.10.11"},                         # all 1.10.x below the fix, and older 1.x
            {"introduced": "1.11.0", "fixed": "1.11.5"},
            {"introduced": "1.12.0", "fixed": "1.12.3"},
        ],
        "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2018-1002105",
        "attack": ["T1068", "T1210"],       # Exploitation for Privilege Escalation; of Remote Services
        "owasp": ["A01:2021"],              # Broken Access Control
    },
]


# ── Pure lookups ───────────────────────────────────────────────────────────────
def cves_for_product(product: str) -> list[dict]:
    """Every curated CVE for a product key. Empty list == a product we track but hold no CVE
    for (detect/cve.py stays silent for it — nothing to assess is not a coverage gap)."""
    if not product:
        return []
    p = product.lower()
    return [c for c in CVES if c["product"] == p]


def products_with_cves() -> set[str]:
    """The set of product keys that have at least one curated CVE."""
    return {c["product"] for c in CVES}
