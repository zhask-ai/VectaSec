"""Curated support-lifecycle (EOL) dataset for the `detect/lifecycle.py` rulepack.

A broker on a dead release branch receives no security patch ever again — and no CVE feed will
tell you that, because a branch nobody maintains stops accruing advisories and therefore looks
*exactly* like a branch nobody needs to patch. Absence of advisories is the failure mode this
dataset exists to convert into a fact. `cve_data.py` answers "is this version affected by a known
flaw"; this answers "will this version ever be fixed again".

Design contract (deliberately the same shape as cve_data.py)
------------------------------------------------------------
* Pure data + pure lookups. No network, no I/O, and NO CLOCK: every function that needs "now"
  takes `today` as an argument, so the rulepack cannot silently change verdicts overnight.
* Every branch entry carries its own `source_url`, not an inherited product-level one. The
  repetition is the point: a contributor adding a branch must paste the page that proves it, and
  `test_lifecycle.py::test_every_entry_has_a_source_url_and_parseable_date` fails if they do not.
  An inherited URL would let an unsourced guess ride in for free on somebody else's citation.
* `eol: None` is a POSITIVE claim — "the source lists this branch as current with no announced
  end date" — not "we have no data". A branch we cannot date is OMITTED, and an omitted branch is
  reported as not-assessable. Conflating "no date recorded" with "supported" is precisely how a
  lifecycle checker starts lying, so the two are different shapes here (absent vs present-with-None).
* `basis` states what the date actually means for that vendor, because "EOL" is not one concept:
  Kong's is the last day a patch is issued, HashiCorp's community date is "when the next minor
  shipped", Kafka's is derived from an informal convention. The rulepack quotes `basis` into every
  finding so a reader never has to assume our reading of a vendor's policy matches theirs.

VERIFICATION LEDGER
-------------------
Every date below was fetched from the cited page on 2026-08-03 (`verified_on`). Where the vendor
publishes its own table, the vendor is cited and endoflife.date is not used. Traps found and
avoided during verification, recorded so they are not re-introduced:

* KONG — the vendor table has TWO columns. "End of Sunset Support" is 12 months later and looks
  like the generous, safe choice; it is wrong. The policy states Kong "will not provide patches
  for software covered by this sunset period", so the last-patch date is END OF FULL SUPPORT, and
  that is what is recorded. endoflife.date's Kong data was stale at verification time (it stopped
  at 3.9 and dated the 3.4 LTS as open-ended), which is why the vendor page is the source here.
* REDIS — redis.io's "product lifecycle" page is REDIS SOFTWARE (the Enterprise cluster product),
  whose version numbers (6.4, 7.8, 7.22) are a different sequence from Redis open source and do
  not exist in OSS. Matching an OSS `redis_version` against that table would produce confident
  nonsense. The OSS branch dates come from endoflife.date/redis.
* APACHE SOLR — the source records `null` for the 1.x/3.x/4.x majors. That null means "no date on
  file", NOT "supported". Those majors are therefore OMITTED rather than entered with eol=None; a
  Solr 4 install lands in not-assessable instead of being declared current.
* ELASTICSEARCH — 8.x minors are dated individually; there is deliberately NO major-level "8"
  fallback entry. Elastic's own page gives an 8.x "End of Support Term" of 2027-07-15, but a
  running 8.10 stops receiving patches long before that, so a major-level entry would mark an
  unpatched minor as supported. Un-listed 8.x minors fall to not-assessable instead.
* ZOOKEEPER 3.7 — endoflife.date says 2024-01-19, the project's own releases page says
  "End-of-Life since 2 Feb 2024". The vendor wins and is cited for that row.
* HASHICORP (vault, consul) — the recorded dates are COMMUNITY support (a minor ends when the next
  minor ships). Vault's two LTS-labelled branches (1.16, 1.19) are omitted rather than dated,
  because Enterprise LTS adds ~12 months of extended maintenance this dataset does not model and
  asserting EOL against a live LTS contract is exactly the confident-wrong-finding failure.
* NATS — DELIBERATELY ABSENT. NATS 2.10/2.11 are widely described as end-of-life, but no primary
  source publishes a DATE, and this dataset does not carry undated assertions. Every NATS server
  therefore files a not-assessable "product not in the curated dataset" finding, which is the
  honest answer and is visibly different from "checked, supported". Add NATS the day nats.io
  publishes a dated support table.
* ARTEMIS / NACOS — same treatment: real middleware, no curated dates, so not-assessable rather
  than silence. Apache ActiveMQ Artemis is a separate product from ActiveMQ Classic with its own
  2.x sequence; mapping it onto the `activemq` 5.x/6.x rows would be a category error.
"""
from __future__ import annotations

import re
from datetime import date, timedelta

# The rulepack's default look-ahead for APPROACHING_EOL. Overridable per scan; see detect/lifecycle.py.
DEFAULT_HORIZON_DAYS = 180

# Source pages, one constant per page so a URL typo cannot vary row to row.
_EOL_RABBITMQ = "https://endoflife.date/rabbitmq"
_EOL_REDIS = "https://endoflife.date/redis"
_EOL_KAFKA = "https://endoflife.date/apache-kafka"
_EOL_ELASTIC = "https://endoflife.date/elasticsearch"
_EOL_OPENSEARCH = "https://endoflife.date/opensearch"
_EOL_ETCD = "https://endoflife.date/etcd"
_EOL_ACTIVEMQ = "https://endoflife.date/apache-activemq"
_EOL_ZOOKEEPER = "https://endoflife.date/apache-zookeeper"
_EOL_SOLR = "https://endoflife.date/apache-solr"
_EOL_MEMCACHED = "https://endoflife.date/memcached"
_EOL_PULSAR = "https://endoflife.date/apache-pulsar"
_EOL_VAULT = "https://endoflife.date/vault"
_EOL_CONSUL = "https://endoflife.date/consul"
_KONG_POLICY = "https://developer.konghq.com/gateway/version-support-policy/"
_ZK_RELEASES = "https://zookeeper.apache.org/releases.html"
_ELASTIC_EOL = "https://www.elastic.co/support/eol"

_VERIFIED = "2026-08-03"


# ── The dataset ────────────────────────────────────────────────────────────────
# product key (matches sbom.py's product keys) -> {display, verified_on, basis, vendor_url?,
# branches: [{branch, eol, source_url}]}. `branch` is "major.minor", or bare "major" where the
# vendor dates a whole major line; a major.minor row always wins over the major row.
SUPPORT_LIFECYCLE: dict[str, dict] = {
    "rabbitmq": {
        "display": "RabbitMQ",
        "verified_on": _VERIFIED,
        "basis": ("Community support for a RabbitMQ series ends on the date below; after it the "
                  "series receives no further releases, including security releases."),
        "branches": [
            {"branch": "4.3", "eol": None, "source_url": _EOL_RABBITMQ},
            {"branch": "4.2", "eol": "2026-07-31", "source_url": _EOL_RABBITMQ},
            {"branch": "4.1", "eol": "2026-01-30", "source_url": _EOL_RABBITMQ},
            {"branch": "4.0", "eol": "2025-04-15", "source_url": _EOL_RABBITMQ},
            {"branch": "3.13", "eol": "2024-09-17", "source_url": _EOL_RABBITMQ},
            {"branch": "3.12", "eol": "2024-02-21", "source_url": _EOL_RABBITMQ},
            {"branch": "3.11", "eol": "2023-06-01", "source_url": _EOL_RABBITMQ},
            {"branch": "3.10", "eol": "2022-09-28", "source_url": _EOL_RABBITMQ},
            {"branch": "3.9", "eol": "2023-01-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.8", "eol": "2022-07-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.7", "eol": "2020-09-30", "source_url": _EOL_RABBITMQ},
            {"branch": "3.6", "eol": "2018-05-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.5", "eol": "2016-10-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.4", "eol": "2015-10-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.3", "eol": "2015-03-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.2", "eol": "2014-10-31", "source_url": _EOL_RABBITMQ},
            {"branch": "3.1", "eol": "2014-04-30", "source_url": _EOL_RABBITMQ},
            {"branch": "3.0", "eol": "2013-11-30", "source_url": _EOL_RABBITMQ},
        ],
    },
    "redis": {
        "display": "Redis",
        "verified_on": _VERIFIED,
        "basis": ("Redis open source: the latest stable release plus two prior versions receive "
                  "fixes for critical bugs and major security issues; LTS branches carry the "
                  "longer dates below. Version numbers here are the OSS sequence reported by "
                  "INFO server, NOT the Redis Software cluster sequence."),
        "branches": [
            {"branch": "8.10", "eol": None, "source_url": _EOL_REDIS},
            {"branch": "8.8", "eol": None, "source_url": _EOL_REDIS},
            {"branch": "8.6", "eol": None, "source_url": _EOL_REDIS},
            {"branch": "8.4", "eol": None, "source_url": _EOL_REDIS},
            {"branch": "8.2", "eol": "2030-09-01", "source_url": _EOL_REDIS},
            {"branch": "8.0", "eol": "2026-12-01", "source_url": _EOL_REDIS},
            {"branch": "7.4", "eol": "2029-12-01", "source_url": _EOL_REDIS},
            {"branch": "7.2", "eol": "2029-12-01", "source_url": _EOL_REDIS},
            {"branch": "7.0", "eol": "2024-07-29", "source_url": _EOL_REDIS},
            {"branch": "6.2", "eol": "2027-04-01", "source_url": _EOL_REDIS},
            {"branch": "6.0", "eol": "2022-05-31", "source_url": _EOL_REDIS},
            {"branch": "5.0", "eol": "2022-04-27", "source_url": _EOL_REDIS},
        ],
    },
    "kafka": {
        "display": "Apache Kafka",
        "verified_on": _VERIFIED,
        "basis": ("Apache Kafka publishes no formal EOL calendar. The project ships a minor "
                  "roughly every four months and has supported up to three minors at a time; the "
                  "dates below are endoflife.date's reading of that convention, not a vendor "
                  "commitment. Confluent Platform sells longer support separately."),
        "branches": [
            {"branch": "4.3", "eol": None, "source_url": _EOL_KAFKA},
            {"branch": "4.2", "eol": None, "source_url": _EOL_KAFKA},
            {"branch": "4.1", "eol": None, "source_url": _EOL_KAFKA},
            {"branch": "4.0", "eol": None, "source_url": _EOL_KAFKA},
            {"branch": "3.9", "eol": None, "source_url": _EOL_KAFKA},
            {"branch": "3.8", "eol": "2024-11-06", "source_url": _EOL_KAFKA},
            {"branch": "3.7", "eol": "2024-07-26", "source_url": _EOL_KAFKA},
            {"branch": "3.6", "eol": "2024-02-27", "source_url": _EOL_KAFKA},
            {"branch": "3.5", "eol": "2023-10-03", "source_url": _EOL_KAFKA},
            {"branch": "3.4", "eol": "2023-06-13", "source_url": _EOL_KAFKA},
            {"branch": "3.3", "eol": "2023-02-06", "source_url": _EOL_KAFKA},
            {"branch": "3.2", "eol": "2022-09-28", "source_url": _EOL_KAFKA},
            {"branch": "3.1", "eol": "2022-09-19", "source_url": _EOL_KAFKA},
            {"branch": "3.0", "eol": "2022-09-19", "source_url": _EOL_KAFKA},
            {"branch": "2.8", "eol": "2022-09-19", "source_url": _EOL_KAFKA},
            {"branch": "2.7", "eol": "2021-11-15", "source_url": _EOL_KAFKA},
            {"branch": "2.6", "eol": "2021-11-15", "source_url": _EOL_KAFKA},
            {"branch": "2.5", "eol": "2020-08-10", "source_url": _EOL_KAFKA},
            {"branch": "2.4", "eol": "2020-04-15", "source_url": _EOL_KAFKA},
            {"branch": "2.3", "eol": "2019-12-16", "source_url": _EOL_KAFKA},
            {"branch": "2.2", "eol": "2019-12-01", "source_url": _EOL_KAFKA},
            {"branch": "2.1", "eol": "2019-03-22", "source_url": _EOL_KAFKA},
            {"branch": "2.0", "eol": "2018-11-20", "source_url": _EOL_KAFKA},
            {"branch": "1.1", "eol": "2018-07-30", "source_url": _EOL_KAFKA},
            {"branch": "1.0", "eol": "2018-07-08", "source_url": _EOL_KAFKA},
            {"branch": "0.11", "eol": "2018-07-02", "source_url": _EOL_KAFKA},
            {"branch": "0.10", "eol": "2018-07-02", "source_url": _EOL_KAFKA},
            {"branch": "0.9", "eol": "2016-05-22", "source_url": _EOL_KAFKA},
            {"branch": "0.8", "eol": "2015-11-23", "source_url": _EOL_KAFKA},
        ],
    },
    "kong": {
        "display": "Kong Gateway",
        "verified_on": _VERIFIED,
        "basis": ("Kong's End of Full Support date — the last day a version receives patches. The "
                  "12-month 'sunset' window that follows explicitly ships no patches ('Kong will "
                  "not provide patches for software covered by this sunset period'), so it is "
                  "upgrade assistance, not security maintenance, and is not counted here."),
        "branches": [
            {"branch": "3.15", "eol": "2027-07-02", "source_url": _KONG_POLICY},
            {"branch": "3.14", "eol": "2029-04-07", "source_url": _KONG_POLICY},   # LTS
            {"branch": "3.13", "eol": "2026-12-18", "source_url": _KONG_POLICY},
            {"branch": "3.12", "eol": "2026-10-01", "source_url": _KONG_POLICY},
            {"branch": "3.11", "eol": "2026-07-03", "source_url": _KONG_POLICY},
            {"branch": "3.10", "eol": "2028-03-31", "source_url": _KONG_POLICY},   # LTS
            {"branch": "3.9", "eol": "2025-12-12", "source_url": _KONG_POLICY},
            {"branch": "3.8", "eol": "2025-09-11", "source_url": _KONG_POLICY},
            {"branch": "3.7", "eol": "2025-05-28", "source_url": _KONG_POLICY},
            {"branch": "3.6", "eol": "2025-02-12", "source_url": _KONG_POLICY},
            {"branch": "3.5", "eol": "2024-11-08", "source_url": _KONG_POLICY},
            {"branch": "3.4", "eol": "2026-08-31", "source_url": _KONG_POLICY},    # LTS
            {"branch": "3.3", "eol": "2024-05-19", "source_url": _KONG_POLICY},
            {"branch": "3.2", "eol": "2024-02-28", "source_url": _KONG_POLICY},
            {"branch": "3.1", "eol": "2023-12-06", "source_url": _KONG_POLICY},
            {"branch": "3.0", "eol": "2023-09-09", "source_url": _KONG_POLICY},
            {"branch": "2.8", "eol": "2025-03-26", "source_url": _KONG_POLICY},
        ],
    },
    "elasticsearch": {
        "display": "Elasticsearch",
        "verified_on": _VERIFIED,
        "vendor_url": _ELASTIC_EOL,
        "basis": ("An Elastic Stack minor is maintained only until a later minor supersedes it; "
                  "the 7.x line's end-of-support date is Elastic's own. 8.x minors not listed "
                  "here are intentionally undated rather than covered by a major-level fallback."),
        "branches": [
            {"branch": "9.4", "eol": None, "source_url": _EOL_ELASTIC},
            {"branch": "9.3", "eol": "2026-05-26", "source_url": _EOL_ELASTIC},
            {"branch": "9.2", "eol": "2026-05-05", "source_url": _EOL_ELASTIC},
            {"branch": "9.1", "eol": "2026-02-03", "source_url": _EOL_ELASTIC},
            {"branch": "9.0", "eol": "2025-10-02", "source_url": _EOL_ELASTIC},
            {"branch": "8.19", "eol": "2027-07-15", "source_url": _EOL_ELASTIC},
            {"branch": "8.18", "eol": "2025-10-21", "source_url": _EOL_ELASTIC},
            {"branch": "8.17", "eol": "2025-08-05", "source_url": _EOL_ELASTIC},
            {"branch": "8.16", "eol": "2025-04-15", "source_url": _EOL_ELASTIC},
            {"branch": "7", "eol": "2026-01-15", "source_url": _ELASTIC_EOL},
            {"branch": "6", "eol": "2022-02-10", "source_url": _EOL_ELASTIC},
        ],
    },
    "opensearch": {
        "display": "OpenSearch",
        "verified_on": _VERIFIED,
        "basis": "OpenSearch dates its whole major lines; 2.x and 3.x are both current.",
        "branches": [
            {"branch": "3", "eol": None, "source_url": _EOL_OPENSEARCH},
            {"branch": "2", "eol": None, "source_url": _EOL_OPENSEARCH},
            {"branch": "1", "eol": "2025-05-06", "source_url": _EOL_OPENSEARCH},
        ],
    },
    "etcd": {
        "display": "etcd",
        "verified_on": _VERIFIED,
        "basis": "etcd maintains the two most recent minors plus dated extended windows on 3.4/3.5.",
        "branches": [
            {"branch": "3.7", "eol": None, "source_url": _EOL_ETCD},
            {"branch": "3.6", "eol": None, "source_url": _EOL_ETCD},
            {"branch": "3.5", "eol": "2027-07-08", "source_url": _EOL_ETCD},
            {"branch": "3.4", "eol": "2026-06-01", "source_url": _EOL_ETCD},
            {"branch": "3.3", "eol": "2021-10-15", "source_url": _EOL_ETCD},
            {"branch": "3.2", "eol": "2021-03-28", "source_url": _EOL_ETCD},
            {"branch": "3.1", "eol": "2018-10-10", "source_url": _EOL_ETCD},
            {"branch": "3.0", "eol": "2017-01-20", "source_url": _EOL_ETCD},
        ],
    },
    "activemq": {
        "display": "Apache ActiveMQ Classic",
        "verified_on": _VERIFIED,
        "basis": ("ActiveMQ Classic's 5.x/6.x lines. Artemis is a different product with its own "
                  "2.x sequence and is not covered by these rows."),
        "branches": [
            {"branch": "6.3", "eol": None, "source_url": _EOL_ACTIVEMQ},
            {"branch": "6.2", "eol": None, "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.19", "eol": None, "source_url": _EOL_ACTIVEMQ},
            {"branch": "6.1", "eol": "2025-12-02", "source_url": _EOL_ACTIVEMQ},
            {"branch": "6.0", "eol": "2024-03-17", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.18", "eol": "2025-03-11", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.17", "eol": "2024-04-12", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.16", "eol": "2023-03-18", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.15", "eol": "2022-03-09", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.14", "eol": "2017-06-27", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.13", "eol": "2016-12-16", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.12", "eol": "2016-02-03", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.11", "eol": "2016-02-03", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.10", "eol": "2015-02-13", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.9", "eol": "2014-06-05", "source_url": _EOL_ACTIVEMQ},
            {"branch": "5.8", "eol": "2013-10-14", "source_url": _EOL_ACTIVEMQ},
        ],
    },
    "zookeeper": {
        "display": "Apache ZooKeeper",
        "verified_on": _VERIFIED,
        "vendor_url": _ZK_RELEASES,
        "basis": ("The project decommissions the previous stable line roughly six months after a "
                  "new minor, providing only security and critical fixes in the interim."),
        "branches": [
            {"branch": "3.9", "eol": None, "source_url": _ZK_RELEASES},
            {"branch": "3.8", "eol": None, "source_url": _ZK_RELEASES},
            {"branch": "3.7", "eol": "2024-02-02", "source_url": _ZK_RELEASES},
            {"branch": "3.6", "eol": "2022-12-30", "source_url": _EOL_ZOOKEEPER},
            {"branch": "3.5", "eol": "2022-06-01", "source_url": _EOL_ZOOKEEPER},
            {"branch": "3.4", "eol": "2020-06-01", "source_url": _EOL_ZOOKEEPER},
        ],
    },
    "solr": {
        "display": "Apache Solr",
        "verified_on": _VERIFIED,
        "basis": ("Solr dates whole major lines. The 1.x/3.x/4.x majors carry no date at the "
                  "source and are omitted rather than assumed either way."),
        "branches": [
            {"branch": "10", "eol": None, "source_url": _EOL_SOLR},
            {"branch": "9", "eol": None, "source_url": _EOL_SOLR},
            {"branch": "8", "eol": "2024-10-25", "source_url": _EOL_SOLR},
            {"branch": "7", "eol": "2022-05-11", "source_url": _EOL_SOLR},
            {"branch": "6", "eol": "2019-03-13", "source_url": _EOL_SOLR},
            {"branch": "5", "eol": "2017-10-24", "source_url": _EOL_SOLR},
        ],
    },
    "memcached": {
        "display": "memcached",
        "verified_on": _VERIFIED,
        "basis": "Only the current 1.6 line receives releases; 1.4 and 1.5 ended on the dates below.",
        "branches": [
            {"branch": "1.6", "eol": None, "source_url": _EOL_MEMCACHED},
            {"branch": "1.5", "eol": "2020-03-09", "source_url": _EOL_MEMCACHED},
            {"branch": "1.4", "eol": "2017-07-21", "source_url": _EOL_MEMCACHED},
        ],
    },
    "pulsar": {
        "display": "Apache Pulsar",
        "verified_on": _VERIFIED,
        "basis": ("Feature releases are maintained ~6 months; LTS releases (3.0, 4.0) for 24 "
                  "months from release."),
        "branches": [
            {"branch": "4.2", "eol": "2026-09-24", "source_url": _EOL_PULSAR},
            {"branch": "4.1", "eol": "2026-03-08", "source_url": _EOL_PULSAR},
            {"branch": "4.0", "eol": "2026-10-21", "source_url": _EOL_PULSAR},     # LTS
            {"branch": "3.3", "eol": "2024-12-05", "source_url": _EOL_PULSAR},
            {"branch": "3.2", "eol": "2024-08-05", "source_url": _EOL_PULSAR},
            {"branch": "3.1", "eol": "2024-02-10", "source_url": _EOL_PULSAR},
            {"branch": "3.0", "eol": "2025-05-02", "source_url": _EOL_PULSAR},     # LTS
            {"branch": "2.11", "eol": "2024-01-11", "source_url": _EOL_PULSAR},
            {"branch": "2.10", "eol": "2023-04-18", "source_url": _EOL_PULSAR},
            {"branch": "2.9", "eol": "2022-12-20", "source_url": _EOL_PULSAR},
            {"branch": "2.8", "eol": "2022-06-15", "source_url": _EOL_PULSAR},
            {"branch": "2.7", "eol": "2021-12-03", "source_url": _EOL_PULSAR},
            {"branch": "2.6", "eol": "2021-06-17", "source_url": _EOL_PULSAR},
            {"branch": "2.5", "eol": "2021-01-15", "source_url": _EOL_PULSAR},
        ],
    },
    "vault": {
        "display": "HashiCorp Vault",
        "verified_on": _VERIFIED,
        "basis": ("COMMUNITY edition: a minor's standard maintenance ends when the next minor "
                  "ships. Vault Enterprise LTS branches get roughly a further year of extended "
                  "maintenance, so the two LTS lines (1.16, 1.19) are deliberately not dated here."),
        "branches": [
            {"branch": "2.0", "eol": None, "source_url": _EOL_VAULT},
            {"branch": "1.21", "eol": "2026-04-13", "source_url": _EOL_VAULT},
            {"branch": "1.20", "eol": "2025-10-21", "source_url": _EOL_VAULT},
            {"branch": "1.18", "eol": "2025-03-04", "source_url": _EOL_VAULT},
            {"branch": "1.17", "eol": "2024-10-09", "source_url": _EOL_VAULT},
            {"branch": "1.15", "eol": "2024-10-08", "source_url": _EOL_VAULT},
            {"branch": "1.14", "eol": "2024-06-10", "source_url": _EOL_VAULT},
            {"branch": "1.13", "eol": "2024-03-25", "source_url": _EOL_VAULT},
            {"branch": "1.12", "eol": "2023-09-27", "source_url": _EOL_VAULT},
            {"branch": "1.11", "eol": "2023-06-21", "source_url": _EOL_VAULT},
            {"branch": "1.10", "eol": "2023-03-01", "source_url": _EOL_VAULT},
            {"branch": "1.9", "eol": "2022-10-10", "source_url": _EOL_VAULT},
        ],
    },
    "consul": {
        "display": "HashiCorp Consul",
        "verified_on": _VERIFIED,
        "basis": ("COMMUNITY edition: a minor's maintenance ends when the next minor ships. "
                  "A Consul Enterprise contract may extend this beyond the date shown."),
        "branches": [
            {"branch": "2.0", "eol": None, "source_url": _EOL_CONSUL},
            {"branch": "1.22", "eol": None, "source_url": _EOL_CONSUL},
            {"branch": "1.21", "eol": None, "source_url": _EOL_CONSUL},
            {"branch": "1.20", "eol": "2026-05-24", "source_url": _EOL_CONSUL},
            {"branch": "1.19", "eol": "2025-10-27", "source_url": _EOL_CONSUL},
            {"branch": "1.18", "eol": "2025-05-06", "source_url": _EOL_CONSUL},
            {"branch": "1.17", "eol": "2024-10-14", "source_url": _EOL_CONSUL},
            {"branch": "1.16", "eol": "2024-06-12", "source_url": _EOL_CONSUL},
            {"branch": "1.15", "eol": "2024-02-27", "source_url": _EOL_CONSUL},
            {"branch": "1.14", "eol": "2023-11-03", "source_url": _EOL_CONSUL},
            {"branch": "1.13", "eol": "2023-06-26", "source_url": _EOL_CONSUL},
            {"branch": "1.12", "eol": "2023-02-23", "source_url": _EOL_CONSUL},
            {"branch": "1.11", "eol": "2022-11-15", "source_url": _EOL_CONSUL},
            {"branch": "1.10", "eol": "2022-08-09", "source_url": _EOL_CONSUL},
            {"branch": "1.9", "eol": "2022-04-19", "source_url": _EOL_CONSUL},
            {"branch": "1.8", "eol": "2021-12-14", "source_url": _EOL_CONSUL},
            {"branch": "1.7", "eol": "2021-06-22", "source_url": _EOL_CONSUL},
            {"branch": "1.6", "eol": "2020-11-24", "source_url": _EOL_CONSUL},
        ],
    },
}


# ── Pure lookups ───────────────────────────────────────────────────────────────
# Outcome vocabulary. Only END_OF_LIFE and APPROACHING are assertions about the target; the rest
# describe the limits of what we know, and the rulepack maps each to a distinct spoken reason.
SUPPORTED = "supported"
APPROACHING = "approaching_eol"
END_OF_LIFE = "end_of_life"
NO_VERSION = "no_version"                 # nothing to compare — coverage gap (a)
UNPARSEABLE_VERSION = "unparseable_version"
UNKNOWN_PRODUCT = "unknown_product"       # coverage gap (b)
UNKNOWN_BRANCH = "unknown_branch"         # coverage gap (b)


def parse_version(v) -> tuple | None:
    """Dotted version → (major, minor), tolerant of a leading 'v', pre-release/build suffixes
    ('8.2.1-alpine', '3.13.7+build') and >2 segments ('0.11.0.3' → (0, 11)). None when nothing
    numeric is present. Same tolerance rules as detect/cve.py::_parse_version, deliberately: a
    version string the CVE pack can read must not be one this pack calls unreadable."""
    m = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", str(v or ""))
    if not m:
        return None
    parts = [int(x) for x in m.group(1).split(".")[:2]]
    while len(parts) < 2:
        parts.append(0)
    return tuple(parts)


def _branch_key(branch: str) -> tuple:
    """'3.13' → (3, 13); '7' → (7,). A one-element key marks a whole-major row."""
    return tuple(int(p) for p in str(branch).split("."))


def _eol_date(entry: dict) -> date | None:
    e = entry.get("eol")
    return date.fromisoformat(e) if e else None


def branches_for(product: str) -> list[dict]:
    """Every curated branch row for a product, newest branch first. Empty when untracked."""
    prod = SUPPORT_LIFECYCLE.get((product or "").lower())
    if not prod:
        return []
    return sorted(prod["branches"], key=lambda b: _branch_key(b["branch"]), reverse=True)


def _match_branch(product: str, version: tuple) -> dict | None:
    """The row governing a (major, minor) version: an exact major.minor row, else the whole-major
    row if the vendor dates majors. Nothing matches → the caller reports UNKNOWN_BRANCH; it must
    never fall through to 'supported', because an undated branch is usually an OLD one."""
    rows = {_branch_key(b["branch"]): b for b in SUPPORT_LIFECYCLE[product]["branches"]}
    return rows.get(version) or rows.get((version[0],))


def nearest_supported_branch(product: str, today: date) -> str | None:
    """Highest curated branch still receiving fixes on `today` — what an upgrade should target.
    None when the dataset knows of no such branch, in which case the rulepack says so instead of
    inventing an upgrade target."""
    for b in branches_for(product):
        eol = _eol_date(b)
        if eol is None or eol > today:
            return b["branch"]
    return None


def support_status(product: str, version, today: date,
                   horizon_days: int = DEFAULT_HORIZON_DAYS) -> dict:
    """The whole lifecycle verdict for one product+version, as of `today`.

    `today` is a required argument rather than a call to date.today() so that a verdict is a pure
    function of its inputs: the rulepack's tests pin a date, and the pack cannot quietly change
    what it reports between two scans of an unchanged estate.

    Returns a dict whose `status` is one of the module constants. Every non-assertion status
    (NO_VERSION / UNPARSEABLE_VERSION / UNKNOWN_PRODUCT / UNKNOWN_BRANCH) is a distinct coverage
    gap the caller must voice — none of them means "fine".
    """
    prod_key = (product or "").lower()
    base = {"product": prod_key, "display": prod_key, "version": version, "branch": None,
            "matched_branch": None, "eol": None, "days": None, "source_url": None,
            "basis": None, "verified_on": None, "vendor_url": None, "nearest_supported": None}

    prod = SUPPORT_LIFECYCLE.get(prod_key)
    if not prod:
        return {**base, "status": UNKNOWN_PRODUCT}

    base.update(display=prod["display"], basis=prod["basis"], verified_on=prod["verified_on"],
                vendor_url=prod.get("vendor_url"),
                nearest_supported=nearest_supported_branch(prod_key, today))

    if version is None or not str(version).strip():
        return {**base, "status": NO_VERSION}

    parsed = parse_version(version)
    if parsed is None:
        return {**base, "status": UNPARSEABLE_VERSION}

    base["branch"] = f"{parsed[0]}.{parsed[1]}"
    row = _match_branch(prod_key, parsed)
    if row is None:
        return {**base, "status": UNKNOWN_BRANCH}

    base.update(matched_branch=row["branch"], source_url=row["source_url"], eol=_eol_date(row))
    eol = base["eol"]
    if eol is None:
        return {**base, "status": SUPPORTED}

    base["days"] = (eol - today).days
    if eol <= today:
        return {**base, "status": END_OF_LIFE}
    if eol <= today + timedelta(days=horizon_days):
        return {**base, "status": APPROACHING}
    return {**base, "status": SUPPORTED}


def tracked_products() -> set[str]:
    """Product keys this dataset can assess. Anything outside it is a declared coverage gap."""
    return set(SUPPORT_LIFECYCLE)
