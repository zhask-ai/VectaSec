"""Supported-version lifecycle — the SUPPLY.LIFECYCLE.* rules.

A CVE feed can only report flaws somebody bothered to fix. Once a release branch is retired, its
advisory stream goes quiet — not because the code got safer, but because nobody is looking any
more — and a quiet feed is byte-identical to a clean one. This pack reads the running version off
the same resources the SBOM builds components from and asks the question no feed answers: *is
anyone still shipping patches for this branch, and if not, since when.*

Rules
  • SUPPLY.LIFECYCLE.END_OF_LIFE      high   — the running branch is past its published EOL date.
  • SUPPLY.LIFECYCLE.APPROACHING_EOL  medium — EOL falls inside the horizon (default 180 days).
  • SUPPLY.LIFECYCLE.NOT_ASSESSABLE   info   — the three ways we can fail to know, each named.

Honesty discipline (contracts.Hit)
  * Absence of data is NEVER a pass. A product outside the curated table, a branch the vendor
    never dated, and a resource whose version could not be read are all not-assessable findings
    with distinct reasons — because returning [] would render "we checked, it is supported" and
    "we have no idea" as the same row.
  * An EOL claim always carries its source URL and the vendor's own definition of the date
    (`basis` in lifecycle.py), so a reader can check our reading of the policy rather than trust it.
  * Product and version come from `sbom.component_for`, the one place in this codebase that
    decides what a resource IS. Re-deriving that here would let the SBOM and the lifecycle finding
    disagree about the same broker.

Kind selection mirrors sbom/osv: broker/server/cluster resources that carry a product+version, not
topics or queues. Kubernetes is out of scope by design — this pack's promise is middleware, and a
`k8s_cluster` row would file a not-assessable gap against a platform the dataset never claimed.
"""
from datetime import date

from ..contracts import Hit
from ..lifecycle import (
    APPROACHING, DEFAULT_HORIZON_DAYS, END_OF_LIFE, NO_VERSION, SUPPORTED, UNKNOWN_BRANCH,
    UNKNOWN_PRODUCT, UNPARSEABLE_VERSION, branches_for, support_status,
)
from ..registry import detector
from ..sbom import component_for

# Kinds carrying a product+version. Straightforward one-kind-one-product mappings live here; the
# kinds where the product depends on what the connector read are resolved in _version_carrier.
# `artemis_broker` and `coord_nacos` are listed on purpose despite holding no curated dates: they
# are real middleware, and a not-assessable finding is the honest answer for them. Silence is not.
_KIND_PRODUCT = {
    "redis_server": "redis",
    "nats_server": "nats",
    "memcached_server": "memcached",
    "solr_server": "solr",
    "vault_server": "vault",
    "activemq_broker": "activemq",
    "artemis_broker": "activemq-artemis",
    "aws_msk_cluster": "kafka",
    "coord_etcd": "etcd",
    "coord_zookeeper": "zookeeper",
    "coord_consul": "consul",
    "coord_nacos": "nacos",
}

_LIFECYCLE_KINDS = list(_KIND_PRODUCT) + [
    "node",                 # rabbitmq — only the cluster resource carries the version
    "broker",               # kong AND kafka share this kind
    "es_cluster",           # elasticsearch OR opensearch, per the distribution the connector read
    "pulsar_cluster",       # only the local cluster carries broker_version
    "discovered_service",   # unauthenticated probe — the inferred-version path
]

# Config keys a scan may set. `lifecycle_today` exists so this pack is reproducible: a rule whose
# verdict is a function of the wall clock cannot be regression-tested, and an estate that did not
# change should not acquire a new high finding because a date rolled over unannounced.
_CFG_TODAY = "lifecycle_today"
_CFG_HORIZON = "lifecycle_horizon_days"


def _today(ctx) -> date:
    raw = str((getattr(ctx, "config", None) or {}).get(_CFG_TODAY) or "").strip()
    if raw:
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            pass    # a malformed pin falls back to the real date rather than voiding the rule
    return date.today()


def _horizon(ctx) -> int:
    try:
        days = int((getattr(ctx, "config", None) or {}).get(_CFG_HORIZON) or DEFAULT_HORIZON_DAYS)
    except (TypeError, ValueError):
        return DEFAULT_HORIZON_DAYS
    return days if days > 0 else DEFAULT_HORIZON_DAYS


def _version_carrier(r) -> str | None:
    """The product key this resource reports a version FOR, or None when the resource is simply
    not the version carrier (a per-node RabbitMQ row, a remote Pulsar cluster, an unfingerprinted
    probe hit). None means "this row was never the place to look" — not "assessed and fine" — and
    is the only case in this pack that produces no finding at all."""
    kind, raw, labels = r.kind, (r.raw or {}), (r.labels or {})

    if kind in _KIND_PRODUCT:
        return _KIND_PRODUCT[kind]

    if kind == "node":                              # rabbitmq: the cluster row holds the version
        return "rabbitmq" if raw.get("role") == "cluster" else None

    if kind == "broker":
        # Same disambiguation detect/cve.py makes: Kong records a node version, a Kafka broker
        # does not. A Kafka broker with no version is still a carrier — it lands in the
        # not-assessable path, which is the true statement (AdminClient exposes no version).
        kong_signal = raw.get("version") or "edition" in labels or "version" in labels
        return "kong" if kong_signal else "kafka"

    if kind == "es_cluster":
        # Elasticsearch and OpenSearch share this kind and have completely separate lifecycles.
        # Defaulting a non-OpenSearch distribution to elasticsearch is safe rather than merely
        # convenient: an OpenSearch version (1.x/2.x/3.x) matches no Elasticsearch row, so a
        # misread distribution yields not-assessable, never a wrong branch's EOL date.
        distribution = str(raw.get("distribution") or "").lower()
        return "opensearch" if distribution == "opensearch" else "elasticsearch"

    if kind == "pulsar_cluster":
        # The connector puts broker_version on the local cluster only, so that an N-cluster
        # topology does not file N copies of one broker's finding.
        return "pulsar" if raw.get("is_local") else None

    if kind == "discovered_service":
        return str(raw.get("product") or "").strip().lower() or None

    return None


def _assess(r, ctx):
    """(status dict, version string, inferred flag) for a carrier resource, else None.

    Version and product come from sbom.component_for — the same reader the SBOM and the OSV
    enrichment use — so the three can never describe one broker differently. component_for
    returning None means it found no version, which this pack reports rather than skips.
    """
    product = _version_carrier(r)
    if product is None:
        return None

    raw = dict(r.raw or {})
    # RabbitMQ reports its version one level down, inside the /api/overview document that
    # sbom._version_of does not walk. Lifting it to the key that reader already knows keeps the
    # single-source-of-truth intact instead of forking a second version parser here.
    overview = raw.get("overview")
    if isinstance(overview, dict) and overview.get("rabbitmq_version"):
        raw.setdefault("rabbitmq_version", overview["rabbitmq_version"])

    comp = component_for({
        "kind": r.kind, "name": r.name, "ext_id": r.ext_id,
        "labels": r.labels or {}, "raw": raw,
        # component_for prefers a product recorded ON the resource (a discovery probe's
        # fingerprint, an MFT appliance family) and falls back to the connection's type; the
        # kind-derived key stands in for that type, which a detector is not given.
        "connection_type": product,
    })

    if comp is None:
        version, inferred, product_key = None, False, product
    else:
        version = comp["version"]
        # component_for marks an inferred version with a CycloneDX evidence block at confidence
        # 0.5 — the same tell osv.py reads. See the inferred-version note on not_assessable().
        inferred = "evidence" in comp
        product_key = comp["name"]

    status = support_status(product_key, version, _today(ctx), _horizon(ctx))
    return status, version, inferred


def _cite(s: dict) -> str:
    """The provenance clause every finding ends with: where the date came from, when we last
    checked it, and what the vendor means by it."""
    parts = [f"source: {s['source_url']}" if s.get("source_url") else "source: (none)"]
    if s.get("vendor_url") and s.get("vendor_url") != s.get("source_url"):
        parts.append(f"vendor policy: {s['vendor_url']}")
    parts.append(f"verified {s['verified_on']}")
    return "; ".join(parts) + f". Basis: {s['basis']}"


def _upgrade_clause(s: dict) -> str:
    target = s.get("nearest_supported")
    if target:
        return f"Upgrade to the {s['display']} {target} branch, which is still receiving fixes."
    return (f"The curated dataset knows of no {s['display']} branch that is still receiving "
            f"fixes; confirm a supported release with the vendor before planning the upgrade.")


@detector(kinds=_LIFECYCLE_KINDS, rule_id="SUPPLY.LIFECYCLE.END_OF_LIFE", severity="high",
          title="Running version is on a branch that has reached end of life")
def end_of_life(r, ctx) -> list:
    """The branch stopped receiving patches on a published date that has passed. High, and not
    conditional on any CVE being known: the exposure is that every flaw found from here on stays
    unfixed in this deployment, which is a worse position than any single advisory describes."""
    assessed = _assess(r, ctx)
    if assessed is None:
        return []
    s, version, inferred = assessed
    if s["status"] != END_OF_LIFE or inferred:
        return []       # an inferred version is voiced by not_assessable(), never asserted here

    past = -s["days"]
    return [Hit(
        observation=(
            f"{s['display']} {r.kind} '{r.name}' reports version {version!r}, which is on the "
            f"{s['matched_branch']} branch; that branch reached end of life on {s['eol']} "
            f"({past} days ago) and receives no further releases, security or otherwise"
        ),
        remediation=(
            f"{_upgrade_clause(s)} An end-of-life branch will never receive a fix for any "
            f"vulnerability disclosed from {s['eol']} onward, so no patching cadence can close "
            f"this. {_cite(s)}"
        ),
        detail=(f"product={s['product']} version={version!r} branch={s['branch']} "
                f"matched={s['matched_branch']} eol={s['eol']} days_past={past} "
                f"nearest_supported={s['nearest_supported'] or 'unknown'}"),
        source_ref={"product": s["product"], "version_read": version,
                    "branch": s["matched_branch"], "eol": str(s["eol"]),
                    "days_past_eol": past, "nearest_supported": s["nearest_supported"],
                    "source": s["source_url"], "vendor_url": s.get("vendor_url"),
                    "verified_on": s["verified_on"], "basis": s["basis"]},
    )]


@detector(kinds=_LIFECYCLE_KINDS, rule_id="SUPPLY.LIFECYCLE.APPROACHING_EOL", severity="medium",
          title="Running version's branch reaches end of life soon")
def approaching_eol(r, ctx) -> list:
    """MEDIUM, deliberately — not low, and not high.

    Not high: the system is still receiving patches today, so there is no present loss of
    coverage. Not low: the date is published and certain, and upgrading a broker is a
    change-managed exercise measured in weeks — filed as low it would sit in a backlog until it
    silently became the high above, which is the exact failure this rule exists to pre-empt. The
    whole value of the rule is that it arrives while there is still time to plan.
    """
    assessed = _assess(r, ctx)
    if assessed is None:
        return []
    s, version, inferred = assessed
    if s["status"] != APPROACHING or inferred:
        return []

    return [Hit(
        observation=(
            f"{s['display']} {r.kind} '{r.name}' reports version {version!r} on the "
            f"{s['matched_branch']} branch, whose end of life is {s['eol']} — {s['days']} days "
            f"away, inside the {_horizon(ctx)}-day planning horizon"
        ),
        remediation=(
            f"Plan the upgrade now, while patches are still shipping. {_upgrade_clause(s)} "
            f"After {s['eol']} this deployment receives no further security releases. {_cite(s)}"
        ),
        detail=(f"product={s['product']} version={version!r} branch={s['branch']} "
                f"matched={s['matched_branch']} eol={s['eol']} days_remaining={s['days']} "
                f"horizon_days={_horizon(ctx)} "
                f"nearest_supported={s['nearest_supported'] or 'unknown'}"),
        source_ref={"product": s["product"], "version_read": version,
                    "branch": s["matched_branch"], "eol": str(s["eol"]),
                    "days_remaining": s["days"], "horizon_days": _horizon(ctx),
                    "nearest_supported": s["nearest_supported"],
                    "source": s["source_url"], "vendor_url": s.get("vendor_url"),
                    "verified_on": s["verified_on"], "basis": s["basis"]},
    )]


@detector(kinds=_LIFECYCLE_KINDS, rule_id="SUPPLY.LIFECYCLE.NOT_ASSESSABLE", severity="info",
          title="Support status of a running component could not be determined")
def not_assessable(r, ctx) -> list:
    """The three ways this pack can fail to answer, each stated in its own words.

      (a) no version could be read for the component;
      (b) the product, or the specific branch, is not in the curated dataset;
      (c) the version was INFERRED rather than read off the wire.

    (c) is a judgement call and it is deliberate. sbom.component_for records an inferred version
    at confidence 0.5 — it comes from matching a service's advertised protocol capability matrix,
    which narrows a version to a neighbourhood, not to a branch. Branch is exactly the granularity
    this pack decides on, so an EOL verdict built on an inferred version would be a high-severity
    assertion resting on a coin-flip input. It is downgraded here instead, and the finding still
    states what the inference points at, so an operator gets the lead without the product staking
    a claim it cannot defend. Confirm the version on the host and the assessed rules take over.

    Note (b) covers a branch that is merely ABSENT from the table. An absent branch is usually an
    old one, which makes "not in the table" tempting to read as "EOL" — that inference is banned
    here, because the table is also incomplete at the new end and for undated vendors.
    """
    assessed = _assess(r, ctx)
    if assessed is None:
        return []
    s, version, inferred = assessed
    status = s["status"]

    if inferred:
        # The version is a probe's inference; every downstream verdict inherits its uncertainty,
        # including a verdict of "supported".
        would = {
            END_OF_LIFE: f"would place it past the {s['matched_branch']} branch's {s['eol']} end of life",
            APPROACHING: f"would place it on the {s['matched_branch']} branch, EOL {s['eol']}",
            SUPPORTED: f"would place it on the supported {s['matched_branch']} branch",
        }.get(status, "matches no curated branch")
        return [Hit(
            observation=(
                f"{s['display']} {r.kind} '{r.name}' has version {version!r} INFERRED from the "
                f"service's advertised protocol capability matrix rather than read off the wire; "
                f"taken at face value it {would}, but an inferred version does not identify a "
                f"release branch reliably enough to assert a support status"
            ),
            remediation=("Read the version from the service directly (authenticate the connector, "
                         "or query the admin/monitoring endpoint) so its support status can be "
                         "assessed rather than guessed."),
            detail=(f"product={s['product']} version={version!r} version_inferred=true "
                    f"provisional_status={status}"),
            assessable=False,
            assessment_reason=("version was inferred from a discovery probe's capability matrix, "
                               "not read from the service"),
            source_ref={"product": s["product"], "version_read": version,
                        "version_inferred": True, "provisional_status": status,
                        "source": s["source_url"]},
        )]

    if status in (NO_VERSION, UNPARSEABLE_VERSION):
        why = ("exposes no version at all" if status == NO_VERSION
               else f"reports {version!r}, which contains no parseable version number")
        return [Hit(
            observation=(f"{s['display']} {r.kind} '{r.name}' {why}, so whether it is running a "
                         f"branch that still receives security patches could not be determined"),
            remediation=(f"Give the scanner read access to the {s['display']} version (or record "
                         f"it) so its support status can be assessed. An unread version is not a "
                         f"supported version."),
            detail=f"product={s['product']} version={version!r} reason=no_readable_version",
            assessable=False,
            assessment_reason=f"no version could be read for this {s['display']} component",
            source_ref={"product": s["product"], "version_read": version, "reason": status},
        )]

    if status == UNKNOWN_PRODUCT:
        # An untracked product short-circuits before the version is examined, so say which of the
        # two we actually have rather than printing a bare None into an operator's finding.
        reports = f"reports version {version!r}" if version else "reports no version"
        return [Hit(
            observation=(f"{r.kind} '{r.name}' {reports} for product {s['product']!r}, which the "
                         f"curated support-lifecycle dataset does not cover, so whether that "
                         f"release still receives security patches is unknown to this scan"),
            remediation=(f"Check {s['product']}'s published support schedule for this release by "
                         f"hand, and add it to vectasec/lifecycle.py with its source URL so the "
                         f"check runs automatically."),
            detail=f"product={s['product']} version={version!r} reason=product_not_curated",
            assessable=False,
            assessment_reason=(f"product {s['product']!r} is not in the curated support-lifecycle "
                               f"dataset"),
            source_ref={"product": s["product"], "version_read": version,
                        "reason": UNKNOWN_PRODUCT},
        )]

    if status == UNKNOWN_BRANCH:
        known = ", ".join(b["branch"] for b in branches_for(s["product"])[:8])
        return [Hit(
            observation=(f"{s['display']} {r.kind} '{r.name}' reports version {version!r} on "
                         f"branch {s['branch']}, which carries no end-of-life date in the curated "
                         f"dataset (dated branches: {known}…), so its support status is unknown"),
            remediation=(f"Look up the {s['display']} {s['branch']} branch on the vendor's support "
                         f"schedule and add it to vectasec/lifecycle.py with its source URL. An "
                         f"undated branch is not evidence of support — older branches are the most "
                         f"likely to be missing."),
            detail=(f"product={s['product']} version={version!r} branch={s['branch']} "
                    f"reason=branch_not_curated"),
            assessable=False,
            assessment_reason=(f"branch {s['branch']} of {s['display']} is not in the curated "
                               f"support-lifecycle dataset"),
            source_ref={"product": s["product"], "version_read": version,
                        "branch": s["branch"], "reason": UNKNOWN_BRANCH,
                        "curated_branches": [b["branch"] for b in branches_for(s["product"])]},
        )]

    return []       # SUPPORTED, read from the wire: checked, and nothing to report
