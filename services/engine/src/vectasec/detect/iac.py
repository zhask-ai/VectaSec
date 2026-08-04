"""Integration-as-code rulepack — the deployment manifest as evidence.

These rules read `iac_workload` / `iac_file` resources produced by connect/iac.py. They are the
shift-left half of the Supply-chain capability: the same exposures the live rulepacks find, but
found in the file that will create them, before anything is listening.

TWO DISCIPLINES CARRIED FROM THE LIVE PACKS.

  Severity is honest about certainty, not just impact. A literal secret in a manifest is
  CRITICAL because it is a fact — the value is in the file, and probably in git history. A
  plaintext listener declared in compose is HIGH rather than critical: it is what the file says
  will happen, and an override at deploy time could still change it. The rules say which they
  are in `detail`, so nobody has to guess whether a finding is a fact or a forecast.

  Absence is never read as safety. A manifest we could not parse produces a NOT-ASSESSABLE
  finding rather than nothing at all, because "we read your compose file and it was clean" and
  "we could not read your compose file" are different sentences and must not render alike.

WHAT IS NOT HERE. No rule reports a secret's VALUE — the connector already dropped it and kept
only a fingerprint. No rule fires on a `${VAR}` reference, which is the correct pattern and
would otherwise be the loudest false positive in the pack.
"""
from ..contracts import Hit
from ..registry import detector


def _raw(r) -> dict:
    return r.raw or {}


def _ref(r, **extra) -> dict:
    raw = _raw(r)
    return {"file": raw.get("file"), "workload": raw.get("workload"),
            "source_format": raw.get("source_format"), "evidence_type": "iac", **extra}


def _where(raw: dict, line=None) -> str:
    at = f"{raw.get('file')}"
    if line:
        at += f":{line}"
    return at


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.LITERAL_SECRET",
          severity="critical", title="Credential written literally into a deployment manifest")
def literal_secret(r, ctx) -> list:
    """A secret whose value is IN the file — not a reference to one.

    This is the finding no live connector can make. A running RabbitMQ cannot tell you its
    password is also in a repository; only the file can, and by the time it is in git it is in
    every clone, every CI cache and every backup of that repository.
    """
    raw = _raw(r)
    secrets = raw.get("literal_secrets") or []
    if not secrets:
        return []
    keys = ", ".join(sorted(s["key"] for s in secrets))
    first = secrets[0]
    return [Hit(
        observation=(f"the manifest {_where(raw, first.get('line'))} sets {len(secrets)} "
                     f"credential value(s) literally on workload {raw.get('workload')!r} "
                     f"({keys}); the value of {first['key']} is {first.get('length')} characters "
                     f"and fingerprints to {first.get('fingerprint')}"),
        detail="The credential is in the file, so it is in every copy of the file: the working "
               "tree, the git history, every fork and every CI cache that ever checked it out. "
               "Rotating the running system does not remove it from those places. The value "
               "itself was never collected — only its length and a non-reversible fingerprint, "
               "which is enough to confirm a rotation actually changed it.",
        remediation="Move each value to a secret store and reference it from the manifest "
                    "(${VAR} from a secrets-managed env, or a Kubernetes secretKeyRef), then "
                    "rotate every value that was committed — treat them as public — and purge "
                    "the history if the repository is shared.",
        source_ref=_ref(r, keys=sorted(s["key"] for s in secrets),
                        fingerprints=[s.get("fingerprint") for s in secrets]),
    )]


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.DEFAULT_CREDENTIAL",
          severity="critical", title="Deployment manifest ships a vendor-default credential")
def default_credential(r, ctx) -> list:
    """Worse than a literal secret: a literal secret an attacker already knows.

    `guest`, `admin`, `changeme` are the first things any scanner tries, and a manifest carrying
    one means the system comes up vulnerable at first boot — there is no window in which it was
    ever secure.
    """
    raw = _raw(r)
    defaults = raw.get("default_credentials") or []
    if not defaults:
        return []
    keys = ", ".join(sorted(d["key"] for d in defaults))
    return [Hit(
        observation=(f"workload {raw.get('workload')!r} in {_where(raw, defaults[0].get('line'))} "
                     f"sets {keys} to a value on the well-known default-credential list"),
        detail="This is not merely a hardcoded secret; it is a hardcoded secret that is already "
               "public. The deployment is vulnerable from its first second of uptime, so there "
               "is no 'before it was compromised' to reason about.",
        remediation="Generate a unique credential per environment, store it in a secret manager, "
                    "and reference it here. Then verify no deployed instance is still running "
                    "with the default — this manifest is evidence that at least one was.",
        source_ref=_ref(r, keys=sorted(d["key"] for d in defaults)),
    )]


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.ANONYMOUS_ACCESS",
          severity="critical", title="Deployment manifest disables authentication")
def anonymous_access(r, ctx) -> list:
    """A switch that turns authentication off entirely — the quickstart setting that reaches
    production because it is what the tutorial said and nothing later complains."""
    raw = _raw(r)
    anon = raw.get("anonymous_access") or []
    if not anon:
        return []
    first = anon[0]
    listed = "; ".join(f"{a['key']}={a['value']} ({a['why']})" for a in anon)
    return [Hit(
        observation=(f"workload {raw.get('workload')!r} in {_where(raw, first.get('line'))} "
                     f"sets {listed}"),
        detail="With this set the component accepts unauthenticated clients. Every other control "
               "on it — ACLs, per-topic grants, audit attribution — is downstream of an identity "
               "that will not exist. This is the single highest-yield misconfiguration in the "
               "integration layer.",
        remediation="Remove the setting and configure real authentication before this manifest "
                    "is applied anywhere. If it exists to make local development easy, move it "
                    "to a development-only overlay that cannot be applied to a shared "
                    "environment.",
        source_ref=_ref(r, settings=[a["key"] for a in anon]),
    )]


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.PLAINTEXT_LISTENER",
          severity="high", title="Deployment manifest declares an unencrypted listener")
def plaintext_listener(r, ctx) -> list:
    """PLAINTEXT:// in a listener map. Declared intent, not observed traffic — hence high
    rather than critical, and the detail says so."""
    raw = _raw(r)
    listeners = raw.get("plaintext_listeners") or []
    if not listeners:
        return []
    return [Hit(
        observation=(f"workload {raw.get('workload')!r} in {raw.get('file')} declares "
                     f"{len(listeners)} PLAINTEXT listener(s): "
                     f"{'; '.join(listeners[:3])}"),
        detail="Everything crossing this listener — messages, keys, headers — is readable by "
               "anyone on the path. This is what the manifest declares; a deploy-time override "
               "could still change it, which is why this is reported as a forecast rather than "
               "as observed traffic. The live rulepack confirms it once the broker is running.",
        remediation="Define an SSL or SASL_SSL listener and make it the advertised one, then "
                    "remove the PLAINTEXT entry rather than leaving it as an unused fallback — "
                    "an unused plaintext listener is still an open plaintext listener.",
        source_ref=_ref(r, listeners=listeners[:5]),
    )]


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.PUBLIC_PORT_BINDING",
          severity="high", title="Integration component published on all interfaces")
def public_port_binding(r, ctx) -> list:
    """A broker port bound to 0.0.0.0. Scoped to integration components on purpose: a web
    frontend on 0.0.0.0 is the point of a web frontend, and firing there would train people to
    ignore the rule."""
    raw = _raw(r)
    if not raw.get("is_integration_component"):
        return []
    public = [p for p in (raw.get("ports") or []) if p.get("public")]
    if not public:
        return []
    ports = ", ".join(str(p.get("published")) for p in public if p.get("published"))
    return [Hit(
        observation=(f"workload {raw.get('workload')!r} in {raw.get('file')} publishes "
                     f"port(s) {ports} with no host-interface restriction, so they bind to all "
                     f"interfaces on the host"),
        detail="An integration component is infrastructure other services talk to, not something "
               "the internet needs to reach. Bound to all interfaces it is reachable from "
               "wherever the host is reachable — which on a cloud VM with a public IP means "
               "everywhere, subject only to a security group somebody else maintains.",
        remediation="Bind to the private interface explicitly (127.0.0.1:9092:9092, or a "
                    "specific host IP), or drop the published port entirely and let other "
                    "services reach it over the internal network only.",
        source_ref=_ref(r, ports=[p.get("published") for p in public]),
    )]


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.PRIVILEGED_CONTAINER",
          severity="high", title="Integration component runs privileged")
def privileged_container(r, ctx) -> list:
    raw = _raw(r)
    if not raw.get("privileged"):
        return []
    return [Hit(
        observation=(f"workload {raw.get('workload')!r} in {raw.get('file')} is declared "
                     f"privileged"),
        detail="A privileged container is not isolated from its host in any meaningful way: it "
               "can access every device and largely escape to the node. Combined with any "
               "remote-code path in the component itself, this turns a broker compromise into a "
               "host compromise.",
        remediation="Remove `privileged` and grant only the specific capabilities the component "
                    "actually needs. Brokers, gateways and MCP servers essentially never need "
                    "this flag; it is usually inherited from a copied example.",
        source_ref=_ref(r),
    )]


@detector(kinds=["iac_workload"], rule_id="SUPPLY.IAC.UNPINNED_IMAGE",
          severity="medium", title="Integration component deployed from a mutable image tag")
def unpinned_image(r, ctx) -> list:
    """The supply-chain rule proper: what you deployed is not what you reviewed.

    This is the link between this rulepack and the SBOM half of the capability — an image
    without a digest means the SBOM's component versions describe whatever was pulled at the
    time, and a later pull of the same tag can silently be different software.
    """
    raw = _raw(r)
    if not raw.get("is_integration_component"):
        return []
    image = raw.get("image") or {}
    if image.get("digest_pinned") or not image.get("mutable_tag"):
        return []
    if not image.get("repository"):
        return []
    tag = image.get("tag") or "latest (implicit)"
    return [Hit(
        observation=(f"workload {raw.get('workload')!r} in {raw.get('file')} deploys "
                     f"{image['repository']} at tag {tag!r} with no digest pin"),
        detail="A tag is a moving pointer. The image running today and the image that will be "
               "pulled on the next restart can be different software with the same name, so the "
               "component inventory and CVE assessment describe a version that may no longer be "
               "what is deployed. This is what makes a supply-chain substitution invisible.",
        remediation="Pin by digest (image@sha256:…) so a restart cannot change the software, and "
                    "update the digest deliberately as part of review. Keep the human-readable "
                    "tag alongside it for legibility.",
        source_ref=_ref(r, image=image.get("repository"), tag=image.get("tag")),
    )]


@detector(kinds=["iac_file"], rule_id="SUPPLY.IAC.NOT_ASSESSED",
          severity="info", title="Manifest could not be parsed")
def manifest_not_parsed(r, ctx) -> list:
    """A file we were pointed at and could not read. Silence here would be indistinguishable
    from a clean parse, which is the failure mode this whole codebase is built to avoid."""
    raw = _raw(r)
    if raw.get("parsed"):
        return []
    return [Hit(
        observation=(f"{raw.get('file')} was included in the scanned scope but could not be "
                     f"parsed: {raw.get('parse_error') or 'unknown error'}"),
        detail="No integration-as-code rule ran against this file. Its contents are unknown to "
               "this assessment, so nothing about it — good or bad — should be inferred from "
               "the absence of findings elsewhere.",
        remediation="Confirm the file is valid YAML or JSON and readable by the engine, then "
                    "rescan. If it is not a deployment manifest, exclude it from the scanned "
                    "path so the scope stays honest.",
        assessable=False,
        assessment_reason=f"the manifest could not be parsed: {raw.get('parse_error')}",
        source_ref=_ref(r),
    )]
