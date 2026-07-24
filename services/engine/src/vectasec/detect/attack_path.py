"""Attack-path detectors — the cross-cutting toxic-combination pack.

This is the detector face of graph_engine.py: it runs the correlation engine over ctx.resources
and emits ATTACKPATH.* findings whose observation names the exact chain hop-by-hop, each hop
citing a resource ext_id and the signal read there. It generalises the ONE hand-built toxic
combination in detect/data.py (DATA.EXPOSURE.SENSITIVE_PLAINTEXT, Kafka-only) into a rule pack
that fires across ANY connector whose resources carry the label-encoded exposure / identity /
classification graph.

  ATTACKPATH.EXPOSED_NHI_SENSITIVE   the full toxic triad — a sensitive-classified resource
                                     reachable by an over-privileged non-human identity that lives
                                     on an exposed surface. Critical on regulated (PCI/PHI/secrets)
                                     data. This is the flagship finding.
  ATTACKPATH.PUBLIC_OVERPRIVILEGED   an exposed / public / unauthenticated surface whose reachable
                                     non-human identity holds a wildcard ALLOW grant — exposure ×
                                     over-privilege, no sensitive data required.
  ATTACKPATH.SENSITIVE_ON_EXPOSED    sensitive data on an unauthenticated / plaintext surface,
                                     across ANY connector — the generalisation of the Kafka-only
                                     DATA.EXPOSURE.SENSITIVE_PLAINTEXT rule. Emits a not-assessable
                                     coverage-gap finding when a hosting surface exists but its
                                     exposure could not be read.

ANCHOR-ONCE (from detect/data.py). Each rule keys on ONE anchor kind and the engine computes the
whole graph once, so a chain is emitted exactly once — never duplicated from two resources. The
two data-anchored rules are mutually exclusive per resource (the engine lets the 3-factor triad
supersede the 2-factor exposure), so a sensitive resource never produces both.

The `ATTACKPATH.` prefix intentionally matches no connector type (unlike DATA./NHI./KAFKA./TLS.):
it is a cross-cutting pack, so the /connectors catalogue counts it against no connector, and the
compliance mapper returns no controls for it (correct — a chain is evidence for triage, and each
underlying single-signal finding still carries its own framework mapping).

HONEST LIMITS. See graph_engine.py's module docstring: "reachable" is an authorization/hosting
relationship encoded in the CURRENT scan's labels, not a proven network path and not multi-hop
data lineage. Co-location is coarse and the observation says so. Deep cross-system lineage awaits
CDC / iPaaS lineage connectors and is not claimed here.
"""
from ..contracts import Hit
from ..graph_engine import paths_for
from ..registry import detector

# The data-carrying kinds a path can terminate on (classify.py's DATA_KINDS). The two data-anchored
# rules register on these; PUBLIC_OVERPRIVILEGED registers on "grant".
_DATA_KINDS = ["topic", "queue", "stream", "exchange", "subject",
               "route", "service", "mcp_tool", "keyspace", "channel"]

_REMEDIATION = {
    "EXPOSED_NHI_SENSITIVE": (
        "Break the chain at any hop: put the sensitive resource behind an encrypted, authenticated "
        "listener; enforce an authorizer with least-privilege ACLs so the identity loses its "
        "wildcard grant; and scope that non-human identity to only what it needs. An exposed "
        "surface plus an over-privileged principal plus regulated data is a directly exploitable "
        "read path — fix the exposure and the wildcard grant first."),
    "PUBLIC_OVERPRIVILEGED": (
        "Authenticate and encrypt the surface, and replace the wildcard grant with least-privilege "
        "rules. A reachable identity holding an ALLOW-anything grant on an exposed surface is a "
        "ready-made privilege-escalation path even before any sensitive data is confirmed."),
    "SENSITIVE_ON_EXPOSED": (
        "Put this data behind an encrypted (TLS/SASL_SSL) and authenticated surface with an "
        "authorizer enforcing least-privilege access. Sensitive data on a plaintext or "
        "unauthenticated surface is readable by anyone who can reach the port."),
}


def _to_hit(path) -> Hit:
    """Render one AttackPath as a grounded Hit: the observation is the cited hop-by-hop chain, the
    severity comes from the combination, and a not-assessable path becomes a coverage-gap Hit."""
    lead = {
        "EXPOSED_NHI_SENSITIVE": "toxic combination (exposure x over-privilege x sensitive data)",
        "PUBLIC_OVERPRIVILEGED": "toxic combination (exposure x over-privileged NHI)",
        "SENSITIVE_ON_EXPOSED": "toxic combination (sensitive data on an exposed surface)",
    }[path.category]
    observation = f"{lead}: {path.chain()}"
    if not path.assessable:
        observation = (f"{lead}: {path.chain()} — this chain could NOT be confirmed: "
                       f"{path.assessment_reason}")
    return Hit(
        severity=path.severity,
        observation=observation,
        remediation=_REMEDIATION[path.category],
        detail=("factors " + " ".join(f"{k}={v}" for k, v in path.factors.items())
                + f" · hops={len(path.hops)}"),
        assessable=path.assessable,
        assessment_reason=path.assessment_reason,
        source_ref={"attack_path": path.category, "anchor": path.anchor_ext_id,
                    "hops": [h.ext_id for h in path.hops], "factors": path.factors},
    )


@detector(kinds=_DATA_KINDS, rule_id="ATTACKPATH.EXPOSED_NHI_SENSITIVE", severity="critical",
          title="Sensitive resource reachable by an over-privileged NHI on an exposed surface")
def exposed_nhi_sensitive(r, ctx) -> list:
    """The full toxic triad, anchored on the sensitive data resource (the crown jewel). Fires when
    an over-privileged non-human identity on an exposed surface is authorized to reach THIS
    resource and it is classified sensitive."""
    return [_to_hit(p) for p in paths_for(r, ctx.resources)
            if p.category == "EXPOSED_NHI_SENSITIVE"]


@detector(kinds=["grant"], rule_id="ATTACKPATH.PUBLIC_OVERPRIVILEGED", severity="high",
          title="Over-privileged NHI reachable via an exposed or public surface")
def public_overprivileged(r, ctx) -> list:
    """Exposure x over-privilege, anchored on the wildcard ALLOW grant. Fires when the grant's
    holder lives on (or the grant targets) an exposed/public/unauthenticated surface — no
    sensitive-data classification required."""
    return [_to_hit(p) for p in paths_for(r, ctx.resources)
            if p.category == "PUBLIC_OVERPRIVILEGED"]


@detector(kinds=_DATA_KINDS, rule_id="ATTACKPATH.SENSITIVE_ON_EXPOSED", severity="high",
          title="Sensitive data on an unauthenticated or plaintext surface")
def sensitive_on_exposed(r, ctx) -> list:
    """Sensitive data on an exposed surface, generalising the Kafka-only DATA.EXPOSURE rule to any
    connector. Anchored on the sensitive data resource; superseded by EXPOSED_NHI_SENSITIVE when an
    over-privileged NHI also reaches it. Emits a not-assessable coverage gap when a hosting surface
    exists but its exposure could not be read."""
    return [_to_hit(p) for p in paths_for(r, ctx.resources)
            if p.category == "SENSITIVE_ON_EXPOSED"]
