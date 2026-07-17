"""The shared shapes every connector and detector speaks in."""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Resource:
    kind: str                       # broker | topic | route | service | acl ...
    name: str
    ext_id: str                     # stable id within a connection (used to link edges)
    namespace: Optional[str] = None
    labels: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)


@dataclass
class Edge:
    src_ext_id: str
    dst_ext_id: str
    kind: str
    labels: dict = field(default_factory=dict)


@dataclass
class Collected:
    resources: list
    edges: list = field(default_factory=list)


@dataclass
class Hit:
    """What a detector returns when a rule fires.

    `observation` is load-bearing: it is the exact evidence written to the immutable
    ledger and the only thing the AI is later allowed to cite. It must state a *fact read
    from the target* ("config authorizer.class.name is empty") — never a conclusion
    ("the broker is insecure").
    """
    observation: str
    remediation: str = ""
    detail: str = ""
    severity: Optional[str] = None  # overrides the decorator's severity when a rule's
                                    # seriousness depends on the resource (e.g. a PII topic)
    source_ref: dict = field(default_factory=dict)  # provenance: {"config_key": "...", "api": "..."}


@dataclass
class ScanContext:
    """Passed to every detector. Carries the whole collected set, so cross-resource rules
    ("this topic is exposed *because* its broker's listener is PLAINTEXT") are expressible."""
    connection_id: str
    tenant_id: str
    resources: list                 # every Resource in this scan
    config: dict = field(default_factory=dict)

    def of_kind(self, kind: str) -> list:
        return [r for r in self.resources if r.kind == kind]
