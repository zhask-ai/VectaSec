"""Findings → framework controls: the mapping table and the controls-table evaluator.

Read docs/research/compliance-mapping.md before changing anything here. Two rules from that
document are structural, not stylistic, and everything below is shaped by them:

  1. A finding can prove FAIL. A finding's absence can never prove PASS. KAFKA.ACL.WILDCARD_*
     firing is evidence PCI 7.2.5 is not met on that broker. It *not* firing says nothing about
     the other 200 system accounts in the CDE we never scanned. So evaluate() only ever emits
     `fail`, `unknown` or `not_applicable`. There is no code path — no flag, no argument — by
     which a clean scan writes `pass`. That is not a default; it is the whole contract, and the
     console states it to the buyer as one (apps/web/app/compliance/frameworks.ts).
  2. Every mapping is conditional on scope, and scope is not a property of the rule. A PLAINTEXT
     listener on a broker carrying no PAN and no ePHI violates nothing — it is just bad practice.
     Framework applicability is the tenant's declaration (`frameworks`); asset-level conditions
     come from resource labels / `scope_tags` and are checked against `ControlRef.gate`.

Only mappings the research rated **A** (defensible — the control text describes this
misconfiguration) or **B** (conditional — defensible once the gate holds) are here. Everything
it rated **C** (stretch) is omitted and recorded in NOT_MAPPED with the reason. A fabricated
citation sitting next to a real one discredits the real one, so the stretches are worth more
to us as documented refusals than as rows.

Provenance warning that must not be lost: the PCI requirement text below is quoted from a
*vendor reproduction* of PCI DSS v4.0.1, not from the standard (the PCI SSC PDF is behind a
click-through). It must be diffed against the official PDF before any customer-facing use.
See docs/research/compliance-mapping.md §8.
"""
import json
from typing import NamedTuple, Optional


class Control(NamedTuple):
    """One control we evaluate. `requirement` is the control's own words — it is quoted in the
    UI next to a finding, so it carries the same citation burden as an observation: no source,
    no row."""
    title: str
    requirement: str
    source_url: str


class ControlRef(NamedTuple):
    """A rule's claim against a control.

    The first four fields are (framework, control_id, title, requirement) so a caller can
    unpack the documented tuple shape; the rest is the honesty metadata that decides whether
    the claim may be asserted at all.
    """
    framework: str
    control_id: str
    title: str
    requirement: str
    relation: str = "violates"   # violates = direct evidence | supports = partial evidence
    confidence: str = "A"        # A = defensible | B = defensible once `gate` holds
    gate: tuple = ()             # asset scope tags that must ALL hold before asserting
    note: str = ""               # shown in the UI beside the citation


# ── Source documents ──────────────────────────────────────────────────────
# Every control_id carries the URL it was read from. This mirrors the citation gate the
# product already applies to AI output: a compliance claim without a source is the same
# defect as an ungrounded AI claim and should fail the same way.
_PCI_SRC = "https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf"
_DORA_SRC = "https://www.digital-operational-resilience-act.com/Article_9.html"
_NIS2_SRC = "https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html"
_HIPAA_SRC = "https://www.law.cornell.edu/cfr/text/45/164.312"
_MCP_SRC = "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization"

PCI = "PCI_DSS_4_0_1"
DORA = "DORA"
NIS2 = "NIS2"
HIPAA = "HIPAA"
MCP_SPEC = "MCP_SPEC_2025_11_25"   # pinned: MCP revisions move fast enough to invalidate detectors


# ── CONTROL_CATALOGUE ─────────────────────────────────────────────────────
# Only controls at least one implemented rule actually maps to. Controls we cannot evaluate
# are deliberately absent rather than present-and-permanently-unknown: an empty row in a
# compliance table reads as coverage we do not have.
CONTROL_CATALOGUE: dict[str, dict[str, Control]] = {
    PCI: {
        "1.2.5": Control(
            "Allowed services, protocols, and ports are identified and approved",
            "All services, protocols, and ports allowed are identified, approved, and have a "
            "defined business need.",
            _PCI_SRC),
        "1.2.6": Control(
            "Security features are defined for insecure services and protocols in use",
            "Security features are defined and implemented for all services, protocols, and ports "
            "that are in use and considered to be insecure, such that the risk is mitigated.",
            _PCI_SRC),
        "1.3.1": Control(
            "Inbound traffic to the CDE is restricted to only what is necessary",
            "Inbound traffic to the CDE is restricted as follows: To only traffic that is "
            "necessary. All other traffic is specifically denied.",
            _PCI_SRC),
        "1.4.2": Control(
            "Inbound traffic from untrusted networks to trusted networks is restricted",
            "Inbound traffic from untrusted networks to trusted networks is restricted to: "
            "Communications with system components that are authorized to provide publicly "
            "accessible services, protocols, and ports. Stateful responses to communications "
            "initiated by system components in a trusted network. All other traffic is denied.",
            _PCI_SRC),
        "2.2.1": Control(
            "Configuration standards are consistent with vendor hardening recommendations",
            "Configuration standards are developed, implemented, and maintained to: Cover all "
            "system components. Address all known security vulnerabilities. Be consistent with "
            "industry-accepted system hardening standards or vendor hardening recommendations. "
            "Be updated as new vulnerability issues are identified, as defined in Requirement "
            "6.3.1. Be applied when new systems are configured and verified as in place before "
            "or immediately after a system component is connected to a production environment.",
            _PCI_SRC),
        "2.2.2": Control(
            "Vendor default accounts are removed, disabled, or have changed passwords",
            "Vendor default accounts are managed as follows: If the vendor default account(s) "
            "will be used, the default password is changed per Requirement 8.3.6. If the vendor "
            "default account(s) will not be used, the account is removed or disabled.",
            _PCI_SRC),
        "2.2.4": Control(
            "Only necessary services, protocols, daemons, and functions are enabled",
            "Only necessary services, protocols, daemons, and functions are enabled, and all "
            "unnecessary functionality is removed or disabled.",
            _PCI_SRC),
        "2.2.5": Control(
            "Insecure services have documented justification and mitigating features",
            "If any insecure services, protocols, or daemons are present: Business justification "
            "is documented. Additional security features are documented and implemented that "
            "reduce the risk of using insecure services, protocols, or daemons.",
            _PCI_SRC),
        "2.2.6": Control(
            "System security parameters are configured to prevent misuse",
            "System security parameters are configured to prevent misuse.",
            _PCI_SRC),
        "2.2.7": Control(
            "Non-console administrative access is encrypted with strong cryptography",
            "All non-console administrative access is encrypted using strong cryptography.",
            _PCI_SRC),
        "4.2.1": Control(
            "Strong cryptography safeguards PAN over open, public networks",
            "Strong cryptography and security protocols are implemented as follows to safeguard "
            "PAN during transmission over open, public networks: Only trusted keys and "
            "certificates are accepted. Certificates used to safeguard PAN during transmission "
            "over open, public networks are confirmed as valid and are not expired or revoked. "
            "The protocol in use supports only secure versions or configurations and does not "
            "support fallback to, or use of insecure versions, algorithms, key sizes, or "
            "implementations. The encryption strength is appropriate for the encryption "
            "methodology in use.",
            _PCI_SRC),
        "7.2.1": Control(
            "An access control model with least privilege is defined",
            "An access control model is defined and includes granting access as follows: "
            "Appropriate access depending on the entity's business and access needs. Access to "
            "system components and data resources that is based on users' job classification and "
            "functions. The least privileges required (for example, user, administrator) to "
            "perform a job function.",
            _PCI_SRC),
        "7.2.5": Control(
            "Application and system accounts have least privilege",
            "All application and system accounts and related access privileges are assigned and "
            "managed as follows: Based on the least privileges necessary for the operability of "
            "the system or application. Access is limited to the systems, applications, or "
            "processes that specifically require their use.",
            _PCI_SRC),
        "7.2.5.1": Control(
            "Application and system account access is reviewed periodically",
            "All access by application and system accounts and related access privileges are "
            "reviewed as follows: Periodically (at the frequency defined in the entity's targeted "
            "risk analysis).",
            _PCI_SRC),
        "8.3.1": Control(
            "User access is authenticated with at least one authentication factor",
            "All user access to system components for users and administrators is authenticated "
            "via at least one of the following authentication factors: Something you know; "
            "Something you have; Something you are.",
            _PCI_SRC),
        "8.3.2": Control(
            "Authentication factors are unreadable in transit and storage",
            "Strong cryptography is used to render all authentication factors unreadable during "
            "transmission and storage on all system components.",
            _PCI_SRC),
        "8.6.3": Control(
            "Application and system account passwords are protected against misuse",
            "Passwords/passphrases for any application and system accounts are protected against "
            "misuse as follows: Passwords/passphrases are changed periodically (at the frequency "
            "defined in the entity's targeted risk analysis, which is performed according to all "
            "elements specified in Requirement 12.3.1) and upon suspicion or confirmation of "
            "compromise. Passwords/passphrases are constructed with sufficient complexity "
            "appropriate for how frequently the entity changes the passwords/passphrases.",
            _PCI_SRC),
    },

    # DORA articles are *principles*, not testable controls — there is no "DORA 9.4.3" the way
    # there is a "PCI 8.6.2". Compliance is assessed against the entity's own Art. 6 ICT risk
    # management framework, so these rows are evidence feeding that framework, never a pass/fail
    # against the Regulation. The requirement text here is the research's paraphrase of Art. 9,
    # not verbatim OJ text (the EUR-Lex fetch truncated) — do not present it as a quotation.
    DORA: {
        "Art.9(2)": Control(
            "Protection and prevention — data security at rest, in use, and in transit",
            "Financial entities shall design, procure and implement ICT security policies, "
            "procedures, protocols and tools that ensure resilience, continuity and availability "
            "and maintain high standards of data security for data at rest, in use, or in "
            "transit. (Paraphrase of Art. 9(2) — not verbatim OJ text.)",
            _DORA_SRC),
        "Art.9(3)": Control(
            "Protection and prevention — securing the means of data transfer",
            "ICT solutions shall secure the means of data transfer, reduce the risk of corruption "
            "or loss of data and unauthorised access, and prevent breaches of confidentiality. "
            "(Paraphrase of Art. 9(3) — not verbatim OJ text.)",
            _DORA_SRC),
        "Art.9(4)": Control(
            "Protection and prevention — access control, strong authentication, network management",
            "Financial entities shall implement, among others: a network and infrastructure "
            "management structure using appropriate techniques; access control policies limiting "
            "physical and logical access to approved functions only; strong authentication "
            "mechanisms based on relevant standards, with protection of cryptographic keys; and "
            "documented patch and change management policies. (Paraphrase of Art. 9(4) — not "
            "verbatim OJ text.)",
            _DORA_SRC),
    },

    # NIS2 is a Directive: the binding text is 27 national laws, not the Directive itself. These
    # rows cite the Directive's Art. 21(2) points as a stable internal spine — the UI must say so
    # rather than imply the tenant is measured against this text. Lowest-fidelity framework here.
    NIS2: {
        "21(2)(e)": Control(
            "Security in acquisition, development and maintenance, incl. vulnerability handling",
            "security in network and information systems acquisition, development and "
            "maintenance, including vulnerability handling and disclosure",
            _NIS2_SRC),
        "21(2)(g)": Control(
            "Basic cyber hygiene practices and cybersecurity training",
            "basic cyber hygiene practices and cybersecurity training",
            _NIS2_SRC),
        "21(2)(h)": Control(
            "Policies and procedures regarding cryptography and encryption",
            "policies and procedures regarding the use of cryptography and, where appropriate, "
            "encryption",
            _NIS2_SRC),
        "21(2)(i)": Control(
            "Human resources security, access control policies and asset management",
            "human resources security, access control policies and asset management",
            _NIS2_SRC),
    },

    # HIPAA note that must survive into the UI: encryption here is *Addressable*, not Required.
    # A covered entity may document why a specification is not reasonable and implement an
    # equivalent alternative. So we map transit findings to the Required 164.312(e)(1) standard
    # and cite (e)(2)(ii) as the addressable spec — never a flat "HIPAA violation".
    HIPAA: {
        "164.312(a)(1)": Control(
            "Access control — access limited to authorized persons or software programs",
            "Implement technical policies and procedures for electronic information systems that "
            "maintain electronic protected health information to allow access only to those "
            "persons or software programs that have been granted access rights.",
            _HIPAA_SRC),
        "164.312(d)": Control(
            "Person or entity authentication",
            "Implement procedures to verify that a person or entity seeking access to electronic "
            "protected health information is the one claimed.",
            _HIPAA_SRC),
        "164.312(e)(1)": Control(
            "Transmission security",
            "Implement technical security measures to guard against unauthorized access to "
            "electronic protected health information that is being transmitted over an electronic "
            "communications network.",
            _HIPAA_SRC),
    },

    # The strongest claims in this file. A spec MUST is not a mapping — it is the target's own
    # normative text, checked directly. No scope gate applies: the MCP spec binds every MCP
    # server regardless of PAN, ePHI, or sector.
    MCP_SPEC: {
        "authorization/protected-resource-metadata": Control(
            "Servers must implement OAuth 2.0 Protected Resource Metadata (RFC 9728)",
            "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728). The "
            "Protected Resource Metadata document MUST include the authorization_servers field "
            "containing at least one authorization server.",
            _MCP_SRC),
        "authorization/server-discovery": Control(
            "Authorization server metadata must be discoverable",
            "MCP clients MUST follow the mandated discovery probe order using OAuth 2.0 "
            "Authorization Server Metadata (RFC 8414) or OpenID Connect Discovery; a server "
            "whose authorization server metadata cannot be discovered cannot be used as "
            "specified.",
            _MCP_SRC),
        "authorization/pkce": Control(
            "PKCE must be supported, advertised, and use S256",
            "MCP clients MUST implement PKCE and MUST verify PKCE support before proceeding, and "
            "MUST use the S256 code challenge method when technically capable.",
            _MCP_SRC),
    },
}


def _ref(framework: str, control_id: str, **kw) -> ControlRef:
    """Build a ControlRef, taking title/requirement from the catalogue so the control's text
    lives in exactly one place. KeyError here is the point: a mapping to a control we do not
    carry must fail at import, not produce a row citing nothing."""
    c = CONTROL_CATALOGUE[framework][control_id]
    return ControlRef(framework, control_id, c.title, c.requirement, **kw)


# ── Gates ─────────────────────────────────────────────────────────────────
# Asset scope tags a ControlRef.gate may require. These come from the asset/tenant, never from
# the detector. NOTE: no connector emits these labels yet and the schema has no column for
# them, so today every gated (confidence B) ref is dropped and only the ungated A mappings
# fire. That is the correct failure direction — silence, not a false claim — but it means
# HIPAA and PCI 4.2.1 produce nothing until scope labelling exists.
GATE_PAN = "pan"                    # asset stores/transmits cardholder data
GATE_EPHI = "ephi"                  # asset stores/transmits ePHI
GATE_PUBLIC_FACING = "public_facing"  # reachable from an untrusted/public network
GATE_HUMAN_USERS = "human_users"    # consumed by people, not services
GATE_MACHINE_CLIENTS = "machine_clients"  # consumed by services, not people


# ── RULE_TO_CONTROLS ──────────────────────────────────────────────────────
# Keys are exact rule_ids, or family prefixes ending in '.' (a prefix lets a new detector in a
# researched family inherit its family's controls instead of silently mapping to nothing).
# Exact keys win over prefixes; the longest prefix wins among prefixes.
RULE_TO_CONTROLS: dict[str, tuple[ControlRef, ...]] = {

    # ── Kafka: transport ──────────────────────────────────────────────────
    "KAFKA.LISTENER.PLAINTEXT": (
        _ref(PCI, "2.2.5"),   # a plaintext listener is the paradigm "insecure service present"
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.5"),
        _ref(PCI, "1.2.6"),
        # 4.2.1 is scoped to PAN over *open, public networks*. An internal broker on a private
        # subnet is out of scope however bad the config is. Mapping it unconditionally is the
        # most common error in this space and a QSA will catch it.
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING),
             note="Only applies where the listener is internet-reachable and the topics carry "
                  "PAN. Confirm both before asserting."),
        _ref(DORA, "Art.9(2)", relation="supports", confidence="B"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii); a documented equivalent "
                  "alternative satisfies the Required (e)(1) standard."),
    ),
    # The rule *is* 8.3.2's gate: SASL_PLAINTEXT means the credential itself crosses the wire in
    # the clear, so what is conditional for a bare PLAINTEXT listener is unconditional here.
    "KAFKA.LISTENER.SASL_PLAINTEXT": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii)."),
    ),
    "KAFKA.INTERBROKER.PLAINTEXT": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii)."),
    ),
    # SASL mechanisms whose credentials are exposed without TLS. 8.3.2's "unreadable during
    # transmission" is exactly this, and needs no gate — the rule already proves the condition.
    "KAFKA.SASL.PLAIN_WITHOUT_TLS": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    "KAFKA.SASL.SCRAM_WITHOUT_TLS": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    "KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "7.2.1"),  # an unsecured JWT is an unverified principal: no enforceable model
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B",
             note="Art. 9(4) requires strong authentication 'based on relevant standards'; an "
                  "unsecured JWT is the standard's own explicitly non-production mode."),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    # 4.2.1's first bullet — "Only trusted keys and certificates are accepted" — is squarely
    # about verification, which is what these two rules read. Still gated: 4.2.1's scope words
    # are PAN over open, public networks, and that is not a property of the TLS config.
    "KAFKA.SSL.HOSTNAME_VERIFICATION_DISABLED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING),
             note="4.2.1 requires that only trusted, valid certificates are accepted; scope is "
                  "PAN over open, public networks."),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    "KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "7.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),

    # ── Kafka: authorization ──────────────────────────────────────────────
    # 7.2.5 is VectaSec's requirement: it is written about non-human identities, which is exactly
    # what a Kafka principal is. 7.2.2 is deliberately absent — its text says "users" and "job
    # classification", and a Kafka principal is a service. See NOT_MAPPED.
    "KAFKA.AUTHZ.NO_AUTHORIZER": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,),
             note="164.312(a)(1) reaches machine identity natively — 'persons or software "
                  "programs that have been granted access rights'."),
    ),
    "KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL": (
        _ref(PCI, "2.2.6"),  # the definitional misuse-enabling security parameter
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
    ),
    # Family prefix: 7.2.5's "Access is limited to the systems, applications, or processes that
    # specifically require their use" is the negation of a wildcard ACL, sentence for sentence.
    # The single best rule→control fit in the whole mapping.
    "KAFKA.ACL.": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1", confidence="B",
             note="Defensible where the ACL grants admin-equivalent cluster rights."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "KAFKA.ACL.ANONYMOUS_PRINCIPAL": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1"),
        _ref(PCI, "8.3.1", confidence="B", gate=(GATE_HUMAN_USERS,),
             note="8.3.1 is written about user access; assert only where the principal fronts "
                  "human access."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),

    # ── Kafka: ZooKeeper legacy mode ──────────────────────────────────────
    "KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    "KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES": (
        _ref(PCI, "7.2.1"),   # cluster metadata with no access control model behind it
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),

    # ── Kafka: topics ─────────────────────────────────────────────────────
    "KAFKA.TOPIC.AUTO_CREATE_ENABLED": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.4"),   # unnecessary functionality enabled by default
        _ref(PCI, "2.2.1"),
    ),

    # ── Kong: admin plane ─────────────────────────────────────────────────
    # 2.2.1 carries these: Kong's own docs say to "avoid using values such as 0.0.0.0:8001",
    # so the vendor's sentence is the evidence. This is the mapping that generalises across
    # every connector we will ever write.
    "KONG.ADMIN.LISTEN_WILDCARD": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(PCI, "2.2.4", confidence="B",
             note="Applies where the admin listener need not be remotely bound."),
        _ref(PCI, "1.3.1", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(PCI, "1.4.2", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    # 2.2.7's home turf. It says *non-console administrative* access — the Kong Admin API over
    # HTTP is the textbook instance, unlike a data-plane listener.
    "KONG.ADMIN.PLAINTEXT_LISTENER": (
        _ref(PCI, "2.2.7"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    "KONG.ADMIN.UNAUTHENTICATED": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "8.3.1", confidence="B", gate=(GATE_HUMAN_USERS,),
             note="8.3.1 covers user and administrator access; assert where the Admin API is "
                  "human-operated."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "KONG.RBAC.DISABLED": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),

    # ── Kong: data plane ──────────────────────────────────────────────────
    # 6.4.2 is deliberately absent: it is a WAF requirement, not an auth requirement. See
    # NOT_MAPPED — this is the single most common mis-mapping in the category.
    "KONG.ROUTE.NO_AUTH_PLUGIN": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "7.2.5", confidence="B", gate=(GATE_MACHINE_CLIENTS,)),
        _ref(PCI, "1.2.5", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(PCI, "8.3.1", confidence="B", gate=(GATE_HUMAN_USERS,)),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "KONG.AUTH.ANONYMOUS_FALLBACK": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),
    # An identity that exists but cannot authenticate is an unreviewed identity: 7.2.5.1's
    # periodic-review requirement is the honest home, and our inventory *is* the review artifact.
    "KONG.CONSUMER.NO_CREDENTIALS": (
        _ref(PCI, "7.2.5.1", relation="supports"),
        _ref(PCI, "7.2.5", confidence="B",
             note="Assert where the credential-less consumer is reachable via an anonymous "
                  "fallback rather than merely dormant."),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    "KONG.ROUTE.HTTP_PROTOCOL_ALLOWED": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING)),
        _ref(DORA, "Art.9(2)", relation="supports", confidence="B"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii)."),
    ),
    "KONG.CORS.WILDCARD_WITH_CREDENTIALS": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "7.2.1", confidence="B",
             note="Assert where the route's credentials carry authorization decisions."),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    "KONG.PLUGIN.SECURITY_PLUGIN_DISABLED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    "KONG.ROUTE.WILDCARD_HOST_OR_PRESERVE_HOST": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
    ),

    # ── Kong / RabbitMQ: known vulnerabilities ────────────────────────────
    # 2.2.1 (not 6.3.x) is the hook: its own text requires configuration standards that "Address
    # all known security vulnerabilities" and "Be updated as new vulnerability issues are
    # identified". 6.3.x text was never fetched in the research pass, so it is not cited here.
    "KONG.VERSION.": (
        _ref(PCI, "2.2.1"),
        _ref(NIS2, "21(2)(e)", relation="supports"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B",
             note="Art. 9(4) requires documented patch management policies."),
    ),
    "RABBITMQ.VERSION.": (
        _ref(PCI, "2.2.1"),
        _ref(NIS2, "21(2)(e)", relation="supports"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
    ),
    "RABBITMQ.CVE.": (
        _ref(PCI, "2.2.1"),
        _ref(NIS2, "21(2)(e)", relation="supports"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
    ),

    # ── RabbitMQ: default credentials ─────────────────────────────────────
    # 2.2.2 is the cleanest mapping in the whole file — the requirement was written for exactly
    # this, and RabbitMQ's own docs say production "should not use the default user".
    "RABBITMQ.USER.DEFAULT_GUEST_PRESENT": (
        _ref(PCI, "2.2.2"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.4", confidence="B",
             note="'Unnecessary functionality is removed or disabled' — assert once the guest "
                  "account is established as unused."),
        _ref(NIS2, "21(2)(g)", relation="supports"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    "RABBITMQ.USER.GUEST_DEFAULT_PASSWORD_REMOTE": (
        _ref(PCI, "2.2.2"),
        _ref(PCI, "2.2.1"),
        # 8.6.3 has no interactive-login qualifier, unlike 8.6.1/8.6.2 — it is the right and
        # safest 8.6.x hook for a middleware service account. A password of 'guest' fails its
        # complexity clause on its face.
        _ref(PCI, "8.6.3"),
        _ref(PCI, "1.2.5"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(g)", relation="supports"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,),
             note="A shared, world-known default defeats 'verify that a person or entity ... is "
                  "the one claimed'."),
    ),
    "RABBITMQ.USER.GUEST_REMOTE_LOGIN": (
        _ref(PCI, "2.2.2"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.5"),
        _ref(NIS2, "21(2)(g)", relation="supports"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),
    # A vhost is not an account, so 2.2.2 does not reach it however tempting. Vendor hardening
    # guidance does — 2.2.1 alone.
    "RABBITMQ.VHOST.DEFAULT_VHOST_IN_USE": (
        _ref(PCI, "2.2.1"),
    ),

    # ── RabbitMQ: authn / authz ───────────────────────────────────────────
    "RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "RABBITMQ.PERMISSION.": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1", confidence="B",
             note="Defensible where the permission grants admin-equivalent rights."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "RABBITMQ.USER.ADMIN_TAG_SPRAWL": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.5.1", relation="supports"),
        _ref(PCI, "7.2.1", confidence="B"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
    ),
    # 8.3.2's text is "unreadable during transmission AND STORAGE" — the storage clause makes
    # this ungated and direct.
    "RABBITMQ.USER.WEAK_PASSWORD_HASHING": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),

    # ── RabbitMQ: transport ───────────────────────────────────────────────
    "RABBITMQ.LISTENER.AMQP_PLAINTEXT": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING)),
        _ref(DORA, "Art.9(2)", relation="supports", confidence="B"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii)."),
    ),
    "RABBITMQ.MGMT.HTTP_API_NO_TLS": (
        _ref(PCI, "2.2.7"),   # the management API is non-console administrative access
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    "RABBITMQ.TLS.PEER_VERIFICATION_DISABLED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING),
             note="4.2.1 requires that only trusted, valid certificates are accepted."),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
    ),
    # Peer verification off while x509 *is* the authentication mechanism is an authn failure,
    # not merely a TLS hygiene one: the certificate is the credential.
    "RABBITMQ.TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "RABBITMQ.CLUSTER.DIST_PORT_EXPOSED": (
        _ref(PCI, "1.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.4", confidence="B"),
        _ref(PCI, "1.3.1", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(PCI, "1.4.2", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),

    # ── MCP: spec conformance ─────────────────────────────────────────────
    # These cite the target's own normative text. A MUST violation is a stronger and cleaner
    # claim than any framework mapping in this file — no gate, no confidence discount.
    "MCP.AUTH.PRM_MISSING_OR_MISMATCHED": (
        _ref(MCP_SPEC, "authorization/protected-resource-metadata"),
    ),
    "MCP.AUTH.AS_METADATA_UNDISCOVERABLE": (
        _ref(MCP_SPEC, "authorization/server-discovery"),
    ),
    "MCP.AUTH.PKCE_S256_NOT_OFFERED": (
        _ref(MCP_SPEC, "authorization/pkce"),
    ),
    "MCP.AUTH.PKCE_METHODS_NOT_ADVERTISED": (
        _ref(MCP_SPEC, "authorization/pkce"),
    ),

    # ── MCP: authorization posture ────────────────────────────────────────
    # Authorization is OPTIONAL in MCP 2025-11-25, and STDIO servers SHOULD NOT implement it.
    # So an unauthenticated endpoint is not a spec violation — it is a framework question, and
    # only once the endpoint is remote and in scope. Hence gates, not a spec citation.
    "MCP.AUTH.UNAUTHENTICATED_ENDPOINT": (
        _ref(PCI, "7.2.1", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="Assert for HTTP-transport servers reachable from the CDE. A local STDIO "
                  "server without authorization conforms to the spec."),
        _ref(PCI, "2.2.5", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
    ),
    "MCP.AUTH.SCOPE_OVERBROAD": (
        _ref(PCI, "7.2.5", confidence="B",
             note="'Access is limited to the systems, applications, or processes that "
                  "specifically require their use' — assert once the token's grants are known "
                  "to exceed the server's need."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
    ),
    "MCP.TRANSPORT.PLAINTEXT_HTTP": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING)),
        _ref(DORA, "Art.9(2)", relation="supports", confidence="B"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii)."),
    ),
    "MCP.TRANSPORT.DEPRECATED_HTTP_SSE": (
        _ref(PCI, "2.2.1", confidence="B",
             note="Configuration-standard drift from the current MCP revision's transport."),
    ),
    "MCP.TRANSPORT.ORIGIN_UNVALIDATED": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
    ),
}


# ── NOT_MAPPED: the refusals, and why ─────────────────────────────────────
# These are load-bearing. Each entry is a mapping we could have made and a reason we did not.
# Keys follow the same exact-or-prefix convention; a NOT_MAPPED key beats a RULE_TO_CONTROLS
# prefix of equal or shorter length, so a family mapping added later cannot silently capture
# a rule we deliberately excluded.
NOT_MAPPED: dict[str, str] = {
    "MCP.TOOL.": (
        "No framework contemplates a model-facing tool description as an attack surface. PCI, "
        "DORA, NIS2 and the current HIPAA Security Rule all predate the threat. NIS2 21(2)(e) "
        "is the least-bad fit and is still a stretch. This family has real security value and "
        "no compliance value, and the product should say so rather than issue a badge — "
        "forcing a mapping here is what would discredit 7.2.5, 2.2.2 and 8.3.2."
    ),
    "MCP.SERVER.INSTRUCTIONS_INJECTION": (
        "Same as MCP.TOOL.*: prompt injection via server instructions has no control text "
        "anywhere in the four frameworks."
    ),
    "MCP.SESSION.": (
        "The research pass verified the MCP spec's authorization MUSTs (PRM, audience "
        "validation, token passthrough, PKCE) but not its session-handling clauses. Citing "
        "MCP_SPEC_2025_11_25 for session rules would be an unverified quotation. Map these "
        "once the spec's session text is fetched and quoted."
    ),
    "MCP.TRANSPORT.PROTOCOL_VERSION_UNVALIDATED": (
        "Only 2.2.1 could carry it, and 'configuration standards' is too thin a thread for a "
        "protocol-negotiation bug. Security finding, not a compliance finding."
    ),
    "MCP.TOOL.INPUTSCHEMA_INVALID": (
        "A malformed schema is a correctness defect, not a control failure."
    ),
    "KAFKA.DURABILITY.": (
        "min.insync.replicas=1 and unclean leader election are data-loss risks, and DORA "
        "Art. 9(2) (resilience/availability), NIS2 21(2)(c) (business continuity) and HIPAA "
        "164.312(c)(1) (integrity — 'improper alteration or destruction') are all plausible. "
        "But the research pass never covered a durability family, so every one of those would "
        "be our inference rather than a sourced mapping. Worth researching — it is the "
        "clearest gap in the table."
    ),
    "KAFKA.TOPIC.RETENTION_UNBOUNDED": (
        "The real fit is PCI 3.x (keep cardholder data storage to a minimum), whose text was "
        "never fetched. Do not cite 3.x without it. 2.2.1 would be a hardening-standard "
        "stretch — unbounded retention is a data-lifecycle decision, not a hardening deviation."
    ),
    "KONG.ROUTE.NO_RATE_LIMITING": (
        "Availability hardening with no researched control. 6.4.2 is a WAF requirement, not a "
        "rate-limit one. Do not reach for 2.2.1 here: Kong does not document rate limiting as "
        "a security hardening default."
    ),
    "KONG.ROUTE.NO_REQUEST_SIZE_LIMIT": (
        "Same as KONG.ROUTE.NO_RATE_LIMITING."
    ),
    "KONG.RATELIMIT.FAIL_OPEN": (
        "Directionally DORA Art. 9(2) (availability) and PCI 2.2.6, but fail-open rate limiting "
        "is a resilience property the research never mapped. Left unmapped pending research."
    ),
    "RABBITMQ.SCAN.NOT_ASSESSABLE": (
        "A coverage signal, not a control failure — the scan could not read the target. "
        "Mapping it would fail controls on the strength of our own blind spot. evaluate() uses "
        "it in the opposite direction: it withdraws the family's PASS signal (see _covered)."
    ),
}

# Mappings the research rated C (stretch) and this file therefore omits, kept as prose so the
# refusal is reviewable rather than invisible:
#
#   • 7.2.2 for every Kafka ACL / RabbitMQ permission rule — its text is "users" and "job
#     classification"; a broker principal is a service. 7.2.5 says what we actually mean.
#   • 8.2.1 / 8.3.1 for machine-identity rules — both say "users". Only asserted behind
#     GATE_HUMAN_USERS.
#   • 8.2.2 (shared/generic IDs) for wildcard ACLs — we can rarely prove sharing from broker
#     config alone.
#   • 2.2.7 for data-plane PLAINTEXT listeners — 2.2.7 is "non-console administrative access";
#     application traffic is not administrative access. Only mapped for the Kong Admin API and
#     the RabbitMQ management API.
#   • 6.4.2 for KONG.ROUTE.NO_AUTH_PLUGIN — 6.4.2 is a WAF/RASP requirement. A route with no
#     auth plugin is an access-control failure, not a missing-WAF failure. 6.4.2 needs a
#     KONG.WAF.MISSING rule that does not exist yet.
#   • 8.6.1 / 8.6.2 for RabbitMQ default creds — both are gated on "can be used for interactive
#     login", which we do not establish. 8.6.3 carries it instead.
#   • NIS2 21(2)(j) (MFA) for any machine-identity rule — MFA is a human concept. A frequent
#     vendor overreach.
#   • NIS2 21(2)(d) (supply chain) for MCP rules — its text says "direct suppliers"; a chained
#     MCP server is arguably not one.
#   • PCI 6.2.4 / 6.3.x for CVE and MCP rules — text never fetched. 2.2.1's "Address all known
#     security vulnerabilities" carries version findings instead.
#   • DORA Art. 8 / Art. 28(3) for MCP inventory — relation is `informs`, not `violates`. An
#     informing finding must never fail a control, so it has no place in RULE_TO_CONTROLS.
#     These belong in the Art. 28 register-reconciliation feature, not the controls table.

# Controls we would map today if the rule existed. Recorded here because the gap is the
# actionable output: each is an audited requirement with no detector behind it.
MISSING_RULES: dict[str, str] = {
    "*.SECRET.HARDCODED": (
        "PCI 8.6.2 — 'not hard coded in scripts, configuration/property files, or bespoke and "
        "custom source code' describes a credential in connect-distributed.properties, kong.yml, "
        "an MCP manifest or a compose file, verbatim. Mandatory since 31 March 2025. Highest-"
        "value missing rule in the product."
    ),
    "KONG.WAF.MISSING": (
        "PCI 6.4.2 — public-facing route with no WAF-class plugin in its chain. Mandatory since "
        "31 March 2025, answerable from Kong's plugin chain, and currently no rule legitimately "
        "maps to 6.4.2."
    ),
    "*.AUDIT.DISABLED": (
        "PCI 10.2.1 / 10.2.1.2 — 10.x is under-served. 10.2.1.2's 'including any interactive "
        "use of application or system accounts' pairs naturally with the 8.6.x narrative."
    ),
}


def _lookup(mapping: dict, rule_id: str) -> Optional[tuple]:
    """Exact key, else the longest matching prefix key. Returns (key, value) or None."""
    if rule_id in mapping:
        return rule_id, mapping[rule_id]
    best = None
    for key, value in mapping.items():
        if key.endswith(".") and rule_id.startswith(key):
            if best is None or len(key) > len(best[0]):
                best = (key, value)
    return best


def controls_for(rule_id: str) -> tuple[ControlRef, ...]:
    """Every control this rule may be asserted against, before gating."""
    hit = _lookup(RULE_TO_CONTROLS, rule_id)
    refused = _lookup(NOT_MAPPED, rule_id)
    # A deliberate refusal beats an equally- or less-specific family mapping, so adding a
    # broad prefix later cannot resurrect a mapping we rejected on the record.
    if refused and (hit is None or len(refused[0]) >= len(hit[0])):
        return ()
    return hit[1] if hit else ()


# ── Evaluation ────────────────────────────────────────────────────────────
# A finding in any of these states is an unremediated problem on the asset. `accepted` is
# included deliberately: accepting a risk is a business decision, not a remediation, and a QSA
# does not care that the entity decided to live with it. `suppressed` and `resolved` are
# excluded — suppression is the tenant's explicit "do not evaluate this" and carries a
# mandatory reason; resolved means fixed.
OPEN_STATUSES = ("open", "triaged", "in_progress", "accepted")

FRAMEWORKS = tuple(CONTROL_CATALOGUE)


def _scope_tags(labels: Optional[dict], tenant_tags: frozenset) -> frozenset:
    """Scope tags for one asset: tenant-wide defaults plus whatever the resource is labelled.

    Scope is a property of the asset and the tenant, never of the rule — which is why this
    reads labels and not the detector. Nothing emits these labels yet; see the GATE_* note.
    """
    tags = set(tenant_tags)
    for key in ("scope", "scope_tags"):
        value = (labels or {}).get(key)
        if isinstance(value, list):
            tags.update(str(v) for v in value)
        elif isinstance(value, str):
            tags.add(value)
    return frozenset(tags)


def _family(rule_id: str) -> str:
    return rule_id.split(".")[0].lower()


def _covered(cur, tenant_id: str) -> set:
    """Connector families we have actually scanned cleanly — the only families about which an
    absence of findings means anything at all.

    A family with an open *.SCAN.NOT_ASSESSABLE finding is withdrawn: the scan ran but could
    not read the target, so silence there is our blind spot, not the tenant's good hygiene.
    """
    cur.execute(
        """select distinct c.type from connections c
             join scans s on s.connection_id = c.id
           where c.tenant_id = %s and s.status = 'done'""",
        (tenant_id,),
    )
    families = {r[0].lower() for r in cur.fetchall()}

    cur.execute(
        """select distinct rule_id from findings
           where tenant_id = %s and status = any(%s) and rule_id like '%%.SCAN.NOT_ASSESSABLE'""",
        (tenant_id, list(OPEN_STATUSES)),
    )
    for (rule_id,) in cur.fetchall():
        families.discard(_family(rule_id))
    return families


def _current_attestations(cur, tenant_id: str, declared) -> set:
    """(framework, control_id) pairs carrying a LIVE (unexpired) human attestation.

    This is the only input that can produce a `pass`. An expired attestation is silently
    ignored — a sign-off is a point-in-time statement, not a permanent one.
    """
    cur.execute(
        """select framework, control_id from control_attestations
           where tenant_id = %s and (expires_at is null or expires_at > now())""",
        (tenant_id,),
    )
    pairs = {(fw, cid) for fw, cid in cur.fetchall()}
    if declared is not None:
        pairs = {(fw, cid) for (fw, cid) in pairs if fw in declared}
    return pairs


def attest(cur, tenant_id: str, framework: str, control_id: str, attested_by: str,
           scope: str, note=None, evidence_ref=None, expires_at=None) -> dict:
    """Record a human's sign-off that a control is met, then re-evaluate so the pass shows at once.

    This is the mechanism the evaluate() docstring used to say did not exist. It does not weaken
    the no-pass-from-silence contract: a live *assessed* failing finding still overrides the
    attestation (evaluate(): fail beats attestation), so this can only move an otherwise
    clean-or-unknown control to `pass`. `scope` is REQUIRED — an attestation that does not say
    what was attested, over which systems and period, is not an attestation.

    Runs on the caller's cursor and does not commit — the API layer owns the transaction so the
    attestation row and the recomputed controls land together and an audit_log row joins them.
    """
    if not scope or not str(scope).strip():
        raise ValueError("attestation requires a scope")
    if framework not in CONTROL_CATALOGUE or control_id not in CONTROL_CATALOGUE[framework]:
        raise ValueError(f"unknown control {framework}:{control_id}")
    cur.execute(
        """insert into control_attestations
             (tenant_id, framework, control_id, attested_by, scope, note, evidence_ref, expires_at)
           values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s) returning id""",
        (tenant_id, framework, control_id, attested_by, scope, note,
         json.dumps(evidence_ref or {}), expires_at),
    )
    att_id = cur.fetchone()[0]
    result = evaluate(cur, tenant_id)
    return {"attestation_id": str(att_id), "framework": framework,
            "control_id": control_id, "status": _status_of(result, framework, control_id)}


def _status_of(evaluation: dict, framework: str, control_id: str) -> Optional[str]:
    """Pull one control's freshly-computed status out of an evaluate() result for the API reply."""
    return evaluation.get("statuses", {}).get(f"{framework}:{control_id}")


def evaluate(cur, tenant_id: str, *, frameworks=None, scope_tags=()) -> dict:
    """Recompute the controls table for a tenant from current open findings.

    Runs on a caller-supplied cursor and does not commit — the caller owns the transaction, so
    a controls table can be recomputed inside the same transaction as the scan that changed it.

    frameworks  — the frameworks the tenant is actually subject to. Controls of any other
                  framework are written as `not_applicable`, which is what that status is for:
                  a PLAINTEXT listener at a US-only non-financial company breaches no EU
                  regulation. None means "we have not been told", and we then evaluate all
                  frameworks rather than invent a scope.
    scope_tags  — tenant-wide asset scope tags ('pan', 'ephi', 'public_facing', ...). Resource
                  labels add to these per asset. Gated refs whose tags are absent are dropped,
                  so an unconfirmed scope produces silence rather than a false claim.

    This function never writes `pass`. The original spec for it asked for "passes if evaluated
    and none do", and the research this mapping is built from (docs/research/compliance-mapping.md
    §0 Rule 1) forbids exactly that: PCI 7.2.5 covers every application and system account in the
    CDE, and we see only the brokers we scanned, so no hit on those brokers is not evidence the
    control is met. A `pass` derived that way is a claim we cannot support and is the specific
    thing the research says gets a vendor thrown out of an audit.

    `pass` enters the table by exactly ONE path: a live human attestation (control_attestations,
    written by attest()). A clean scan never writes `pass` on its own — the research this mapping
    is built from (docs/research/compliance-mapping.md §0 Rule 1) forbids it: PCI 7.2.5 covers
    every application and system account in the CDE, and we see only the brokers we scanned, so no
    hit on those brokers is not evidence the control is met. The attestation is a person taking
    responsibility for that gap, with a stated scope, and a live *assessed* failing finding still
    overrides it (fail beats attestation) — so a `pass` here always means "no current evidence of
    failure, and a human signed for the coverage." A control with scan coverage and no failing
    finding but no attestation stays `unknown`, the honest answer; `covered_families` reports
    where we actually looked.
    """
    declared = frozenset(frameworks) if frameworks is not None else None
    tenant_tags = frozenset(scope_tags)

    cur.execute(
        """select f.id, f.rule_id, coalesce(r.labels, '{}'::jsonb), f.assessment
           from findings f
             left join resources r on r.id = f.resource_id
           where f.tenant_id = %s and f.status = any(%s)""",
        (tenant_id, list(OPEN_STATUSES)),
    )
    open_findings = cur.fetchall()

    # A finding maps to a control as one of two things, never conflated:
    #   • assessment='assessed'       => it FAILS the control (real evidence of a violation).
    #   • assessment='not_assessable' => it could not be checked, so it can only make the control
    #     UNKNOWN, never fail it. Failing a control on our own blind spot is the exact dishonesty
    #     findings.assessment exists to prevent (STATUS.md gap 19).
    # Both buckets are keyed (framework, control_id) with stable-sorted ids for a stable diff.
    failing: dict = {}
    unknown: dict = {}
    for finding_id, rule_id, labels, assessment in open_findings:
        tags = _scope_tags(labels, tenant_tags)
        bucket = unknown if assessment == "not_assessable" else failing
        for ref in controls_for(rule_id):
            if declared is not None and ref.framework not in declared:
                continue
            # An unsatisfied gate is not a soft signal — it means the control's own scope words
            # do not reach this asset, so the ref says nothing about it.
            if any(g not in tags for g in ref.gate):
                continue
            bucket.setdefault((ref.framework, ref.control_id), []).append(str(finding_id))

    covered = _covered(cur, tenant_id)
    attested = _current_attestations(cur, tenant_id, declared)

    counts = {"fail": 0, "pass": 0, "unknown": 0, "not_applicable": 0}
    statuses: dict[str, str] = {}   # "framework:control_id" -> status, for attest()'s reply
    rows = 0
    for framework, controls in CONTROL_CATALOGUE.items():
        for control_id, control in controls.items():
            key = (framework, control_id)
            ids = sorted(set(failing.get(key, [])))
            unknown_ids = sorted(set(unknown.get(key, [])))

            if declared is not None and framework not in declared:
                status = "not_applicable"   # out of scope for this tenant: not "we don't know"
                ids = []
                unknown_ids = []
            elif ids:
                # An assessed violation. ALWAYS wins — even over a human attestation. You cannot
                # sign away a control the scanner can currently prove is broken (decision 1).
                status = "fail"
            elif key in attested:
                # The ONLY path to `pass`: a current, unexpired human attestation, on a control
                # with no assessed failure. A clean scan alone can never reach here.
                status = "pass"
            else:
                # Clean-but-unattested, or only not_assessable findings map here. Neither is
                # evidence the control is met, so both are `unknown` — the honest answer. Where we
                # actually looked is reported via `covered_families`, never as a result. Module
                # header, Rule 1.
                status = "unknown"

            cur.execute(
                """insert into controls
                     (tenant_id, framework, control_id, title, requirement, status,
                      failing_finding_ids, unknown_finding_ids, evaluated_at)
                   values (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb, now())
                   on conflict (tenant_id, framework, control_id) do update
                     set title               = excluded.title,
                         requirement         = excluded.requirement,
                         status              = excluded.status,
                         failing_finding_ids = excluded.failing_finding_ids,
                         unknown_finding_ids = excluded.unknown_finding_ids,
                         evaluated_at        = now()""",
                (tenant_id, framework, control_id, control.title, control.requirement,
                 status, json.dumps(ids), json.dumps(unknown_ids)),
            )
            counts[status] += 1
            statuses[f"{framework}:{control_id}"] = status
            rows += 1

    return {
        "controls": rows,
        "frameworks": sorted(declared) if declared is not None else sorted(FRAMEWORKS),
        "covered_families": sorted(covered),
        "open_findings": len(open_findings),
        "mapped_findings": sum(len(v) for v in failing.values()),
        "unassessable_findings": sum(len(v) for v in unknown.values()),
        **counts,
        "statuses": statuses,
        "failing": {f"{fw}:{cid}": ids for (fw, cid), ids in sorted(failing.items())},
    }
