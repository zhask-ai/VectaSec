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

Second provenance warning, same weight: the SOC 2 (AICPA TSC 2017, 2022 points of focus) and
ISO/IEC 27001:2022 Annex A rows below are *paraphrases*, not quotations. Both texts are
copyrighted and licensed (the TSC by the AICPA, ISO 27001 by ISO); neither was reproduced here.
`requirement` for those two frameworks states the control's title and intent in our own words
and says so inline. Before any customer-facing use the paraphrase must be checked against the
licensed text, and the UI must present it as a paraphrase, never as the criterion's wording.
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
# Licensed texts: the URL is where the document is obtained, not where its text was copied from.
_SOC2_SRC = ("https://www.aicpa-cima.com/resources/download/"
             "2017-trust-services-criteria-with-revised-points-of-focus-2022")
_ISO27001_SRC = "https://www.iso.org/standard/27001"

PCI = "PCI_DSS_4_0_1"
DORA = "DORA"
NIS2 = "NIS2"
HIPAA = "HIPAA"
MCP_SPEC = "MCP_SPEC_2025_11_25"   # pinned: MCP revisions move fast enough to invalidate detectors
SOC2 = "SOC2_TSC_2017"             # 2017 TSC with the 2022 revised points of focus
ISO27001 = "ISO_27001_2022"        # Annex A control ids follow the 2022 numbering


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

    # SOC 2 Trust Services Criteria (AICPA, 2017, with the 2022 revised points of focus).
    # PARAPHRASED, NOT QUOTED. The TSC is a licensed AICPA document and its text is not
    # reproduced here; each `requirement` restates the criterion's intent in our words and says
    # so. Check every row against the licensed TSC before customer-facing use (module header).
    # SOC 2 is also an *attestation* framework: the criteria are met by the service organisation's
    # own controls, so a failing row is evidence an auditor would weigh against a CC6/CC7 control,
    # not a verdict on the report. No asset gate — the tenant's framework declaration is scope.
    SOC2: {
        "CC6.1": Control(
            "Logical access security over protected information assets",
            "The entity implements logical access security software, infrastructure, and "
            "architectures over protected information assets to protect them from security "
            "events to meet its objectives. (Paraphrase of CC6.1 — not the TSC wording.)",
            _SOC2_SRC),
        "CC6.2": Control(
            "Registration, authorization and removal of system access",
            "Before issuing system credentials and granting access, the entity registers and "
            "authorizes new internal and external users; it removes access when a user's access "
            "is no longer authorized. (Paraphrase of CC6.2 — not the TSC wording.)",
            _SOC2_SRC),
        "CC6.3": Control(
            "Access is authorized, modified and removed on roles and least privilege",
            "The entity authorizes, modifies, or removes access to data, software, functions, and "
            "other protected information assets based on roles, responsibilities, or the system "
            "design and changes, giving consideration to least privilege and segregation of "
            "duties. (Paraphrase of CC6.3 — not the TSC wording.)",
            _SOC2_SRC),
        "CC6.6": Control(
            "Logical access security against threats from outside system boundaries",
            "The entity implements logical access security measures to protect against threats "
            "from sources outside its system boundaries. (Paraphrase of CC6.6 — not the TSC "
            "wording.)",
            _SOC2_SRC),
        "CC6.7": Control(
            "Transmission, movement and removal of information is restricted and protected",
            "The entity restricts the transmission, movement, and removal of information to "
            "authorized internal and external users and processes, and protects it during "
            "transmission, movement, or removal. (Paraphrase of CC6.7 — not the TSC wording.)",
            _SOC2_SRC),
        "CC7.1": Control(
            "Detection of configuration changes and newly discovered vulnerabilities",
            "The entity uses detection and monitoring procedures to identify changes to "
            "configurations that result in the introduction of new vulnerabilities, and "
            "susceptibilities to newly discovered vulnerabilities. (Paraphrase of CC7.1 — not "
            "the TSC wording.)",
            _SOC2_SRC),
        "CC7.2": Control(
            "Monitoring of system components for anomalies",
            "The entity monitors system components and their operation for anomalies that are "
            "indicative of malicious acts, natural disasters, and errors affecting its "
            "objectives, and analyzes anomalies to determine whether they are security events. "
            "(Paraphrase of CC7.2 — not the TSC wording.)",
            _SOC2_SRC),
    },

    # ISO/IEC 27001:2022 Annex A. PARAPHRASED, NOT QUOTED. The standard is ISO copyright and
    # sold under licence; only each control's title and intent are restated here, in our words,
    # and every row says so. Annex A controls are also *selected* via the entity's Statement of
    # Applicability — a row here is evidence against a control the SoA includes, not a verdict
    # against the certificate. Check against the licensed text before customer-facing use.
    # A.8.8 (technical vulnerability management) is the honest ISO home for the CVE/version
    # rules and is deliberately NOT in this catalogue yet: adding it means adding it to the
    # research doc first. Until then those rules carry SOC 2 CC7.1 only.
    ISO27001: {
        "A.5.15": Control(
            "Access control",
            "Rules to control physical and logical access to information and other associated "
            "assets are established and implemented based on business and information security "
            "requirements. (Paraphrase of A.5.15 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.5.16": Control(
            "Identity management",
            "The full life cycle of identities is managed; identities are assigned to a single "
            "person or entity, and shared identities are permitted only where necessary for "
            "business or operational reasons. (Paraphrase of A.5.16 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.5.17": Control(
            "Authentication information",
            "Allocation and management of authentication information is controlled by a "
            "management process, including protecting it in storage and in transit, changing "
            "default authentication information, and guidance on its proper handling. "
            "(Paraphrase of A.5.17 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.5.18": Control(
            "Access rights",
            "Access rights to information and other associated assets are provisioned, "
            "reviewed, modified and removed in accordance with the access control policy and "
            "rules. (Paraphrase of A.5.18 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.8.2": Control(
            "Privileged access rights",
            "The allocation and use of privileged access rights is restricted and managed. "
            "(Paraphrase of A.8.2 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.8.3": Control(
            "Information access restriction",
            "Access to information and other associated assets is restricted in accordance with "
            "the established access control policy. (Paraphrase of A.8.3 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.8.5": Control(
            "Secure authentication",
            "Secure authentication technologies and procedures are implemented based on "
            "information access restrictions and the access control policy. (Paraphrase of "
            "A.8.5 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.8.9": Control(
            "Configuration management",
            "Configurations, including security configurations, of hardware, software, services "
            "and networks are established, documented, implemented, monitored and reviewed. "
            "(Paraphrase of A.8.9 — not the ISO wording.)",
            _ISO27001_SRC),
        "A.8.20": Control(
            "Networks security",
            "Networks and network devices are secured, managed and controlled to protect "
            "information in systems and applications. (Paraphrase of A.8.20 — not the ISO "
            "wording.)",
            _ISO27001_SRC),
        "A.8.24": Control(
            "Use of cryptography",
            "Rules for the effective use of cryptography, including cryptographic key "
            "management, are defined and implemented. (Paraphrase of A.8.24 — not the ISO "
            "wording.)",
            _ISO27001_SRC),
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
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
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
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
        _ref(ISO27001, "A.5.17",
             note="A.5.17 covers protection of authentication information in transit; the "
                  "credential itself crosses the wire in the clear."),
    ),
    "KAFKA.INTERBROKER.PLAINTEXT": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(e)(1)", confidence="B", gate=(GATE_EPHI,),
             note="Encryption is Addressable under 164.312(e)(2)(ii)."),
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    # SASL mechanisms whose credentials are exposed without TLS. 8.3.2's "unreadable during
    # transmission" is exactly this, and needs no gate — the rule already proves the condition.
    "KAFKA.SASL.PLAIN_WITHOUT_TLS": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
        _ref(ISO27001, "A.5.17",
             note="A.5.17 covers protection of authentication information in transit; the "
                  "credential itself crosses the wire in the clear."),
    ),
    "KAFKA.SASL.SCRAM_WITHOUT_TLS": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
        _ref(ISO27001, "A.5.17",
             note="A.5.17 covers protection of authentication information in transit; the "
                  "credential itself crosses the wire in the clear."),
    ),
    "KAFKA.SASL.OAUTHBEARER_UNSECURED_JWT": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "7.2.1"),  # an unsecured JWT is an unverified principal: no enforceable model
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B",
             note="Art. 9(4) requires strong authentication 'based on relevant standards'; an "
                  "unsecured JWT is the standard's own explicitly non-production mode."),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.5"),
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
        _ref(SOC2, "CC6.7", confidence="B",
             note="TLS is on but peer trust is not validated; assert where the channel carries "
                  "protected information."),
        _ref(ISO27001, "A.8.24"),
    ),
    "KAFKA.SSL.CLIENT_AUTH_NOT_REQUIRED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "7.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.1", confidence="B",
             note="Assert where the client certificate is the authentication mechanism rather than "
                  "one of several."),
        _ref(ISO27001, "A.8.5", confidence="B",
             note="Assert where mTLS is the intended authentication mechanism."),
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
        _ref(SOC2, "CC6.1"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),
    "KAFKA.AUTHZ.ALLOW_EVERYONE_IF_NO_ACL": (
        _ref(PCI, "2.2.6"),  # the definitional misuse-enabling security parameter
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
        _ref(SOC2, "CC6.1"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
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
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.8.2", confidence="B",
             note="Assert where the wildcard grants admin-equivalent rights."),
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
        _ref(SOC2, "CC6.1"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.5"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.5.16", confidence="B",
             note="An anonymous principal is an identity assigned to no one; assert where the grant "
                  "is not a deliberate public-read design."),
    ),

    # ── Kafka: ZooKeeper legacy mode ──────────────────────────────────────
    "KAFKA.ZK.LEGACY_MODE_PLAINTEXT_ZK": (
        _ref(PCI, "2.2.5"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    "KAFKA.ZK.LEGACY_MODE_UNSECURED_ZNODES": (
        _ref(PCI, "7.2.1"),   # cluster metadata with no access control model behind it
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
    ),

    # ── Kafka: topics ─────────────────────────────────────────────────────
    "KAFKA.TOPIC.AUTO_CREATE_ENABLED": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.4"),   # unnecessary functionality enabled by default
        _ref(PCI, "2.2.1"),
        _ref(SOC2, "CC7.1", relation="supports", confidence="B",
             note="Auto-created topics are configuration change nobody reviewed; evidence toward "
                  "CC7.1, not a failure of it."),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B",
             note="A security-relevant default left at the vendor's non-hardened value."),
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
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="CC6.6 is about threats from outside the system boundary; assert where the "
                  "listener is reachable from one."),
        _ref(ISO27001, "A.8.20"),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
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
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
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
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.5"),
        _ref(ISO27001, "A.8.2"),
    ),
    "KONG.ADMIN.NO_AUDIT_LOG": (
        _ref(SOC2, "CC7.2", relation="supports"),
    ),
    "KONG.RBAC.DISABLED": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.2", confidence="B",
             note="Without RBAC every Admin API caller is a full administrator; assert where more "
                  "than one caller exists."),
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
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.5"),
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="CC6.6 is about threats from outside the system boundary; assert where the "
                  "listener is reachable from one."),
    ),
    "KONG.AUTH.ANONYMOUS_FALLBACK": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.5"),
    ),
    # An identity that exists but cannot authenticate is an unreviewed identity: 7.2.5.1's
    # periodic-review requirement is the honest home, and our inventory *is* the review artifact.
    "KONG.CONSUMER.NO_CREDENTIALS": (
        _ref(PCI, "7.2.5.1", relation="supports"),
        _ref(PCI, "7.2.5", confidence="B",
             note="Assert where the credential-less consumer is reachable via an anonymous "
                  "fallback rather than merely dormant."),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.2", relation="supports", confidence="B",
             note="An identity nobody can authenticate as is an access record that was never "
                  "removed; evidence toward the removal half of CC6.2."),
        _ref(ISO27001, "A.5.16", relation="supports", confidence="B"),
        _ref(ISO27001, "A.5.18", relation="supports", confidence="B"),
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
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    "KONG.CORS.WILDCARD_WITH_CREDENTIALS": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "7.2.1", confidence="B",
             note="Assert where the route's credentials carry authorization decisions."),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.6", confidence="B",
             note="A browser on any origin is a source outside the system boundary; assert where "
                  "the route serves browser clients."),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
    ),
    "KONG.PLUGIN.SECURITY_PLUGIN_DISABLED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC7.1", relation="supports", confidence="B",
             note="A security plugin flipped to disabled is the configuration change CC7.1 wants "
                  "detected; the rule is the detection, not proof it was missed."),
        _ref(ISO27001, "A.8.9"),
    ),
    "KONG.ROUTE.WILDCARD_HOST_OR_PRESERVE_HOST": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
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
        _ref(SOC2, "CC7.1"),
    ),
    "RABBITMQ.VERSION.": (
        _ref(PCI, "2.2.1"),
        _ref(NIS2, "21(2)(e)", relation="supports"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(SOC2, "CC7.1"),
    ),
    "RABBITMQ.CVE.": (
        _ref(PCI, "2.2.1"),
        _ref(NIS2, "21(2)(e)", relation="supports"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(SOC2, "CC7.1"),
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
        _ref(SOC2, "CC6.2", confidence="B",
             note="A vendor-shipped account nobody registered or authorized; assert once it is "
                  "established as unused."),
        _ref(ISO27001, "A.5.16"),
        _ref(ISO27001, "A.5.17", confidence="B",
             note="A.5.17 asks that default authentication information be changed; this rule "
                  "proves the account exists, not that the password is still 'guest' (that is "
                  "GUEST_DEFAULT_PASSWORD_REMOTE)."),
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
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.17"),
        _ref(ISO27001, "A.8.5"),
    ),
    "RABBITMQ.USER.GUEST_REMOTE_LOGIN": (
        _ref(PCI, "2.2.2"),
        _ref(PCI, "2.2.1"),
        _ref(PCI, "1.2.5"),
        _ref(NIS2, "21(2)(g)", relation="supports"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
        _ref(SOC2, "CC6.1", confidence="B",
             note="Assert where the guest account's password is unconfirmed; a confirmed "
                  "default is GUEST_DEFAULT_PASSWORD_REMOTE."),
        _ref(ISO27001, "A.5.16"),
    ),
    # A vhost is not an account, so 2.2.2 does not reach it however tempting. Vendor hardening
    # guidance does — 2.2.1 alone.
    "RABBITMQ.VHOST.DEFAULT_VHOST_IN_USE": (
        _ref(PCI, "2.2.1"),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
    ),

    # ── RabbitMQ: authn / authz ───────────────────────────────────────────
    "RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED": (
        _ref(PCI, "7.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(d)", confidence="B", gate=(GATE_EPHI,)),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.5"),
    ),
    "RABBITMQ.PERMISSION.": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.1", confidence="B",
             note="Defensible where the permission grants admin-equivalent rights."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.8.2", confidence="B",
             note="Assert where the wildcard grants admin-equivalent rights."),
    ),
    "RABBITMQ.USER.ADMIN_TAG_SPRAWL": (
        _ref(PCI, "7.2.5"),
        _ref(PCI, "7.2.5.1", relation="supports"),
        _ref(PCI, "7.2.1", confidence="B"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(HIPAA, "164.312(a)(1)", confidence="B", gate=(GATE_EPHI,)),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.2"),
        _ref(ISO27001, "A.5.18"),
    ),
    # 8.3.2's text is "unreadable during transmission AND STORAGE" — the storage clause makes
    # this ungated and direct.
    "RABBITMQ.USER.WEAK_PASSWORD_HASHING": (
        _ref(PCI, "8.3.2"),
        _ref(PCI, "2.2.1"),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.17"),
        _ref(ISO27001, "A.8.24", relation="supports", confidence="B",
             note="A.8.24 governs algorithm choice; a password hash is a cryptographic use, but the "
                  "control is written about rules, not instances."),
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
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    "RABBITMQ.MGMT.HTTP_API_NO_TLS": (
        _ref(PCI, "2.2.7"),   # the management API is non-console administrative access
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.5"),
        _ref(PCI, "1.2.6"),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    "RABBITMQ.TLS.PEER_VERIFICATION_DISABLED": (
        _ref(PCI, "2.2.1"),
        _ref(PCI, "2.2.6"),
        _ref(PCI, "4.2.1", confidence="B", gate=(GATE_PAN, GATE_PUBLIC_FACING),
             note="4.2.1 requires that only trusted, valid certificates are accepted."),
        _ref(DORA, "Art.9(3)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(h)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.7", confidence="B",
             note="TLS is on but peer trust is not validated; assert where the channel carries "
                  "protected information."),
        _ref(ISO27001, "A.8.24"),
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
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.5"),
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
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="CC6.6 is about threats from outside the system boundary; assert where the "
                  "listener is reachable from one."),
        _ref(ISO27001, "A.8.20"),
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
        _ref(SOC2, "CC6.1", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="Assert for HTTP-transport servers reachable beyond the host; a local STDIO "
                  "server without authorization conforms to the spec."),
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(ISO27001, "A.5.15", confidence="B", gate=(GATE_PUBLIC_FACING,)),
        _ref(ISO27001, "A.8.5", confidence="B", gate=(GATE_PUBLIC_FACING,)),
    ),
    "MCP.AUTH.SCOPE_OVERBROAD": (
        _ref(PCI, "7.2.5", confidence="B",
             note="'Access is limited to the systems, applications, or processes that "
                  "specifically require their use' — assert once the token's grants are known "
                  "to exceed the server's need."),
        _ref(DORA, "Art.9(4)", relation="supports", confidence="B"),
        _ref(NIS2, "21(2)(i)", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.3", confidence="B",
             note="Assert once the token's grants are known to exceed the server's need."),
        _ref(ISO27001, "A.5.18", confidence="B",
             note="Assert once the token's grants are known to exceed the server's need."),
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
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
    ),
    "MCP.TRANSPORT.ORIGIN_UNVALIDATED": (
        _ref(PCI, "2.2.6"),
        _ref(PCI, "2.2.1"),
        _ref(SOC2, "CC6.6", confidence="B",
             note="DNS rebinding is an outside-boundary threat; assert where the server binds "
                  "beyond loopback."),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
    ),

    # ═════════════════════════════════════════════════════════════════════
    # SOC 2 / ISO 27001 only. The families below were never researched against PCI / DORA /
    # NIS2 / HIPAA, so they carry no row for those four — adding one means adding it to the
    # research doc first. SOC 2 CC6/CC7 and ISO Annex A are written at a level of abstraction
    # that reaches machine identities and cloud resource policies natively, which is why the
    # NHI, credential-lifecycle, cloud and Kubernetes packs land here first.
    # ═════════════════════════════════════════════════════════════════════

    # ── NHI: cross-cutting identity hygiene ───────────────────────────────
    # NHI.GRANT.WILDCARD is the generalised KAFKA.ACL.* / RABBITMQ.PERMISSION.* finding, so it
    # inherits their mapping verbatim — a wildcard grant is the negation of CC6.3's least
    # privilege and A.5.18's "in accordance with the access control policy".
    # MCP client configs committed to repositories (detect/mcp_client.py).
    "MCP.CLIENTCONFIG.LITERAL_SECRET": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.17"),
    ),
    "MCP.CLIENTCONFIG.BROAD_FILESYSTEM": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.3"),
    ),
    "MCP.CLIENTCONFIG.DATABASE_DIRECT": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.3"),
    ),
    "MCP.CLIENTCONFIG.PLAINTEXT_REMOTE": (
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
    ),
    # Effective-access rules (detect/effective_access.py): who can actually reach the data.
    "KAFKA.EFFECTIVE.TOPIC_OPEN_NO_ACL": (
        _ref(SOC2, "CC6.1"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.3"),
    ),
    "KAFKA.EFFECTIVE.TOPIC_WORLD_READABLE": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.5.18"),
    ),
    "REDIS.ACL.KEYPATTERN_BYPASS": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.3"),
    ),
    "REDIS.ACL.SELF_ESCALATION": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.8.2"),
        _ref(ISO27001, "A.5.18"),
    ),
    "K8S.MESH.JWT_NOT_ENFORCED": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.5"),
    ),
    "K8S.MESH.AUTH_ONLY_AT_GATEWAY": (
        _ref(SOC2, "CC6.6"),
        _ref(ISO27001, "A.8.20"),
    ),
    "MFT.TRANSFER.CREDENTIAL_NOT_ROTATED": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.17"),
    ),
    "MFT.TRANSFER.ACCOUNT_UNUSED": (
        _ref(SOC2, "CC6.2"),
        _ref(ISO27001, "A.5.18"),
    ),
    # LiteLLM (connect/litellm.py)
    "LITELLM.AUTH.NO_MASTER_KEY": (_ref(SOC2, "CC6.1"), _ref(ISO27001, "A.8.5")),
    "LITELLM.AUTH.DEFAULT_MASTER_KEY": (_ref(SOC2, "CC6.1"), _ref(ISO27001, "A.5.17")),
    "LITELLM.VERSION.KNOWN_CVE": (_ref(SOC2, "CC7.1"),),
    "LITELLM.KEY.NO_OWNER": (_ref(SOC2, "CC6.2"), _ref(ISO27001, "A.5.18")),
    "LITELLM.KEY.UNUSED": (_ref(SOC2, "CC6.2"), _ref(ISO27001, "A.5.18")),
    # Make (connect/make.py)
    "MAKE.CONNECTION.PERSONAL_ACCOUNT": (
        _ref(SOC2, "CC6.2"),
        _ref(ISO27001, "A.5.18"),
    ),
    "MAKE.CONNECTION.UNUSED": (
        _ref(SOC2, "CC6.2"),
        _ref(ISO27001, "A.5.18"),
    ),
    "MAKE.ORG.TFA_NOT_ENFORCED": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.5"),
    ),
    "NHI.GRANT.WILDCARD": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.8.2", confidence="B",
             note="Assert where the wildcard grants admin-equivalent rights."),
    ),
    # A.5.16 is the one control in either framework that says "shared identities only where
    # necessary" in so many words.
    "NHI.IDENTITY.SHARED_DEFAULT": (
        _ref(ISO27001, "A.5.16"),
        _ref(SOC2, "CC6.1", confidence="B",
             note="A default or shared principal defeats attribution; assert where the identity "
                  "is enabled and not a deliberate, documented service identity."),
        _ref(SOC2, "CC6.2", relation="supports", confidence="B",
             note="A vendor-shipped identity was never registered or authorized by the entity."),
    ),
    "NHI.CREDENTIAL.WEAK_HASH": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.17"),   # protection of authentication information in storage
        _ref(ISO27001, "A.8.24", relation="supports", confidence="B",
             note="A.8.24 governs algorithm choice; MD5/SHA-1 for a stored credential is an "
                  "ineffective use of cryptography, but the control is written about rules."),
    ),
    # Always not_assessable by construction, so this only ever moves a control to `unknown` —
    # which is exactly right: a storage mode we cannot read is a coverage gap on A.5.17.
    "NHI.CREDENTIAL.STORAGE_UNVERIFIED": (
        _ref(ISO27001, "A.5.17", relation="supports", confidence="B",
             note="Coverage gap: the connector cannot read whether credential hashing is on."),
        _ref(SOC2, "CC6.1", relation="supports", confidence="B"),
    ),

    # ── Credential lifecycle ──────────────────────────────────────────────
    # Exact keys, not a "CREDENTIAL.LIFECYCLE." prefix: ORPHANED_IDENTITY is about an identity's
    # grants (A.5.18 / CC6.2), the rest about the credential itself (A.5.17), so no single set
    # fits the whole family. A.5.17 is the honest ISO home for rotation/expiry: its intent covers
    # the management process for authentication information, and a static, never-expiring secret
    # is the absence of one. SOC 2 has no rotation criterion; CC6.1 carries it as `supports`.
    "CREDENTIAL.LIFECYCLE.ROTATION_STALE": (
        _ref(ISO27001, "A.5.17"),
        _ref(SOC2, "CC6.1", relation="supports", confidence="B",
             note="SOC 2 has no rotation criterion; a long-lived unrotated secret weakens the "
                  "logical access security CC6.1 describes."),
    ),
    # Dormancy is indicative, not proof the access is no longer needed — hence `supports` and B
    # on both. (Today this rule is not_assessable everywhere, so it only ever yields `unknown`.)
    "CREDENTIAL.LIFECYCLE.NEVER_USED": (
        _ref(SOC2, "CC6.2", relation="supports", confidence="B",
             note="CC6.2 requires removal of access no longer authorized; a never-used credential "
                  "is a removal candidate, not proof the authorization lapsed."),
        _ref(ISO27001, "A.5.18", relation="supports", confidence="B",
             note="A.5.18 requires access rights be reviewed and removed; dormancy is the "
                  "review's input, not its conclusion."),
        _ref(ISO27001, "A.5.17", relation="supports", confidence="B"),
    ),
    "CREDENTIAL.LIFECYCLE.STATIC_NO_ROTATION": (
        _ref(ISO27001, "A.5.17"),
        _ref(SOC2, "CC6.1", relation="supports", confidence="B",
             note="SOC 2 has no rotation criterion; see ROTATION_STALE."),
    ),
    "CREDENTIAL.LIFECYCLE.NO_EXPIRY": (
        _ref(ISO27001, "A.5.17"),
        _ref(SOC2, "CC6.1", relation="supports", confidence="B",
             note="SOC 2 has no expiry criterion; see ROTATION_STALE."),
    ),
    "CREDENTIAL.LIFECYCLE.SHARED": (
        _ref(ISO27001, "A.5.16"),
        _ref(ISO27001, "A.5.17"),
        _ref(SOC2, "CC6.1", confidence="B",
             note="Assert where the shared key is not a deliberate, documented design (e.g. a "
                  "SAS policy intentionally shared by one application tier)."),
    ),
    "CREDENTIAL.LIFECYCLE.DEFAULT_ACTIVE": (
        _ref(ISO27001, "A.5.17"),   # 'change default authentication information' is its intent
        _ref(SOC2, "CC6.1"),
    ),
    # Disabled-but-still-granted is literally access that was not removed: CC6.2's removal clause
    # and A.5.18's "removed" are the two cleanest fits for any lifecycle rule.
    "CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY": (
        _ref(SOC2, "CC6.2"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
        _ref(ISO27001, "A.5.16"),
    ),

    # ── Known vulnerabilities (generic) ───────────────────────────────────
    # CC7.1's "susceptibilities to newly discovered vulnerabilities" is a version/CVE finding by
    # definition. ISO A.8.8 would be the match and is not in the catalogue yet (see the
    # catalogue note), so no ISO row here.
    "CVE.KNOWN_VULNERABILITY": (
        _ref(SOC2, "CC7.1"),
    ),
    "REDIS.VERSION.RCE_CVE": (
        _ref(SOC2, "CC7.1"),
    ),

    # ── Redis ─────────────────────────────────────────────────────────────
    "REDIS.AUTH.NO_PASSWORD": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.5"),
        _ref(ISO27001, "A.8.3"),
    ),
    "REDIS.USER.NOPASS": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.8.5"),
        _ref(ISO27001, "A.5.17"),
    ),
    "REDIS.TLS.DISABLED": (
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    "REDIS.NETWORK.BIND_ALL": (
        _ref(ISO27001, "A.8.20"),
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="Binding every interface is exposure only where an interface faces outside "
                  "the system boundary."),
    ),
    "REDIS.NETWORK.PROTECTED_MODE_OFF": (
        _ref(ISO27001, "A.8.20"),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,)),
    ),

    # ── AWS ───────────────────────────────────────────────────────────────
    # A resource policy with Principal "*" is the rule proving its own CC6.6 condition: "any AWS
    # principal" is by definition a source outside the entity's system boundary. No gate.
    "AWS.SQS.QUEUE_POLICY_PUBLIC": (
        _ref(SOC2, "CC6.6"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),
    "AWS.SNS.TOPIC_POLICY_PUBLIC": (
        _ref(SOC2, "CC6.6"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),
    "AWS.EVENTBRIDGE.BUS_POLICY_PUBLIC": (
        _ref(SOC2, "CC6.6"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),
    "AWS.SQS.POLICY_WILDCARD_ACTION": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
    ),
    "AWS.SNS.POLICY_WILDCARD_ACTION": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
    ),
    "AWS.EVENTBRIDGE.BUS_POLICY_WILDCARD_ACTION": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
    ),
    "AWS.MSK.UNAUTHENTICATED_ACCESS": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.5"),
    ),
    "AWS.MSK.PUBLIC_ACCESS_ENABLED": (
        _ref(SOC2, "CC6.6"),   # the rule reads the public-access flag itself: no gate needed
        _ref(ISO27001, "A.8.20"),
    ),
    "AWS.MSK.CLIENT_PLAINTEXT_IN_TRANSIT": (
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    "AWS.MSK.INTERBROKER_PLAINTEXT": (
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    # Enhanced monitoring is operational telemetry, not security monitoring: `supports` + B is
    # as far as CC7.2 can honestly be stretched for it.
    "AWS.MSK.ENHANCED_MONITORING_DEFAULT": (
        _ref(SOC2, "CC7.2", relation="supports", confidence="B",
             note="Per-broker/per-topic metrics are a precondition for the anomaly detection "
                  "CC7.2 describes, not that detection itself."),
        _ref(ISO27001, "A.8.9", relation="supports", confidence="B"),
    ),
    "AWS.APIGW.ROUTE_NO_AUTHORIZER": (
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.5"),
        _ref(SOC2, "CC6.6", confidence="B", gate=(GATE_PUBLIC_FACING,),
             note="A regional/edge endpoint is usually internet-reachable, but a private API "
                  "is not; the gate decides."),
    ),

    # ── Logging / monitoring disabled ─────────────────────────────────────
    # The honest CC7.2 fit: with the component's own logging off, anomaly monitoring on it is
    # not merely weak but impossible. `supports` because CC7.2 is about the entity's monitoring
    # programme, which one silent component does not by itself disprove.
    "AWS.APIGW.STAGE_LOGGING_DISABLED": (
        _ref(SOC2, "CC7.2", relation="supports"),
    ),
    "GCP.PROJECT.AUDIT_LOGGING_DISABLED": (
        _ref(SOC2, "CC7.2", relation="supports"),
    ),
    "ELASTICSEARCH.AUDIT.DISABLED": (
        _ref(SOC2, "CC7.2", relation="supports"),
    ),
    "VAULT.AUDIT.NO_DEVICE": (
        _ref(SOC2, "CC7.2", relation="supports"),
    ),

    # ── GCP: public IAM ───────────────────────────────────────────────────
    "GCP.PUBSUB.TOPIC_IAM_PUBLIC": (
        _ref(SOC2, "CC6.6"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),
    "GCP.PUBSUB.SUBSCRIPTION_IAM_PUBLIC": (
        _ref(SOC2, "CC6.6"),
        _ref(SOC2, "CC6.1"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),

    # ── Kubernetes ────────────────────────────────────────────────────────
    # cluster-admin on a ServiceAccount is the clearest A.8.2 instance in the product: a
    # privileged access right allocated to a workload token.
    "K8S.RBAC.SA_CLUSTER_ADMIN": (
        _ref(ISO27001, "A.8.2"),
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
    ),
    "K8S.RBAC.WILDCARD_BOUND": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.8.2", confidence="B",
             note="Assert where the wildcard role is cluster-scoped or covers secrets/RBAC."),
    ),
    # system:unauthenticated is, by name, a source outside the system boundary — CC6.6 ungated.
    "K8S.RBAC.ANONYMOUS_BOUND": (
        _ref(SOC2, "CC6.1"),
        _ref(SOC2, "CC6.6"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
        _ref(ISO27001, "A.8.5"),
    ),
    "K8S.SA.DEFAULT_BOUND": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.18"),
        _ref(ISO27001, "A.5.16", confidence="B",
             note="The default SA is one identity shared by every pod in the namespace; assert "
                  "where more than one workload runs there."),
    ),
    # A non-expiring bearer token is the Kubernetes instance of STATIC_NO_ROTATION.
    "K8S.SA.LEGACY_TOKEN_SECRET": (
        _ref(ISO27001, "A.5.17"),
        _ref(SOC2, "CC6.1", relation="supports", confidence="B",
             note="SOC 2 has no rotation criterion; see CREDENTIAL.LIFECYCLE.ROTATION_STALE."),
    ),
    "K8S.MESH.MTLS_NOT_STRICT": (
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
        _ref(ISO27001, "A.8.5", relation="supports", confidence="B",
             note="mTLS is also workload authentication; PERMISSIVE lets unauthenticated "
                  "plaintext peers through."),
    ),
    "K8S.MESH.AUTHZ_ALLOW_ALL": (
        _ref(SOC2, "CC6.3"),
        _ref(ISO27001, "A.5.15"),
        _ref(ISO27001, "A.8.3"),
    ),
    "K8S.INGRESS.NO_TLS": (
        _ref(SOC2, "CC6.7"),
        _ref(ISO27001, "A.8.24"),
        _ref(ISO27001, "A.8.20", relation="supports", confidence="B"),
    ),
    # NetworkPolicy IS network control: A.8.20 is its home, sentence for sentence.
    "K8S.NETPOL.ALLOW_ALL": (
        _ref(ISO27001, "A.8.20"),
        _ref(SOC2, "CC6.6", relation="supports", confidence="B"),
    ),
    "K8S.NETPOL.NO_DEFAULT_DENY": (
        _ref(ISO27001, "A.8.20"),
        _ref(SOC2, "CC6.6", relation="supports", confidence="B"),
    ),

    # ── Kafka: super.users (previously unmapped) ──────────────────────────
    "KAFKA.AUTHZ.SUPER_USERS_BREADTH": (
        _ref(ISO27001, "A.8.2"),   # un-revocable, ACL-bypassing admin is privileged access
        _ref(SOC2, "CC6.3"),
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
    "ATTACKPATH.": (
        "A chain is a correlation of single-signal findings that each already carry their own "
        "framework rows (the wildcard grant, the plaintext listener, the public policy). Mapping "
        "the chain as well — SOC 2 CC6.6 and ISO A.8.20 are the tempting ones — would fail the "
        "same control twice on one root cause and present triage priority as a second "
        "violation. detect/attack_path.py documents the pack as mapping to no control, and "
        "test_detect_attack_path.py pins it."
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
