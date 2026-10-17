# Compliance Mapping Research — integration-layer findings → framework controls

**Status:** research input for `services/engine/src/vectasec/compliance/map.py` (not yet written) and the `controls` table in `supabase/migrations/20260717000002_platform_schema.sql`.
**Researched:** 2026-07-17. Every factual claim below carries an inline source link to a page that was actually fetched during this research pass. Claims that could **not** be verified against a primary source are marked **[low confidence]** and collected in [§8 Verification gaps](#8-verification-gaps).

---

## 0. The two design rules that must survive contact with an auditor

Before any table: two rules that make the difference between a mapping a QSA will accept and a mapping that gets VectaSec thrown out of an audit.

**Rule 1 — A finding can prove FAIL. A finding's absence can never prove PASS.**
`KAFKA.ACL.WILDCARD` firing is evidence that PCI DSS 7.2.5 is not met on that broker. `KAFKA.ACL.WILDCARD` *not* firing is **not** evidence that 7.2.5 *is* met — 7.2.5 covers every application and system account in the CDE, and VectaSec only sees the brokers it scanned. The `controls.status` enum in the platform schema already has `unknown`; the mapping engine must default to `unknown` and only ever move a control to `fail`. Moving a control to `pass` requires a human attestation plus scope coverage evidence, not the absence of a hit. Any vendor claiming automated `pass` on 7.2.5 from a broker scan is selling a fiction.

**Rule 2 — Every mapping is conditional on scope, and scope is not a property of the rule.**
PCI DSS applies to system components in, connected to, or that could affect the security of the CDE ([PCI SSC](https://blog.pcisecuritystandards.org/now-is-the-time-for-organizations-to-adopt-the-future-dated-requirements-of-pci-dss-v4-x) — 12.5.2 requires annual scope confirmation). DORA applies to in-scope financial entities. NIS2 applies to essential/important entities in the 18 covered sectors ([EC press release, July 2026](https://europeansting.com/2026/07/13/commission-refers-ireland-spain-france-and-the-netherlands-to-the-court-of-justice-for-failing-to-transpose-the-rules-on-cybersecurity-2/)). HIPAA applies to ePHI. A PLAINTEXT Kafka listener on a broker that carries no PAN, no ePHI, in a US-only non-financial company violates **nothing** — it is just bad practice.

So the mapping is not `rule_id -> [control_id]`. It is:

```
(rule_id, asset_scope_tags, tenant_frameworks) -> [(framework, control_id, relation, confidence)]
```

`asset_scope_tags` (`cde`, `ephi`, `ict_critical_important`, `nis2_essential`) come from the asset/tenant, not the detector. The `controls` table's `not_applicable` status is the correct output when a tenant lacks the scope tag. This is the single most important structural decision in this document — if the mapping table is a flat dict, the product will produce false compliance claims by construction.

---

## 1. PCI DSS 4.0.1

### 1.1 Current status

**v4.0.1 is the current version.** It was released in June 2024 as "a limited revision...with minor updates and to provide further clarification" for requirements — it adds no new requirements and deletes none ([PCI SSC blog](https://blog.pcisecuritystandards.org/now-is-the-time-for-organizations-to-adopt-the-future-dated-requirements-of-pci-dss-v4-x)).

**The future-dated requirements are now in force.** Of the 64 new requirements introduced in v4.0, **51 were future-dated and became mandatory on 31 March 2025** ([PCI SSC blog](https://blog.pcisecuritystandards.org/now-is-the-time-for-organizations-to-adopt-the-future-dated-requirements-of-pci-dss-v4-x)). As of today (2026-07-17) they must be validated in every assessment. There is no grace period remaining. Two the PCI SSC blog names explicitly: **11.3.2** (ASV scans, quarterly, for SAQ A e-commerce merchants) and **12.5.2** (annual scope confirmation).

**Why this matters commercially for VectaSec:** the future-dated set includes the non-human-identity requirements (**8.6.1–8.6.3**, **7.2.5.1**) and **6.4.2**. These went from "best practice" to "audited" 16 months ago, and they are the requirements that most directly describe *service accounts on middleware* — which is exactly VectaSec's wedge. The compliance module should lead with 8.6.x and 7.2.5, not with 1.x. **[low confidence]** on the precise future-dated membership of 8.6.x/7.2.5.1/6.4.2 — see [§8](#8-verification-gaps).

### 1.2 Source note on requirement text

The authoritative PCI DSS v4.0.1 PDF sits behind the PCI SSC Document Library click-through agreement and could not be fetched directly. The verbatim requirement text quoted below was extracted from a **Genesys Cloud PCI responsibility matrix** hosted publicly at [help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf), which reproduces the "PCI-DSS v4.0.1 Defined Approach Requirements" column in full. **This is a vendor reproduction, not the standard.** Before this mapping ships to a paying customer, someone must diff these strings against the official PDF from the PCI SSC Document Library and record the diff. Treat the wording below as high-confidence-but-unofficial.

### 1.3 The requirements a broker/gateway misconfiguration actually violates

All text below is verbatim from the [Genesys reproduction](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf) of PCI DSS v4.0.1.

#### 1.x — Network security controls

| Req | Text (verbatim) |
|---|---|
| **1.2.1** | "Configuration standards for NSC rulesets are: Defined, Implemented and Maintained." |
| **1.2.5** | "All services, protocols, and ports allowed are identified, approved, and have a defined business need." |
| **1.2.6** | "Security features are defined and implemented for all services, protocols, and ports that are in use and considered to be insecure, such that the risk is mitigated." |
| **1.3.1** | "Inbound traffic to the CDE is restricted as follows: To only traffic that is necessary. All other traffic is specifically denied." |
| **1.3.2** | "Outbound traffic from the CDE is restricted as follows: To only traffic that is necessary. All other traffic is specifically denied." |
| **1.4.1** | "NSCs are implemented between trusted and untrusted networks." |
| **1.4.2** | "Inbound traffic from untrusted networks to trusted networks is restricted to: Communications with system components that are authorized to provide publicly accessible services, protocols, and ports. Stateful responses to communications initiated by system components in a trusted network. All other traffic is denied." |

**1.2.5 and 1.2.6 are the sleepers.** An exposed Kong Admin API on `0.0.0.0:8001` or a Kafka PLAINTEXT listener is precisely "a service/protocol/port in use and considered insecure" without documented mitigation. These map better than the headline 1.3.1.

#### 2.2.x — Secure configuration and defaults

| Req | Text (verbatim) |
|---|---|
| **2.2.1** | "Configuration standards are developed, implemented, and maintained to: Cover all system components. Address all known security vulnerabilities. Be consistent with industry-accepted system hardening standards or vendor hardening recommendations. Be updated as new vulnerability issues are identified, as defined in Requirement 6.3.1. Be applied when new systems are configured and verified as in place before or immediately after a system component is connected to a production environment." |
| **2.2.2** | "Vendor default accounts are managed as follows: If the vendor default account(s) will be used, the default password is changed per Requirement 8.3.6. If the vendor default account(s) will not be used, the account is removed or disabled." |
| **2.2.4** | "Only necessary services, protocols, daemons, and functions are enabled, and all unnecessary functionality is removed or disabled." |
| **2.2.5** | "If any insecure services, protocols, or daemons are present: Business justification is documented. Additional security features are documented and implemented that reduce the risk of using insecure services, protocols, or daemons." |
| **2.2.6** | "System security parameters are configured to prevent misuse." |
| **2.2.7** | "All non-console administrative access is encrypted using strong cryptography." |

**2.2.1's "consistent with industry-accepted system hardening standards or vendor hardening recommendations" is the single most useful hook in PCI for VectaSec.** It is the requirement that turns *any* vendor-documented hardening deviation into a citable finding. RabbitMQ's own docs say production "should not use the default user" ([RabbitMQ access control docs](https://www.rabbitmq.com/docs/access-control)); Kong's own docs say "avoid using values such as `0.0.0.0:8001`" ([Kong: Secure the Admin API](https://developer.konghq.com/gateway/secure-the-admin-api/)). Deviating from those is a 2.2.1 finding with the vendor's own words as the evidence. This is the mapping that generalizes across every connector VectaSec will ever write — it should be a *default* mapping applied to every hardening-class rule, not a per-rule decision.

**2.2.7 is narrower than it looks.** It says *non-console administrative access*. It covers the Kong Admin API over HTTP and Kafka admin/JMX over plaintext. It does **not** cover a PLAINTEXT data-plane listener carrying application traffic. Do not stretch it.

#### 4.2.1 — Strong cryptography in transit

> **4.2.1** "Strong cryptography and security protocols are implemented as follows to safeguard PAN during transmission over **open, public networks**: Only trusted keys and certificates are accepted. Certificates used to safeguard PAN during transmission over open, public networks are confirmed as valid and are not expired or revoked. The protocol in use supports only secure versions or configurations and does not support fallback to, or use of insecure versions, algorithms, key sizes, or implementations. The encryption strength is appropriate for the encryption methodology in use."
> — [verbatim](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf) (emphasis added)

**Read the scope words.** 4.2.1 is conditioned on **PAN** **over open, public networks**. An internal Kafka broker with a PLAINTEXT listener on a private VPC subnet is **not** a 4.2.1 violation, however bad it is. Mapping `KAFKA.LISTENER.PLAINTEXT` → 4.2.1 unconditionally is the most tempting and most common error in this space, and a QSA will catch it. It is only a 4.2.1 violation when the listener is internet-reachable *and* the topics carry PAN. VectaSec can determine the first from the connector (advertised listeners / security groups) and cannot determine the second without data classification. So: **4.2.1 is a conditional mapping gated on `cde` + internet-exposure, and it should be surfaced as "candidate" for human confirmation, never auto-asserted.**

#### 6.4.2 — Automated technical solution for public-facing web apps (WAF)

> **6.4.2** "For public-facing web applications, an automated technical solution is deployed that continually detects and prevents web-based attacks, with at least the following: Is installed in front of public-facing web applications and is configured to detect and prevent web-based attacks. Actively running and up to date as applicable. Generating audit logs. Configured to either block web-based attacks or generate an alert that is immediately investigated."
> — [verbatim](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf)

This is a **WAF/RASP** requirement. It is *not* an authentication requirement. Mapping `KONG.AUTH.MISSING` → 6.4.2 is wrong: a route with no auth plugin is an access-control failure (7.x), not a missing-WAF failure. 6.4.2 deserves its own rule (`KONG.WAF.MISSING` / `KONG.PLUGIN.WAF_ABSENT` — not currently in the rule families listed), which fires when a Kong route is public-facing and has no WAF-class plugin in its chain. Kong is well-placed to answer this: the plugin chain is enumerable. **Recommend adding this rule** — it maps to a requirement that became mandatory 31 March 2025 and is a genuine gateway-posture question, which makes it a strong demo beat.

#### 7.x — Least privilege

| Req | Text (verbatim) |
|---|---|
| **7.2.1** | "An access control model is defined and includes granting access as follows: Appropriate access depending on the entity's business and access needs. Access to system components and data resources that is based on users' job classification and functions. The least privileges required (for example, user, administrator) to perform a job function." |
| **7.2.2** | "Access is assigned to users, including privileged users, based on: Job classification and function. Least privileges necessary to perform job responsibilities." |
| **7.2.5** | "**All application and system accounts** and related access privileges are assigned and managed as follows: Based on the least privileges necessary for the operability of the system or application. Access is limited to the systems, applications, or processes that specifically require their use." |
| **7.2.5.1** | "All access by application and system accounts and related access privileges are reviewed as follows: Periodically (at the frequency defined in the entity's targeted risk analysis...)..." |

**7.2.5 is VectaSec's requirement.** It is written about non-human identities, it is exactly what a Kafka ACL / Kong consumer / MCP token *is*, and it is machine-checkable from a broker scan in a way that 7.2.1/7.2.2 (which are about *people* and *documented models*) are not. 7.2.1 and 7.2.2 say "users" — mapping an over-broad Kafka ACL for `User:*` to 7.2.2 is a stretch, because a Kafka `User:` principal is usually a service, not a job classification. **Prefer 7.2.5 over 7.2.2 for every NHI rule.** 7.2.5.1 (periodic review) is the natural home for stale/orphaned-ACL rules — VectaSec's inventory *is* the review artifact.

#### 8.x — Authentication, incl. 8.6.x for application/system accounts

| Req | Text (verbatim) |
|---|---|
| **8.2.1** | "All users are assigned a unique ID before access to system components or cardholder data is allowed." |
| **8.2.2** | "Group, shared, or generic IDs, or other shared authentication credentials are only used when necessary, on an exception basis, and are managed as follows: Account use is prevented unless needed for an exceptional circumstance. Use is limited to the time needed for the exceptional circumstance. Business justification for use is documented. Use is explicitly approved by management..." |
| **8.3.1** | "All user access to system components for users and administrators is authenticated via at least one of the following authentication factors: Something you know... Something you have... Something you are..." |
| **8.3.2** | "Strong cryptography is used to render all authentication factors unreadable during transmission and storage on all system components." |
| **8.6.1** | "If accounts used by systems or applications can be used for interactive login, they are managed as follows: Interactive use is prevented unless needed for an exceptional circumstance. Interactive use is limited to the time needed for the exceptional circumstance. Business justification for interactive use is documented. Interactive use is explicitly approved by management. Individual user identity is confirmed before access to account is granted. Every action taken is attributable to an individual user." |
| **8.6.2** | "Passwords/passphrases for any application and system accounts that can be used for interactive login are **not hard coded in scripts, configuration/property files, or bespoke and custom source code**." |
| **8.6.3** | "Passwords/passphrases for any application and system accounts are protected against misuse as follows: Passwords/passphrases are changed periodically (at the frequency defined in the entity's targeted risk analysis, which is performed according to all elements specified in Requirement 12.3.1) and upon suspicion or confirmation of compromise. Passwords/passphrases are constructed with sufficient complexity appropriate for how frequently the entity changes the passwords/passphrases." |

**8.6.2 is the highest-value mapping in this entire document for the NHI wedge.** "not hard coded in scripts, **configuration/property files**" describes, verbatim, a credential sitting in `connect-distributed.properties`, a Kong declarative `kong.yml`, an MCP server manifest, or a `docker-compose.yml`. VectaSec's static analysis of integration-as-code (already in the README's Supply-chain row) lands directly on an audited PCI requirement. This should be a headline rule family (`*.SECRET.HARDCODED`) — it is currently missing from the rule families in scope and is a bigger commercial unlock than most of the ones listed.

**Caveat on 8.6.1/8.6.2's scope:** both are gated on "**can be used for interactive login**". A Kafka SASL principal that cannot interactively log in is out of scope for 8.6.1 and 8.6.2. 8.6.3, by contrast, applies to "any application and system accounts" with no interactive-login qualifier — so **8.6.3 is the broadest and safest 8.6.x mapping for middleware service accounts**. Getting this distinction right is what separates a credible mapping from a checkbox.

**8.2.1/8.3.1 say "users".** Do not map machine-identity rules to them. `KONG.AUTH.MISSING` on a route consumed by humans → 8.3.1 defensible; on a machine-to-machine route → stretch.

#### 10.x — Logging

| Req | Text (verbatim) |
|---|---|
| **10.2.1** | "Audit logs are enabled and active for all system components and cardholder data." |
| **10.2.1.2** | "Audit logs capture all actions taken by any individual with administrative access, **including any interactive use of application or system accounts**." |
| **10.2.2** | "Audit logs record the following details for each auditable event: User identification. Type of event. Date and time. Success and failure indication. Origination of event. Identity or name of affected data, system component, resource, or service (for example, name and protocol)." |

10.2.1.2's explicit call-out of "interactive use of application or system accounts" is the logging counterpart to 8.6.1 and pairs with it in the same finding narrative.

---

## 2. DORA — Regulation (EU) 2022/2554

### 2.1 Status

**DORA has applied since 17 January 2025** (Article 64) ([DORA Art. 64](https://www.digital-operational-resilience-act.com/Article_64.html)). It is a Regulation, so it is "binding in its entirety and directly applicable in all Member States" — no transposition, no national variation. This is the opposite of NIS2's situation ([§3](#3-nis2--directive-eu-20222555)) and it makes DORA the *easier* framework to build against: one text, one meaning, 27 countries.

### 2.2 ICT risk management — Articles 5–15

Titles, verbatim from [digital-operational-resilience-act.com](https://www.digital-operational-resilience-act.com/DORA_Articles.html):

| Art | Title |
|---|---|
| 5 | Governance and organisation |
| 6 | ICT risk management framework |
| 7 | ICT systems, protocols and tools |
| 8 | Identification |
| 9 | Protection and prevention |
| 10 | Detection |
| 11 | Response and recovery |
| 12 | Backup policies and procedures, restoration and recovery procedures and methods |
| 13 | Learning and evolving |
| 14 | Communication |
| 15 | Further harmonisation of ICT risk management tools, methods, processes and policies |

**Article 9 (Protection and prevention) is where nearly every VectaSec finding lands.** Per [DORA Art. 9](https://www.digital-operational-resilience-act.com/Article_9.html):

- **9(1)** — financial entities must "continuously monitor and control the security and functioning of ICT systems" and deploy appropriate security tools. *(This is arguably a mapping for VectaSec's own existence, not for a finding — useful in sales, not in the controls table.)*
- **9(2)** — "design, procure and implement ICT security policies, procedures, protocols and tools" ensuring resilience/continuity/availability and "maintaining high data standards" across data **at rest, in use, or in transit**. → the transit clause is the hook for PLAINTEXT findings.
- **9(3)** — ICT solutions must secure data transfer means, reduce risks of corruption/unauthorised access, and prevent confidentiality breaches.
- **9(4)** — the operative list. Includes: documented information security policies; "network and infrastructure management structure using appropriate techniques" with **automated isolation mechanisms** during cyber-attacks; **access control policies limiting physical/logical access to approved functions only**; "**strong authentication mechanisms, based on relevant standards**" with cryptographic key protection; controlled ICT change management; patch policies; and network infrastructure that can be "instantaneously severed or segmented" to prevent contagion.

**Article 8 (Identification)** underpins the inventory itself — VectaSec's asset graph is Art. 8 evidence.

**Honest limitation:** DORA articles are *principles*, not testable controls. There is no "DORA 9.4.3" the way there is a "PCI 8.6.2". Mapping a finding to "Art. 9(4)" is directionally right but an auditor will ask *which* internal control it breaks. In practice DORA compliance is assessed against the entity's own ICT risk management framework, which DORA requires the entity to write (Art. 6). **So VectaSec's DORA output should be framed as evidence feeding the entity's Art. 6 framework, not as a pass/fail against Art. 9.** This is a meaningful product constraint: the DORA "control catalogue" in the `controls` table will be coarser than PCI's, and the UI should not imply otherwise. Sub-paragraph granularity (`DORA.9.4.c`) is a VectaSec-invented identifier — label it as such rather than implying it is an official citation.

### 2.3 Article 28 — register of information

Article 28(3) requires financial entities to "maintain and update at entity level, and at sub-consolidated and consolidated levels, a register of information in relation to all contractual arrangements on the use of ICT services provided by ICT third-party service providers." Contractual arrangements "shall be appropriately documented, **distinguishing between those that cover ICT services supporting critical or important functions and those that do not**" ([DORA Art. 28](https://www.digital-operational-resilience-act.com/Article_28.html)).

Entities must report **at least yearly** to competent authorities on the number of new arrangements, categories of providers, types of contractual arrangements, and services/functions provided; must inform the authority "in a timely manner" about any planned arrangement covering a critical or important function, or when a function *becomes* critical or important; and the authority may request the full register or any section on demand ([DORA Art. 28](https://www.digital-operational-resilience-act.com/Article_28.html)).

#### The register's actual fields — ITS (EU) 2024/2956

The field-level specification is **Commission Implementing Regulation (EU) 2024/2956 of 29 November 2024**, which lays down ITS for the standard templates for the register of information ([EUR-Lex](https://eur-lex.europa.eu/eli/reg_impl/2024/2956/oj/eng)). It defines **15 inter-linked templates**:

| Template | Records |
|---|---|
| **B_01.01** | Entity maintaining the register (entity / sub-consolidated / consolidated level) |
| **B_01.02** | List of entities within the scope of consolidation |
| **B_01.03** | List of branches outside the home country |
| **B_02.01** | Contractual arrangements — general; assigns unique reference numbers |
| **B_02.02** | Contractual arrangements — specific: ICT services, supported functions, notice periods, governing law, **data locations** |
| **B_02.03** | Intra-group arrangements, linked to external third-party arrangements |
| **B_03.01** | Entities signing contracts with direct ICT providers |
| **B_03.02** | ICT third-party providers signing arrangements |
| **B_03.03** | Group entities providing ICT services to other group entities |
| **B_04.01** | Entities **using** the ICT services |
| **B_05.01** | ICT third-party service providers — direct, intra-group, subcontractors, ultimate parents |
| **B_05.02** | **ICT service supply chains** — provider rankings and subcontractor relationships |
| **B_06.01** | Functions identification, with unique function identifiers |
| **B_07.01** | Risk assessments for critical/important functions (substitutability, audit dates) |
| **B_99.01** | Definitions — entity-specific explanations of closed-set indicators |

Key structural facts ([EUR-Lex](https://eur-lex.europa.eu/eli/reg_impl/2024/2956/oj/eng)): the templates form a **relational, key-based structure** linking contractual arrangements, entity/provider identifiers (LEI where available), functions, and ICT service types; a single contract typically produces **multiple rows** because each contract is decomposed into service lines using the ITS service taxonomy.

**What this means for VectaSec's Art. 28 register feature (from the README):** the honest read is that **VectaSec can populate perhaps 3 of the 15 templates and no more.** A scanner sees *technical* facts — which MCP server, which SaaS endpoint, which managed broker is actually wired in, and what it connects to. It cannot see contract reference numbers, governing law, notice periods, annual spend in EUR, or LEI codes. Those live in procurement and legal systems.

The defensible pitch is therefore **not** "VectaSec generates your Article 28 register." It is: **"VectaSec finds the ICT third-party dependencies that are missing from the register you already have"** — the shadow MCP server, the undocumented iPaaS connector, the SaaS webhook nobody declared. That is a *discovery/reconciliation* play against **B_05.01** (providers), **B_05.02** (supply chains / subcontractors — where a chained MCP server or a broker's upstream SaaS genuinely is a nth-party dependency), and **B_04.01** (which entities use which service). It is a real, differentiated, and *modest* claim, and it is far more credible than register-generation. Reporting the reconciliation gap is also directly useful, because Art. 28(3) requires the entity to notify the authority when a function *becomes* critical or important — a newly discovered dependency is exactly that trigger.

The reporting format is **xBRL-CSV** following the EBA taxonomy **[low confidence]** — see [§8](#8-verification-gaps).

### 2.4 Incident reporting — Articles 17–23

Titles, verbatim from [digital-operational-resilience-act.com](https://www.digital-operational-resilience-act.com/DORA_Articles.html):

| Art | Title |
|---|---|
| 17 | ICT-related incident management process |
| 18 | Classification of ICT-related incidents and cyber threats |
| 19 | Reporting of major ICT-related incidents and voluntary notification of significant cyber threats |
| 20 | Harmonisation of reporting content and templates |
| 21 | Centralisation of reporting of major ICT-related incidents |
| 22 | Supervisory feedback |
| 23 | Operational or security payment-related incidents concerning credit institutions, payment institutions, account information service providers, and electronic money institutions |

**Article 21** requires the ESAs to have produced a joint report by 17 January 2025 assessing the feasibility of "a single EU Hub for major ICT-related incident reporting by financial entities" ([DORA Art. 21](https://www.digital-operational-resilience-act.com/Article_21.html)) — a *future* consolidation of reporting, not a current obligation on entities.

**The deadlines** are set by **Commission Delegated Regulation (EU) 2025/301 of 20 February 2025**, Article 5 ([Springlex](https://www.springlex.eu/en/packages/dora/rts-ir-regulation/article-5/)):

| Report | Deadline (verbatim) |
|---|---|
| **Initial notification** | "within four hours from the classification of the ICT-related incident as a major ICT-related incident and no later than 24 hours from the moment the financial entity has become aware of the ICT-related incident" |
| **Intermediate report** | "at the latest within 72 hours from the submission of the initial notification" — with updates without undue delay when regular activities resume |
| **Final report** | "no later than one month after either the submission of the intermediate report, or, where applicable, after the latest updated intermediate report" |

Note the **two-clock structure** on the initial notification: 4h from *classification* **and** 24h from *awareness*, whichever binds first. A common misstatement is "4 hours from discovery" — it is not.

There is a **weekend/bank-holiday extension** (submission by noon the next working day) which does **not** apply to credit institutions, central counterparties, trading venue operators, or entities designated essential/important under NIS2; competent authorities may also remove it for other financially significant entities ([Springlex](https://www.springlex.eu/en/packages/dora/rts-ir-regulation/article-5/)).

**Product implication:** the 4-hour clock is a *response* obligation, not a *posture* obligation. VectaSec's findings do not map to Art. 19. What VectaSec plausibly contributes is Art. 17 (incident management process) evidence and asset/dependency context that shortens classification under Art. 18. Do not claim VectaSec "helps you meet the 4-hour deadline" without the runtime sensor — with posture-only data, that claim is not supportable.

---

## 3. NIS2 — Directive (EU) 2022/2555

### 3.1 Transposition status — messy, and that is the point

NIS2 was due to be transposed by **17 October 2024** ([EC press release, July 2026](https://europeansting.com/2026/07/13/commission-refers-ireland-spain-france-and-the-netherlands-to-the-court-of-justice-for-failing-to-transpose-the-rules-on-cybersecurity-2/)).

Verified enforcement timeline:

- **28 November 2024** — Commission sent letters of formal notice ([EC press release](https://europeansting.com/2026/07/13/commission-refers-ireland-spain-france-and-the-netherlands-to-the-court-of-justice-for-failing-to-transpose-the-rules-on-cybersecurity-2/)).
- **7 May 2025** — Commission issued **reasoned opinions to 19 Member States** for failing to notify complete transposition: Bulgaria, Czechia, Denmark, Germany, Estonia, Ireland, Spain, France, Cyprus, Latvia, Luxembourg, Hungary, the Netherlands, Austria, Poland, Portugal, Slovenia, Finland, Sweden ([EC — NIS2 transposition page](https://digital-strategy.ec.europa.eu/en/policies/nis-transposition)).
- **July 2026** — Commission **referred Ireland, Spain, France and the Netherlands to the Court of Justice of the EU**, requesting "a lump sum and daily penalties until notification of complete transposition" ([EC press release](https://europeansting.com/2026/07/13/commission-refers-ireland-spain-france-and-the-netherlands-to-the-court-of-justice-for-failing-to-transpose-the-rules-on-cybersecurity-2/)). Exact date is **[low confidence]** — see [§8](#8-verification-gaps).

The Commission's own transposition page carries the caveat that it reflects "a state-of-play based on information provided by Member States" and is "without prejudice to the formal assessment of the compliance" ([EC](https://digital-strategy.ec.europa.eu/en/policies/nis-transposition)) — and, notably, that page was **last updated 1 July 2025**, i.e. it is over a year stale as of today. Do not build a live compliance feature on it.

**The consequence for VectaSec is architectural, not cosmetic.** NIS2 is a **Directive**: the binding text is 27 different national laws, not the Directive itself. An Italian entity is measured against Italian law; an Irish entity is currently measured against *nothing* (which is why the Commission is in court). So a `controls` row with `framework='NIS2'` and `control_id='21.2.d'` is **citing a text that no entity is directly bound by**. The workable approach is to map to the Directive's Article 21(2) points as a *stable internal spine* and treat national law as a later per-jurisdiction overlay — while being explicit in the UI that this is a mapping to the Directive, not to the customer's national implementation. Ship NIS2 as the *lowest*-fidelity of the four frameworks, and price/position it accordingly. PCI and DORA are where the defensible claims are.

### 3.2 Article 21(2) — the ten measures

Verbatim from [nis-2-directive.com](https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html). The measures "shall include at least":

| Point | Text (verbatim) |
|---|---|
| **(a)** | "policies on risk analysis and information system security" |
| **(b)** | "incident handling" |
| **(c)** | "business continuity, such as backup management and disaster recovery, and crisis management" |
| **(d)** | "supply chain security, including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers" |
| **(e)** | "security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure" |
| **(f)** | "policies and procedures to assess the effectiveness of cybersecurity risk-management measures" |
| **(g)** | "basic cyber hygiene practices and cybersecurity training" |
| **(h)** | "policies and procedures regarding the use of cryptography and, where appropriate, encryption" |
| **(i)** | "human resources security, access control policies and asset management" |
| **(j)** | "the use of multi-factor authentication or continuous authentication solutions, secured voice, video and text communications and secured emergency communication systems within the entity, where appropriate" |

Article 21(1) carries a **proportionality principle** — the depth of controls must match the entity's risk exposure, size, and societal impact.

Notes for mapping:
- **(i)** — "access control policies **and asset management**" is the workhorse. Nearly every VectaSec authz/ACL finding lands here, and the asset-management clause covers the inventory itself.
- **(h)** — cryptography/encryption, for PLAINTEXT/TLS findings.
- **(d)** — supply chain, "**direct** suppliers or service providers". Note "direct": a chained/nth-party MCP server is arguably *not* a direct supplier, which weakens the tempting MCP→21(2)(d) mapping. Contrast DORA, which explicitly reaches subcontractors via ITS template B_05.02.
- **(j)** — MFA. **Do not map machine identity rules to (j).** MFA is a human-authentication concept; "continuous authentication" is the closest fit for workload identity and it is a stretch. This is a frequent vendor overreach.
- **(g)** — "basic cyber hygiene" is a legitimate home for default-credential findings, and is honest about what they are.

---

## 4. HIPAA Security Rule

### 4.1 Current rule — 45 CFR 164.312 (Technical safeguards)

Verbatim from [Cornell LII, 45 CFR § 164.312](https://www.law.cornell.edu/cfr/text/45/164.312):

| Cite | Standard / spec | R or A | Text (verbatim) |
|---|---|---|---|
| **164.312(a)(1)** | Access control | Standard | "Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights" |
| **164.312(a)(2)(i)** | Unique user identification | **Required** | "Assign a unique name and/or number for identifying and tracking user identity" |
| **164.312(a)(2)(ii)** | Emergency access procedure | **Required** | "Establish (and implement as needed) procedures for obtaining necessary electronic protected health information during an emergency" |
| **164.312(a)(2)(iii)** | Automatic logoff | *Addressable* | "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity" |
| **164.312(a)(2)(iv)** | Encryption and decryption | *Addressable* | "Implement a mechanism to encrypt and decrypt electronic protected health information" |
| **164.312(b)** | Audit controls | Standard | "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information" |
| **164.312(c)(1)** | Integrity | Standard | "Implement policies and procedures to protect electronic protected health information from improper alteration or destruction" |
| **164.312(d)** | Person or entity authentication | Standard | "Implement procedures to verify that a person or entity seeking access to electronic protected health information is the one claimed" |
| **164.312(e)(1)** | Transmission security | Standard | "Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network" |
| **164.312(e)(2)(i)** | Integrity controls | *Addressable* | "Implement security measures to ensure that electronically transmitted electronic protected health information is not improperly modified without detection" |
| **164.312(e)(2)(ii)** | Encryption | *Addressable* | "Implement a mechanism to encrypt electronic protected health information whenever deemed appropriate" |

**Two things to get right.**

**First — 164.312(a)(1) says "persons *or software programs*".** That is a 2003 rule text that natively covers non-human identity. It is a genuinely good fit for broker/gateway service-account findings, and better than most people assume. Lean on it.

**Second — encryption in HIPAA is *Addressable*, not *Required*.** This is the most misrepresented fact in health-IT compliance marketing. "Addressable" does not mean optional, but it also does not mean "encrypt or fail": a covered entity may document why a specification is not reasonable and appropriate and implement an equivalent alternative. So `KAFKA.LISTENER.PLAINTEXT` on an ePHI broker is **not automatically a HIPAA violation** — it is a violation of the (Required) 164.312(e)(1) *standard* only if no equivalent measure is in place. VectaSec should map PLAINTEXT to **164.312(e)(1)** (the Required standard) and cite (e)(2)(ii) as the addressable spec, with UI language that permits a documented alternative. Claiming a hard HIPAA failure on unencrypted transit is legally wrong and a knowledgeable healthcare CISO will notice immediately.

**Note (d) "person or entity"** — again explicitly reaches non-human entities.

### 4.2 Status of the 2025 proposed Security Rule update — **still proposed**

Verified directly against the Federal Register API on 2026-07-17:

- **"HIPAA Security Rule To Strengthen the Cybersecurity of Electronic Protected Health Information"**, document **2024-30983**, **RIN 0945-AA22**, HHS / Office of the Secretary.
- **Type: `Proposed Rule`**. **Published 2025-01-06.** **Comments closed 2025-03-07.**
  ([Federal Register document](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information); verified via `https://www.federalregister.gov/api/v1/documents/2024-30983.json`)
- **A query of every Federal Register document under RIN 0945-AA22 returns `count: 1`** — the NPRM itself. As of 2026-07-17 there is **no final rule and no withdrawal notice** published under that RIN. (Verified via `https://www.federalregister.gov/api/v1/documents.json?conditions[regulation_id_number]=0945-AA22`.)

The NPRM proposed removing the Required/Addressable distinction and mandating encryption, MFA, asset inventory, and network segmentation **[low confidence — see [§8](#8-verification-gaps)]**. Reported industry opposition and a final-action date pushed to 2027 are **[low confidence]** and should not be repeated to customers without checking.

**Product implication:** build against the **current** rule (§4.1). The NPRM is a roadmap signal, not a requirement — 18 months after the comment period closed it has not been finalised, and its direction of travel (mandatory encryption, mandatory MFA, mandatory asset inventory) happens to describe VectaSec's product. That is a good story for a *forward-looking* slide and a bad basis for a `controls` row. If it is surfaced at all, gate it behind an explicit "proposed — not in force" flag.

---

## 5. OSCAL — what it is and what VectaSec should export

**OSCAL (Open Security Controls Assessment Language)** is "a NIST-led initiative developed in collaboration with industry to modernize and automate the processes of security and compliance," delivering "open, machine-readable formats available in XML, JSON, and YAML that streamline control-based risk assessments" ([NIST OSCAL](https://pages.nist.gov/OSCAL/)).

**Current release: v1.2.2, released 30 April 2026** ([OSCAL releases](https://github.com/usnistgov/OSCAL/releases)). Recent history: v1.2.1 (6 Mar 2026); **v1.2.0 (12 Dec 2025) — "introducing the Control Mapping Model"**; v1.1.3 (26 Nov 2025).

### 5.1 The models

Per [NIST OSCAL — Layers and Models](https://pages.nist.gov/OSCAL/learn/concepts/layer/):

**Control layer**
- **Catalog** — expresses and organizes security controls machine-readably. "Controls from any control-based framework can be expressed in an OSCAL catalog." Foundation for all other models.
- **Profile** — select, organize, and tailor controls from catalogs into a baseline, with traceability back to the originals.
- **Control Mapping** — "represents relationships among controls across different frameworks," identifying source and target frameworks and documenting relationships via metadata such as equivalence or subset.

**Implementation layer**
- **System Security Plan (SSP)** — documents security implementation for a system within a baseline.
- **Component Definition** — "a description of the controls that are supported in a given implementation of a hardware, software, service, policy, process, or procedure," including the provider, name/version, controls the component could satisfy, configuration options for achieving security objectives, and "assessment tests or scripts that may be used to validate the component's implementation" ([NIST — Component Definition](https://pages.nist.gov/OSCAL/learn/concepts/layer/implementation/component-definition/), via search index). Component definition content can be imported into SSPs to pre-populate implementation info.

**Assessment layer**
- **Assessment Plan** — intended assessment activities: scope, timing, methodology.
- **Assessment Results** — "information related to the findings of a periodic or continuous assessment of a specific system"; reports "what was assessed, how it was assessed, who performed the assessment, what was found, and what risks were identified."
- **POA&M** — findings requiring remediation, with corrective actions and timelines.

### 5.2 Recommendation for VectaSec — export **three**, in this order

**1. Assessment Results — build this first.** It is the exact shape of what VectaSec produces: a scan of a specific system, at a time, by a tool, yielding findings and risks. Every field has an obvious source in the existing schema (`findings`, `observations`, `scans`, `resources`). It is the fastest credible OSCAL story and it is what a customer's GRC tool actually wants to ingest. `observations` is a first-class OSCAL Assessment Results concept and VectaSec already has a table named exactly that — the impedance match is unusually good, and it strongly suggests Assessment Results is the natural primary export.

**2. Component Definition — this is the strategic one.** Component Definition is *literally the OSCAL model for "here is a component, and here are the controls it can satisfy, and here are the assessment tests that validate it."* That is a one-to-one description of `RULE_TO_CONTROLS` plus VectaSec's detectors. A published VectaSec component definition for "Apache Kafka," "Kong Gateway," "RabbitMQ," "MCP server" — each declaring the controls implicated and the checks that validate them — is a *reusable, machine-readable artifact* that a customer imports into their SSP. That is defensible category leadership: it makes VectaSec's opinion about middleware compliance into a portable standard object, and it is the natural OSCAL home for this whole document. It is also the format in which this mapping table should eventually be *maintained*, rather than as a Python dict.

**3. Control Mapping — new in v1.2.0 (12 Dec 2025), and directly on point.** It exists to represent "relationships among controls across different frameworks" with equivalence/subset metadata. VectaSec's cross-framework crosswalk (PCI 7.2.5 ≈ DORA 9(4) ≈ NIS2 21(2)(i) ≈ HIPAA 164.312(a)(1)) is exactly a control mapping document. **Caveat:** it is ~7 months old, tooling support is likely thin, and this is a bet — so treat it as the third priority and re-check ecosystem support before committing. The upside is that it lets VectaSec express the "defensible vs stretch" judgment in [§6](#6-rule_to_controls--the-proposed-mapping) as first-class metadata rather than a comment in a source file, which is precisely the honesty this product needs.

**Do not export SSP.** An SSP is the customer's document about their whole system; VectaSec has no basis to author one and doing so would overclaim. **POA&M is a plausible fourth** (findings + remediation + timeline is a natural fit) but only once findings carry owners and due dates.

---

## 6. RULE_TO_CONTROLS — the proposed mapping

### 6.1 Legend

**Relation:**
- `violates` — a hit is direct evidence the control is not met (on that asset).
- `supports` — a hit is *partial* evidence; the control is broader than the rule.
- `informs` — the finding is context for the control; not evidence of failure.

**Confidence** — how well the mapping would survive an auditor challenge:
- **A — defensible.** The control text describes this misconfiguration. Assert it.
- **B — conditional.** Defensible *only* if the gating condition holds (scope tag, exposure, data class). Assert only when the gate is satisfied; otherwise `not_applicable`.
- **C — stretch.** Directionally related; the control text does not really describe this. **Do not auto-assert.** Show as "related guidance" at most.

Framework-level gates, applied before any row: PCI → asset has `cde`; HIPAA → asset has `ephi`; DORA → tenant is a financial entity **and** asset supports an ICT function; NIS2 → tenant is essential/important.

### 6.2 The table

#### `KAFKA.LISTENER.PLAINTEXT`
*Broker listener configured with the `PLAINTEXT` security protocol — no TLS, no authentication on that listener.*

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| PCI DSS 4.0.1 | **2.2.5** | violates | **A** | "If any insecure services, protocols, or daemons are present: Business justification is documented. Additional security features are documented and implemented..." A plaintext listener is the paradigm case. The finding proves the *condition*; the entity must produce the justification. |
| PCI DSS 4.0.1 | **2.2.1** | violates | **A** | Hardening standards "consistent with...vendor hardening recommendations" — Kafka documents TLS/SASL listeners as the secure configuration ([Kafka authz docs](https://kafka.apache.org/41/security/authorization-and-acls/)). |
| PCI DSS 4.0.1 | **1.2.5 / 1.2.6** | violates | **A** | 1.2.5 "All services, protocols, and ports allowed are identified, approved, and have a defined business need"; 1.2.6 security features for in-use insecure protocols. |
| PCI DSS 4.0.1 | **4.2.1** | violates | **B** | **Gate: PAN + listener reachable from an open, public network.** 4.2.1 is explicitly scoped to "PAN during transmission over open, public networks". An internal-only broker is out of scope. Surface as a candidate for human confirmation. |
| PCI DSS 4.0.1 | **8.3.2** | violates | **B** | **Gate: listener is `SASL_PLAINTEXT`** (credentials in the clear). "Strong cryptography is used to render all authentication factors unreadable during transmission." Does not apply to bare `PLAINTEXT` with no auth. |
| PCI DSS 4.0.1 | **2.2.7** | violates | **C** | Only if the plaintext listener carries *administrative* access. Data-plane traffic is not "non-console administrative access." Usually a stretch. |
| DORA | **Art. 9(2)**, **9(3)** | supports | **B** | 9(2) requires high data standards "in transit"; 9(3) requires securing data transfer means. Coarse — evidence for the Art. 6 framework, not a pass/fail. |
| NIS2 | **21(2)(h)** | supports | **B** | "policies and procedures regarding the use of cryptography and, where appropriate, encryption." Mapping is to the Directive, not national law. |
| HIPAA | **164.312(e)(1)** | violates | **B** | **Gate: ePHI in transit.** Required standard. Cite **(e)(2)(ii)** (Addressable) as the spec — a documented equivalent alternative is permissible. Never assert a flat HIPAA failure. |

#### `KAFKA.AUTHZ.*`
*e.g. `AUTHZ.DISABLED` (no `authorizer.class.name`), `AUTHZ.ALLOW_EVERYONE` (`allow.everyone.if.no.acl.found=true`), `AUTHZ.SUPERUSER_BROAD`.*

Grounding: by default, "if a resource does not have any ACLs defined, Kafka will restrict access to that resource" and "only super users are allowed to access it"; setting `allow.everyone.if.no.acl.found=true` reverses this to allow "access to everyone" ([Kafka — Authorization and ACLs](https://kafka.apache.org/41/security/authorization-and-acls/)). `authorizer.class.name` selects the implementation; `StandardAuthorizer` stores ACLs in the KRaft metadata log ([ibid.](https://kafka.apache.org/41/security/authorization-and-acls/)).

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| PCI DSS 4.0.1 | **7.2.5** | violates | **A** | "All application and system accounts and related access privileges are assigned and managed as follows: Based on the least privileges necessary..." No authorizer = no privilege limitation at all. Strongest mapping. |
| PCI DSS 4.0.1 | **7.2.1** | violates | **A** | "An access control model is defined and includes granting access as follows:...The least privileges required." A disabled authorizer means no enforceable access control model exists on that broker. |
| PCI DSS 4.0.1 | **2.2.6** | violates | **A** | "System security parameters are configured to prevent misuse" — `allow.everyone.if.no.acl.found=true` is the definitional misuse-enabling parameter. |
| PCI DSS 4.0.1 | **2.2.1** | violates | **A** | Deviation from vendor hardening guidance. |
| PCI DSS 4.0.1 | **7.2.2** | violates | **C** | Text says "Access is assigned to **users**...Job classification and function." Kafka principals are services, not job classifications. Prefer 7.2.5. |
| DORA | **Art. 9(4)** (access control policy) | supports | **B** | "access control policies limiting physical/logical access to approved functions only" ([Art. 9](https://www.digital-operational-resilience-act.com/Article_9.html)). |
| NIS2 | **21(2)(i)** | supports | **B** | "access control policies and asset management." |
| HIPAA | **164.312(a)(1)** | violates | **B** | **Gate: ePHI.** "allow access only to those persons **or software programs** that have been granted access rights" — reaches machine identity natively. |

#### `KAFKA.ACL.*`
*e.g. `ACL.WILDCARD` (`User:*` principal or `*` resource pattern), `ACL.ORPHANED` (ACL for a principal with no active client), `ACL.OVERBROAD` (cluster-wide `ALL` where topic-scoped would do).*

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| PCI DSS 4.0.1 | **7.2.5** | violates | **A** | "Access is limited to the systems, applications, or processes that specifically require their use." A `User:*` / `*` ACL is the negation of this sentence. The single best rule→control fit in this document. |
| PCI DSS 4.0.1 | **7.2.5.1** | supports | **A** (for `ACL.ORPHANED`) | "All access by application and system accounts...are reviewed...Periodically." An orphaned-ACL finding is evidence the periodic review is not happening or is ineffective. VectaSec's inventory *is* review evidence. |
| PCI DSS 4.0.1 | **7.2.1** | violates | **B** | Defensible where the ACL grants admin-equivalent cluster rights. |
| PCI DSS 4.0.1 | **7.2.2** | violates | **C** | "users"/"job classification" — same objection as above. |
| PCI DSS 4.0.1 | **8.2.2** | violates | **C** | Only if a *shared* principal is used across services. VectaSec can rarely prove sharing from broker config alone. |
| DORA | **Art. 9(4)** (access control policy) | supports | **B** | Least-privilege logical access. |
| NIS2 | **21(2)(i)** | supports | **B** | Access control policies. |
| HIPAA | **164.312(a)(1)** | violates | **B** | **Gate: ePHI.** "software programs...granted access rights." |

#### `RABBITMQ.DEFAULT_USER`
*Default `guest` user present; higher severity if `loopback_users` no longer restricts it to localhost.*

Grounding: RabbitMQ creates a default `guest`/`guest` user on first startup, prohibited from connecting from remote hosts (loopback only) by default via `loopback_users`. The docs state it is "**highly recommended** to pre-configure a new user with a generated username and password or delete the `guest` user or at least change its password"; "Production environments should not use the default user"; and allowing remote connections for it "will dramatically reduce the security of the cluster" ([RabbitMQ — Access Control](https://www.rabbitmq.com/docs/access-control)).

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| PCI DSS 4.0.1 | **2.2.2** | violates | **A+** | "Vendor default accounts are managed as follows: If the vendor default account(s) will be used, the default password is changed per Requirement 8.3.6. If the vendor default account(s) will not be used, the account is removed or disabled." This is the cleanest mapping in the whole table — the requirement was written for exactly this. |
| PCI DSS 4.0.1 | **2.2.1** | violates | **A** | Vendor's own hardening recommendation, in the vendor's own words ([RabbitMQ docs](https://www.rabbitmq.com/docs/access-control)). Cite the doc in the finding. |
| PCI DSS 4.0.1 | **8.6.3** | violates | **B** | "Passwords/passphrases for any application and system accounts are protected against misuse...changed periodically...constructed with sufficient complexity." A password of `guest` fails on complexity. **8.6.3 has no interactive-login qualifier**, unlike 8.6.1/8.6.2 — so it is the right 8.6.x hook here. |
| PCI DSS 4.0.1 | **2.2.4** | violates | **B** | **Gate: guest not in use.** "all unnecessary functionality is removed or disabled." |
| PCI DSS 4.0.1 | **8.6.1 / 8.6.2** | violates | **C** | Both are gated on "can be used for interactive login". Do not assert without establishing that. |
| DORA | **Art. 9(4)** (strong authentication) | supports | **B** | "strong authentication mechanisms, based on relevant standards" ([Art. 9](https://www.digital-operational-resilience-act.com/Article_9.html)). |
| NIS2 | **21(2)(g)** | supports | **B** | "basic cyber hygiene practices" — an honest home for default creds. |
| NIS2 | **21(2)(i)** | supports | **B** | Access control policies. |
| HIPAA | **164.312(d)** | violates | **B** | **Gate: ePHI.** "verify that a person or entity seeking access...is the one claimed" — a shared, world-known default defeats this. |

*Note: HIPAA §164.308(a)(5)(ii)(D) (password management) is likely also relevant but sits in the Administrative Safeguards, which were not fetched in this pass. Do not cite it until verified.*

#### `KONG.AUTH.*`
*e.g. `AUTH.MISSING` (route/service with no auth-class plugin), `AUTH.WEAK` (key-auth on a sensitive route), `AUTH.ANONYMOUS_CONSUMER`.*

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| PCI DSS 4.0.1 | **7.2.1** | violates | **A** | No enforceable access control model on that route. |
| PCI DSS 4.0.1 | **7.2.5** | violates | **B** | **Gate: route is machine-consumed.** Least privilege for application/system accounts. |
| PCI DSS 4.0.1 | **1.2.5** | violates | **B** | An unauthenticated route is a service/port without a "defined business need" — defensible when the route is exposed. |
| PCI DSS 4.0.1 | **8.3.1** | violates | **B** | **Gate: route is human-consumed.** "All **user** access to system components for users and administrators is authenticated via at least one of the following authentication factors." |
| PCI DSS 4.0.1 | **8.2.1** | violates | **C** | "All **users** are assigned a unique ID" — stretch for M2M routes. |
| PCI DSS 4.0.1 | **6.4.2** | violates | **C** | ✗ **Common error.** 6.4.2 is a WAF requirement, not an auth requirement. Missing auth ≠ missing WAF. Route 6.4.2 to a dedicated `KONG.WAF.MISSING` rule instead (see [§7](#7-gaps-in-the-rule-set-this-research-exposes)). |
| DORA | **Art. 9(4)** (access control policy) | supports | **B** | Logical access limited to approved functions. |
| NIS2 | **21(2)(i)** | supports | **B** | Access control policies. |
| HIPAA | **164.312(a)(1)**, **164.312(d)** | violates | **B** | **Gate: ePHI.** (a)(1) covers "software programs"; (d) covers "person **or entity**". |

#### `KONG.ADMIN_API.*`
*e.g. `ADMIN_API.EXPOSED` (`admin_listen` on `0.0.0.0`), `ADMIN_API.PLAINTEXT` (HTTP), `ADMIN_API.NO_RBAC` (`enable_rbac` off).*

Grounding: "By default, Kong Gateway only accepts requests from the local interface (`127.0.0.1:8001`)"; "avoid using values such as `0.0.0.0:8001`" as this could "seriously compromise the security of your whole Kong cluster"; where the Admin API must extend beyond localhost "the best practice is to restrict network-layer access as much as possible"; RBAC provides "fine-grained control over resource access based on a model of user roles and permissions" ([Kong — Secure the Admin API](https://developer.konghq.com/gateway/secure-the-admin-api/)).

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| PCI DSS 4.0.1 | **2.2.1** | violates | **A** | Direct contradiction of the vendor's documented hardening recommendation — quote Kong's own sentence as the observation. |
| PCI DSS 4.0.1 | **2.2.7** | violates | **A** (for `ADMIN_API.PLAINTEXT`) | "All non-console administrative access is encrypted using strong cryptography." The Kong Admin API over HTTP is the textbook instance — this is 2.2.7's home turf, unlike the data-plane case above. |
| PCI DSS 4.0.1 | **1.2.5 / 1.2.6** | violates | **A** (for `EXPOSED`) | Service/port without defined business need; insecure protocol in use without mitigating features. |
| PCI DSS 4.0.1 | **7.2.1** | violates | **A** (for `NO_RBAC`) | No access control model with least privilege on the admin plane. |
| PCI DSS 4.0.1 | **2.2.4** | violates | **B** | "Only necessary services...are enabled" — a remotely-bound admin listener that need not be remote. |
| PCI DSS 4.0.1 | **1.3.1 / 1.4.2** | violates | **B** | **Gate: exposed to an untrusted network.** Inbound restriction to only necessary traffic. |
| PCI DSS 4.0.1 | **8.2.1 / 8.3.1** | violates | **B** | **Gate: admin API is human-operated.** Admin access without identity. |
| PCI DSS 4.0.1 | **10.2.1.2** | supports | **B** | "Audit logs capture all actions taken by any individual with administrative access" — relevant if admin API access is unlogged. |
| DORA | **Art. 9(4)** (network mgmt / segmentation, access control) | supports | **B** | Art. 9(4) requires a network management structure and the ability to sever/segment connections ([Art. 9](https://www.digital-operational-resilience-act.com/Article_9.html)). |
| NIS2 | **21(2)(i)** | supports | **B** | Access control policies. |
| HIPAA | **164.312(a)(1)** | violates | **B** | **Gate: ePHI behind the gateway.** |

#### `MCP.AUTH.*`
*e.g. `AUTH.MISSING` (HTTP-transport MCP server with no authorization), `AUTH.NO_PRM` (no RFC 9728 Protected Resource Metadata), `AUTH.NO_AUDIENCE_VALIDATION`, `AUTH.TOKEN_PASSTHROUGH`, `AUTH.NO_PKCE`, `AUTH.SECRET_IN_MANIFEST`.*

**Read this before mapping.** The current MCP protocol revision is **2025-11-25** ([MCP versioning](https://modelcontextprotocol.io/specification/versioning)) — *not* 2025-06-18, which many tools still cite. In that revision, **"Authorization is OPTIONAL for MCP implementations"**; HTTP-transport implementations **SHOULD** conform; STDIO implementations **SHOULD NOT** follow it and should take credentials from the environment ([MCP 2025-11-25 — Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)). So a bare `MCP.AUTH.MISSING` on a local STDIO server is **not** a spec violation and must not be reported as one. The rule must gate on transport.

Once authorization *is* supported, the spec's **MUST**s are hard and checkable ([MCP 2025-11-25 — Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)):
- "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata ([RFC9728](https://datatracker.ietf.org/doc/html/rfc9728))...**MUST** include the `authorization_servers` field containing at least one authorization server."
- "MCP servers **MUST** validate that access tokens were issued specifically for them as the intended audience, according to RFC 8707 Section 2."
- "MCP servers **MUST NOT** accept or transit any other tokens." / "The MCP server **MUST NOT** pass through the token it received from the MCP client."
- "MCP clients **MUST** implement PKCE...and **MUST** verify PKCE support before proceeding" and "**MUST** use the `S256` code challenge method when technically capable."
- "Access tokens **MUST NOT** be included in the URI query string."
- Clients **MUST** send the RFC 8707 `resource` parameter "regardless of whether authorization servers support it."

Changes in 2025-11-25 vs 2025-06-18 that affect detector logic: Dynamic Client Registration dropped from **SHOULD** to **MAY** (retained for backwards compatibility); **Client ID Metadata Documents** added as the preferred no-prior-relationship path; AS discovery now allows RFC 8414 **or** OpenID Connect Discovery, with a mandated probe order; explicit PKCE-support verification added.

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| **MCP spec 2025-11-25** | Token Handling / Access Token Privilege Restriction | violates | **A** | For `NO_AUDIENCE_VALIDATION` and `TOKEN_PASSTHROUGH`: unambiguous **MUST**/**MUST NOT**. Cite the spec clause directly — this is a *specification* violation, which is a stronger and cleaner claim than any framework mapping here. |
| **MCP spec 2025-11-25** | Authorization Server Discovery (RFC 9728) | violates | **A** | For `NO_PRM`: "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata." |
| PCI DSS 4.0.1 | **8.6.2** | violates | **A** | For `SECRET_IN_MANIFEST`: "not hard coded in scripts, **configuration/property files**, or bespoke and custom source code." An API key in an MCP server manifest/config is this requirement, verbatim. Best framework mapping in the MCP family. |
| PCI DSS 4.0.1 | **7.2.5** | violates | **B** | For over-scoped tokens: "Access is limited to the systems, applications, or processes that specifically require their use." |
| PCI DSS 4.0.1 | **8.6.3** | violates | **B** | MCP server credentials are application/system account passwords; no interactive-login gate on 8.6.3. |
| PCI DSS 4.0.1 | **7.2.1** | violates | **B** | **Gate: HTTP transport + CDE reachable.** No access control model. |
| PCI DSS 4.0.1 | **2.2.5** | violates | **B** | Unauthenticated remote MCP endpoint as an insecure service in use. |
| PCI DSS 4.0.1 | **8.3.1** | violates | **C** | "user access" — MCP is agent-to-server. Stretch. |
| DORA | **Art. 9(4)** (strong authentication) | supports | **B** | "strong authentication mechanisms, **based on relevant standards**" — OAuth 2.1 / RFC 9728 / RFC 8707 *are* the relevant standards, which makes this mapping unusually well-grounded for DORA. |
| DORA | **Art. 28(3)** | informs | **B** | A remote/hosted MCP server is plausibly an ICT third-party service requiring a register entry — feeds template B_05.01/B_05.02 ([ITS 2024/2956](https://eur-lex.europa.eu/eli/reg_impl/2024/2956/oj/eng)). |
| NIS2 | **21(2)(i)** | supports | **B** | Access control policies. |
| NIS2 | **21(2)(j)** | supports | **C** | ✗ MFA/continuous authentication is a *human* concept. Do not assert for agent identity. |
| HIPAA | **164.312(d)** | violates | **B** | **Gate: ePHI.** "person **or entity**". |

#### `MCP.TOOL.*`
*e.g. `TOOL.POISONING` (instructions embedded in a tool description), `TOOL.OVERBROAD_SCOPE`, `TOOL.SHADOWING`, `TOOL.MUTABLE_DEFINITION` (rug-pull), `TOOL.UNPINNED_SOURCE`.*

**Be honest: this family has no good framework mapping, and that is a finding in itself.** None of PCI DSS 4.0.1, DORA, NIS2, or the current HIPAA Security Rule contemplates a model-facing tool description as an attack surface. Every mapping below is weak. **Do not let this family carry a compliance badge in the UI.** Its value is security value, not compliance value — and the product should say so. Forcing a mapping here is exactly the sort of thing that would discredit the mappings that *are* strong (7.2.5, 8.6.2, 2.2.2).

| Framework | Control | Rel | Conf | Justification |
|---|---|---|---|---|
| NIS2 | **21(2)(e)** | supports | **C** | "security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure." The least-bad fit: a poisoned tool is a vulnerability in an acquired component. Still a stretch. |
| NIS2 | **21(2)(d)** | supports | **C** | "supply chain security...relationships between each entity and its **direct** suppliers." Note **direct** — a chained MCP server is arguably not a direct supplier, which weakens this further. |
| DORA | **Art. 8** (Identification) | informs | **B** | Inventorying MCP tools is Art. 8 identification evidence. This is the honest mapping: *inventory*, not *control failure*. |
| DORA | **Art. 28(3)** | informs | **B** | Third-party-provided MCP tools may need register entries (B_05.01/B_05.02). |
| DORA | **Art. 9(2)** | supports | **C** | Generic "implement ICT security...tools." Too vague to assert. |
| PCI DSS 4.0.1 | **6.3.x / 6.2.4** | supports | **C** | Secure development / vulnerability identification — only if the MCP server is bespoke/custom software the entity wrote. Not verified in this pass; do not cite without checking the text. |
| PCI DSS 4.0.1 | **2.2.1** | violates | **B** | For `TOOL.MUTABLE_DEFINITION`/`UNPINNED_SOURCE`: config-standard drift. Weak but real. |
| HIPAA | — | — | — | **No mapping.** Say so. |

### 6.3 Suggested code shape

Matches `registry.py`'s existing decorator style and the `controls` table (`framework`, `control_id`, `status`, `failing_finding_ids`):

```python
# services/engine/src/vectasec/compliance/map.py
from dataclasses import dataclass

@dataclass(frozen=True)
class ControlRef:
    framework: str       # PCI_DSS_4_0_1 | DORA | NIS2 | HIPAA | MCP_SPEC_2025_11_25
    control_id: str      # "7.2.5" | "9.4" | "21.2.i" | "164.312(a)(1)"
    relation: str        # violates | supports | informs
    confidence: str      # A | B | C
    gate: tuple = ()     # ('cde',) ('ephi',) ('public_facing',) ('sasl',) ('http_transport',)
    note: str = ""       # shown in the UI next to the citation
    source_url: str = "" # every control_id must carry the URL it was read from

RULE_TO_CONTROLS: dict[str, tuple[ControlRef, ...]] = { ... }
```

Enforcement the engine must apply:
1. **Never emit `status='pass'`** from this map. Only `fail` / `unknown` / `not_applicable` (Rule 1, §0).
2. **Drop any ref whose `gate` is unsatisfied** by the asset's scope tags → `not_applicable` (Rule 2, §0).
3. **Never auto-assert `confidence='C'`.** Render as "related guidance", excluded from any score.
4. **`source_url` is mandatory.** This mirrors the citation gate the README already applies to AI output (`ai_outputs`) — a compliance claim without a source is the same defect as an ungrounded AI claim, and should fail the same way.
5. **Pin the framework version in `framework`**, not just the name. `PCI_DSS_4_0_1` (already the schema's convention) is right; extend it to `MCP_SPEC_2025_11_25`, since MCP revisions move fast enough to invalidate detectors.

---

## 7. Gaps in the rule set this research exposes

Three rule families are *missing* and map to strong, currently-audited controls. These are cheap to build and land on better requirements than several rules already planned:

1. **`*.SECRET.HARDCODED`** → **PCI 8.6.2** (**A**). "not hard coded in scripts, configuration/property files, or bespoke and custom source code." Applies to Kafka `.properties`, Kong declarative config, RabbitMQ definitions, MCP manifests, compose files. Mandatory since 31 March 2025, dead-centre on the NHI wedge, and VectaSec already plans integration-as-code static analysis. **Highest-value missing rule.**
2. **`KONG.WAF.MISSING`** (public-facing route with no WAF-class plugin) → **PCI 6.4.2** (**A**). Currently 6.4.2 has no rule that legitimately maps to it; it is mandatory since 31 March 2025 and is answerable from Kong's plugin chain.
3. **`*.ACCOUNT.STALE` / `*.ACL.ORPHANED`** → **PCI 7.2.5.1** (**A**). Periodic review of application/system account access. VectaSec's inventory is the review artifact — a rare case where the product *is* the control.

Also worth noting: **PCI 10.x is under-served.** Rules like `KAFKA.AUDIT.DISABLED` / `KONG.LOG.MISSING` would map to 10.2.1 and 10.2.1.2 (**A**), and 10.2.1.2's "including any interactive use of application or system accounts" pairs naturally with the 8.6.1 narrative.

---

## 8. Verification gaps

Everything here is **[low confidence]** — flagged rather than dropped, with what it would take to confirm.

| Claim | Status | To verify |
|---|---|---|
| **PCI requirement text is authentic** | Quoted from a [Genesys vendor responsibility matrix](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf), not the standard. The PCI SSC PDF is behind a click-through agreement and could not be fetched. | Download PCI DSS v4.0.1 from the PCI SSC Document Library and diff every quoted string. **Do this before any customer-facing use.** |
| **Which specific requirements are in the 51 future-dated set** | The PCI SSC blog confirms *51 requirements* and the *31 March 2025* date, and names only 11.3.2 and 12.5.2. Membership of 6.4.2 / 7.2.5.1 / 8.6.1–8.6.3 comes from secondary summaries not independently fetched. One secondary source said "1 April 2025" rather than "31 March 2025" — effectively the same boundary, but the discrepancy is unresolved. | Check the "Applicability Notes" column in the official v4.0.1 PDF, or Appendix A of the v4.0→v4.0.1 Summary of Changes. |
| **PCI DSS v4.0 retired 31 Dec 2024** | Search-summary only; not independently fetched. Does not affect the mapping (v4.0.1 is current either way). | PCI SSC standards/retirement notice. |
| **Exact date of the NIS2 CJEU referral** | Sources conflict: the EC transposition page referenced a **8 July 2026** press release; the [European Sting mirror](https://europeansting.com/2026/07/13/commission-refers-ireland-spain-france-and-the-netherlands-to-the-court-of-justice-for-failing-to-transpose-the-rules-on-cybersecurity-2/) is dated **13 July 2026**. The canonical EC press release ([ip_26_1499](https://ec.europa.eu/commission/presscorner/detail/en/ip_26_1499)) is JS-rendered and returned no body. **The four countries and the fact of referral are confirmed; only the date is uncertain.** | Retrieve ip_26_1499 via a JS-capable fetch or the EC press API. |
| **"22 of 27 Member States have transposed"** | Search-summary from secondary trackers only. The EC's own page was **last updated 1 July 2025** and is stale. | Per-country check against the EC page's country links, or ENISA/ECSO trackers. **Do not put a live count in the product.** |
| **DORA register reporting format is xBRL-CSV / EBA Taxonomy 4.0** | Search-summary only; not in the fetched EUR-Lex content. | EBA reporting framework / DPM taxonomy pages. |
| **HIPAA NPRM contents** (removing Required/Addressable, mandating encryption, MFA, asset inventory, segmentation) | Search-summary only. The **status** (still a Proposed Rule, no final rule under RIN 0945-AA22 as of 2026-07-17) **is** verified via the Federal Register API. | Read the NPRM body at [federalregister.gov/documents/2025/01/06/2024-30983](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information). |
| **HIPAA final rule now targeted for July 2027; industry withdrawal requests; ~$9bn cost estimate** | Search-summary only. Plausible but unverified. **Do not repeat to customers.** | OMB Unified Agenda (reginfo.gov) under RIN 0945-AA22. |
| **HIPAA §164.308(a)(5)(ii)(D)** (password management) relevance to default creds | Not fetched — only §164.312 was retrieved. | [law.cornell.edu/cfr/text/45/164.308](https://www.law.cornell.edu/cfr/text/45/164.308). |
| **PCI 6.2.4 / 6.3.x text** (cited as **C** for `MCP.TOOL.*`) | Not fetched. | Official v4.0.1 PDF. |
| **Kafka: default of `allow.everyone.if.no.acl.found`** | The [Kafka docs](https://kafka.apache.org/41/security/authorization-and-acls/) describe restrictive default behaviour but do not state the literal default value in the fetched text. Behaviour is confirmed; the literal default (`false`) is inferred. | Kafka broker configuration reference. |
| **Kafka: no `authorizer.class.name` ⇒ no authorization** | Inferred from "pluggable authorization framework"; the fetched docs do not state it explicitly. The `AUTHZ.DISABLED` rule depends on this. | Kafka broker config reference / KIP-500 authorizer docs. |
| **DORA Art. 5–15 / 17–23 titles and Art. 9 / 28 text** | From [digital-operational-resilience-act.com](https://www.digital-operational-resilience-act.com/DORA_Articles.html), a third-party mirror. The [EUR-Lex CELEX:32022R2554](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32022R2554) fetch truncated before the operative articles. | Re-fetch EUR-Lex per-article, or the OJ PDF. |
| **NIS2 Art. 21(2) text** | From [nis-2-directive.com](https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html), a third-party mirror. | EUR-Lex CELEX:32022L2555. |
| **OSCAL Component Definition description** | From the search index rather than a direct fetch of the [NIST page](https://pages.nist.gov/OSCAL/learn/concepts/layer/implementation/component-definition/) (the layer overview *was* fetched directly and corroborates it). | Direct fetch. |
| **OSCAL Control Mapping Model maturity/tooling** | v1.2.0 release date (12 Dec 2025) is verified via [GitHub releases](https://github.com/usnistgov/OSCAL/releases). Ecosystem support is an assumption. | OSCAL docs + community tooling survey before committing. |

---

## 9. Sources fetched

Primary / official:
- [PCI SSC — Now is the Time for Organizations to Adopt the Future-Dated Requirements of PCI DSS v4.x](https://blog.pcisecuritystandards.org/now-is-the-time-for-organizations-to-adopt-the-future-dated-requirements-of-pci-dss-v4-x)
- [EUR-Lex — Commission Implementing Regulation (EU) 2024/2956 (ITS, register of information)](https://eur-lex.europa.eu/eli/reg_impl/2024/2956/oj/eng)
- [EUR-Lex — Regulation (EU) 2022/2554 (DORA)](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32022R2554) *(truncated before operative articles)*
- [European Commission — NIS2 Directive transposition in EU countries](https://digital-strategy.ec.europa.eu/en/policies/nis-transposition) *(last updated 1 July 2025)*
- [Federal Register — HIPAA Security Rule NPRM, doc 2024-30983, RIN 0945-AA22](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information) *(status verified via the Federal Register API)*
- [Cornell LII — 45 CFR § 164.312 Technical safeguards](https://www.law.cornell.edu/cfr/text/45/164.312)
- [NIST — OSCAL](https://pages.nist.gov/OSCAL/)
- [NIST — OSCAL Layers and Models](https://pages.nist.gov/OSCAL/learn/concepts/layer/)
- [GitHub — usnistgov/OSCAL releases](https://github.com/usnistgov/OSCAL/releases)

Vendor / specification docs:
- [Model Context Protocol — Versioning](https://modelcontextprotocol.io/specification/versioning)
- [Model Context Protocol — Authorization (2025-11-25, current)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Model Context Protocol — Authorization (2025-06-18, superseded)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [Apache Kafka — Authorization and ACLs](https://kafka.apache.org/41/security/authorization-and-acls/)
- [RabbitMQ — Access Control](https://www.rabbitmq.com/docs/access-control)
- [Kong — Secure the Admin API](https://developer.konghq.com/gateway/secure-the-admin-api/)

Third-party mirrors and reproductions (**treat as unofficial**):
- [PCI DSS v4.0.1 Defined Approach Requirements, reproduced in a Genesys Cloud responsibility matrix](https://help.mypurecloud.com/wp-content/uploads/2025/02/pci-dss-requirements-v4.0.1.pdf)
- [DORA article index](https://www.digital-operational-resilience-act.com/DORA_Articles.html) · [Art. 9](https://www.digital-operational-resilience-act.com/Article_9.html) · [Art. 21](https://www.digital-operational-resilience-act.com/Article_21.html) · [Art. 28](https://www.digital-operational-resilience-act.com/Article_28.html) · [Art. 64](https://www.digital-operational-resilience-act.com/Article_64.html)
- [Springlex — RTS on incident reporting (Commission Delegated Regulation (EU) 2025/301), Article 5](https://www.springlex.eu/en/packages/dora/rts-ir-regulation/article-5/)
- [NIS2 Directive Article 21](https://www.nis-2-directive.com/NIS_2_Directive_Article_21.html)
- [European Sting mirror — Commission refers Ireland, Spain, France and the Netherlands to the Court of Justice](https://europeansting.com/2026/07/13/commission-refers-ireland-spain-france-and-the-netherlands-to-the-court-of-justice-for-failing-to-transpose-the-rules-on-cybersecurity-2/) *(mirror of EC [ip_26_1499](https://ec.europa.eu/commission/presscorner/detail/en/ip_26_1499), which is JS-rendered and returned no body)*

---

## 10. Addendum (2026-10) — SOC 2 TSC and ISO/IEC 27001:2022 Annex A

Two frameworks were added to `compliance/map.py` after the research pass above, so they are
**not** covered by the per-rule tables in §6. This section records what was added and the two
caveats that must survive into the UI.

**Provenance — both texts are paraphrased, never quoted.** The 2017 Trust Services Criteria
(with the 2022 revised points of focus) are an AICPA licensed document; ISO/IEC 27001:2022 is
ISO copyright and sold under licence. Neither was reproduced. Every `requirement` for
`SOC2_TSC_2017` and `ISO_27001_2022` restates the control's title and intent in our own words
and says "(Paraphrase of … — not the … wording.)" inline. Before any customer-facing use the
paraphrases must be checked against the licensed text, and the console must label them as
paraphrases. Same weight as the PCI vendor-reproduction warning in §1.2 / §8.

**Fidelity.** Both are *attestation / certification* frameworks, not regulations: SOC 2 criteria
are met by the service organisation's own controls as described in its system description, and
ISO Annex A controls apply only where the entity's Statement of Applicability selects them. A
failing row is therefore evidence an auditor would weigh against a CC6/CC7 or Annex A control,
never a verdict on the report or the certificate. In `frameworks.ts` terms this is `evidence`,
not `direct`.

**Controls carried, and the spine of the mapping** (confidence per row is in the code):

| Framework | Control | Mapped from (families) |
|---|---|---|
| SOC 2 | CC6.1 logical access security | no-authz / no-authn / anonymous / weak-hash / default-credential rules across Kafka, Kong, RabbitMQ, Redis, AWS, GCP, K8s, MCP; NHI and credential-lifecycle rules (lifecycle as `supports`/B — SOC 2 has no rotation criterion) |
| SOC 2 | CC6.2 register / authorize / remove access | `CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY` (A), `CREDENTIAL.LIFECYCLE.NEVER_USED` (supports/B), `KONG.CONSUMER.NO_CREDENTIALS`, `RABBITMQ.USER.DEFAULT_GUEST_PRESENT`, `NHI.IDENTITY.SHARED_DEFAULT` |
| SOC 2 | CC6.3 roles / least privilege | `NHI.GRANT.WILDCARD`, `KAFKA.ACL.*`, `RABBITMQ.PERMISSION.*`, `K8S.RBAC.*`, `K8S.SA.DEFAULT_BOUND`, `AWS.*.POLICY_WILDCARD_ACTION`, `KONG.RBAC.DISABLED`, `MCP.AUTH.SCOPE_OVERBROAD` (B) |
| SOC 2 | CC6.6 threats from outside the boundary | public resource policies (AWS/GCP, ungated — `Principal:*` proves the condition), `AWS.MSK.PUBLIC_ACCESS_ENABLED`, `K8S.RBAC.ANONYMOUS_BOUND`; bind-all / exposed-port / no-auth-route rules gated on `public_facing` |
| SOC 2 | CC6.7 protection in transmission | every plaintext-listener / no-TLS rule (A); peer-verification-disabled rules (B) |
| SOC 2 | CC7.1 config change and new vulnerabilities | `CVE.KNOWN_VULNERABILITY`, `*.VERSION.*`, `RABBITMQ.CVE.*`, `REDIS.VERSION.RCE_CVE` (A); `KAFKA.TOPIC.AUTO_CREATE_ENABLED`, `KONG.PLUGIN.SECURITY_PLUGIN_DISABLED` (supports/B) |
| SOC 2 | CC7.2 anomaly monitoring | logging/audit-disabled rules (`AWS.APIGW.STAGE_LOGGING_DISABLED`, `GCP.PROJECT.AUDIT_LOGGING_DISABLED`, `ELASTICSEARCH.AUDIT.DISABLED`, `VAULT.AUDIT.NO_DEVICE`) as `supports`; `AWS.MSK.ENHANCED_MONITORING_DEFAULT` (supports/B) |
| ISO | A.5.15 access control | no-authz / no-authn / public-policy rules |
| ISO | A.5.16 identity management | `NHI.IDENTITY.SHARED_DEFAULT`, `CREDENTIAL.LIFECYCLE.SHARED`, `CREDENTIAL.LIFECYCLE.ORPHANED_IDENTITY`, `RABBITMQ.USER.DEFAULT_GUEST_PRESENT` (A); anonymous principal / default SA (B) |
| ISO | A.5.17 authentication information | weak-hash, default-credential, rotation/expiry/static-secret rules, credentials in clear on the wire, `K8S.SA.LEGACY_TOKEN_SECRET` |
| ISO | A.5.18 access rights | wildcard grants, orphaned identity, `NEVER_USED` (supports/B), admin sprawl |
| ISO | A.8.2 privileged access rights | `K8S.RBAC.SA_CLUSTER_ADMIN`, `KAFKA.AUTHZ.SUPER_USERS_BREADTH`, `RABBITMQ.USER.ADMIN_TAG_SPRAWL`, `KONG.ADMIN.UNAUTHENTICATED` (A); wildcard grants (B, admin-equivalent) |
| ISO | A.8.3 information access restriction | no-authz, wildcard grants, public policies |
| ISO | A.8.5 secure authentication | anonymous / no-password / unsecured-JWT / x509-without-verification / no-authorizer rules |
| ISO | A.8.9 configuration management | hardening-default drift (`KAFKA.TOPIC.AUTO_CREATE_ENABLED`, `KONG.PLUGIN.SECURITY_PLUGIN_DISABLED` (A), default vhost, CORS wildcard, deprecated transports) mostly `supports`/B |
| ISO | A.8.20 networks security | `K8S.NETPOL.*`, bind-all / public-access / exposed-port rules (A); plaintext listeners (supports/B) |
| ISO | A.8.24 use of cryptography | every plaintext / no-TLS / peer-verification rule (A); weak password hashing (supports/B) |

**Deliberately not done.**
- `ATTACKPATH.*` is now in `NOT_MAPPED`: a chain is a correlation of findings that already carry
  their own rows, and mapping it to CC6.6 / A.8.20 would fail one control twice on one root cause.
- ISO **A.8.8** (technical vulnerability management) is the honest home for the CVE/version rules
  and is not in the catalogue: add it here first, then to the code. Until then those rules carry
  SOC 2 CC7.1 only.
- No PCI / DORA / NIS2 / HIPAA rows were added for the newly mapped families (NHI, credential
  lifecycle, AWS, GCP, K8s, Redis, CVE): they were never researched against those four texts.

Sources (documents obtained from, not quoted):
- [AICPA — 2017 Trust Services Criteria with revised points of focus (2022)](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
- [ISO — ISO/IEC 27001:2022](https://www.iso.org/standard/27001)

## 11. Addendum (2026-10) — the auditor access register as evidence

`GET /reports/access-register` (report.to_access_register_rows / _csv / _markdown) exports one
row per non-human identity: system, type, owner, external/automation flags, credential count and
types, last-used (with its source), days idle, grants, wildcard grants, targets, highest target
sensitivity, open `CREDENTIAL.LIFECYCLE.*` / `NHI.*` verdicts, and a `controls` column. The
column is the list of controls the row is **evidence toward** — never a satisfied control; the
two design rules in §0 apply unchanged. The text per control is a quote-free paraphrase
(`report.ACCESS_REGISTER_CONTROLS`):

| Framework | Control | What a register row evidences | Gate |
|---|---|---|---|
| SOC 2 | CC6.1 | an inventory of the non-human principals with logical access to protected assets | none |
| SOC 2 | CC6.2 | each principal is registered with an owner and its access can be reviewed and removed | none |
| SOC 2 | CC6.3 | grants per principal with wildcards flagged, as the input to a least-privilege review | none |
| ISO 27001:2022 | A.5.16 | identity life cycle: every identity named, typed, owned; shared/default flagged | none |
| ISO 27001:2022 | A.5.17 | authentication information per identity: credential types and lifecycle verdicts | none |
| ISO 27001:2022 | A.5.18 | access rights per identity with last-use, as the input to a periodic review | none |
| PCI DSS 4.0.1 | 8.6.1 | application/system accounts enumerated; interactive-login capability is **not** established | system declared in CDE scope |
| PCI DSS 4.0.1 | 8.6.2 | account credentials enumerated by type; hard-coding is **not** established | system declared in CDE scope |
| PCI DSS 4.0.1 | 8.6.3 | account credentials with rotation/age verdicts where a connector records them | system declared in CDE scope |

The PCI rows carry a `pci_scope` value per row: `in_cde`, `out_of_scope`, or `not_declared`
when the tenant has declared no CDE scope at all (today: always, until scope declaration lands;
the export then lists no PCI control for any row rather than assuming scope). 8.6.1/8.6.2 keep
the interactive-login caveat from §1.3 verbatim in the document header.

**Last-used honesty, carried into the export (strategy §8).** `last_used_at` is one of three
things and the document says which: a dated value (newest across connector telemetry and
`runtime_evidence`), `never` (a source positively read an empty last-used — AWS access keys
and roles today), or `unknown` (no source could read it — Kong, Kubernetes service accounts,
Kafka principals). The Markdown header lists the systems with no last-used source and states
that unknown is not unused, so a blank cell cannot be read as idleness by an auditor.

**Vanta / Drata push.** notify.py's `vanta` and `drata` integration types attach the same
material as external evidence (a JSON file of findings or the weekly digest, plus a pointer to
this export). Shapes and their provenance are documented in the notify.py module docstring;
both are best-effort until exercised against a vendor sandbox.
