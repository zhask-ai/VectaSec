# Compliance & Evidence Capabilities for an Integration-Layer Security Posture Product (as of October 2026)

Scope: message brokers (Kafka/RabbitMQ/Redis/etc.), API gateways (Kong/Envoy/NGINX), service meshes (Istio), iPaaS/automation, non-human identities (NHI), and AI agents. Notes are organised by key question. Every cited finding has an inline source; items I could not source are in Gaps. Labels: **[verified]** = read from source; **[secondary]** = vendor/consultant blog, not the standard text; **[inference]** = my reasoning.

Research caveat: the shared web-search budget was exhausted before the final batch (PCI 8.6.3 primary text, Federal Register HIPAA NPRM text, SOC 2 2022 points-of-focus text, MITRE technique pages). Those remain gaps and are flagged below.

---

## KQ1. Which frameworks matter to SMB / mid-market / regulated buyers, and which control IDs in each can an integration-layer scanner evidence?

### Takeaway
SOC 2 and ISO 27001:2022 are the universal SMB/mid-market targets; PCI DSS 4.0.1 (now with all future-dated requirements in force), HIPAA (current rule; the overhaul is still an NPRM), DORA, NIS2 (via Implementing Regulation 2024/2690) and the EU AI Act (high-risk now deferred to Dec 2027) are the regulated-buyer drivers. For the integration layer the recurring control themes across all of them are: identity/credential lifecycle for NHIs, least privilege, encryption in transit, secure configuration baselines, logging/monitoring, change management, and a third-party/asset register. A key finding: **there is no CIS Benchmark for Kafka, RabbitMQ, Redis, Kong or Istio** (verified against the CIS list page), so a scanner's checks for those products must be anchored to generic controls (CIS Controls v8.1, ISO A.8.9, PCI Req 2) rather than a product benchmark.

### Cited Findings

**SOC 2 (AICPA TSC 2017, 2022 points of focus)**
- Auditor acceptance tests for an artefact: it must be "attributable to a named actor or system, complete against a population they can bound, timely with respect to the period" and reliable at source; a screenshot taken after the period "describes the present rather than the audit window" and does not prove operation during the period — [idenhq SOC 2 CC6 checklist](https://www.idenhq.com/checklists/soc-2-cc6/md) [secondary]
- MFA/password-policy evidence expected "as dated screenshots or config export per system"; auditors check whether enforcement is universal and specifically look for exempted accounts such as "service or break-glass accounts" — [idenhq SOC 2 CC6 checklist](https://www.idenhq.com/checklists/soc-2-cc6/md) [secondary]
- CC7.1 typical evidence: vulnerability scan tool exports (Qualys/Tenable), pentest reports with remediation tickets, EDR console exports; for continuous monitoring "the evidence is an alert-history feed, not point-in-time samples" — [idenhq SOC 2 CC6 checklist](https://www.idenhq.com/checklists/soc-2-cc6/md) [secondary]
- CC8.1 change-management evidence: ticket histories, code commit logs and approval workflows — [bastion.tech SOC 2 evidence guide](https://bastion.tech/learn/soc2/evidence-collection/) [secondary]
- Population/sampling: auditors want the full population first, then sample (typical 25–40 items for large populations; quarterly controls tested in full) and need to know how the list was generated (e.g., upload a screenshot of the export filters alongside the CSV) — [Strike Graph population & sampling guide](https://help.strikegraph.com/articles/4056301-soc-2-type-2-population-and-sampling-guide) [secondary]
- Access-review export "must be dated and show reviewer name" — [idenhq ISO 27001 access evidence playbook](https://www.idenhq.com/de/playbooks/iso-27001-access-evidence) [secondary]

**ISO/IEC 27001:2022 Annex A**
- A.5.15 Access control, A.5.16 Identity management, A.5.17 Authentication information, A.5.18 Access rights: recommended evidence is "provisioning trails, termination records, review cycles and orphaned-account scans" — [idenhq ISO 27001 access evidence playbook](https://www.idenhq.com/de/playbooks/iso-27001-access-evidence) [secondary]
- A.8.16 (monitoring): monitoring records form part of evidence that detection controls work; a "detection-to-alert timeline exercised end to end" is the suggested artefact — [Exigence IR exercises guide](https://content.exigence.io/which-iso-27001-annex-a-controls-do-ir-exercises-evidence-a-guide-for) [secondary]
- A.8.15 (logging) and A.5.28 (collection of evidence) are the controls most directly about audit evidence; evidence must be handled "in a secure, lawful, and controlled manner, with a documented chain of custody" — [Readynez ISO 27001:2022 roadmap](https://www.readynez.com/en/blog/isoiec-270012022-roadmap-requirements-annex-a-changes-and-audit-evidence/) [secondary]
- The Statement of Applicability should map each control to the records retained as evidence — [Sprinto ISO 27001 evidence collection](https://sprinto.com/hub/iso-27001-evidence-collection/) [secondary]

**PCI DSS v4.0.1**
- 52 future-dated requirements became mandatory on 31 March 2025 (usd.de) / "On April 1, 2025, all the future-dated requirements—or FDRs—will become mandatory" (CSA) — one-day discrepancy between sources — [usd.de future-dated requirements](https://www.usd.de/en/pci-dss-future-dated-requirements/); [CSA / VikingCloud](https://cloudsecurityalliance.org/articles/final-countdown-to-compliance-preparing-for-pci-dss-v4-x) [secondary]
- 8.6.1 (interactive use of system/application accounts): interactive login prevented unless needed for an exceptional circumstance, time-limited, documented business justification, management approval, individual user identity confirmed, every action attributable to an individual; "best practice until 31 March 2025, after which it will be required" — [usd.de technical user handling](https://www.usd.de/en/news-pci-dss-v4-0-technical-user-handling/); [Cloudaware PCI 4.0.1 Req 8.6](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/08/06) [secondary]
- 8.6.2 (no hard-coded passwords): applies to system/application accounts that *can* log in interactively; credentials must not be in scripts, configuration/property files, or custom source code; one practitioner notes credentials in a `.env` file or Kubernetes secret "may still be acceptable" depending on implementation — [Schellman PCI service account requirements](https://www.schellman.com/blog/pci-compliance/pci-dss-service-account-requirements) [secondary]
- 8.6.3: applies to *all* system/application accounts (not just interactive ones); passwords must be protected against misuse and changed periodically at a frequency set by the entity's targeted risk analysis — [Cloudaware PCI 4.0.1 Req 8.6](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/08/06) [secondary; snippet truncated]
- 12.3.1 (targeted risk analysis): every PCI requirement that allows flexibility in frequency must be backed by a documented TRA evaluating threat environment, business impact and effectiveness of the chosen approach; TRAs replace the enterprise-wide risk process of earlier versions — [Tevora on 12.3.1](https://www.tevora.com/resource/the-questions-surrounding-pci-requirement-12-3-1/); [usd.de](https://www.usd.de/en/pci-dss-future-dated-requirements/) [secondary]
- PCI SSC removed 12.3.1 from SAQ A because it only supported 11.6.1 (payment-page script integrity) — [PCI SSC "Coffee with the Council" podcast](https://blog.pcisecuritystandards.org/coffee-with-the-council-podcast-guidance-for-pci-dss-e-commerce-requirements-effective-after-31-march-2025) [verified primary]

**HIPAA Security Rule**
- Status: the proposed overhaul (NPRM published 6 Jan 2025; comments closed 7 Mar 2025 with >4,700 comments) is **still not final** as of Sept/Oct 2026; HHS's Unified Agenda target for final action slipped from May 2026 to **July 2027**; the current, unchanged Security Rule is what OCR enforces today — [Pact-One Sept 2026 status](https://www.pact-one.com/2026/09/hipaa-security-rule-2026-status/); [DWT July 2026 on HHS timeframes](https://www.dwt.com/blogs/privacy--security-law-blog/2026/07/hhs-updates-hipaa-rulemaking-timeframes); [Linford & Co](https://linfordco.com/blog/hipaa-security-rule-requirements-implementation-specifications) [secondary]
- A coalition of >100 hospital/provider groups has asked HHS to withdraw the NPRM — [HIPAA Journal](https://www.hipaajournal.com/hipaa-updates-hipaa-changes/) [secondary]
- NPRM content (if finalised): removes "addressable" designation; mandatory encryption at rest/in transit and MFA (legacy-tech and emergency exceptions); technology asset inventory and **network map showing ePHI flows**, reviewed at least every 12 months and on environment change; vulnerability scanning every 6 months, pentest annually; 72-hour restoration; workforce access changes notified within 24 hours; compliance ~240 days after finalisation (60-day effective + 180-day compliance) — [BDO summary](https://www.bdo.com/insights/industries/healthcare/proposed-hipaa-security-rule-updates); [Qubika NPRM summary](https://qubika.com/blog/hipaa-security-rule-2025-nprm-changes-preparation/); [Medcurity](https://medcurity.com/hipaa-security-rule-2026-update/) [secondary]

**DORA**
- Article 28(3) register of information must be kept at entity, sub-consolidated and consolidated levels and must distinguish arrangements supporting critical or important functions — [locaterisk DORA registry](https://locaterisk.com/en/dora-information-registry-reporting-requirements-for-financial-institutions/) [secondary]
- Register content follows the standard templates in **Commission Implementing Regulation (EU) 2024/2956**: "15 templates in 8 groups linked by relational keys", covering entities, contractual arrangements, signing entities, providers and supply chains, functions and criticality — [SureCloud register guide](https://www.surecloud.com/resource-hub/dora-register-of-information-guide); [Advisera CIR 2024/2956](https://advisera.com/cir-2024-2956/content-of-the-register-of-information/) [secondary]
- "ICT service supply chain" is defined as the sequence of contractual arrangements from the direct ICT third-party provider through its subcontractors — [Advisera CIR 2024/2956 definitions](https://advisera.com/cir-2024-2956/definitions/) [secondary]
- Spain's CNMV set a 1 March window for the registration round; BaFin first collected in April 2025 and annually in March since 2026; the 2026 cycle covers data as at 31 Dec 2025 — [CNMV procedure PDF](https://www.cnmv.es/DocPortal/Ciberseguridad/ProcOperRepRegProvDORA2026en.pdf); [locaterisk](https://locaterisk.com/en/dora-information-registry-reporting-requirements-for-financial-institutions/); [Mitratech](https://mitratech.com/zh/博客/what-is-dora/) [secondary]
- ESAs designated the first 19 critical ICT third-party providers in Nov 2025 — [locaterisk](https://locaterisk.com/en/dora-information-registry-reporting-requirements-for-financial-institutions/) [secondary]
- Article 30 minimum contractual elements apply to all ICT contracts — [McCann FitzGerald](https://www.mccannfitzgerald.com/knowledge/data-privacy-and-cyber-risk/delving-into-dora-ict-contractual-arrangements) [secondary]

**NIS2**
- Transposition deadline 17 Oct 2024 was widely missed; Commission opened infringement proceedings against 23 member states in April 2025; Jan 2026 Wavestone tracker places countries in tiers; counts of "transposed" states conflict (~22–24 per Deloitte vs ~14 per another tracker); Austria in force 1 Oct 2026; Commission proposed targeted NIS2 amendments in Jan 2026 (not yet law) — [Wavestone Jan 2026](https://www.wavestone.com/en/insight/nis-2-european-countries-transposing-directive/); [Deloitte BE](https://www.deloitte.com/be/en/services/consulting-risk/research/navigating-nis2-compliance.html); [risidata tracker](https://www.risidata.com/regulations/nis2/countries) [secondary, conflicting]
- Implementing Regulation (EU) 2024/2690 applies directly (no transposition) to the entities it covers (DNS, cloud, data centres, CDNs, managed service/security providers, marketplaces, search engines, social networks, trust services); requires a cryptography policy (algorithm/key-strength selection, key lifecycle: generation, storage, rotation, destruction) and MFA/continuous authentication scaled to asset classification; strong authN/authZ for privileged accounts — [nisd2.eu CIR 2024/2690](https://nisd2.eu/en/wiki/fundamentals/cir-2024-2690); [nisd2.eu cryptography](https://nisd2.eu/en/wiki/implementation/cryptography-nis2); [nisd2.eu MFA](https://nisd2.eu/en/wiki/implementation/mfa-requirement-nis2) [secondary]
- Art. 21(2) items: (b) incident handling, (d) supply chain, (h) cryptography, (i) access control, (j) MFA — [presencis Article 21](https://presencis.com/regulations/nis2/article-21/) [secondary]

**CIS Controls v8.1 and CIS Benchmarks**
- **No CIS Benchmark exists for Kafka, RabbitMQ, Redis, Kong or Istio** on the current CIS Benchmarks list; relevant ones that *do* exist: NGINX (3.0.0), Kubernetes (2.1.0), Docker (1.9.0), Apache Cassandra (4.0/4.1/5.0), Apache Tomcat (7–10.1), MongoDB (3.2–8), PostgreSQL (9.5–18), Software Supply Chain Security, and a new "AI" category; Envoy appears only as a VMware vCenter Appliance STIG component — [CIS Benchmarks list](https://www.cisecurity.org/cis-benchmarks) [verified primary; page truncated after YugabyteDB]
- A Feb 2026 third-party guide confirms "there is no standalone CIS benchmark specifically for Istio" and suggests applying the Kubernetes benchmark sections — [OneUptime Istio/CIS](https://oneuptime.com/blog/post/2026-02-24-how-to-configure-istio-for-cis-benchmarks/view) [secondary]
- CIS Controls v8.1 safeguards relevant to the integration layer: 4.1 Establish and Maintain a Secure Configuration Process (IG1); 4.7 Manage Default Accounts (IG1); 5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts; **5.5 Establish and Maintain an Inventory of Service Accounts (IG2)**; 6.8 Define and Maintain Role-Based Access Control (IG3) — [bastion.tech CIS v8 list](https://bastion.tech/learn/cis-controls/cis-controls-v8-list); [myctrl.tools CIS 5.4](https://myctrl.tools/frameworks/cis-v8-detailed/5-4) [secondary]

**NIST CSF 2.0 / SP 800-207 / SP 800-53 rev5**
- CSF 2.0: 6 functions, 106 subcategories; PR.AA-01 "Manage identities and credentials for authorized users, services and hardware" — [CyberArk CSF 2.0 glossary](https://www.cyberark.com/fr/what-is/nist-csf-20/); [cyesec subcategory reference](https://help.app.cyesec.com/en/articles/366572-nist-csf-2-0-subcategory-reference) [secondary]
- SP 800-207: Policy Engine decides, Policy Administrator relays, Policy Enforcement Point enforces; SP 1800-35 (NCCoE) built 19 example ZTA implementations with 24 collaborators, focusing on the Enhanced Identity Governance approach, with mappings to common standards — [NordLayer SP 800-207](https://nordlayer.com/learn/zero-trust/nist-sp-800-207/); [Cloudflare on SP 1800-35](https://cfl.re/4kM4wiH); [SP 1800-35 PDF mirror](https://www.compliancepoint.com/wp-content/uploads/2025/06/NIST.SP_.1800-35.pdf) [secondary]
- SP 800-53 rev5 IA-5(7) "No Embedded Unencrypted Static Authenticators": static storage includes "access scripts and function keys"; FedRAMP Moderate/High tailor it to any storage where unencrypted authenticators "persist beyond the time required to complete the access process" — [Cloudaware IA-5(7) FedRAMP Moderate](https://ce.prod.cloudaware.com/frameworks/fedramp-moderate-security-controls/ia/05/07); [myctrl IA-5(7)](https://myctrl.tools/frameworks/nist-800-53-r5/ia-5-7) [secondary]

**EU AI Act / ISO 42001**
- Digital Omnibus on AI = **Regulation (EU) 2026/1744**, published OJ 24 July 2026, in force 27 July 2026; Annex III high-risk deadline moved from 2 Aug 2026 to **2 Dec 2027**; Annex I (product-embedded) to 2 Aug 2028; public-authority high-risk use to 2 Aug 2030; prohibited practices, GPAI obligations (since Aug 2025) and most Article 50 transparency duties (from 2 Aug 2026) **unchanged**; generative systems on market before 2 Aug 2026 get until 2 Dec 2026 for machine-readable marking — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-omnibus-vii-deadline-delay-20260/); [Orrick July 2026](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes); [Jones Walker](https://www.joneswalker.com/en/insights/blogs/ai-law-blog/yes-august-2-still-matters-the-eu-approved-a-high-risk-ai-delay-but-most-trans.html); [technology.org Oct 2026](https://www.technology.org/2026/10/13/eu-ai-act-deadlines-after-the-digital-omnibus-what-applies-from-december-2026-to-august-2028/) [secondary but consistent]
- ISO/IEC 42001: BSI obtained ANAB accreditation (10 Mar 2026), adding to UKAS and RvA — first triple-accredited CB — [BSI press release](https://www.bsigroup.com/en-IE/insights-and-media/media-centre/press-releases/2026/march/bsi-secures-anab-accreditation-to-certify-isoiec-42001/) [verified primary]; Annex A reportedly 38 controls in 9 areas (A.2–A.10) — [Konfirmity](https://www.konfirmity.com/blog/iso-42001) [secondary, unverified against standard]

**OWASP projects**
- OWASP NHI Top 10 (2025): NHI1 Improper Offboarding; NHI2 Secret Leakage; NHI3 Vulnerable Third-Party NHI; NHI4 Insecure Authentication; NHI5 Overprivileged NHI; NHI6 Insecure Cloud Deployment Configurations; NHI7 Long-Lived Secrets; NHI8 Environment Isolation; NHI9 NHI Reuse; NHI10 Human Use of NHI — [OWASP NHI Top 10 2025](https://owasp.org/www-project-non-human-identities-top-10/2025/) [verified primary]; [CSA](https://cloudsecurityalliance.org/articles/introducing-the-owasp-nhi-top-10-standardizing-non-human-identity-security)
- OWASP Top 10 for Agentic Applications 2026: released 9 Dec 2025, >100 contributors, entries ASI01–ASI10; ASI01 = Agent Goal Hijack; categories cover goal hijacking, tool misuse, identity/privilege, supply chain, code execution, memory, inter-agent communication, cascading failures, human-agent trust, rogue agents — [OWASP GenAI project page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026) [verified for date]; [Modulos summary](https://docs.modulos.ai/frameworks/owasp-top-10-agentic) [secondary for category list]
- OWASP Top 10 for LLM Applications 2026: v1.0 dated 3–4 Aug 2026 (sources differ by a day), CC BY-SA 4.0; ranking = 75% practitioner vote + 25% from 6,639 incidents; Excessive Agency rose to #3; System Prompt Leakage renamed Hidden Context Exposure; new appendix maps all ten risks to nine external frameworks with pinned versions — [CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-owasp-genai-top10-2026-agent-control-stand/); [Akamai](https://www.akamai.com/blog/ai/owasp-top-10-llm-applications-2026-realistic-security-model) [secondary]
- OWASP ASVS 5.0.0: released 30 May 2025 at Global AppSec EU Barcelona, ~350 requirements, 17 chapters, 3 levels; V4 = API & Web Service, V6 Authentication, V7 Session Management confirmed — [Security Compass](https://www.securitycompass.com/blog/what-is-owasp-asvs/); [smithery ASVS skill listing](https://smithery.ai/skills/zate/asvs-requirements) [secondary; full chapter list conflicting across sources]
- OWASP API Security Top 10 2023 remains current (API2:2023 Broken Authentication, API5:2023 BFLA); one glossary claims a next edition due 7 Sept 2026 — **no official OWASP confirmation found** — [unihackers glossary](https://unihackers.com/glossary/owasp-api-top-10) [secondary, unconfirmed]

**MITRE ATT&CK**
- T1071.005 Publish/Subscribe Protocols (MQTT/AMQP as C2) added 2023; T1552.007 Container API; a 2026 RabbitMQ CVE advisory (CVE-2026-57219, OAuth client secret disclosure) maps to Valid Accounts and Credentials in Files — [securityscientist T1071.005](https://www.securityscientist.net/blog/12-questions-and-answers-about-publish-subscribe-protocols-t1071-005-2/); [Graylog API techniques](https://graylog.org/post/mitre-attck-api-based-enterprise-techniques-and-sub-techniques); [Aviatrix RabbitMQ advisory](https://aviatrix.ai/threat-research-center/rabbitmq-oauth-client-secret-disclosure-cve-2026-57219/) [secondary]

**FedRAMP / GovRAMP**
- FedRAMP 20x: KSIs reported as 56 (Low) / 61 (Moderate) across 12 domains by some sources, 46 with Class A/B/C tiers by another; evidence is machine-readable, "aligned to OSCAL where it applies"; Rev5 deadlines conflict (30 Sept 2026 per RFC-0024 vs 7 Dec 2026 vs 30 Sept 2027 end of Rev5); Consolidated Rules finalised 25 June 2026 / effective 4 July 2026 per different sources — [bdemerson FedRAMP 20x](https://www.bdemerson.com/article/fedramp-20x); [Knox Systems](https://knoxsystems.com/resources/fedramp-20x); [BleepingComputer](https://bleepingcomputer.com/news/security/fedramp-rev5-is-ending-what-the-20x-transition-really-requires) [secondary, conflicting]
- StateRAMP rebranded GovRAMP; North Carolina requires GovRAMP-aligned assessments in new cloud contracts from 1 Apr 2026 (mandatory 1 Apr 2027); Nevada centralised model from July 2026 — [NC DIT June 2026](https://it.nc.gov/blog/2026/06/29/strengthening-compliance-through-updated-govramp-requirements-existing-it-contracts); [Nevada press release](https://www.it.nv.gov/siteassets/itnew.nv.gov/content/prs/govramp_press_release_march_2026.pdf); [GovRAMP 2026 modernization](https://govramp.org/blog/2026-program-modernization-and-adoption/) [verified primary]

**Secure Controls Framework (SCF)**
- SCF 2026.2 (July 2026) adds a Quantum Security domain; all LRFs now have published STRM except NIST 800-53 Rev4 and SIG; STRM uses NIST IR 8477 with five relationship types (e.g., "Subset Of", "Intersects With") plus a numeric strength score; free in Excel/CSV and **JSON (OSCAL)**; editable STRM Excel bundle $25 — [SCF 2026.2 newsletter](https://securecontrolsframework.com/blog-posts/scf-2026-2-newsletter); [SCF STRM page](https://securecontrolsframework.com/start-here/set-theory-relationship-mapping-strm); [SCF 2026.1 release](https://securecontrolsframework.com/blog-posts/scf-release-20261) [verified primary]

### Inferences
- Control-to-asset map a scanner can realistically produce evidence for (**[inference]** built from the cited control text; exact TSC/ISO wording not retrieved):
  - *Broker/gateway/mesh TLS & mTLS enforcement* → SOC 2 CC6.1/CC6.6/CC6.7; ISO A.8.20, A.8.21, A.8.24; PCI 4.2.1 (strong crypto in transit), 2.2.7 (admin access encrypted); NIS2 CIR 2024/2690 §9 cryptography; NIST SC-8/SC-13; CSF PR.DS-02.
  - *Default/anonymous access disabled, hardened listener config* → PCI 2.2.x; CIS 4.1/4.7; ISO A.8.9; CC6.1.
  - *ACL/RBAC least privilege on topics, routes, mesh AuthorizationPolicy* → CC6.3; ISO A.5.15/A.5.18/A.8.2/A.8.3; PCI 7.2.x; CIS 5.4/6.8; NIST AC-6; OWASP API5:2023 BFLA.
  - *NHI inventory, ownership, rotation age, long-lived secrets, hard-coded creds* → CC6.1/CC6.2/CC6.3; ISO A.5.16/A.5.17; PCI 8.2.2, 8.6.1–8.6.3; CIS 5.5; NIST IA-5(7); CSF PR.AA-01; OWASP NHI1/2/5/7.
  - *Audit logging on brokers/gateways, log integrity & retention* → CC7.2/CC7.3; ISO A.8.15/A.8.16; PCI 10.2–10.5; CSF DE.CM.
  - *Config drift / unauthorised change* → CC8.1; ISO A.8.9/A.8.32; PCI 1.2.2, 6.5.1, 11.5.2 (change-detection).
  - *Third-party/iPaaS connector register with criticality & data flows* → DORA Art 28(3) + CIR 2024/2956 templates; NIS2 Art 21(2)(d); ISO A.5.19–A.5.22; HIPAA NPRM asset inventory + ePHI network map (if finalised).
  - *AI-agent tool/credential scope, goal integrity, inter-agent auth* → OWASP ASI01–10, LLM Top 10 2026 (Excessive Agency), ISO 42001 Annex A, EU AI Act Art. 9–15 (high-risk, now Dec 2027).
- For PCI, a scanner's most defensible outputs are the 8.6.x service-account population with interactive-login capability, hard-coded-credential findings, and the TRA frequency evidence for 8.6.3 rotation — because those are the requirements that only became mandatory in 2025 and are new ground for QSAs.
- Because no CIS Benchmark exists for the core broker/gateway/mesh products, a vendor could differentiate by publishing its own hardening baselines explicitly cross-walked via SCF STRM — and should state in product that these are *not* CIS-certified.

### Gaps
- Exact AICPA 2022 points-of-focus text for CC6.1–6.8, CC7.1–7.4, CC8.1 not retrieved (search budget exhausted); mapping above is from secondary evidence guides.
- ISO 27002:2022 implementation text for A.8.9 (configuration management) and A.8.20 (network security) not found.
- PCI DSS 4.0.1 primary text for 8.6.3 not retrieved (snippet truncated); the TRA-driven rotation frequency should be verified in the standard and PCI SSC FAQ.
- Federal Register text of the HIPAA NPRM (90 FR 898) not retrieved; details are from BDO/Qubika/Medcurity summaries.
- DORA RTS 2024/1773 (contractual arrangements policy) content not found.
- Official OWASP Agentic ASI02–ASI10 names not retrieved from the OWASP page (list lives in the downloadable PDF); CSF 2.0 PR.DS/PR.PS/DE.CM subcategory text not found.
- MITRE ATT&CK primary pages for T1552.001, T1078.004, T1557 were not fetched; no authoritative ATT&CK-to-integration-layer mapping exists in the results.
- CIS Controls 12.2, 13.3 and Control 16 safeguard text not found.

---

## KQ2. What evidence auditors accept for these controls, and in what format?

### Takeaway
Auditors accept evidence that is attributable, complete against a bounded population, timely (inside the audit period), and reliable at source — in practice: dated configuration exports with visible source/URL/timestamp, full-population lists with the export parameters shown, immutable/dated logs rather than after-the-fact screenshots, and for NHIs specifically: owner, purpose, scope, rotation and revocation records. Machine identities are a frequent exception area because they fall outside human access-review populations.

### Cited Findings
- Four acceptance tests: attributable, complete, timely, reliable at source; point-in-time current-state evidence is not evidence of operation during the period — [idenhq SOC 2 CC6](https://www.idenhq.com/checklists/soc-2-cc6/md) [secondary]
- Screenshots should show the URL in the console and the system timestamp; add "URLs, report names, system IDs" to evidence lacking context — [Oneleet "what makes good evidence"](https://docs.oneleet.com/guides/what-makes-good-evidence/) [secondary]
- For historical point-in-time evidence use "configuration history, immutable audit logs, dated exports, version-controlled configuration"; a dated baseline plus a complete change log can explain state over a span better than repeated screenshots — [OneUptime Aug 2026 SOC 2 evidence](https://oneuptime.com/blog/post/2026-08-03-what-counts-as-soc-2-evidence/markdown) [secondary]
- "The service auditor decides whether the evidence is sufficient and appropriate for the procedure" — [OneUptime](https://oneuptime.com/blog/post/2026-08-03-what-counts-as-soc-2-evidence/markdown) [secondary]
- Mandatory to prove evidence comes from within the audit period — [soc2auditors.org evidence request list](https://soc2auditors.org/insights/soc-2-evidence-request-list/) [secondary]
- NHI evidence auditors expect: named owners, defined purpose, lifecycle control; "ownership, scoped permissions, rotation, and revocation records"; rotation logs (not just policy); offboarding records showing secret revocation; exceptions with expiry dates, compensating controls and re-approval; operating-effectiveness evidence (remediation records, approval trails, review outcomes) — [Lumos NHI audit readiness](https://www.lumos.com/identity-matters/non-human-identity/non-human-identity-audit-readiness) [secondary]
- "No universal standard for exactly how much evidence SOC 2 auditors will require for every credential type"; evidence depth should scale with risk — [Lumos](https://www.lumos.com/identity-matters/non-human-identity/non-human-identity-audit-readiness) [secondary]
- Common NHI exceptions: unowned service accounts (creator left), service accounts outside the access-review population, incomplete inventory ("only 5.7% of organisations have full visibility into their service accounts" — vendor stat), vault-only answers that do not prove inventory completeness/ownership/offboarding, short-lived tokens without governed issuance/scope/revocation, emergency/delegated access without explicit exception handling — [NHIMG SOC 2 access review gap](https://nhimg.org/articles/soc-2-audit-checklists-expose-the-access-review-gap-in-saas-governance/); [NHIMG FAQ on NHIs in SOC 2](https://nhimg.org/faq/why-do-non-human-identities-matter-in-soc-2-audits/) [secondary, vendor]
- ISO 27001 access evidence: provisioning trails, termination records, review cycles, orphaned-account scans; exports dated with reviewer name — [idenhq ISO playbook](https://www.idenhq.com/de/playbooks/iso-27001-access-evidence) [secondary]
- SOC 2 auditors check whether MFA is enforced for everyone and specifically look for service/break-glass exemptions — [idenhq SOC 2 CC6](https://www.idenhq.com/checklists/soc-2-cc6/md) [secondary]

### Inferences
- A scanner's evidence artefact should therefore carry, per finding and per snapshot: collection timestamp (UTC), source system identifier/endpoint, the raw config fragment or API response hash, the population it was drawn from (e.g., "all 1,284 Kafka ACL entries"), and the collector's identity — this directly satisfies the four acceptance tests. **[inference]**
- Because "current state ≠ operated during the period", the product needs *time-series* snapshots (daily/hourly) with retention ≥ the audit window (12 months for SOC 2 Type II), not just a live dashboard. **[inference]**
- For NHIs the product should emit a register (owner, purpose, scope, creation date, last rotation, last use, interactive-capable yes/no, expiry) — this one artefact covers PCI 8.6.1–8.6.3, CIS 5.5, ISO A.5.16, CC6.2 and the common "unowned account" exception. **[inference]**

### Gaps
- No A-LIGN, Prescient Assurance, or Johanson Group published evidence playbooks surfaced in search results; all evidence-format guidance here is from compliance-tool vendors and small audit firms.
- No AICPA/ISACA formal definition of acceptable electronic evidence retrieved.

---

## KQ3. How do compliance-automation platforms ingest third-party evidence?

### Takeaway
All five platforms accept structured JSON pushed by API, against a customer- or partner-defined schema, which then feeds pass/fail "custom tests" mapped to controls. Vanta (resource model, `PUT /v1/resources/<type>`), Drata (Custom Connections & Tests; 5 MB JSON, 500 req/min, Advanced/Enterprise plans only), and Secureframe (custom integrations via JSON API or CSV) are documented; Sprinto and Thoropass offer custom-evidence APIs but with thinner public docs. Partner-built integrations (Vanta public integrations, Thoropass TIPP) are the route to "auditor-vetted" status.

### Cited Findings

**Vanta**
- Integrations push full current state via `PUT /v1/resources/<type>` and read via `GET /v1/resources/<type>`, only for resources the integration owns; cannot assign control owners, query test results or manage vendors (those are Manage Vanta API) — [Vanta developer: integrations concept](https://developer.vanta.com/docs/concepts/integrations.md) [verified primary]
- Named resource types: `UserAccount`, `Computer`, `Vulnerability`, `BackgroundCheck`, `TrainingRecord`, `CustomResource` (define your own schema) — [Vanta integrations concept](https://developer.vanta.com/docs/concepts/integrations.md) [verified primary]
- Auth: public integrations use OAuth authorization-code flow (per-customer access/refresh tokens); private integrations use client-credentials; payload limits exist (values not on page); recommends sending only Critical/High vulnerabilities if sync would exceed limits — [Vanta integrations concept](https://developer.vanta.com/docs/concepts/integrations.md) [verified primary]
- Custom test definition (UI): test name, description, resource, property to check, comparison operator and value; failing resources fail the test — [Vanta Application Custom Tests](https://developer.vanta.com/docs/application-custom-tests) [secondary via search snippet; page returned 404 on fetch]
- Evidence snapshot read-back: `GET .../evidence/{evidenceId}/test-snapshot` returns test metadata and raw data at snapshot time, one row per resource, rate-limited 10 req/min — [Vanta API: test snapshot](https://developer.vanta.com/api-reference/audits/get-test-snapshot-detail-for-an-evidence-row.md) [secondary via search]
- Example partner pattern: Speakeasy custom test fails when any resource has `agent_active = false` and maps to SOC 2/ISO controls — [Speakeasy Vanta reference](https://www.speakeasy.com/docs/ai-control-plane/reference/device-agent/mdm-installations/vanta) [secondary]

**Drata**
- Custom Connections & Tests: send structured JSON from any source; available on **Advanced and Enterprise plans**; "not a standard integration" — cadence and push are customer-initiated (cron, Make.com, Tines) — [Drata help: Part 1 CCT](https://help.drata.com/en/articles/11995676-part-1-custom-connections-and-tests) [verified primary]
- Schema rules: at least one top-level string/number property (used as display name); avoid top-level arrays; supply JSON Schema or sample JSON (recommended); nested arrays may need the advanced test editor — [Drata CCT Part 1](https://help.drata.com/en/articles/11995676-part-1-custom-connections-and-tests) [verified primary]
- Limits: max JSON 5 MB; rate limit 500 requests/min per source IP; array items processed individually with per-item 200/201/400; record ID semantics: no ID → new UUID; existing ID → update (200); new ID → create (201) — [Drata CCT Part 1](https://help.drata.com/en/articles/11995676-part-1-custom-connections-and-tests) [verified primary]
- API key scopes: Custom Connections Data: Create Data, Create and Update Data, Delete Data — [Drata CCT Part 1](https://help.drata.com/en/articles/11995676-part-1-custom-connections-and-tests) [verified primary]
- Published custom tests run automatically, generate audit-visible evidence, show pass/fail and a Findings tab of failing items (individual findings can be excluded) — [Drata: create and publish custom tests](https://help.drata.com/en/articles/13401776-create-and-publish-custom-tests) [secondary via search]
- Partner connections push evidence with an API key but "don't have access to Drata's automated tests" — [Drata partner connections](https://help.drata.com/en/articles/12151473-partner-connections-expanding-compliance-with-external-tools) [secondary via search]
- Customers onboarded on/after 24 Feb 2026 use the "New Experience" UI — [Drata test details](https://help.drata.com/en/articles/13392374-view-and-manage-test-details-new-experience) [secondary]

**Secureframe**
- Custom integrations accept data via public API as structured JSON or CSV upload; Secureframe auto-infers source/target fields from valid JSON; additional requests target a schema by slug name and connection ID; Request-logs tab records each call and validation errors — [Secureframe: create custom integrations](https://support.secureframe.com/en/articles/15111548-create-custom-integrations) [secondary via search]
- Read endpoints include `/evidences/{id}` and `/users/{user_id}/evidences`, auth by API key + secret via developer portal — [Secureframe evidence FAQ](https://support.secureframe.com/en/articles/15111232-faqs-evidence-and-documentation-uploads-attachments-and-proof-in-secureframe) [secondary]
- Uploads carry an "evidence type" that determines mapping to tests/controls/personnel; wrong type can cause test failures — [Secureframe evidence FAQ](https://support.secureframe.com/en/articles/15111232-faqs-evidence-and-documentation-uploads-attachments-and-proof-in-secureframe) [secondary]

**Sprinto / Thoropass**
- Sprinto: "API to upload custom evidence against any checks running in the system" (examples: self-hosted DB backup logs, DR run output); third-party note that the API relies heavily on internal `pk` identifiers — [Sprinto API documentation](https://sprinto.com/sprinto-api-documentation/); [Truto Sprinto connector guide](https://truto.one/blog/connect-sprinto-to-ai-agents-sync-workflow-evidence-staff-scope/) [secondary]
- Thoropass Integration Partner Program (TIPP): partner API with "standardized object templates"; integrations are "vetted and approved by auditors" — [Thoropass TIPP](https://www.thoropass.com/tipp) [secondary, vendor]
- Thoropass-authored comparison lists "Custom API" supported by both Sprinto and Thoropass — [Thoropass vs Sprinto](https://www.thoropass.com/blog/comparing-sprinto-and-thoropass) [vendor claim]

### Inferences
- Minimum viable integration set for an integration-layer scanner: (1) Vanta private-integration pushing a `CustomResource` per broker/gateway/NHI with boolean/enum properties (e.g., `tls_enforced`, `anonymous_access`, `secret_age_days`) so customers can author tests; (2) Drata CCT JSON records keyed by stable resource ID (so re-pushes update, not duplicate); (3) Secureframe JSON custom integration; (4) generic webhook/CSV for Sprinto/Thoropass. **[inference]**
- Pushing *resources with properties* (not just pass/fail) is the pattern all three documented vendors expect; the scanner should expose a normalised "posture resource" model that maps to each vendor's schema. **[inference]**
- Drata's Advanced/Enterprise gating means SMB customers on lower Drata tiers cannot consume API evidence — a CSV/PDF evidence-pack export is therefore still necessary for the SMB segment. **[inference]**

### Gaps
- Vanta's exact payload limits, OAuth scope names, and whether `CustomResource` uses the same `PUT /v1/resources/<type>` path were not on the fetched page; the Application Custom Tests doc returned 404.
- Drata's endpoint URL/path for CCT was not in the help article.
- Secureframe's documented upload endpoint and request format (developer portal is gated).
- Sprinto and Thoropass public API references were not retrievable.

---

## KQ4. What reporting and export formats matter?

### Takeaway
Four format families matter: (1) GRC-platform JSON (above); (2) machine-readable control formats — OSCAL (now required direction for FedRAMP 20x and the format SCF ships in) and SCF STRM crosswalks for dedup; (3) security-tool interchange — OCSF for SIEM (Compliance Finding class 2003, Vulnerability Finding 2002, Application Security Posture Finding 2007, IAM Analysis Finding 2008 in v1.9.0), SARIF for code-scanning pipelines, CycloneDX 1.6 SBOM/VEX for component exposure; (4) auditor-facing — dated PDF/CSV evidence packs, signed attestations (in-toto/DSSE), and WORM/object-lock retention.

### Cited Findings
- OSCAL assessment-results root is `assessment-results`; FedRAMP says the model "provides a means to reference low-level assessment scans, logs, and interview details"; gaps are "findings" with associated risks — [NIST OSCAL AR reference](https://pages.nist.gov/OSCAL-Reference/models/v1.0.0/assessment-results/json-definitions/); [FedRAMP: What is OSCAL](https://automate.fedramp.gov/about/what-is-oscal) [verified primary]
- Component Definition model sits in the OSCAL implementation layer alongside SSP — [NIST OSCAL presentation](https://www.nist.gov/document/presentation-oscal-models-assessment-planning-results-and-poam) [primary]
- SCF 2026.2 distributed as Excel/CSV and JSON (OSCAL) — [SCF 2026.2 newsletter](https://securecontrolsframework.com/blog-posts/scf-2026-2-newsletter) [verified primary]
- OCSF v1.9.0 Findings category classes: Security Finding 2001 (deprecated since v1.1.0), Vulnerability Finding 2002, **Compliance Finding 2003**, Detection Finding 2004, Incident Finding 2005, Data Security Finding 2006, Application Security Posture Finding 2007, IAM Analysis Finding 2008 — [OCSF schema classes](https://schema.ocsf.io/classes) [verified primary]
- SARIF: standardised JSON for SAST/secret-scanning/code-quality findings; uploaded to GitHub Code Scanning — [DevGuard open standards](https://docs.devguard.org/explanations/core-concepts/open-standards/) [secondary]
- VEX supported for CycloneDX SBOMs only (not SPDX) in Checkmarx; JFrog Xray 3.67.x+ embeds VEX in CycloneDX; DefectDojo exports standalone CycloneDX 1.6 VEX via `GET /api/v2/sbom/{asset_id}/vex/` — [Checkmarx VEX](https://docs.checkmarx.com/en/34965-543091-vulnerability-exploitability-exchange--vex-.html); [JFrog export](https://docs.jfrog.com/security/docs/export-scan-results); [DefectDojo VEX export](https://docs.defectdojo.com/asset_modelling/locations/pro__exporting_sboms_and_vex/) [secondary vendor docs]
- Signed evidence: Cosign attestations use the in-toto statement model with DSSE signing (subjects by digest + predicate type); GitHub flow ties a short-lived Fulcio cert to workflow identity and logs to Rekor; Bernstein wraps an audit evidence bundle in an Ed25519-signed DSSE/in-toto v1 envelope verifiable by a third-party auditor with only the public key; Akka emits signed DSSE bundles as red-team audit trail; DigiCert smctl produces in-toto/DSSE attestations for SBOMs/scans — [OneUptime cosign guide](https://oneuptime.com/blog/post/2026-08-11-cosign-signature-attestation-sbom-differences/markdown); [Tenki GitHub attestations](https://tenki.cloud/blog/github-actions-artifact-attestations-slsa); [Bernstein DSSE envelope](https://bernstein.readthedocs.io/en/latest/security/audit-dsse-envelope/); [Akka attestation](https://doc.akka.io/testing/red-teaming/attestation.html); [DigiCert smctl](https://docs.digicert.com/en/software-trust-manager/code-signing/sign-with-digicert-signing-tools/manage-attestations-with-smctl.html) [secondary]
- Caveat: a valid signature proves only signer and subject match; policy must still check predicate contents (builder identity, source, scan time) — [OneUptime](https://oneuptime.com/blog/post/2026-08-11-cosign-signature-attestation-sbom-differences/markdown) [secondary]
- WORM: SEC Rule 17a-4(f) allows non-rewriteable/non-erasable storage *or* (since 2022 amendments) an audit-trail alternative; object-lock **compliance mode** (not governance mode) is required because the rule prohibits admin bypass; attestation package also needs vendor-signed media representation, serialised ingest audit trail, and a designated third-party downloader ("most frequently missing piece"); Object Lock must be enabled at bucket creation (S3 and Ceph RGW) — [Impossible Cloud 17a-4](https://www.impossiblecloud.com/en-us/magazine/worm-compliance-storage-sec-17a-4-s3); [Folderit WORM](https://www.folderit.com/blog/worm-object-lock-immutable-archives/); [OneUptime Ceph Object Lock](https://oneuptime.com/blog/post/2026-03-31-rook-set-up-ceph-object-lock-worm-compliance/markdown) [secondary]
- FedRAMP 20x evidence is machine-readable, "aligned to OSCAL where it applies"; Rev5 holders must transition packages to OSCAL by Sept 2026 per RFC-0024 (consultancy claim, not confirmed against FedRAMP) — [bdemerson](https://www.bdemerson.com/article/fedramp-20x); [Lazarus Alliance](https://lazarusalliance.com/using-fedramp-to-fast-track-your-govramp-market-entry/) [secondary]
- DORA register must be deliverable in the CIR 2024/2956 template structure (15 templates / 8 groups, relational keys) — [SureCloud](https://www.surecloud.com/resource-hub/dora-register-of-information-guide) [secondary]

### Inferences
- Priority export matrix for an integration-layer posture product **[inference]**: (a) GRC JSON push (Vanta/Drata/Secureframe) — table stakes for SMB/mid-market; (b) OCSF Compliance Finding (2003) + IAM Analysis Finding (2008) for SIEM/data-lake; (c) OSCAL component-definition + assessment-results for FedRAMP/GovRAMP-adjacent and SCF-using buyers; (d) CycloneDX 1.6 SBOM/VEX for broker/gateway component CVEs; (e) PDF/CSV dated evidence pack per control with population + sample + hash; (f) DSSE-signed in-toto statements over each snapshot with Rekor/transparency log or customer KMS; (g) retention to customer-owned object-lock (compliance mode) bucket.
- A DORA-template CSV export of the connector/iPaaS/third-party inventory (provider, function, criticality, supply-chain depth) is a direct differentiator for EU financial-services buyers. **[inference]**
- SARIF is lower priority than OCSF for runtime-config findings; it matters mainly if the product also scans IaC/pipeline definitions of gateways/meshes. **[inference]**

### Gaps
- No source directly describes how third-party scanners populate OSCAL component definitions; the mechanics are unspecified in the results.
- No primary FedRAMP document confirming the OSCAL transition deadline or KSI counts (sources conflict: 46 vs 56/61).
- OCSF: no source describing field-level mapping of configuration/posture findings to Compliance Finding 2003.

---

## KQ5. What do "continuous compliance" and "control drift" mean to buyers, and how do leaders implement it?

### Takeaway
There is no formal standards-body definition; the market uses "control drift" in three senses — documentation/practice gap, configuration drift from a compliant baseline, and runtime AI-behaviour drift — and "continuous compliance" means replacing annual snapshot evidence with continuously collected, dated, population-complete evidence (continuous control monitoring). Buyers increasingly expect evidence as an alert/feed history rather than point-in-time screenshots.

### Cited Findings
- Compliance drift defined as "the gap between what a policy says, what the procedure requires, and what the organisation actually does", not a single failure event — [NHIMG glossary (updated 12 Jul 2026)](https://nhimg.org/glossary/compliance-drift/) [secondary]
- Control drift (SOC 2 context): "configuration changes slowly move your systems away from their original, compliant state" (e.g., unlogged hotfix, security group left open) — [securityscientist control drift](https://answers.securityscientist.net/q/12868/what-is-control-drift-in-compliance) [secondary]
- AI drift: June 2026 TrustEvals/Accorian framework uses "control drift" for runtime AI behaviour change from vendor updates, input shifts, evolving agent behaviours (64.5% statistic is vendor-reported) — [techintelpro](https://techintelpro.com/news/cybersecurity/ai/trustevals-accorian-launch-ai-grc-framework-for-control-drift-risk) [secondary, vendor]
- Continuous Control Monitoring = "real-time oversight of your internal security controls" — [securityscientist CCM](https://answers.securityscientist.net/q/11487/what-is-continuous-control-monitoring-ccm) [secondary]
- Shift framed as moving from the annual "assess, review controls, gather evidence, address findings, close audit" cycle to continuous evidence — [Feroot Aug 2026](https://feroot.com/blog/beyond-the-compliance-snapshot-why-grc-needs-continuous-evidence/) [secondary]
- For continuous monitoring, SOC 2 evidence "is an alert-history feed, not point-in-time samples" — [idenhq](https://www.idenhq.com/checklists/soc-2-cc6/md) [secondary]
- FedRAMP 20x framed as "proof over paperwork" with continuous, machine-readable KSI validation — [GRC Report](https://www.grcreport.com/post/proof-over-paperwork-fedramps-shift-from-rev5-to-20x) [secondary]

### Inferences
- Implementation pattern leaders converge on: baseline → scheduled re-collection → diff → finding with timestamp + prior/current value → auto-push to GRC test → ticket. For the integration layer this means per-asset config fingerprints (hash of normalised broker/gateway/mesh config) with change attribution. **[inference]**
- PCI 11.5.2 (change-detection on critical files) and CC8.1 give drift detection a direct control hook; the product should express drift as both a security finding and a change-management exception. **[inference]**

### Gaps
- No NIST/ISACA/AICPA formal definition of "continuous compliance" or "control drift" was found.
- No independent survey data on buyer expectations for continuous compliance in SMB/mid-market (only vendor statistics).

---

## KQ6. 2025–2026 regulatory changes affecting the integration layer

### Takeaway
Confirmed in force: PCI 4.0.1 future-dated requirements (31 Mar/1 Apr 2025), DORA (applies since 17 Jan 2025, register submissions annual, 19 CTPPs designated Nov 2025), EU AI Act GPAI (Aug 2025) and Article 50 transparency (Aug 2026). Deferred: EU AI Act Annex III high-risk to 2 Dec 2027 (Reg. 2026/1744). Still pending: HIPAA Security Rule overhaul (target July 2027), NIS2 transposition in several states plus a Jan 2026 Commission amendment proposal, SEC Item 1.05 (industry petition to rescind, April 2026; no adopted change found).

### Cited Findings
- PCI: 52 FDRs mandatory 31 Mar 2025 / 1 Apr 2025 — [usd.de](https://www.usd.de/en/pci-dss-future-dated-requirements/); [CSA](https://cloudsecurityalliance.org/articles/final-countdown-to-compliance-preparing-for-pci-dss-v4-x)
- HIPAA: NPRM 6 Jan 2025; final rule target July 2027; not in force — [DWT](https://www.dwt.com/blogs/privacy--security-law-blog/2026/07/hhs-updates-hipaa-rulemaking-timeframes); [Pact-One](https://www.pact-one.com/2026/09/hipaa-security-rule-2026-status/)
- EU AI Act: Reg. (EU) 2026/1744 in force 27 Jul 2026; Annex III → 2 Dec 2027; Annex I → 2 Aug 2028; public authorities → 2 Aug 2030; GPAI and Art. 50 unchanged — [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-eu-ai-act-omnibus-vii-deadline-delay-20260/); [Orrick](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes); [artificialintelligenceact.eu omnibus explorer](https://artificialintelligenceact.eu/ai-act-explorer/digital-omnibus/)
- DORA: BaFin annual collection each March since 2026; CNMV 1 March window; 19 CTPPs Nov 2025 — [locaterisk](https://locaterisk.com/en/dora-information-registry-reporting-requirements-for-financial-institutions/); [CNMV](https://www.cnmv.es/DocPortal/Ciberseguridad/ProcOperRepRegProvDORA2026en.pdf)
- NIS2: 23 infringement proceedings April 2025; Commission amendment proposal Jan 2026; Austria law in force 1 Oct 2026 — [Wavestone](https://www.wavestone.com/en/insight/nis-2-european-countries-transposing-directive/); [risidata](https://www.risidata.com/regulations/nis2/countries)
- SEC: Item 1.05 (Release 33-11216, July 2023) requires 8-K within four business days of a materiality determination; on 10 Apr 2026 five bank/securities trade groups asked the SEC to rescind or narrow Item 106 and Item 1.05 with safe harbours; SEC CETU formed Feb 2025; no adopted change found — [Vaquill 2026 enforcement update](https://www.vaquill.ai/blog/sec-cyber-disclosure-2026-enforcement-update); [WilmerHale 2023 adoption](https://www.wilmerhale.com/en/insights/blogs/Focus-on-Audit-Committees-Accounting-and-the-Law/20230728-sec-adopts-cybersecurity-disclosure-rules) [secondary]
- OWASP: Agentic Top 10 (9 Dec 2025); LLM Top 10 2026 (3–4 Aug 2026); NHI Top 10 (Jan 2025); ASVS 5.0 (30 May 2025) — sources cited in KQ1
- ISO 42001: ANAB-accredited certification available from Mar 2026 (BSI) — [BSI](https://www.bsigroup.com/en-IE/insights-and-media/media-centre/press-releases/2026/march/bsi-secures-anab-accreditation-to-certify-isoiec-42001/)
- GovRAMP: NC contracts from 1 Apr 2026; Nevada July 2026 — [NC DIT](https://it.nc.gov/blog/2026/06/29/strengthening-compliance-through-updated-govramp-requirements-existing-it-contracts); [Nevada](https://www.it.nv.gov/siteassets/itnew.nv.gov/content/prs/govramp_press_release_march_2026.pdf)

### Inferences
- The product's regulatory roadmap for the next 14 months should be sequenced: DORA register export and NIS2 CIR 2024/2690 crypto/MFA/privileged-NHI checks (live now) → PCI 8.6.x NHI evidence (live, QSAs now testing) → EU AI Act Annex III agent controls (Dec 2027, so design now, ship 2027) → HIPAA NPRM asset-inventory/network-map (contingent, 2027+). **[inference]**

### Gaps
- No primary EUR-Lex retrieval for Reg. 2026/1744, CIR 2024/2690, or CIR 2024/2956; all from consistent secondary sources.
- Outcome of SEC Regulation S-K review unknown.
- Whether the Jan 2026 NIS2 amendment proposal touches Article 21 technical measures is unknown.
