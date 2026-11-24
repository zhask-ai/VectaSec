# Platform-level table-stakes and differentiators for security posture platforms (as of October 2026)

Scope: everything "around" the detectors — finding lifecycle, prioritization, remediation tiers, integrations, identity/access, API/extensibility, reporting, MSSP mode, onboarding, scanner safety, deployment/residency, trust, pricing/packaging, AI features — benchmarked against Wiz, Orca, Prisma Cloud, CrowdStrike Falcon Cloud, Aikido, Prowler Cloud, Snyk, Semgrep, Lacework/FortiCNAPP, Upwind, Sysdig, Vanta, Drata, Secureframe.

Method note: ~30 web searches/fetches; the web-search budget was exhausted before every vendor could be checked against primary docs, so per-vendor coverage is uneven. Every claim below carries a source; "vendor-claimed" marks vendor marketing/blog statements; "third-party" marks aggregator or review-site data; "verified" is used only where a primary doc or pricing page was fetched directly. Items I could not source are listed under Gaps rather than asserted.

---

## Key Question 1: For each feature, who has it, is it table-stakes or differentiator in 2026 RFPs, and what does the best implementation look like

### Takeaway
By October 2026 the "around the detector" layer has polarized: a core set (bidirectional Jira, Slack/Teams, SSO/RBAC, public API, compliance-framework mapping, exec PDF, cloud onboarding via CloudFormation/Terraform, trial-to-first-finding in hours) is assumed in every RFP, while the genuine differentiators have moved to (a) a formal finding-triage lifecycle with risk-accepted/false-positive states and verify-after-fix rescans, (b) PR-based and agentic remediation with human approval gates and independent verification, and (c) a vendor-hosted remote MCP server plus IDE/agent plugins. Forrester's Q1 2026 CNAPP Wave explicitly scores "Agentic AI and copilots" as a Current Offering criterion, which is the clearest signal that AI-era features are now in the scoring rubric rather than a bonus.

### Cited Findings

#### 1a. Finding lifecycle (dedup, suppression with expiry, risk acceptance, SLA/aging, ownership routing, false-positive feedback)

- Prowler Cloud (July 2026) added a formal finding triage lifecycle with statuses Open, Under Review, Remediating, Risk Accepted, False Positive, Resolved; findings auto-resolve when they pass and show as "Reopened" on regression. Verified from vendor newsletter — [Prowler July 2026 Newsletter](https://prowler.com/blog/prowler-july-2026-newsletter)
- Prowler distinguishes "muting" (mute lists/rules that suppress findings considered non-relevant) from "triage" (records review status and notes without suppressing). Both are exposed via its MCP server; triage is Cloud-only. Verified from docs — [Prowler MCP docs](https://docs.prowler.com/getting-started/products/prowler-mcp)
- Prowler Cloud's paid tier lists "Autonomous Fixer, triage lifecycle, notes, manual findings with evidence" under Remediation and "single-finding rescans" under scheduling. Verified from pricing page — [Prowler pricing](https://prowler.com/pricing)
- Wiz's Ignore Issue action (as surfaced in the Google SecOps integration) takes a required resolution reason of False Positive, Exception, or Won't Fix, plus an optional note; the API scopes are `update:posture_issue_ignore` and `write:issue_ignore`. Whether Wiz ignore rules support expiry was not confirmed (docs.wiz.io returned 429). — [Google SecOps Wiz integration docs](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/wiz?authuser=0)
- Wiz runs an internal practice of mapping cloud risk to service owners through a Service Catalog and surfacing Wiz Issues inside Backstage for developers (ownership routing pattern). Vendor-claimed blog — [Wiz at Wiz: Reducing Risk through Service Ownership](https://www.wiz.io/pt-br/authors/omer-mesika)
- Palo Alto Cortex Cloud issue exceptions use an approval workflow: if an approver does not approve or reject an exception rule request within seven days, the request expires. Verified from docs — [Cortex Cloud: create issue exceptions](https://cortex-docs.paloaltonetworks.com/cortex-cloud-runtime-security/cases-and-issues/customize-cases-and-issues/create-issue-exceptions.md)
- Compliance platforms consume CNAPP findings against SLAs: Sprinto ingests Wiz Issues via API and tracks remediation against policy-defined SLAs, syncing status back as issues resolve. Vendor-claimed — [Wiz/Sprinto integration](https://www.wiz.io/integrations/sprinto)
- Vanta's Essentials plan AI Agent includes "SLA tracking"; Professional adds "agentic issue management". Verified from pricing page — [Vanta pricing](https://www.vanta.com/pricing)
- Orca and Wiz score 7.5 and 7.4 respectively on G2's "False Positives" feature rating (118 and 275 reviews), both at the low end of their feature scores — i.e. buyers still rate noise as the weakest area for even the leaders. Third-party — [G2 comparison](https://www.g2.com/compare/uptycs-uptycs-vs-wiz-wiz-vs-orca-security)
- AccuKnox's CNAPP comparison checklist (updated March 2026) notes operational metrics like remediation time, false-positive rate and runtime enforcement depth "rarely appear in an RFP" and recommends a mandatory pass/fail tier plus weighted optional tier. Vendor-authored checklist — [AccuKnox CNAPP comparison checklist](https://accuknox.com/blog/cnapp-comparison-checklist)

#### 1b. Prioritization (reachability, exploitability, EPSS/KEV, toxic combinations, business context)

- Wiz MCP positions "toxic risk combinations", internet exposure and data sensitivity as natural-language-queryable posture attributes, and "contextual intelligence for prioritizing responses using business context" as a core pillar. Vendor-claimed — [Introducing the MCP Server for Wiz](https://www.wiz.io/blog/introducing-mcp-server-for-wiz)
- Prowler: open-source tier includes ThreatScore and basic AWS attack paths; Cloud tier adds full attack-path graph, Lighthouse AI, and "Censys validation" (external exposure validation). Verified — [Prowler pricing](https://prowler.com/pricing)
- Semgrep includes reachability analysis, cross-file/cross-function taint analysis, a policy engine and AI triage on all tiers including Free. Verified — [Semgrep pricing](https://semgrep.dev/pricing)
- Semgrep markets its AI Assistant as triaging findings with 96% alignment to human decisions. Vendor-claimed — [Semgrep vs Snyk](https://try.semgrep.dev/snyk-vs-semgrep/)
- Decryption Digest's 2026 comparison: "Most platforms handle CSPM and CWPP well; runtime detection and cross-signal prioritization separate the field"; leading platforms link misconfigurations, network exposure, identities and sensitive data into prioritized attack paths. Third-party — [CNAPP comparison 2026](https://www.decryptiondigest.com/blog/cnapp-comparison-2026-wiz-prisma-cloud-orca-lacework-defender-for-cloud)
- Ciphers' 2026 buyer guide PoC checklist: ask for prioritized attack paths built from your own environment during the PoC; check CIEM attack-path depth ("does it tie an exposed workload to the identity that enables a breach path"); "score signal-to-noise, not feature counts". Third-party — [CNAPP Buyer's Guide 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- CSA/Tenable mid-market guidance: CIEM is "the area buyers most often skip, even though unused roles and overly permissive policies tend to produce the most actionable findings". Vendor-adjacent — [CSA: six factors](https://cloudsecurityalliance.org/articles/six-factors-mid-sized-enterprises-should-look-for-when-selecting-a-cnapp); [SSOJet CNAPP buyer's guide](https://ssojet.com/security-vendors/guides/cnapp-buyers-guide/)

#### 1c. Remediation tiers (guided text, IaC snippets, PR fixes, auto-remediation with approval gates, verify-after-fix)

- Orca Jira integration (verified from vendor page): optional automatic ticket creation from alerts; field mapping UI (Alert Name, Risk Level -> Assignee, Description); ticket status visible in Orca; when a ticket is resolved Orca automatically rescans to confirm the fix and reopens the Jira ticket if the problem persists. — [Orca + Jira](https://orca.security/partners/technology/jira-by-atlassian/)
- Orca uses generative AI (Amazon Bedrock, earlier GPT-4) to write remediation steps and code into tickets assigned to DevOps/dev teams; users copy generated code into CLI or IaC — i.e. guided fix text, not applied fixes. Vendor-claimed — [Orca + Amazon Bedrock](https://orca.security/resources/blog/orca-integrates-with-amazon-bedrock-ai/); [CSO Online on Orca GPT-4](https://www.csoonline.com/article/575261/orca-integrates-cloud-app-security-platform-with-gpt-4.html)
- Wiz MCP (preview, April 2025): in the IDE it lists critical issues, identifies root cause, proposes and applies code fixes, submits them as GitHub PRs, then verifies resolution in Wiz; for threats it suggests containment (e.g. restrict public ports via AWS CLI). Vendor-claimed — [Wiz MCP blog](https://www.wiz.io/blog/introducing-mcp-server-for-wiz)
- Wiz AI agents (Nov 4, 2025): Issues Agent (preview) links findings, ownership and impact to recommend a remediation path and can trigger a suggested PR to the dev team with context linked in Slack; SecOps Agent auto-triages threats with a verdict + confidence + reasoning that analysts review/accept/adjust before response proceeds. Vendor-claimed — [AI-Powered Wiz: From Agents to Everyday Intelligence](https://wiz.io/blog/wiz-ai-agents)
- Wiz "Green Agent" (remediation/PR generation) was reported as launched 2026-07-21 by ThreatCluster, and as part of an April 2026 Google Cloud Next launch by Tamnoon; Futurum reports Wiz agents in FedRAMP High "Wiz for Gov" can be configured to act autonomously or require human-in-the-loop approval for sensitive systems. Dates conflict; all third-party. — [ThreatCluster](https://threatcluster.io/cluster/introducing-wiz-workflows-ec4ebab3); [Tamnoon on Google Cloud Next 2026](https://tamnoon.io/blog/google-cloud-next-2026-agentic-cloud-security/); [Futurum](https://futurumgroup.com/?p=96694)
- Snyk Evo Agentic AppSec (announced Oct 15, 2026): five agents (Code Scanning, Dependency Firewall, Agentic Security Review, Remediation, Secrets). Remediation Agent runs the full fix loop autonomously on new code and backlog (starting with Snyk Open Source); fixes that might break the build are held for approval; "none of the agents grade their own work" — Evo Continuous Offensive Security attacks the running app to confirm fixes. Benchmark claim: 90% mergeable-fix rate vs 59.6% for LLMs alone. Status: Remediation Agent open preview; Secrets/ADS/COS GA; others experimental preview. Vendor-claimed — [Snyk launches Evo](https://snyk.io/news/snyk-launches-evo-agentic-appsec/)
- Aikido: AI AutoFix is metered per tier (Developer 10/mo; Basic/Pro/Advanced "Unlimited" per the fetched page; a third-party snapshot from 2026-05-09 showed 50/mo on Pro — the limits have changed over time). "Aikido Max" add-on sells unlimited monthly AI credits by quote. Verified pricing page — [Aikido pricing](https://www.aikido.dev/pricing); third-party history — [PricingSaaS Aikido](https://pricingsaas.com/companies/aikido)
- Prowler Claude Code plugin (Cloud only): prioritizes failing checks, remediates via IaC or cloud CLIs, opens PRs, triggers rescans to confirm fixes, writes markdown reports; Prowler Hub exposes "fixers" (remediation scripts) and check code via MCP; Lighthouse AI's cloud access is read-only. Verified — [Prowler July 2026 newsletter](https://prowler.com/blog/prowler-july-2026-newsletter); [Prowler MCP docs](https://docs.prowler.com/getting-started/products/prowler-mcp)
- Vanta Claude Code plugin: `/vanta:fix-test` generates code changes for a failing test and opens a PR; `/vanta:list-tests` lists prioritized failing tests relevant to the codebase. Verified — [Vanta MCP docs](https://developer.vanta.com/docs/vanta-mcp)
- Semgrep lists "AI detection, triage, autofix" on all tiers; AI credits are 60 total on Free, 20/dev/month on Teams, 50/dev/month on Enterprise; Enterprise allows a custom AI model provider. Verified — [Semgrep pricing](https://semgrep.dev/pricing)

#### 1d. Integrations (Slack/Teams, Jira/ServiceNow, SIEM via OCSF, PagerDuty, SCM apps, Vanta/Drata, Security Hub)

- Wiz, Orca and Lacework were all listed by AWS as third-party OCSF sources for Amazon Security Lake at GA (2023). Findings sent to Security Hub are converted to OCSF when Security Hub is enabled as a Security Lake source. Primary (AWS, but dated) — [AWS Security Lake GA blog](https://aws.amazon.com/blogs/security/amazon-security-lake-is-now-generally-available/); [Security Hub findings in Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/security-hub-findings.html)
- Google SecOps (Chronicle) ships a marketplace Wiz integration with Ignore Issue and other actions. Verified — [Google SecOps Wiz integration](https://docs.cloud.google.com/chronicle/docs/soar/marketplace-integrations/wiz?authuser=0)
- Prowler: OSS tier ships AWS Security Hub, GitHub Action, SARIF; Cloud adds Jira, Slack, email, Power BI; Private Cloud adds AWS Security Lake (Parquet) and "custom SIEM". Verified — [Prowler pricing](https://prowler.com/pricing)
- Aikido: Basic adds Jira/Linear sync and sync to Drata/Vanta; Advanced adds SIEM integration and higher API rate limits; Slack/Teams chat notifications listed in comparison table (tier unclear). Verified — [Aikido pricing](https://www.aikido.dev/pricing)
- Semgrep: Jira ticketing and Slack/email on all tiers; Wiz integration and Palo Alto Cortex integration on Teams and Enterprise (CNAPP-to-ASPM finding export is now a packaged integration). Verified — [Semgrep pricing](https://semgrep.dev/pricing)
- Snyk: Jira integration gated to Team and above; IDE/CLI/SCM on all tiers. Verified — [Snyk plans](https://snyk.io/plans/)
- Vanta pulls data from "400+ tools" (not mapped to plans). Verified — [Vanta pricing](https://www.vanta.com/pricing)
- Drata developer portal lists Public API v2, Drata MCP, Custom Connections (on-prem/custom systems for evidence collection), Custom Workflows (triggers/actions), and SafeBase Trust API. Verified landing page only — [Drata developers](https://developers.drata.com/)
- Orca ServiceNow bidirectional sync is asserted by a third-party Q&A site only; not confirmed on Orca materials. — [securityscientist Q&A](https://answers.securityscientist.net/q/26152/how-does-orca-integrate-with-existing-security-workflows)

#### 1e. Identity and access (SSO SAML/OIDC, SCIM, RBAC, audit log export)

- Semgrep: Free = GitHub/GitLab login only; Teams and Enterprise = OIDC + SAML SSO and RBAC. Verified — [Semgrep pricing](https://semgrep.dev/pricing)
- Prowler Cloud: SAML SSO for multiple domains plus Google/GitHub login; RBAC not mentioned on pricing page (though the MCP server exposes "users, roles" tools, implying RBAC exists). Verified — [Prowler pricing](https://prowler.com/pricing); [Prowler MCP docs](https://docs.prowler.com/getting-started/products/prowler-mcp)
- Vanta MCP acts with the user's own Vanta role permissions (Admin gets full tool set; Editor/Collaborator/View-only get a subset). Verified — [Vanta MCP docs](https://developer.vanta.com/docs/vanta-mcp)
- Aikido lists SSO/SAML in its comparison table (tier mapping not legible in text). Verified page, tier unclear — [Aikido pricing](https://www.aikido.dev/pricing)

#### 1f. API and extensibility (REST/GraphQL, SDKs, Terraform provider, SARIF/OCSF import, policy-as-code, custom rules, webhooks)

- Semgrep: REST API on Teams+; custom rules on all tiers; "AI coding agent plugin" on all tiers. Verified — [Semgrep pricing](https://semgrep.dev/pricing)
- Prowler: OSS ships API keys, SDK, GitHub Action, SARIF output; Cloud adds Cloud API, remote MCP server, and a private registry for custom controls, providers and frameworks; add-on "Custom Check Development" at $10,000 per check. Verified — [Prowler pricing](https://prowler.com/pricing)
- Aikido: public REST API listed (tier unclear); Advanced has higher API rate limits; "AI SAST (including custom rules)" on Free. Verified — [Aikido pricing](https://www.aikido.dev/pricing)
- Vanta: Essentials includes an "Auditor API"; a general Vanta API exists as a separate product page; Professional adds custom monitoring tests and automation; TPRM REST API is an add-on. Verified — [Vanta pricing](https://www.vanta.com/pricing)
- Drata: Public API v2 "faster, expanded endpoints"; Custom Connections for custom evidence; Custom Workflows. Verified landing page — [Drata developers](https://developers.drata.com/)
- Wiz MCP server translates natural-language requests into Wiz operations including "retrieving data from third-party security tools" (Wiz as aggregator of imported findings). Vendor-claimed — [Wiz MCP blog](https://www.wiz.io/blog/introducing-mcp-server-for-wiz)

#### 1g. Reporting (exec PDF, trend, benchmarks, board reports)

- Prowler Cloud (July 2026): cross-provider compliance tab combining scans into one posture per framework with per-provider breakdown and a combined executive PDF; 70+ frameworks incl. NATO D32, CIS Controls 8.1, CSA CCM 4.0, DORA. Verified — [Prowler July 2026 newsletter](https://prowler.com/blog/prowler-july-2026-newsletter); [Prowler pricing](https://prowler.com/pricing)
- Aikido: "reports and analytics" from Basic; security audit reports (PDF) in comparison table. Verified — [Aikido pricing](https://www.aikido.dev/pricing)
- Vanta: basic reporting on Essentials; Professional adds advanced reporting (six customizable reports), risk dashboard; risk report/dashboard also sold as add-ons. Verified — [Vanta pricing](https://www.vanta.com/pricing)
- Peer comparison / benchmark reports: no vendor page fetched documented peer-benchmark reporting (gap).

#### 1h. Multi-tenant / MSSP partner mode

- Prowler: MSP/MSSP partner program with multi-tenant environment, consolidated billing, deal registration, partner pricing, co-marketing. Verified — [Prowler pricing](https://prowler.com/pricing)
- Aikido Enterprise: multi-tenant portal for managing multiple business units or customers; a separate agencies offer. Verified — [Aikido pricing](https://www.aikido.dev/pricing)
- Vanta: partner program for service providers and auditors; Essentials includes "access to expert partners". Verified — [Vanta pricing](https://www.vanta.com/pricing)

#### 1i. Onboarding (one-click roles, least-privilege policies, time-to-first-finding)

- Prowler Cloud: one-click AWS Organization onboarding via CloudFormation stack + StackSet deploying the scan role to all member accounts; Okta provider uses OAuth 2.0 M2M with read-only scopes; org-wide onboarding for AWS Orgs, Azure Management Groups, GCP Orgs. Verified — [Prowler July 2026 newsletter](https://prowler.com/blog/prowler-july-2026-newsletter); [Prowler pricing](https://prowler.com/pricing)
- Prowler free trial: 7 days, no cloud-account limit, no credit card, every check and framework. Verified — [Prowler pricing](https://prowler.com/pricing)
- Time-to-value benchmarks (third-party): new AWS org connection yields first risk findings "within hours"; agentless tools deploy across hundreds of accounts in 1–3 days; hybrid/agent platforms 2–8 weeks for complete coverage. — [Ciphers CNAPP Buyer's Guide 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- Industry pattern for cloud onboarding (non-target vendors, as reference for "best implementation"): Terraform module creating a cross-account IAM role with external ID and read-only permissions; AWS managed `SecurityAudit` policy; Terraform option creating the same read-only role as the CloudFormation template. — [AlgoSec AWS onboarding](https://techdocs.algosec.com/en/ace/content/cloud-common/ace-aws-script-terr.htm); [unusd.cloud Terraform](https://docs.unusd.cloud/how-to/use-terraform/); [Zesty Terraform onboarding](https://docs.zesty.co/docs/onboard-an-aws-account-for-kompass-with-terraform)
- CSA/Tenable mid-market factor 6: "intuitive interfaces, pre-configured templates, automated setup, and strong customer support and documentation"; request a free trial to judge whether the team can handle the platform. — [CSA six factors](https://cloudsecurityalliance.org/articles/six-factors-mid-sized-enterprises-should-look-for-when-selecting-a-cnapp)

#### 1j. Scanner operational safety

- Prowler Lighthouse AI: access to cloud environments is read-only; cannot modify data or access secrets/tenant details. Verified — [Prowler July 2026 newsletter](https://prowler.com/blog/prowler-july-2026-newsletter); [Prowler Lighthouse docs](https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai.md)
- Prowler scan configurations are reusable, schema-validated, attachable to multiple providers; scans schedulable per provider or in bulk; partial scans and single-finding rescans. Verified — [Prowler July 2026 newsletter](https://prowler.com/blog/prowler-july-2026-newsletter)
- Wiz "outpost" model: scanning runs on the customer's cloud resources and sends metadata to Wiz (community-reported). Third-party — [Reddit snapshot on CNAPP on-prem](https://reddit.sentinel-team.org/posts/1s8gc97/snapshots/2026-04-03T16%3A10%3A19.98477Z)
- Rate limiting, scan windows, and production-safe read guarantees were not documented on any fetched vendor page (gap).

#### 1k. Data residency and deployment options

- Vanta MCP has regional endpoints for US, EU and Australia. Verified — [Vanta MCP docs](https://developer.vanta.com/docs/vanta-mcp)
- Prowler Private Cloud: deploy in own cloud, data center or air-gapped; data residency of choice; VMware VCF; renamed from "Enterprise" in July 2026 (per third-party price tracker). Verified pricing page; rename third-party — [Prowler pricing](https://prowler.com/pricing); [PricingSaaS Prowler](https://pricingsaas.com/companies/prowler)
- Aikido: on-prem scanning from Pro; broker for internal apps on Advanced; on-prem deployment and FedRAMP Moderate on Enterprise; FIPS base images on Advanced. Verified — [Aikido pricing](https://www.aikido.dev/pricing)
- Semgrep Enterprise: self-managed/on-prem SCM support, dedicated infrastructure option, custom AI model provider. Verified — [Semgrep pricing](https://semgrep.dev/pricing)
- Lacework FortiCNAPP: Fortinet added regional PoPs (Australia, then Singapore) for data residency; a UK G-Cloud listing says data storage limited to EEA and other locations with no customer control over location. Third-party/procurement — [CRN Asia](https://www.crnasia.com/news/2025/cybersecurity/fortinet-launches-new-regional-pop-to-strengthen-cybersecuri); [G-Cloud listing](https://www.applytosupply.digitalmarketplace.service.gov.uk/g-cloud/services/611960892467545)
- Wiz for Gov is FedRAMP High authorized and now includes AI agents. Third-party — [Futurum](https://futurumgroup.com/?p=96694)

#### 1l. Trust (SOC 2, ISO, pen test, trust center)

- Prowler Cloud: SOC 2 Type 2 listed on paid tier. Verified — [Prowler pricing](https://prowler.com/pricing)
- Vanta: Trust Center on Essentials, Advanced Trust Center on Professional. Verified — [Vanta pricing](https://www.vanta.com/pricing)
- Drata: SafeBase Trust API for security reviews, questionnaires and trust center. Verified — [Drata developers](https://developers.drata.com/)
- Snyk Evo Continuous Offensive Security (AI pentesting) GA; Aikido AI Pentesting "skip payment" model (high/critical and full report unlock on payment). Verified — [Snyk Evo](https://snyk.io/news/snyk-launches-evo-agentic-appsec/); [Aikido pricing](https://www.aikido.dev/pricing)

### Inferences
- Table-stakes in Oct 2026 RFPs (present in every tier of even the cheapest vendors fetched): Jira sync, Slack/email, SSO (OIDC+SAML) on first paid tier, RBAC, public REST API, custom rules, compliance-framework mapping with PDF export, CloudFormation/Terraform read-only onboarding, free tier or no-card trial.
- Differentiators (present in only a subset or only at top tiers): verify-after-fix rescans with automatic ticket reopen (Orca, Prowler), formal triage lifecycle with Risk Accepted/False Positive states and regression reopen (Prowler; Wiz has reasons but expiry unconfirmed), approval-gated agentic remediation with independent verification (Snyk Evo, Wiz agents), vendor-hosted remote MCP with regional endpoints (Vanta), air-gapped/private-cloud deployment (Prowler, Aikido Enterprise), FedRAMP (Wiz Gov, Aikido Enterprise), MSSP multi-tenant portals (Prowler, Aikido).
- "Best implementation" composite for lifecycle: Prowler's six-state lifecycle + auto-resolve/reopen, Wiz's mandatory reason codes on ignore, Cortex's time-boxed exception approval, Orca's rescan-on-close/reopen — no single vendor fetched documents all four.
- Compliance platforms (Vanta/Drata) now sit upstream of CNAPP findings as SLA/evidence consumers (Sprinto example, Aikido->Vanta/Drata sync), so a "custom evidence" push integration is effectively table-stakes for any posture tool selling into SOC 2-driven SMBs.

### Gaps
- Could not fetch Wiz docs on ignore-rule expiration, issue SLAs, project/ownership rules or automation rules (docs.wiz.io returned 429; search budget exhausted). Also could not verify a Wiz Terraform provider or Wiz's published read-only CloudFormation policy.
- No primary data found for Upwind, Sysdig, CrowdStrike Falcon Cloud, Prisma Cloud, Lacework/FortiCNAPP, Secureframe or Drata on lifecycle, remediation, SCIM, audit-log export, webhooks, rate limiting or scan windows.
- SCIM provisioning and audit-log export were not stated on any pricing page fetched.
- Peer-comparison/benchmark reporting and "noise budgets" were not documented by any vendor page fetched.
- Drata Public API v2 endpoint detail, rate limits and tier gating not fetched (only landing page); Vanta developer getting-started page returned 404.

---

## Key Question 2: What SMB/mid-market evaluations (1–3 person security teams) actually weight vs enterprise RFPs

### Takeaway
Small teams weight time-to-first-finding, zero-ops deployment, flat/predictable pricing, compliance-report output, and whether developers (not security) can own remediation; enterprise RFPs weight integrated architecture, CIEM/attack-path depth, runtime coverage, data residency/FedRAMP, and SIEM/SOAR integration. Analyst and vendor guides agree that most RFPs still omit operational metrics (false-positive rate, remediation time) that matter most to small teams.

### Cited Findings
- CSA/Tenable six factors for mid-sized enterprises: (1) integrated-not-acquired architecture ("ask whether developed in-house or assembled through acquisitions"), (2) CIEM, (3) modular, scalable pricing with a clear breakdown of initial and expansion costs, (4) compliance flexibility incl. hybrid/on-prem where required, (5) DSPM for AI, (6) simple deployment, pre-configured templates, strong support/docs, judged via free trial. — [CSA six factors](https://cloudsecurityalliance.org/articles/six-factors-mid-sized-enterprises-should-look-for-when-selecting-a-cnapp); [Tenable mid-sized CNAPP blog](https://kr.tenable.com/blog/choosing-the-right-cnapp-six-considerations-for-mid-sized-enterprises)
- SSOJet guide: define the problem in one sentence first; decide before signing whether engineering owns remediation (security as advisor) or security owns the platform end-to-end; warns that if engineering owns the accounts but security owns the tool, findings "pile up in a ticket queue nobody works"; be wary of shift-left scanning without enforcement. — [SSOJet CNAPP buyer's guide](https://ssojet.com/security-vendors/guides/cnapp-buyers-guide/)
- AccuKnox: teams compare feature lists without scoring deployment speed, alert quality, runtime depth and compliance evidence; recommends mandatory pass/fail + weighted optional scoring and testing 15 scored questions in a proof-of-value rather than demos. Vendor-authored — [AccuKnox comparison checklist](https://accuknox.com/blog/cnapp-comparison-checklist); [AccuKnox evaluation checklist](https://accuknox.com/blog/cnapp-evaluation-checklist)
- Ciphers 2026 guide use-case labels: Orca "mid-market wanting fast coverage"; Wiz "large multi-cloud estates"; Defender for Cloud fastest start for Azure-heavy shops; Sysdig entry pricing "can feel steep for very small environments"; PoC advice includes "model workload and account counts before requesting quotes" and "confirm the platform maps to your audit scope". Third-party — [Ciphers CNAPP Buyer's Guide 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- Ciphers cites a Gartner expectation that 80% of enterprises will consolidate cloud-native application security to three or fewer vendors, and notes most CNAPP vendors are quote-only and field-led. Third-party citing Gartner — [Ciphers CNAPP Buyer's Guide 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- Forrester Q1 2026 CNAPP Wave evaluated 14 vendors; Current Offering has 12 criteria including CSPM capabilities, IaC security, and "Agentic AI and copilots"; Wiz claims top score in Current Offering and top possible scores in 10/12 criteria plus Innovation and Roadmap. Vendor-reported — [Wiz on Forrester Wave Q1 2026](https://www.wiz.io/blog/forrester-wave-cnapp-2026)
- Enterprise RFP artifacts: Wiz publishes a CNAPP buyer's guide with an RFP template; Sysdig/SANS buyer's guide frames requirements as CWPP, CSPM, CDR with required/desired checklist; ISMG/CIO guide uses Platform Architecture, AppSec, Cloud Posture, Runtime Protection, SOC Integration. Vendor-authored — [Wiz CNAPP Buyer's Guide](https://wiz.io/lp/cnapp-buyers-guide); [Sysdig/SANS CNAPP Buyer's Guide](https://go.sysdig.com/s-sans-cnapp-buyers-guide); [CIO CNAPP Buyer's Guide](https://us.resources.cio.com/resources/the-cnapp-buyers-guide-3)
- SMB-targeted packaging evidence: Aikido free tier (2 users, 10 repos, 1 cloud account), flat monthly fees "no hidden charges", 30% startup discount (<$1.5M funding, <10 people), AWS/Azure Marketplace purchase on Basic–Advanced; Prowler $99/cloud account/month no commitment; Semgrep Free up to 10 contributors/10 repos; Snyk Free 5 projects. Verified — [Aikido pricing](https://www.aikido.dev/pricing); [Prowler pricing](https://prowler.com/pricing); [Semgrep pricing](https://semgrep.dev/pricing); [Snyk plans](https://snyk.io/plans/)
- G2 review themes: Orca cons are thin (Security Vulnerabilities 6 reviews, Dashboard Issues 5); older IT Central Station data says Orca users want more integrations, Wiz users want more customization and faster support; PeerSpot CNAPP mindshare March 2026: Wiz 17.4%, Orca 6.3% (down from 8.1%). Third-party — [G2 comparison](https://www.g2.com/compare/uptycs-uptycs-vs-wiz-wiz-vs-orca-security); [IT Central Station Orca vs Wiz](https://Itcentralstation.com/products/comparisons/orca-security_vs_wiz); [PeerSpot Orca](https://origin.peerspot.com/vendors/orca-security)

### Inferences
- A 1–3 person team's effective weighting (inferred from the SMB-packaged vendors' tier design): free/no-card trial with real findings in hours > flat predictable price > Jira/Slack + PR-based fixes so developers self-serve > SOC 2/ISO evidence push to Vanta/Drata > everything else. Runtime agents, CIEM depth, SIEM/OCSF, data residency and MSSP mode are enterprise weights.
- The "who owns remediation" decision is the single most repeated non-feature criterion across buyer guides; for small teams this translates to demanding developer-facing surfaces (PR comments, IDE/MCP, Slack) rather than a security console.
- Because G2 "false positives" is the lowest-rated feature even for Wiz/Orca, SMB evaluators who run a PoC on their own environment will weight signal-to-noise more than RFP templates suggest.

### Gaps
- No independent survey data (e.g., Gartner Peer Insights or a published 2026 buyer survey) quantifying SMB vs enterprise criterion weights was found; the weighting above is inferred from guides and packaging.
- The Wiz RFP template and Sysdig/SANS checklist contents were not fetched (gated downloads).

---

## Key Question 3: Current pricing units and tiers for each leader (published vs third-party)

### Takeaway
Only the developer-first and open-core vendors publish prices (Aikido, Prowler, Snyk, Semgrep); CNAPP leaders (Wiz, Orca, Prisma, CrowdStrike, Sysdig, Upwind, Lacework) and compliance platforms (Vanta, Drata, Secureframe) are quote-only, with the only "published" signal being AWS Marketplace bands (Orca) or credit rate cards (Snyk Enterprise, Prisma). Third-party estimates conflict widely and should be treated as ranges.

### Cited Findings

Published (fetched from vendor pricing pages, Oct 2026):
- Prowler: Free Trial 7 days; Prowler Cloud $99 per cloud account per month, monthly no commitment or annual at 20% off (example: 5 accounts = $495/mo list), buyable via AWS Marketplace; Private Cloud custom; Open Source free (Apache-2.0). Unit definitions: AWS account / GCP project / Azure subscription / GitHub repo / M365 tenant; resources counted per scan as a shared allowance with overages at discounted rate on annual plans. Add-ons: Custom Training $5,000/day, Custom Check $10,000/check, dedicated TAM $50,000/yr. — [Prowler pricing](https://prowler.com/pricing). (Third-party trackers show an older $79/account/mo figure and a $0.24/resource model, now superseded — [PricingSaaS Prowler](https://pricingsaas.com/companies/prowler); [Toolify](https://www.toolify.ai/tool/prowler-cloud/))
- Aikido: Developer $0 (2 users, 10 repos, 2 images, 1 domain, 1 cloud account, 10 AutoFixes/mo); Basic $300/mo (10 users, 100 repos, 3 cloud accounts); Pro $600/mo (10–50+ users, 200 repos, 10 cloud accounts, 100 credits/mo); Advanced listed at $600/mo on the page (likely display error; 500 repos, 20 cloud accounts, 200 credits/mo); Enterprise custom. Annual 10% off; startup discount up to 30%; AWS/Azure Marketplace. — [Aikido pricing](https://www.aikido.dev/pricing). Third-party snapshots list $350/$700/$1,050 per month (10 users) and a 2026-05-09 snapshot of Basic $300 / Pro $600 with 50 AutoFixes/mo on Pro — [PricingSaaS Aikido](https://pricingsaas.com/companies/aikido); [aicodereview Aikido](https://aicodereview.cc/tool/aikido)
- Snyk: Free $0 (5 projects, 100 Snyk Code tests/mo); Team from $25/mo (up to 10 devs, 100 projects, 1,000 Code tests/mo, Jira); Enterprise credit-based, 1 credit = $1 prepurchased: Code 1.0 and Open Source 1.0 credit per Active Contributor/day, IaC 0.33, Secrets 0.66, Evo AI-SPM 0.66, Container 0.33 per Monitored Image/day, DAST 3.0 per Provisioned Target/day, Evo ADS 1.0 per Active Machine/day, Evo COS 4,000 credits per assessment; overage billed in arrears. — [Snyk plans](https://snyk.io/plans/). Third-party: Ignite tier "$1,260/dev/year"; >10 committers forces Enterprise — [aicodereview Snyk](https://aicodereview.cc/blog/is-snyk-worth-it/)
- Semgrep: Free (10 contributors, 10 repos, 60 AI credits); Teams from $30/contributor/month per product (Code $30, Supply Chain $30, Secrets $15; 500 private repos; 20 AI credits/dev/mo); Enterprise custom (50 AI credits/dev/mo, unlimited). — [Semgrep pricing](https://semgrep.dev/pricing). Third-party: Vendr list range $40–80/dev/mo — [Vendr Semgrep](https://www.vendr.com/marketplace/semgrep)
- Vanta: plans Essentials / Plus / Professional / Enterprise, no prices published ("Get personalized pricing"); Essentials = one framework. — [Vanta pricing](https://www.vanta.com/pricing)

Marketplace / semi-published:
- Orca: AWS Marketplace 1-month contract, Small tier up to 100 concurrent EC2 workloads $7,000/mo, Small-medium up to 300; private-offer 12-month listing. — [AWS Marketplace Orca](https://aws.amazon.com/marketplace/pp/prodview-rogbt2k4b63xc). Third-party bands: Small $7k, Small-Medium $12k, Medium $17k, Large $30k per month — [ComparEdge Orca](https://comparedge.com/tools/orca-security/pricing); CostBench median contract $100k/yr (5 reports) — [CostBench Orca](https://www.costbench.com/software/cybersecurity/orca-security/); UK G-Cloud listing $390 per workload — [G-Cloud pricing doc](https://assets.applytosupply.digitalmarketplace.service.gov.uk/g-cloud-15/documents/704942/579921108240522-pricing-document-2026-01-19-1024.pdf); G2: annual license priced by compute asset — [G2](https://www.g2.com/compare/uptycs-uptycs-vs-wiz-wiz-vs-orca-security)

Third-party only:
- Wiz: priced as a percentage of annual cloud spend, typically 1.0–2.5% — [Decryption Digest container pricing](https://www.decryptiondigest.com/blog/container-security-platform-pricing-prisma-cloud-aqua-wiz-sysdig); entry "around $24,000+/year" with per-cloud minimums — [Ciphers 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- Sysdig: ~$35–55 per host per month covering unlimited containers; 500 nodes ≈ $210k–330k/yr list — [Decryption Digest](https://www.decryptiondigest.com/blog/container-security-platform-pricing-prisma-cloud-aqua-wiz-sysdig); entry "from ~$699/mo" — [Ciphers 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- Prisma Cloud: per-credit "~$1.20/credit", full CNAPP from ~$45,000/yr — [Ciphers 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)
- Upwind: custom quote, annual contract, single SKU bundling runtime, code scanning and data security; no free tier — [ethicalhacking.ai Upwind](https://ethicalhacking.ai/pricing/upwind-security-pricing); [HackerNoon Upwind vs Wiz](https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection)
- Drata: $10k–80k+/yr; entry ~$7,500/yr (≤50 employees), Foundation ~$15k one framework, Growth $20k–45k incl. API access; SpendHound SMB average $34,496 — [trycomp Drata pricing](https://trycomp.ai/drata-pricing); [knowlee Drata 2026](https://www.knowlee.ai/blog/tools/drata-pricing-2026); [SpendHound Vanta](https://www.spendhound.com/marketplace/vanta-pricing)
- Vanta: ~$7,500–30k+/yr with per-framework fees; Vendr median ~$20k; CostBench median $20k from 320 purchases; SpendHound SMB average $29,043 — [strac Vanta pricing](https://www.strac.io/blog/vanta-pricing); [CostBench Vanta](https://www.costbench.com/software/compliance-management/vanta/); [SpendHound](https://www.spendhound.com/marketplace/vanta-pricing)
- Secureframe: Fundamentals ~$7,500/yr, Complete, Federal; median ~$20k, range ~$7.7k–32.6k; per-framework add-ons ~$7,500 — [trycomp Secureframe](https://trycomp.ai/secureframe-pricing); [CostBench Secureframe](https://costbench.com/software/compliance-management/secureframe/)
- Negotiation: buyers "consistently achieve 20–30% discounts"; 2-year commitment 15–25% — [knowlee](https://www.knowlee.ai/blog/tools/drata-pricing-2026)
- Mid-market CNAPP starting prices "commonly $50K–$200K per year" (vendor guide claim) — [Ciphers 2026](https://cipherssecurity.com/cnapp-buyers-guide-2026/)

### Inferences
- Pricing-unit taxonomy in 2026: per cloud account (Prowler), per concurrent workload band (Orca), per host (Sysdig), per active contributor/day credits (Snyk), per contributor per product (Semgrep), flat tier with caps (Aikido), % of cloud spend (Wiz, third-party), per framework + headcount (Vanta/Drata/Secureframe).
- Snyk's credit rate card is the most granular public consumption model and is effectively the "ASPM Enterprise" reference; Prowler's $99/account is the lowest public CSPM entry point with SOC 2 Type 2 and SSO included.

### Gaps
- No published or marketplace price found for CrowdStrike Falcon Cloud Security, Lacework/FortiCNAPP, Upwind (search budget exhausted before AWS Marketplace listings could be fetched).
- Aikido Advanced true price unresolved (page shows $600 same as Pro).
- Vanta/Drata/Secureframe official plan feature matrices only partially readable (image checkmarks).

---

## Key Question 4: Which AI-era features changed buyer expectations in 2025–2026 (auto-fix PRs, MCP servers, agents)

### Takeaway
Between April 2025 and October 2026 every vendor in scope that could be verified shipped a remote MCP server and some form of PR-generating remediation; Snyk reports Evo at 60% of new deal volume and Forrester added "Agentic AI and copilots" to its CNAPP scoring, so buyers now expect (1) an MCP endpoint their coding agents can call, (2) fix PRs with approval gates and independent verification, and (3) natural-language posture Q&A — while also expecting the vendor to secure the agents themselves (AI-SPM, MCP scanning).

### Cited Findings
- Wiz MCP Server: announced April 21, 2025 in preview; translates natural language into Wiz operations; IDE flow lists issues -> root cause -> applies fix -> GitHub PR -> verifies in Wiz; complements Mika AI assistant; warns that queries flow through the MCP host so customers must review that host's data-handling/training settings. Vendor-claimed — [Wiz MCP blog](https://www.wiz.io/blog/introducing-mcp-server-for-wiz)
- Wiz AI agents (Nov 4, 2025): Issues Agent (preview) and SecOps Agent (auto-triage with confidence + reasoning, analyst review before response); Ask AI (Mika) and Wiz Extend browser Q&A ("is this CVE relevant to my environment"). Vendor-claimed — [Wiz AI agents blog](https://wiz.io/blog/wiz-ai-agents)
- Wiz 2026: agent-based remediation, "AI-Application Protection Platform", AI-BOM for shadow AI (Google Cloud Next, April 2026); Green Agent for developer-workflow remediation and PR generation; agents available in FedRAMP High Wiz for Gov with autonomous or human-in-the-loop modes. Third-party — [Tamnoon](https://tamnoon.io/blog/google-cloud-next-2026-agentic-cloud-security/); [ThreatCluster](https://threatcluster.io/cluster/introducing-wiz-workflows-ec4ebab3); [Futurum](https://futurumgroup.com/?p=96694)
- Forrester Wave CNAPP Q1 2026 scores "Agentic AI and copilots" as one of 12 Current Offering criteria. Vendor-reported — [Wiz Forrester blog](https://www.wiz.io/blog/forrester-wave-cnapp-2026)
- Vanta MCP: public preview June 9, 2025; now beta, released to all customers; hosted at mcp.vanta.com / mcp.eu.vanta.com / mcp.aus.vanta.com; OAuth, inherits user role; six capability areas (remediate failing tests, manage controls, vendor risk, vulnerabilities, policies, compliance gaps); works with Claude, Cursor, Perplexity, Codex; official Claude Code plugin with `/vanta:fix-test` (opens PR) and `/vanta:list-tests`; open-source self-hosted `@vantasdk/vanta-mcp-server`. Verified — [Vanta MCP docs](https://developer.vanta.com/docs/vanta-mcp); [Meet the Vanta MCP Server](https://www.vanta.com/resources/meet-the-vanta-mcp-server); [Vanta help: MCP overview](https://help.vanta.com/en/articles/15461008-vanta-mcp-overview)
- Vanta AI Agent is in every plan (search, Q&A, evidence checks, policy templates, control mapping, evidence collection, SLA tracking); "agentic policy generator" on Essentials; "agentic issue management" on Professional. Verified — [Vanta pricing](https://www.vanta.com/pricing)
- Drata MCP: "lets AI agents work with Drata ... managing controls through natural language". Verified landing page — [Drata developers](https://developers.drata.com/)
- Prowler: MCP server (preview) with cloud-hosted `https://mcp.prowler.com/mcp` and local STDIO option; tool namespaces `prowler_*` (findings, providers, scans, muting, compliance, attack paths, integrations, users, roles), `prowler_cloud_*` (alerts, triage, scheduling), `prowler_hub_*` (2,000+ checks, fixers, 70+ frameworks), `prowler_docs_*`; clients include Claude Desktop, Claude Code, Cursor, Codex, VS Code. Lighthouse AI (LangChain agent, default GPT-5.6 Terra, read-only, supports OpenAI/Bedrock/OpenAI-compatible) can run attack-path queries, schedule scans, create mute rules. Claude Code plugin remediates via IaC/CLI, opens PRs, rescans. Verified — [Prowler MCP docs](https://docs.prowler.com/getting-started/products/prowler-mcp); [Prowler Lighthouse architecture](https://docs.prowler.com/developer-guide/lighthouse-architecture.md); [Prowler July 2026 newsletter](https://prowler.com/blog/prowler-july-2026-newsletter)
- Snyk Evo (Oct 15, 2026): five-agent team; Remediation Agent 90% mergeable fixes vs 59.6% LLM-only; build-breaking fixes held for approval; independent verifier (Evo COS) attacks the running app; Snyk study of ~10,000 dev environments found 1 in 12 developers running MCP servers had a high/critical finding. Vendor-claimed — [Snyk Evo launch](https://snyk.io/news/snyk-launches-evo-agentic-appsec/)
- Snyk Sept 2026: Remediation Agent in open preview "automatically fixing the issues it finds"; Agentic AppSec Agent in private preview orchestrating a continuous autonomous triage-and-remediation loop. Vendor-claimed — [Snyk: agentic AI security moves into production](https://snyk.io/jp/news/agentic-ai-security-moves-into-production/)
- Snyk reports "Evo by Snyk reaches 60% of new deal volume" (Sept 22, 2026). Vendor-claimed via press — [Cyprus Shipping News press release](https://cyprusshippingnews.com/2026/09/22/as-ai-risk-scales-and-vulnerabilities-compound-evo-by-snyk-reaches-60-of-new-deal-volume/)
- Snyk prices AI products in its credit card: Evo AI-SPM 0.66 credit/contributor/day, Evo ADS (coding agent security) 1.0 credit/machine/day, Evo COS 4,000 credits/assessment; Evo requires Enterprise. Verified — [Snyk plans](https://snyk.io/plans/)
- Semgrep: AI detection/triage/autofix on all tiers with metered AI credits; custom AI model provider on Enterprise; "AI coding agent plugin" on all tiers. Verified — [Semgrep pricing](https://semgrep.dev/pricing)
- Aikido: AI SAST with custom rules on Free; AutoFix metered then unlimited on paid; "Aikido Max" unlimited AI credits add-on; "AI and bot protection" on Basic; AI Pentesting with pay-to-unlock. Verified — [Aikido pricing](https://www.aikido.dev/pricing)
- Orca: generative-AI remediation text in tickets via Amazon Bedrock/GPT-4 (2023-era), not autonomous apply. Vendor-claimed — [Orca Bedrock blog](https://orca.security/resources/blog/orca-integrates-with-amazon-bedrock-ai/)
- Tamnoon "State of Cloud Remediation 2026" report exists (not fetched). — [Tamnoon](https://tamnoon.io/?p=19767)

### Inferences
- The buyer expectation shift is from "AI explains the finding" (2023–24: Orca GPT-4 text) to "AI fixes it in a PR and something independent verifies the fix" (2026: Snyk Evo COS, Wiz Issues Agent -> PR -> verify, Prowler plugin rescans, Orca rescan-on-close). RFP language in 2026 should ask for approval gates, verification method, and whether the agent "grades its own work".
- A remote, vendor-hosted MCP server with OAuth that inherits the user's RBAC and regional endpoints (Vanta) is now the reference implementation; local-only STDIO servers are a fallback.
- Vendors are also monetizing "securing the agents" (Snyk ADS, Wiz AI-BOM/AI-APP, Aikido AI/bot protection), so AI features cut both ways in evaluations: capability and attack surface.
- Pricing of AI is converging on metered credits (Semgrep, Aikido, Snyk) on top of base tiers, which SMBs will experience as a new overage line.

### Gaps
- No primary source for Wiz Green Agent launch date (conflicting third-party dates April vs July 2026) or Wiz MCP GA status after preview.
- Could not verify MCP servers or agentic features for Orca, Prisma Cloud, CrowdStrike Falcon Cloud, Lacework/FortiCNAPP, Upwind, Sysdig (Sysdig Sage), Secureframe within the search budget.
- No independent (non-vendor) measurement of auto-fix PR merge rates or buyer adoption beyond Snyk's own "60% of new deal volume" claim.
