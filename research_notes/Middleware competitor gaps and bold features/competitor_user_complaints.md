# Competitor user complaints: where security tools adjacent to an integration-layer posture product leave users unhappy (as of 23 Nov 2026)

Reading notes for the report writer:

- Evidence tags used below. **[Fetched]** = I opened the page and the quote/paraphrase was extracted from it. **[Snippet]** = seen only in a search-result summary; wording may be slightly off and should be re-checked before being printed as a direct quote. **[Vendor]** = written by a vendor or competitor with a commercial interest; treat as a claim, not a user statement.
- Reddit could not be fetched from this environment, and Gartner Peer Insights returned HTTP 403. Hacker News comment search (Algolia, 2025+) returned zero hits for three queries. So Reddit/HN/Blind evidence here is second-hand only, and is flagged as such. Most verified user statements come from PeerSpot, G2 (via AWS Marketplace mirror), vendor community forums and one n8n forum thread.
- No quotes are invented. Where a category had little public complaint data, that is stated under Gaps.

---

## 1. What do users dislike about CNAPP/CSPM tools (Wiz, Orca, Prisma/Cortex Cloud, Lacework/FortiCNAPP, Prowler, Aikido, Datadog Cloud Security)?

### Takeaway
The verified complaints cluster on four things: price (Wiz repeatedly described as among the most expensive), alert volume that needs tuning before developers can be exposed to it, remediation workflow/ownership being left to the customer, and "we still are not getting a complete view" despite buying a platform. I found no user review that names brokers, gateways or iPaaS as the missing coverage; the "incomplete view" complaint is generic.

### Cited Findings

Wiz (PeerSpot, verified reviewers) **[Fetched]**
- "feedback indicates that Wiz is among the most expensive tools available." Madhav Shyam Lakhera, Cyber Security Engineer, consultancy, 10,001+ employees, 5 Dec 2025 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- "it is a bit expensive compared to its peers, but I do think the premium is worth it"; "Wiz's ServiceNow integration is not the best"; remediation backlog "we still have a few dozen left to work through." Darin Hurd, EVP and CISO, Rate, 12 Jan 2026 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- "Initially... there were too many alerts" and little reduction since; "if your hybrid environment is not managed properly, it will be difficult to implement." MohammedYasin, Senior AI/SRE and Automation Engineer, tech vendor, 5,001-10,000 employees, 9 Dec 2025 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- "there were overlapping capabilities, and we still are not getting a complete view"; enabling add-on capabilities later "can be time-consuming." Karunesh Tripathi, Product Management Cybersecurity Leader, tech vendor, 10,001+ employees, 17 Jun 2026 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- "Wiz does not allow for tool consolidation in our environment." Jagdish Mandaramariq, Cyber Security Analyst, DigitalTrack Solutions, 27 Jul 2026 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- "Integrations need to be monitored to ensure there are no gaps in the integration part." Navaneet Upadhyay, Principal Solution Architect, reseller, 14 Nov 2025 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- Older (dated): "If Wiz can figure out the remediation workflow, I would put the solution close to a ten." Sr. Manager/AVP Vulnerability Management, computer software, 201-500 employees, 17 Mar 2023 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- Older (dated): "some policies included in the connectors were flagging our production EBS in AWS." AWS Cloud Security Engineer, tech services, 51-200 employees, 15 Apr 2024 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- Older (dated): a CISO at an 11-50 employee retailer marked Wiz down "primarily due to reporting challenges," 13 Jun 2024 — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)

Wiz (other review sites) **[Snippet]**
- A G2 reviewer's answer to "what do you dislike" was alert fatigue and avoiding overwhelming the teams (date/role not captured) — [G2](https://g2.com/products/wiz-wiz/reviews?page=4)
- AWS Marketplace reviewer: the platform needs significant tuning so developers are not overwhelmed by non-critical findings; another says Wiz does not fully remove false positives (dates/roles not captured) — [AWS Marketplace reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ibgbkrqusncsm)
- PeerSpot reviewers: cost "seems to be going up"; request for more transparent pricing; higher cost than Microsoft Defender for Cloud across multiple subscriptions — [PeerSpot Wiz questions](https://www.peerspot.com/products/wiz/questions)
- G2 aggregate con tags for Wiz: Complexity (26 reviews), Expensive (23), False Positives (18); Microsoft Defender for Cloud: Complexity (27), Expensive (24), False Positives (19). Small counts, indicative only — [G2 comparison page](https://www.g2.com/compare/check-point-cloudguard-cnapp-vs-snyk-vs-forticnapp)
- **[Vendor]** Aikido's "Wiz alternatives" blog lists high alert volume and false positives and quotes a Reddit DevOps engineer saying Wiz is mostly a security-team tool. Competitor content; original Reddit post not verified — [Aikido](https://de.aikido.dev/blog/top-wiz-io-alternatives-for-cloud-application-security)

Prisma Cloud / Cortex Cloud (PeerSpot) **[Fetched]**
- "it was difficult to implement from an operational point of view." Cyber Security Architect, comms service provider, 10,001+ employees, 14 Nov 2025 — [PeerSpot](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons)
- "I notice multiple false positives, which is one weakness I found." Pinki Jaiswal, IT Engineer, DXC Technology, 30 Jun 2026 — [PeerSpot](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons)
- "I would enhance the integration with other vendors." Sector Manager, comms service provider, 51-200 employees, 23 Feb 2026 — [PeerSpot](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons)
- A Cloud Security Engineer (tech vendor, 201-500 employees, 13 Nov 2025) asked for a way to prove a flagged resource is actually exploitable (a "dummy payload" feature) — [PeerSpot](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons)
- Older (dated 2024): users must switch between modules to see the full risk picture (Security Solutions Architect, 10,001+, 3 Sep 2024); a request to "ask questions about the context of the alert" (Senior Security Consultant, 20 Aug 2024); "enterprise reporting needs significant improvement" (Assistant VP, NatWest Group, 22 Jul 2024) — [PeerSpot](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons)

Small-team framing of the CSPM problem
- **[Vendor]** iomergent (CSPM services blog) lists alert fatigue from false positives as the DIY CSPM challenge and gives rough startup pricing of about $500-2,000/month for commercial CSPM and $1,000-5,000/month managed. Vendor figures, unverified — [iomergent](https://iomergent.com/cspm-for-startups/)

### Inferences
- The most intense CNAPP pain in verified reviews is not detection quality, it is what happens after detection: tuning, routing, ownership and ticketing integration. Three separate reviewers (2023, 2026, 2026) describe remediation workflow or backlog as the unresolved part.
- "Expensive" plus "still not a complete view" plus "does not allow tool consolidation" is a consistent trio. A cheap, narrow tool that fills a named blind spot is a credible complement rather than a competitor.
- The Prisma reviewer asking for proof of exploitability, and the Wiz reviewers asking for fewer alerts, both point at the same want: evidence that a finding is real before a human spends time on it. VectaSec's Verify loop is aimed at exactly this.

### Gaps
- No verified user complaints found for Orca, Lacework/FortiCNAPP, Prowler, Aikido or Datadog Cloud Security in this pass. One 2026 comparison blog credits Orca with low false positives and about $36K+/yr pricing, but it is an affiliate-style source — [Cloudaware](https://cloudaware.com/blog/cnapp-tools/).
- No Prowler GitHub issue mining was done; false-positive and coverage-request issues there would be a good follow-up.
- No user review explicitly says "my CNAPP does not see Kafka/RabbitMQ/Kong/n8n." See section 7.

---

## 2. What do users dislike about API security tools (Salt, Akamai/Noname, Traceable/Harness, Akto, 42Crunch, Cequence, Wallarm)?

### Takeaway
Public complaint data is thin and reviews are mostly positive (4.6 averages). The verified negatives are: per-API pricing that gets expensive as you add APIs, poor fit for small environments, setup complexity and a steep learning curve, and false-positive tuning that requires security expertise. Traffic-mirroring friction is asserted mainly by competitors, not by reviewers.

### Cited Findings
- Salt Security: "Regarding scalability, for users in smaller environments, it is not exactly the best." Risk Advisory Senior Manager, marketing services firm, 1,001-5,000 employees, 22 Jun 2026 **[Fetched]** — [PeerSpot](https://www.peerspot.com/products/salt-security-pros-and-cons)
- Salt Security: "The setup cost was acceptable, but adding additional APIs was actually quite expensive." Tacio Veiga, Sr Investigation Specialist, iFood, 26 May 2026 **[Fetched]** — [PeerSpot](https://www.peerspot.com/products/salt-security-pros-and-cons)
- Salt Security, older (dated): "The integration part could be a bit extended." Managing Director, Tegra Solutions, 8 Jan 2024 **[Fetched]** — [PeerSpot](https://www.peerspot.com/products/salt-security-pros-and-cons)
- Counter-evidence: a Gartner Peer Insights reviewer at a large manufacturer described Salt's traffic-mirroring deployment as fairly simple; Salt rates 4.6 from 56 ratings with a 4.5 Integration & Deployment sub-score **[Snippet]** — [Gartner Peer Insights](https://www.gartner.com/reviews/market/api-protection/vendor/salt-security/product/salt-security-api-protection-platform/likes-dislikes)
- Cequence: G2 summarises its main complaints as setup complexity and steep learning curve, with setup delays in fine-tuning; a smaller group cites false positives affecting eCommerce traffic. 4.6/5 across 55 reviews **[Snippet]** — [G2 Cequence](https://g2.com/products/cequence-security/reviews?page=2)
- Wallarm: one reviewer says you need to build rules to reduce false positives "which can get fairly complex"; another that first-time configuration is tricky for people without a cybersecurity background; another dislikes a lack of documentation/manuals and wants more best-practice config examples. Other reviewers praise low false positives **[Snippet]** — [G2 Wallarm](https://www.g2.com/products/wallarm-api-security-platform/reviews?page=2)
- Noname/Akamai: the claim that G2 and Gartner reviews highlight difficulty integrating Noname with existing tools comes from Wallarm's comparison page **[Vendor]**; not verified against the review sites — [Wallarm](https://wallarm.com/noname-security-vs-wallarm)
- **[Vendor]** Escape argues traffic-based tools are slow to deploy and blind to APIs with no traffic. Competitor content — [Escape](https://escape.tech/blog/api-security-issues-with-traffic-based-tools/)

### Inferences
- The Salt quote that it is "not exactly the best" for smaller environments, plus per-API pricing, supports the view that runtime API security is priced and shaped for enterprises. Small teams are under-served on the gateway side.
- Complaints about needing a security background to tune rules map directly onto the 0-3 security people buyer.

### Gaps
- No user complaints retrieved for Traceable/Harness, Akto (including GitHub issues) or 42Crunch.
- Deployment-friction complaints specific to mirroring/sensors (time to first value, network team approvals) were not found in verified user voice, only in competitor marketing. Treat as plausible but unproven.

---

## 3. What do users dislike about non-human identity / secrets tools (Astrix/Cisco, Entro/SailPoint, Oasis/Cyera, Token Security, Clutch, GitGuardian, Aembit, Akeyless, HashiCorp Vault)?

### Takeaway
Vault is the only product here with a deep verified complaint record: operational complexity, steep learning curve, expensive enterprise licence for small use cases, and difficulty finding which team owns a secret. For the pure-play NHI vendors there is almost no public user complaint data; the "rotation breaks production because nobody knows the dependencies" pain is widely asserted but documented mostly by an industry group and vendor reports, not by user reviews.

### Cited Findings

HashiCorp/IBM Vault (PeerSpot) **[Fetched]**
- "I have had hard times trying to find secrets that different teams own." SRE, financial services firm, 10,001+ employees, 15 Dec 2025 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- "the enterprise license is expensive, especially for some of the smaller use cases." Senior Cyber Security Engineer, tech vendor, 10,001+ employees, 11 Dec 2025 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- "HashiCorp Vault could improve by being a little bit more accommodating to startup companies." Managing Trustee and CTO, financial services firm, 1-10 employees, 30 Oct 2025 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- "HashiCorp Vault is quite complex to use for new users and has a steep learning curve." Cloud Ops Lead, 10,001+ employees, 18 Jan 2026 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- "Setting up HashiCorp Vault can present operational challenges because deploying it involves complex initial setup." Senior Platform Engineer, Giant Group, 5 Aug 2026 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- "The ACLs within HashiCorp Vault, such as policies and AppRole authentication, were not intuitive at first." Senior DevOps Engineer, tech services, 10,001+ employees, 11 Nov 2025 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- "One of the challenges we had was that we used a really old version." IT Security Engineer, security firm, 11-50 employees, 15 Dec 2025 — [PeerSpot](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons)
- A G2 review describes immense operational complexity, a steep developer learning curve and escalating enterprise costs after the IBM acquisition **[Snippet]** — [G2 review](https://www.g2.com/survey_responses/ibm-vault-formerly-hashicorp-vault-review-13455184)
- **[Vendor]** Infisical (competitor) states Vault Enterprise pricing is unpublished and cites about $0.62/hr (~$450/mo) for the smallest managed dedicated cluster. Not verified against IBM — [Infisical](https://infisical.com/blog/hashicorp-vault-pricing)

GitGuardian
- G2 reviewer dislike: it can sometimes generate false positives that need manual review and slow things down; G2's summary repeats this **[Snippet]** — [G2 GitGuardian](https://g2.com/products/gitguardian/reviews)
- A third-party review says the tool needs a dedicated security engineer to triage the alert volume (single reviewer blog) **[Snippet]** — [The CTO Club](https://thectoclub.com/tools/gitguardian-review/)
- **[Vendor]** Aikido notes the documented False Positive Remover requires a paid plan — [Aikido](https://www.aikido.dev/blog/astrix-vs-gitguardian)

Entro
- "Entro Security could benefit from improvements in IAM control to allow segregation of duties among developers." PeerSpot reviewer (role/date not captured) **[Snippet]** — [PeerSpot](https://origin.peerspot.com/products/comparisons/entro-security_vs_gitguardian-platform)

Astrix
- **[Vendor]** Aikido states Astrix is now part of Cisco and ended standalone sales of new licences on 30 Jun 2026. Competitor source; verify before relying on it — [Aikido](https://www.aikido.dev/blog/astrix-vs-gitguardian)

Rotation breaking production / unknown owners (industry and vendor sources, not user reviews)
- NHI Mgmt Group: teams often rotate a credential without knowing everywhere it is used; unknown secrets usually surface only after an outage or failed deployment. Advice: "Quarantine unknown secrets, verify ownership, then rotate only after dependency checks pass." **[Snippet, vendor-affiliated industry group]** — [NHIMG FAQ](https://nhimg.org/faq/what-breaks-when-secret-rotation-is-not-tied-to-ownership-review/)
- Entro's 2025 State of NHIs and Secrets report, as cited by NHIMG: 62% of secrets are duplicated and stored in multiple locations **[Vendor, second-hand]** — [NHIMG FAQ](https://nhimg.org/faq/why-do-manual-secret-rotations-keep-failing-in-production/)
- Cloud Security Alliance has a practitioner article on expired secrets disrupting operations (not fetched) — [CSA](https://cloudsecurityalliance.org/articles/how-to-stop-expired-secrets-from-disrupting-your-operations)

### Inferences
- The Vault SRE quote ("hard times trying to find secrets that different teams own") is direct user evidence that ownership mapping is unsolved even in the market-leading secrets store, at a 10,001+ employee company. Small teams have it worse because they have no platform team.
- A startup CTO (1-10 employees) and an enterprise engineer both say Vault's enterprise tier is mispriced for small use cases. A cheap inventory-and-usage layer over whatever secrets already exist is a real opening.
- Because "rotation broke prod" is asserted far more than it is documented in reviews, a feature like "show every consumer of this credential before you rotate, and verify after" should be pitched on the ownership/dependency evidence, which is verified, rather than on outage anecdotes.

### Gaps
- No user reviews found for Oasis, Token Security, Clutch, Aembit or Akeyless complaints; the category is young, enterprise-sold and being consolidated by acquirers, so public dislike data is sparse. This is a real data gap, not evidence of satisfaction.
- An NHIMG article titled as a Cloudflare rotation outage returned HTTP 404; I could not confirm the incident details and have not cited it as fact.
- "No usage data" (cannot tell whether a key is still used) was not found as a verbatim user complaint.

---

## 4. What do users dislike about compliance automation (Vanta, Drata, Secureframe, Sprinto)?

### Takeaway
Cost and contract lock-in dominate: multi-year contracts with no termination for convenience, add-on fees and renewal jumps when frameworks are added. The second theme is that automation stops at the connector boundary, so anything custom or without an integration falls back to manual evidence. Much of the Reddit evidence is second-hand via review aggregators and could not be opened directly.

### Cited Findings
- r/soc2 thread (2025), as reported by soc2auditors.org: a commenter who used Vanta, Drata and Secureframe calls Vanta too expensive and says its cross-mapping "does not work as advertised"; another user cancelled because cost and benefit did not add up **[Fetched secondary; Reddit original not opened]** — [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/), original [Reddit thread](https://www.reddit.com/r/soc2/comments/1krz49z/interested_in_feedback_on_vanta/)
- Same page: a startup of under 10 people reports the integrations worked but a two-year contract stayed in force when company finances changed **[Fetched secondary]** — [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/)
- Same page: an unnamed 2026 commenter calls switching to Vanta for HITRUST/SOC 2/HIPAA "a roughly $14,000 mistake" and says every mid-contract cancellation proposal was refused. No link given by the page **[Fetched secondary, unlinked]** — [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/)
- Same page, on Vanta's own contract FAQ: no right to terminate for convenience; renewal promises "a level of pricing predictability" with no stated cap. The information request list for auditors is "an upgrade or add-on"; historical results export one test at a time **[Fetched secondary describing vendor terms]** — [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/)
- Same page's own analysis: custom or on-premises systems need manual evidence; Vanta's public pages do not establish the collection interval for every connector **[Fetched secondary]** — [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/)
- r/SaaS, Sep 2026: a 40-person SaaS buyer asks how much evidence collection is really automated once connectors are installed. A question, not a complaint, but it shows buyer doubt **[Fetched secondary]** — [Reddit thread](https://www.reddit.com/r/SaaS/comments/1whv6yi/vanta_vs_drata_for_a_40person_saas_how_much/)
- Secondary write-ups report a Reddit user citing a 40% year-two Vanta price increase, and Drata renewal quotes rising from $7,500 to $20,000 to add two frameworks; also unexpected add-on fees. Originals not retrieved **[Snippet, second-hand]** — [Cyber Sierra](https://cybersierra.co/blog/vanta-drata-review/), [soc2auditors.org Drata review](https://soc2auditors.org/insights/drata-review/)
- Vanta Trustpilot/TrustRadius themes reported: poor support, absent CSMs, no refund for unused services **[Snippet, second-hand]** — [soc2auditors.org Vanta listing](https://soc2auditors.org/software/vanta/)
- A comparison site says both vendors auto-renew by default with a negotiable 10% annual increase cap. One site's claim **[Snippet]** — [Costbench](https://costbench.com/compare/drata-vs-vanta/)
- Both platforms are criticised for "checkbox compliance" rather than real security impact **[Snippet, source not pinned down]** — [Cyber Sierra](https://cybersierra.co/blog/vanta-drata-review/)
- "If your security policy is just a template with your company's name swapped in" (on checklist-driven compliance creating paperwork without reducing risk). Aayush Choudhury, CEO, Scrut Automation, 5 Aug 2025 **[Fetched, Vendor: Scrut competes with Vanta/Drata]** — [Help Net Security](https://www.helpnetsecurity.com/2025/08/05/aayush-choudhury-scrut-automation-lean-security-teams/)
- **[Vendor]** Drata publishes "customer wins" pages in 2026 about buyers leaving other vendors at renewal (titles include "A renewal deadline that forced the right question", 28 Oct 2026, and "Cut the bill, keep the compliance", 24 Jul 2026). Promotional, but they confirm renewal price is the switching trigger vendors themselves sell against — [Drata](https://drata.com/customers/wins/a-renewal-deadline-that-forced-the-right-question)
- Vanta disclosed a data-exposure bug in June 2025 that it said affected fewer than 4% of customers (reported by TechCrunch, per the review page) **[Fetched secondary]** — [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/)

### Inferences
- The connector boundary is the structural weakness: compliance platforms automate evidence for systems they integrate with, and brokers, gateways, self-hosted n8n and MFT servers are generally not among them. VectaSec's existing Vanta/Drata evidence push speaks to this; it should be framed as "evidence for the systems your compliance tool cannot see."
- Buyers resent lock-in and add-on pricing as much as headline price. Month-to-month terms and no per-framework surcharge would be a visible contrast for a small-company product.

### Gaps
- Auditor pushback on automated evidence: no user complaint found. Unverified.
- Secureframe and Sprinto: no specific user complaints retrieved.
- All Reddit material is second-hand; exact wording, usernames and dates were not verified at source.

---

## 5. What do users dislike about the built-in security/governance of middleware vendors (Confluent, Conduktor, Kong, MuleSoft, Boomi, Workato, n8n, Zapier)?

### Takeaway
Security and governance features are consistently placed in the top tier, and small teams hit this exactly when an IT security review or audit asks for logs. The clearest verified case is an n8n Pro customer who could not produce user activity logs and could not justify Enterprise. Kong's free/OSS mode ended at 3.10 with no forum response from maintainers. Confluent excludes audit logs from Basic clusters and keeps them only seven days.

### Cited Findings

n8n **[Fetched]**
- A Pro-plan user needed workflow change tracking and login/creation/deletion logs for an IT security review, could not find them, and wrote: "I might be at risk to suspend in using n8n just because i can't comply to IT security policies." On upgrading: "can't justify the ROI yet as not many members are using this tool." User weitat.bipo, 20 and 24 Jun 2025 — [n8n community](https://community.n8n.io/t/pro-version-with-user-activity-logs-urgent/135551)
- n8n staff reply (jan, 24 Jun 2025): "It sounds like what you are looking for is the Log streaming feature, which is available in the Enterprise version of the product," then pointed to sales or the Startup licence — [n8n community](https://community.n8n.io/t/pro-version-with-user-activity-logs-urgent/135551)
- Third-party analysis: audit logging, log streaming and instance-wide enforced 2FA are reserved for Enterprise; Business includes SSO only; Community edition has no SSO, RBAC, audit logs or support **[Snippet; consultancy/competitor blogs]** — [nordflux](https://nordflux.de/en/insights/n8n-cloud-vs-enterprise-where-is-the-security-boundary-for-smbs), [Activepieces (competitor)](https://www.activepieces.com/blog/n8n-audit-logs-what-each-plan-includes-2026.md)
- "'free to license' is not the same as 'free to run'"; "Someone has to operate it, secure it, patch it, and back it up"; governance "has essentially none of this out of the box." Ashish Maurya, Ivoyant (maker of a competing product), posted 15 Apr, edited 11 Sep, year inferred 2026 **[Fetched, Vendor]** — [DEV Community](https://dev.to/theashishmaurya/weve-implemented-enterprise-integrations-for-years-heres-the-honest-ipaas-landscape-in-2026-ib5)

Kong **[Fetched]**
- "As announced in the release notes is free mode in the Kong gateway since v.3.10.0 not supported anymore." The poster found no official announcement and no OSS images or release branches, and asked for an official statement. MarkusFlorian79, 9 May 2025 — [Kong Nation](https://discuss.konghq.com/t/is-opensource-support-for-kong-ceased/13529)
- "The lack of response from the Kong maintainers is an interesting indicator." mloskot, 8 Oct 2025. No Kong staff reply on the thread as of fetch; a 15 Dec 2025 post quotes the changelog: "Free mode is no longer available." — [Kong Nation](https://discuss.konghq.com/t/is-opensource-support-for-kong-ceased/13529)
- Kong Konnect G2 reviews (via AWS Marketplace mirror), Sep-Nov 2026: "The SaaS dependency is a hard requirement, not an option"; "For some enterprises, sending API metadata to a third-party cloud is a dealbreaker on its own"; "Pricing can be a little on the higher side for small teams" (khushbu K., 1 Oct 2026); "enterprise tier pricing scales sharply with API call volume" (Vikash K., 30 Sep 2026); "For a project with only a few APIs, Kong Konnect can also feel like more infrastructure than what is necessary" (Jay Prakash S., 7 Oct 2026); "The learning curve is also steeper than it needs to be" (9 Oct 2026). Company sizes not shown — [AWS Marketplace reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-qwksr2wun4awo)
- **[Vendor]** Zuplo's migration page says the last Kong OSS release was 3.9.1 and 3.10 shipped without prebuilt OSS Docker images. Competitor source, consistent with the forum thread — [Zuplo](https://zuplo.com/migrate/kong-community)
- A Kong forum thread "Free Kong OIDC plugin now live again!" (22 Aug 2025) implies OIDC was unavailable to free users for a time. Content not fetched **[Snippet]** — [Kong Nation](https://discuss.konghq.com/tag/kong-gateway)

Confluent Cloud (vendor documentation, not complaints) **[Snippet of official docs]**
- Audit logs are on for Standard, Enterprise, Dedicated and Freight clusters; Basic clusters do not include audit logs. Records are retained seven days; longer retention requires replicating them elsewhere. Reading the audit topic is billed per GB. Console access requires OrganizationAdmin — [Confluent docs](https://docs.confluent.io/cloud/current/monitoring/audit-logging/cloud-audit-log-concepts.html), [billing](https://docs.confluent.io/cloud/current/billing/dimensions/audit-logs.html)
- Cost complaints exist but the retrievable material is competitor marketing (AutoMQ, Redpanda, Estuary) quoting G2 reviewers on bills rising with data volume **[Vendor]** — [Estuary](https://estuary.dev/blog/confluent-alternatives/)

MuleSoft, Boomi, Workato, Zapier
- G2 lists "Expensive" among top cons for MuleSoft Anypoint (57 mentions on one comparison page, 183 on another) and for Zapier **[Snippet]** — [G2 comparison](https://www.g2.com/compare/boomi-vs-workato-vs-mulesoft-anypoint-platform)
- MuleSoft: "Mid-market teams routinely spend $400K+ in year one and still aren't in production at the end of it"; governance "requires certified MuleSoft architects to use it properly." Workato: "the governance model feels layered on rather than designed in"; audit logs "not deep enough for teams with real compliance requirements." Zapier: "there's no meaningful governance story." Boomi: pricing "harder to predict as workloads grow." Ashish Maurya, Ivoyant **[Fetched, Vendor; cost figures unsourced]** — [DEV Community](https://dev.to/theashishmaurya/weve-implemented-enterprise-integrations-for-years-heres-the-honest-ipaas-landscape-in-2026-ib5)
- Zapier's own comparison page states SAML SSO, audit logs and RBAC start on the Team plan, with SCIM and app/action-level restrictions at Enterprise **[Snippet, Vendor]** — [Zapier](https://zapier.com/blog/mulesoft-vs-zapier/)
- Workato: audit logs and SSO require the Enterprise plan, per a third-party alternatives guide **[Snippet]** — [Rework](https://resources.rework.com/tools/automation/best-workato-alternatives)

General "security tax" sentiment
- Practitioner/vendor essays in 2025 argue SSO should not be an enterprise perk ("Stop Paywalling Security", OneUptime, 19 Aug 2025) **[Snippet, Vendor]** — [OneUptime](https://oneuptime.com/blog/post/2025-08-19-sso-is-a-security-basic-not-an-enterprise-perk)

### Inferences
- The n8n thread is the single best piece of evidence for VectaSec's positioning: a paying small customer, forced by an internal security review, unable to produce who-changed-what, and unable to afford the tier that has it. An external tool that reconstructs change history and access evidence for lower tiers (workflow diffs, credential inventory, who has access) answers that exact situation.
- Kong's end of free mode with silence from maintainers leaves a population on unmaintained 3.9.x OSS gateways. They get no vendor security tooling at all; an agentless scanner that tells them what is exposed and what an unpatched version means is useful to them specifically.
- Confluent's seven-day audit retention and Basic-tier exclusion mean small teams on Basic have no audit trail to show an auditor. "Evidence when the vendor will not give you logs" generalises across n8n, Confluent Basic, Kong OSS, Zapier below Team and Workato below Enterprise.
- "Sending API metadata to a third-party cloud is a dealbreaker" is a warning for VectaSec too: offer a local or self-hosted scan mode, or be explicit about what leaves the customer's environment.

### Gaps
- No user complaints found for Conduktor, Confluent RBAC specifically, Azure APIM, Apigee, or Boomi governance from actual users.
- r/apachekafka sentiment on Confluent pricing could not be retrieved (Reddit blocked).
- Whether RBAC was removed from Kong OSS was not confirmed; only the end of free mode and OSS images is supported.

---

## 6. What do small teams (no dedicated security staff) say they actually want from a security tool but cannot get?

### Takeaway
They want a short, prioritised, plain-English list of what is actually dangerous and what to do first, at a price and setup effort that fits a team of under five, without needing security expertise to tune. Most first-person evidence for this is from vendor founders describing their customers, plus scattered reviewer comments; there is little raw small-team voice in the sources I could open.

### Cited Findings
- "Often, teams of <5 people are handling all of those responsibilities"; "Most SMBs end up using only 20 to 30 percent of the tool's functionality"; "many tools marketed to them are scaled-down versions of enterprise solutions"; implementation can run "over 6-12 months"; small workflow changes "will often trigger a 2-3 week long change request with the SI." Aayush Choudhury, CEO, Scrut Automation, 5 Aug 2025 **[Fetched, Vendor]** — [Help Net Security](https://www.helpnetsecurity.com/2025/08/05/aayush-choudhury-scrut-automation-lean-security-teams/)
- "What a small team actually needs isn't more findings." Needs listed: "What is genuinely dangerous right now", "What is probably noise", "What to fix first and why", "Explained in plain English without assuming security expertise." On current scanners: "They find. They don't evaluate." Wael Matoussi, founder of SecOpsium, posted 29 May (year appears to be 2026) **[Fetched, Vendor]** — [DEV Community](https://dev.to/wael_matoussi/the-problem-with-security-scanners-isnt-the-scanning-5cgl)
- Older (dated 12 Jun 2024), practitioners Rami McCarthy and Kane Narraway list security problems too small for venture-scale vendors. Relevant ones: cloud access/credential ergonomics ("a narrow vendor offering focused on access ergonomics would have a place in many cloud security programs"); teams want "an easy-to-deploy bot they can connect in" to confirm alerts with users; small teams lack capacity to run open-source tools ("managing and maintaining the fleet can be a beast") **[Fetched, independent practitioners]** — [tl;dr sec](https://tldrsec.com/p/sub-venture-scale-security-problems)
- An Aikido customer story describes a previous tool as "expensive, noisy, and often out of date" with most findings not real issues, making conversations with developers hard **[Snippet, Vendor case study]** — [Aikido](https://www.aikido.dev/customer-story/nerdio)
- Supporting reviewer voice from other sections: Vault "more accommodating to startup companies" (CTO, 1-10 employees, Oct 2025); Kong Konnect "more infrastructure than what is necessary" for a few APIs (Oct 2026); Salt "not exactly the best" for smaller environments (Jun 2026); Wallarm config tricky without a cybersecurity background — sources in sections 2, 3, 5.
- Safeguard (vendor guide) recommends report-only for the first weeks and failing checks only on serious, exploitable findings for teams with no security hire **[Snippet, Vendor]** — [Safeguard](https://safeguard.sh/resources/blog/sast-for-startup-no-security-team)

### Inferences
- The wants are consistent across sources: (1) a handful of findings, not hundreds; (2) each one explained without jargon; (3) an order to fix them in, with the reason; (4) the fix itself; (5) proof it worked; (6) something to hand an auditor or customer; (7) no implementation project.
- VectaSec already has guided fix + Verify and a weekly digest. The gaps relative to these wants are likely presentation and proof: a "top 3 this week" default view, a plain-English blast-radius sentence per finding, and a shareable one-page evidence export for a customer security questionnaire.
- The tl;dr sec point that small teams cannot operate open-source tooling argues for hosted, agentless and zero-maintenance as a first-class selling point, not a technical detail.

### Gaps
- Direct first-person statements from founders/engineers at companies with no security hire (r/sysadmin, r/msp, r/devops) were not retrievable. The category of evidence most wanted for this question is the weakest in this pass.
- No data on willingness to pay at the small end beyond vendor-blog ranges.

---

## 7. Which complaints mention the integration layer explicitly being invisible to existing tools?

### Takeaway
I found no verified end-user complaint that says in so many words "my CNAPP/CSPM cannot see my brokers, gateways or iPaaS." The blind spot is described by vendors (Gravitee), an industry group (NHIMG), and one independent opinion piece on SaaS integrations (CSO Online). Users express it only generically ("we still are not getting a complete view"). This is a real finding: the gap exists structurally but buyers are not yet articulating it, so VectaSec will have to show it rather than rely on existing demand language.

### Cited Findings
- "there were overlapping capabilities, and we still are not getting a complete view." Product Management Cybersecurity Leader, 10,001+ employees, on Wiz, 17 Jun 2026 **[Fetched]** — [PeerSpot](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz)
- "Of all those applications, security teams have clear sight into maybe one in 10"; "Most organizations have dozens of these connections sitting open across their SaaS platforms"; "The moment you authorize a third-party application; its security posture becomes your problem too." Ashish Mishra, IT professional, CSO Online opinion, 17 Jul 2026. Covers OAuth and CI/CD connections, not brokers or iPaaS specifically **[Fetched, independent contributor]** — [CSO Online](https://www.csoonline.com/article/4197923/the-saas-blind-spot-why-security-teams-cant-get-inside-their-own-apps.html)
- **[Vendor]** Gravitee defines shadow integrations as those existing outside formal ownership, security review and lifecycle management, listing unmanaged iPaaS flows and rogue Kafka consumers; notes the "easy path" is direct credentials while the "secure path" is slow approvals and unclear ownership; and that broker monitoring captures health but not ownership or purpose of topics and consumer groups **[Snippet]** — [Gravitee: shadow integration detection](https://gravitee.io/corpus/gen-707/java-business-integration/shadow-integration-detection.html), [Gravitee: event stream blind spots](https://gravitee.io/corpus/gen-1848/the-cycle-of-terror-and-tragedy/event-stream-blind-spots-and-operational-risk.html)
- NHIMG: CNAPPs depend on cloud provider APIs or agents and can overlook shadow assets; each tool sees one slice of risk so dangerous conditions stay split across consoles **[Snippet, vendor-affiliated]** — [NHIMG FAQ](https://nhimg.org/faq/why-do-cspm-and-cnapp-miss-some-cloud-attacks/), [NHIMG article](https://nhimg.org/articles/cloud-security-tool-sprawl-creates-blind-spots-across-identity-and-data/)
- Cloud Security Alliance article frames the application layer as the blind spot in CNAPP coverage (not fetched) **[Snippet]** — [CSA](https://cloudsecurityalliance.org/articles/breaking-the-cloud-security-illusion-putting-the-app-back-in-cnapp)
- Indirect user evidence that the integration layer lacks its own evidence trail: the n8n Pro user unable to produce activity logs for a security review (Jun 2025) and the Kong OSS users left without a supported edition (2025) — sources in section 5.

### Inferences
- Structural reason for the blind spot: CNAPPs read cloud-provider control-plane APIs. A self-hosted RabbitMQ, a Kong admin API, an n8n instance's credential store, or a Zapier workspace is configured inside the product, not in the cloud control plane, so it is outside what those tools enumerate. This is my reasoning from the sources above, not a quoted claim.
- Because buyers do not yet name the gap, the free external exposure scan is strategically important: it creates the "I did not know that was exposed" moment that no review currently describes.
- Compliance-tool connector limits (section 4) and vendor log paywalls (section 5) are the two places where users already feel the integration-layer gap, even if they do not call it that. These are the best entry points for messaging.

### Gaps
- No Reddit/HN/Blind thread found where a practitioner complains that their security tooling misses message brokers, API gateway config, iPaaS workflows, MFT or MCP servers. Could exist; Reddit was not searchable from here.
- No user complaint data at all on MCP server or AI gateway security tooling. Too new for review sites.

---

## 8. Ranked list: the most repeated or most intense pains, and which ones no vendor has solved

### Takeaway
Ranking is by how many independent verified sources repeat the pain, then by intensity (a user at risk of losing the tool or the contract ranks above mild friction). Pains 1-6 are well evidenced; 7-12 moderately; 13-18 are thinly evidenced or mostly vendor-asserted and are labelled so. "Unsolved" is my judgement from this evidence, not a quoted claim.

### Cited Findings

| # | Pain | Evidence strength | Where it shows up | Solved by any vendor? |
|---|------|-------------------|-------------------|-----------------------|
| 1 | Security/audit features paywalled in top tiers (audit logs, log streaming, SSO, RBAC), hitting small teams at audit time | Strong: n8n forum thread with staff confirmation; Confluent docs; Zapier/Workato tiering | [n8n](https://community.n8n.io/t/pro-version-with-user-activity-logs-urgent/135551), [Confluent](https://docs.confluent.io/cloud/current/monitoring/audit-logging/cloud-audit-log-concepts.html) | **Unsolved.** No third party reconstructs audit/access evidence for lower tiers of integration tools |
| 2 | Price too high and rising, especially for small use cases | Strong: Wiz, Vault, Salt, Kong Konnect, MuleSoft, Vanta/Drata | [PeerSpot Wiz](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz), [PeerSpot Vault](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons) | Partly (Aikido, Prowler at the low end for cloud); not for the integration layer |
| 3 | Alert volume / false positives requiring tuning before developers can see them | Strong: Wiz, Prisma, GitGuardian, Wallarm, Cequence | [PeerSpot Prisma](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons) | Partly; every vendor claims it, reviewers still complain |
| 4 | Remediation workflow and ownership left to the customer; backlogs persist | Strong: three Wiz reviewers across 2023-2026; Prisma asks for auto-fix | [PeerSpot Wiz](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz) | **Largely unsolved**, especially for teams with no ticketing/ownership process |
| 5 | Complexity and steep learning curve; needs security expertise to operate | Strong: Vault, Kong, Prisma, Cequence, Wallarm | [PeerSpot Vault](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons), [Kong reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-qwksr2wun4awo) | Partly |
| 6 | Tools built for enterprises fit small environments badly ("more infrastructure than necessary", "not the best for smaller environments") | Strong: Salt, Kong, Vault, Scrut CEO | [PeerSpot Salt](https://www.peerspot.com/products/salt-security-pros-and-cons) | **Unsolved for integration layer** |
| 7 | Contract lock-in, auto-renewal, add-on and per-framework fees | Moderate: second-hand Reddit via review site; vendor contract terms | [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/) | Unsolved by incumbents; a pricing choice, not a technical one |
| 8 | Platform bought, still "not a complete view"; cannot consolidate tools | Moderate: three Wiz reviewers | [PeerSpot Wiz](https://www.peerspot.com/questions/what-advice-do-you-have-for-others-considering-wiz) | **Unsolved** for brokers/gateways/iPaaS (my inference) |
| 9 | Cannot tell who owns a secret/credential | Moderate: one strong verbatim (Vault SRE) plus industry-group material | [PeerSpot Vault](https://www.peerspot.com/products/hashicorp-vault-pros-and-cons) | Claimed by NHI vendors for cloud/SaaS; not for broker users, gateway consumers, iPaaS connections |
| 10 | Open-source edition withdrawn or starved (Kong free mode ended, silence from maintainers) | Moderate: forum thread, changelog quote | [Kong Nation](https://discuss.konghq.com/t/is-opensource-support-for-kong-ceased/13529) | **Unsolved**; stranded OSS users have no security tooling |
| 11 | Compliance automation stops at the connector boundary; manual evidence for everything else | Moderate: review-site analysis, buyer question on r/SaaS | [soc2auditors.org](https://soc2auditors.org/insights/vanta-review/) | **Unsolved** for integration-layer systems |
| 12 | Usage-based pricing is hard to forecast (per API, per call, per task, per GB) | Moderate: Salt, Kong, Boomi, Workato, Zapier, Confluent | [Kong reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-qwksr2wun4awo) | Unsolved; flat pricing would differentiate |
| 13 | Short audit log retention (Confluent seven days) and logs missing on entry tier | Moderate: vendor docs only, no user complaint found | [Confluent docs](https://docs.confluent.io/cloud/current/monitoring/audit-logging/cloud-audit-log-concepts.html) | **Unsolved** unless customer builds a pipeline |
| 14 | Findings not proven exploitable; users want proof before acting | Thin: one Prisma reviewer, vendor essays | [PeerSpot Prisma](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons) | Partly (attack-path tools); not for integration layer |
| 15 | Mandatory SaaS control plane / metadata leaving the environment is a dealbreaker for some | Thin: one Kong Konnect reviewer (Oct 2026) | [Kong reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-qwksr2wun4awo) | Depends on vendor |
| 16 | Rotation breaks production because consumers of a credential are unknown | Thin as user voice; widely asserted by industry group and vendors | [NHIMG](https://nhimg.org/faq/what-breaks-when-secret-rotation-is-not-tied-to-ownership-review/) | **Unsolved** for integration-layer credentials (my inference) |
| 17 | Checkbox compliance: paperwork without risk reduction | Thin: vendor CEO, second-hand reviews | [Help Net Security](https://www.helpnetsecurity.com/2025/08/05/aayush-choudhury-scrut-automation-lean-security-teams/) | Unsolved; structural to the category |
| 18 | Reporting weak or not shareable with leadership/auditors | Thin and mostly older: Wiz CISO 2024, Prisma AVP 2024 | [PeerSpot Prisma](https://www.peerspot.com/products/prisma-cloud-by-palo-alto-networks-pros-and-cons) | Partly |
| 19 | Small teams want plain-English, prioritised "fix this first" output | Thin as user voice; vendor founders describe it | [DEV Community](https://dev.to/wael_matoussi/the-problem-with-security-scanners-isnt-the-scanning-5cgl) | Partly (Aikido for code/cloud); not for integration layer |

### Inferences
Feature directions these pains suggest for VectaSec (inference, for the report writer to weigh):
- **Audit trail without the enterprise tier** (pains 1, 13): poll configuration and credentials on a schedule and keep a diff history of workflows, ACLs, routes, plugins and connections for n8n below Enterprise, Confluent Basic, Kong OSS, Zapier below Team. Output a "who has access and what changed" report an IT reviewer will accept. This is the most directly evidenced unmet need.
- **Stranded-OSS safety net** (pain 10): explicit support for Kong OSS 3.9.x and community-edition tools, with version/CVE exposure and compensating-control guidance.
- **Credential ownership and consumer map before rotation** (pains 9, 16): for each broker user, gateway consumer key or iPaaS connection, show last-seen usage and every consumer, then a guided rotate-and-verify. Pitch on the verified ownership quote, not on outage stories.
- **Evidence for systems Vanta/Drata cannot see** (pain 11): already built as an evidence push; lead with it.
- **Three findings, not three hundred** (pains 3, 4, 19): default view is the top few items with a plain-English consequence, owner, fix and Verify. Never show a count as the headline.
- **Flat, month-to-month pricing with no per-API/per-framework meter** (pains 2, 7, 12): a commercial feature, but the most repeated complaint in the whole set.
- **Local scan option / explicit data-leaves-your-environment statement** (pain 15).
- **Shareable one-page posture summary** for customer security questionnaires and leadership (pain 18).

### Gaps
- The ranking leans on PeerSpot because it was the one large review site that could be opened; G2 and Gartner Peer Insights "dislike" sections were only visible as search snippets, and Reddit/HN/Blind not at all. A manual pass on r/cybersecurity, r/devops, r/apachekafka, r/n8n, r/soc2 and r/msp is the highest-value follow-up, particularly for questions 6 and 7.
- No verified complaint data for: Orca, Lacework/FortiCNAPP, Prowler, Aikido, Datadog Cloud Security, Traceable/Harness, Akto, 42Crunch, Oasis, Token Security, Clutch, Aembit, Akeyless, Secureframe, Sprinto, Conduktor, Apigee, Azure APIM.
- Dollar figures quoted from vendor/competitor blogs (MuleSoft $400K+, Workato $30K-80K, CSPM $500-2,000/month, Vault ~$450/month, Orca ~$36K+/yr) are unverified and should be presented as such or omitted.
- "Unsolved by any vendor" judgements are based on the absence of evidence in this pass plus the earlier feature report's scope; they were not checked against every competitor's current roadmap.
