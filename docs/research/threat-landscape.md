# VectaSec Threat Landscape Research

**Compiled:** 2026-07-17
**Purpose:** Ground VectaSec's positioning and demo narrative in verified, citable real-world incidents and data.

---

## How to read this document

Every claim carries an evidence tag. Do not use a claim in a pitch deck, demo, or marketing asset without checking its tag first.

| Tag | Meaning |
|---|---|
| **[VERIFIED]** | Confirmed in a primary source: the affected vendor's own disclosure, an incident responder's technical report, NVD, or CISA. |
| **[REPORTED]** | Consistently reported by credible security press, but not traceable to a primary technical source. Directionally reliable; treat exact figures as soft. |
| **[VENDOR CLAIM]** | Published by a company that sells a product in this category. May be a survey of opinions rather than measurement. Attribute explicitly, never present as neutral fact. |
| **[VENDOR TELEMETRY]** | Published by a vendor, but derived from measurement of real systems rather than opinion surveys. More credible than a survey; still has selection bias. |
| **[UNVERIFIED]** | Circulating claim that could not be confirmed. Do not use. |
| **[FABRICATED]** | Actively checked and found to be false. Do not use. Flagged here so we do not re-ingest it later. |

**Standing rule for VectaSec:** we are a security posture vendor. If we cite unverifiable vendor statistics to sell a security product, we are doing the thing we criticize. Prefer incident facts and measured telemetry over survey-based ratios.

---

## 1. The Salesloft Drift OAuth breach (2025)

The single most important incident for VectaSec's positioning. An integration-layer compromise, with no vulnerability in any of the victim organizations' own systems, that reached 700+ enterprises including most of the major security vendors.

### 1.1 Timeline [VERIFIED]

Primary source: Google Threat Intelligence Group (GTIG) / Mandiant advisory, first published 2025-08-26, updated 2025-08-28.

| Date | Event |
|---|---|
| **Mar–Jun 2025** | Actor (UNC6395) accesses the Salesloft GitHub account. Downloads content from multiple repositories, adds a guest user, establishes workflows. [REPORTED — reconstructed in later reporting from Salesloft/Mandiant's own investigation summary; the original GTIG advisory does not carry this detail] |
| **(subsequent)** | Actor pivots to Drift's AWS environment and steals OAuth tokens for Drift customers' integrations. [REPORTED] |
| **2025-08-08 → 08-18** | Active data theft campaign against Salesforce instances via stolen Drift OAuth tokens. [VERIFIED — GTIG] |
| **2025-08-09** | Actor accesses Google Workspace email accounts via the compromised "Drift Email" integration. GTIG describes a "very small number" of accounts. [VERIFIED — GTIG] |
| **2025-08-09** | (Cloudflare-specific) GRUB1 conducts recon, validating a stolen API token using TruffleHog. [VERIFIED — Cloudflare] |
| **2025-08-12 → 08-14** | (Cloudflare-specific) Actor accesses Cloudflare's Salesforce tenant; object enumeration, schema discovery. [VERIFIED — Cloudflare] |
| **2025-08-16** | (Cloudflare-specific) Final "dry run" query to confirm dataset size. [VERIFIED — Cloudflare] |
| **2025-08-17** | (Cloudflare-specific) Exfiltration executed in **just over three minutes** via Salesforce Bulk API 2.0, followed by attempted log deletion. [VERIFIED — Cloudflare] |
| **2025-08-20** | Salesloft + Salesforce revoke **all** active access and refresh tokens for the Drift application. Drift removed from Salesforce AppExchange. [VERIFIED] |
| **2025-08-23** | Salesforce and Salesloft notify Cloudflare. [VERIFIED — Cloudflare] |
| **2025-08-26** | GTIG issues public advisory. [VERIFIED] |
| **2025-08-28** | GTIG update: scope is **not** limited to Salesforce. Google revokes impacted OAuth tokens and disables the Google Workspace–Drift integration. [VERIFIED] |
| **2025-09-02** | Cloudflare formally notifies impacted customers. [VERIFIED — Cloudflare] |

**The 2025-08-28 GTIG escalation is the line to quote.** Verbatim:

> "Based on new information identified by GTIG, the scope of this compromise is not exclusive to the Salesforce integration with Salesloft Drift and impacts other integrations. We now advise all Salesloft Drift customers to treat any and all authentication tokens stored in or connected to the Drift platform as potentially compromised."

This is exactly VectaSec's thesis stated by Google: **the blast radius of an integration compromise is every token that integration holds, not the one system you thought about.**

### 1.2 How the OAuth tokens were abused [VERIFIED]

The tokens were used as intended — that is the point. No exploit, no MFA bypass, no vulnerability. The actor authenticated as a legitimate, pre-authorized third-party application.

Mechanics documented by GTIG:

1. **Reconnaissance via count queries** to size the target before exfiltrating:
   ```sql
   SELECT COUNT() FROM Account;
   SELECT COUNT() FROM Opportunity;
   SELECT COUNT() FROM User;
   SELECT COUNT() FROM Case;
   ```

2. **Bulk extraction via SOQL**, e.g.:
   ```sql
   SELECT Id, Username, Email, FirstName, LastName, Name, Title, CompanyName,
   Department, Division, Phone, MobilePhone, IsActive, LastLoginDate,
   CreatedDate, LastModifiedDate, TimeZoneSidKey, LocaleSidKey,
   LanguageLocaleKey, EmailEncodingKey
   FROM User WHERE IsActive = true
   ORDER BY LastLoginDate DESC NULLS LAST LIMIT 20
   ```
   ```sql
   SELECT Id, IsDeleted, MasterRecordId, CaseNumber <...> FROM Case LIMIT 10000
   ```

3. **Bulk API 2.0 for the actual exfiltration** — Cloudflare's data left in just over three minutes. [VERIFIED — Cloudflare]

4. **Anti-forensics:** actor deleted query jobs. GTIG notes logs remained intact, so the deletion failed to hide the activity. [VERIFIED]

5. **Infrastructure:** a mix of commercial hosting and Tor exit nodes. [VERIFIED]

**IOCs — user-agent strings** [VERIFIED — GTIG]:
- `Salesforce-Multi-Org-Fetcher/1.0`
- `Salesforce-CLI/1.0`
- `python-requests/2.32.4`
- `Python/3.11 aiohttp/3.12.15`

**IOCs — non-Tor infrastructure** [VERIFIED — GTIG]:
- `208.68.36.90` (DigitalOcean)
- `44.215.108.109` (AWS)

Plus ~20 Tor exit nodes including `185.220.101.33/133/143/164/167/169/180/185`, `192.42.116.20/179`, `194.15.36.117`, `195.47.238.83/178`, `154.41.95.2`, `176.65.149.100`, `179.43.159.198`, `185.130.47.58`, `185.207.107.130`. GTIG advises searching for **any** Tor exit node activity, not just the listed IPs.

### 1.3 What the actor was actually after [VERIFIED]

GTIG's assessment, verbatim:

> "Primary intent of the threat actor is to harvest credentials. After the data was exfiltrated, the actor searched through the data to look for secrets that could be potentially used to compromise victim environments."

Specifically searched-for patterns:
- **AWS access keys** — the `AKIA` prefix
- **Snowflake credentials** — strings `Snowflake` / `snowflakecomputing.com`
- Generic `password`, `secret`, `key`
- Organization-specific VPN and SSO login URLs

**The narrative that matters:** this was a *credential harvesting operation staged through a CRM*. Support case text is a secrets store nobody treats as one. Customers paste API keys into support tickets. The Salesforce case object became a credential database, and an OAuth token to a chatbot vendor was the key to it.

**Cloudflare's own numbers** [VERIFIED — Cloudflare]: **104 Cloudflare API tokens** were found exposed in Salesforce support case text fields. All rotated; no suspicious activity observed on them. Cloudflare's stated lesson, verbatim:

> "We are responsible for the tools that we select and when those tools are compromised by sophisticated threat actors, we own the consequences."

### 1.4 Scale [REPORTED — with an important caveat]

**GTIG never published a victim count.** The advisory says "widespread" and "numerous corporate Salesforce instances."

The **700+ organizations** figure is [REPORTED] — widely attributed to a Google estimate in secondary reporting, but not present in the public GTIG advisory text. Use it as "more than 700 organizations, per reporting on Google's assessment," not as "Google said 700."

Named victims who publicly disclosed [VERIFIED via their own statements or direct reporting]: **Cloudflare, Zscaler, Palo Alto Networks, PagerDuty, Proofpoint, SpyCloud, Tanium, Google.**

**Do not use** the ShinyHunters claim of **1.5 billion records across 760 companies**. [UNVERIFIED] That is a threat-actor claim made to BleepingComputer. Actor-supplied numbers are marketing too. Additionally, a Telegram channel calling itself "Scattered LAPSUS$ Hunters 4.0" claimed responsibility; investigators found no credible evidence supporting the claim and noted it merely repeated open-source information. [REPORTED]

Attribution naming: Google tracks the cluster as **UNC6395**; Cloudflare's Cloudforce One tracks it as **GRUB1**. [VERIFIED]

### 1.5 Root cause [VERIFIED]

There was **no vulnerability in Salesforce**, and **no vulnerability in any victim's environment**. GTIG is explicit that the core Salesforce platform was not at fault.

The causal chain:
1. Salesloft's GitHub account was compromised. [REPORTED]
2. That access enabled a pivot into Drift's AWS environment. [REPORTED]
3. Drift's AWS environment stored **OAuth access and refresh tokens for every customer's connected integrations** — a centralized token vault. [VERIFIED, by implication of the mass revocation on 08-20]
4. Those tokens were long-lived, broadly scoped, and not IP-restricted.
5. Refresh tokens meant stolen material stayed valid indefinitely without re-consent.

**The structural failure is aggregation.** A chatbot vendor became a single point of compromise for 700+ enterprises' CRM data because the integration model concentrates every customer's tokens in one vendor's cloud, and because those tokens carry far more authority than the chatbot's function requires.

### 1.6 What a posture tool could have detected beforehand

This is VectaSec's demo spine. Each item is grounded in the incident facts above, not aspirational.

| Detectable condition | Evidence it mattered |
|---|---|
| **Over-scoped connected app** — Drift held scopes far beyond a chat widget's needs, including bulk read of Case/Account/User/Opportunity. | GTIG's hardening advice leads with "Review and Restrict Connected App Scopes… avoid `full` access." Least privilege would have shrunk the exfiltrated dataset. |
| **No IP restriction on the connected app** — actor connected from Tor exit nodes and DigitalOcean/AWS hosts. | GTIG advises setting "IP Relaxation" to "Enforce IP restrictions" and defining Login IP Ranges. Drift's traffic has a knowable egress range; Tor traffic on that token is definitionally anomalous. This alone would have blocked the campaign. |
| **`API Enabled` granted broadly via profiles** rather than narrowly via permission sets. | GTIG advises removing "API Enabled" from profiles and granting only via Permission Sets. |
| **Non-expiring refresh tokens / no session timeout** — stolen tokens stayed valid until mass revocation. | GTIG advises configuring Salesforce Session Settings for session timeout "to limit compromised session lifespan." |
| **Secrets sitting in CRM free-text fields** — the actual crown jewels. | Cloudflare found 104 live API tokens in case text. GTIG advises grepping Salesforce objects for `AKIA`, `Snowflake`, `password`, `secret`, `key`, and running TruffleHog. **A posture scan of case-object content would have found these before the attacker did.** |
| **Dormant/forgotten integrations still holding live tokens** — the "we thought it was unused" failure mode. | See Cloudflare/Atlassian (§3.2): four credentials survived rotation *because they were believed unused*. |
| **Token inventory + blast-radius mapping** — knowing which third parties hold which tokens against which systems. | GTIG's 08-28 escalation ("treat any and all authentication tokens stored in or connected to the Drift platform as potentially compromised") is unanswerable without an inventory. Every Drift customer had to ask "what did Drift have?" and most could not answer quickly. |

**The honest framing for the demo:** posture tooling would not have stopped Salesloft from being breached. It would have (a) reduced the scope of what the token could reach, (b) blocked Tor-origin API use via IP enforcement, (c) surfaced the 104 plaintext tokens in case text before exfiltration, and (d) answered "what is our blast radius?" in minutes instead of weeks. Claiming more than that is dishonest.

**Sources:**
- https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift (GTIG/Mandiant — primary)
- https://blog.cloudflare.com/response-to-salesloft-drift-incident/ (Cloudflare — primary, victim disclosure)
- https://www.bleepingcomputer.com/news/security/shinyhunters-claims-15-billion-salesforce-records-stolen-in-drift-hacks/ (actor claims — treat as unverified)
- https://cyberscoop.com/salesloft-drift-attacks-cloudflare-palo-alto-networks-zscaler/

---

## 2. Gainsight / Salesforce (2025) [VERIFIED]

The sequel — and the reason the "blast radius" argument is not hypothetical. **Gainsight was compromised using secrets stolen in the Drift breach.** One integration compromise seeded the next.

### 2.1 Facts

- **Window of unauthorized access:** 2025-10-23 → 2025-11-19. [VERIFIED — Salesforce]
- **2025-11-20:** Salesforce disables the connection between Gainsight-published applications and the Salesforce ecosystem after detecting "unusual activity." [VERIFIED]
- **Mechanism:** ShinyHunters obtained Gainsight OAuth tokens **via secrets stolen from Salesloft/Drift support case data**, then used them to issue refresh tokens for Salesforce instances linked to Gainsight. [REPORTED — consistent across CSO Online, The Register, Dark Reading, SecurityWeek]
- **Scale:** up to **285 Salesforce instances** linked to Gainsight allegedly affected; ShinyHunters claims **200+ companies**. [REPORTED — actor-influenced figure, soften it]
- **Resolution:** Salesforce has since re-enabled Gainsight integrations. Gainsight identified compromised customer tokens and notified impacted customers. [VERIFIED]

### 2.2 Why this matters more than the raw numbers

The Drift breach's *stolen support-case text* contained *Gainsight's OAuth credentials*. The secrets harvested in incident #1 were the initial access for incident #2. This is the compounding property of integration-layer compromise, and it is the strongest single argument for VectaSec's existence:

> An integration breach does not end when the tokens are revoked. It ends when every secret that transited that integration has been rotated — and nobody knows what those are.

### 2.3 Microsoft's synthesis (2026-07-13) [VERIFIED]

Microsoft Security published an analysis mapping a year of ShinyHunters activity into **three Salesforce attack paths**. Published **2026-07-13** — four days before this document. This is the most current authoritative framing available.

1. **Voice-phishing-driven OAuth consent abuse** — actors impersonate IT support and convince employees to authorize malicious connected apps disguised as legitimate Salesforce tools, granting "API calls on behalf of the victim user."
2. **SaaS supply chain compromise** — compromised third-party integration credentials give persistent access across many customer instances.
3. **Direct credential abuse** — stolen credentials from compromised platforms enable unauthorized API access.

Microsoft's timeline of the campaign:
- **Aug 2025** — Salesloft Drift credentials compromised; enabled access to "connection secrets used by downstream SaaS applications."
- **Nov 2025** — Gainsight-published applications targeted for their trusted external connections.
- **Jun 2026** — **Klue** platform incident provided Salesforce access credentials. Microsoft tracks this as **Storm-3138**.

**The Klue incident (June 2026) is a third iteration of the same pattern, four weeks before this writing.** The integration-layer attack path is not a 2025 story that has been fixed. It is the current, live, repeatedly-successful playbook. Worth a dedicated follow-up research pass.

Microsoft's key sentence: integrations allow "threat actors to leverage trusted external connections to maintain persistent API access."

**Sources:**
- https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/ (primary, current)
- https://www.csoonline.com/article/4094506/oauth-token-compromise-hits-salesforce-ecosystem-again-gainsight-impacted.html
- https://www.theregister.com/2025/11/21/shinyhunters_salesforce_gainsight_breach/
- https://thehackernews.com/2026/07/microsoft-maps-year-long-shinyhunters.html

---

## 3. Other integration-layer / NHI incidents

### 3.1 Okta support system breach (Sept–Oct 2023) [VERIFIED]

Primary source: Okta's own root-cause post.

- **Window:** 2023-09-28 → 2023-10-17.
- **Scale:** files accessed for **134 Okta customers** — Okta states "less than 1% of Okta customers."
- **What leaked:** HAR files uploaded to support tickets, containing **live session tokens**.
- **Downstream:** session tokens used to hijack Okta sessions of **5 customers**. Three self-disclosed: **1Password, BeyondTrust, Cloudflare**.
- **Root cause — the detail that matters:** the attacker used a **service account stored in the support system itself**, which held permissions to view and update support cases. An Okta employee had signed into a **personal Google profile on their work laptop** and saved the service account credentials to that personal Google account. Compromise of the personal account yielded the service account.
- **Detection:** BeyondTrust handed Okta a suspicious IP on 2023-10-13; that indicator is what let Okta find the rest of the file-access events. **A customer detected Okta's breach before Okta did.**
- **Remediation:** service account disabled; Chrome Enterprise policy applied to block personal-profile sign-in on managed laptops.

**VectaSec relevance:** a **non-human identity** with standing access to a data store full of customer secrets, credentialed into a browser profile, invisible to the org's identity posture. Same shape as Drift: support tickets are a secrets store, and a service account was the key.

**Sources:**
- https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/ (primary)
- https://krebsonsecurity.com/2023/10/hackers-stole-access-tokens-from-oktas-support-unit/
- https://thehackernews.com/2023/11/oktas-recent-customer-support-data.html

### 3.2 Cloudflare / Atlassian — Thanksgiving 2023 [VERIFIED]

Primary source: Cloudflare's own blog. The best-documented "unrotated NHI credential" case in existence, and the highest-value story for VectaSec because Cloudflare published exact numbers.

**Timeline:**
| Date | Event |
|---|---|
| 2023-10-18 | Okta compromise (see §3.1) |
| 2023-11-14 → 17 | Threat actor reconnaissance |
| 2023-11-15 | Atlassian access achieved |
| 2023-11-22 | Persistence established via **Sliver** implant |
| 2023-11-23 16:00 | Detected; remediation begins |
| 2023-11-24 10:44 | Last threat actor activity |

**Root cause — the number to lead with:** Cloudflare rotated **thousands** of credentials after the Okta breach, but **4 were missed**:
1. One **Moveworks service token** — Atlassian remote access
2. A **Smartsheet service account** — administrative access to Jira
3. A **Bitbucket service account** — source code access
4. An **AWS account** (no access to sensitive data)

Cloudflare's own explanation, verbatim:

> "The one service token and three accounts were not rotated because mistakenly it was believed they were unused."

**Impact (Cloudflare's figures):**
- **36 Jira tickets** accessed (of 2,059,357 total)
- **202 wiki pages** accessed (of 194,100 total)
- **120 code repositories** viewed, **76 downloaded**
- Attacker read documentation on vulnerability management, MFA bypass, and network access
- **No customer data and no production network systems compromised**

**Response cost — the ROI slide:** Cloudflare declared "Code Red" and rotated **over 5,000 production credentials** and reimaged **4,893 systems** globally.

**VectaSec relevance — this is the money quote for the product.** Four dormant machine credentials, believed unused, defeated a competent security team's full credential rotation at one of the most security-mature companies on earth. The failure was **not knowing what they had**. That is an inventory problem, and inventory is exactly what a posture tool provides. If Cloudflare cannot manually enumerate its own NHI credentials accurately, nobody can.

**Sources:**
- https://blog.cloudflare.com/thanksgiving-2023-security-incident/ (primary)
- https://www.theregister.com/2024/02/02/cloudflare_okta_atlassian/
- https://www.infosecurity-magazine.com/news/cloudflare-breach-stolen-okta/

### 3.3 Codecov Bash Uploader (2021) [VERIFIED]

The original CI/CD secrets-harvesting supply chain attack. Structurally identical to Drift: compromise one vendor, harvest every customer's secrets.

- **2021-01-31:** Attacker extracts a credential due to **an error in Codecov's Docker image creation process** that left the credential retrievable from the published image. Uses it to modify the Bash Uploader script.
- **~2 months undetected.** The modified uploader exfiltrated **all environment variables from customers' CI runs** to an attacker IP — i.e. cloud credentials, API tokens, deployment keys, signing keys, service-account passwords.
- **2021-04-01:** Detected by **a customer**, not Codecov — they compared the SHA-256 of the downloaded uploader against the checksum Codecov published on GitHub and found a mismatch.
- **Downstream:** **HashiCorp** disclosed its **GPG signing key** was exposed and rotated it. Twilio, Rapid7 and others confirmed impact.

**VectaSec relevance:** (a) a secret baked into a container image — a scannable posture condition; (b) CI environment variables are an unmanaged NHI credential store; (c) detection came from an integrity check a customer ran, which is a posture control, not a detection control.

**Sources:**
- https://about.codecov.io/apr-2021-post-mortem/ (primary)
- https://about.codecov.io/security-update/ (primary)
- https://blog.gitguardian.com/codecov-supply-chain-breach/
- https://www.bleepingcomputer.com/news/security/hashicorp-is-the-latest-victim-of-codecov-supply-chain-attack/

### 3.4 MOVEit / CL0P (2023) [VERIFIED for mechanism, REPORTED for scale]

- **From 2023-05-27:** CL0P (TA505) mass-exploits **CVE-2023-34362**, a zero-day SQL injection in Progress MOVEit Transfer. [VERIFIED — CISA AA23-158A]
- **Mechanism:** internet-facing MOVEit Transfer web apps infected with the **LEMURLOOT** web shell, used to steal data from the underlying MOVEit databases. [VERIFIED — CISA]
- **Scale:** **2,700+ organizations**, **95+ million individuals**. [REPORTED — the canonical tracking is Emsisoft's, not a primary vendor disclosure. Widely accepted; cite as "per Emsisoft's tracking."]

**VectaSec relevance — use with care.** MOVEit is a *vulnerability exploitation* story, not an OAuth/NHI story. Its honest use is as the reference point for **supply-chain blast radius**: one product's flaw cascaded to thousands of downstream orgs that had no relationship with the attacker. It supports "your exposure is your vendors' exposure." It does **not** support any claim about token posture. Do not blur these.

**Sources:**
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a (primary)
- https://www.rapid7.com/blog/post/2023/06/14/etr-cve-2023-34362-moveit-vulnerability-timeline-of-events/
- https://en.wikipedia.org/wiki/2023_MOVEit_data_breach

### 3.5 Snowflake customer instances / UNC5537 (2024) [VERIFIED]

Primary source: Mandiant/GTIG.

- **Scale:** ~**165 Snowflake customer organizations**. Named victims include Ticketmaster/Live Nation, Santander, AT&T, Advance Auto Parts, Pure Storage, Neiman Marcus.
- **Timeline:** exfiltration began in earnest **April 2024**, ran through **June 2024**. Coordinated disclosure by Snowflake, Mandiant and CrowdStrike in late May 2024.
- **Root cause — explicitly not a Snowflake breach.** Mandiant found **no evidence** that access stemmed from a compromise of Snowflake's own environment. Every incident traced to **compromised customer credentials**.
- **The three conditions that made it work:**
  1. Credentials stolen via **infostealer malware on non-Snowflake systems**, the majority from **historical infostealer infections dating back as far as 2020**.
  2. Affected instances **did not require MFA**.
  3. In many cases credentials **had not been rotated for as long as four years**.

**VectaSec relevance — arguably the cleanest posture story in the set.** All three root-cause conditions are static, scannable posture facts, not behavioral detections: *is MFA enforced on this identity? how old is this credential? is it network-restricted?* Nothing about this attack was sophisticated. It was 100% preventable by posture hygiene, and it hit 165 enterprises. Mandiant tracks UNC5537 as a financially motivated actor that extorts victims.

**Sources:**
- https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion (primary)
- https://www.securityweek.com/snowflake-attacks-mandiant-links-data-breaches-to-infostealer-infections/
- https://www.computerweekly.com/news/366588696/More-than-160-Snowflake-customers-hit-in-targeted-data-theft-spree

### 3.6 2026 incidents involving MCP servers / agent tooling

- **Klue (June 2026)** — Microsoft-attributed (**Storm-3138**); the Klue platform incident provided Salesforce access credentials. [VERIFIED — Microsoft, 2026-07-13] Detail is thin in Microsoft's post; **flagged for a dedicated follow-up research pass.**
- **Shai-Hulud 2** — a supply-chain attack whose dataset GitGuardian analyzed, covering **6,943 compromised machines**. [VENDOR TELEMETRY — GitGuardian, 2026-03-17] Referenced in passing in their report; **this incident is under-researched here and warrants its own pass.**
- **Active internet-wide scanning for MCP infrastructure** — see §5.2. [VERIFIED — SANS ISC]

**Honest status:** we have **no verified breach** in which an exposed MCP server was the confirmed initial access vector. We have verified *exposure* (Censys) and verified *adversary reconnaissance* (SANS ISC), which is a real and current pre-attack signal, but not a breach. **Do not imply an MCP breach has happened.** The accurate and still-strong claim is: *the exposure is measured, the scanning is measured, and the incident is a matter of time.* Overreaching here would be the exact vendor behavior this document exists to guard against.

---

## 4. Non-human identity statistics — read the fine print

This is the most marketing-polluted area in the whole document. Treat with maximum skepticism.

### 4.1 The 82:1 ratio [VENDOR CLAIM — survey of opinion, not measurement]

**The figure:** "There are 82 machine identities for every human in organizations worldwide."

**Who published it:** **CyberArk**, *2025 Identity Security Landscape*, published **2025-04-23**.

**Methodology:** conducted by market research firm **Vanson Bourne**; **2,600 cybersecurity decision-makers**; organizations of **500+ employees**; **20 countries** (Brazil, Canada, US, several European nations, UAE, Saudi Arabia, South Africa, Australia, India, Hong Kong, Israel, Japan, Singapore, Taiwan).

**The critical caveat:** this is a **questionnaire administered to security decision-makers**, not telemetry from real environments. The 82:1 figure is **what surveyed humans believe about their machine identity counts** — from the same population that, per the same report, largely does not have machine identity inventory tooling. A number about how many machine identities exist, sourced from people who by the report's own admission cannot see their machine identities, is self-undermining.

**CyberArk sells machine identity security products.** This ratio is the top-line statistic in the press release announcing that product line's expansion. That does not make it false. It makes it a marketing artifact.

**Related figures from the same survey** [all VENDOR CLAIM, same caveats]:
- **88%** of respondents say the definition of "privileged user" applies **solely to human identities** — while **42% of machine identities have privileged or sensitive access**. (Note: the 42% is itself survey-derived.)
- **61%** lack identity security controls for cloud infrastructure and workloads.
- **68%** lack identity security controls for AI.

**A separate CyberArk figure — "96 machines per human" in the financial sector** [VENDOR CLAIM] appears in a CyberArk blog on agentic AI. Same provenance problems, narrower cut.

**On the "45:1" figure:** searched for and **not found**. It does not appear in CyberArk's material. If it is circulating internally, it is likely a garbled recollection or a different vendor's number. [UNVERIFIED — do not use]

**Recommended usage:** *"CyberArk's 2025 survey of 2,600 security decision-makers reported a perceived ratio of 82 machine identities per human."* Attribute in the sentence itself. Never render it as "machine identities outnumber humans 82:1" without the attribution — that is laundering a survey into a fact.

**Better alternative:** lead with the **Cloudflare** number instead (§3.2). Cloudflare rotated **5,000+ production credentials** and reimaged **4,893 systems** in response to four missed machine credentials. That is a *measured* count from a *real* environment, published by the affected party, and it makes the NHI-scale point more powerfully than any survey ratio.

**Source:** https://www.cyberark.com/press/machine-identities-outnumber-humans-by-more-than-80-to-1-new-report-exposes-the-exponential-threats-of-fragmented-identity-security/

### 4.2 GitGuardian secrets sprawl [VENDOR TELEMETRY — measured, more credible]

*State of Secrets Sprawl 2026*, published **2026-03-17**. This is **telemetry** — automated detection across public GitHub commits and internal repositories — not a survey. Materially more credible than §4.1, though GitGuardian sells secrets detection and the sample is GitHub-centric.

- **28.65 million** new hardcoded secrets added to **public** GitHub commits in **2025** — **+34% YoY**, the largest single-year jump they have recorded.
- **Validity/revocation gap — the strongest stat in this document:** credentials leaked in **2022**, retested in **January 2026**, were **still valid at above 64%**. Nearly 70% were still valid when tested in 2025. **Roughly two-thirds of secrets leaked four years ago still work.** This is the empirical proof that secret rotation does not happen absent tooling — and it is measured, not surveyed.
- **1,275,105** leaked secrets tied to **AI services** detected in 2025 — **+81% YoY**. Includes **113,000 leaked DeepSeek API keys**.
- **LLM infrastructure** (orchestration, RAG, vector storage) secrets leaked **5× faster** than core model-provider secrets.
- **Claude Code-assisted commits** showed a **3.2%** secret-leak rate vs a **1.5%** baseline. (Report this one straight; it cuts against AI tooling and is therefore unlikely to be marketing spin.)
- **~32.2%** of internal repos contain at least one hardcoded secret vs **5.6%** of public repos — internal repos are ~**6×** more likely.
- **28%** of 2025 incidents originated **entirely outside source code** — Slack, Jira, Confluence. These were **13 percentage points more likely** to be rated critical.

**The 28% non-source-code figure directly corroborates the Drift and Okta incidents:** secrets live in collaboration and support tools, not just repos. Cloudflare's 104 API tokens in Salesforce case text is that statistic made concrete. **This pairing — GitGuardian's 28% plus Cloudflare's 104 — is the single strongest evidence chain in this document.** One is measured across the industry, the other is a named company's own disclosure, and they say the same thing.

**Sources:**
- https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/ (primary)
- https://www.gitguardian.com/state-of-secrets-sprawl-report-2026

### 4.3 Verizon DBIR — third-party breach involvement [REPORTED — vendor-published but methodologically respected]

The DBIR is vendor-published but is the closest thing to a neutral industry baseline, with a large disclosed dataset and published methodology. Still not peer-reviewed.

**2026 DBIR** (published **2026-05-19**, covering 2025 data):
- **48% of all breaches** involve third parties — a **60% jump** from the prior year. [VERIFIED — Verizon press release]
- **Vulnerability exploitation is now the #1 initial access vector at 31%**, surpassing stolen credentials **for the first time in 19 years**. [VERIFIED — Verizon]
- Only **23%** of third-party organizations fully remediated missing or improperly secured MFA on cloud accounts. [REPORTED — via secondary summaries of the full report; not in the press release]
- Weak password and permission misconfigurations took a **median of 8 months** to resolve 50% of findings. [REPORTED — same caveat]
- "The majority of high-profile cloud-based, third-party incidents in 2025 came down to insecure authentication — missing or misconfigured MFA, improper credential rotation — and lack of least-privilege enforcement." [REPORTED — same caveat]

**2025 DBIR** (for the YoY trend):
- Third-party involvement **doubled from 15% → 30%**. [VERIFIED — Verizon press release]
- Credential abuse: **22%** of breaches. Vulnerability exploitation: **20%** (+34% YoY). Ransomware in **44%** of breaches (+37% YoY).
- Dataset: **22,000+ security incidents**, including **12,195 confirmed data breaches**.
- **81%** of third-party-involved breaches involved "system intrusion." [REPORTED]

**The trend line is the asset: 15% → 30% → 48% over three consecutive DBIR editions.** Third-party involvement in breaches has more than tripled in two years, per the industry's most-cited dataset. That is VectaSec's market, measured by a party with no stake in our category.

**One honesty note for the pitch:** the 2026 DBIR finding that *vulnerability exploitation overtook stolen credentials* cuts slightly against a pure identity-posture narrative. Do not hide it. VectaSec scans both — exposed/unpatched middleware (§5, §6) **and** token posture. The DBIR finding argues for the breadth of our scope, not against our thesis. Present it as such.

**Sources:**
- https://www.verizon.com/about/news/breach-industry-wide-dbir-finds (2026, primary)
- https://www.verizon.com/about/news/2025-data-breach-investigations-report (2025, primary)
- https://www.verizon.com/business/resources/Td15/reports/2026-dbir-data-breach-investigations-report.pdf (2026 full report)

---

## 5. Real exposure data for the systems VectaSec scans

### 5.1 Exposed MCP servers [VERIFIED — Censys measurement]

**Censys**, published **2026-05-27**, data collection begun **2026-04-24**:

- **12,520 internet-accessible MCP services** across **8,758 unique IP addresses**, spanning **56 countries** and **425 autonomous systems** — as of **2026-04-28** (four days into collection).
- A **2026-05-06** update noted the dataset had grown to **over 21,000 servers**, though the report's analysis stayed on the April 24 data.
- **Protocol versions:** `2025-03-26` (latest) — 11,189 services (89.4%); `2024-11-05` (initial release) — 1,034 services (8.3%).
- **Geography:** US 3,057 services (39.7% of IP-hosted); China 950.
- **Hosting:** AWS (AS16509 + AS14618) 2,801 services (**22.4%**); Hetzner 567 (4.5%).
- **Implementations:** LangGraph 362; Spotlight MCP 343; LilyAnalyticsMCPServer 263.
- **Fingerprinting:** 48.3% of services unique; 42.6% shared identical toolsets with other deployments; 9.1% advertised no capabilities despite completing the MCP handshake.

**⚠️ CORRECTION — the "40% unauthenticated" figure is NOT from Censys. [UNVERIFIED]**

Multiple secondary sources (ChatForest, Medium, and others) attribute "~40% of MCP servers are unauthenticated" to the Censys report. **Censys did not publish that figure.** What Censys actually says is more careful:

> "at a minimum, the servers discussed throughout this blog were accessible without authentication"

— because their scanner successfully enumerated the endpoints. They also note the MCP protocol "does not require authentication or authorization (by default)."

**The correct reading is stronger than the fabricated one, and we should use it:** all **12,520** servers Censys enumerated were reachable **without authentication**, because enumeration succeeded. That is ~100% of the measured set being unauthenticated *to the extent of capability disclosure* — not 40%. Do not cite 40%; cite Censys's actual language and the 12,520 count.

**Censys's own methodological caveat — quote it if challenged:**
> "never attempted to execute any functionality on these servers; we simply scanned the resources the MCP protocol provides"

and: "a server may advertise a tool named `shell_exec`, but that alone does not prove the underlying implementation will actually execute a command." **Advertised capability ≠ exploitable capability.** Any VectaSec claim about what those servers *could do* must respect this line.

**Other MCP exposure claims — all [UNVERIFIED], do not use:**
- "106 zero-days found across 39,884 MCP repositories" / "VIPER-MCP swept ~40,000 repos, produced 67 CVEs" — sourced to a blog aggregator (ChatForest) and an Adversa AI post; the underlying academic work was not located or verified.
- "8,000+ MCP servers exposed" (Medium) — inconsistent with Censys's own numbers and lower than them; provenance unclear.
- "tripled to 1,467 in separate scans" — incoherent alongside the Censys figures; likely a garbled secondary summary.

**Sources:**
- https://censys.com/blog/mcp-servers-on-the-internet/ (primary, measured)
- https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/update-on-exposed-mcp-servers-the-threat-widens-to-the-cloud (secondary, unverified specifics)

### 5.2 Active adversary scanning for MCP / AI infrastructure [VERIFIED]

**SANS Internet Storm Center**, diary #33150, author **Manuel Humberto Santander Peláez**, published **2026-07-13** — four days before this document. Analysis of **14 days of server logs from a single low-traffic host**:

- MCP protocol activity and AI-assistant reconnaissance together comprised roughly **200 requests**.
- MCP protocol handshake probes came from **49 distinct source IPs** — indicating a coordinated campaign, not isolated probing.

**Four target categories observed:**
1. **Live MCP servers** — well-formed **JSON-RPC 2.0 `initialize` calls to `POST /mcp`**, attempting valid MCP handshakes.
2. **AI assistant configuration files** — probes for **`.claude/mcp.json`** and **`.cursor/mcp.json`**, which contain server endpoints and potential API keys.
3. **Unauthenticated LLM endpoints** — `GET /v1/models` and `/api/tags`.
4. **Cloud credential theft** — SSRF against GCP/AWS metadata services, plus credential-file harvesting.

**Tradecraft note:** the use of **HEAD requests** to test credential-file existence is, per the author, "an efficiency optimization you build when scanning a very large number of hosts" — evidence of mature, large-scale infrastructure rather than experimental probing.

**Why this is the strongest MCP data point we have:** it is a **low-traffic single host** seeing **49 distinct sources** probing for MCP in a two-week window. That implies indiscriminate internet-wide sweeps. Adversaries are enumerating MCP infrastructure and AI assistant credential files *right now*, and `.claude/mcp.json` is an explicit target. The scanning is verified even though no resulting breach is.

**Caveat to state honestly:** n=1 host, 14 days, ~200 requests. It establishes *that* the scanning is happening and is distributed; it does **not** support any quantitative claim about global scan volume.

**Source:** https://isc.sans.edu/diary/33150 (primary)

### 5.3 Exposed Kafka / RabbitMQ / Kong — **RESEARCH GAP**

**We could not obtain credible, current, empirical exposure counts for these systems.** Recording this honestly rather than filling it with a plausible-sounding number.

**What is verified:**
- **Kafka has no authentication on port 9092 by default.** Port 9092 is the default PLAINTEXT listener. Kubernetes deployments (Strimzi Kafka Operator, Bitnami Kafka Helm chart) expose broker listeners on 9092 by default. [VERIFIED — Apache Kafka docs] This is a *configuration fact*, and a strong one: the default is unauthenticated, so exposure equals compromise.
- **RabbitMQ management interface (port 15672) should never be internet-exposed.** Miggo's guidance on CVE-2026-57219: if the management interface was ever reachable by an untrusted network, **the OAuth client secret should be assumed leaked**. [VERIFIED — see §6.2]
- **Shadowserver runs an "Accessible AMQP Report"** scanning **port 5672/TCP**, collecting 28 fields including AMQP version, supported capabilities, product identification (RabbitMQ and platform details), and **authentication mechanisms**. Shadowserver notes "many instances on the Internet are configured for cleartext authentication and message sharing." They scan the entire IPv4 internet **42 times per day**. [VERIFIED — Shadowserver]

**Why the gap:** Shadowserver's dashboard is JS-rendered and its statistics API requires authentication; direct queries returned no data. Shodan/Censys queries for Kafka and Kong exposure counts require authenticated API access not available here.

**Recommended next step (do this before any claim ships):** obtain a **Shadowserver report subscription** (free for network owners) or a **Censys/Shodan API key**, and pull first-party counts for ports **9092** (Kafka), **5672/15672** (RabbitMQ/AMQP), and **8000/8001/8443/8444** (Kong admin API). **Kong's admin API on 8001 exposed without auth is a full gateway takeover** and is a well-known misconfiguration — but we need a real count before saying so publicly. Numbers we generate from our own scanner would be first-party VectaSec telemetry and far more defensible than citing anyone else.

**Sources that were checked and did not yield counts:**
- https://www.shadowserver.org/what-we-do/network-reporting/accessible-amqp-report/
- https://kafka.apache.org/43/security/listener-configuration/

**⚠️ Rejected sources:**
- **CyberLeveling "EU internet exposure research 2026"** — claims 2.85M exposed services across 14 protocols in the EU (scan window 2026-03-01→03-07). **Returned HTTP 403 on direct fetch; could not verify methodology or authorship.** [UNVERIFIED — do not cite]
- The "80,000+ unauthenticated Mosquitto MQTT brokers" figure surfaced in the same search — same provenance problem, and MQTT is out of scope anyway. [UNVERIFIED]

### 5.4 Default credential prevalence — **RESEARCH GAP**

No credible current published research on default-credential prevalence for Kafka/RabbitMQ/Kong was located. **RabbitMQ's `guest`/`guest` default is real and well-known** (and is restricted to localhost by default in modern versions — a nuance we must get right rather than overstate). Any claim about how often it is found exposed needs first-party scanning data. **Do not assert a prevalence figure without it.**

---

## 6. CVEs of note: Kafka, RabbitMQ, Kong, Istio, MCP (2025–2026)

### 6.1 Apache Kafka

**CVE-2025-27819** [VERIFIED — NVD]
- **CVSS v3.1: 7.5 HIGH** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE-502** — Deserialization of Untrusted Data
- **Affected:** Apache Kafka **2.0.0 → 3.3.2**
- **Fixed:** 3.4.0+ (system property available to disable the module); **3.9.1 / 4.0.0+** (vulnerable modules disabled by default)
- **Published:** 2025-06-10 | **Last modified:** 2026-06-17
- **What it is:** extends **CVE-2023-25194**'s SASL JAAS `JndiLoginModule` RCE/DoS attack **from the Kafka Connect API to Kafka brokers themselves**. Requires cluster connection and **AlterConfigs** permission.
- **VectaSec relevance:** the precondition is a *permission*, not a network position. An over-privileged Kafka principal with AlterConfigs is a posture finding.

**CVE-2025-27817** [VERIFIED via NVD listing; details from secondary]
- **Severity: HIGH.** Java Apache Kafka Client **3.1.0 → 3.9.0**.
- Insecure handling of OAuth configuration parameters — `sasl.oauthbearer.token.endpoint.url` and `sasl.oauthbearer.jwks.endpoint.url`. An attacker able to control these can **read local files / environment variables (SSRF + file disclosure)** or force requests to arbitrary endpoints.
- **Note:** a Seal Security post argues the fix is incomplete in 3.9.1. [VENDOR CLAIM — Seal sells patching; unverified, flagged for follow-up]
- **VectaSec relevance:** an **OAuth misconfiguration in a message broker client** that leaks environment variables — i.e. leaks other credentials. Directly on-thesis.

**CVE-2025-27818** [VERIFIED — exists in NVD/Red Hat tracking; details not fully retrieved. **Follow-up needed.**]

**Also noted:** KAFKA-20043 references `kafka-clients` exposure to **CVE-2025-12183** and **CVE-2025-66566**. [REPORTED — ASF Jira; not independently verified here. **Follow-up needed.**]

**Mitigation of note:** where patching is not immediate, **JMX ports must be firewalled to localhost or VPN**. Exposed JMX is a scannable posture condition.

**Sources:** https://nvd.nist.gov/vuln/detail/CVE-2025-27819 · https://kafka.apache.org/cve-list · https://issues.apache.org/jira/browse/KAFKA-20043

### 6.2 RabbitMQ — **the most on-thesis CVE in this document** [VERIFIED — NVD]

Discovered by **Miggo**, published **2026-07-10** (NVD) / **2026-07-13** (Miggo writeup). **One week old at time of writing — this is current, and it is the ideal demo case.**

**CVE-2026-57219 — OAuth client secret disclosure, unauthenticated**
- **CVSS v3.1: 7.5 HIGH** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
- **CVSS v4.0: 8.7 HIGH**
- **CWE-522** (Inadequately Protected Credentials) + **CWE-200** (Information Exposure)
- **Affected:** RabbitMQ Server **3.13.0 → <3.13.15**, **4.0.0 → <4.0.21**, **4.1.0 → <4.1.11**, **4.2.0 → <4.2.6**
- **Fixed:** **4.3.0, 4.2.6, 4.1.11, 4.0.20/4.0.21, 3.13.15** (note: Miggo's post says 4.0.20; NVD's range implies <4.0.21 — **use NVD**)
- **Authentication required: NO**
- **Mechanism:** an obsolete management endpoint, **`GET /api/auth`**, returns the broker's confidential **OAuth client secret to any unauthenticated requester**. Applies to installations configured with `management.oauth_client_secret`. The attacker exchanges that secret for an **administrator token** via the identity provider, yielding — in Miggo's words — "full control of every message, queue, user, and broker setting."

**CVE-2026-57221 — permission bypass via passive declare**
- **CVSS: 5.3 MODERATE**
- **Affected/fixed:** same version ranges as above.
- **Authentication required:** yes — **but any account works, including zero-permission accounts**.
- **Mechanism:** the passive queue/exchange declare operation skipped authorization checks, letting a zero-permission authenticated user **enumerate and monitor other tenants' queues and exchanges** and read their statistics. A multi-tenant isolation failure.

**Why CVE-2026-57219 is the perfect VectaSec demo:**
1. **Unauthenticated → full broker takeover.** No user interaction, no privileges.
2. It is **an OAuth secret leaking out of middleware** — the exact seam VectaSec exists to watch. Message broker + OAuth + credential disclosure in one CVE.
3. The blast radius is **credential-shaped, not data-shaped**: the stolen secret becomes an admin token, which is Drift's pattern (§1) at the infrastructure layer.
4. **Exposure implies compromise, retroactively.** Miggo's guidance: if the management interface was **ever** reachable from an untrusted network, **assume the secret is leaked**. This is a posture question — *was port 15672 ever exposed?* — not a detection question. Detection tools cannot answer it. Posture tools can.
5. It is one week old and affects every 3.13+ branch.

**Scale context** [VENDOR CLAIM — Miggo, no methodology given]: RabbitMQ downloads exceed **15 million annually** and it comprises **"8% of all containers"** globally. The 8% figure has no stated methodology and should be treated as marketing; **do not repeat it**. Miggo cites no exploit count or affected-org count.

**Sources:**
- https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-57219 (primary, verified)
- https://www.miggo.io/post/full-broker-takeover-no-login-required-miggo-discovers-critical-rabbitmq-vulnerabilities-putting-application-data-at-risk

### 6.3 Kong — ⚠️ **A FABRICATED CVE IS CIRCULATING. READ THIS BEFORE CITING ANY KONG CVE.**

**CVE-2026-29413 DOES NOT EXIST. [FABRICATED]**

A blog at **kensai.app** ("Kong API Gateway CVE-2026: Authentication Bypass & Rate Limiting Vulnerabilities") ranks highly in search results and claims:
- A critical vulnerability **CVE-2026-29413**, disclosed **2026-03-28**, affecting **Kong 3.4–3.8**
- A "logic flaw in Kong's plugin execution ordering within the rewrite phase of the Nginx request lifecycle" allowing complete **authentication plugin bypass** and rate-limiting circumvention
- That **CISA added it to the KEV catalog** "following confirmed exploitation against financial services and healthcare API gateways"
- That Konnect SaaS customers were "automatically patched on 2026-03-29"

**Verification performed — all three checks failed:**
1. **NVD:** queried `services.nvd.nist.gov` for CVE-2026-29413 → **`totalResults: 0`**. The CVE does not exist.
2. **CISA KEV:** fetched the live `known_exploited_vulnerabilities.json` catalog → **no entry for CVE-2026-29413, and no Kong entries at all.** The KEV claim is false.
3. **Kong's official vulnerability page** (`developer.konghq.com/gateway/vulnerabilities/`) → **no mention of this CVE.** That page documents Kong's patching *process* only.

**Assessment:** this reads as AI-generated SEO content — plausible technical detail (the Nginx rewrite-phase framing is superficially credible), specific-sounding dates, and an authoritative-sounding CISA KEV claim, all fabricated. **The CISA KEV fabrication is the tell:** KEV listing is trivially checkable and no legitimate outlet would invent it.

**Actions:**
- **Never cite CVE-2026-29413.** Recorded here permanently so it is not re-ingested in a future research pass.
- **Treat kensai.app as a poisoned source.** Nothing from it enters VectaSec material.
- **Verify every CVE against NVD before it ships in any artifact.** This document's Kafka and RabbitMQ CVEs were checked this way; the Kong one failed the check.
- **Broader lesson worth a slide:** the security-content supply chain is itself being polluted by generated misinformation. A vulnerability-intelligence tool that ingests blogs uncritically will ingest fabrications. VectaSec should source CVE data from **NVD/OSV/vendor advisories only**.

**Genuine Kong CVE status: RESEARCH GAP.** NVD keyword searches for "Kong Gateway" (404 on the date-filtered endpoint) and "konghq" (`totalResults: 0`) returned nothing usable — the keyword search likely needs different terms rather than Kong being CVE-free, which is implausible. **Follow-up required** via NVD CPE-based search (`cpe:2.3:a:konghq:kong`), Kong's GitHub security advisories, and OSV.

**Sources checked:**
- https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-29413 → zero results
- https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json → no Kong entries
- https://developer.konghq.com/gateway/vulnerabilities/ → process doc only

### 6.4 Istio [VERIFIED — official Istio security bulletins]

Source: https://istio.io/latest/news/security/ (Istio's own bulletin index — authoritative)

**2026:**
| Bulletin | Date | CVSS | Affected | Summary |
|---|---|---|---|---|
| ISTIO-SECURITY-2026-005 | 2026-06-24 | 7.5 | 1.30.1–1.30.2, 1.29.4–1.29.5, 1.28.8–1.28.9 | CVEs reported by Envoy + Istio security fixes |
| ISTIO-SECURITY-2026-004 | 2026-06-04 | 7.5 | 1.30.0, 1.29.0–1.29.3, 1.28.0–1.28.7 | CVE reported by Envoy |
| ISTIO-SECURITY-2026-003 | 2026-04-20 | 5.4 | 1.29.0–1.29.1, 1.28.0–1.28.5 | **Authorization bypass and SSRF** |
| ISTIO-SECURITY-2026-002 | 2026-03-21 | 5.9 | All releases using the mesh gateway VirtualService option | **Man-in-the-Middle via VirtualService** |
| ISTIO-SECURITY-2026-001 | 2026-03-10 | **8.7** | 1.29.0, 1.28.0–1.28.4, 1.27.0–1.27.7 | CVEs reported by Envoy + Istio security fixes |

**2025:**
| Bulletin | Date | CVSS | Affected | Summary |
|---|---|---|---|---|
| ISTIO-SECURITY-2025-003 | 2025-12-03 | 8.1 | 1.28.0, 1.27.0–1.27.3, 1.26.0–1.26.6 | CVEs reported by Envoy |
| ISTIO-SECURITY-2025-002 | 2025-10-20 | 6.6 | 1.27.0–1.27.1, 1.26.0–1.26.5 | CVEs reported by Envoy |
| ISTIO-SECURITY-2025-001 | 2025-09-03 | 7.5 | 1.27.0, 1.26.0–1.26.3, 1.25.0–1.25.4 | CVEs reported by Envoy |

**Observations:**
- **8 bulletins in ~10 months** (Sept 2025 → June 2026), already **5 in 2026 alone** vs 3 in all of 2025 — an accelerating cadence.
- **Most Istio CVEs are inherited from Envoy.** Istio's exposure is largely its data-plane dependency. This is a *transitive dependency* story: you patch Istio to fix Envoy, and most operators do not track Envoy advisories directly. Good VectaSec argument — version drift in a service mesh is a supply-chain exposure.
- **ISTIO-SECURITY-2026-003 (authorization bypass + SSRF)** and **-2026-002 (MitM via VirtualService)** are the on-thesis ones: authz bypass in the mesh means the service identity layer VectaSec cares about is unreliable. -2026-002 affecting **"all releases"** using a specific VirtualService option is a **configuration-dependent** exposure — precisely a posture-scannable condition.
- **Individual CVE IDs were not extracted** from the bulletin index. **Follow-up needed** to map each bulletin to CVE IDs for the scanner's rule set.

### 6.5 MCP implementations [RESEARCH GAP]

No verified MCP CVEs were confirmed in this pass. Claims of "106 zero-days" and "67 CVEs from VIPER-MCP" (§5.1) are [UNVERIFIED] and traced only to aggregator blogs. **Follow-up:** search NVD/OSV/GitHub Security Advisories for the major MCP SDKs (`modelcontextprotocol/*` TypeScript and Python SDKs, LangGraph) rather than relying on blog aggregation.

---

## 7. Synthesis — the argument, in the order it should be made

The strongest version of VectaSec's narrative uses only [VERIFIED] material. It does not need a single vendor survey.

1. **The integration layer is now the primary breach path, and the trend is steep.** Third-party involvement in breaches: **15% → 30% → 48%** across three consecutive Verizon DBIRs. More than tripled in two years, measured by a party with no stake in our category. [VERIFIED]

2. **The attacks require no exploit.** Drift, Gainsight, Okta, and Snowflake all involved zero vulnerabilities in the victims' systems. Attackers authenticated as authorized integrations. Snowflake's 165 victims fell to credentials up to four years old on accounts without MFA. [VERIFIED]

3. **The blast radius is credential-shaped and it compounds.** Drift's stolen support-case text contained the OAuth secrets used to breach Gainsight three months later — which in turn seeded Klue in June 2026. Three iterations, eleven months, same playbook, still working. [VERIFIED — GTIG + Microsoft 2026-07-13]

4. **Nobody knows what tokens they have — and the best security teams on earth are the proof.** Cloudflare rotated *thousands* of credentials after Okta and still missed **four**, "because mistakenly it was believed they were unused." Those four cost them **5,000+ rotated credentials** and **4,893 reimaged systems**. If Cloudflare cannot manually inventory its NHI credentials, no one can. [VERIFIED — Cloudflare's own disclosure]

5. **Secrets live where nobody is looking.** GitGuardian measures **28% of 2025 secret-leak incidents originating entirely outside source code** — Slack, Jira, Confluence. Cloudflare found **104 live API tokens sitting in Salesforce support-case text**. Industry-wide measurement and a named company's disclosure, saying the same thing. [VENDOR TELEMETRY + VERIFIED]

6. **Secrets are not rotated. This is measured, not asserted.** Credentials leaked in 2022 were **still valid at >64% when retested in January 2026**. Two-thirds of four-year-old leaked secrets still work. [VENDOR TELEMETRY — GitGuardian]

7. **Every root cause was a static, scannable posture fact.** Over-scoped connected apps; no IP restrictions (Tor exit nodes used stolen tokens freely); no MFA; four-year-old credentials; dormant tokens believed unused; secrets in free-text fields; unauthenticated `GET /api/auth` on RabbitMQ. Not one required behavioral detection. Every one is answerable by a scan **before** the incident. [VERIFIED]

8. **The next surface is already exposed and already being scanned.** Censys: **12,520 MCP services** on **8,758 IPs** across **56 countries**, all enumerable **without authentication**, growing to **21,000+ in nine days**. SANS ISC: **49 distinct source IPs** probing a single low-traffic host for MCP handshakes and **`.claude/mcp.json`** credential files in a two-week window. No confirmed MCP breach yet. That is the window we are selling into. [VERIFIED]

**The line that ties it together — Google's, not ours:**
> "treat any and all authentication tokens stored in or connected to the Drift platform as potentially compromised"

Every Drift customer had to answer that question. Almost none could. **That is the product.**

---

## 8. Discipline notes for anyone using this document

**Do not use, ever:**
- **CVE-2026-29413** — fabricated; verified nonexistent in NVD and CISA KEV. [§6.3]
- **"40% of MCP servers are unauthenticated"** — not a Censys figure. Censys's actual finding is stronger; use it. [§5.1]
- **"1.5 billion records / 760 companies"** (Drift) — threat-actor claim to press. [§1.4]
- **"45:1 NHI ratio"** — no such figure found in any source. [§4.1]
- **"RabbitMQ is 8% of all containers"** — Miggo marketing, no methodology. [§6.2]
- Anything from **kensai.app** or **cyberleveling.com**. [§5.3, §6.3]

**Use with mandatory attribution in-sentence:**
- **82:1 NHI ratio** — "CyberArk's 2025 survey of 2,600 security decision-makers reported…" Never as bare fact. Prefer Cloudflare's measured numbers instead. [§4.1]
- **"700+ organizations"** (Drift) — "per reporting on Google's assessment." GTIG published no count. [§1.4]
- **MOVEit's 2,700 orgs / 95M individuals** — "per Emsisoft's tracking." [§3.4]

**Do not overreach on:**
- **MCP** — exposure and scanning are verified; **no breach is**. Say "the exposure is measured and the scanning is measured," never "MCP servers are being breached." [§5.3.6, §5.2]
- **What VectaSec would have prevented** — Drift's compromise was not preventable by us. Scope reduction, IP enforcement, secret discovery in case text, and blast-radius inventory were. Claim those four; claim nothing more. [§1.6]
- **Censys capability data** — advertised tool ≠ working tool, in Censys's own words. [§5.1]

**Do not hide:**
- The **2026 DBIR finding that vulnerability exploitation (31%) overtook stolen credentials** as the top initial access vector for the first time in 19 years. It complicates a pure identity narrative. It argues for VectaSec's breadth — we scan middleware exposure *and* token posture. Present it, don't bury it. [§4.3]

**Standing rules:**
1. **Verify every CVE against NVD before it ships.** The Kong fabrication passed every smell test except the one that mattered. Kafka and RabbitMQ CVEs here were NVD-checked; treat anything unchecked as unverified.
2. **Prefer first-party incident disclosures over any vendor statistic.** Cloudflare's 104 tokens and 4,893 reimaged systems beat every survey ratio in this document.
3. **We are a security vendor citing security statistics.** If we launder surveys into facts, we are the problem we describe.

---

## 9. Open research gaps — prioritized

| Priority | Gap | Action |
|---|---|---|
| **High** | Kafka/RabbitMQ/Kong internet exposure counts [§5.3] | Obtain Shadowserver subscription (free for network owners) or Censys/Shodan API key. Pull ports 9092, 5672, 15672, 8001, 8444. **First-party VectaSec scan data would be more defensible than anyone's citation** — and is a product asset, not just research. |
| **High** | Genuine Kong CVEs [§6.3] | NVD **CPE-based** search (`cpe:2.3:a:konghq:kong`), Kong GitHub security advisories, OSV. The keyword search failed; Kong being CVE-free is implausible. |
| **High** | **Klue incident, June 2026** [§2.3] | Microsoft's post is thin. Four weeks old, third iteration of the Drift playbook, Storm-3138. Most current proof the attack path is live. Dedicated pass. |
| **Medium** | Istio bulletin → CVE ID mapping [§6.4] | Needed for the scanner rule set. Fetch each ISTIO-SECURITY-YYYY-NNN bulletin individually. |
| **Medium** | MCP implementation CVEs [§6.5] | NVD/OSV/GHSA for `modelcontextprotocol/*` SDKs, LangGraph. Do not rely on aggregator blogs. |
| **Medium** | CVE-2025-27818 and CVE-2025-27817 fix completeness [§6.1] | Full NVD records; assess Seal Security's claim that 3.9.1 does not fully fix 27817. Also KAFKA-20043 → CVE-2025-12183, CVE-2025-66566. |
| **Medium** | **Shai-Hulud 2** supply-chain attack [§3.6] | 6,943 compromised machines per GitGuardian. Under-researched here; likely relevant to the agent-tooling narrative. |
| **Medium** | 2026 DBIR full-report figures [§4.3] | The 23%-MFA-remediation and 8-month-median stats came from secondary summaries. Verify in the PDF. Also extract dataset size. |
| **Low** | Default credential prevalence [§5.4] | Needs first-party scan data. Get the RabbitMQ `guest`/`guest` localhost-restriction nuance right rather than overstating. |
| **Low** | Salesloft GitHub → AWS pivot detail [§1.1] | The Mar–Jun 2025 phase is [REPORTED] only. Check for a Salesloft/Mandiant post-incident report. |

---

## 10. Master source list

**Primary — incident disclosures and responder reports:**
- Google GTIG/Mandiant, Salesloft Drift: https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift
- Google GTIG/Mandiant, UNC5537/Snowflake: https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion
- Cloudflare, Salesloft Drift response: https://blog.cloudflare.com/response-to-salesloft-drift-incident/
- Cloudflare, Thanksgiving 2023 incident: https://blog.cloudflare.com/thanksgiving-2023-security-incident/
- Okta, support system root cause: https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/
- Codecov post-mortem: https://about.codecov.io/apr-2021-post-mortem/
- Codecov security update: https://about.codecov.io/security-update/
- Microsoft Security, ShinyHunters OAuth abuse (2026-07-13): https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/
- CISA AA23-158A, CL0P/MOVEit: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a

**Primary — vulnerability data:**
- NVD CVE-2025-27819: https://nvd.nist.gov/vuln/detail/CVE-2025-27819
- NVD CVE-2026-57219: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-57219
- Apache Kafka CVE list: https://kafka.apache.org/cve-list
- Istio security bulletins: https://istio.io/latest/news/security/
- CISA KEV catalog: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- Kong vulnerability process: https://developer.konghq.com/gateway/vulnerabilities/
- Miggo RabbitMQ research: https://www.miggo.io/post/full-broker-takeover-no-login-required-miggo-discovers-critical-rabbitmq-vulnerabilities-putting-application-data-at-risk

**Primary — measurement and telemetry:**
- Censys, MCP servers on the internet (2026-05-27): https://censys.com/blog/mcp-servers-on-the-internet/
- SANS ISC diary #33150 (2026-07-13): https://isc.sans.edu/diary/33150
- GitGuardian State of Secrets Sprawl 2026: https://blog.gitguardian.com/the-state-of-secrets-sprawl-2026/
- Shadowserver Accessible AMQP Report: https://www.shadowserver.org/what-we-do/network-reporting/accessible-amqp-report/
- Verizon 2026 DBIR press release: https://www.verizon.com/about/news/breach-industry-wide-dbir-finds
- Verizon 2025 DBIR press release: https://www.verizon.com/about/news/2025-data-breach-investigations-report
- Verizon 2026 DBIR (full PDF): https://www.verizon.com/business/resources/Td15/reports/2026-dbir-data-breach-investigations-report.pdf

**Vendor claims — attribute explicitly:**
- CyberArk 2025 Identity Security Landscape (82:1): https://www.cyberark.com/press/machine-identities-outnumber-humans-by-more-than-80-to-1-new-report-exposes-the-exponential-threats-of-fragmented-identity-security/
- CyberArk, 96 machines per human in financial sector: https://www.cyberark.com/resources/blog/96-machines-per-human-the-financial-sectors-agentic-ai-identity-crisis

**Secondary reporting — corroborating, not primary:**
- CyberScoop, Drift victims: https://cyberscoop.com/salesloft-drift-attacks-cloudflare-palo-alto-networks-zscaler/
- The Register, Gainsight: https://www.theregister.com/2025/11/21/shinyhunters_salesforce_gainsight_breach/
- CSO Online, Gainsight OAuth: https://www.csoonline.com/article/4094506/oauth-token-compromise-hits-salesforce-ecosystem-again-gainsight-impacted.html
- The Hacker News, Microsoft ShinyHunters map: https://thehackernews.com/2026/07/microsoft-maps-year-long-shinyhunters.html
- Krebs on Security, Okta tokens: https://krebsonsecurity.com/2023/10/hackers-stole-access-tokens-from-oktas-support-unit/
- BleepingComputer, HashiCorp/Codecov: https://www.bleepingcomputer.com/news/security/hashicorp-is-the-latest-victim-of-codecov-supply-chain-attack/
- Rapid7, MOVEit timeline: https://www.rapid7.com/blog/post/2023/06/14/etr-cve-2023-34362-moveit-vulnerability-timeline-of-events/
- SecurityWeek, Snowflake/infostealers: https://www.securityweek.com/snowflake-attacks-mandiant-links-data-breaches-to-infostealer-infections/

**Rejected — do not use:**
- kensai.app (fabricated CVE-2026-29413 with false CISA KEV claim)
- cyberleveling.com (unverifiable; 403 on fetch)
- ChatForest / Medium MCP statistics (unverified, mutually inconsistent)
- ShinyHunters press claims (actor-supplied)
