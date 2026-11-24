# How AI (LLMs and agents) is used inside security posture products — design reference for VectaSec (as of 23 Nov 2026)

Evidence labels used on every finding:
- **[P]** = read from the primary page (fetched; note the fetch tool returns a model-made extraction of the page, so exact wording should be re-checked before quoting).
- **[V]** = vendor-claimed number or behaviour, not independently verified (may also be [P] if read on the vendor's own page).
- **[S]** = seen only in a search-result summary; not opened. Treat as a lead, not a fact.

Scope note: this file does not repeat the launch list from the earlier note. It covers mechanism, grounding, guardrails, quality, cost and failure.

---

## 1. Natural-language questions over a security graph

### Takeaway
Three architectures are in production: (a) text-to-query with retrieval of examples and schema fragments (Wiz Ask AI, Google SecOps, Security Copilot KQL), (b) a tool-calling agent over a fixed, permission-checked API (Prowler Lighthouse, Datadog Bits), and (c) document retrieval (questionnaire tools). The only vendor that published an accuracy figure for text-to-query reported 80% on a 200-item golden set, and user reviews of every product in this class mention wrong tables, "I don't know" answers or the need to validate the generated query.

### Cited Findings
- **Wiz Ask AI is text-to-query, not free-form chat.** The model (Claude Sonnet 3.5 on Bedrock at the time) emits a JSON query in Wiz's own graph query language. Pipeline: embed the question, retrieve similar past query examples by cosine similarity, re-rank with Maximal Marginal Relevance for diversity, then fetch — for the entities that appear in those examples — their properties, allowed operators and value types, allowed values per property, technology IDs, and the permitted relationship paths. Those fragments are the "schema" given to the model, because the graph has no fixed schema. Published 23 Oct 2024. [P] — [Wiz engineering blog](https://www.wiz.io/blog/askai-text-to-security-graph-query)
- **Wiz's reported accuracy: 80% on a 200 query/JSON-pair benchmark**, "verified through exact matches or manual review"; later improvements described only as "substantial" with no number. They avoided an LLM re-ranker to save cost and latency. [P][V] — [Wiz engineering blog](https://www.wiz.io/blog/askai-text-to-security-graph-query)
- **Wiz's stated failure modes:** real user phrasing diverged from the seeded example database; an error in any one retrieval step degrades the final query because steps are interdependent; redundant examples; some examples actively confused JSON generation and were removed; new entity types (e.g. AI models) lacked examples. They built the example set by clustering anonymised customer queries (UMAP + DBSCAN, ~150 topics, 50 sampled per cluster). [P] — [Wiz engineering blog](https://www.wiz.io/blog/askai-text-to-security-graph-query)
- **Wiz Mika (2026) is positioned as a companion over the Security Graph plus specialised agents;** the public material is marketing and does not confirm whether every Mika answer uses the Ask AI pipeline above. [S] — [Wiz blog](https://www.wiz.io/blog/wiz-ai-agents)
- **User comments on Wiz AI are mixed.** G2 reviewers say the AI search "is very good" and Mika is easy to use; an AWS Marketplace review (product attribution not confirmed) reports "I don't know" responses or an endless spinner on every query. [S] — [G2 Wiz reviews](https://www.g2.com/products/wiz-wiz/reviews); [AWS Marketplace reviews](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-ibgbkrqusncsm?page=7)
- **Prowler Lighthouse AI is a tool-calling agent, not text-to-query.** LangChain agent → Prowler MCP server. Instead of registering every MCP tool it exposes two meta-tools, `describe_tool` (fetch a tool's schema) and `execute_tool` (run it), to keep the tool list small for the model. Tool namespaces: `prowler_*` (findings, providers, scans, resources — JWT required), `prowler_hub_*` (check catalogue, compliance frameworks — no auth), `prowler_docs_*` (docs search). The bearer token is attached only to `prowler_*` calls; the MCP server applies row-level security for tenant isolation. [P] — [Prowler Lighthouse architecture](https://docs.prowler.com/developer-guide/lighthouse-architecture)
- **Prowler shows its work as a "chain of thought" panel** driven by tool start/end events streamed over SSE. The system prompt also receives tenant "business context" and a current-posture summary. [P] — [Prowler Lighthouse architecture](https://docs.prowler.com/developer-guide/lighthouse-architecture)
- **Prowler's stated limits:** "may make mistakes"; it "can only access data the logged-in user can view"; "the agent doesn't have the tools to make the changes" (read-only by absence of tools); provider secrets "cannot be read"; resource names, tags and account IDs may be sent to the LLM provider depending on the query; recommended model is `gpt-5`, and models must support tool calling. The architecture page describes no prompt-injection controls. [P] — [Prowler Lighthouse AI docs](https://docs.prowler.com/getting-started/products/prowler-lighthouse-ai)
- **Google SecOps Gemini generates YARA-L 2.0 search queries** from English only; when it cannot interpret a prompt it returns a "no valid query" message and asks for a rephrase; users rate the generated query. [S] — [Google SecOps docs](https://docs.cloud.google.com/chronicle/docs/investigation/generate-udm-search-queries-gemini)
- **Microsoft Security Copilot** grounds through plugins (collections of tools/APIs), runs post-processing (extra grounding calls, RAI/compliance checks) and "displays intermediate steps in a process log, providing opportunities to double-check its processes and sources". Its own application card warns generated code "may appear valid but might not be semantically or syntactically correct" and tells users to check that parameters such as the time range in the generated KQL match the prompt. Page dated 22 Jun 2026. [P] — [Microsoft Security Copilot application card](https://learn.microsoft.com/en-us/copilot/security/security-copilot-application-card)
- **Security Copilot KQL quality in reviews:** a G2 reviewer says generated KQL is sometimes wrong or uses the wrong table and must be validated; another finds it a time-saver as an editable draft. [S] — [G2 review](https://www.g2.com/survey_responses/microsoft-security-copilot-review-14014476)
- **Datadog Bits Security Analyst** lists, for each investigation, the steps, the data queries run at each step with embedded results and links to the full query, and an analysis per step. [P] — [Datadog docs](https://docs.datadoghq.com/bits_ai/bits_security_analyst)

### Inferences
- The pattern that matches VectaSec's "evidence ledger" ethos is: model produces a **typed, validated query object** (not prose, not raw SQL), deterministic code executes it under the caller's tenant scope, and the UI shows the query and the result rows. The model's prose answer is a caption on the rows, never the source of truth.
- Wiz's lesson generalises: retrieval of *examples* matters more than a big schema dump, and a small, curated, clustered example library is the main accuracy lever. For a product with ~450 detectors and a modest graph vocabulary, the schema is small enough to enumerate allowed node types, edge types and property values in the prompt (and cache it).
- The most dangerous failure is not a refusal but a **syntactically valid query that answers a different question** (wrong time window, wrong relationship direction) and returns a plausible or empty table. "No results" must be distinguishable from "query was wrong".
- Prowler's two-meta-tool trick is a cost/latency optimisation, but it also means any tool added to the MCP server is automatically reachable by the agent — convenient, and a risk if a write tool is added later.

### Gaps
- No architecture detail found for Orca AI search, Snyk's or Vanta's NL question features; searches returned nothing usable for Orca.
- No independent benchmark of text-to-graph-query accuracy for any CNAPP. The 80% Wiz figure is from 2024 and self-reported.
- Wiz Mika's internal pipeline (2026) is behind login-only docs.

---

## 2. AI explanation and summarisation (findings, diffs, digests, questionnaires)

### Takeaway
Summarisation is the most widely shipped and best-liked AI use, and also the task that research finds most vulnerable to injected text. Questionnaire vendors ground strictly in a customer-approved library and publish very low hallucination rates, but those numbers are self-reported, inconsistent across their own pages, and conditional on a "strong library".

### Cited Findings
- **Conveyor claims a 0.1% hallucination rate** ("about 1 in 1,000 answers") when seeded with a strong library, versus ~3% it cites for off-the-shelf GPT-4 RAG. Hallucination is defined as a statement "not present in the original facts". The page names post-processing to keep answers grounded, use of the most capable models, and evaluation/observability pipelines; it gives no measurement method. Updated 1 Dec 2025. [P][V] — [Conveyor docs](https://docs.conveyor.com/docs/what-is-conveyors-hallucination-rate)
- **Conveyor's numbers are inconsistent across sources** (0.1% in docs; a third-party review cites 0.01%; 95% and 98% accuracy figures appear in different places). [S] — [Conveyor comparison page](https://conveyor.com/compare/conveyor-vs-vanta); [ComplyJet review](https://www.complyjet.com/blog/best-security-questionnaire-automation)
- **Vanta** says its AI answers "an average of 80% or more" of questions and answers are "accepted up to 95% of the time", with the caveat that results depend on the knowledge base; responses are reviewed in Vanta before return. Acceptance rate is not accuracy. [S][V] — [Vanta questionnaire automation](https://vanta.com/products/questionnaire-automation)
- **Vanta AI Agent** (private beta June 2025) reads uploaded policies, extracts title/version/SLAs, suggests control mappings, flags mismatches between policy SLAs and configured settings, and checks uploaded evidence against audit requirements. No public description of its citation mechanism was found. [S] — [Help Net Security, 11 Jun 2025](https://www.helpnetsecurity.com/2025/06/11/vanta-ai-agent/)
- **Competitors frame the trust question as "does it generate, or does it reuse pre-approved text word for word?"** [S] — [Loopio](https://loopio.com/blog/conveyor-vs-loopio/); [Wolfia](https://wolfia.com/blog/conveyor-vs-wolfia-for-ai-questionnaire-accuracy)
- **Summarisation is the highest-risk task under injection.** In "Poisoning the Watchtower" (May 2026, gpt-4o-mini only, 48 strategy/defence/task combinations), context-manipulation payloads in log fields achieved 96% injection success on summarisation with no defence and 38% with constrained output; direct "ignore previous instructions" overrides achieved 0% on classification, while persona hijacks suppressed 68% of malicious logs under a naive classifier. Average success fell from 26.6% (naive) to 11.8% (strongest defence) — reduced, not eliminated. [P] — [arXiv 2605.24421](https://arxiv.org/abs/2605.24421)
- **Real-world precedent:** Tenable showed Gemini Cloud Assist could be injected through a log entry (attacker-set HTTP User-Agent) that a victim later asked it to summarise; the summary rendered an attacker phishing link. Google's fix was deterministic: stop rendering hyperlinks in log-summary responses. Disclosed Sept 2025. [S] — [Tenable advisory TRA-2025-10](https://www.tenable.com/security/research/tra-2025-10); [The Hacker News](https://thehackernews.com/2025/09/researchers-disclose-google-gemini-ai.html)
- **Model-provider citation primitive:** Anthropic's Citations feature chunks supplied documents into sentences and returns answer spans tied to exact source passages; `cited_text` does not count as output tokens. [S] — [Claude docs: Citations](https://platform.claude.com/docs/en/build-with-claude/citations)
- **Security Copilot** lists "stakeholder reporting" (technical summaries and executive briefings) as an intended use and says it "cites source materials" to mitigate over-reliance. [P] — [Security Copilot application card](https://learn.microsoft.com/en-us/copilot/security/security-copilot-application-card)
- **Practitioners use LLMs for reporting a lot:** in a study of 892 Reddit posts (Dec 2022–Sep 2025), reporting and documentation was the third most common SOC use (84 posts) after triage/IR (139) and scripting/query support (88). [P] — [arXiv 2604.09998, SOUPS 2026](https://arxiv.org/html/2604.09998)

### Inferences
- VectaSec's existing constraint (model must cite numbered observations; schema + DB constraint) is stronger than anything publicly documented by the questionnaire vendors. The same contract extends naturally to: change-diff explanation (cite diff hunk IDs), digests (cite finding IDs and precomputed metric IDs), breach-day briefs, leaver reports, and questionnaire answers (cite ledger observation IDs with timestamps).
- For digests and executive summaries, **numbers should never be generated**. Compute counts, deltas and rankings deterministically, pass them as named slots, and verify after generation that every numeral in the output equals a slot value.
- The Gemini fix is the lesson for rendering: strip or neutralise links, markdown images and HTML in any model output that was conditioned on scanned strings.
- Questionnaire answering from live posture data is a differentiator against library-only tools, but the answer must carry "as of scan X" and must refuse ("no evidence in ledger") rather than fill gaps; a wrong attestation to a customer's buyer is a contractual problem, not just a UX one.

### Gaps
- Found no shipped, documented feature that explains a configuration diff or change history with AI, and no reviewer commentary on one. This appears to be open ground, but absence of evidence here may reflect search coverage.
- No independent measurement of questionnaire-answer hallucination rates.
- Drata and Secureframe AI questionnaire mechanisms were not found in this pass.

---

## 3. AI-assisted detection (finding what rules miss)

### Takeaway
Where a model's verdict is used in shipped products it is almost always as a filter, ranker or candidate generator on top of deterministic findings, with a deliberately asymmetric error policy; I found no production posture product that documents letting a model create a finding on its own. Academic results for LLM misconfiguration detection are strong on recall but come from narrow, fine-tuned settings, and LLM "guardrail" classifiers have themselves been bypassed by injection.

### Cited Findings
- **Semgrep Assistant (triage of rule-produced findings)** uses RAG to give a binary verdict, "likely true positive" / "likely false positive". Inputs: rule metadata, past triage decisions for the same rule, examples of what the rule should/should not flag, customer "Memories", dozens of code lines around the finding and at each dataflow step. Golden set: 2,000+ findings labelled by the security research team with written reasoning; compared models with promptfoo. Jan 2025. [P] — [Semgrep blog](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/)
- **Semgrep's honest numbers:** initial agreement with researchers was ~55% even though in-product user feedback suggested >90% (feedback was biased because unhappy users simply leave). Final: 96% agreement on true positives, only 41% on false positives — a deliberate choice to minimise missed real issues. Likely-false-positive findings are tagged and not surfaced to the developer but stay in the backlog for AppSec review; "at this stage" Assistant does not close findings. [P] — [Semgrep blog](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/)
- **Semgrep's later metrics page (as of 21 Aug 2025):** 96% human-agree rate from thumbs up/down across 3,500+ customers and 6.5M+ findings; 60% average reduction in findings as noise; internal benchmark of 2,000+ findings gives a 96% "false positive confidence rate" (precision when it says FP, explicitly "does not mean [it] catches all false positives") and 80% of remediation guidance rated helpful on a binary scale. [P][V] — [Semgrep Assistant metrics](https://docs.semgrep.dev/semgrep-assistant/metrics)
- **Memories:** natural-language context built from triage notes and developer feedback and reused in triage; one Fortune 500 beta user reportedly saw 2.8x more noise filtered after adding five memories. [S][V] — [Semgrep blog](https://semgrep.dev/blog/2025/announcing-ai-noise-filtering-and-triage-memories)
- **LLM misconfiguration detection research:** GenKubeSec (May 2024) reports precision 0.990 and recall 0.999 on Kubernetes manifests versus three rule-based tools, with an expert judging sampled localisation/reasoning/remediation explanations "100% correct" (sample size not given on the abstract page). [P] — [arXiv 2405.19954](https://arxiv.org/abs/2405.19954). A search summary adds that expert review found over 83% of that paper's apparent false positives were real issues the rule tools did not cover. [S] — same source
- **Counter-evidence on LLM config fixes:** a Springer empirical paper reports LLM refactorings of cloud misconfigurations had very low correctness; a Helm-chart study asks explicitly whether LLM refactorings hallucinate. [S] — [Springer EMSE](https://link.springer.com/article/10.1007/s10664-025-10688-0); [arXiv 2403.09537](https://arxiv.org/pdf/2403.09537)
- **Sensitive-data classification from metadata only (Ethyca, 23 Dec 2025):** LLM labels columns from name, type and optional description, never table contents. ~2,000 tagging tasks over 43 categories; precision/recall/F1 rose from ~50% to >80% on an adversarial benchmark and >90% on customer datasets; on human-labelled customer data a positive AI label was wrong 5% of the time versus 14% for human labels. Failure modes named "laziness" (skips fields — fixed with one request per field), "shallowness" (accepts plausible wrong tags — fixed by asking for considerations first), "credulity" (follows vague guidance). ~95 fields/min on one GPU, ~$0.603 per 1,000 fields; models at ~18B parameters and below made unfixable errors, ~32B was enough. [P] — [Ethyca engineering](https://ethyca.com/news/engineering-llm-data-classifier-metadata-only)
- **DSPM vendors describe hybrids:** deterministic matchers (proximity, checksums, exact-match fingerprints) with LLMs used "only for those entity types where context is crucial". [S][V] — [Varonis](https://www.varonis.com/blog/data-classification-deep-dive); [Proofpoint](https://www.proofpoint.com/us/blog/dspm/improving-accuracy-a-smarter-approach-to-data-classification)
- **MCP tool-description scanning:** Snyk's `mcp-scan` flags prompt injection in tool descriptions as "untrusted content" and names tool poisoning and "toxic flow analysis" as analyses; the post does not say whether detection is rules or a model (published 19 Aug 2025, updated 28 Sep 2026). [P] — [Snyk Labs](https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/)
- **Research on poisoned tool descriptions:** a March 2026 paper tested seven MCP clients and found some show descriptions at setup but hide them at runtime; an April 2026 paper trains BERT/BiLSTM/SVC classifiers and reports they beat rule-based detection. Static source scanners cannot see descriptions loaded at runtime from databases or remote files. [S] — [arXiv 2603.22489](https://arxiv.org/html/2603.22489v1); [arXiv 2604.10534](https://arxiv.org/html/2604.10534); [DEV: what static scanners miss](https://dev.to/coppersundev/mcp-tool-poisoning-what-static-scanners-miss-2idg)
- **An LLM used as a security classifier can be told to say "safe":** n8n's LLM-based Guardrail node was bypassable by prompt injection (GHSA-fvfv-ppw4-7h2w, fixed in 2.10.0, PoC public). [S] — [DEV write-up](https://dev.to/cverports/ghsa-fvfv-ppw4-7h2w-n8n-guardrail-bypass-when-ai-safety-rails-are-made-of-paper-k5k)
- **No established product was found that uses an LLM to review n8n/Zapier workflow definitions for risky intent;** search returned only runtime guardrail nodes and audits of agent skill packages. [S] — [Socket: securevector n8n node](https://socket.dev/npm/package/@securevector/n8n-nodes-securevector)
- **Rule generation from advisories (AWS RuleForge, arXiv Apr 2026):** five candidate rules per CVE in parallel (temperature 0.7–0.9, DSPy on Bedrock), then four gates: (1) LLM-generated synthetic tests, pass at ≥8/10; (2) LLM-as-judge scoring sensitivity ≥0.5 and specificity ≥0.7; (3) run against sampled production traffic — rule must match 10–500 IPs and >70% must be labelled malicious by threat intel; (4) human review of every rule. Up to five refinement attempts per candidate ("5×5"). Judge calibration: AUROC 0.75, ECE 0.17. Adding the judge gate gave 67% fewer false positives than synthetic tests alone at equal true positives. LLM reasoning matched human reasoning on 6 of 9 rules, which the authors say is not distinguishable from chance. Nothing ships without human approval. [P] — [arXiv 2604.01977](https://arxiv.org/html/2604.01977v1)
- **Other rule-generation work:** Sublime Security published a holdout-based framework for evaluating LLM-written detection rules against a human corpus (Sept 2025); CTI-REALM is a 2026 benchmark for agent rule generation. [S] — [arXiv 2509.16749](https://arxiv.org/html/2509.16749v1); [arXiv 2603.13517](https://arxiv.org/pdf/2603.13517)

### Inferences
- The defensible policy for VectaSec: **a model may raise, annotate or rank; it may not create a first-class finding or suppress one on its own authority.** Model output becomes an "AI-suspected" candidate that needs either a deterministic corroborating check or a human confirm before it enters the ledger as a finding. This preserves the "every finding cites stored observations" invariant.
- Asymmetry matters and should be explicit per feature. Semgrep chose high recall on true positives and accepted weak FP detection. For a scanner reading attacker-influenced text, the n8n guardrail bypass and the Watchtower "persona hijack" results say the same thing: injected content most easily pushes a verdict toward *benign*. So a "benign" verdict from a model that read untrusted text should carry no weight.
- Semantic review of n8n/Zapier workflow definitions and MCP tool descriptions looks like genuinely unoccupied territory for a posture product, and it is exactly where rules are weakest (intent expressed in free text). It is also the feature most exposed to injection, because the thing being judged is the injection payload.
- Metadata-first classification (topic names, schema field names, queue names, header keys) fits an agentless product and avoids sending payload samples to a model provider. Ethyca's "one request per field" + prompt caching is the cost pattern.
- RuleForge is the template for an *internal* detector-authoring pipeline: many candidates, cheap automated gates, replay against real customer-shaped data, human sign-off. Its own data says the LLM judge is a weak filter (AUROC 0.75), so the replay-against-real-data gate carries the weight.

### Gaps
- No vendor documentation found describing a production CSPM/CNAPP detector whose finding is created solely by an LLM reading raw config. Either it is not done, or not disclosed.
- No public precision/recall for Snyk mcp-scan or any MCP description scanner against adaptive attacks.
- No evidence found on LLM anomaly *explanation* quality (as opposed to detection) in posture tools.
- AI owner/resource classification: Wiz Green Agent produces a "Suggested Assignee" (see §4) but no accuracy figure is published.

---

## 4. AI remediation

### Takeaway
Generated fixes are the feature with the worst measured reliability: the largest 2026 study found roughly one in four AI patches cleanly fixed the target flaw, and passing tests or reproducers did not indicate a real fix. Every credible implementation keeps a human merge step; what makes a fix trustworthy is narrow scope, correct guidance, and verification by something other than the generator.

### Cited Findings
- **1Password Off-by-1 Labs study (6 Aug 2026):** 6,080 patches from ChatGPT 5.5 and Claude Opus 4.8 across six recent CVEs. Roughly one in four fixed the bug cleanly; close to one in twenty introduced a new vulnerability; more than a third of "successful" patches were fragile (blocked the demonstrated exploit with a narrow check, left the vulnerable code reachable). In the freenginx case, 114 of 270 attempts closed the hole and every one of the 114 introduced a new problem. [P] — [Help Net Security](https://www.helpnetsecurity.com/2026/08/06/1password-ai-generated-vulnerability-patches/)
- **Exact headline figures seen only in search summaries:** 53.9% failed to remediate, introduced a new vulnerability, or both; 26.0% fully fixed without side effects. Dark Reading framed it as only 46% solving the underlying vulnerability — a different cut of the same data. [S] — [TechRadar](https://techradar.com/pro/security/shock-horror-ai-generated-security-patches-fall-short-of-actually-solving-all-the-problems-they-were-meant-to-fix); [Dark Reading](https://darkreading.com/application-security/ai-generated-patches-fail-half-time)
- **Guidance correctness dominates:** correct fix direction in the prompt closed the bug about two-thirds of the time; plausible-but-wrong direction dropped that to about one in six. Recommendation: do not give a patching agent direction you cannot vouch for. An iterative harness beat a single attempt but mattered less than guidance. [P] — [Help Net Security](https://www.helpnetsecurity.com/2026/08/06/1password-ai-generated-vulnerability-patches/)
- **Verification is itself unreliable:** test suites and reproducers often passed flawed patches; model-based validators and humans agreed on the exact grade only about two-thirds of the time; an off-by-one copied from a flawed upstream fix was caught in only a couple dozen of ~250 patches containing it. Each attempt-plus-validation cycle cost about $2–3. [P] — [Help Net Security](https://www.helpnetsecurity.com/2026/08/06/1password-ai-generated-vulnerability-patches/)
- **Caveats on that study:** six complex multi-file CVEs, one per codebase, two model versions; The Register reports 1Password added a post-publication note acknowledging a critique but did not withdraw. [P] for caveats — Help Net Security above; [S] — [The Register](https://theregister.com/ai-and-ml/2026/08/06/ai-struggles-to-patch-vulns-without-adult-supervision/5284319)
- **Independent academic result in the same direction:** of 319 LLM-generated patches for Java vulnerabilities, only 24.8% achieved full correctness (March 2026). [S] — [arXiv 2603.10072](https://arxiv.org/html/2603.10072v1)
- **GitHub Copilot Autofix:** prompt contains the CodeQL alert in SARIF, short snippets around source and sink, the first ~10 lines of each involved file, and the query help text. "Suggestions that fail internal testing are not displayed." Evaluation harness: 2,300+ alerts from public repos with test coverage; the suggestion is merged unedited and checked for (a) alert fixed, (b) new alerts, (c) syntax errors, (d) changed test output. Documented failure modes: non-determinism, truncated context, syntax errors, fixes at the wrong location, semantic changes, partial fixes or new vulnerabilities, and "fabricated dependencies published under statistically probable names". [P] — [GitHub docs: responsible use of Autofix](https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning)
- **Wiz Green Agent (3 Nov 2026):** reasons over the Security Graph (runtime exposure, identity access, code-to-cloud mapping) plus commit history, project assignments, service catalogue/CMDB and cloud logs; decides remediate vs lower severity; names the file and line; proposes a "Suggested Assignee"; emits code/Terraform changes and a one-click PR or a hand-off to a coding agent. Developers "review, validate, and merge". Customer claims: Fireblocks >70% less daily triage time; project44 "10x" remediation velocity. No acceptance or accuracy rates; no post-deploy re-check described on that page. [P][V] — [Wiz blog](https://www.wiz.io/blog/green-agent-agentic-remediation)
- **Wiz remediation playbook:** non-PR actions route to an owner in Slack for approval, execute after approval, and are verified "from the next scan". [S] — [Wiz blog](https://www.wiz.io/blog/wiz-remediation-playbook)
- **Semgrep:** autofix is only triggered for true-positive verdicts; 80% of remediation guidance rated helpful (binary). No autofix correctness metric published. [P] — [Semgrep Assistant metrics](https://docs.semgrep.dev/semgrep-assistant/metrics)

### Inferences
- A trustworthy generated fix in VectaSec's domain has four properties: (1) the model **parameterises a vetted fix template** from the guided-fix library rather than free-writing config; (2) the fix is passed through the existing deterministic **fix-impact preview** and least-privilege dry run before the user sees it; (3) verification after apply is the **deterministic rescan plus the read-only proof probe**, never the model's own opinion; (4) a rollback snippet derived from the stored pre-change observation ships with every fix.
- The 1Password "fragile fix" class maps directly to middleware: a fix that makes the detector stop firing (e.g. changes the flagged field) without closing the access path. The proof probe is the antidote — verify the *exploit path* is closed, not just the detector.
- The "wrong guidance is worse than none" result argues against letting a model infer fix direction from scanned free text. Fix direction should come from the detector's own remediation metadata.
- Config/CLI fixes for brokers and gateways are much smaller and more templated than multi-file C patches, so success rates should be far higher than the 1Password numbers — but that is an expectation, not evidence. It needs VectaSec's own measurement.

### Gaps
- No published success rate for AI-generated *configuration* fixes (Terraform, broker ACLs, gateway policy) from any vendor.
- No detail on how any vendor verifies a merged-but-not-yet-deployed fix.
- AWS, Orca and Snyk remediation internals were not examined in this pass.

---

## 5. Agentic investigation

### Takeaway
Shipped investigation agents are read-only query runners that expose every step, end in a recommended verdict rather than an action, and take customer-written context; public benchmarks show the best models still score well under what "autonomous" would require.

### Cited Findings
- **Datadog Bits Security Analyst:** autonomously investigates Cloud SIEM signals from eligible rules (above medium severity by default, configurable per rule or by signal query). Output panel: conclusion, key evidence, suggested next steps, rule-tuning suggestions, and each step with its queries, embedded results and links. Signals stay "Investigating" until a human marks Benign or Suspicious. Follow-up actions (case, SOAR workflow, incident, suppression) are user-initiated. Context comes from an org-wide `Bits.md` and "Situational Context" entries with optional expiry. Step/time limits are not documented. [P] — [Datadog docs](https://docs.datadoghq.com/bits_ai/bits_security_analyst)
- **Datadog claims up to 98% less investigation time.** [S][V] — [Datadog press release](https://www.datadoghq.com/newsroom/press-releases/bits-ai-security-analyst-reduces-threat-investigation-time/)
- **Microsoft Security Copilot agents** act "within configured permissions", require "appropriate user or administrator approval" for scoped actions, run under either a dedicated agent identity (Entra Agent ID) or the configuring user's credentials, and expose an "agent node map" of steps performed. [P] — [Security Copilot application card](https://learn.microsoft.com/en-us/copilot/security/security-copilot-application-card)
- **ExCyTIn-Bench (Microsoft):** 8 simulated multi-step attacks, 57 Sentinel log tables; agents query a database to answer investigation questions; step-wise rewards. Best reward 0.368 (o4-mini) in the first arXiv version (Jul 2025); the later ICML 2026 version reports a best of 0.606. Used to evaluate Security Copilot. [S] — [arXiv 2507.14201](https://arxiv.org/abs/2507.14201); [PMLR v306](https://proceedings.mlr.press/v306/wu26bd.html); [Microsoft Security blog](https://microsoft.com/en-us/security/blog/2025/10/14/microsoft-raises-the-bar-a-smarter-way-to-measure-ai-for-cybersecurity/)
- **Adversarial telemetry downgrades verdicts:** a NeurIPS 2026 paper reports that across five model configurations and 1,100+ payloads, telemetry-borne indirect injection caused verdict downgrades in every configuration. LogInject (Jul 2026) splits a payload across several log entries ("Context Stitching") to evade per-entry filters; reported success figures conflict between sources (76.4% in the abstract vs 83.4% in a secondary summary). [S] — [NeurIPS 2026 poster](https://neurips.cc/virtual/2026/168153); [arXiv 2607.14493](https://arxiv.org/abs/2607.14493)
- **Autonomy in practice:** in Prophet Security's 2026 survey (250+ respondents, vendor-sponsored), 57% require a human to review every AI decision before closing an alert, 44% let AI recommend actions that humans execute, 30% allow low-risk automated remediation, and none grant full unsupervised autonomy. [P] of a sponsored article — [The Hacker News, 27 Aug 2026](https://thehackernews.com/2026/08/what-data-says-about-ai-in-security.html)

### Inferences
- VectaSec already owns the deterministic building blocks an investigation agent would call: change history (time machine), findings, graph neighbours, toxic flows, canary hits, proof results, leaver data. An agent adds value by *sequencing* those reads into a timeline, not by reasoning from raw text.
- The bounding recipe visible across vendors: read-only tool set; fixed step and token budget; every tool call logged with arguments and result hash; output is a structured timeline whose every entry cites an observation or change ID; verdict is a recommendation that a human confirms.
- Plan-then-execute (see §7) fits well: the plan (which reads to run) can be fixed from the trigger and the finding type before any scanned text is read, so injected text cannot add steps.
- A benchmark-best reward of ~0.6 on investigation questions says "root cause" output must be labelled a hypothesis with its supporting and missing evidence listed.

### Gaps
- No vendor publishes step limits, token budgets or per-investigation cost for its investigation agent.
- No audit-log schema for agent runs was found in public docs (Datadog's investigation API is in Preview).
- Datadog engineering-level internals (planner, model) were not found.

---

## 6. Exposing the product to the customer's own AI (remote MCP servers)

### Takeaway
By late 2026 a remote, OAuth-authenticated MCP server that mirrors the user's own role is the norm for security vendors, and several now include write tools; none of the vendor pages read here documents a defence against their own finding text being used as an injection vector into the customer's agent.

### Cited Findings
- **Vanta (remote, beta, all customers):** OAuth browser sign-in; the agent acts with the signed-in user's permissions; admins get all tools, non-admins the same minus an unnamed admin-only set. Capability areas include listing failing tests, controls, vendors, vulnerable assets and policies, and write-type actions such as remediating tests, running vendor assessments, uploading policy documents and managing controls. **"There is no read-only mode and no way to give an agent a chosen subset of tools"** — scope by choosing which account connects, or disable tools client-side. Regional endpoints for US, EU, Australia. The page has no prompt-injection warning. [P] — [Vanta MCP docs](https://developer.vanta.com/docs/vanta-mcp)
- **Semgrep (remote, beta, 12 Nov 2026):** ten capability areas — findings/triage (including bulk ignore/reopen), fixes (generate Autofix, start AI fix jobs), scans, projects, supply chain, rules and policies (dry-run and apply), reports, agentic workflows, ticketing/automations, settings — plus a discover tool and `semgrep_account`. Auth: OAuth (agent gets your role) or API token, where a read-only token permits reads only. Every tool call hits the same API route as the platform with the caller's credential, so "if you cannot do something in the platform, the agent cannot". Only admins can trigger agentic workflows; scans and workflows consume credits; "An agent that works on its own needs limits." [P] — [Semgrep blog](https://semgrep.dev/blog/2026/semgrep-mcp-server)
- **Prowler MCP:** `prowler_app_*` (authenticated management tools), `prowler_hub_*` and `prowler_docs_*` (no auth), plus cloud-only `prowler_cloud_*`; row-level security on the server. [P]/[S] — [Prowler architecture](https://docs.prowler.com/developer-guide/lighthouse-architecture); [Prowler MCP docs](https://docs.prowler.com/getting-started/products/prowler-mcp)
- **Wiz MCP:** official docs are login-only. Third-party integration docs describe a remote endpoint (`mcp.app.wiz.io`), OAuth with PKCE, a self-hosted variant configured with a Wiz client ID/secret, and advise scoping the service account to read access on issues and resources. [S] — [Aembit](https://docs.aembit.io/ai-guide/mcp/identity-gateway/supported-servers/wiz/); [StackOne](https://www.stackone.com/connectors/wiz/mcp/)
- **Snyk:** MCP server runs locally inside the Snyk CLI (no hosted remote), ~13 tools covering scan types plus auth tools; browser login plus per-folder trust. [S] — [pkg.go.dev snyk/studio-mcp](https://pkg.go.dev/github.com/snyk/studio-mcp)
- **Datadog:** the Bits Security Analyst API is reachable by agents connected to the Datadog MCP Server. [P] — [Datadog docs](https://docs.datadoghq.com/bits_ai/bits_security_analyst)
- **Vendor guidance on MCP risk (Wiz research):** tool poisoning = instructions in tool metadata; indirect injection via untrusted content such as a README or commit message; treat an MCP server's role like a privileged service account with least privilege. [S] — [Wiz MCP security briefing](https://www.wiz.io/blog/mcp-security-research-briefing)

### Inferences
- The "mirror the user's role through the same API route" design (Semgrep) is the cleanest tenant-scoping story: no second authorisation model to get wrong.
- VectaSec should do the opposite of Vanta on one point: ship **read-only by default with an explicit, separately-consented write scope**, and allow tool-subset selection server-side. For buyers with 0–3 security people, an over-privileged agent is more likely than a carefully governed one.
- A security scanner's MCP output is unusually dangerous to its consumer: finding titles, resource names, topic names, workflow text and MCP tool descriptions are attacker-influenced strings, and the customer's agent often also has code, cloud or ticketing tools (the "lethal trifecta" shape). Mitigations that follow from §7: return scanned strings in clearly typed fields separate from VectaSec-authored text; offer a "sanitised" mode that returns IDs and enumerated attributes with raw strings fetched only on explicit request; never put scanned strings into tool *descriptions*; include a provenance flag on every field.
- VectaSec's own MCP agent-reach map can be dog-fooded: show the customer what their agent could reach through the VectaSec MCP connection.

### Gaps
- Drata MCP: no information found.
- No vendor documentation found on sanitising or provenance-tagging finding text returned through MCP, and no published incident of injection via a security vendor's MCP output. This is an inferred risk grounded in the log-injection research, not an observed exploit.
- Rate limits and audit logging of MCP calls are not documented on the pages read.

---

## 7. Prompt-injection and data-safety issues specific to a scanner

### Takeaway
The consensus in 2025–2026 guidance is that injection cannot be reliably filtered, so systems must be built so a successful injection has no consequence: untrusted text is processed by a model with no tools and a constrained output, and model output never triggers an action or renders active content without deterministic checks or human approval.

### Cited Findings
- **OWASP LLM01:2025 mitigations (seven):** constrain model behaviour; define and validate expected output formats with deterministic code; input and output filtering; privilege control and least privilege (keep functions in application code with the app's own tokens); human approval for high-risk actions; segregate and identify external content; adversarial testing. OWASP states it is unclear whether fool-proof prevention exists. [P] — [OWASP GenAI LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- **OWASP Top 10 for Agentic Applications 2026:** ASI02 Tool Misuse — agents misuse tools they legitimately hold; mitigations are tool permission scoping, argument validation, sandboxing, logging every tool call, and a separate approval tier for destructive operations; "least agency" as a principle. [S] (vendor summaries of the OWASP document) — [Palo Alto Networks](https://www.paloaltonetworks.com/blog/?p=349925); [Aikido](https://aikido.dev/blog/owasp-top-10-agentic-applications)
- **"Design Patterns for Securing LLM Agents against Prompt Injections" (Beurer-Kellner et al., v3 27 Jun 2025):** six patterns — Action-Selector (model picks from a fixed set of actions; results never feed back), Plan-Then-Execute (plan fixed before untrusted data is read), LLM Map-Reduce (isolated tool-less sub-models each process one untrusted item and return constrained output), Dual LLM (privileged model never sees untrusted data; quarantined model does and returns results by reference), Code-Then-Execute, Context-Minimisation. Core principle: once an agent has ingested untrusted input it must be constrained so that "it is impossible for that input to trigger any consequential actions". For a SQL agent over a database with attacker-influenced contents, the recommendation is plan/code-then-execute so results are not processed by the privileged LLM. [P] — [arXiv 2506.08837](https://arxiv.org/html/2506.08837v3)
- **CaMeL** argues Dual LLM alone is incomplete because an attacker can still influence tool *arguments* through the quarantined model; it adds information-flow control. [S] — [arXiv 2503.18813](https://arxiv.org/pdf/2503.18813)
- **Microsoft's layered defence (MSRC, 29 Jul 2025):** preventative and probabilistic — hardened system prompts and Spotlighting (delimiting with randomised delimiters; datamarking by interleaving a marker through untrusted text; encoding e.g. base64); detection — Prompt Shields classifier; impact mitigation — deterministic blocking of exfiltration channels such as markdown image rendering and untrusted links, data governance, and human consent for actions. Stated principle: do not rely on blocking every injection; design so a successful injection has no security impact. [P] — [MSRC blog](https://www.microsoft.com/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
- **Spotlighting numbers (Microsoft Research, 2024, own test setup):** attack success from over 50% to below 2%; encoding strongest; datamarking may not suit code-like inputs. [S][V] — [arXiv 2403.14720](https://arxiv.org/abs/2403.14720)
- **Scanner-specific attack surface is documented:** HTTP URIs, user agents, POST bodies, DNS names, email headers and attempted usernames are attacker-chosen before the defender stores them; "detection becomes the delivery channel". Constrained output cut summarisation injection from 96% to 38% in one study — helpful, not sufficient. [S]/[P] — [arXiv 2605.24421](https://arxiv.org/abs/2605.24421)
- **Deterministic output controls work where filters do not:** Google's fix for the Gemini log-summary injection was to stop rendering hyperlinks. [S] — [The Hacker News](https://thehackernews.com/2025/09/researchers-disclose-google-gemini-ai.html)
- **Security Copilot** lists optional classifier models for jailbreak and indirect prompt injection among its mitigations, alongside content filtering. [P] — [Security Copilot application card](https://learn.microsoft.com/en-us/copilot/security/security-copilot-application-card)

### Inferences
Mapping the patterns to VectaSec's data (topic names, queue names, consumer-group IDs, n8n workflow text, Zapier step text, MCP tool descriptions, gateway route names, header values):
- **Per-item quarantine (Map-Reduce):** each untrusted string is judged by a tool-less call whose output is an enum plus span offsets (e.g. `{label: suspicious_instruction | benign | unclear, spans: [...]}`), validated by schema. No free text flows onward from that call.
- **Never let scanned strings share a context with instructions that matter:** the explainer/triage prompt should receive observation *IDs and typed attributes*; raw strings are included only where essential, datamarked or encoded, length-capped, and declared as data.
- **Model output never triggers anything:** no fix applied, no finding closed, no severity lowered, no ticket filed, no outbound request, without a deterministic check or a human click. VectaSec's DB constraint on citations is exactly this kind of control; extend it with "cited observation IDs must belong to this finding and tenant".
- **Asymmetric trust:** output conditioned on untrusted text may *raise* attention but may not *lower* it.
- **Render safely:** strip links, images and HTML from model output; show scanned strings in a monospace "untrusted" style.
- **Injection is also a detection:** a quarantine call that flags instruction-like text in a tool description or workflow is itself a candidate finding (MCP tool poisoning, workflow tampering).
- **Tenant isolation:** no cross-tenant examples or memories in prompts; per-tenant cache namespaces.

### Gaps
- The NIST AI RMF Generative AI Profile (AI 600-1) was not read in this pass; no claims are made about its content.
- Model-provider guidance pages specifically on handling injection in tool results were not retrieved (search returned only the Citations feature).
- No measured results for these defences on middleware-shaped strings (short identifiers, JSON workflow definitions).

---

## 8. Evaluation

### Takeaway
The credible vendors run a labelled golden set of a few hundred to a few thousand items, score precision separately from recall, and distrust in-product thumbs; public benchmarks exist for SOC investigation and threat-intel reasoning but none was found for posture-graph Q&A or middleware configuration reasoning.

### Cited Findings
- **Semgrep:** 2,000+ findings labelled by security researchers with written reasoning; promptfoo for model comparison; in-product feedback over-stated quality (>90% vs ~55% measured), attributed to feedback friction and survivorship; changes that improved TP agreement often hurt FP agreement. A rotating team of engineers periodically re-reviews. [P] — [Semgrep blog](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/); [Semgrep metrics](https://docs.semgrep.dev/semgrep-assistant/metrics)
- **Wiz:** 200 query/JSON pairs, exact match or manual review; plus random expert sampling of live requests. [P] — [Wiz engineering blog](https://www.wiz.io/blog/askai-text-to-security-graph-query)
- **GitHub Autofix:** 2,300+ alerts on repos with test coverage; automated checks for alert fixed, new alerts, syntax errors, test changes. [P] — [GitHub docs](https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning)
- **Ethyca:** precision/recall/F1 rather than accuracy because positive labels are sparse; an LLM-assisted relabelling pass raised labelled fields from 449 to 825, i.e. the original human ground truth was incomplete. [P] — [Ethyca](https://ethyca.com/news/engineering-llm-data-classifier-metadata-only)
- **RuleForge:** reports calibration of its LLM judge (AUROC 0.75, ECE 0.17) rather than assuming it. [P] — [arXiv 2604.01977](https://arxiv.org/html/2604.01977v1)
- **1Password:** LLM validators and human reviewers agreed on the exact grade only about two-thirds of the time. [P] — [Help Net Security](https://www.helpnetsecurity.com/2026/08/06/1password-ai-generated-vulnerability-patches/)
- **Microsoft Security Copilot:** custom evaluations for groundedness, relevance, coherence, and adversarial sets for jailbreak and prompt injection, with regression tests when changing models; no numbers published. [P] — [Security Copilot application card](https://learn.microsoft.com/en-us/copilot/security/security-copilot-application-card)
- **Public benchmarks:** ExCyTIn-Bench (investigation over Sentinel logs; best reward 0.368 → 0.606 across paper versions); CyberSOCEval (Meta/CrowdStrike, Sept 2025; malware-analysis and threat-intel reasoning; authors say models are "far from saturating" it and that reasoning models gain less than in coding/maths). [S] — [arXiv 2507.14201](https://arxiv.org/abs/2507.14201); [arXiv 2509.20166](https://arxiv.org/abs/2509.20166)
- **Conveyor** gives a hallucination definition but no method. [P] — [Conveyor docs](https://docs.conveyor.com/docs/what-is-conveyors-hallucination-rate)

### Inferences
A workable evaluation set for VectaSec, per feature:
- *Explain/triage:* citation precision (does each cited observation actually support the sentence), citation coverage (share of claims with a citation), unsupported-claim rate — on a few hundred findings labelled by a security engineer with written reasoning.
- *NL query:* execution accuracy (result set equals gold result set) on 200–300 question/query pairs clustered from real usage, plus a "should refuse" subset.
- *Digest/brief:* numeric fidelity (every numeral matches a computed slot) — fully automatable.
- *AI-candidate detection:* precision at the "raise" threshold and recall against seeded cases, reported separately; never a single accuracy number.
- *Fix generation:* apply in a disposable broker/gateway container, run the detector and the proof probe, run a functional smoke test, and test rollback.
- *Injection:* a standing canary suite of adversarial topic names, workflow texts and tool descriptions (persona hijack and split-payload variants, per the 2026 papers), run on every prompt or model change; the pass criterion is "no verdict downgraded, no action field changed".
- LLM judges are useful for cheap screening but need calibration against humans before their scores are trusted (RuleForge, 1Password).

### Gaps
- No public benchmark found for security-graph Q&A, config-diff explanation, or middleware misconfiguration reasoning.
- No vendor publishes citation-precision or groundedness numbers for posture explanations.

---

## 9. Cost and latency practice

### Takeaway
At late-2026 list prices, per-finding explanation is a fraction of a cent on a small model, and stacking prompt caching with batch processing cuts cost several-fold again; the practical question is less "can we afford it" than "which calls justify a large model and which must be on-demand".

### Cited Findings
- **Anthropic list prices (pricing page read 23 Nov 2026), per million tokens input/output:** Haiku 5.5 $0.10/$0.50 (prompts ≤100k tokens; $0.50/$2.50 above); Haiku 4.5 $1/$5; Sonnet 5.5 $2/$10; Opus 5.5 $4/$20; Fable 5.2 $8/$40. [P] — [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing)
- **Prompt caching:** 5-minute cache write 1.25x base input, 1-hour write 2x, cache read 0.1x on most models (0.05x on Opus 5.5 and Sonnet 5.5; 0.025x on Fable 5.1/5.2). Pays for itself after one read (5-minute) or two reads (1-hour). [P] — [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing)
- **Batch API:** 50% off input and output, asynchronous; stacks with caching. Cache hits within a batch are best-effort because requests run concurrently. [P] for discount and stacking — [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing); [S] for best-effort note — search summary of the same docs
- **Tokeniser note:** Claude 4.7-and-later models produce roughly 30% more tokens for the same text. [P] — [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing)
- **Provider's own routing advice:** small model for simple tasks, mid model for most production work, large model for the hardest reasoning; cache repeated context; batch anything not time-sensitive. [P] — [Claude pricing](https://platform.claude.com/docs/en/about-claude/pricing)
- **Wiz** chose a mid-tier model for query generation and avoided an LLM re-ranker (used MMR) for cost and latency. [P] — [Wiz engineering blog](https://www.wiz.io/blog/askai-text-to-security-graph-query)
- **Ethyca:** ~$0.603 per 1,000 fields with one request per field, made affordable by prompt caching; ~32B-parameter open models were sufficient for classification. [P] — [Ethyca](https://ethyca.com/news/engineering-llm-data-classifier-metadata-only)
- **Microsoft Security Copilot** is metered in Security Compute Units; community sources cite about $4 per provisioned SCU-hour and $6 overage; consumption varies per prompt, and pre-built KQL skills are reported cheaper than free natural-language prompts. [S] — [Microsoft FAQ](https://learn.microsoft.com/en-us/security-copilot/faq-security-copilot); [LevelBlue](https://www.levelblue.com/blogs/spiderlabs-blog/the-value-of-microsoft-security-copilot-scu-billing-and-why-agent-design-matters)
- **Semgrep** meters managed scans and agentic workflows in credits. [P] — [Semgrep blog](https://semgrep.dev/blog/2026/semgrep-mcp-server)
- **Agentic patch attempts cost $2–3 each** including validation in the 1Password study. [P] — [Help Net Security](https://www.helpnetsecurity.com/2026/08/06/1password-ai-generated-vulnerability-patches/)
- **Cost is a practitioner complaint:** 86% of cost-related Reddit posts in the SOUPS 2026 study were negative (inference cost, unclear ROI). [P] — [arXiv 2604.09998](https://arxiv.org/html/2604.09998)

### Inferences
- Illustrative arithmetic from the list prices above (my calculation, not a sourced figure): an explanation call of ~3,000 input and ~500 output tokens costs about $0.0006 on Haiku 5.5 and about $0.011 on Sonnet 5.5; batch halves both. A tenant with 2,000 findings explained once on the small model is on the order of a dollar.
- Scan-time versus on-demand split: run at scan time, in batch, only what is (a) keyed on content that changes rarely and (b) shown to most users — per-finding explanation, metadata classification, digest text. Run on demand what is interactive or rarely opened — NL queries, investigations, fix generation, questionnaire answers.
- Cache key = hash of (prompt version, model, sorted observation IDs + their content hashes). If the evidence has not changed, do not re-call. This makes cost proportional to *change*, which VectaSec's change history already tracks.
- Put the stable material first (system rules, schema, detector description, few-shot examples) so it is cacheable; put per-finding evidence last.
- Routing: small model for classification, extraction and per-item quarantine; mid model for explanation, query generation and digests; large model only for multi-step investigation and fix synthesis. Keep the rule-based fallback for every feature so a provider outage or budget cap degrades gracefully.
- Per-tenant monthly AI budget with hard stop and visible meter addresses the cost distrust directly and avoids the SCU-style surprise.

### Gaps
- No vendor publishes per-feature AI unit cost or latency targets.
- OpenAI and Google pricing/caching terms were not checked in this pass.

---

## 10. What buyers and practitioners want and distrust

### Takeaway
Practitioners value speed on drudge work (triage notes, queries, reports) and strongly distrust reliability, data handling, autonomy and cost; the single most requested trust feature is being able to see how the AI reached its conclusion, and almost nobody grants unsupervised action.

### Cited Findings
- **Reddit study (SOUPS 2026; 892 posts, mostly r/cybersecurity, Dec 2022–Sep 2025):** efficiency perceptions 84% positive but with "verification overhead"; reliability 95% negative (hallucination, non-determinism); security/privacy 88% negative (data leaking to commercial models; LLM as new attack surface); autonomy 87% negative (advice-only preferred); cost 86% negative. Only 5 posts described fully autonomous mitigation. Barriers include overpromising vendors and a preference for traditional automation. Authors conclude LLMs are "promising yet insufficiently trustworthy" for high-stakes SOC work. Limitation: self-selected Reddit users. [P] — [arXiv 2604.09998](https://arxiv.org/html/2604.09998)
- **Prophet Security survey 2026 (250+ respondents; sponsored content):** 40% use AI daily, 56% testing; 72% say it cut investigation time by ≥25%; 57% require human review of every AI decision before closing an alert; none grant full autonomy; top roadblocks are data privacy/model training (44%) and explainability (41%); 72% of AI users tried to build internal tools and 46% of those projects were abandoned or replaced. [P] of a sponsored article — [The Hacker News, 27 Aug 2026](https://thehackernews.com/2026/08/what-data-says-about-ai-in-security.html)
- **Torq 2026 AI SOC Leadership Report (450+ leaders; vendor):** 46% say seeing how AI reaches its conclusions would be the single biggest confidence booster; leaders trust AI to analyse and recommend far more than to act. [S] — [NHI Mgmt Group summary](https://nhimg.org/articles/ai-in-the-soc-is-creating-a-trust-and-control-gap/)
- **SANS 2026 AI survey (via vendor blog):** adoption is outpacing maturity and trust. [S] — [Swimlane](https://swimlane.com/blog/sans-ai-2026-soc-trust/)
- **Rapid7/Omdia 2026 (500 professionals):** titled "AI Is Working in the SOC. The Question Is Whether You Can Trust It"; executives 1.6x more likely than practitioners to be highly concerned about AI governance. [S] — [Rapid7](https://www.rapid7.com/resources/ai-in-the-soc-omdia-report-2026/)
- **Academic caution on explanations:** "Too Much to Trust?" proposes a trust–explainability curve in which explanations can become a burden depending on context. [S] — [arXiv 2503.02065](https://arxiv.org/html/2503.02065v2)
- **Product reviews:** Security Copilot KQL "sometimes wrong or uses the wrong table"; Intezer's review notes inconsistent results needing manual checks; Wiz reviewers praise AI search while one reports non-answers. [S] — [G2](https://www.g2.com/survey_responses/microsoft-security-copilot-review-14014476); [Intezer](https://intezer.com/guides/soc-as-a-service/microsoft-security-copilot); [G2 Wiz](https://www.g2.com/products/wiz-wiz/reviews)

### Inferences
- For a buyer with 0–3 security people the AI is standing in for a colleague they do not have, which raises both the value of explanation and the cost of a confident error: there is nobody to catch it. "Cites its evidence, shows the query, never acts alone, and has a visible off switch and budget" is a selling point, not a limitation.
- Verification overhead is the real tax. Every AI output should be one click from the observations behind it, so checking takes seconds.
- Explanations should be short by default with evidence on demand (the trust–explainability curve); long AI prose is itself a distrust signal.
- State data handling plainly in-product: which fields leave the tenant, to which provider, with what retention; offer a metadata-only mode and bring-your-own-key/model (Prowler's model) for cautious buyers.

### Gaps
- All surveys found are vendor-sponsored or SOC-focused; nothing specific to SMB buyers of posture tools or to integration-layer security.
- G2/PeerSpot comments specifically about Vanta, Drata, Orca or Snyk AI features were not retrieved.
- Full Torq, SANS and Omdia reports were not opened.

---

## 11. Ranked list: the AI capabilities most worth building for VectaSec

### Takeaway
The highest-value, lowest-risk work extends the existing cited-observation contract to more surfaces (explain, diff, digest, question-answering); detection and remediation by model are worth building only as candidate generators behind deterministic gates. The ranking below is the researcher's inference from the evidence in sections 1–10, not a sourced ranking.

### Cited Findings
- Evidence base for the ranking: summarisation and reporting are heavily used and liked ([arXiv 2604.09998](https://arxiv.org/html/2604.09998)); explainability is the top trust lever ([NHI Mgmt Group summary of Torq](https://nhimg.org/articles/ai-in-the-soc-is-creating-a-trust-and-control-gap/)) [S]; text-to-query reaches roughly 80% without heavy investment ([Wiz](https://www.wiz.io/blog/askai-text-to-security-graph-query)) [P]; model triage is strong at confirming true positives and weak at dismissing false ones ([Semgrep](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/)) [P]; roughly one in four AI patches is a clean fix ([Help Net Security](https://www.helpnetsecurity.com/2026/08/06/1password-ai-generated-vulnerability-patches/)) [P]; injected text most easily defeats summarisation and pushes verdicts toward benign ([arXiv 2605.24421](https://arxiv.org/abs/2605.24421)) [P]; no agent should be able to act on untrusted input ([arXiv 2506.08837](https://arxiv.org/html/2506.08837v3)) [P]; no shipped LLM review of workflow definitions was found ([search result](https://socket.dev/npm/package/@securevector/n8n-nodes-securevector)) [S].

### Inferences

Ranked by (value to a 0–3 person team) x (fit with the evidence ledger) / (risk).

1. **"Why this matters here" finding narrative (extend existing triage).**
   Grounding: input is the finding's numbered observations plus graph-path edge IDs, fix-impact preview result and proof-probe result; output schema requires a citation on every sentence; DB constraint checks IDs belong to the finding and tenant. Generated at scan time in batch, cached by evidence hash; rule-based fallback.
   Main failure to guard: a fluent sentence whose citation does not actually support it (citation precision), and scanned strings steering the text. Measure citation precision on a labelled set; pass typed attributes rather than raw strings.

2. **Ask-the-graph: natural-language question to a typed query plan.**
   Grounding: model emits a JSON query object over an enumerated vocabulary (node types, edge types, properties, allowed values, time windows); schema-validated; executed by deterministic code under the caller's tenant scope; UI shows the plan in plain words, the result rows and an editable form. Retrieve similar curated examples per question (Wiz pattern). Prose answer cites row IDs.
   Main failure: a valid query that answers a different question, or an empty result presented as "none found". Echo the interpreted question, distinguish "no rows" from "could not translate", keep an execution-accuracy golden set.

3. **Change explainer over configuration history.**
   Grounding: deterministic diff produces numbered hunks with before/after values and actor/time; model classifies each hunk (security-relevant / neutral / unclear) from an enum and writes one cited sentence; links to findings opened or closed by the same change.
   Main failure: inventing intent ("someone disabled auth to debug") or missing a risky change described in benign words. Forbid intent claims in the schema; any hunk touching a detector-relevant key is flagged deterministically regardless of the model.

4. **Weekly digest, executive summary and breach-day brief prose.**
   Grounding: all counts, deltas, rankings and deadlines computed in code and passed as named slots; model arranges and words them; post-check that every numeral and resource name in the output matches a slot; links stripped.
   Main failure: invented or mismatched numbers and trends; injected text surfacing in an email to an executive. Numeric verifier is a hard gate; fall back to the template on failure.

5. **Semantic review of n8n/Zapier workflows and MCP tool descriptions (AI-suspected candidates).**
   Grounding: per-item quarantined, tool-less call; output is enum labels plus character spans (e.g. hidden instruction, data sent to an external host, credential handling in free text, description/behaviour mismatch); a candidate becomes a finding only when a deterministic check corroborates (the span exists; the destination host is actually in the node config; the tool's declared scopes exceed its description) or a human confirms. Stored as its own observation type with the model and prompt version.
   Main failure: the payload under review tells the model it is safe. A "benign" label carries no weight and never suppresses a deterministic detector; run an adversarial canary suite on every prompt/model change.

6. **Customer-specific fix parameterisation with deterministic verify.**
   Grounding: model fills parameters of a vetted template from the guided-fix library using the resource's stored observations; output is passed through fix-impact preview and least-privilege dry run before display; never executed by VectaSec; verification is rescan plus proof probe; rollback snippet generated from the stored pre-change state.
   Main failure: a fix that silences the detector without closing the path, or that breaks a consumer. Verify the exploit path, not the detector; show the impact preview next to the fix; fix direction comes from detector metadata, never from scanned text.

7. **Metadata-first sensitive-data and purpose classification.**
   Grounding: one small-model request per field over topic, queue, stream, schema field and header names with types and any description; enum taxonomy; cached; deterministic matchers run first and the model only handles ambiguous names. Payload sampling is a separate, opt-in mode.
   Main failure: false positives that flood findings, and skipped fields. Use labels to adjust priority and feed toxic-flow weighting rather than to open findings; measure precision and recall on a labelled tenant.

8. **Posture-backed questionnaire and auditor answers.**
   Grounding: answers assembled only from ledger observations, the access register and the generated benchmark; each answer carries observation IDs and "as of" scan time; explicit "no evidence" response; human approval before export.
   Main failure: over-claiming ("all brokers enforce TLS") from partial coverage or stale scans. Require coverage statements (N of M resources scanned) in the answer schema; refuse universal claims without full coverage.

9. **Bounded read-only investigation timeline.**
   Grounding: plan-then-execute — the plan is chosen from the trigger type before any scanned text is read; tools are VectaSec's own read APIs (change history, findings, graph neighbours, canary hits, proof results, leaver data); fixed step and token budget; every step logged with arguments and result hash; output is a timeline in which every entry cites an ID, plus a hypothesis section listing supporting and missing evidence.
   Main failure: a plausible but wrong root cause accepted because there is no one to challenge it. Label as hypothesis, show what would falsify it, never auto-close anything.

10. **Remote MCP server for the customer's own agent.**
    Grounding: OAuth, the caller's role enforced by the same API routes, read-only default, server-side tool subsets, separate consent for any write tool; scanned strings returned in typed, provenance-flagged fields, with a sanitised mode returning IDs and enums only; full call audit log.
    Main failure: VectaSec's finding text becomes an injection path into an agent that also holds code or cloud tools. Never place scanned strings in tool descriptions or in VectaSec-authored summary fields; document the risk to customers.

11. **Org context and triage memories.**
    Grounding: customer-written statements ("staging brokers are in account X", "this Zap is owned by finance") stored as dated, attributed, expirable records and cited like observations when they influence priority (Semgrep Memories, Datadog Bits.md pattern).
    Main failure: a memory that silently suppresses a real issue, or a poisoned memory. Memories may lower priority but not close findings; show which memory influenced each decision; expiry by default.

12. **Owner and environment suggestion.**
    Grounding: suggest owner/team/environment from deterministic signals first (credential owner, creator in change history, tags, naming conventions), with the model only reconciling conflicting signals; output cites the signals; one-click confirm writes a human-attested record.
    Main failure: confident misassignment that routes a critical finding to the wrong person. Show as a suggestion with its evidence until confirmed.

13. **Attack-path and agent-reach narration.**
    Grounding: the toxic flow or MCP reach path is computed by the graph; the model narrates the ordered edge list, one cited sentence per edge, with no added steps permitted by schema.
    Main failure: narrating a step that is not in the path. Validate that the cited edge sequence equals the computed path.

14. **Internal detector-authoring assistant (advisory to candidate detector).**
    Grounding: RuleForge-style pipeline — several candidates per advisory, generated tests, replay against recorded customer-shaped fixtures and the existing detector corpus, human review of every detector before release. Internal tool, not customer-facing.
    Main failure: detectors that match nothing or fire broadly; a weak LLM judge trusted as a gate. Replay results and human review decide, not the judge score.

15. **Evaluation and safety harness (enabler for all of the above).**
    Grounding: per-feature golden sets, citation precision and coverage, execution accuracy, numeric fidelity, injection canary suite, per-tenant budget meter, prompt and model version recorded on every stored output.
    Main failure: trusting in-product thumbs or an uncalibrated LLM judge as the quality signal.

Deliberately not recommended on current evidence: any model-authored finding without corroboration; any model-initiated change to a customer system; model-driven finding closure or severity reduction; auto-merging generated fixes.

### Gaps
- The ranking has not been tested with customers; value weights are the researcher's judgement.
- Expected success rates for items 5 and 6 on middleware configuration are unknown; no external data exists and VectaSec would need to measure them.
- Items 3 and 5 had no directly comparable shipped feature found; novelty is inferred from absence in search results.
