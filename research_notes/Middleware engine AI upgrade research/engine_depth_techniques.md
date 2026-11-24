# Engine depth: techniques of the best posture engines (half A) and effective-permission / exposure semantics of middleware (half B)

State of knowledge: 23 November 2026. Evidence labels used on every finding:

- **[P]** = read from the primary page itself in this session (official docs, spec, or vendor's own page).
- **[S]** = seen only in a search-result summary; the page was not opened. Treat as a lead, not as verified.
- Version tags give the product version the page documented when read.

Anything I could not source this session is in a Gaps list, not in Cited Findings. Engineering recommendations are in Inferences and are my reasoning, not sourced fact.

---

# HALF A: TECHNIQUES

## A1. Graph query engines in security products

### Takeaway
The pattern shared by every serious engine is the same: normalise everything into a property graph, add a small number of *derived* edges that encode evaluated semantics (for example `STS_ASSUMEROLE_ALLOW`, `CAN_ACCESS` from an `Internet` sentinel node), then express attack paths as short declarative graph queries with findings overlaid on the nodes. "Choke points" are, in the one product that defines them precisely (BloodHound Enterprise), simply the edges crossing into the crown-jewel set, ranked by how many principals sit behind them.

### Cited Findings
- **Prowler Attack Paths** runs against a property graph built by Cartography and enriched with Prowler findings. Prowler adds: a `ProwlerFinding` node (`status`, `severity`, `check_id`), an `Internet` sentinel node, an `(Internet)-[:CAN_ACCESS]->(resource)` exposure edge, `(resource)-[:HAS_FINDING]->(:ProwlerFinding)`, `TRUSTS_AWS_PRINCIPAL`, and `STS_ASSUMEROLE_ALLOW`. [P] — [Prowler developer guide: attack paths queries](https://docs.prowler.com/developer-guide/attack-paths-queries.md)
- Prowler query definition is a Python dataclass with fields `id`, `name`, `short_description`, `description`, `provider`, `cypher`, `parameters`, optional `attribution`; predefined queries live in `api/src/backend/api/attack_paths/queries/{provider}.py`; the only bound parameter is `$provider_uid`; every `MATCH` chains from the account anchor, and "path connectivity is the isolation boundary". The documented patterns are fixed-length hops; the finding overlay is an `OPTIONAL MATCH (n)-[:HAS_FINDING]-(pf {status:'FAIL'})`. [P] — [Prowler developer guide](https://docs.prowler.com/developer-guide/attack-paths-queries.md)
- Prowler tenant isolation for graph queries: the runner injects a `_Provider_{uuid}` label into every node pattern via `cypher_sanitizer.py`, with a post-query filter for edge cases; internal labels must not appear in query text. The page does not state timeouts or row caps. [P] — [Prowler developer guide](https://docs.prowler.com/developer-guide/attack-paths-queries.md)
- Prowler queries are read-only openCypher v9 so they run on both Neo4j and Amazon Neptune; users can write custom openCypher in the app; custom queries are described as sandboxed with safety limits; Cartography ingestion always runs in a temporary Neo4j database even if Neptune is the sink. [S] — [Prowler docs search summary](https://docs.prowler.com/developer-guide/attack-paths-queries), [Prowler app attack paths](https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths)
- Prowler stores list-typed properties as child item nodes (`<ParentLabel><Property>Item` with a `HAS_<PROPERTY>` edge and a `value` property) so that list members can be matched in Cypher. [P] — [Prowler developer guide](https://docs.prowler.com/developer-guide/attack-paths-queries.md)
- **Cartography** sync model: each sync run has an `update_tag` (Unix timestamp of sync start); every intel module stamps `lastupdated` on all nodes and relationships; at the end of the run a cleanup job deletes anything whose `lastupdated` is stale; a module is `get` then `load` then `cleanup`; analysis jobs `MERGE` derived relationships then delete edges whose `lastupdated` differs from the current tag. [S] — [Cartography: writing intel modules](https://cartography-cncf.github.io/cartography/dev/writing-intel-modules.html), [Cartography ops guide](https://lyft.github.io/cartography/ops.html)
- **BloodHound Enterprise** defines a choke point as any edge into the collection of Tier Zero nodes, "the optimal location to block the largest number of Attack Paths". Exposure is reported as a count and a percentage of principals with a Tier Zero attack path. [S] — [BloodHound glossary](https://bloodhound.specterops.io/resources/glossary/overview.md)
- BloodHound Enterprise analysis evaluates how abusable relationships cross boundaries between Tier Zero and user-defined Privilege Zones; it generates one choke-point view per environment, organised by finding category with the number of exposed principals; analysis is triggered by schedule, by request, or by waiting ingest jobs. The page gives no formula. [P] — [BloodHound: analysis](https://bloodhound.specterops.io/analyze-data/findings/analysis.md)
- **BloodHound OpenGraph** (v8, July 2025) lets third parties ingest custom nodes, edges and properties from other systems; custom node types can be registered through `POST /api/v2/custom-nodes`; SpecterOps published an MSSQL OpenGraph extension as a worked example. [S] — [OpenGraph overview](https://bloodhound.specterops.io/opengraph/overview.md), [BloodHound v8 blog](https://specterops.io/blog/2025/07/29/bloodhound-v8-usability-extensibility-and-opengraph/), [Adding MSSQL to BloodHound with OpenGraph](https://specterops.io/blog/2025/08/04/adding-mssql-to-bloodhound-with-opengraph/)
- **Wiz** describes its Security Graph as the database, the normalising data model and the analysis layer at once; a "toxic combination" is a resource that is very likely to be compromised and would have significant business impact, surfaced as a critical Wiz Issue. Wiz stores the graph in Amazon Neptune and its "risk engines" traverse it to link risk factors. [S] — [Wiz: anatomy of a toxic combination](https://wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk), [AWS Database Blog: how Wiz uses Neptune](https://aws.amazon.com/blogs/database/the-world-is-a-graph-how-wiz-reimagines-cloud-security-using-a-graph-in-amazon-neptune)
- Wiz says that in 1 of every 6 environments monitored at runtime, adding observed network connections surfaced a high or critical attack path that configuration-only analysis missed (vendor-reported). [S] — [Wiz: runtime signals in the security graph](https://wiz.io/blog/runtime-signals-in-security-graph)
- **Steampipe / Powerpipe**: the data model is SQL tables over live APIs; a `control` is an HCL resource whose `sql` returns rows; a `benchmark` groups controls or other benchmarks to any depth; controls live in a mod and run with `powerpipe benchmark run` / `powerpipe control run`. Steampipe-side mods are deprecated in favour of Powerpipe. [S] — [Powerpipe: custom controls](https://powerpipe.io/docs/build/writing-controls), [Powerpipe control reference](https://powerpipe.io/docs/powerpipe-hcl/control), [Steampipe: custom controls](https://steampipe.io/docs/mods/writing-controls)

### Inferences
- VectaSec does not need a graph database to get this. At small-company scale (thousands of nodes, tens of thousands of edges) the same model fits in Postgres tables `nodes(id, kind, props jsonb)` and `edges(src, dst, type, props jsonb)` plus recursive CTEs, or in-process `networkx`. The valuable part is the *derived-edge layer*, not the storage engine.
- The Prowler design is the most directly copyable: (1) sentinel `Internet` node, (2) evaluated permission edges rather than raw grant rows, (3) findings as nodes attached to resources, (4) each attack-path rule as a declarative query record with metadata. VectaSec's three hard-coded attack-path rules become rows in a registry, and middleware-specific derived edges (`CAN_CONSUME`, `CAN_PRODUCE`, `CAN_INVOKE_TOOL`, `HOLDS_CREDENTIAL`, `ROUTES_TO`, `TRIGGERS`) are the differentiator no cloud-centric graph has.
- Choke-point ranking can be computed without a formula from a vendor: for each edge on any path from an entry node (Internet, anonymous consumer, guest user, no-auth webhook) to a crown-jewel node (sensitive topic/queue/keyspace, admin tool), count distinct (entry, target) pairs whose every path uses that edge (a dominator / min-cut computation) or, more cheaply, count paths through the edge. Present "fix this one binding and N paths disappear".
- BloodHound OpenGraph is also a distribution channel: exporting VectaSec's middleware graph in OpenGraph format would let customers who already run BloodHound see Kafka/RabbitMQ/Kong paths next to AD paths. This is an inference about opportunity, not something a source proposes.

### Gaps
- No Wiz primary engineering source was opened; graph schema, edge computation and path search algorithms are not public in what I found. All Wiz statements are vendor marketing seen in summaries.
- JupiterOne (J1QL, entity/relationship model) was not researched this session; no source.
- No published formula for BloodHound exposure/impact or choke-point ranking was found; the analysis page explicitly defers to another page I did not open.
- Prowler's numeric sandbox limits for custom Cypher (timeout, row cap) and the mechanism enforcing read-only were not on the page read.
- Cartography's own schema docs were not opened; the sync semantics above are from search summaries.

---

## A2. Effective-permission engines

### Takeaway
There are three tiers of rigour: SMT-based provable reasoning (Zelkova, Tiros, Cedar Analysis), local simulation of the authoriser plus graph search (PMapper), and pattern matching on policy text (Cloudsplaining). For Kafka, RabbitMQ, Redis, NATS and Kong a theorem prover is unnecessary: each has a small, fully documented evaluation function over finite principals and enumerable resources, so a faithful *simulator per system* plus enumeration gives exact answers.

### Cited Findings
- **Zelkova** (FMCAD 2018, AWS) encodes IAM policy semantics into SMT and its core operation is checking whether one policy is less-or-equally permissive than another; the encoding uses theories of strings, regular expressions, bit vectors and integers and runs on multiple solvers including Z3 and CVC4; the authors describe the encoding as sound, in contrast with syntactic heuristics. IAM Access Analyzer for S3 is one of the services built on it. [S] — [Zelkova FMCAD 2018 paper](https://cs.utexas.edu/~hunt/FMCAD/FMCAD18/papers/paper3.pdf), [AWS Security Blog on Zelkova](https://aws.amazon.com/blogs/security/protect-sensitive-data-in-the-cloud-with-automated-reasoning-zelkova)
- **PMapper** builds a graph whose nodes are IAM users and roles and whose edges mean "principal A can access principal B" (for example via `sts:AssumeRole`); it answers queries with a local simulation of AWS authorisation and also checks whether the principal can reach another principal that already has the access; a principal is an admin if it can effectively call any action on any resource, and privilege escalation is a non-admin with an edge path to an admin. [S] — [PMapper repository](https://github.com/nccgroup/PMapper), [DEF CON forum description](https://forum.defcon.org/node/237245)
- In a Palo Alto Unit 42 comparison, PMapper detected 77% of privilege-escalation cases, Pacu 68% and Cloudsplaining 61%; Unit 42 attributes Cloudsplaining's residual false positives after remediation partly to it not evaluating the effective permissions (it ignored the deny-based remediation policy). [S] — [Unit 42: IAM-Deescalate](https://unit42.paloaltonetworks.com/iam-deescalate/)
- **Cedar**: the symbolic compiler translates Cedar policies to SMT-LIB with an encoding described as sound, complete and decidable; the language was modelled in Lean and properties of the design proved; AWS open-sourced Cedar Analysis tooling for verifying policies. Rego, by contrast, has no decidable procedure that always answers policy-inclusion questions. [S] — [Cedar paper (arXiv 2403.04651)](https://arxiv.org/abs/2403.04651v2), [How We Built Cedar (arXiv 2407.01688)](https://arxiv.org/pdf/2407.01688), [AWS Open Source Blog: Cedar Analysis](https://aws.amazon.com/blogs/opensource/introducing-cedar-analysis-open-source-tools-for-verifying-authorization-policies)
- **Kubernetes RBAC** permissions are purely additive ("there are no deny rules"); a RoleBinding may reference a ClusterRole, which is then scoped to the binding's namespace; a ClusterRoleBinding grants cluster-wide. [P] (Kubernetes docs; page version not confirmed, navigation listed v1.33 to v1.37) — [Kubernetes: Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- A real-world precedent for "prover over a YAML policy" at small scale: NVIDIA's OpenShell dev note (9 Nov 2026) says it evaluates policy with Rego via the Rust engine `regorus` and gets analysis by maintaining a prover model for the supported YAML structure with an SMT solver as the decision procedure; it is evaluating Cedar. [S] — [NVIDIA OpenShell dev note](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-11-09-cedar-policy-language.md)

### Inferences
- What is practical without a theorem prover, in increasing cost:
  1. **Concrete simulator** per system: a pure function `decide(principal, operation, resource, context) -> allow/deny + matching rule ids`, implementing the documented evaluation order (half B). This is the PMapper approach and is exact for concrete queries.
  2. **Enumeration**: principals and resources in a scan are finite, so `who_can(op, resource)` = filter over known principals; `what_can(principal)` = filter over known resources. Complexity is principals x resources x rules, trivially cheap here.
  3. **Pattern-level reasoning for unseen resources**: grants are globs/regex/prefixes, so "can principal P reach *any* resource matching pattern S, including ones not yet created" is language intersection. For Kafka (literal, prefix, `*`) and NATS (token wildcards) this is closed-form. For RabbitMQ regex and Redis globs, convert to automata (for example with a regex-to-DFA library) and test intersection/emptiness. That gives Zelkova-style "is X at most as permissive as Y" answers for these small languages with no SMT.
  4. Only if customer-authored conditions enter the model would an SMT solver (Z3 Python bindings) be worth it.
- Store the *evaluated* result as derived edges with provenance: `(principal)-[CAN_READ {via: [acl_id...], because: "prefixed ALLOW, no matching DENY", confidence}]->(topic)`. The flat (identity, action, target, wildcard) rows stay as the raw layer; the derived layer is what detectors and the graph consume.
- The Unit 42 result is the argument for doing this: the tool that pattern-matched text scored lowest and kept flagging remediated principals. VectaSec's current flat rows are in the Cloudsplaining tier.
- Kubernetes RBAC is the easy case (additive only), and the same simulator shape covers it if VectaSec ever adds a Kubernetes connector.

### Gaps
- Cloudsplaining's internals, rbac-tool, rakkess and kubectl-who-can were not opened; no sourced description of their algorithms. (From recall only, unverified: they enumerate bindings and expand rules; `kubectl auth can-i --as --list` is the server-side equivalent.)
- The rest of the Kubernetes RBAC page (aggregated ClusterRoles, `resourceNames` limits, `escalate`/`bind`/`impersonate`) was truncated before it could be read; those details are not cited.
- The Cedar Analysis blog body could not be retrieved (page returned navigation only), so the specific property list and solver are not confirmed.
- OPA partial evaluation as an effective-permission technique was not researched.

---

## A3. Policy-as-code and custom rule languages

### Takeaway
For a small-company user the realistic choice is declarative YAML with a fixed operator vocabulary (Checkov-style: attribute conditions plus "is connected to" graph conditions), with an expert escape hatch (SQL or a graph query). General-purpose languages (Rego, Python checks) are the hardest to write and the hardest to sandbox; YAML rules need no sandbox at all because they are data interpreted by your engine.

### Cited Findings
- **Checkov YAML custom policies**: metadata `id`, `name`, `category`, optional `guideline`, optional `severity`; a single `definition` object which is an attribute block (`cond_type: attribute`, `resource_types`, `attribute`, `operator`, `value`), a connection block (`cond_type: connection`, `resource_types`, `connected_resource_types`, `operator: exists | not_exists | one_exists`), a resource block, or `and`/`or`/`not` nesting; `cond_type: filter` scopes by resource type at the top level. Operators include `equals`, `regex_match`, `exists`, `contains`, `within`, `starting_with`, `subset`, numeric comparisons, list-length operators, `intersects`, `range_includes`, CIDR subset, and a `jsonpath_` prefix applicable to any operator. [P] — [Checkov: YAML custom policies](https://www.checkov.io/3.Custom%20Policies/YAML%20Custom%20Policies.html)
- **Prowler custom checks** are Python: loaded from a folder with `-x` (or an S3 URI), one subfolder per check, check name must begin with its service name, and a mandatory `<check_name>.metadata.json`; a separate `--custom-checks-metadata-file` YAML can override Severity, CheckTitle, Risk, RelatedUrl and Remediation of existing checks. [S] — [Prowler misc tutorial](https://docs.prowler.com/user-guide/cli/tutorials/misc), [Prowler checks developer guide](https://docs.prowler.com/developer-guide/checks), [Prowler custom checks metadata](https://docs.prowler.com/user-guide/cli/tutorials/custom-checks-metadata)
- **Powerpipe / Steampipe**: a custom control is SQL returning rows inside an HCL `control` resource; `param` blocks are allowed only on controls that specify `sql`. [S] — [Powerpipe control reference](https://powerpipe.io/docs/powerpipe-hcl/control)
- **Prowler custom graph queries**: customers write openCypher in the app; isolation is enforced by rewriting the query to inject a per-provider label into every node pattern, plus a post-query filter. [P] — [Prowler developer guide](https://docs.prowler.com/developer-guide/attack-paths-queries.md)
- **Kong ACL plugin** from Gateway 3.16 supports expression-based `allow_when` / `deny_when`; a `deny_when` expression that fails to compile or evaluate returns 500 (fails closed). This is a current example of a vendor embedding an expression language with defined failure behaviour. [P] (Kong Gateway 3.16) — [Kong ACL plugin](https://developer.konghq.com/plugins/acl/)
- Cedar vs Rego: AWS reports Cedar evaluation 42 to 60 times faster than Rego (vendor figure, not independently verified); Rego is a general-purpose language without a decidable inclusion procedure. [S] — [AWS Security Blog: migrating from OPA to Verified Permissions](https://aws.amazon.com/blogs/security/migrating-from-open-policy-agent-to-amazon-verified-permissions), [Styra: comparing OPA/Rego to Cedar and Zanzibar](https://styra.com/?p=44737)

### Inferences
- Recommended shape for VectaSec: a YAML rule = `id`, `title`, `severity`, `applies_to: [resource kinds]`, `where:` (attribute conditions with a Checkov-like operator set and JSONPath into the raw config), optional `connected:` (edge type + target kind + conditions on the target, which reaches the derived effective-permission edges), `observation:` template (keeps the existing cited-observation contract), `controls:` mapping. Because the rule is interpreted, the only sandboxing needed is a regex engine with linear-time guarantees (RE2 via `google-re2`) or a regex timeout, a cap on rule count and on JSONPath depth.
- If an expression language is wanted for the `where` clause, CEL is the conventional low-risk choice (non-Turing-complete by design, used for Kubernetes admission policies); a Python implementation exists (`cel-python`). This is from recall; I did not verify CEL claims this session.
- Never run customer Python in the scan worker. Prowler's Python custom checks are acceptable for a CLI the customer runs themselves, not for a multi-tenant SaaS.
- Testing customer rules: ship a "dry run against last scan" that returns matched resources and the observation text before the rule is enabled, and let rules carry inline `tests:` with a resource fixture and expected pass/fail (the Semgrep/OPA convention, see A9).
- Graph rules for customers: offer the three or four parameterised templates ("any path from {entry kind} to {resource tagged X} of length <= N") rather than raw Cypher/SQL at first; Prowler's label-injection approach shows the isolation work that raw queries demand.

### Gaps
- CEL: no source read this session (search returned nothing relevant). Claims about termination guarantees and cost limits are unverified recall.
- OPA/Rego sandboxing (built-in restrictions, `http.send` disabling, timeouts) and `opa test` were not researched.
- Semgrep-style YAML rule schema was not read (testing page redirected and was not re-fetched).
- No comparative usability study of which rule language non-experts write most successfully was found; the "YAML is easiest" claim is my judgment.
- How Checkov custom policies are loaded and tested was not on the page read.

---

## A4. Reachability and exposure analysis

### Takeaway
State-of-the-art reachability is static: encode network semantics in logic and ask a solver which flows are feasible, sending no packets (AWS Tiros / VPC Reachability Analyzer; Batfish does similar with Datalog). The most useful increment on top is validation with observed or probed traffic, which Wiz reports finds paths configuration alone misses.

### Cited Findings
- **Tiros** (CAV 2019) is a static reachability tool that encodes AWS networking semantics into logic and uses up to three reasoning engines: the Datalog solver Souffle, the SMT solver MonoSAT, or the first-order prover Vampire. It sends no packets. VPC Reachability Analyzer uses the Tiros formal model of VPC networking to decide whether a destination is reachable from a source. [S] — [Tiros paper, Springer](https://link.springer.com/chapter/10.1007%2F978-3-030-25543-5_14), [Amazon Science: reachability analysis for AWS-based networks](https://cdn.amazon.science/3c/1d/f40c8400440ab085e8bd77b61e45/reachability-analysis-for-aws-based-networks.pdf), [AWS News Blog: VPC Reachability Analyzer](https://aws.amazon.com/blogs/aws/new-vpc-reachability-analyzer/)
- The Tiros paper characterises Batfish (and SyNET) as similar to its Datalog approach, letting users express whole-network reachability queries in a logic language, with published results on small but complex routing scenarios of a few dozen routers. [S] — [Tiros paper](https://link.springer.com/chapter/10.1007%2F978-3-030-25543-5_14)
- Wiz layers live network connections from workloads into the graph to validate attack paths (vendor-reported 1-in-6 figure, see A1). [S] — [Wiz runtime signals blog](https://wiz.io/blog/runtime-signals-in-security-graph)
- Wiz example of config-plus-exposure narrowing: 171 misconfigured machines reduced to 17 that were actually internet-exposed and exploitable (vendor example via secondary source). [S] — [Security Scientist: Wiz toxic combinations Q&A](https://www.securityscientist.net/blog/12-questions-and-answers-about-wiz-toxic-combinations/)
- Application-layer "reachability" facts that are fully config-derivable for middleware (each cited in half B): RabbitMQ `guest` is loopback-only unless `loopback_users` is changed; an Istio workload with no AuthorizationPolicy accepts all requests; a Kong route's auth plugin with `config.anonymous` set does not reject failed credentials; an n8n Webhook node with Authentication `None` is callable by anyone with the URL and an empty IP allowlist admits all IPs.

### Inferences
- VectaSec's existing external exposure scan with a DNS ownership gate (in the repo's commit history) is the probe half. The upgrade is to fuse the two halves into a three-valued exposure attribute per listener/route: `config_exposed` (derived from listener binding, security groups, gateway route), `probe_confirmed` (reachable from outside, with timestamp and what was observed), and `auth_effective` (from half-B evaluation). The combination "config says private, probe says reachable" is itself a high-value finding; "config says public, probe failed" lowers priority without suppressing.
- For a small engine, reachability does not need Datalog: model `Internet -> load balancer/ingress -> gateway route -> service -> broker listener` as edges with predicate properties (port, CIDR, auth mode) and do a filtered BFS. Reserve the formal treatment for cloud VPC semantics, where calling the provider's own analyser (VPC Reachability Analyzer / Network Access Analyzer) is cheaper than re-implementing it.
- Safe probes for middleware that require no credentials and change nothing: TCP/TLS handshake and certificate read; AMQP protocol header and `connection.start` mechanisms list; Kafka `ApiVersions` request; Redis `PING`/`HELLO` unauthenticated response class (`NOAUTH` vs success); NATS `INFO` line (advertises `auth_required`, `tls_required`); MCP unauthenticated request to observe 401 plus `WWW-Authenticate` (see B7). These are from protocol knowledge, not sourced this session; each should be checked against the protocol docs before implementation.

### Gaps
- Batfish's own documentation was not opened; its description here is second-hand from the Tiros paper.
- No source was found on how vendors combine a config-derived verdict with a probe result into one confidence value.
- AWS Network Access Analyzer was not researched.

---

## A5. Risk scoring beyond severity

### Takeaway
The consensus model is layered rather than a single formula: known exploitation (KEV) overrides everything, predicted exploitation (EPSS) orders the rest, and environment context (exposure, privilege, data sensitivity, blast radius) decides what is actually critical. No vendor publishes its scoring formula; the published mechanics that exist are definitional (Wiz toxic combination = likelihood AND impact; BloodHound exposure = share of principals with a path).

### Cited Findings
- EPSS predicts the probability a vulnerability will be exploited in the next 30 days; EPSS v4 began publishing 17 March 2025. One source states FIRST deployed EPSS v5 (model build v2026.06.15) on 15 June 2026, while several other pages still call v4 current. **Conflict: the v5 claim comes from a single non-FIRST source and is unverified.** [S] — [tech-insider: EPSS vs CVSS vs KEV vs SSVC 2026](https://tech-insider.org/epss-score-vs-cvss-vs-cisa-kev-vs-ssvc-2026/); v4 described as current by [Phoenix Security: EPSS v4](https://phoenix.security/?p=34874) and others in the same result set
- Layering guidance across sources: a KEV entry goes to the top regardless of its EPSS score; CISA's SSVC decision tree uses exploitation status as a decision point and EPSS can inform it where no direct evidence exists; "CVSS describes the bug, EPSS forecasts the attacker, KEV records what attackers already did, SSVC turns those plus context into a decision". [S] — [tech-insider comparison](https://tech-insider.org/epss-score-vs-cvss-vs-cisa-kev-vs-ssvc-2026/)
- Wiz defines a toxic combination as a resource very likely to be compromised that would have significant business impact, arising from interconnected factors that let an attacker move from initial compromise to crown jewels; a third-party write-up cites a typical customer going from 10,000+ vulnerabilities to a few dozen critical toxic combinations (vendor-originated figure). [S] — [Wiz toxic combination blog](https://wiz.io/blog/the-anatomy-of-a-toxic-combination-of-risk), [Security Boulevard, April 2025](https://securityboulevard.com/2025/04/wizs-security-graphdb-vs-deeptempos-loglm)
- BloodHound Enterprise reports exposure as count and percentage of principals with a Tier Zero attack path and shows exposed-principal counts per finding category on the choke-point view. [S]/[P] — [BloodHound glossary](https://bloodhound.specterops.io/resources/glossary/overview.md), [BloodHound analysis](https://bloodhound.specterops.io/analyze-data/findings/analysis.md)
- DSPM accuracy should be measured with precision, recall and F1 rather than confidence alone (Sentra, via IT Brief, August 2026). [S] — [IT Brief: the cost of false positives in DSPM](https://itbrief.news/story/the-cost-of-false-positives-in-dspm)

### Inferences
- EPSS/KEV apply only where a finding maps to a CVE (broker/gateway/n8n version findings). Most VectaSec findings are configuration, so the scoring axes must be environment-derived. A transparent, explainable score suited to a small team:
  - `likelihood` in {0..1} from: entry reachability (probe-confirmed internet > config internet > internal > loopback), authentication effective (none > shared/default credential > weak > strong), and number of principals able to exercise the path.
  - `impact` in {0..1} from: data sensitivity of reachable resources (with classifier confidence, A7), operation class (admin/configure > write > read), and blast radius = count of distinct sensitive resources reachable from the finding's node in the derived graph.
  - `score = likelihood x impact`, shown with its factors. Rank issues by score; keep the detector's intrinsic severity only as a floor/ceiling.
- Alert-volume reduction techniques that follow from the sources: (1) group raw findings under an attack path or choke point and present the path as the issue; (2) dedupe findings that share one root cause (one wildcard ACL producing 40 "principal can read sensitive topic" rows becomes one issue with 40 affected resources); (3) hide findings with no entry-point path by default ("not currently reachable") rather than deleting them.
- Publishing the formula in the product would be a differentiator precisely because larger vendors do not.

### Gaps
- FIRST's EPSS model page returned 404 at the URL tried; the current EPSS version (v4 vs v5) is unresolved and must be checked at first.org before being stated in a report.
- No vendor scoring formula (Wiz, Orca, Prisma/Cortex, Tenable VPR) was found in primary form.
- No academic source on toxic-combination scoring or attack-graph risk metrics was opened.
- CISA KEV and SSVC primary pages were not opened.

---

## A6. Incremental and event-driven scanning

### Takeaway
Production engines run a hybrid: events trigger a re-read of only the named resource (never trusting the event payload as state), and a periodic full scan reconciles what events missed. Cartography's update-tag sweep is the simplest correct ledger discipline for the full-scan half.

### Cited Findings
- **Cloud Custodian** `cloudtrail` mode runs a policy in Lambda when matching CloudTrail API events arrive; for event-triggered runs Custodian "reconstitutes the current state" of the resources named in the event and evaluates the policy against that, rather than trusting the event; `periodic` mode is a scheduled full evaluation via EventBridge cron; `config-poll-rule` polls and evaluates all resources periodically. [S] — [Cloud Custodian AWS modes](https://cloudcustodian.io/docs/aws/aws-modes.html), [Cloud Custodian Lambda support](https://cloudcustodian.io/docs/policy/lambda.html)
- Rapid7 InsightCloudSec documents "Event-Driven Harvesting" that augments standard polling-based harvesting (the same hybrid in a commercial product). [S] — [Rapid7: AWS event-driven harvesting](https://docs.rapid7.com/insightcloudsec/event-driven-harvesting-aws/)
- **Cartography ledger**: per-run `update_tag`, `lastupdated` stamped on every node and relationship, stale items deleted by cleanup at the end of the run. [S] — [Cartography intel module guide](https://cartography-cncf.github.io/cartography/dev/writing-intel-modules.html)
- **Confluent audit logs**: on Confluent Cloud each record is stored in the `confluent-audit-log-events` topic on the audit log cluster; records use a CloudEvents envelope (`id`, `source`, `specversion`, `type`, `time`, `datacontenttype`, `subject`, route); authorisation records have type `io.confluent.kafka.server/authorization`; `kafka.CreateAcls` is an auditable management event captured by default (Platform 8.1 table); authorisation events are logged *before* the action occurs and are logged even if the caller does not follow through; a single user action can yield several records correlated by request ID; older docs nest the route under `confluentRouting`, newer show a top-level `route`. [S] — [Confluent Cloud audit log records](https://docs.confluent.io/cloud/current/monitoring/audit-logging/audit-log-records.html), [Confluent Platform auditable events](https://docs.confluent.io/platform/8.1/security/compliance/audit-logs/auditable-events.html), [Confluent Cloud Kafka management event methods](https://docs.confluent.io/cloud/current/monitoring/audit-logging/event-methods/kafka-management.html)
- **MCP 2026-07-28**: `tools/list`, `prompts/list`, `resources/list` results carry required `ttlMs` and `cacheScope` fields (a freshness hint for polling), and `subscriptions/listen` delivers `toolsListChanged` notifications; servers SHOULD return tools in a deterministic order. [P] — [MCP 2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog.md)
- **n8n** self-hosted supports external hooks ("running custom code when n8n performs specific operations"). [P] (title/description only from the docs index) — [n8n external hooks](https://docs.n8n.io/deploy/host-n8n/configure-n8n/external-hooks.md)
- Zapier's Zap list response includes `updated_at` per Zap. [P] — [Zapier Get Zaps v2](https://docs.zapier.com/api-reference/workflow/zaps/get-zaps-v2.md)

### Inferences
- Design that fits VectaSec's connector model:
  1. Give every stored resource and edge a `content_hash` (hash of normalised raw config) and `last_seen_scan`. A full scan becomes: read, hash, compare; only changed or new resources are re-run through detectors; unchanged resources carry findings forward. This alone removes most recomputation and yields a change log for free (the repo already has a `resource_changes` migration).
  2. Detectors must declare their inputs (`reads: [resource kinds / edge types]`) so a change invalidates only dependent detectors and derived edges. Single-resource detectors are trivially incremental; graph rules re-run when any node or edge type they read changed.
  3. Event sources act as *triggers to re-read one resource*, following Custodian: Confluent audit topic (ACL and role-binding events), CloudTrail via EventBridge (queues, IAM), Kubernetes audit, n8n external hooks, MCP `tools/list_changed`. Because Confluent authorisation events fire before the action and even for abandoned attempts, they must never be applied as state.
  4. Keep the periodic full sweep with Cartography-style stale deletion as the reconciler; record `source: event | sweep` on each ledger entry so drift between the two is measurable.
  5. Cheap change detection where no events exist: `updated_at` (Zapier, n8n workflows), `ttlMs`/deterministic order hash (MCP), Kafka metadata/ACL describe hash, RabbitMQ definitions export hash.
- Ledger consistency rule: a finding's identity should be `(rule_id, resource_id, stable evidence key)` so that a re-scan updates `last_seen` instead of creating a duplicate, and resolution is recorded when a scan that covered the resource no longer produces it (not merely when the resource was not scanned).

### Gaps
- No sample `kafka.CreateAcls` audit record was retrieved; ACL-specific payload fields are unverified.
- Apache Kafka (non-Confluent) has no built-in audit event stream that I sourced; detecting ACL changes there by polling/hash is an inference.
- Kubernetes audit log, RabbitMQ event exchange (`rabbitmq_event_exchange`), Redis keyspace/ACL log, NATS advisories and n8n log streaming were not researched this session.
- No source describes how commercial vendors reconcile event-driven and full-scan results.

---

## A7. Data classification beyond names

### Takeaway
DSPM products classify by sampling a bounded number of values per field, matching them against signals, and reporting a type, a sensitivity level and a numeric confidence; context words near a match raise confidence and combined evidence is weighed rather than taken from one signal. For a posture tool that should not read payloads by default, schema metadata is the first and cheapest upgrade over names.

### Cited Findings
- **Netskope One DSPM**: default structured-data process takes 50 non-null samples from each data store field and matches them against heuristic signals to determine whether the field is sensitive, its type, sensitivity level and a confidence score; unstructured sampling is per file with a configurable rate. [S] — [Netskope DSPM classification management overview](https://docs.netskope.com/en/dspm-classification-management-overview)
- **Forcepoint DSPM** reports confidence between 0 and 1 and describes combining evidence in a Bayesian-style network so that a strong signal can be outweighed by several weaker ones. [S] — [Forcepoint: AI-powered accuracy in DSPM](https://help.forcepoint.com/dspm/en-us/cloud_dspm/guid-869d54b8-00fd-4306-9004-ddd628fbf441.html)
- **Wiz** recommends attaching confidence scores to findings, pairing them with ignore rules, human review and feedback loops, and describes sparse sampling on large repetitive datasets where the sample grows until statistical confidence is reached. [S] — [Wiz Academy: data classification](https://www.wiz.io/academy/data-classification)
- **Microsoft Presidio**: the default `LemmaContextAwareEnhancer` raises a match's score when the recognizer's context words appear near the entity; default similarity factor 0.35 and minimum score 0.4; in the tutorial a zip-code match rose from 0.01 to 0.4 with context. [S] — [Presidio tutorial: context](https://microsoft.github.io/presidio/tutorial/06_context)
- **MCP tools expose schemas without invocation**: `inputSchema` (required) and optional `outputSchema` are JSON Schema with property names and descriptions; in 2026-07-28 any JSON Schema 2020-12 keyword is allowed. [P] — [MCP 2026-07-28 tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools.md)
- Measure classifier accuracy with precision/recall/F1, not confidence alone. [S] — [IT Brief](https://itbrief.news/story/the-cost-of-false-positives-in-dspm)

### Inferences
- A ladder of evidence, each rung adding confidence and each recorded on the classification so the UI can say *why*:
  1. **Name** (today): topic/queue/key-prefix/tool name. Low confidence, cap at about 0.3.
  2. **Schema metadata, no payload access**: Schema Registry subjects (Avro/Protobuf/JSON Schema field names, types, `doc`, tags), MCP tool `inputSchema`/`outputSchema` property names and descriptions, n8n node parameter and field mappings, Kong route paths and request-validator schemas, AsyncAPI/OpenAPI documents. Field-name lexicon plus type/format constraints (`format: email`, `pattern`) gives medium confidence, about 0.5 to 0.7. This is the highest value-for-effort step because it needs only read-only metadata calls VectaSec largely already makes.
  3. **Opt-in bounded sampling**: N messages from the tail of a topic or N keys via `SCAN` with a strict cap, processed in the customer's environment or in memory only, storing *match counts and detector names, never values*. Validators: regex plus checksum (Luhn for cards, IBAN mod-97, national ID check digits) plus context words (Presidio pattern). Checksum-validated hits across more than a threshold share of samples give high confidence, 0.9+.
  4. **Small-model classification** of field names + descriptions + a few redacted samples for the residual "free text / unknown" class; treat its output as one more signal, never the sole basis for a critical finding.
- Report confidence the way Netskope/Forcepoint do: `(data_type, sensitivity, confidence, evidence[])`, and feed confidence into the risk score (A5) instead of a boolean "sensitive" flag. Let users confirm or reject a classification; a human label pins confidence to 1.0 or 0 and becomes regression data.
- Sampling safety checklist (inference): explicit per-connector opt-in; read-only credentials; consumer without committing offsets and with a unique throwaway group, or `assign`+`seek` without a group; byte and time caps; no persistence of raw values; redact before any model call.

### Gaps
- Amazon Macie (managed data identifiers, keyword proximity, sampling depth) returned no sources; not covered.
- Presidio's checksum-validation internals were not found in primary form.
- Confluent Schema Registry / Stream Catalog tag APIs were not opened this session; the claim that field tags are readable is unverified.
- No vendor documents a published confidence *formula*.

---

## A8. Drift and baseline

### Takeaway
I found no primary sources on drift detection this session. What can be said from sourced material is limited to the storage discipline (Cartography's timestamped ledger) that makes time-series posture possible.

### Cited Findings
- Cartography stamps every node and relationship with the sync's `update_tag` and removes stale items at the end of each run, which is the minimal mechanism from which "what changed between run N and N+1" can be derived. [S] — [Cartography ops guide](https://lyft.github.io/cartography/ops.html)
- Prowler's mutelist is keyed by account, check, region, resource and tags and supports Exceptions and a Description; no expiry field appeared in the pages retrieved. [S] — [Prowler mutelisting](https://docs.prowler.com/user-guide/cli/tutorials/mutelist)

### Inferences
- With content hashes per resource (A6), three baselines become cheap: (1) **previous scan** (change log, already begun in the repo's `resource_changes` migration and `timemachine.py`); (2) **customer-approved golden snapshot** per resource kind ("these ACLs are the approved set; alert on any addition"), which suits middleware because approved grants are few; (3) **declared state**: parse Terraform state/plan JSON, Strimzi `KafkaUser`/`KafkaTopic` CRDs, RabbitMQ definitions JSON, Kong decK YAML, NATS config/JWT claims, n8n source-control exports, and diff against live. Category 3 produces the most actionable finding type: "live grant not present in code" (out-of-band change).
- Time-series posture: store per-scan aggregates (score, open findings by severity, exposed-path count, mean time to resolve) rather than recomputing from history.

### Gaps
- No source read on driftctl, Terraform drift detection, GitOps (Argo CD/Flux) drift, or any CSPM vendor's baseline feature. Everything actionable in this section is inference.
- Kong decK, Strimzi CRDs and RabbitMQ definitions as declared-state sources are from recall, not verified this session.

---

## A9. Detector quality engineering

### Takeaway
Sourced material here is thin. The practices with a primary or near-primary basis are: rule-as-data with paired test fixtures, per-rule metadata files, suppression lists keyed by scope, and hiding empty rules based on observed results.

### Cited Findings
- Prowler requires a `<check_name>.metadata.json` beside every check and loads each check from its own folder; names must be prefixed with the service. [S] — [Prowler checks developer guide](https://docs.prowler.com/developer-guide/checks)
- Prowler Cloud records which built-in attack-path queries returned data after each scan and hides queries confirmed empty. [S] — [Prowler attack paths: active queries](https://docs.prowler.com/user-guide/tutorials/prowler-app-attack-paths-active-queries)
- Prowler mutelist rules are keyed by account, check, region, resource and tags, with Exceptions and Description. [S] — [Prowler mutelisting](https://docs.prowler.com/user-guide/cli/tutorials/mutelist)
- Kong documents fail-closed behaviour for rule evaluation errors (500 when a `deny_when` expression fails). [P] — [Kong ACL plugin](https://developer.konghq.com/plugins/acl/)
- Unit 42's head-to-head measurement of three IAM tools by detection rate and post-remediation false positives is a published example of benchmarking detectors against a labelled scenario set. [S] — [Unit 42: IAM-Deescalate](https://unit42.paloaltonetworks.com/iam-deescalate/)

### Inferences
- Minimum quality harness for about 450 Python detectors:
  1. **Golden fixtures**: for each detector, at least one failing and one passing raw-config fixture captured from real systems (sanitised), asserted on finding presence *and* observation text. A CI check fails if a detector has no fixtures; publish the coverage number.
  2. **Semantic conformance tests** for the half-B simulators: spin up real Kafka/RabbitMQ/Redis/NATS/Kong in containers, apply a matrix of grants, and assert the simulator's allow/deny equals the broker's actual behaviour (Redis has `ACL DRYRUN`; Kubernetes has `kubectl auth can-i`; others need a real client attempt). This is the only way to trust "effective" claims and it catches version drift.
  3. **Mutation testing of rules**: mutate fixtures (flip a boolean, widen a pattern, remove a deny) and require that at least one detector's output changes; mutate detector thresholds and require a test to fail. Reports detectors whose tests cannot tell them apart from a no-op.
  4. **False-positive tracking**: every "dismiss" in the console carries a reason enum (`not_applicable`, `accepted_risk`, `false_positive`, `compensating_control`); per-rule false-positive rate is a dashboard, and rules above a threshold are auto-demoted in severity pending review.
  5. **Suppressions with mandatory expiry and owner**; expired suppressions re-open the finding. (No sourced product behaviour found for expiry; this is a recommendation.)
  6. **Coverage-gap reporting**: per connector, list what could not be read (permission denied, API unavailable, feature not supported), and per resource kind, which detectors ran. "Not assessed" must be visibly distinct from "passed".
  7. **Empty-rule telemetry** (Prowler pattern): track per-rule fire rates across tenants; rules that never fire or always fire are candidates for review.

### Gaps
- Semgrep rule-test conventions were not retrieved (the docs URL redirected and was not re-fetched). From recall only, unverified: test files carry `ruleid:` / `ok:` / `todoruleid:` comment annotations and run with `semgrep --test`.
- No sources on mutation testing of security rules, on `opa test`, or on suppression-with-expiry in a named product.
- No published false-positive-rate benchmarks for CSPM detectors were found.

---

# HALF B: SYSTEM SEMANTICS

## B1. Apache Kafka ACLs and Confluent RBAC

### Takeaway
Kafka authorisation is default-deny with three overrides: `super.users` bypass everything, `allow.everyone.if.no.acl.found` opens resources that no ACL matches, and DENY beats ALLOW. Effective access to a topic is the union over LITERAL, PREFIXED and `*` patterns and over `User:<name>` and `User:*`, minus matching DENYs, plus implied DESCRIBE, plus (on Confluent) RBAC role bindings, which are allow-only.

### Cited Findings
Apache Kafka 4.4 documentation, [P] — [Apache Kafka 4.4: Authorization and ACLs](https://kafka.apache.org/44/security/authorization-and-acls/):
- KRaft clusters set `authorizer.class.name=org.apache.kafka.metadata.authorizer.StandardAuthorizer` on all nodes; ACLs are stored in the KRaft metadata log. The 4.4 page does not mention a ZooKeeper `AclAuthorizer`.
- If no ACL matches a resource, access is restricted and "only super users are allowed to access it".
- `allow.everyone.if.no.acl.found=true` lets everyone access resources with no ACLs; "This flag only changes behavior when no ACL matches the resource." Default is `false`.
- `super.users` is a semicolon-delimited list in `server.properties` (for example `super.users=User:Bob;User:Alice`); semicolons because SSL names can contain commas; the `User` type string is case-sensitive.
- Resource patterns: `--resource-pattern-type` defaults to `literal`; a literal `*` resource matches any name; `prefixed` matches names starting with the given text. `--allow-principal User:'*'` means all users.
- Hosts: `--allow-host` / `--deny-host` accept only IP addresses, not hostnames; with a principal and no host, host defaults to `*`.
- Listing with the `match` pattern filter returns all ACLs affecting a resource, including wildcard and prefixed ones.
- mTLS principal: by default the full X.500 distinguished name string; `ssl.principal.mapping.rules` uses `RULE:pattern/replacement/` with optional `/L` or `/U`, rules checked in order, first match wins, `DEFAULT` keeps the DN.
- Kerberos principal: by default the primary part; `sasl.kerberos.principal.to.local.rules` follows krb5 `auth_to_local` syntax.
- `principal.builder.class` sets a custom principal builder; on KRaft it must implement `KafkaPrincipalSerde`.
- Protocol to ACL mapping (selected): FETCH needs Read on Topic for consumers (ClusterAction on Cluster for followers); PRODUCE needs Write on Topic, plus Write on TransactionalId for transactional producers and IdempotentWrite on Cluster for idempotent produce; OFFSET_COMMIT needs Read on Group and Read on Topic (group checked first); JOIN_GROUP needs Read on Group; METADATA needs Describe on Topic (Create on Cluster or Topic for auto-creation); CREATE_ACLS / DELETE_ACLS need Alter on Cluster; DESCRIBE_ACLS needs Describe on Cluster.
- Newer group protocols: CONSUMER_GROUP_HEARTBEAT needs Read on Group; CONSUMER_GROUP_DESCRIBE needs Describe on Group; SHARE_GROUP_HEARTBEAT needs Read on Group; SHARE_FETCH and SHARE_ACKNOWLEDGE need Read on Group and Read on Topic.
- The 4.4 page as extracted did not explicitly state DENY-over-ALLOW precedence or implied operations; it shows a DENY carving an exception out of a broad ALLOW by example.

Confluent Platform 8.4 (page last updated 19 Oct 2026), [P] — [Confluent: ACL overview](https://docs.confluent.io/platform/current/security/authorization/acls/overview.html):
- Deny ACLs take precedence over allow ACLs wherever both apply.
- "if a resource does not have associated ACLs, only super users can access the resource." With `allow.everyone.if.no.acl.found=true`, deleting the last ACL exposes the resource, and adding an ACL later locks out users who previously had access.
- Super users access any resource regardless of ACLs; wildcards are not supported in `super.users` (`User:*` there does not make everyone a super user); broker principals must be super users.
- `User:*` applies an ACL to all users; `Group:*` only with authorisers that support group principals (Confluent Server Authorizer).
- Implied operations: READ, WRITE or DELETE implicitly grant DESCRIBE; ALTER_CONFIGS implicitly grants DESCRIBE_CONFIGS.
- Operation tables (stated as not comprehensive): Topic Read covers Fetch, OffsetCommit, TxnOffsetCommit; Topic Write covers Produce, AddPartitionsToTxn; Topic Describe covers ListOffsets, Metadata, OffsetFetch, OffsetForLeaderEpoch; Group Read covers JoinGroup, Heartbeat, SyncGroup, LeaveGroup, OffsetCommit, OffsetFetch, AddOffsetsToTxn, TxnOffsetCommit; Cluster Alter covers CreateAcls, DeleteAcls; Cluster Describe covers DescribeAcls, ListGroups.
- Role bindings do not support wildcard matching under Confluent Server Authorizer.
- Multi-tenant note: `confluent.max.acls.per.tenant` default 1000; setting it to 0 turns off ACLs for tenants so every tenant user gets full access to their own resources.

Confluent Platform 8.4 RBAC, [P] — [Confluent: RBAC overview](https://docs.confluent.io/platform/current/security/authorization/rbac/overview.html):
- RBAC adds an enforcement layer on top of ACLs; the Confluent Server Authorizer checks the principal against both role bindings and ACLs.
- RBAC roles do not support DENY rules.
- The page's example has a group granted access via RBAC and one member denied via an ACL, implying ACL DENY overrides a role-binding allow, but the page does not state a precedence rule.
- Roles can be bound to groups from LDAP or an OAuth/OIDC provider; user IDs in bindings are case-specific; MDS is the system of record for role bindings; `confluent iam rbac role-binding list` lists them; a bootstrap super user in `super.users` on the MDS cluster assigns `SystemAdmin`.
- Named roles on the page: `SystemAdmin`, `UserAdmin`, `ResourceOwner` (can grant access to resources it owns, for example topics with a `finance_` prefix).

### Inferences
- Algorithm for `can(principal P, host H, op O, resource R of type T)` on StandardAuthorizer, assembled from the rules above:
  1. If `P` is in `super.users`: ALLOW.
  2. Collect ACLs whose resource type is T and whose pattern matches R: LITERAL name == R, LITERAL `*`, or PREFIXED where R starts with the prefix.
  3. If the collected set is empty (for *any* principal, per "no ACL matches the resource"): result is `allow.everyone.if.no.acl.found`.
  4. Filter to ACLs whose principal is `P` or `User:*` (and groups on Confluent) and whose host is H or `*`.
  5. If any DENY matches operation O or ALL: DENY.
  6. If any ALLOW matches O or ALL, or O is DESCRIBE and an ALLOW exists for READ/WRITE/DELETE (and ALTER per upstream behaviour, see Gaps), or O is DESCRIBE_CONFIGS and ALLOW ALTER_CONFIGS exists: ALLOW.
  7. Otherwise DENY. On Confluent Server Authorizer, additionally ALLOW if a role binding grants O on R and no ACL DENY matched (precedence is implied, not stated; flag as assumption).
- **Effective readers of topic X** = super users, plus principals passing `can(P, *, READ, topic X)`. A *working consumer-group reader* additionally needs READ on some Group; a principal with topic READ but no group READ can still fetch via manual partition assignment (FETCH needs only topic Read), so topic READ alone is sufficient for data exposure. **Effective writers** = `can(P, *, WRITE, topic X)`.
- Step 3 creates a non-obvious trap worth a dedicated detector: with `allow.everyone.if.no.acl.found=true`, a topic is world-accessible until *any* ACL (including a prefixed or wildcard one for an unrelated principal) matches it; and a single wildcard-resource ACL silently converts every topic from open to closed. The engine should evaluate this per resource instead of flagging the flag.
- Principal identity must be resolved before matching: an mTLS client with no mapping rule has a principal equal to the full DN, so ACLs written for `User:alice` will not match `User:CN=alice,OU=...`. The connector should read `ssl.principal.mapping.rules` and, where it can, list observed principals.
- `User:*` ALLOW on a cluster with an unauthenticated (PLAINTEXT) listener includes `User:ANONYMOUS`; from recall, not sourced.
- Who can change ACLs (a privilege-escalation edge): principals with ALTER on Cluster. Who can see them: DESCRIBE on Cluster. The scanner itself needs DESCRIBE on Cluster.

### Gaps
- ZooKeeper vs KRaft differences: the 4.4 docs simply omit ZooKeeper. I did not open a source this session confirming ZooKeeper-mode removal in Kafka 4.0 or `kafka.security.authorizer.AclAuthorizer` semantics for 3.x clusters (recall: ZooKeeper mode was removed in 4.0; AclAuthorizer stored ACLs in ZooKeeper and had the same deny-precedence and `allow.everyone` semantics). Verify against the 3.9 docs if customers run 3.x.
- Whether ALTER implies DESCRIBE: Confluent lists READ, WRITE, DELETE; upstream KIP/authoriser code (recall) also includes ALTER. Unverified this session.
- Apache docs did not, in the extracted text, state deny precedence in a sentence; the explicit statement is Confluent's.
- RBAC and ACL precedence is not stated normatively on the page read; the remaining 53k characters of the RBAC page and the predefined-roles page were not read, so the role-to-operation matrix (DeveloperRead, DeveloperWrite, ResourceOwner, Operator, ClusterAdmin, SecurityAdmin) and prefixed role bindings are not cited.
- Confluent Cloud's ACL and RBAC model (service accounts, cloud role names) was not researched.
- Delegation tokens and `User:ANONYMOUS` behaviour were not sourced.

---

## B2. RabbitMQ

### Takeaway
RabbitMQ access is two checks: may the user enter the vhost at all, then per-operation regex checks of the resource name against the user's configure, write and read patterns for that vhost. "Who can consume queue Q" is exactly the users whose read regex for Q's vhost matches Q's name. Tags govern only the management plane, where `administrator` is full control.

### Cited Findings
RabbitMQ 4.4, [P] — [RabbitMQ: Authentication, Authorisation, Access Control](https://www.rabbitmq.com/docs/access-control):
- A `guest`/`guest` user and `/` vhost are created only on a blank node, not when definitions are imported on boot. `guest` can connect only over loopback for any protocol; controlled by `loopback_users`, which contains only `guest` by default; setting it to `none` allows remote `guest` logins.
- Permissions are per vhost: three regular expressions (configure, write, read) matched against exchange and queue names. `.*` matches everything; `^$` matches only the empty string and so denies; the empty string `''` is a synonym for `^$`.
- The default exchange is checked under the name `amq.default`; server-generated queue names start with `amq.gen`.
- Operation table: `queue.declare` needs configure on the queue (with a DLX: write on the DLX exchange and read on the queue); `queue.delete` configure on queue; `exchange.declare` configure on exchange (with an alternate exchange: read on the exchange and write on the AE); `queue.bind`/`unbind` write on the queue and read on the exchange; `exchange.bind`/`unbind` write on destination, read on source; `basic.publish` write on the exchange; `basic.get`, `basic.consume`, `queue.purge` read on the queue.
- Passive declarations (since 4.3.1): any one of configure, write or read on the resource suffices.
- MQTT: SUBSCRIBE needs configure and write on the queue and read on the exchange; PUBLISH needs write on `amq.topic` (or the configured exchange) and passes topic authorisation.
- Topic authorisation applies to topic exchanges and checks the routing key in addition to the publish check; for AMQP 0-9-1, binding routing keys between a topic exchange and a queue/exchange are checked against topic permissions if any are configured; if no topic permissions are defined, publishing and consuming are authorised (opt-in per exchange). Internal-backend patterns support `{username}`, `{vhost}`, and `{client_id}` (MQTT only).
- A user with no permissions in a vhost is refused at connection time; a user with too-narrow permissions connects and gets `access_refused` on the operation.
- `auth_backends` is a chain; for authentication the first positive result is final; authn and authz can be split across backends (for example LDAP authn, internal authz).
- Permission checks may be cached per connection or channel; clearing permissions does not affect open connections; deleting a user closes its connections.
- New users have no tags.

RabbitMQ 4.4 management plugin, [P] — [RabbitMQ: Management plugin](https://www.rabbitmq.com/docs/management):
- No tag: no management access. `management`: anything the user could do via messaging protocols, plus list vhosts they can log into, view queues/exchanges/bindings there, view and close own connections and channels, view vhost-level stats including other users' activity in those vhosts. `policymaker`: management plus view/create/delete policies and parameters in their vhosts. `monitoring`: management plus list all vhosts, view other users' connections and channels, node-level data, global stats. `administrator`: policymaker plus monitoring plus create/delete vhosts, view/create/delete users and permissions, close other users' connections.

### Inferences
- Algorithm, per vhost V: `consumers(Q) = { u : u has a permission row for V and re.search(u.read[V], Q.name) }`; `publishers(E) = { u : re.search(u.write[V], E.name) }`; an *effective writer into queue Q* is a publisher to any exchange with a binding path to Q, or to `amq.default` with routing key = Q's name (so a write pattern matching `amq.default` allows publishing directly to every queue by name). `can_rebind(Q)` (attach Q to a sensitive exchange and siphon messages) = write on Q and read on the exchange. `can_declare/delete` = configure.
- Model the binding topology as graph edges (`exchange -[BINDS {routing_key}]-> queue`) so that "who can read messages published to exchange E" resolves through bindings to queues and then to queue readers. This is the RabbitMQ analogue of a derived permission edge.
- Regex anchoring: the docs' examples are explicitly anchored (`^user2`, `^(amq\.gen.*|amq\.default)$`) and the page does not say patterns are implicitly anchored. From recall, matching is unanchored (a pattern `orders` matches `preorders-dlq`), which makes unanchored patterns a real over-grant detector, but this must be confirmed by a conformance test before shipping.
- Management-plane escalation edges: `administrator` can set any user's permissions, so it is effectively full data access to every vhost; `policymaker` can set policies (for example federation or dead-lettering) that redirect messages, a data-exfiltration path within its vhosts; `monitoring` is read-only metadata across all vhosts.
- Remote exposure of the default credential requires three facts together: `guest` exists, its password is still `guest`, and `loopback_users` no longer contains it. Only the first and third are config-readable; the second needs a (customer-authorised) login probe.
- When authz is delegated to LDAP, HTTP or OAuth 2 backends, the internal permission table is not the truth; the scanner must detect `auth_backends` and downgrade confidence or evaluate token scopes instead.

### Gaps
- Whether permission regexes are implicitly anchored is not stated on the page read (ambiguous; see inference).
- The HTTP API endpoints for users, permissions and topic-permissions (`/api/users`, `/api/permissions`, `/api/topic-permissions` from recall) were not confirmed on a page this session.
- OAuth 2 scope-to-permission mapping, `impersonator` and `protected` tags, and stream/AMQP 1.0 specific permission mappings were not covered by the pages read.

---

## B3. Redis ACLs

### Takeaway
A Redis user's effective access is: enabled flag and password state, then an ordered left-to-right command allow/deny list, key patterns with read/write qualifiers, pub/sub channel patterns, and (7.0+) independent selectors of which any one may authorise a command. The decisive exposure fact is the `default` user: out of the box it is `on nopass ~* &* +@all`, so every new connection is fully privileged without AUTH.

### Cited Findings
All [P] from the current Redis docs (page references behaviour up to Redis 8.8) — [Redis: ACL](https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/):
- Default configuration: `user default on nopass ~* &* +@all`. With `nopass` on the default user, "new connections are automatically authenticated with the default user without any explicit AUTH call". `requirepass` sets a password for the default user. `AUTH <password>` (one argument) authenticates as `default`.
- Rules are applied "from the first to the last, left-to-right", and order matters.
- `on` / `off`: `off` prevents new authentication but "previously authenticated connections will still work". If `default` is `off`, new connections start unauthenticated and must AUTH.
- Commands: `+<command>`, `-<command>`, `+@<category>`, `-@<category>`, `allcommands` (= `+@all`), `nocommands` (= `-@all`). Subcommands with `|` (for example `+config|get`); blocking subcommands with `-cmd|sub` from Redis 7.0. `+<command>|first-arg` is deprecated since 7.0.
- `+@all` includes all commands "both the ones currently present in the server, and the ones that will be loaded in the future via modules"; categories other than `@all` never include module commands. A command can be in several categories, so `+@geo -@read` removes read-only geo commands.
- Keys: `~<pattern>` glob (like `KEYS`), multiple allowed; `%R~<pattern>`, `%W~<pattern>`, `%RW~<pattern>` from 7.0; `allkeys` = `~*`; `resetkeys` flushes patterns.
- Read permission covers returning/processing user data, not metadata (for example `STRLEN`, `TYPE`, `SISMEMBER` are not "read" of data); required permission derives from the command's key-spec flags (insert/update/delete map to W, access maps to R); a key with no logical-operation flags (for example `EXISTS`) needs either R or W. `LPUSH` needs only W; `LPOP` needs R and W.
- Key patterns restrict only commands that name keys: "Commands that operate on an entire database or the whole keyspace ... are not limited by key patterns." A user `~tenant1:* +@all` can still run `FLUSHALL`, `FLUSHDB`, `SWAPDB`.
- Channels: `&<pattern>` from 6.2; matching applies to channels in `PUBLISH` and `SUBSCRIBE`, whereas `PSUBSCRIBE` "requires a literal match between its channel patterns and those allowed for user"; `allchannels` = `&*`; `resetchannels`.
- New-user default for channels: in 6.2, new users got `allchannels` for backward compatibility; from 7.0 `acl-pubsub-default` defaults to `resetchannels`.
- Selectors (7.0+): additional rule sets in parentheses; "either the root permissions ... or any of the selectors ... must match the given command"; root is checked first, then selectors in order added; a command touching several keys must be fully matched by one of them (example: `+@all ~app1:* (+@read ~app2:*)` cannot `COPY app2:user app1:user`, whereas `+@all ~app1:* %R~app2:*` can).
- Passwords: `>pw`, `<pw`, `#<sha256>`, `!<hash>`, `nopass` (any password works), `resetpass`. A user with no password and not `nopass` cannot log in. Passwords are stored as SHA-256.
- A new user created with no rules is `off resetchannels -@all` with no keys.
- `ACL SETUSER` is incremental: later calls modify, not reset, the user.
- `ACL LIST` prints users in config-file format; `ACL GETUSER` returns `flags`, `passwords` (hashes), `commands`, `keys`, `channels`, `selectors`.
- Users are defined either in `redis.conf` or an external `aclfile` (mutually exclusive); `ACL LOAD` / `ACL SAVE` apply to the file.
- Replicas see the master as the root user; replicas need `+psync +replconf +ping` on the master.

### Inferences
- Evaluator: parse the `commands` string from `ACL GETUSER` left to right into an allowed-command set using the live server's `ACL CAT <category>` membership (categories vary by version and loaded modules, so never hard-code them), then for a query `(user, command, keys[], channels[])`: allowed if the root rule set or any single selector permits the command *and* every key with the access type required by the command's key specs *and* every channel. `COMMAND DOCS` / `COMMAND INFO` supply key specs.
- Effective-access summaries worth materialising as derived edges: `CAN_READ_KEYS(pattern)`, `CAN_WRITE_KEYS(pattern)`, `CAN_PUBSUB(pattern)`, and boolean capabilities with outsized impact: can run `@admin`/`@dangerous` commands (`CONFIG SET`, `ACL SETUSER` = self-escalation to full control; `FLUSHALL`; `KEYS`/`SCAN` enumeration; `EVAL`/`FUNCTION` scripting; `MODULE LOAD`; `REPLICAOF`/`MIGRATE` exfiltration; `MONITOR` = read all traffic regardless of key patterns).
- Three findings a one-setting-at-a-time detector cannot produce: (1) key-pattern "tenant isolation" defeated by keyless destructive commands (documented explicitly above); (2) `+@all -@dangerous` style blacklists that silently include future and module commands; (3) a restricted user that retains `ACL SETUSER` or `CONFIG SET` and can therefore rewrite its own restrictions.
- Unauthenticated exposure = `default` user is `on` AND `nopass` AND a non-loopback bind is reachable AND protected mode does not block it. The first two are from `ACL GETUSER default`.

### Gaps
- `protected-mode` semantics are not on the ACL page and were not sourced this session (recall: when enabled with no password on the default user and no explicit bind, Redis accepts only loopback connections; documented on the Redis security page and in `redis.conf`).
- `ACL DRYRUN` was not mentioned on the page read (recall: added in 7.0, simulates a command for a user without executing it; ideal for conformance tests). Verify at redis.io/commands/acl-dryrun.
- Redis Enterprise / Redis Cloud role-based ACLs, Valkey divergences, and managed-service variants (ElastiCache RBAC users/groups, MemoryDB) were not researched.
- Redis 8 changes to module-related categories ("potentially breaking changes to ACLs") are referenced by the page but the release notes were not opened.

---

## B4. NATS

### Takeaway
NATS has two layers: accounts are hard isolation boundaries (a subject in one account is a different subject in another, crossed only by explicit export/import), and inside an account each user has publish and subscribe allow/deny subject lists where deny wins and the absence of a permissions block means unrestricted. The system account can query every account.

### Cited Findings
NATS docs (navigation shows 2.15 as latest; the pages state no minimum version), all [P]:

Authorization — [NATS: Authorization](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/authorization):
- Each user has independent `publish` and `subscribe` permissions, each with `allow` and/or `deny` subject lists.
- "The moment you write an `allow` list, every subject not on it is denied."
- An empty list is not a lock-down: "`publish: []` parses as no list at all, so the user can publish anywhere." To block all publishes use `deny: [">"]`.
- "When a subject matches both lists, deny wins."
- "a permission with no `allow` and no `deny` means unrestricted"; a user without a `permissions` block can do anything in its account.
- `default_permissions` inside `authorization {}` applies only to users with no `permissions` block; a user's own block and the defaults "are never merged".
- Wildcards: `*` matches one token; `>` matches one or more trailing tokens (`orders.*` does not match `orders.at.northpole`; `orders.>` does).
- Queue-group permission: a subscribe entry `"orders.created billing-workers"` permits subscribing only as a member of that queue group; a plain subscribe stays denied.
- Wildcard subscription overlapping a deny is accepted, and "the server filters the denied subjects out at delivery time"; a literal subscribe to a denied subject is rejected with a permissions violation.
- `allow_responses`: the server "tracks each reply subject it handed out and permits exactly that one reply".
- `subscribe: { deny: [">"] }` blocks the `_INBOX.` subscription a request needs.

Accounts — [NATS: Accounts](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/accounts):
- "An account is an isolated tenant with its own subject space"; "Two accounts on the same server never see each other's traffic"; the account boundary "is absolute".
- With no `accounts` block, all connections land in the global account `$G`. Once tenant accounts are defined, unauthenticated connects are rejected; but a config whose only account is the system account still admits unauthenticated clients into `$G`.
- A user lives in exactly one account; usernames are unique across accounts.
- The server always creates `$SYS`; ordinary accounts subscribing to `$SYS.>` receive nothing; a system-account user can query any account; `system_account` renames it.
- `no_auth_user` admits unauthenticated clients as the named user in that user's account; it cannot be introduced or changed by config reload; it is rejected alongside a trusted operator.
- JetStream is opt-in per account (`jetstream: enabled`) when an `accounts` block exists; each account has its own JetStream store.

Cross-account — [NATS: Cross-account](https://docs.nats.io/learn/security/cross-account):
- Stream export = one-way publish/subscribe (exporter publishes, importers subscribe), unrelated to JetStream streams; service export = request/reply.
- Both halves are required; an import with no matching export fails at startup ("stream import not authorized"); an export with no import is silent.
- An export with no `accounts` list is public (any account on the server may import); restrict with `accounts: [..]` on the export.
- An import keeps the exported subject by default and may add `prefix:` or remap with `to:`.
- Operator (JWT) mode: exports/imports live in account JWTs; "JWT mode has no startup check to catch a mismatch"; `--token-position` keys a wildcard export so each importer can import only the subject carrying its own account key.

JetStream, [S] — [NATS: JetStream cross-account subjects](https://docs.nats.io/reference/jetstream/cross-account-subjects), [NATS learn: authorization](https://docs.nats.io/learn/security/authorization):
- JetStream control is on `$JS.API.>`; a publish-allow of `>` exposes the JetStream control plane; a wildcard API export `$JS.API.>` needs `response_type: stream`; `$JS.ACK.>` and `$JS.FC.>` must also be exported/imported for acks and flow control.
- NATS 2.14 and 2.15 change `$JS.ACK` and `$JS.FC` subject formats; exports/permissions using the more specific forms must be updated before 2.16. [S] — [Upgrade to NATS 2.14](https://docs.nats.io/release-notes/upgrade-to-2.14), [Upgrade to NATS 2.15](https://docs.nats.io/release-notes/upgrade-to-2.15)

### Inferences
- Evaluator per user U in account A: `can_pub(s)` = (no publish block, or allow list empty/absent, or s matches an allow entry) AND s matches no deny entry. Same for subscribe, with queue-group entries handled separately. Subject-pattern overlap (does grant pattern G intersect sensitive pattern S) is token-wise: walk tokens, `*` matches one, `>` matches the rest; intersection is non-empty unless two literal tokens differ at some position before either pattern ends with `>`.
- Effective readers of subject S in account A = users of A with `can_sub` on a pattern intersecting S, plus users of every account that imports a stream export covering S (apply the import's `prefix`/`to` remap, then that account's user permissions), plus system-account users for metadata.
- JetStream data access is determined by `$JS.API.*` publish rights, not by rights on the stream's subjects: a user allowed to publish to `$JS.API.CONSUMER.CREATE.<stream>.>` (and subscribe to its inbox) can read a stream's stored messages even with no subscribe permission on the underlying subjects; `$JS.API.STREAM.DELETE.*` / `PURGE.*` are destructive. Derive `CAN_READ_STREAM`, `CAN_ADMIN_STREAM` edges from JS API subject grants. (Subject names from recall; confirm against the JetStream API reference.)
- High-signal correlated findings: `no_auth_user` pointing at a user with no permissions block (anonymous = full account access); public exports (no `accounts` list) of sensitive subjects; accounts defined but only `$SYS`, leaving `$G` open to anonymous; `publish: []` written as an intended lock-down but meaning unrestricted.
- In operator/JWT mode the server config does not contain users; permissions are in user JWTs and account JWTs held by the resolver. The scanner needs the account server/resolver or `nsc`-exported claims; otherwise mark coverage as partial.

### Gaps
- Whether a user's own subscribe permissions gate delivery of imported subjects, and whether transitive re-export is possible, are not stated on the cross-account page (documentation silent).
- Activation tokens for private exports in config mode were not documented on the pages read.
- `allow_responses` `max` / `expires` defaults, the full JetStream API subject list, leafnode and gateway permission semantics, and auth callout were not read.
- The pages do not tie rules to a specific server version.

---

## B5. Kong, AWS API Gateway, Istio

### Takeaway
A Kong route is "effectively authenticated" only if, after resolving which plugin instance wins by scope precedence, an auth plugin applies to it with no working anonymous fallback, or the anonymous consumer is explicitly blocked. API Gateway combines authoriser and resource policy by fixed tables that differ for same-account and cross-account callers. Istio is allow-all until the first ALLOW policy selects a workload, after which it is deny-by-default for that workload.

### Cited Findings
**Kong Gateway** (scope tables cover 3.12 to 3.16; precedence list not tied to a version), [P] — [Kong: Plugin entity](https://developer.konghq.com/gateway/entities/plugin/):
- A plugin with no service, route, consumer or consumer-group association is global and runs on every request (per workspace in Enterprise, whole environment in OSS, per control plane in Konnect).
- A plugin instance "always runs once per request". Precedence when the same plugin is configured at several scopes, highest first: (1) Consumer + Route + Service, (2) Consumer group + Service + Route, (3) Consumer + Route, (4) Consumer + Service, (5) Consumer group + Route, (6) Consumer group + Service, (7) Route + Service, (8) Consumer, (9) Consumer group, (10) Route, (11) Service, (12) Global.
- If a consumer is in two groups with scoped instances of the same plugin, one runs, chosen by group name alphabetically; the docs say these rules are not formally defined and may change.

Authentication combination, [P] (page states no version) — [Kong: Authentication](https://developer.konghq.com/gateway/authentication/):
- Without `config.anonymous`, every configured auth plugin must authenticate (logical AND) and a 4xx is returned otherwise; the last plugin executed sets upstream credentials.
- With `config.anonymous` set to a valid consumer, a failed authentication does not return a 40x; the request is attributed to the anonymous consumer and continues (this is how logical OR across auth methods is built).
- To allow anonymous fallback without letting unauthorised users reach the service, configure the Request Termination plugin on the anonymous consumer.

ACL plugin (Gateway 3.16; `allow_when`/`deny_when` need 3.16+), [P] — [Kong: ACL plugin](https://developer.konghq.com/plugins/acl/):
- Restricts access using an allow list or a deny list of consumers or consumer groups; `allow`, `deny`, `allow_when`, `deny_when` are mutually exclusive on an instance.
- An authentication plugin must be configured on the same service or route; the ACL plugin relies on authenticated consumers.
- Denied requests get 403; a failing `deny_when` expression returns 500.

Plugin ordering, [S] — [Kong Konnect plugin ordering reference](https://docs.konghq.com/konnect/reference/plugins), [Kong: plugin ordering algorithms](https://developer.konghq.com/gateway/plugins/plugin-ordering/):
- Static priorities: key-auth 1250, acl 950, request-termination 2; higher runs first; ties broken by plugin name descending; dynamic ordering can override in the access phase, with a `priority_preserving` algorithm in Gateway 3.16+.

**AWS API Gateway (REST APIs)**, [P] — [API Gateway: how resource policies affect authorization workflow](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-authorization-flow.html):
- Resource policy only (no auth type): an explicit allow is required; implicit or explicit deny rejects the caller.
- Lambda authoriser + resource policy: the policy is first checked for explicit denies (immediate rejection), then the authoriser runs and its returned policy is evaluated with the resource policy per Table A; authoriser results may be cached.
- IAM auth + resource policy: same account, *either* the identity policy or the resource policy must allow (Table A); cross account, *both* must allow (Table B).
- Cognito authoriser + resource policy: after successful authentication the resource policy is evaluated independently and an explicit allow is required (Table B).
- Table A (same account; IAM or Lambda authoriser): Allow+Allow = Allow; Allow+Neither = Allow; Neither+Allow = Allow; Neither+Neither = Implicit Deny; any Deny = Explicit Deny.
- Table B (cross account IAM, or Cognito): Allow+Allow = Allow; Allow+Neither = Implicit Deny; Neither+Allow = Implicit Deny; any Deny = Explicit Deny.

**Istio 1.32**, [P] — [Istio: AuthorizationPolicy reference](https://istio.io/latest/docs/reference/config/security/authorization-policy/), [Istio: security concepts](https://istio.io/latest/docs/concepts/security/):
- Evaluation: (1) if any CUSTOM policy matches and the external authoriser denies, deny; (2) if any DENY policy matches, deny; (3) if there are no ALLOW policies for the workload, allow; (4) if any ALLOW policy matches, allow; (5) otherwise deny.
- Workloads with no authorization policies accept all requests. Multiple policies on a workload apply additively.
- `spec: {}` is "allow-nothing" for every workload in the namespace (no rules means nothing matches an ALLOW); `rules: [{}]` is allow-all.
- Scope: `metadata.namespace` sets the scope; the root namespace (default `istio-system`) applies mesh-wide; `selector` narrows to workloads; a policy sets at most one of `selector` and `targetRefs`; waypoint proxies require `targetRefs` and ignore `selector` policies.
- `principals`, `namespaces`, `serviceAccounts`, `trustDomains` require mTLS.
- For DENY rules, attributes missing from a request are treated as matches (stated for HTTP-only attributes on TCP traffic; the docs recommend scoping DENY policies to ports).
- AUDIT does not change allow/deny outcomes and needs a separate plugin.
- PeerAuthentication: PERMISSIVE accepts mTLS and plaintext, STRICT only mTLS, DISABLE none; unset mode inherits from the parent; mesh-wide unset defaults to PERMISSIVE.

### Inferences
- Kong route evaluator (`effective_auth(route)`):
  1. Collect auth-type plugin instances (key-auth, basic-auth, jwt, oauth2, openid-connect, hmac-auth, mtls-auth, ldap-auth and enterprise variants) at route, service and global scope. For each plugin *name*, the most specific instance wins (Route+Service > Route > Service > Global); mind `enabled: false` on a more specific instance, which overrides an enabled global one for that route.
  2. No winning enabled auth instance: route is **unauthenticated**.
  3. All winning instances have no `anonymous`: **authenticated (AND)**.
  4. Some have `anonymous = C`: the route is reachable unauthenticated *as consumer C* unless (a) request-termination is scoped to consumer C, or (b) an ACL plugin applies to the route whose allow list excludes C's groups (or deny list includes them). Otherwise classify **authenticated-optional (effectively open)**.
  5. Layer other reachability gates as separate attributes rather than auth: ip-restriction, mTLS at the listener, `protocols`, and whether the route's `hosts`/`paths` are actually bound to an internet-facing proxy listener.
  - Consumer-scoped plugins cannot be the route's primary gate because the consumer is unknown until an auth plugin runs.
- Because acl (950) runs after key-auth (1250) and request-termination (2) runs last by static priority, the documented combination works as intended under default ordering; dynamic ordering rules can invalidate that and should be read.
- API Gateway evaluator: classify each method by `authorizationType` (NONE, AWS_IAM, CUSTOM, COGNITO_USER_POOLS) plus `apiKeyRequired` (API keys are metering, not auth; recall, unsourced) plus resource policy, then apply the cited tables. The dangerous cells are: NONE with no resource policy; and same-account IAM where a broad resource-policy Allow (`Principal: *`) alone grants access without any identity policy (Table A row "Neither + Allow = Allow").
- Istio evaluator: for each workload, gather policies from root namespace, its namespace, and matching selectors/targetRefs; if zero ALLOW policies apply, the workload is open to anything that can reach it (subject only to DENY/CUSTOM). Combine with PeerAuthentication: an ALLOW rule keyed on `principals` while the workload is PERMISSIVE still denies plaintext callers (no principal), but a workload with *no* ALLOW policy and PERMISSIVE mode accepts plaintext from anywhere in the network path, which is the real toxic combination.
- DENY policies written with HTTP attributes can match TCP traffic unexpectedly (missing attributes count as matches), so a DENY may be broader than intended; conversely ALLOW rules with HTTP fields never match plain TCP.

### Gaps
- Kong ACL plugin behaviour for anonymous consumers, and `include_consumer_groups` / `always_use_authenticated_groups`, are not described on the page read (documentation silent in the extract).
- The Kong authentication page states no Gateway version. The static priority numbers are from a search summary.
- API Gateway HTTP APIs (JWT authorisers, no resource policies) and WebSocket APIs, API keys/usage plans, private-endpoint policies and mutual TLS were not covered.
- The Istio pages read do not spell out DENY behaviour on plaintext for `principals`/`notPrincipals`, ambient-mode L4 (ztunnel) vs L7 (waypoint) enforcement details, or path normalisation settings.
- Envoy's native RBAC filter and ext_authz semantics were not researched separately from Istio.

---

## B6. n8n and Zapier

### Takeaway
n8n's public API exposes enough for structural analysis (workflows, credential metadata with sharing and dependency lists, users and roles) and never returns secrets; webhook authentication mode is a node parameter. Zapier's Workflow API is a partner API scoped to what one authorising user can see, exposing steps, inputs and authentication *references* but no owner, folder or secret data.

### Cited Findings
**n8n** public API (OpenAPI version 1.1.1; n8n release not stated on the pages), [P] — [n8n API: credentials](https://docs.n8n.io/connect/n8n-api/credential.md), [n8n API reference: users](https://docs.n8n.io/api/api-reference/):
- Credential endpoints: `GET /credentials` (instance owner and admin only), `POST /credentials`, `GET /credentials/{id}`, `PATCH /credentials/{id}`, `DELETE /credentials/{id}`, `PUT /credentials/{id}/transfer` (body `destinationProjectId`), `POST /credentials/{id}/test`, `GET /credentials/schema/{credentialTypeName}`, `GET /credentials/{id}/dependencies` (lists workflows and agents that use the credential; returns `type`, `id`, `name`, optional `projectId`, `nextCursor`, `inaccessibleCount`).
- List returns `id`, `name`, `type`, `createdAt`, `updatedAt` and `shared` (entries with `id`, `name`, `role`, timestamps). Get returns `id`, `name`, `type`, `isManaged`, `isGlobal`, `isResolvable`, `resolvableAllowFallback`, `resolverId`, timestamps.
- "Credential data (secrets) is not included." `data` is write-only on create/update.
- Auth to the API: API key in `X-N8N-API-KEY`, a JWT bearer token, or the `n8n-auth` cookie.
- Users: `GET /users` is "Only available for the instance owner", returns id, email, names, `isPending`, `mfaEnabled`, timestamps, and `role` with `includeRole=true`; supports a `projectId` filter. Global roles referenced: `global:admin`, `global:member`, `global:chatUser`. `DELETE /users/{id}` accepts `transferId` to move workflows and credentials.

n8n Webhook node, [P] — [n8n: Webhook node](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.webhook.md):
- Authentication options: None, Basic auth, Header auth, JWT auth, and "n8n User Auth (OAuth2)" (limits calls to logged-in users of the instance). With None, anyone with the URL can call it.
- Test URL is registered while listening in the editor; Production URL is registered when the workflow is published.
- Options: IP(s) Allowlist (comma-separated; others get 403; blank = all IPs), Allowed Origins (CORS, default `*`), Ignore Bots, custom path with route parameters (default path is random), methods DELETE/GET/HEAD/PATCH/POST/PUT, response modes (Immediately; When Last Node Finishes; Using Respond to Webhook node; Streaming), max payload 16MB (`N8N_PAYLOAD_SIZE_MAX`).
- Version notes: HTML responses are sandboxed in iframes from n8n 1.103.0; the OAuth2 option applies to Webhook node version 2.2+.

n8n other, [P] (titles from docs index only) — [n8n: run security audits](https://docs.n8n.io/deploy/host-n8n/configure-n8n/security/run-security-audits.md), [n8n: external hooks](https://docs.n8n.io/deploy/host-n8n/configure-n8n/external-hooks.md): n8n has a built-in security audit and supports external hooks on self-hosted instances.

**Zapier** Workflow API, [P] — [Zapier: Get Zaps v2](https://docs.zapier.com/api-reference/workflow/zaps/get-zaps-v2.md):
- Requires OAuth scopes `zap`, `zap:all` or `zap:account:all`. `zap` returns only Zaps using your own integration; `zap:all` all of the authenticated user's Zaps; `zap:account:all` all Zaps the user can access in their account. `include_shared=true` adds Zaps shared with the user and "has no effect" without `zap:account:all`.
- Client IDs are issued "once you are approved for access to the API".
- Zap fields: `type`, `id`, `is_enabled`, `last_successful_run_date`, `updated_at`, `title`, `links` (including `html_editor`), `steps`; each step has `action`, `authentication`, `inputs`, `title`.
- `expand` converts IDs into objects (example `steps.action`); an expanded authentication exposes `type`, `id`, `app`, `is_expired`, `title`; "The actual fields are held securely by Zapier."
- No owner or folder fields appear in the schema. Rate limiting returns 429 with `Retry-After` and `X-RateLimit-*` headers; the limit value is not stated. Default `limit` 10 with `offset`.

### Inferences
- n8n assessable without secrets: (1) every Webhook node's auth mode, path, methods, IP allowlist and CORS from workflow JSON; active vs inactive workflow decides whether the production URL is live; (2) credential blast radius = `shared` projects/users x `/dependencies` workflows, with credential *type* indicating the downstream system (for example AWS, Postgres, Slack); (3) data flow edges trigger -> nodes -> destination systems, giving `n8n workflow -[USES]-> credential -[GRANTS_ACCESS_TO]-> system`; (4) dangerous node types (Code, Execute Command, HTTP Request with dynamic URLs, AI agent/tool nodes, MCP client/server nodes); (5) user roles and MFA state.
- n8n not readable: credential secret values (by design), therefore not the *scope* of the downstream token (an AWS credential's IAM policy must come from the AWS connector by matching the access key id, which n8n does not return); execution payloads unless executions are read separately; whether a webhook's header-auth secret is strong.
- Toxic combination unique to this class: webhook with Authentication None + active workflow + node using a credential shared instance-wide + downstream write action. That is an unauthenticated internet-to-privileged-action path expressible in the graph.
- Zapier readable: per authorising user only; steps, apps, input mappings, whether a connection is expired, enabled state, last success time. Not readable: account-wide inventory unless the authorising user can see everything; owner, folder, sharing ACLs, connection secrets or OAuth scopes of connections, Zap run history/payloads via this API. Because the API is partner-gated and user-scoped, Zapier coverage should be labelled partial by construction, and the trigger type for "Webhooks by Zapier" Catch Hook (which, from recall, has no built-in auth) must be inferred from `steps[0].action`.

### Gaps
- n8n workflow endpoints (`GET /workflows` with nodes/connections, `active`, tags, project/owner), executions, projects, variables, source control and `POST /audit` were not read this session (the docs index was truncated and the API reference page returned only the Users section). Their existence is from recall and should be confirmed in the OpenAPI spec.
- n8n API key scopes were not documented on the pages read.
- Whether the `shared` entries in the credential list are projects is not stated by the spec (ambiguous).
- Zapier: no admin/enterprise inventory API, audit-log API, or SCIM details were researched; the full `steps`/`inputs` schema and the exact approval requirements for API access were not confirmed.
- A community thread reports "GET method not allowed" on `/credentials` on a cloud instance, undated and unresolved. [S] — [n8n community thread](https://community.n8n.io/t/n8n-cloud-api-credentials-list/263668)

---

## B7. MCP (Model Context Protocol)

### Takeaway
As of the 2026-07-28 revision MCP is stateless: no `initialize` handshake and no sessions, a mandatory `server/discover` RPC, list results that may vary by presented authorisation but not by connection, and OAuth 2.1 with RFC 9728 protected-resource metadata as the (still optional) authorisation model. Almost everything a posture scanner needs is obtainable without invoking a tool: unauthenticated 401 challenge and metadata documents, `server/discover`, and `tools/list` schemas and annotations, with the standing caveat that annotations and serverInfo are self-reported and untrusted.

### Cited Findings
Spec versions: the documentation index lists `2026-07-28`, `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` and `draft`; 2026-07-28 is the newest dated revision. [P] — [MCP llms.txt index](https://modelcontextprotocol.io/llms.txt)

Changes in 2026-07-28 vs 2025-11-25, [P] — [MCP 2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog.md):
- Protocol-level sessions and the `Mcp-Session-Id` header are removed from Streamable HTTP; `tools/list`, `resources/list`, `prompts/list` "no longer vary per-connection".
- The `initialize` / `notifications/initialized` handshake is removed; every request carries protocol version and client capabilities in `_meta`; servers SHOULD identify themselves in each result's `_meta` (`io.modelcontextprotocol/serverInfo`).
- `server/discover` is added and servers MUST implement it.
- `subscriptions/listen` replaces the HTTP GET stream and resource subscribe/unsubscribe; opt-in types include `toolsListChanged`.
- List and read results require `ttlMs` and `cacheScope` (`public` or `private`).
- Streamable HTTP POSTs require `Mcp-Method` and `Mcp-Name` headers; tool parameters can be mirrored into `Mcp-Param-{name}` headers via `x-mcp-header`.
- Authorisation changes: authorisation servers SHOULD include `iss` in authorisation responses (RFC 9207) and clients MUST validate it; client credentials are bound to the issuing authorisation server; clients must specify `application_type` in dynamic registration.
- Deprecated: Dynamic Client Registration (RFC 7591) in favour of Client ID Metadata Documents; Roots, Sampling and Logging features; HTTP+SSE transport. Tasks moved to an extension. A feature lifecycle policy sets a minimum twelve-month deprecation window.

Discovery (2026-07-28), [P] — [MCP: server/discover](https://modelcontextprotocol.io/specification/2026-07-28/server/discover.md):
- `server/discover` returns `supportedVersions`, `capabilities`, `_meta` serverInfo (name, version; SHOULD be included), optional `instructions`, plus `ttlMs`/`cacheScope`.
- "`serverInfo` is self-reported by the server and is not verified by the protocol ... Clients SHOULD NOT ... rely on it for security decisions."

Tools (2026-07-28), [P] — [MCP: tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools.md):
- A tool has `name`, optional `title`, `description`, optional `icons`, `inputSchema` (required, JSON Schema, default dialect 2020-12), optional `outputSchema`, optional `annotations`.
- "clients MUST consider tool annotations to be untrusted unless they come from trusted servers."
- The tool set "MUST NOT vary per-connection" but "MAY vary by the authorization presented on the request — for example, returning only the tools the caller's granted scopes permit".
- Tool names are unique only within a server; server `name` is not guaranteed unique.
- Servers SHOULD NOT mark sensitive parameters with `x-mcp-header` because header values are visible to intermediaries.
- Handles for stateful tools: for authenticated servers "a handle is a name, not a capability" and must be authorised on every call; for unauthenticated servers the handle is necessarily a bearer token needing high entropy and bounded lifetime (non-normative guidance).
- Security: servers MUST validate inputs, implement access controls, rate limit, sanitise outputs; clients SHOULD confirm sensitive operations and log tool usage.

Authorisation model (read in full for 2025-11-25; 2026-07-28 restructures it into sub-pages and adds the changes listed above), [P] — [MCP 2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization):
- "Authorization is OPTIONAL for MCP implementations." HTTP transports SHOULD conform; STDIO SHOULD NOT and should take credentials from the environment.
- Based on OAuth 2.1 (draft-13), RFC 8414, RFC 7591, RFC 9728, and Client ID Metadata Documents.
- MCP servers MUST implement RFC 9728 Protected Resource Metadata with at least one `authorization_servers` entry, discoverable via a `resource_metadata` parameter in the `WWW-Authenticate` header of a 401 or at `/.well-known/oauth-protected-resource[/path]`.
- Servers SHOULD include `scope` in the 401 challenge; runtime insufficient scope SHOULD return 403 with `error="insufficient_scope"` and the needed scopes (step-up).
- Authorisation servers MUST provide RFC 8414 metadata or OIDC discovery; clients MUST verify PKCE support via `code_challenge_methods_supported` and refuse to proceed if absent; S256 required when capable.
- Clients MUST send the RFC 8707 `resource` parameter; servers MUST validate that tokens were issued specifically for them (audience) and MUST NOT accept or pass through other tokens; tokens MUST NOT appear in query strings; authorisation MUST be sent on every HTTP request.
- Registration priority: pre-registered, then Client ID Metadata Documents (`client_id_metadata_document_supported`), then Dynamic Client Registration (`registration_endpoint`), then user prompt.
- Authorisation server endpoints MUST be HTTPS; redirect URIs MUST be localhost or HTTPS.
- Extensions exist for OAuth client credentials and enterprise-managed authorisation. [P] (titles only) — [MCP authorization extensions overview](https://modelcontextprotocol.io/extensions/auth/overview.md)

2025-11-25 servers (still widely deployed) disclose via `initialize`: `protocolVersion`, `capabilities`, `serverInfo` (`name`, `version`, optional `title`, `description`, `websiteUrl`, `icons`) and optional `instructions` that "may be added to the system prompt". [P] — [MCP 2025-11-25 schema](https://modelcontextprotocol.io/specification/2025-11-25/schema.md)

Registry and server cards: an official MCP Registry exists with a moderation policy; SEP-2127 proposes MCP Server Cards for HTTP server discovery. [P] (index titles only) — [MCP registry: about](https://modelcontextprotocol.io/registry/about.md), [SEP-2127: MCP Server Cards](https://modelcontextprotocol.io/seps/2127-mcp-server-cards.md)

### Inferences
- Assessable with zero tool invocations, in probe order:
  1. **Unauthenticated POST** of `server/discover` (or `tools/list`) to the endpoint. Outcomes: 200 with content = server is open (finding, weighted by what the tools do); 401 with `WWW-Authenticate: Bearer resource_metadata=...` = spec-conformant protected server; 401 without metadata, or a non-OAuth scheme (static API key header) = non-conformant auth, still protected; HTTP (not HTTPS) = finding.
  2. **Protected Resource Metadata**: `authorization_servers`, `scopes_supported`; is the `resource` value the canonical URL.
  3. **Authorisation server metadata**: PKCE `S256` advertised; `registration_endpoint` present (open dynamic registration, now deprecated, means anyone can mint a client); `client_id_metadata_document_supported`; issuer consistency.
  4. **`server/discover`** (or legacy `initialize`): supported versions (a server offering only pre-2025-06 versions predates RFC 9728 and audience binding), capabilities, `instructions` text (scan for prompt-injection patterns), `cacheScope`.
  5. **`tools/list`** with the customer's own token: tool names, descriptions (tool-poisoning text, hidden instructions, unusual Unicode), `inputSchema` (free-form string parameters named like `query`, `command`, `path`, `url`, `sql` indicate injection/SSRF/exfiltration surface; sensitive parameters marked `x-mcp-header`), `outputSchema` field names (data classification, A7), and annotations.
  6. **Diff across identities and time**: because lists may vary by authorisation but must not vary by connection, listing with two tokens of different scope shows whether scope-based tool filtering exists; hashing the deterministic-order list each scan detects tool-definition drift ("rug pull").
- Annotations should be used as *claims to test*, not facts: a tool whose name/description/schema implies mutation (`delete_`, `write`, `execute`, `send`) but which declares itself read-only is a mismatch finding; a destructive, open-world tool on an unauthenticated server is the MCP toxic combination; treat annotations from servers not in the customer's allow-list as untrusted, as the spec requires.
- Cannot be assessed without invoking tools (or reading server source): whether the server actually validates token audience, whether it passes tokens through to upstream APIs, the upstream credentials and their scope, input validation quality, whether tool behaviour matches its description, rate limiting, and STDIO servers' environment credentials (those need the host's client config files, for example the MCP client JSON, rather than the protocol).
- For STDIO servers the posture surface is the launch command, package provenance (registry entry, pinned version) and environment variables in client configuration; authorisation spec does not apply.
- The scanner must speak both protocols for the next year or more: `server/discover` first, fall back to `initialize` (the spec describes exactly this probe for stdio; for HTTP, fallback is driven by status codes).

### Gaps
- **Tool annotation fields and defaults** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`, `title`) were not retrievable: both schema fetches truncated before `ToolAnnotations`, and the tools page only says "optional properties describing tool behavior". From recall of earlier spec versions, unverified for 2026-07-28: `readOnlyHint` default false, `destructiveHint` default true, `idempotentHint` default false, `openWorldHint` default true, all advisory. Confirm in the 2026-07-28 schema reference before relying on defaults.
- The 2026-07-28 authorisation sub-pages (authorization index, authorization-server-discovery, client-registration, security-considerations) were not opened; the authorisation rules above are verified for 2025-11-25, with 2026-07-28 deltas taken from the changelog only.
- Whether `server/discover` may be answered without authentication on a protected server is not stated on the discover page (ambiguous; the example marks its result `cacheScope: public`).
- Adoption of 2026-07-28 by real servers and clients as of November 2026 is unknown; no data found.
- MCP Server Cards (SEP-2127) status and any `.well-known` MCP discovery path were not read; registry `server.json` contents were not read.
- Enterprise-managed authorisation and client-credentials extensions were not read beyond their titles.

---

# RANKED UPGRADES

## Ranked list: the 15 engine upgrades with the highest value for effort

### Takeaway
The single largest step from "checklist" to "deep" is turning stored grants into evaluated permissions per system and feeding those as derived edges into a general graph with declarative path rules; nearly every other upgrade (scoring, choke points, customer rules, incremental scans) compounds on that foundation. Everything in this section is inference from the findings above; effort figures are rough estimates for a small team and are not sourced.

### Cited Findings
- The supporting evidence for each item is in the section named in the "Basis" column; no new facts are introduced here.

### Inferences

| # | Upgrade | What it is | Basis | Effort (est.) | Why this rank |
|---|---|---|---|---|---|
| 1 | Effective-permission evaluators per system | Pure functions `decide(principal, op, resource)` for Kafka, RabbitMQ, Redis, NATS implementing the documented order (deny precedence, patterns, super users, selectors, vhost regex, account boundaries), plus `who_can` / `what_can` enumeration with rule provenance | A2, B1 to B4 | 1 to 2 weeks per system | Fixes the core weakness (flat grant rows); every later item consumes it |
| 2 | Derived-edge layer in the graph | Materialise evaluator output as edges (`CAN_READ`, `CAN_WRITE`, `CAN_ADMIN`, `BINDS`, `IMPORTS`, `USES_CREDENTIAL`, `CAN_ACCESS` from an `Internet` node) with `via` and `because` | A1 (Prowler model) | 1 to 2 weeks | Makes attack paths data, not code |
| 3 | Effective-authentication evaluators for gateways | Kong route resolution (scope precedence, anonymous fallback, ACL, request-termination), API Gateway tables, Istio policy evaluation | B5 | 1 to 2 weeks | Converts "plugin present" into "route is actually open"; high false-positive and false-negative reduction |
| 4 | Declarative attack-path rule registry | Replace three hard-coded rules with query records (id, description, pattern over node/edge types, finding overlay); ship 20 to 30 middleware paths | A1 | 2 weeks | Unlocks breadth without engine changes; prerequisite for customer rules |
| 5 | Conformance test harness against real brokers | Containers plus grant matrices asserting simulator == real behaviour; resolves the documented ambiguities (RabbitMQ anchoring, Kafka ALTER implies DESCRIBE, RBAC+ACL precedence) | A9, B gaps | 1 to 2 weeks, then ongoing | Without it "effective" claims are unproven; cheap insurance |
| 6 | Explainable risk score | `likelihood x impact` from exposure state, auth effectiveness, operation class, data sensitivity confidence, blast-radius count; factors shown | A5 | 1 week | Immediate visible change; replaces severity-only ordering |
| 7 | Root-cause grouping and choke points | Collapse findings sharing one cause into an issue; rank edges by number of entry-to-crown-jewel paths removed | A1 (BloodHound), A5 | 1 to 2 weeks | Largest alert-volume cut; "fix one binding, close N paths" |
| 8 | Content-hash delta scanning with detector input declarations | Hash normalised resources, re-run only affected detectors and derived edges, keep full-sweep stale deletion | A6 (Cartography) | 2 weeks | Ends full re-evaluation; yields change log and drift for free |
| 9 | Schema-based data classification with confidence | Schema Registry, MCP tool schemas, n8n field mappings, API schemas; output `(type, sensitivity, confidence, evidence)` | A7 | 1 to 2 weeks | Biggest accuracy gain over name-only with no payload access |
| 10 | YAML custom rule language | Checkov-style attribute plus connection conditions, JSONPath into raw config, dry-run against last scan, inline tests; no code execution | A3 | 2 to 3 weeks | Customer-authored rules with no sandbox problem |
| 11 | Three-state exposure fusion | Per endpoint: config-exposed, probe-confirmed, auth-effective; mismatch findings | A4 | 1 week (probe exists) | Uses the existing DNS-gated scan to validate config reasoning |
| 12 | MCP no-invoke assessment | Unauthenticated challenge, RFC 9728 and AS metadata checks, `server/discover` with `initialize` fallback, tool schema and annotation mismatch analysis, tool-list hash drift | B7 | 1 to 2 weeks | Fast-moving area where precise spec-based checks are rare |
| 13 | Coverage-gap and fixture-coverage reporting | "Not assessed" distinct from "passed"; per-detector pass and fail fixtures enforced in CI; per-rule false-positive rate from dismiss reasons; suppressions with owner and expiry | A9 | 1 to 2 weeks | Trust and auditability; cheap |
| 14 | Event-triggered re-reads | Confluent audit topic, CloudTrail/EventBridge, n8n hooks, MCP list-changed as triggers to re-read one resource; never applied as state | A6 | 2 to 3 weeks | Near-real-time posture; depends on item 8 |
| 15 | Declared-state drift | Diff live grants against Terraform state, Strimzi CRDs, decK, RabbitMQ definitions; "live but not in code" findings; golden snapshot approval | A8 | 2 to 3 weeks | High-value finding class, but weakest sourcing and most connector work |

Deferred as lower value for effort: opt-in payload sampling with checksum validators (strong but needs privacy and consent engineering); pattern-language intersection via automata for "any future resource" queries; SMT-backed analysis; small-model classification; OpenGraph export.

Sequencing note: items 1, 2, 4 and 5 form one release (the "effective permissions" release) and should not be split, because derived edges without conformance tests risk confidently wrong findings, which is worse than the current flat rows.

### Gaps
- Effort estimates are judgment, not measured; they assume the current connectors already collect the raw fields each evaluator needs, which was not verified against the VectaSec codebase in this research task.
- No evidence was gathered on which of these capabilities buyers of small-company posture tools value most; the ranking weights engineering leverage, not market demand.
