# MCP Rulepack

**Target spec revision: 2025-11-25** (current FINAL, confirmed at https://modelcontextprotocol.io/specification/versioning). 2025-06-18 and 2025-03-26 are superseded. A release candidate for **2026-07-28** is locked (RC locked 2026-05-21, publishes 2026-07-28) and removes the `initialize` handshake and `MCP-Session-Id`; every rule below that depends on those surfaces carries a version gate. Build against 2025-11-25; re-verify the pack on 2026-07-28.

Rule count: 18 primary rules + 6 split-out sub-rules. Status of each is stated per section.

## What the scanner sees

Three distinct collectors, with different reachability and different consent requirements. A rule is only evaluable if its collector is wired in.

| Collector | Access needed | Surfaces yielded |
|---|---|---|
| **C1 — Unauthenticated network probe** | Network egress to the endpoint. No credentials. | HTTP status/headers on `POST /mcp`, `WWW-Authenticate`, `/.well-known/oauth-protected-resource*`, AS metadata, TLS handshake, cert chain |
| **C2 — Authenticated MCP client** | A valid bearer token for the target | `InitializeResult` (`instructions`, `serverInfo`, `capabilities`, `protocolVersion`), `tools/list` (all pages), `MCP-Session-Id` |
| **C3 — Host/gateway config read** | Read access to the host app's MCP registry (client config JSON, gateway admin API, k8s Service spec, Docker `HostConfig.PortBindings`) | Which servers are mounted into one agent context; stdio `command`/`args`; publish addresses |

**Not read-only, gate behind an explicit active-probe consent flag:** `initialize` allocates server-side session state on 2025-11-25 servers. Any rule that calls it MUST issue `HTTP DELETE` with the returned `MCP-Session-Id` afterward. Rules requiring a canary credential or an intentionally-malformed probe are marked ACTIVE.

**Never in scope for the scanner:** `tools/call` (side-effectful; `readOnlyHint` is self-asserted and per spec "clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers", so it cannot be used to establish safety), exploitation of any finding, minting tokens via DCR (`POST /register` is a write at the AS).

**Probe hygiene, applies to every C2 rule.** Send `Accept: application/json, text/event-stream` (a MUST for clients on POST). Parse **both** `application/json` and `text/event-stream` responses — the server MAY choose either, and a JSON-only parser silently misses SSE-mode servers. Echo the `MCP-Session-Id` from `InitializeResult` on every subsequent request (servers requiring a session SHOULD return 400 without it). Send `MCP-Protocol-Version` equal to the version negotiated in `InitializeResult`, never a hardcoded one. Send `notifications/initialized` before `tools/list`. Drain `nextCursor` pagination on `tools/list` before hashing or classifying.

**Posture vs conformance.** Authorization is **OPTIONAL** in MCP. Rules keyed on "no auth" are *deployment-posture* findings, not spec violations. Never word evidence as "non-compliant" for these.

---

## MCP.AUTH.UNAUTHENTICATED_ENDPOINT

**Severity:** high (base). Escalate to `critical` only on operator-confirmed sensitive/state-changing toolset — never automatically.
**Kinds:** `mcp_server`, `route`, `service`
**Collector:** C1 (ACTIVE — allocates a session; clean up)
**Class:** posture, not conformance.

**Precondition (recorded, not a FAIL condition):** transport is Streamable HTTP (skip stdio). Record the scanner's vantage point — source network zone and resolved target IP — as evidence fields. A probe proves reachability *from where you probed*; it cannot see the server's bind address, upstream firewall, security group, or service-mesh policy. **Never assert "internet-exposed" from a probe.**

**Check**
1. `POST {endpoint}` with a JSON-RPC `initialize`, no `Authorization` header, `Accept: application/json, text/event-stream`.
2. If 200, send `notifications/initialized`, then `tools/list` echoing `MCP-Session-Id` and the negotiated `MCP-Protocol-Version`.
3. **FAIL** if step 1 returns HTTP 200 carrying a JSON-RPC `result` (an `InitializeResult` with `serverInfo`/`capabilities`) rather than 401.
4. `HTTP DELETE {endpoint}` with the session ID.

**Tiering (mandatory — prevents the dominant false positive).** Steps 1–2 prove **discovery** exposure only, not **execution** exposure. A public read-only docs server and an open server exposing `delete_repo` produce byte-identical evidence. Emit:
- `initialize`+`tools/list` open → **"unauthenticated tool discovery"**, high.
- Confirmed unauthenticated *execution* → separate auth-bypass finding. The scanner does not establish this; it requires operator confirmation.

**Evidence claim**
> Unauthenticated POST initialize to {endpoint} returned HTTP 200 with an InitializeResult (serverInfo.name={name}, protocolVersion={ver}); unauthenticated tools/list returned {n} tool definitions. No 401 challenge issued. Probed from {source_zone} to resolved IP {ip}; this establishes reachability from that vantage point only.

**Remediation**
Per the transports spec Security Warning, "Servers **SHOULD** implement proper authentication for all connections" and "When running locally, servers **SHOULD** bind only to localhost (127.0.0.1) rather than all network interfaces (0.0.0.0)". For a local server the spec's preferred hardening is to "Use the `stdio` transport to limit access to just the MCP client", or if HTTP is required, "Require an authorization token" or "Use unix domain sockets or other Interprocess Communication (IPC) mechanisms with restricted access". If auth is adopted, note that "authorization **MUST** be included in every HTTP request from client to server, even if they are part of the same logical session", and unauthenticated requests should receive 401 with `WWW-Authenticate: Bearer resource_metadata="..."`.

**False-positive risk: high.** Gate before shipping.
- *Intentionally public servers* (docs/search/reference/registry). Unauthenticated read is the product. **Requires an operator allowlist keyed on endpoint URL.** No intent signal exists in the protocol.
- *Auth at the tool-call layer with open discovery.* Spec-legal and actively requested by implementers (fastmcp issue #3291, closed 2026-02-25: "user adds MCP server -> immediately gets 19 public tools, no login required. User invokes the authenticated tool -> then the OAuth flow triggers"). The discovery/execution tiering above is what mitigates this.
- *Authenticating gateway / mTLS / service mesh / VPN / IP allowlist in front.* A scanner inside the trust boundary always sees 200. Common in k8s and enterprise.
- *Loopback carve-out is unreliable in containers.* A pod-local or ClusterIP-only server has a non-loopback address but no ingress; the carve-out fails open.

Base rate is high (Knostic, 2025-07-17: 1,862 internet-exposed servers found via Shodan, 119 manually verified, **all 119** returned tool listings to an unauthenticated `tools/list`). A rule firing on a large fraction of targets with no intent signal will be triaged as noise — the allowlist is not optional.

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports (Security Warning — primary basis)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices (Local MCP Server Compromise — remediation basis)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization (401 challenge / per-request auth text only)
- https://www.knostic.ai/blog/mapping-mcp-servers-study

---

## MCP.AUTH.PRM_MISSING_OR_MISMATCHED

**Severity:** medium
**Kinds:** `mcp_server`, `route`
**Collector:** C1

**Gate (mandatory).** Fire only if an unauthenticated `POST` (JSON-RPC `initialize`, `Accept: application/json, text/event-stream`) returns **401 or 403** — i.e. the server claims to be an OAuth protected resource. **SKIP on 2xx** (authorization is OPTIONAL; a public server owes no PRM). **SKIP stdio** (spec: stdio "**SHOULD NOT** follow this specification"). Use POST, not GET — a bare GET returns 405 on some Streamable HTTP servers.

**Check**
1. Parse `WWW-Authenticate` on the 401 for a `resource_metadata` parameter.
2. If absent, GET in spec order: `https://{host}/.well-known/oauth-protected-resource{/path-of-mcp-endpoint}`, then `https://{host}/.well-known/oauth-protected-resource`.
3. **FAIL** if neither the header nor either well-known URI yields a JSON document (both 404).
4. If a PRM document is retrieved, **FAIL** if:
   - `authorization_servers` is missing, not an array, or empty *(the MUST here is MCP-specific — RFC 9728 §2 marks the field OPTIONAL; attribute it to the MCP spec in evidence)*;
   - `resource` is absent (REQUIRED per RFC 9728 §2);
   - `resource` is not byte-equal to **the base derived from the well-known URL that actually served the document** — strip `/.well-known/oauth-protected-resource` from the fetched URL. **This is the comparison base, not the MCP endpoint URL.**

**Comparison base — do not get this wrong.** RFC 9728 §3.3: "The `resource` value returned **MUST** be identical to the protected resource's resource identifier value into which the well-known URI path suffix was inserted to create the URL used to retrieve the metadata." Comparing against the MCP endpoint contradicts the RFC. `mcp.asana.com/sse` 404s on `/.well-known/oauth-protected-resource/sse`, falls back to root, returns `resource="https://mcp.asana.com"` — **fully §3.3-compliant**. Same for `mcp.paypal.com/mcp`. The MCP spec lists *both* `https://mcp.example.com/mcp` and `https://mcp.example.com` as valid canonical URIs, and "most specific URI" is SHOULD, not MUST.

Relax equality on scheme/host **case** and trailing slash — spec says implementations "**SHOULD** accept uppercase scheme and host components for robustness". Report those deltas as info, not medium.

**Evidence claim**
> MCP server {endpoint} returned {401|403} unauthenticated. Discovery: WWW-Authenticate {lacked resource_metadata | absent}; GET {well_known_url} returned {status}. PRM served from {served_from_url} (implied resource identifier "{base}") declares resource="{resource}" and authorization_servers={value}. The non-empty authorization_servers requirement is MCP-specific (RFC 9728 §2 marks the field OPTIONAL).

**Remediation**
Implement RFC 9728: serve a Protected Resource Metadata document whose `resource` equals the resource identifier implied by the well-known URL serving it, with a non-empty `authorization_servers` array, and advertise it via the `resource_metadata` parameter of `WWW-Authenticate` on 401. Spec: "MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728)" and the document "**MUST** include the `authorization_servers` field containing at least one authorization server."

**False-positive risk: high as written, low once gated.** Measured on 15 live servers: ungated it fires 6/15 with ≥3 false positives (asana, paypal §3.3-compliant; deepwiki `mcp.deepwiki.com/mcp` returns 200 to unauthenticated `initialize` — serverInfo "DeepWiki 2.14.3" — and 404s both well-known URIs, a compliant public server; same for `gitmcp.io/docs`). With the 401/403 gate and the §3.3 base fix it fires ~3/15, all genuine.

**Confirmed true positives:** `mcp.intercom.com/mcp` — 401, `WWW-Authenticate` with no `resource_metadata`, both well-known URIs 404. `mcp.atlassian.com/v1/sse` — 401 with **no** `WWW-Authenticate` at all, both 404. Both violate "MCP servers **MUST** implement one of the following discovery mechanisms."

**Impact ceiling — do not overstate.** Missing PRM is a discovery/interop MUST violation, not an exploitable auth bypass. Token audience validation is enforced server-side and is unaffected by PRM absence (see MCP.AUTH.TOKEN_AUDIENCE_UNVALIDATED). Do not claim a mismatch "means audience binding is advertised against the wrong identifier" — unsupported.

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- RFC 9728 §2, §3.3

---

## MCP.AUTH.PKCE_S256_NOT_OFFERED

**Severity:** high
**Kinds:** `mcp_server`, `broker`, `service`
**Collector:** C1

**Check**
Resolve each issuer in the PRM `authorization_servers` array. GET AS metadata in spec priority order — issuers **with** a path: `/.well-known/oauth-authorization-server/{path}`, then `/.well-known/openid-configuration/{path}`, then `{issuer}/.well-known/openid-configuration`; **path-less** issuers: `/.well-known/oauth-authorization-server`, then `/.well-known/openid-configuration`. Record which candidate URL actually resolved.

**FAIL** if `code_challenge_methods_supported` is **present but does not contain `S256`** (e.g. `["plain"]`). This is direct positive evidence of a downgrade.

If **every** candidate 404s → emit a separate *AS-metadata-undiscoverable* finding, **not** a PKCE finding. (Concrete case: issuer `https://login.microsoftonline.com/common/v2.0` — candidate 1 `/.well-known/oauth-authorization-server/common/v2.0` returns 404 and discovery falls through to the OIDC document.)

**Evidence claim**
> AS metadata at {metadata_url} (resolved from candidate {n} of the spec discovery order) for issuer {issuer} advertises code_challenge_methods_supported={value}, which does not include "S256".

**Remediation**
Support PKCE with S256 and publish `code_challenge_methods_supported: ["S256"]`. Spec: "MCP clients **MUST** use the `S256` code challenge method when technically capable."

**False-positive risk: low.** Positive evidence; no inference.

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

---

## MCP.AUTH.PKCE_METHODS_NOT_ADVERTISED

**Severity:** medium (conformance/interop, not proven crypto weakness)
**Kinds:** `mcp_server`, `broker`, `service`
**Collector:** C1

**Check**
Same discovery as above. **FAIL** if `code_challenge_methods_supported` is **absent**.

**Downgrade to `info` + annotate** when the issuer host matches the known-omitter list — these providers were verified to support S256 while omitting the field:
- `login.microsoftonline.com`, `*.ciamlogin.com`, `sts.windows.net` (Microsoft Entra ID / Azure AD)
- `*.snowflakecomputing.com` (Snowflake)

Match on issuer host. Maintain this list.

**Evidence claim**
> AS metadata at {metadata_url} for issuer {issuer} does not advertise code_challenge_methods_supported (observed: {value_or_ABSENT}). Per MCP spec 2025-11-25, MCP clients MUST refuse to proceed when this field is absent, so spec-compliant clients will fail to connect. Note: absence does not prove the AS lacks S256 support — several major providers support S256 without advertising it.

**Do not** assert or imply the AS lacks PKCE. The spec sentence "If `code_challenge_methods_supported` is absent, the authorization server does not support PKCE and MCP clients **MUST** refuse to proceed" may be quoted as *rationale*; it must never be restated as an observed fact about the target.

**Remediation**
Publish `code_challenge_methods_supported: ["S256"]` in AS metadata. OpenID providers must include the field explicitly to be MCP-compatible.

**False-positive risk: medium**, mitigated by the omitter list.

**Removed from the original rule — do not reintroduce.** "FAIL if `token_endpoint_auth_methods_supported` permits `client_secret_basic`/`client_secret_post` for public clients without also offering PKCE" is **unobservable**. AS metadata carries no public/confidential client distinction; that field lists methods the AS accepts at the token endpoint, not which client types may use them. Client type is per-client registration data, invisible to a metadata fetch. Verified: Apollo MCP advertises `["client_secret_basic","client_secret_post","none"]` *alongside* `code_challenge_methods_supported=["S256"]`; Entra advertises `["client_secret_post","private_key_jwt","client_secret_basic","self_signed_tls_client_auth"]` with no `"none"`. Neither tells you anything about public-client PKCE.

**Follow-on worth adding:** `code_challenge_methods_supported` containing `"plain"` alongside `"S256"` is an uncovered downgrade risk (Google advertises `["plain","S256"]` and passes both rules above).

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

---

## MCP.AUTH.TOKEN_AUDIENCE_UNVALIDATED

**Severity:** critical when the AS allows attacker-controlled token minting (multi-tenant/public IdP, open DCR). **Downgrade to high** for a single-tenant AS where the attacker needs an existing foothold to obtain any valid token — that is lateral movement, not anonymous bypass.
**Kinds:** `mcp_server`, `route`
**Collector:** C2 + canary credential (ACTIVE)
**Confidence:** medium — no clean read-only check exists.

**Scope.** The canary is only free when the customer has **≥2 MCP servers on one AS** (replay server A's token at server B). Single-server inventories require minting a token via dynamic client registration (`POST /register` = a write at the AS), which a read-only client cannot do. Scope this rule to the ≥2-resource case or to an explicitly provisioned canary.

**Gate 1 — no-token baseline (mandatory).** Probe with no `Authorization` first. If it returns 200, the server has no auth at all → **suppress this rule**, emit MCP.AUTH.UNAUTHENTICATED_ENDPOINT. Precondition: the server MUST return 401 + `WWW-Authenticate`/PRM unauthenticated before this rule may fire. Without this gate the evidence claim is misattributed across a very large population.

**Gate 2 — decode the canary (mandatory).** Assert: `aud` present, token unexpired, and the target's canonical URI **not** in `aud` (`aud` may be an array per RFC 7519). If `aud` is absent → emit a distinct **AS-side** finding, not this one. The spec concedes many ASes ignore RFC 8707 ("clients **MUST** send this parameter regardless of whether authorization servers support it"); if the AS ignored `resource` and minted a token with no/generic `aud`, the canary is not foreign-audience and a 200 proves nothing about the MCP server.

**Gate 3 — canary provenance.** Never build the canary from a path/case/trailing-slash variant of the target. A server may legitimately register its origin (`https://mcp.example.com`) as audience while serving at `https://mcp.example.com/mcp`. Use a demonstrably unrelated resource **on a different host**.

**Check**
1. `initialize` with `Authorization: Bearer <foreign-aud-token>`, then `tools/list` echoing `MCP-Session-Id` and `MCP-Protocol-Version`.
2. **FAIL only on a parsed successful body** — a genuine `InitializeResult` or a non-empty `tools` array. **Do not FAIL on status alone.** JSON-RPC-layer errors are conventionally delivered at HTTP 200 with `{"error":{...}}`; a server that rejects the token at the JSON-RPC layer is spec-noncompliant on status but **secure**, and status-matching flags it wrongly.
3. Note the false-negative statuses: 403 (bad Origin), 400 (bad `MCP-Protocol-Version` or missing `MCP-Session-Id`), 404 (dead session).
4. `HTTP DELETE` to clean up.

**Passive corroborating signal (demoted).** "PRM `resource` not an accepted audience in the AS registration" requires AS-vendor-specific admin API reads and is evidence about the **AS**, not the MCP server. Do not use it as the primary signal.

**Evidence claim**
> MCP server {endpoint} returned a valid InitializeResult/tools array when presented a token with aud="{foreign_aud}" (decoded; unexpired; canonical resource "{canonical}" absent from aud). The same endpoint returned 401 with no token. The server does not verify it is the intended recipient of inbound tokens.

**Remediation**
Reject any token the server is not the intended recipient of. Spec: "MCP servers **MUST** only accept tokens specifically intended for themselves and **MUST** reject tokens that do not include them in the audience claim **or otherwise verify that they are the intended recipient of the token**" and "MCP servers **MUST NOT** accept or transit any other tokens." Note the spec does **not** mandate the `aud` claim specifically — opaque tokens validated via RFC 7662 introspection are compliant. If the server calls upstream APIs it must obtain a separate token from the upstream AS: "The MCP server **MUST NOT** pass through the token it received from the MCP client." Clients should send the RFC 8707 `resource` parameter on both authorization and token requests. Authority for the audience requirement is the MCP authorization spec §Access Token Privilege Restriction + RFC 8707 §2 + RFC 9068 — **not** OAuth 2.1 §5.2, which reads in full "The authorization server MUST ensure that access tokens cannot be generated, modified, or guessed to produce valid access tokens by unauthorized parties," never mentions audience, and addresses the AS rather than the resource server. (The MCP spec does say "A MCP server **MUST** follow the guidelines in OAuth 2.1 - Section 5.2 to validate inbound tokens", so citing it is faithful; presenting it as the authority for audience rejection is not.)

**Relationship to token passthrough — soften.** A server accepting a foreign-audience token **may also be** a passthrough candidate. Not "by definition": the spec treats these as two distinct dimensions ("1. Audience validation failures. 2. Token passthrough"), and passthrough additionally requires forwarding the token upstream, which a server with no upstream API never does.

**False-positive risk: high as written → low with Gates 1–3.** Remaining: deliberate shared audience (gateway/fleet designs issue one audience for many backends; `aud` may legally be an array) — support a per-target allowlist of additionally-accepted audiences to downgrade.

**Not theoretical:** fastmcp < 3.2.4 (SFTY-20260416-44662 / pyup.io-93393) — `AuthKitProvider` set `JWTVerifier.audience` from `client_id` instead of the canonical resource URL, making tokens interchangeable across MCP servers in one WorkOS AuthKit tenant. That advisory carries CVSS 0.0/Unknown; there is no authoritative score.

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization (all three quotes: §Access Token Privilege Restriction, §Access Token Usage > Token Handling)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices (§Token Passthrough > Mitigation: "MCP servers **MUST NOT** accept any tokens that were not explicitly issued for the MCP server")

---

## MCP.AUTH.SCOPE_OVERBROAD

**Severity:** low (baseline). §Scope Minimization carries **no MUST/SHOULD server obligations** — it is non-normative "Common Mistakes" guidance, unlike Token Passthrough (MUST NOT) or session hijacking (MUST). Impact is conditional on a separate compromise (token theft). Escalating a literal `*`/`all`/`full-access` match to medium is defensible as a per-match escalation, not as the rule's baseline.
**Kinds:** `mcp_server`, `acl`, `mcp_tool`
**Collector:** C1 (unauthenticated GET of the PRM well-known URI)

**Not-applicable guard (mandatory).** `scopes_supported` is OPTIONAL per RFC 9728 §2. **If absent, the rule MUST NOT fire.**

**Check**
Parse `scopes_supported` from the PRM document. **FAIL** if any scope string:
- is exactly `*`, `all`, `full`, or `full-access`; **or**
- matches `^[A-Za-z0-9_.-]+:\*$` (e.g. `files:*`, `db:*`, `s3:*`, `S3:*`); **or**
- ends in `.*`

The prefix-wildcard check is source-backed — the spec's attack description names `files:*`, `db:*`, `admin:*` verbatim.

**Evidence claim**
> PRM at {prm_url} advertises scopes_supported={scopes}, including wildcard/omnibus scope "{scope}", which MCP 2025-11-25 Security Best Practices §Scope Minimization lists under Common Mistakes.

**Remediation**
Adopt a progressive least-privilege scope model: publish a minimal baseline scope set (e.g. `mcp:tools-basic`) covering only low-risk discovery/read operations in `scopes_supported`, and elevate incrementally via targeted `WWW-Authenticate: Bearer error="insufficient_scope", scope="..."` challenges on HTTP 403 when a privileged tool is first called. Spec §Scope Minimization "Common Mistakes" explicitly lists publishing all possible scopes in `scopes_supported`, using wildcard or omnibus scopes (`*`, `all`, `full-access`), and returning the entire scope catalogue in every challenge.

**False-positive risk: low once narrowed.** Three clauses were **removed** and must not be reintroduced:

1. **`admin`, `root`, `write`, `read_write` literals — deleted.** Unsupported by source (the spec names only `*`, `all`, `full-access` as wildcard/omnibus) and self-contradictory: it would fail a server for exposing a `write` scope while a separate clause failed it for *not* separating read from write. A bare `admin` scope alongside `read` **is** privilege separation.
2. **"N>10 scopes + 401 returns the entire catalogue" — deleted.** It inverts the normative authorization spec: "The scopes included in the `WWW-Authenticate` challenge **MAY** match `scopes_supported`, be a subset or superset of it, or an alternative collection… Clients **MUST NOT** assume any particular set relationship between the challenged scope set and `scopes_supported`." The same spec defines `scopes_supported` as "intended to represent the minimal set of scopes necessary for basic functionality" — so a challenge equal to `scopes_supported` is **expected**. N=10 was invented with no source. §Scope Challenge Handling further blesses an "Extended approach: Include existing scopes, newly required scopes, and related scopes that commonly work together."
3. **The `tools/list` / `destructiveHint` cross-reference — deleted.** `Tool.annotations` is optional and most real servers omit it; `destructiveHint` defaults to **true** and is "meaningful only when `readOnlyHint == false`". With annotations absent you cannot identify the "read-only tools" the clause requires as a conjunct — the clause is either unsatisfiable or universally firing. The schema states all `ToolAnnotations` are "hints… not guaranteed to provide a faithful description of tool behavior." It also inverts the spec a second time: a single minimal scope is exactly what the spec asks for, so failing on "advertises only one scope" penalizes conformant servers. It also required an authenticated session, unlike the rest of the rule.

**Note on provenance:** RFC 9728 defines only `resource_metadata` for `WWW-Authenticate`; the `scope` auth-param comes from RFC 6750 §3, and MCP layers a SHOULD on top ("MCP servers **SHOULD** include a `scope` parameter in the `WWW-Authenticate` header").

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices (§Scope Minimization > Common Mistakes)

---

## MCP.TRANSPORT.PLAINTEXT_HTTP

**Severity:** high. **Downgrade to medium** when the endpoint host is RFC1918 (10/8, 172.16/12, 192.168/16), a Docker-network name, or `host.docker.internal` — TLS may be terminated upstream and the scanner cannot see an ingress or service-mesh sidecar from the URL alone.
**Kinds:** `mcp_server`, `route`, `service`
**Collector:** C1

**Two tiers — they have different authority.**
- **Tier A — AS/OAuth endpoint plaintext = spec MUST violation.** Quote the spec.
- **Tier B — MCP endpoint plaintext = CWE-319** cleartext transmission of bearer tokens. **There is no HTTPS MUST for the MCP endpoint** in the 2025-11-25 transports spec — only the illustrative "For example, this could be a URL like `https://example.com/mcp`". Cite OAuth 2.1 §5.1.1 (Authorization header requirement), never a fabricated transports MUST.

**Check**
Inspect the configured MCP endpoint URL and every OAuth URL discovered during introspection: PRM `authorization_servers` entries, AS metadata `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `jwks_uri`.
**FAIL** if any uses scheme `http://` **and** the host does not resolve to loopback. Loopback set: `localhost`, `127.0.0.0/8`, `::1`, **`::ffff:127.0.0.1`** (IPv4-mapped IPv6 loopback).
**Emit one finding per URL** — the rule fires on any single match, so a combined evidence string would over-assert.

**Certificate validation (spec-backed).** FAIL on expired / self-signed / hostname-mismatched certificate. OAuth 2.1 §1.5: "When using `https`, TLS certificates **MUST** be checked according to [RFC9110]."

**TLS version (separate probe, re-sourced).** FAIL if the endpoint negotiates below TLS 1.2 — cite **BCP 195 / RFC 8996**, *not* the MCP spec. MCP §Security Considerations defers to OAuth 2.1 §1.5, which explicitly states "The identification of the TLS versions and algorithms is outside the scope of this specification" and references TLS 1.3 only descriptively. Detecting this requires **active downgrade probing** (offering only TLS 1.0/1.1 handshakes) — a scanner connecting with modern defaults negotiates the best mutual version and will never observe that TLS 1.0 remains enabled. Run it as a distinct probe from metadata introspection and record both "highest negotiated" and "lowest accepted".

**`redirect_uris` — removed from this collector.** It is **not observable read-only**: PRM → `authorization_servers` → AS metadata never yields redirect URIs (per-client registration data; RFC 8414 metadata does not expose it), and RFC 7592 client-configuration reads require a registration access token and reveal only the scanner's own client. Re-scope this clause to fire **only** when scanning client-side config or a Client ID Metadata Document. When it does run: the spec's own CIMD example lists `http://127.0.0.1:3000/callback` and `http://localhost:3000/callback` as legitimate — **loopback http redirect URIs must never fire.**

**Evidence claim (per URL)**
> {role} URL {url} uses scheme http:// with host {host} resolving to non-loopback {ip}. TLS: highest negotiated {tls_negotiated_or_NONE}, lowest accepted {tls_floor_or_UNTESTED}. Certificate: {cert_status}.

**Remediation**
Serve the MCP endpoint and all OAuth endpoints over HTTPS with a valid certificate. Spec: "All authorization server endpoints **MUST** be served over HTTPS" and "All redirect URIs **MUST** be either `localhost` or use HTTPS." Access tokens must not appear in query strings ("Access tokens **MUST NOT** be included in the URI query string"). Separately, disable TLS below 1.2 per BCP 195/RFC 8996 (this is not an MCP spec requirement).

**False-positive risk: medium.** Private-address downgrade path above is the main mitigation.

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization

---

## MCP.TRANSPORT.DEPRECATED_HTTP_SSE

**Severity:** low. HTTP+SSE is **Deprecated, not Removed**; no CVE; the probe proves no active exploit primitive. SEP-2596 merged ~2026-05-18 (Final ~2026-06-03, medium confidence — read off the GitHub PR page), so earliest removal is roughly 2026-09 — still future as of 2026-07-17. Lifecycle/hygiene.
**Kinds:** `mcp_server`, `route`
**Collector:** C1

**Title is deliberately "exposes", not "instead of"** — the check cannot distinguish "instead of" from "in addition to".

**Check**
1. POST an `InitializeRequest` with `Accept: application/json, text/event-stream`.
2. On HTTP 400/404/405: **first inspect the body**. A modern server returns 404 + JSON-RPC `-32601` for an unknown method; a recognized modern JSON-RPC error means **stop — not legacy**. Only if the body is not a modern JSON-RPC error, fall back to GET.
3. GET the same URL. **FAIL** if the response is `Content-Type: text/event-stream` whose first SSE event is named `endpoint` — the 2024-11-05 handshake, in which a separate POST message endpoint is advertised.
4. Version probe (**gate on era**): read `protocolVersion` from `InitializeResult`; FAIL at `info` if it is `2024-11-05`. This probe only works for 2025-03-26…2025-11-25 — the 2026-07-28 revision removes the `initialize` handshake in favour of per-request `_meta` and will silently break it.

**Known false negative:** an auth-gated legacy server returns 401, which is not in {400,404,405}, so the GET fallback never triggers.

**Evidence claim**
> GET {endpoint} returned text/event-stream with first SSE event name="endpoint" (data={post_url}), indicating the deprecated HTTP+SSE transport; initialize reported protocolVersion="{version}". Modern Streamable HTTP {was|was not} detected at {modern_endpoint_probed}.

**Remediation**
Migrate to Streamable HTTP: expose a single MCP endpoint path supporting both POST and GET. **(Pinned to 2025-11-25.** The 2026-07-28 revision removes the GET stream endpoint and protocol-level sessions and tells servers to return 405 to GET — this remediation's mechanics change on that date.) HTTP+SSE has been Deprecated since revision 2025-03-26 and is registered as Deprecated under SEP-2596, with earliest removal three months after SEP-2596 reaches Final — "New implementations **SHOULD NOT** adopt it." The 2024-11-05 transport also predates any MCP authorization spec and therefore the RFC 9728 model ("MCP servers **MUST** implement OAuth 2.0 Protected Resource Metadata (RFC9728)").

**False-positive risk: medium.** The spec explicitly **recommends** dual-hosting: "Continue to host both the SSE and POST endpoints of the old transport, alongside the new MCP endpoint." Legacy compat endpoints conventionally live at `/sse` while the modern one is at `/mcp`. A single-URL probe pointed at `/sse` fires on a server that fully supports Streamable HTTP at `/mcp` and is correctly following the blessed migration pattern. **Mitigation (mandatory):** before concluding, also probe the conventional modern endpoint and any advertised MCP endpoint; downgrade to `info` when Streamable HTTP is present and report **"legacy compat endpoint still exposed"**, not "server uses deprecated transport."

**Removed / split out:**
- *"WARN if the server accepts requests with no `MCP-Protocol-Version` header"* — **deleted, it is inverted.** 2025-11-25 states the server "**SHOULD** assume protocol version 2025-03-26" when the header is absent. It would warn on spec-mandated behaviour and fire on nearly every conformant server.
- *"fails to return HTTP 400 for an unsupported version value"* — **split to its own rule** (below). It is a real MUST but is version-validation conformance, unrelated to this rule's title, and this rule's evidence claim does not cover it.
- *"the separate POST endpoint is keyed only by session ID"* — **deleted from the rationale.** Not in any spec; 2024-11-05 says only "a URI for the client to use for sending messages". Session-ID-in-query-param is a Python/TS SDK convention, not normative. Session hijacking is also not unique to HTTP+SSE (2025-11-25 has a session_hijacking section covering `Mcp-Session-Id` in Streamable HTTP too).

**Sources**
- https://modelcontextprotocol.io/specification/draft/deprecated (SEP-2596 lifecycle facts; this registry exists only under /draft/)
- https://modelcontextprotocol.io/specification/2024-11-05/basic/transports ("the server **MUST** send an `endpoint` event containing a URI for the client to use for sending messages")
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports (backward-compat fallback; remediation mechanics)

---

## MCP.TRANSPORT.PROTOCOL_VERSION_UNVALIDATED (split out)

**Severity:** low
**Kinds:** `mcp_server`, `route`
**Collector:** C1 (ACTIVE — sends an intentionally invalid header)

**Check:** send a request with `MCP-Protocol-Version: 9999-99-99`. **FAIL** if the server does not respond 400. Spec: "If the server receives a request with an invalid or unsupported `MCP-Protocol-Version`, it **MUST** respond with `400 Bad Request`."

**Evidence claim**
> {endpoint} returned HTTP {status} for MCP-Protocol-Version: 9999-99-99; spec requires 400 Bad Request.

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

---

## MCP.TRANSPORT.ORIGIN_UNVALIDATED

**Severity:** medium (default). **Escalate to high only when the target is loopback/private-bound AND unauthenticated** — the CVE-2025-49596 shape. Ecosystem CVSS for that exact condition is 7.6 High; the public-server case is near-informational.
**Kinds:** `mcp_server`, `route`
**Collector:** C1 (ACTIVE — allocates a session; clean up)

**Scope gate (mandatory).** DNS rebinding is a **localhost threat model only**. MCP maintainers state on PR modelcontextprotocol#1439: "DNS rebinding mitigation only makes sense for local deployments… Public servers are not affected by DNS rebinding." Both SDK advisories confirm — CVE-2025-66416 (Python, CVSS 7.6, GHSA-9h52-p55h-vw2f) fixed in 1.23.0 auto-enables protection **only** "when the host parameter is 127.0.0.1 or localhost"; CVE-2025-66414 (TS, GHSA-w48q-cv73-mx4w) likewise. **Fire only when** the endpoint resolves to loopback/RFC1918/link-local **and** no auth is enforced (no 401/`WWW-Authenticate` on an unauthenticated call). On a public, authenticated endpoint → `info`/hygiene. Unscoped, this rule fires on essentially every public MCP server on the internet.

**Check**
Send a **spec-conforming** `initialize` POST (`Accept: application/json, text/event-stream`, valid `MCP-Protocol-Version`) with `Origin: https://attacker.example`.

- **PASS** on any of: **401, 403, 421, or 400-with-an-origin-error.**
- **FAIL only on HTTP 200 + a valid JSON-RPC `InitializeResult`.**

**"FAIL on anything other than 403" was the rule's fatal bug — do not restore it.** Verified counterexamples: (a) the Python SDK returns **421 Misdirected Request / "Invalid Host Header"** when DNS-rebinding protection **is correctly enabled** (python-sdk issue #1798) — the rule would flag a correctly-hardened server as vulnerable; (b) an OAuth-protected server returns **401** — the most secure config scores worst; (c) the spec requires **400** for a bad/missing `MCP-Protocol-Version` or non-conforming `Accept`, so a malformed probe self-triggers; (d) SDKs disagreed historically (TS 403 vs Python 400) — the 403 wording only landed via PR modelcontextprotocol#1439.

Issue `HTTP DELETE` with the returned `MCP-Session-Id` — repeated probing otherwise leaks sessions.

**Sub-probes, both demoted to informational**
- **`Host` header rebinding simulation** — unreliable. Reverse proxies, CDNs, k8s ingress and LBs rewrite or vhost `Host`, and many hostnames legitimately map to one backend; the probe cannot distinguish "server accepted it" from "proxy rewrote it." Skip when a proxy/CDN is fingerprinted (see inspector#639, where Docker port-mapping broke legitimate origin validation).
- **`Origin: null`** — weak. The spec only requires rejecting origins invalid *per the server's own allowlist*, which a black-box scanner cannot know. A public server legitimately allowlisting browser origins (e.g. `https://claude.ai`, `https://app.cursor.com` — the SDK's own documented `allowedOrigins` example) correctly returns 200.

**CORS corroboration — removed, it was conceptually wrong.** DNS rebinding makes the request **same-origin** from the browser's view; CORS is not involved in the rebinding path at all, so ACAO says nothing about rebinding exposure. Worse, "FAIL (aggravating) on `Access-Control-Allow-Origin: *`" is **backwards** — with `*` browsers refuse to send credentials, making it strictly *safer* than reflected-origin + `Access-Control-Allow-Credentials: true`. Only the reflected-origin + ACAC:true pair is a genuine finding, and that is a separate CORS rule. If browser-exploitability is the real question, probe the **OPTIONS preflight** — a cross-origin POST with `Content-Type: application/json` cannot be sent by a browser at all unless preflight passes. Preflight is the actual determinant and the original rule ignored it.

**Evidence claim**
> POST {endpoint} with Origin: https://attacker.example returned HTTP {status} with a valid InitializeResult; expected a rejection (401/403/421/400-origin-error). Endpoint resolves to {ip} ({loopback|private|public}) and {does|does not} enforce authentication.

**Remediation**
Validate the `Origin` header on all incoming connections against an allowlist. Spec (Streamable HTTP Security Warning): "Servers **MUST** validate the `Origin` header on all incoming connections to prevent DNS rebinding attacks. If the `Origin` header is present and invalid, servers **MUST** respond with HTTP 403 Forbidden."

Concrete config:
- **TypeScript SDK** — `StreamableHTTPServerTransport({ enableDnsRebindingProtection: true, allowedHosts: [...], allowedOrigins: [...] })`, or use `createMcpExpressApp()` which enables it. Upgrade to ≥1.24.0.
- **Python SDK** — `TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=[...], allowed_origins=[...])`. Upgrade to ≥1.23.0 for FastMCP localhost auto-enable.

Both SDKs still default the protection to **false** for backwards compatibility.

`Host` validation is **not** in the transports spec or security_best_practices (both fetched) — it comes from the SDK implementations (`allowedHosts`/`allowed_hosts`) and the Inspector's `originValidationMiddleware`. Cite those, not the spec.

**CVE-2025-49596 framing.** Accurate as narrative: CVSS 9.4, MCP Inspector <0.14.1, fixed 2025-06-13 by adding a session token + Host/Origin validation via `originValidationMiddleware` in `server/src/index.ts` plus localhost binding; a malicious web page reached the localhost proxy via DNS rebinding and the 0.0.0.0-day and achieved RCE. **But** the GHSA classes the root cause as **CWE-306 Missing Authentication**, with missing Origin validation as the enabling second condition. Do not present Origin validation alone as the control that would have prevented it.

**False-positive risk: high as written → low with the status accept-list and the loopback/unauth scope gate.**

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports (Streamable HTTP > Security Warning)
- https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596

---

## MCP.TRANSPORT.BIND_ALL_INTERFACES

**Severity:** medium. Bind-all is an **exposure amplifier, not a vulnerability**. The spec grades it SHOULD, deliberately weaker than the MUST on Origin validation. A 0.0.0.0-bound server *with* a bearer token is a minor hardening gap. Escalate only when unauthenticated access is **confirmed by probe**, never when inferred.
**Kinds:** `mcp_server`, `service`
**Collector:** C3 (orchestrated paths only) — see checkability split below

**Check**
- **Orchestrated / read-only-observable (this rule):** Kubernetes Service spec via GET — FAIL on `type: NodePort` or `LoadBalancer` fronting the server. Docker `HostConfig.PortBindings` — evaluate the **host-side publish** `HostIp`; FAIL if it is `0.0.0.0`/empty.
- **Host-local:** `ss -ltnp` / `netstat -anv`. **This is not reachable by a read-only admin API client** — it needs a host shell, and `-p` needs root/CAP_NET_ADMIN to attribute sockets to other users' processes. This is an internal contradiction in the original rule, which *targeted* local/developer use — precisely the mode where no admin API exists. **Split this into a separate rule with a declared host-agent requirement**, or drop it.

**Container false positive — must gate.** **Never fire on an in-container socket table alone.** The official MCP Inspector README's *recommended hardened* recipe is:

```
docker run --rm -p 127.0.0.1:6274:6274 -p 127.0.0.1:6277:6277 \
  -e HOST=0.0.0.0 -e MCP_AUTO_OPEN_ENABLED=false \
  ghcr.io/modelcontextprotocol/inspector:latest
```

`HOST=0.0.0.0` inside the netns is **correct and required** there; isolation comes from the `127.0.0.1` publish. The same applies to dev containers, WSL2, and Codespaces, where 0.0.0.0 inside the VM is required for host port forwarding.

**Heuristics removed — both are self-refuting:**
- *"no OAuth PRM published"* → authorization is OPTIONAL ("Authorization is **OPTIONAL** for MCP implementations"); the PRM MUST binds only when auth is implemented. The spec's own blessed local hardening is "Require an authorization token", which publishes no PRM. **Absence of PRM is not evidence of no auth.** Use the direct signal instead: HTTP 200 to an unauthenticated `initialize`.
- *"no TLS"* → pods behind a TLS-terminating ingress/service mesh serve plaintext by design. Combined with the above, both heuristics misfire on legitimate production servers using static bearer tokens behind an LB.

**CVE attribution removed.** The original check claimed BIND_ALL + UNAUTH + ORIGIN_UNVALIDATED "is the CVE-2025-49596 exposure shape." **False.** Tenable confirms the CORS vector "could be compromised even if the server was bound to localhost" and DNS rebinding "worked regardless of binding address"; Oligo confirms binding to localhost would **not** have prevented it (browsers alias 0.0.0.0 to localhost). The real CVE shape is **AUTH.UNAUTHENTICATED + ORIGIN_UNVALIDATED, bind-address-independent.** Gating `critical` on all three makes the scanner **miss** the genuine critical shape (loopback-bound + unauth + no Origin validation). Move the critical escalation to the AUTH+ORIGIN pair; treat BIND_ALL as an independent severity modifier for network reachability only. (The rule's own remediation already conceded this and contradicted its check.)

**Evidence claim**
> {k8s Service {name} is type {type} | Docker container {id} publishes {containerPort} on HostIp 0.0.0.0} fronting MCP server {server}. Host-side publish is non-loopback. Authentication status: {confirmed_unauthenticated_by_probe | not probed}.

The original evidence claim's "returned HTTP 200 to an unauthenticated initialize" is an **active probe** that creates state (the spec allows `initialize` to assign an `MCP-Session-Id`). Gate it behind the active-probe consent flag; do not perform it under a read-only posture scan, and mark the field `not probed` when it is skipped.

**Remediation**
Bind local MCP servers to 127.0.0.1 only. Spec: "When running locally, servers **SHOULD** bind only to localhost (127.0.0.1) rather than all network interfaces (0.0.0.0)" and "Servers **SHOULD** implement proper authentication for all connections." The spec's preferred hardening for local servers is to "Use the `stdio` transport to limit access to just the MCP client", or if HTTP is required, "Require an authorization token" or "Use unix domain sockets or other Interprocess Communication (IPC) mechanisms with restricted access." **Binding to loopback alone is insufficient against browser-based attacks** — pair with Origin validation and a session token. TypeScript SDK: the key is `enableDnsRebindingProtection`, disabled by default before v1.24.0 (GHSA-w48q-cv73-mx4w); v1.24.0+ adds automatic protection in `createMcpExpressApp()` when binding to localhost plus an exported `hostHeaderValidation()` middleware. MCP Inspector: the key is the `HOST` env var, with `MCP_PROXY_AUTH_TOKEN` / `DANGEROUSLY_OMIT_AUTH` governing auth.

**False-positive risk: high as written → medium with the container gate and heuristic removal.**

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports (first two quotes, verbatim for rev 2025-11-25)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices (§Local MCP Server Compromise — stdio / authorization token / unix domain socket quotes; note the spec reads "other Interprocess Communication (IPC) mechanisms", not "other IPC mechanisms")

---

## MCP.SESSION.PREDICTABLE_ID

**Severity:** medium — **not inflated, do not escalate to high.** Impact is contingent: the same security_best_practices page states "MCP Servers **MUST NOT** use sessions for authentication" and "MCP servers that implement authorization **MUST** verify all inbound requests", so a guessed session ID alone should not authenticate on an otherwise-compliant server. Predictability is a genuine MUST-violation but reaches impersonation only when the server **also** violates the no-session-auth MUST.
**Kinds:** `mcp_server`, `route`
**Collector:** C1/C2 (ACTIVE — allocates sessions)

**Version gate (mandatory).** Gate on the negotiated `MCP-Protocol-Version`; **auto-skip for ≥ 2026-07-28** — that revision removes this surface: "The `Mcp-Session-Id` header and the protocol-level session that came with it are also removed (SEP-2567)." As of 2026-07-17 it is a **release candidate** (locked 2026-05-21, final publication 2026-07-28 — 11 days away), **not yet shipped**. Flag this rule for sunset review; its addressable population starts shrinking in under two weeks.

**N/A skip (mandatory).** Stateless servers (`sessionIdGenerator: undefined`) return **no** `MCP-Session-Id` header. Emit **N/A-skip, not FAIL.**

**Check**
Issue **N = 8–12** fresh `initialize` requests (not 32 — see hygiene) and collect `MCP-Session-Id`. Clean up each with `HTTP DELETE`. Back off on 429.

**FAIL** on any **structural** test:
1. Value parses as an integer, a timestamp, or a counter.
2. Constant or near-constant delta between sorted values.
3. Charset + length below floor: **< 22 chars base62 / < 32 hex** (≥122 bits).
4. UUID version byte == **1**.
5. Value is derivable from request inputs via a **fixed enumerated** transform: md5/sha1/sha256/sha512 of user id, client name, email, or unix timestamp at second granularity.
6. Contains characters outside visible ASCII 0x21–0x7E *(spec violation; sourced to the **transports** page, not security_best_practices)*.

**Entropy threshold — 122 bits, not 128.** The original "~128 bits" **fails the spec's own recommended answer.** Per RFC 9562, UUIDv4 carries **122 bits** of randomness, and RFC 9562 says "If UUIDs are required for use with any security operation… then UUIDv4 **SHOULD** be utilized". The reference TypeScript SDK's canonical pattern is `sessionIdGenerator: () => randomUUID()` (v4). At 128 bits the rule fails **every spec-compliant reference-SDK server**. Accept UUIDv4 / ≥16 CSPRNG bytes outright.

**"Shannon entropy of the value set" — deleted, it is statistically incoherent.** 32 samples bound measurable distribution entropy at log2(32) = **5 bits**. You cannot compute a 122-bit entropy estimate from a sample set. Use the structural tests only.

**Evidence claim**
> {n} initialize calls to {endpoint} returned MCP-Session-Id values {sample}; values fail structural test {test} (delta={delta}, charset={charset}, length={len}, uuid_version={ver}), permitting session-ID guessing. Negotiated protocolVersion={ver}.

**Remediation**
Generate session IDs with a cryptographically secure RNG. Spec: "MCP servers **MUST** use secure, non-deterministic session IDs. Generated session IDs (e.g., UUIDs) **SHOULD** use secure random number generators. Avoid predictable or sequential session identifiers that could be guessed by an attacker" (security_best_practices) and "The session ID **SHOULD** be globally unique and cryptographically secure (e.g., a securely generated UUID, a JWT, or a cryptographic hash)" (**transports** §Session Management). Bind session IDs to user-specific information — "Use a key format like `<user_id>:<session_id>`" — so a guessed session ID cannot impersonate another user; rotate and expire session IDs. Note the 2026-07-28 revision (RC locked 2026-05-21, final 2026-07-28) removes `Mcp-Session-Id` entirely in favour of a stateless core.

**False-positive risk: high as written → low with the fixes.** Confirmed classes:
1. **UUIDv4 (122 bits)** fails a 128-bit clause. Most common compliant case. Fatal as written.
2. **UUIDv7** trips *both* "monotonically increasing" (timestamp-ordered by design) *and* the entropy clause (74 random bits per RFC 9562). 74 bits is not online-guessable. **Do not lump v7 with v1.** Emit at `info`/`low` ("prefer v4 per RFC 9562"), never a medium FAIL. Same for ULID/KSUID.
3. **Stateless servers** — N/A skip, above.
4. **JWT session IDs** are spec-blessed but are long, structured, contain client-derivable claims, and have a monotonically increasing `iat` — tripping the "derivable" and "sequential" clauses. **Exempt well-formed JWTs**; test only `jti`/signature entropy.
5. "Derivable from request inputs via a hash the scanner can reproduce" was unbounded and unimplementable — narrowed to the fixed set in test 5.

**Header casing:** `MCP-Session-Id` is correct for 2025-11-25 (transports §Session Management and its sequence diagram). HTTP header names are case-insensitive per RFC 9110; the `Mcp-Session-Id` spelling in older text is cosmetic.

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices (non-deterministic MUST; `<user_id>:<session_id>`)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports (§Session Management — globally-unique SHOULD; ASCII 0x21–0x7E)
- https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- RFC 9562 (UUID bit counts)

---

## MCP.SESSION.ID_COLLISION (split out)

**Severity:** high
**Kinds:** `mcp_server`, `route`
**Collector:** C1 (ACTIVE)

**Check:** across N fresh `initialize` calls, **FAIL** if any `MCP-Session-Id` value repeats. This is a session-collision/fixation bug with different impact from predictability and does not belong folded into a medium rule.

**Evidence claim**
> {n} initialize calls to {endpoint} returned a repeated MCP-Session-Id ({value} seen {count} times), indicating session collision.

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

---

## MCP.SESSION.USED_FOR_AUTHENTICATION

**Severity:** high — defensible, not inflated. Explicit MUST NOT + impersonation/auth-bypass impact, but exploitation is gated on obtaining a session ID that SHOULD be cryptographically random. Not remotely guessable absent a leak (logs, proxies, shared queues). **Not critical.**
**Kinds:** `mcp_server`, `route`
**Collector:** C2 + a legitimately obtained session (ACTIVE)

**Version gate:** skip for ≥ 2026-07-28 (sessions removed).

**Check**
1. `initialize` with a valid `Authorization: Bearer` token; capture `MCP-Session-Id`.
2. **Negative control (mandatory — this is what makes the rule sound).** Send `tools/list` with **neither** `MCP-Session-Id` **nor** `Authorization`. Record `control_status`.
3. Replay `tools/list` carrying **only** `MCP-Session-Id`, `Authorization` removed.
4. **FAIL** only if step 3 returns **any 2xx** AND step 2 returns **non-2xx** (spec: 400 for missing session ID, 401 for missing token).
   - If step 2 **also** returns 2xx, the endpoint is simply unauthenticated → emit MCP.AUTH.UNAUTHENTICATED_ENDPOINT, **not** this rule. Without this control the rule mis-diagnoses every no-auth server as "session-authenticated" — the dominant false positive, since authorization is OPTIONAL in MCP.
5. Phrase the condition as **FAIL-on-2xx**, not "200 instead of 401" — 403 is also a legitimate rejection, and a spec-compliant server may answer 400 per the session-ID rule.

**Removed from the probe:**
- *"and a read-only `tools/call`"* — **dropped.** The scanner cannot establish that a tool is read-only (`readOnlyHint` is an untrusted hint; clients MUST NOT make security-critical decisions on annotations from untrusted servers). It adds zero evidentiary value over `tools/list` while risking side effects on the target.
- *Step 3 from a different source IP* — **demoted to OPTIONAL corroboration.** It requires dual-egress infrastructure most scanners lack, and the original evidence claim hardcoded an assertion the scanner usually cannot substantiate. Step 3 alone proves the defect; IP provenance is irrelevant to it.

**Optional corroboration:** if the server supports resumable streams (`Last-Event-ID` on GET — "Resumption is always via HTTP GET with `Last-Event-ID`"), check whether it replays events for a session ID presented without a bearer token. That enables the session-hijack prompt-injection variant where an attacker enqueues a malicious event under a victim's session ID.

**Evidence claim**
> tools/list at {endpoint} returned HTTP {status} with MCP-Session-Id={sid} and no Authorization header, while the same request without a session ID returned {control_status} — the session ID alone is being accepted as the credential.

**Remediation**
Never treat the session as a credential. Spec: "MCP servers that implement authorization **MUST** verify all inbound requests. MCP Servers **MUST NOT** use sessions for authentication" (security_best_practices) and, most directly: "Note that authorization **MUST** be included in every HTTP request from client to server, even if they are part of the same logical session" (authorization). Validate the bearer token on every HTTP request including resumption GETs. The spec **recommends** (SHOULD, not MUST) binding session state to the authenticated user id derived from the token — "MCP servers **SHOULD** bind session IDs to user-specific information", key format `<user_id>:<session_id>` — "This ensures that even if an attacker guesses a session ID, they cannot impersonate another user as the user ID is derived from the user token and not provided by the client."

**False-positive risk: high without the negative control → low with it.** Residual caveats (uncommon, and largely caught by the control): (a) transport-layer auth — mTLS/client-cert or cookie-based session auth makes a tokenless request legitimately succeed; (b) gateway-terminated auth where the scanner probes the origin directly, bypassing the enforcing proxy.

**Sources**
- https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports

---

## MCP.TOOL.DESCRIPTION_HIDDEN_INSTRUCTIONS

**Severity:** high — for **class (a) + narrowed class (b) only**. Real, widely corroborated, pre-invocation, and it bypasses the human-in-the-loop control the spec relies on. Not critical: it requires the user to have already added a malicious/compromised server, and a pattern match is evidence of a poisoning *attempt*, not of successful compromise. **Classes (c)/(d)/(e) must not inherit high** — at their FP rate that makes the rule net-noise.
**Kinds:** `mcp_tool`, `mcp_server`
**Collector:** C2

**Scan scope.** `tools[].description`, `tools[].title`, `tools[].annotations.title`, **plus** `inputSchema`/`outputSchema` property names and descriptions, and (2025-11-25 additions) `icons` and `_meta`. Case-insensitive, whitespace-normalised. Record `{spec_version}` — the field set differs between 2025-06-18 and 2025-11-25.

**Scope is documented-insufficient if you scan `description` alone.** CyberArk "Poison everywhere" (2025-05-30) demonstrates **Full-Schema Poisoning**: parameter **names** are a live vector (PoC renamed a param to `content_from_reading_ssh_id_rsa` and exfiltrated with a **clean** description), as are `inputSchema` property descriptions and the `required`/`type` fields. "Focusing only on the description field… leaves a wide surface exposed." Tool **results**/errors are out of scope for a `tools/list`-time rule — that is a separate runtime rule.

### FAIL classes — CONFIRMED, severity high

**(a) Pseudo-tag delimiters framing an instruction block.** `<IMPORTANT>`, `<SYSTEM>`, `<secret>`, `<instructions>`, `<admin>`, HTML comments `<!--...-->`. High precision.

**(b-narrow) Concealment / override imperatives only:**
`ignore (all )?previous instructions` · `do not (tell|mention|inform|reveal) the user` · `without (telling|informing) the user` · `the user (will not|cannot) see`

### Signal classes — non-failing, feed the AI layer

These detect **vocabulary, not malice**. Never emit as CONFIRMED.

- **(b-wide)** `before (using|calling) this tool( you must| always)` · `you must first` · `as an AI` · `this is (very )?important`. **Standard developer documentation.** Canonical published example: "Create a new Salesforce contact. Required workflow: Call `discover_required_fields('Contact')` first to identify mandatory fields and prevent creation errors." First-party confirmation — the Supabase MCP server's own instructions say "Before making schema changes, use `list_tables`" and "start with `get_logs` and `get_advisors` before making changes."
- **(c) Secret-bearing filesystem paths** — `~/.ssh/id_rsa`, `id_rsa`, `.env`, `~/.aws/credentials`, `/etc/passwd`, `~/.config/gcloud`, `.git-credentials`, `~/.npmrc`. **Anchor to path boundaries** — bare `.env` matches `docs/.env.example`, `.environment`, prose. These paths are legitimately named by secrets-management, dotenv, SSH, and cloud-credential MCP servers whose actual job is those paths. Promote only when paired with a concealment or exfil verb.
- **(d) Exfiltration verb + sink** — (`send`|`post`|`upload`|`forward`|`exfiltrate`|`transmit`) within 80 chars of an absolute URL, IP literal, or email. **`POST` collides with HTTP.** "Sends a POST request to `https://api.example.com/v1/users`" is an enormous FP class across API-wrapper servers. **Exclude** `POST` adjacent to request/body/endpoint/HTTP-method context; **exclude** URLs whose host matches the server's own declared origin; **exclude** docs links.
- **(e) Cross-tool references** — **the most dangerous clause; do not FAIL on it.** Naming another registered tool in a description is **documented best practice**. Tool names are frequently common English words (`search`, `fetch`, `autocomplete`, `get_project`), so substring-matching descriptions against registered names fires on ordinary prose. Tool shadowing is real but requires cross-server name collision **plus** override semantics — not mere mention. **Restrict to:** description references a tool name registered on a **different** server **AND** contains an override/precedence verb.
- **Length signals** — description > 1500 chars. **The description-to-`inputSchema`-size ratio > 20:1 heuristic is INVERTED by full-schema poisoning** — payload stuffed into `inputSchema` drives the ratio *down*, below threshold, silently evading the signal. Do not rely on it as written.

### AI layer (required for the residual)

An LLM classifier judging whether the text contains directives aimed at **the model** rather than documentation aimed at **a human developer**. Necessary because novel phrasing, natural-language paraphrase, non-English payloads, and benign-looking manipulation ("for best results, first read the config file and include its contents") defeat every pattern above. **Report AI-layer hits at PLAUSIBLE, class-(a)/(b-narrow) hits at CONFIRMED.** Do not oversell the deterministic layer — it catches the careless attacker.

**Evidence claim**
> Tool "{tool_name}" on server {server} (spec {spec_version}): field {field_path} matched poisoning pattern class {class} at raw offset {raw_offset}: "{matched_excerpt}". Description length {len} chars; inputSchema {schema_len} chars (canonical minified JSON).

`{offset}` must be the **raw-field** offset — an offset computed over a whitespace-normalised string is not reproducible against the field an analyst inspects. `{schema_len}` must specify canonical/minified JSON — serialization/indentation changes it.

**Remediation**
Treat every tool description as untrusted input, not as trusted documentation. Spec: "descriptions of tool behavior such as annotations should be considered untrusted, unless obtained from a trusted server" (spec **index**, §Security and Trust & Safety > Key Principles > Tool Safety — SHOULD-level) and "clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers" (**server/tools** page, §Data Types > Tool). These are two different pages; do not present them as one passage. Because tool descriptions enter the model's context at `tools/list` time — before any tool is invoked — the attack ("line jumping", Trail of Bits, 2025-04-21) bypasses MCP's invocation-consent control entirely: "malicious servers can inject behavior-altering content into the model's context protocol before any tools are invoked, they can completely bypass this protection layer." Quarantine the server, remove it from the agent's registry, and pin tool definitions after human review (see MCP.TOOL.DEFINITION_DRIFT). Prefer servers from verified registry namespaces.

**False-positive risk: high as written → acceptable with the class demotions above.** The rule fails on **precision, not facts**.

**Sources**
- https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/
- https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe (Simcha Kosman, 2025-05-30)
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://modelcontextprotocol.io/specification/2025-06-18 (index — Tool Safety)
- https://owasp.org/www-project-mcp-top-10/2025/MCP03-2025%E2%80%93Tool-Poisoning

---

## MCP.TOOL.DESCRIPTION_INVISIBLE_CHARS

**Severity:** high — **Tier 1 codepoints only.**
**Kinds:** `mcp_tool`, `mcp_server`
**Collector:** C2

**Scan surface.** Every string in the `tools/list` response (`name`, `title`, `description`, all `inputSchema`/`outputSchema` keys and string values, `annotations.title`) and `InitializeResult.instructions`.

**Version-gate `serverInfo.description`.** It does **not** exist in 2025-06-18 (`Implementation extends BaseMetadata { version: string }` — name/title/version only). It was **added in 2025-11-25** (`Implementation extends BaseMetadata, Icons { version: string; description?: string; websiteUrl?: string }`). Do not FAIL or error when scanning a 2025-06-18 server that lacks it.

**Add these 2025-11-25 surfaces** (they reach the model or the approval UI and are equally smugglable): `Implementation.websiteUrl`, `icons[].src` / `icons[].mimeType` / `icons[].sizes` (`src` can be a `data:` URI), `Tool._meta` string values, `Tool.execution`, `inputSchema.$schema`.

### Tier 1 — FAIL, severity high, near-zero FP

- **Unicode Tags block U+E0000–U+E007F** — the ASCII-smuggling range. No legitimate modern use; deprecated since Unicode 5.1. Invisible in every renderer, tokenised by the model.
- **Bidi overrides U+202A–U+202E and isolates U+2066–U+2069** — legitimate only in genuinely mixed-direction runs, which tool metadata is not.
- **Raw U+001B / ANSI escapes** — regex `\x1B\[[0-9;]*[A-Za-z]`. JSON metadata has no terminal to format.
- **U+200B ZWSP, U+2060 WORD JOINER, U+FEFF** appearing **mid-string**.

### Tier 2 — split to MCP.TOOL.DESCRIPTION_UNUSUAL_UNICODE, severity low

**The claim "a legitimate tool description has no reason to carry any of these" is demonstrably false for these classes**, and as originally written the rule fires **high** on well-behaved servers:

- **U+FE0F VS-16** is **required** for emoji presentation of any `Emoji_Presentation=No` character: ⚠️ is `U+26A0 U+FE0F`; same for ℹ️ ✔️ ❗. Emoji in descriptions are common — this alone fires on a large share of real servers.
- **U+200D ZWJ** is in every emoji ZWJ sequence (👨‍💻 = `U+1F468 U+200D U+1F4BB`; families, flags).
- **U+200C ZWNJ** is **required Persian/Farsi orthography** (compound words, non-joining suffixes) and controls Devanagari conjunct/visible-virama formation. Any non-English description may carry it legitimately.
- **PUA U+E000–U+F8FF** holds Nerd Font icon glyphs and Apple's logo (U+F8FF) — plausible in CLI-adjacent metadata.
- **U+FE00–U+FE0F, U+E0100–U+E01EF** — U+E0100+ are Ideographic Variation Selectors used legitimately in Japanese (Adobe-Japan1 IVD). Flag as a carrier **only** on anomalous run length (>2 consecutive selectors, or selectors not immediately following a base character with a registered variation sequence) — never on mere presence.

### Homoglyph clause — scope it, and drop the "100% decidable" claim

Mixed-script detection (UTS#39 confusables / resolved script set) **is** mechanical, but "otherwise collides with a known tool" requires a **reference corpus** of known tool names and a skeleton-collision baseline — stateful, not a codepoint-class scan, and deployment-specific. Either scope to "tool name is single-script non-Latin, or mixed-script per UTS#39" (mechanical), or move the collision check to a separate rule that declares its corpus. Note the spec places **no charset restriction** on tool names (`BaseMetadata.name` is an unconstrained string, "intended for programmatic or logical use"), so non-ASCII names are spec-legal and client-side `^[a-zA-Z0-9_-]+$` conventions cannot be assumed.

**Implementation caveat (checkability).** Scan the **raw JSON-RPC bytes**, or the post-unescape string **before any sanitizer runs**. Payloads normally arrive as `​` / `\ud83c`-style JSON escapes, and an SDK/client that strips or normalizes control characters will erase the finding before the scanner sees it. **Do not apply NFKC before the scan** — NFKC deletes several target codepoints (e.g. U+FEFF, U+200B in some contexts) and would mask the very thing being detected. NFKC belongs in remediation only.

**Evidence claim**
> Tool "{tool_name}" field {field_path} contains {count} codepoints in Tier-1 class {class} (e.g. U+{codepoint} at offset {offset}).

The `visible_len`/`raw_len` delta from the original claim is **removed**: `raw_len != visible_len` legitimately for any emoji, combining mark, or astral-plane character, and "rendered length" requires grapheme-cluster segmentation (UAX#29), not codepoint counting. Keep the codepoint+offset evidence — precise and defensible.

**Remediation**
Reject or strip invisible/control characters from all server-supplied metadata before it reaches the model or a human approval UI. Render ANSI escapes visibly rather than interpreting them — Trail of Bits' context-protector provides `--visualize-ansi-codes`: "Make ANSI escape codes visible by replacing escape characters with 'ESC'" — precisely because hidden control characters let a malicious server show one thing to the reviewer and another to the model. Normalise to NFKC and enforce an allowlist of scripts for tool names. A server emitting any Tier-1 character in metadata should be treated as hostile.

**False-positive risk: high as written → low with the Tier 1/2 split.**

**Sources** (the ToB repo supports **only** the ANSI portion — it does not mention the Tags block, zero-width characters, homoglyphs, bidi overrides, or PUA; the rest need their own citations):
- https://github.com/trailofbits/context-protector (canonical; repo renamed from `mcp-context-protector`)
- https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/
- https://blog.trailofbits.com/2025/04/23/how-mcp-servers-can-steal-your-conversation-history/
- https://labs.cloudsecurityalliance.org/research/csa-research-note-unicode-instruction-injection-ai-skills-20/
- https://aws.amazon.com/blogs/security/defending-llm-applications-against-unicode-character-smuggling/
- https://www.promptfoo.dev/docs/red-team/plugins/ascii-smuggling/

---

## MCP.TOOL.SCHEMA_POISONING

**Severity:** high
**Kinds:** `mcp_tool`, `mcp_server`
**Collector:** C2

**Check**
Recursively walk `tools[].inputSchema` and `tools[].outputSchema`. **Resolve `$ref`/`allOf`/`anyOf`/`oneOf` and account for `patternProperties`/`additionalProperties` FIRST.** Then apply the MCP.TOOL.DESCRIPTION_HIDDEN_INSTRUCTIONS pattern classes to (a) every property KEY, (b) every nested `description`, (c) every `default`, `const`, `enum`, `examples`, `title`, `pattern` value, (d) every string in `required`.

**Sub-check 1 — suspicious property key (AI-gated).**
Key **token** matches `(ssh|id_rsa|passwd|token|secret|credential|env|aws|key)` **AND** the tool's stated purpose is unrelated. Reference: the CyberArk PoC used a parameter literally named `content_from_reading_ssh_id_rsa`.

**Token matching is mandatory — substring matching is broken.** Split on `_`/`-`/camelCase and match **whole tokens**. Substring `(…|token|env|key|aws|secret)` matches `max_tokens` (ubiquitous), `keyword`/`keywords`, `monkey`, `sort_key`, `primary_key`, `environment`, `inventory`, `secret_name`, `aws_region` (verified legitimate on AWS MCP servers). Allowlist `max_tokens`, `api_key`, `aws_region`, `secret_name`, `env` for tools whose purpose covers them.

**This sub-check is NOT deterministic.** The original rule claimed "the structural checks above are deterministic" while gating this one on "the tool's stated purpose is unrelated" — a semantic judgement requiring the AI layer. Only the null-schema and orphan-required checks are deterministic.

**Sub-check 2 — prose-shaped orphan in `required`.**
FAIL if a `required` entry names a string that is not a declared property key **AND** is prose-shaped (contains whitespace or sentence punctuation, or length > 64).

**Bare orphans are LEGAL — do not FAIL on them.** JSON Schema 2020-12 validation §6.5.3 says only "every item in the array is the name of a property in the instance" — it constrains **the instance**, not the schema's own `properties`. Legit orphans arise routinely from `$ref`/`allOf`/`$defs` composition (Pydantic model inheritance emits exactly this; the spec has a whole `$ref` resolution requirement) and from `patternProperties`/`additionalProperties`.

**Sub-check 3 — non-standard keyword carrying an injection payload.**
FAIL if a key outside the JSON Schema 2020-12 vocabulary has a string value > 40 chars **that itself matches a DESCRIPTION_HIDDEN_INSTRUCTIONS pattern**.

**Presence alone is overbroad — do not FAIL on it.** Common benign hits: `markdownDescription` (VS Code / JSON-Schema-Store convention, always prose >40 chars), `example` (OpenAPI 3.0 singular, not 2020-12's `examples`), `errorMessage` (ajv-errors), `deprecationMessage`, `x-*` vendor extensions. Critically, the spec **blesses** a non-standard keyword inside property schemas: **`x-mcp-header`**. Allowlist `x-mcp-header` and `$schema`. If reporting presence alone, drop to `info`.

**Evidence claim**
> Tool "{tool_name}" inputSchema contains poisoned element at JSON path {json_path}: {kind} = "{value}". Prose-shaped orphans in required (after $ref/allOf resolution): [{orphans}]. Non-standard keywords carrying injection-matching prose: [{extra_keys}].

**Remediation**
Scan the entire tool schema, not just the description field — "the entire tool schema is part of the LLM's context window and thus part of its reasoning" and "every part of the tool schema is a potential injection point, not just the description" (CyberArk, Full-Schema Poisoning, Simcha Kosman, 2025-05-30; note the article predates the 2025-11-25 spec). Validate `inputSchema` against **the declared (`$schema`) or default (2020-12) dialect** — SEP-1613 establishes 2020-12 as the default only when `$schema` is absent, and schemas MAY declare alternatives; the spec ships an explicit "Tool with explicit draft-07 schema" example as valid, and the MCP TypeScript SDK historically emitted draft-07 via zod-to-json-schema. **Do not "reject unknown keywords"** — that would reject the spec-blessed `x-mcp-header`, and meta-schema validation alone does not reject unknown keywords anyway (the 2020-12 meta-schema permits them; rejection requires ajv strict mode or explicit vocabulary enforcement). Enforce that every `required` entry names a property declared in the resolved schema; strip or reject prose in `default`/`const`/`examples`. Pin the full schema after review and block on drift.

**False-positive risk: medium.**

**Sources**
- https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- JSON Schema 2020-12 validation §6.5.3

---

## MCP.TOOL.INPUTSCHEMA_INVALID (split out)

**Severity:** low/info — a conformance bug, not an attack. It must not inherit `high` from schema poisoning.
**Kinds:** `mcp_tool`
**Collector:** C2

**Check:** FAIL if `inputSchema` is `null` or not a valid JSON Schema object. Spec: `inputSchema` "**MUST** be a valid JSON Schema object (not `null`)". **Exemption:** SEP-1613 (Final) lists `true` and `{}` as valid for no-param tools while the draft requires an object — if targeting 2025-06-18/SEP-1613 servers, **exempt `true`**.

**Evidence claim**
> Tool "{tool_name}" declares inputSchema={value}, which is not a valid JSON Schema object.

**Source:** https://modelcontextprotocol.io/specification/2025-11-25/server/tools

---

## MCP.TOOL.DEFINITION_DRIFT

**Severity:** high. **Escalate to critical only** if the diff introduces an MCP.TOOL.DESCRIPTION_HIDDEN_INSTRUCTIONS pattern that was absent at approval.
**Kinds:** `mcp_tool`, `mcp_server`
**Collector:** C2, **stateful/differential** — not a point-in-time config check. It cannot fire on first scan (no baseline).

**Check — trust-on-first-use pinning**
At approval time, compute and store a canonical hash over: `InitializeResult.instructions`, `serverInfo.name`/`version`, and for each tool `name`, **`title`**, `description`, `inputSchema`, `outputSchema`, `annotations`.

**`title` is the material gap in the original tuple** — it is the name surfaced in client UI, so a rug pull can mutate the displayed tool identity without moving the hash. (`icons` / `execution.taskSupport` are lower value; add if cheap.)

**Canonicalisation MUST be semantic:** sort the tools array by `name`, sort object keys, sort `required`, ignore property ordering — so benign reordering does not false-positive.

**Drain pagination before hashing.** `tools/list` is paginated via `cursor`/`nextCursor` in both 2025-06-18 and 2025-11-25. Hashing a partial list makes the hash flap on page-boundary shifts.

**Pin per `(server, credential-scope)` tuple, not per server.** If the scanner authenticates with different credentials/scopes than the approving user, the first comparison fires spuriously.

**Triggers, split by deployment mode:**
- **Scanner mode:** `scheduled_rescan` only.
- **Proxy mode only:** `notifications/tools/list_changed` requires a live persistent session — that is an inline proxy (what ToB's context-protector is), not a periodic read-only scanner.

**FAIL** if the recomputed hash differs from the pinned value. Report the field-level diff.

**The `serverInfo.version`-unchanged escalation is REMOVED — it is factually wrong.** "An honest update bumps the version" does not hold and would emit **critical**-severity FPs on mainstream servers. GitHub MCP Server (changelog 2026-01-28) "automatically detects your token's OAuth scopes and hides tools you don't have permission to use" — same server, same version, different `tools/list`. Speakeasy's dynamic-tool-discovery guide documents `tool.enable()`/`disable()` on auth expiry, permission/subscription tier, and external-service availability, with the TypeScript SDK emitting `list_changed` automatically and no version change. **Version-static tool mutation is the norm for dynamic servers.**

**Evidence claim**
> Server {server}: tools/list hash changed from {pinned_hash} to {current_hash} since baseline pinned at {pin_time}. Tool "{tool_name}" diff: {diff}.

The original claim's "without re-approval" and "{delta_time} after initial approval" are **removed**: a read-only scanner cannot observe the host application's (Claude Desktop/Cursor) approval database, so it cannot assert either. It can only assert "changed since pinned baseline." Restore the re-approval assertion **only** if VectaSec itself owns the approval record.

**Remediation**
Pin server configuration on first use and block downstream tool calls until a human explicitly approves any change — "Any deviation from the approved/known-good server configuration will block downstream tool calls until the user explicitly approves the changed server configuration" (Trail of Bits context-protector, which pins exactly server instructions, tool descriptions, and tool input schemas). Rug pulls are why approval-at-install is insufficient: Invariant Labs' April 2025 WhatsApp PoC used a benign "fact of the day" tool that mutated its definition **on second load to shadow a separate `whatsapp-mcp` server**, embedding instructions in its description telling the agent to redirect `send_message` calls to an attacker-controlled number (+13241234123) and exfiltrate contact lists in the message body. Re-verify on every `notifications/tools/list_changed`.

**Attribution corrected:** the malicious server did **not** reroute its own output — it **shadowed a separate server**. The rug-pull mechanic ("only activates on the second launch", circumventing re-approval) is accurate.

**False-positive risk: high → medium with suppression.** Treat tool-set **removals** and auth/scope-gated additions as **informational, not fail** — the high-signal case is a **modified** `description`/`inputSchema` on a tool whose `name` is unchanged. Normalize dynamic description content (embedded dates, counts, tenant names) or the finding churns on every rescan.

**Sources**
- https://github.com/trailofbits/context-protector
- https://invariantlabs.ai/blog/whatsapp-mcp-exploited (2025-04-07)
- https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks (2025-04-01 — rug-pull concept)

---

## MCP.SERVER.INSTRUCTIONS_INJECTION

**Severity:** high — **for the core injection-pattern hit on `instructions`/`serverInfo.description` only.** That field is auto-loaded into the system prompt, pre-consent, with strictly broader reach than a tool description. **The four bolt-on sub-checks MUST NOT inherit high** — emit them as separate info/medium findings with their own IDs.
**Kinds:** `mcp_server`
**Collector:** C2

**Version note.** The 2026-07-28 RC removes the `initialize` handshake; `InitializeResult.instructions` needs a new source under a stateless core. Re-verify against the final spec on/after 2026-07-28.

**Check (core, high)**
Read `instructions` from `InitializeResult` (`InitializeResult.instructions?: string`) and `serverInfo.description` from `Implementation` (2025-11-25 only). Apply the full MCP.TOOL.DESCRIPTION_HIDDEN_INSTRUCTIONS class set **at their corrected severities** plus the MCP.TOOL.DESCRIPTION_INVISIBLE_CHARS Tier-1 codepoint scan. FAIL on a Tier-1 or class-(a)/(b-narrow) hit.

**Evidence anchor — use the strong quote.** The full doc comment on `instructions` is: "This can be used by clients to improve the LLM's understanding of available tools, resources, etc. It can be thought of like a \"hint\" to the model. **For example, this information MAY be added to the system prompt.**" The spec itself states the field lands in the system prompt — that is the rule's whole premise. Pair with lifecycle: "The initialization phase **MUST** be the first interaction between client and server", which substantiates "before any tool is invoked."

**Sub-checks — all demoted**

| Sub-check | Verdict |
|---|---|
| `instructions` references tools not in this server's `tools/list` | **info / manual review, fuzzy-matched.** Not FAIL. |
| `instructions` exceeds 4000 chars | **info.** No spec basis — zero `maxLength` anywhere in schema.json. |
| `serverInfo.websiteUrl` / `icons[].src` host ≠ endpoint host | **info / manual review, compare eTLD+1.** Not FAIL. **Skip entirely for stdio.** |

- **Foreign-tool check fires on legitimate first-party servers.** Live counterexamples: the official **Supabase** MCP server's instructions say "Use `get_project_url` and `get_publishable_api_key`" while its actual exposed tool is `get_publishable_keys` — a stale docstring, not an attack. The **claude-in-chrome** server's instructions reference `ToolSearch`, a client-side tool it does not expose. Legit instructions routinely reference host CLIs ("Use the Supabase CLI"), agent skills, client features, tools gated behind `notifications/tools/list_changed`, and simply misspelled names. Fuzzy-match against `tools/list` to suppress near-miss typos.
- **Length is not evidence of injection.** Verbose legitimate instructions are common. Use as a metric that raises reviewer attention.
- **Host check:** exact host match fails the normal hosted-server pattern — an endpoint at `mcp.<vendor>.tld` with `websiteUrl` at the apex `<vendor>.tld` is standard, and icons are routinely served from CDNs (githubusercontent, `cdn.*`). Compare **eTLD+1**. This sub-check is **undefined for stdio-transport servers** (no endpoint host) and must be **explicitly skipped, not failed**, or it errors/false-fires on a large share of real servers.

**Evidence claim**
> Server {server} InitializeResult.instructions ({len} chars) matched injection pattern class {class}: "{excerpt}".

Emit the foreign-tool / websiteUrl observations as **separate** findings with their own IDs, not as clauses of this one.

**Remediation**
Treat `instructions` as untrusted server-controlled input injected into the model's context at connection time, before any consent gate — the same line-jumping surface as tool descriptions. Trail of Bits' **context-protector** names server instructions alongside tool descriptions as a pinned surface: "Server configuration comparisons compare server instructions, tool descriptions, and tool input schemas." Strip, sandbox, or require human review of the field; pin it as part of the server-config hash (MCP.TOOL.DEFINITION_DRIFT).

**Two attribution errors corrected — do not reintroduce:**
1. The ToB **blog** ("Jumping the line") discusses **tool descriptions only** and does **not** name server instructions. The claim is true but the citation must be the **context-protector repo**, not the blog.
2. **There is no spec "connection-isolation promise."** security_best_practices (fetched) covers confused deputy, token passthrough, SSRF, session hijacking, local server compromise, OAuth URL validation, stdio proxy, and scope minimization — it contains no connection-isolation guarantee, no guidance on treating `instructions` as untrusted, and nothing on icon/websiteUrl consent spoofing. "Connection isolation" is Trail of Bits' framing of an *implied* guarantee. Attribute to ToB or delete the clause. **Never cite it as spec.**

**Checkability:** confirmed. `initialize` is the mandatory first handshake, so a read-only scanner acting as an MCP client receives `InitializeResult` with no write/shell/filesystem access; `tools/list` is likewise read-only. Only gap is the stdio endpoint-host case above.

**False-positive risk: high as written → low with the sub-check demotions.**

**Sources**
- https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.ts (all field names verified; latest dated dir — siblings are 2024-11-05, 2025-03-26, 2025-06-18, draft)
- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://github.com/trailofbits/context-protector

---

## MCP.SERVER.STDIO_ARBITRARY_COMMAND

**Severity:** critical **only** for the unauthenticated-remote-reachable case (LiteLLM/Upsonic are both CVSS 9.8 AV:N/PR:N/UI:N). The CVE set spans **8.6–9.8** — Agent Zero is HIGH, not critical. For an **authenticated admin-only** config surface — which is LiteLLM's intended, documented design — stdio config is **intended function, not a vulnerability**: downgrade to low/info.
**Kinds:** `mcp_server`, `service`
**Collector:** C3

**Mandatory precondition on EVERY FAIL clause: `command`/`args` must be populated from an unauthenticated or user-supplied request.** Without this gate two clauses fire on normal deployments:
- The allowlist clause matches the canonical documented config `command: "npx", args: ["-y", "@modelcontextprotocol/server-github"]` — i.e. **essentially every legitimate MCP install, including Anthropic's own docs**.
- "A stdio spawn path exists in the backend despite no UI exposing it" fires on **any** application that imports the MCP SDK, since a stdio spawn path is the SDK's normal function.

**A user-authored local desktop config is not a finding** — the user already has code execution on their own machine; no trust boundary is crossed.

**Check (the read-only-observable subset — this rule)**
Inspect the host application's MCP server configuration surface: client config JSON (`mcpServers[].command`/`args` — Claude Desktop/Windsurf format, which infers stdio from the presence of `command`), or an admin API's MCP-adapter fields (LiteLLM: `mcp_servers` with `transport: "stdio"`, `command`, `args`, `env`).

**Enumerate real per-product keys.** `transportType` is **not a universal key** and appears invented — LiteLLM uses `transport`; standard client config has no transport discriminator at all.

FAIL if, **and only if**, the config surface is populated from an unauthenticated or user-supplied request **and**:
- `command`/`args` reach subprocess spawn from that input; **or**
- an allowlist exists but is bypassable: the allowlisted binary is `npx`/`npm`/`node`/`python`/`uv`/`uvx`/`bash`/`sh`/`deno` **AND** `args` is not itself constrained — flag arg patterns `-c`, `-e`, `--eval` (e.g. `npx -c '<payload>'`, `python -c`, `node -e`). Verbatim from OX (Flowise): blocked `{"command":"touch","args":["/tmp/pwn"]}` → bypassed `{"command":"npx","args":["-c","touch /tmp/pwn"]}`.

**`uvx --from` is NOT an eval flag — removed.** Per docs.astral.sh/uv, `--from` is the documented **package selector** for when command name != package name (`uvx --from httpie http`). uvx has no documented inline-code-eval flag. Flagging `--from` beside `python -c` is a category error and a direct FP generator on correct configs. It does accept git URLs — if retained at all it belongs in a **separate untrusted-package-source/supply-chain signal**, not payload smuggling.

**Split out of this rule (not read-only-observable):**
- *"reach subprocess spawn without validation"* as a general claim → dataflow/source analysis, not an API read. This rule can only observe that the values are attacker-supplied and that the pattern is present.
- *"config file is writable by an agent/LLM without explicit user consent"* (the Windsurf pattern) → needs filesystem permission inspection. **Move to a separate host/filesystem rule.**
- *"hidden-config family — test by replaying an intercepted request"* → **struck.** That is exploitation, not observation.

**Evidence claim**
> Application {app} exposes MCP stdio configuration at {surface} ({authenticated|UNAUTHENTICATED}); field {field} is populated from request input. Configured command={cmd}, args={args}. Allowlist={allowlist}, bypassable via `{binary} -c <payload>`.

The original claim's "spawned a subprocess (verified by {benign_marker})" is **removed** — it mutates target state and spawns processes. Assert only what is observable: stdio transport configured, the command/args values, and whether the config surface requires authentication.

**Remediation**
Never construct stdio subprocess invocations from untrusted input. Validate `command` against a strict allowlist of **absolute binary paths** AND constrain `args` (reject `-c`/`-e`/`--eval` and shell metacharacters) — allowlisting the binary alone is bypassable. Do not permit the LLM to write MCP config files without explicit user consent. Spawn servers without a shell and under a sandbox. Spec: servers **MUST** "Validate all tool inputs" (MCP 2025-06-18 Tools > Security Considerations). OX Security's 2026 advisory found this pattern systemic across the MCP SDK ecosystem (Python/TypeScript/Java/Rust), with CVE-2026-30615 (Windsurf 1.9544.26 — zero-click prompt-injection → `mcp.json` write), CVE-2026-30623 (LiteLLM 1.18.10, 9.8 CRITICAL, CISA-ADP), CVE-2026-30624 (Agent Zero 0.9.8, 8.6 HIGH, CWE-77), CVE-2026-30625 (Upsonic 0.71.6, 9.8 CRITICAL, explicitly an npm/npx allowlist bypass via argument flags). All four verified on NVD.

**The "43% of MCP CVEs" statistic is REMOVED — it was fabricated/misattributed.** The claimed OX source contains **no** percentage statistics. The real figure is **Equixly**: "Command injection: 43% of tested MCP servers vulnerable" (2025–Feb 2026 offensive-security assessment) — that is 43% of **tested servers**, not of CVEs filed. Wrong denominator **and** wrong source. Cite Equixly or drop it; never OX.

**Verified real (no hallucinated keys in the core):** `StdioServerParameters(command=, args=)` is the genuine Python MCP SDK API — OX shows both the intended form `StdioServerParameters(command="python", args=["myapp.py"])` and the vulnerable `StdioServerParameters(command=user_input_command, args=user_input_arguments)`. LiteLLM's current docs confirm `transport: "stdio"`, `command`, `args`, `env` under `mcp_servers`. Windsurf's agent-writable `mcp.json` is real.

**False-positive risk: high as written → low/medium with the untrusted-reachability gate, `--from` removal, exploit-test removal, and filesystem split.**

**Sources**
- https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
- https://modelcontextprotocol.io/specification/2025-06-18/server/tools (§Security Considerations)
- NVD: CVE-2026-30615, CVE-2026-30623, CVE-2026-30624, CVE-2026-30625
- https://docs.litellm.ai/docs/mcp · https://docs.astral.sh/uv/guides/tools

---

## MCP.GATEWAY.LETHAL_TRIFECTA

**Severity:** medium (default). **Escalate to high only** with an additional verified signal: egress is auto-approved/unattended **AND** bucket A resolves to authenticated/private data. The rule substantiates capability **coexistence** (a risk precondition), not a demonstrated exploit path; as specified it cannot distinguish an unattended trifecta (genuinely high) from a human-in-the-loop trifecta (an accepted, extremely common design). Firing high on a shape present in nearly every real agent gateway is alert fatigue.
**Kinds:** `mcp_server`, `mcp_tool`, `service`
**Collector:** C3 + C2. **Gateway-scope only — do not wire into a per-server code path.** The composition input (which servers are mounted into one agent context) is host/gateway config, not observable from any single MCP server.

This is the pack's only composition-level rule and its highest-value differentiator: no per-server scanner can see it. It requires a **curated tool-classification table**; budget for maintaining it.

**Check**
Build the union of tools from every mounted server's `tools/list`. Classify each into three buckets. **FAIL if all three are non-empty in the same context.**

- **(A) PRIVATE DATA** — reads **authenticated/private** user/org data. Tools whose schema takes a path/repo/query and returns content **from an authenticated source**.
- **(B) UNTRUSTED CONTENT** — ingests **attacker-influenceable** text: web fetch/search, email/issue/ticket readers.
- **(C) EXTERNAL COMMS** — can emit data outbound to an **attacker-readable** channel: HTTP request tools, send-message/email, create-PR/issue/comment, `resource_link` fetches.

### Three defects that must be fixed before this is implementable

**(1) "the OAuth scopes actually granted" is NOT an MCP surface — remove it.** MCP has **no per-tool scope declaration**. SEP-1880 ("Tool-level scope requirements", issue #1880, opened 2025-11-23) proposed exactly this (`authorization.scopes` on `Tool`) and was **CLOSED AS NOT PLANNED**. Its own motivation: "nothing in the current schema allows tools to declare their expected scopes ahead of time." You cannot map `files:read`/`repo`/`mail.read` to individual tools.

Replace with what **is** observable: `scopes_supported` from RFC 9728 PRM (unauthenticated GET; MCP servers MUST implement RFC 9728) plus the `scope` param on `WWW-Authenticate` 401/403 challenges. Both are **per-server** and mean "supported"/"required for this request" — **not "granted"**. Actually-granted scopes require holding the token (JWT claims) or RFC 7662 introspection: out of scope. Worse, the spec's Scope Selection Strategy tells clients to request **all** of `scopes_supported` when no challenge scope is present, so granted scopes are systematically over-broad and non-discriminating even if visible. (The scope strings themselves are not invented — `files:read` is the spec's own `WWW-Authenticate` example. Only the per-tool binding is.)

**(2) `openWorldHint` is MIS-BUCKETED — move it to bucket C or treat as bucket-agnostic.** Schema verbatim: "If true, this tool may interact with an 'open world' of external entities. If false, the tool's domain of interaction is closed," example "the world of a web search tool is open, whereas that of a memory tool is not." It flags **external interaction generally** — true for both web-search (ingress/B) **and** send-email (egress/C). It is **not a bucket-B discriminator**. Assigning `openWorldHint == true → B` manufactures **phantom B legs**: a context of `{read_repo, send_email}` is A+C only, but `send_email`'s `openWorldHint=true` fabricates a B leg and fires a false trifecta.

**(3) SPEC DEFAULTS INVERT THE CHECK — this is the single largest FP driver.** Verbatim defaults: `openWorldHint` **Default: true**. `readOnlyHint` **Default: false**. (`destructiveHint` default true; `idempotentHint` default false.) Most real servers ship **no annotations at all**. If the scanner applies spec defaults, **every un-annotated tool is simultaneously bucket-B and bucket-C** — so one un-annotated server plus any data-reading tool fires the rule. **Treat absent annotations as UNKNOWN. Never apply spec defaults as evidence.**

**Annotations are self-asserted regardless.** Per spec, "clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers." Classification **MUST NOT** rely on `readOnlyHint` alone.

**Split out:** a tool named `delete_*`/`send_*` carrying `readOnlyHint: true` is **its own rule** — correctly reasoned and directly supported by the untrusted-annotations warning, but not a trifecta finding.

**Evidence claim**
> Agent context {context} mounts {n} servers spanning all three trifecta buckets: private data via [{bucket_a_tools}], untrusted content via [{bucket_b_tools}], external comms via [{bucket_c_tools}]. {tool_a} -> {tool_b} -> {tool_c} forms a candidate exfiltration path; whether egress requires user approval is host-dependent and not established by this check.

"requires no further user consent" is **struck** — not verifiable from `tools/list` or any read-only surface. Whether the host prompts for approval on egress is a host-side property invisible to the scan, and the spec SHOULD-requires it: "there **SHOULD** always be a human in the loop with the ability to deny tool invocations."

**Remediation**
Break the trifecta — the combination, not any single tool, is the vulnerability, and there is no reliable prompt-level fix. Simon Willison's framing (2025-06-16): the three legs are "access to your private data", "exposure to untrusted content", and "the ability to externally communicate". MCP is uniquely exposed because "The problem with Model Context Protocol - MCP - is that it encourages users to mix and match tools from different sources" and "once you start mixing and matching tools yourself there's nothing those vendors can do to protect you!" The GitHub MCP exploit combined all three (read public issues, access private repos, open PRs) — "The recently discovered GitHub MCP exploit provides an example where one MCP mixed all three patterns in a single tool" (it was a single MCP **server**, not one tool; underlying research: Invariant Labs' "toxic agent flow", 2025-05-26). Split high-risk capabilities across separate agent contexts with separate credentials, remove the external-communication leg from any context that touches both private data and untrusted content, or require human approval on every egress action. Track this as a property of the gateway's mounted-server composition and re-evaluate whenever a server is added.

**False-positive risk: high as written.** Confirmed classes:
- (a) The **annotation-default trap** (3) — fires on nearly everything.
- (b) **`openWorldHint` conflation** (2) — phantom B legs on pure-egress contexts.
- (c) **Human-in-the-loop egress** — trifecta present, path not unattended, finding not actionable.
- (d) Bucket B "any tool returning content from a third-party origin" catches internal wikis authored solely by trusted employees — **third-party origin ≠ attacker-influenceable**.
- (e) Bucket C "`readOnlyHint == false` targeting a remote host" catches write-only-to-first-party-store tools (cache warm, search index) with **no attacker-readable channel**.
- (f) Bucket A "takes a path/repo/query and returns content" matches any lookup tool **including public-data search** — public docs search is not private data.
- (g) All-internal contexts with network egress filtering.

Fixes (1)(2)(3) + tightening A to authenticated/private sources + gating severity on egress approval make this genuinely valuable — it is the central MCP composition risk and the source backs it squarely.

**Sources**
- https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/ (all quotes verbatim)
- https://invariantlabs.ai/blog/mcp-github-vulnerability (2025-05-26)
- https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2025-11-25/schema.ts (annotation defaults)

---

## Implementation notes

### What the connector must collect

**C1 — unauthenticated network probe** (no credentials; network egress only)
- `POST {endpoint}` JSON-RPC `initialize`, `Accept: application/json, text/event-stream` → status, headers, body (parse **both** JSON and SSE framing)
- `WWW-Authenticate` header, fully parsed into auth-scheme + params (`resource_metadata`, `scope`, `error`)
- `GET /.well-known/oauth-protected-resource{/path}` and `GET /.well-known/oauth-protected-resource` → **record which URL served the document** (required for the RFC 9728 §3.3 base)
- AS metadata via the spec discovery order → **record which candidate resolved**
- TLS: highest negotiated version, **lowest accepted version via a separate downgrade probe**, full cert chain + validation result
- Resolved target IP + scanner source network zone (**recorded as a precondition field, never as a FAIL condition**)

**C2 — authenticated MCP client** (bearer token)
- Full `InitializeResult`: `instructions`, `serverInfo` (`name`, `version`, `description`†, `websiteUrl`†, `icons`†), `capabilities`, `protocolVersion`
- `MCP-Session-Id` from the response header; N=8–12 fresh values for the session rules
- `tools/list` **all pages** (drain `nextCursor`) — raw JSON-RPC bytes preserved **pre-sanitization** for the codepoint scan
- Per tool: `name`, `title`, `description`, `inputSchema`, `outputSchema`, `annotations` (+ `annotations.title`), `_meta`, `icons`†, `execution`†
- `HTTP DELETE` with the session ID after every probe

† 2025-11-25 only — version-gate; absence on a 2025-06-18 server is not a finding.

**C3 — host/gateway config read**
- Mounted-server registry per agent context (required for LETHAL_TRIFECTA; unavailable in per-server scans)
- Client config JSON: `mcpServers[].command` / `args` / `env`
- Gateway admin API MCP-adapter fields (per-product keys: LiteLLM `mcp_servers` + `transport`; **not** a generic `transportType`)
- k8s `Service.spec.type`; Docker `HostConfig.PortBindings[].HostIp` (**host-side publish only — never the in-container socket table**)

**Not collected (declared out of scope):** `tools/call`; DCR `POST /register`; `ss -ltnp` (needs host shell + root/CAP_NET_ADMIN — split to a host-agent rule); filesystem permission bits (split to a host/filesystem rule); dataflow analysis of `command`/`args` to spawn.

### Cross-cutting requirements

1. **Version gate everything on the negotiated `protocolVersion`.** Auto-skip session rules for ≥ 2026-07-28. Gate `serverInfo.description`/`websiteUrl`/`icons` to 2025-11-25+. Gate the HTTP+SSE version probe to the 2025-03-26…2025-11-25 era.
2. **Active-probe consent flag.** `initialize` allocates server-side state. Foreign-audience canaries, invalid-version headers, and attacker Origins are ACTIVE. Do not run any of these under a read-only posture scan.
3. **Session cleanup is mandatory** on every probe that calls `initialize`. Back off on 429.
4. **Status accept-lists, never single-status matching.** ORIGIN_UNVALIDATED passes on 401/403/421/400-origin-error. Session rules FAIL on any 2xx. TOKEN_AUDIENCE FAILs only on a **parsed successful body**, never on status.
5. **Negative controls are load-bearing.** SESSION.USED_FOR_AUTHENTICATION needs a no-session-no-token control. TOKEN_AUDIENCE needs a no-token baseline. Without them both rules mis-diagnose unauthenticated servers.
6. **Operator allowlists required before ship:** intentionally-public endpoints (AUTH.UNAUTHENTICATED_ENDPOINT); known PKCE-metadata omitters (Entra, Snowflake); additionally-accepted audiences (gateway/fleet designs).
7. **Confidence mapping.** Deterministic → CONFIRMED. AI-layer → PLAUSIBLE. Do not report vocabulary-matching classes (paths, exfil verbs, cross-tool references) as CONFIRMED.
8. **Never assert what the vantage point cannot see:** "internet-exposed", "without re-approval", "requires no user consent", "the AS does not support PKCE", "spawned a subprocess". Each was struck from an evidence claim above for this reason.

### Deterministic vs AI — the honest split

- **Fully mechanical, no model:** invisible/bidi/tag-block/ANSI codepoint scanning; schema structural violations (prose-shaped `required` orphans, invalid `inputSchema`); definition-drift hashing; every transport and OAuth check.
- **Pattern-matchable, good precision, bypassable by paraphrase:** DESCRIPTION_HIDDEN_INSTRUCTIONS classes (a) and (b-narrow).
- **Genuinely requires AI:** semantic intent of natural-language descriptions; non-English payloads; benign-looking manipulation; the relatedness gate in SCHEMA_POISONING; tool classification for LETHAL_TRIFECTA; all of ATPA/output injection (payloads are generated server-side at runtime and may be conditional on traffic patterns, so no static pattern set bounds them).

**Do not oversell the deterministic layer as catching tool poisoning — it catches the careless attacker.** The MCPTox benchmark and MCPXKIT toolkit (both arXiv, Aug 2025) exist for evaluating detector recall; they were found in search but **not fetched**, so they are not cited as rule sources.

### Roadmap — 2026-07-28 RC (publishes in 11 days)

The largest revision since launch. It breaks several assumptions this pack relies on.

- **Stateless core.** `initialize` and `Mcp-Session-Id` are **removed** (SEP-2567). MCP.SESSION.* become inapplicable. MCP.SERVER.INSTRUCTIONS_INJECTION needs a new source for `instructions`. Re-verify on/after 2026-07-28.
- **Six authorization-hardening SEPs land:** `iss` validation per RFC 9207, `application_type` at registration, credentials bound to issuer, scope-accumulation rules at step-up, `.well-known` discovery suffix rules. Expect **2–3 new rules**, notably an RFC 9207 `iss` check.
- **New surfaces:** `Mcp-Method`/`Mcp-Name` routing headers; `ttlMs`/`cacheScope` caching — a **new cache-poisoning surface** not covered here.
- **DCR formally Deprecated** (deprecated 2026-07-28, earliest removal 2027-07-28); migration path is **Client ID Metadata Documents**. A planned MCP.AUTH.PROXY_NO_PER_CLIENT_CONSENT shifts from "DCR is open" toward "CIMD trust policy is absent". CIMD brings its own surface the spec calls out explicitly — AS-side SSRF from fetching attacker-supplied `client_id` URLs, and localhost `redirect_uri` impersonation that CIMD "cannot prevent by itself" — worth **2 future rules**.
- **Also newly deprecated:** Roots, Sampling, Logging, `includeContext: "thisServer"/"allServers"`. Any sampling-related rules have a ~12-month shelf life.
- **HTTP+SSE is deprecated but NOT removed** (SEP-2596, earliest removal ~2026-09) — which is why MCP.TRANSPORT.DEPRECATED_HTTP_SSE is `low`.

### Coverage gaps worth filling

Mapped to **OWASP MCP Top 10** — currently **v0.1 beta, Phase 3 (pilot testing)**. Map to it for marketing; **do not treat IDs as stable**. IDs: MCP01 Token Mismanagement & Secret Exposure · MCP02 Privilege Escalation via Scope Creep · MCP03 Tool Poisoning · MCP04 Software Supply Chain · MCP05 Command Injection & Execution · MCP06 Intent Flow Subversion · MCP07 Insufficient Authentication & Authorization · MCP08 Lack of Audit and Telemetry · MCP09 Shadow MCP Servers · MCP10 Context Injection & Over-Sharing.

Not covered by this pack:
- **MCP08 (audit/telemetry)** — a real gap; checkable via whether the server logs tool invocations with correlation IDs.
- **MCP09 (shadow servers) + MCP04 (supply chain)** — checkable against the official registry at `registry.modelcontextprotocol.io`, which verifies `io.github.*` namespaces via GitHub OAuth and `com.example` via DNS TXT records. **"Server not published under a verified registry namespace" is a mechanically checkable provenance rule** worth adding.
- **`code_challenge_methods_supported` containing `"plain"`** alongside `S256` — an uncovered downgrade risk.
- **Reflected-origin + `Access-Control-Allow-Credentials: true`** — a genuine CORS finding, deliberately removed from ORIGIN_UNVALIDATED as conceptually distinct.
- **Self-asserted-annotation contradiction** (`delete_*`/`send_*` with `readOnlyHint: true`) — split out of LETHAL_TRIFECTA, not yet written.
- **MCP.TOOL.OUTPUT_INJECTION / ATPA** — undetectable at scan time by construction; needs runtime egress inspection, an architecturally different collector from the rest of this pack.

### Unverified claims — do not put in customer-facing material without checking

- **Verified and citable:** Knostic (2025-07-17) — 1,862 internet-exposed servers via Shodan, 119 manually verified, all 119 returned tool listings to unauthenticated `tools/list`. CVE-2025-49596 (Inspector <0.14.1, CVSS 9.4). OX Security's four stdio CVEs (all four confirmed on NVD).
- **NOT verified to primary sources — do not cite as fact:** Censys ~12,520 services (2026-04-28) → 21,000+ (2026-05-06), ~40% unauthenticated. An academic scan of 39,884 repos finding 106 zero-days. tapauth.ai's "518 MCP servers scanned, 41% no auth" (secondary, methodology unpublished — indicative only, LOW confidence).
- **CVEs seen only in search snippets, verify on NVD before citing:** CVE-2025-6514 (mcp-remote, claimed CVSS 9.6), CVE-2025-54136 (Cursor), CVE-2026-22252 (LibreChat), CVE-2026-22688 (WeKnora), CVE-2025-54994.
- **Could not retrieve:** the NSA CSI on MCP security (nsa.gov returned HTTP 403). It exists and is worth obtaining manually — government guidance is useful for enterprise buyers.
- **Undated source:** the merge.dev tool-description article carries no publication date — treat its "best practice" framing as corroborating, not authoritative. The Supabase first-party example independently establishes the same false positive.
