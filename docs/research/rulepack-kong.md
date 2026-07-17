# KONG Rulepack

Posture rules for Kong Gateway (OSS "community" and Enterprise), evaluated entirely through read-only Admin API `GET` requests. This document is the implementation spec: each rule states the exact field, the failing condition, the evidence string, and the suppression logic required to keep the false-positive rate survivable.

## What the scanner sees

The connector needs one credential: an Admin API base URL plus, on Enterprise with RBAC enabled, a `Kong-Admin-Token` for a read-only user. Everything below is derived from these endpoints:

| Endpoint | Yields |
|---|---|
| `GET /` (node information) | `.version`, `.edition` (`"enterprise"` \| `"community"`), `.hostname`, `.node_id`, `.tagline`, `.plugins`, `.configuration` — the running `kong.conf` **with secrets stripped** |
| `GET /status` | `.database.reachable`, `.memory`, `.server.*` — health only, no posture signal. Used for reachability confirmation, nothing else. |
| `GET /services`, `/routes`, `/plugins`, `/consumers` | Entity inventory. **All paginate.** |
| `GET /consumers/{id}/{key-auth,basic-auth,jwt,hmac-auth,oauth2,acls,mtls-auth}` | Per-consumer credentials |
| `GET /rbac/users` | Enterprise only; 404 on OSS |

**`.configuration` is sanitized, not raw.** `kong/api/routes/kong.lua` calls `kong.configuration.remove_sensitive()`. `CONF_SENSITIVE` (`kong/conf_loader/constants.lua`) = `{pg_password, pg_ro_password, proxy_server, declarative_config_string, cluster_cert_key, ssl_cert_key, client_ssl_cert_key, admin_ssl_cert_key, admin_gui_ssl_cert_key, status_ssl_cert_key, debug_ssl_cert_key, $refs}`. Every field these rules read — `admin_listen`, `proxy_listen`, `enforce_rbac`, `rbac_auth_header`, `database`, `role`, `trusted_ips`, `nginx_http_client_max_body_size` — is **not** redacted and is reliably present.

**What the scanner cannot see, and must never pretend to:** firewalls, security groups, Docker port publishing, Kubernetes NetworkPolicy, service-mesh mTLS, upstream CDN/WAF controls, or the sensitivity of the upstream a route fronts. Several rules below observe a *bind address* or an *absent plugin* and are frequently correct about the config while being wrong about the exposure. Where that is true, the rule text says so and the severity is capped accordingly.

**Baselines that must not be flagged:** `proxy_listen` defaults to `0.0.0.0:8000, 0.0.0.0:8443 ssl` — this is expected. `admin_listen` defaults to `127.0.0.1:8001 reuseport backlog=16384, 127.0.0.1:8444 http2 ssl reuseport backlog=16384`.

**CVE coverage is thin by design.** Only four NVD records mention Kong Gateway; Kong ships most fixes through its changelog and support portal without CVE assignment. Version rules are a floor, not a picture. Pin CVE enrichment to the NVD API or Kong's support portal — **never to web search**. (Search results for "Kong CVE 2026" confidently describe CVE-2026-29413 and CVE-2026-29414; both are fabrications. MITRE's CVE Services API returns 404 for them, NVD has neither, and Kong's PSA page carries no such advisory. The sole source is one SEO blog whose technical narrative is internally incoherent.)

---

## KONG.ADMIN.LISTEN_WILDCARD

**Severity:** high (conditional escalation to critical) · **Kinds:** broker, service · **FP risk:** high · **Confidence:** high

### Check

`GET /` → `.configuration.admin_listen` — an array of nginx-style listener strings.

Parse each entry:

1. **Not applicable** if `admin_listen` is absent, empty, or the literal `off`. `admin_listen = off` disables the Admin interface entirely for that node; it is *not* a per-entry token. This also covers hybrid-mode data planes, which cannot be scanned via `GET /` anyway.
2. Strip nginx listen suffixes before host parsing: `ssl`, `http2`, `proxy_protocol`, `deferred`, `bind`, `reuseport`, `backlog=N`, `ipv6only=on|off`, `so_keepalive=...`. Tokenize on whitespace — never substring-match.
3. Strip IPv6 brackets before comparison.

Then tier the verdict:

- **FAIL (high)** — host is a true wildcard: `0.0.0.0`, `::`, `[::]`, `*`, `0.0.0.0/0`.
- **WARN (info)** — host is a specific non-loopback unicast address (`10.0.0.5:8001`, a mgmt-VLAN or pod IP). Emit as "verify an L3/L4 ACL, RBAC, or mTLS is in front." Do **not** hard-FAIL.
- **PASS** — host is loopback: anything in `127.0.0.0/8`, `::1`, `[::1]`, or the hostname literal `localhost`. For other hostnames (`admin_listen` accepts hostnames), either resolve them or return inconclusive — never FAIL.

**Escalate to critical only** if a companion unauthenticated-reachability probe (KONG.ADMIN.UNAUTHENTICATED) independently confirms the Admin API answered `GET /` from an untrusted, non-loopback network path *without credentials*.

The `[::]` form matters: Kong and the Kong Helm chart emit bracketed `[::]`, not bare `::`. A bare-`::` comparison misses it.

### Why the tiering, not a flat FAIL on non-loopback

Kong's own guidance blesses non-loopback binding plus network restriction: *"In cases where the Admin API must be exposed beyond a local interface, the best practice is to restrict network-layer access as much as possible."* The Secure-the-Admin-API page lists five acceptable mitigations — network layer, L3/L4 firewall, API loopback via a Kong Service with auth plugins, custom Nginx authz, RBAC — of which only the first is loopback binding. A flat non-loopback FAIL fires on every documented firewalled deployment and contradicts this rule's own remediation.

### Evidence claim

> Admin API node info `GET /` reports `.configuration.admin_listen = ['0.0.0.0:8001 reuseport backlog=16384']`, binding the Admin API to all interfaces instead of the documented default `127.0.0.1:8001, 127.0.0.1:8444 http2 ssl`. The bind address alone does not establish network reachability — confirm the compensating control (firewall / security group / published container ports / NetworkPolicy) before treating this as exposure. Scanner reached this node over: `<loopback | remote path>`.

Recording whether the scanner's own request arrived over loopback or a remote path materially changes severity; capture it.

### Remediation

Set `admin_listen` to a loopback or tightly-scoped address (default: `127.0.0.1:8001, 127.0.0.1:8444 http2 ssl`). Kong docs explicitly say to avoid values such as `0.0.0.0:8001` because it "could seriously compromise the security of your whole Kong cluster." Otherwise place the Admin API behind a firewall / L3-L4 ACL, or proxy it through a Kong Service protected by auth plugins.

### False positives and how to avoid them

The two largest FP drivers are **Kong's own defaults**:

- **Docker.** Kong's official Docker docs instruct `KONG_ADMIN_LISTEN=0.0.0.0:8001, 0.0.0.0:8444 ssl`. Inside a container, `0.0.0.0` means the container netns only; exposure is decided by port publishing (`-p 127.0.0.1:8001:8001`) or non-publication.
- **Helm.** `Kong/charts` `templates/_helpers.tpl` defines `{{- $defaultAddrs := (list "0.0.0.0" "[::]") -}}` in `kong.listen`, and only forces loopback when admin is *disabled*: `{{- if (and (not (hasKey . "addresses")) (not .enabled)) -}} set addresses (list "127.0.0.1" "[::1]")`. So `admin.enabled=true` ⇒ `0.0.0.0` by chart default, guarded by NetworkPolicy and Service scope instead.

The finding text must name the compensating control to verify rather than assert internet reachability.

On Enterprise with `enforce_rbac`, `GET /` may require an admin token; a credentialed read-only client still sees the field.

### Source

<https://developer.konghq.com/gateway/secure-the-admin-api/>

Verified against `kong.conf.default`, `kong/conf_loader/constants.lua`, `kong/api/routes/kong.lua` (Kong/kong master), and `Kong/charts` `_helpers.tpl`. CVE-2020-11710 (docker-kong `0.0.0.0` admin bind, CVSS 9.8) surfaced in search and is corroborating context only — the vendor disputes the classification and it is a docker-kong packaging default, not a Kong Gateway code defect. It is deliberately **not** used to justify severity.

---

## KONG.ADMIN.UNAUTHENTICATED

**Severity:** high (base) / critical (when off-host or non-loopback bind) · **Kinds:** broker, service · **FP risk:** high · **Confidence:** high

### Check

Two probes. **They are not interchangeable — do not OR them into one verdict.**

**Probe A — edition/reachability.** `GET /` with no `Kong-Admin-Token` and no client certificate.
- HTTP 200 returning the node-info object (`.tagline == "Welcome to Kong"`, `.version`, `.edition`, sanitized `.configuration`) ⇒ the Admin API answers unauthenticated.
- On **Kong OSS this always returns 200**. That is the documented, intended, only-possible OSS posture. It is a reachability signal, not a defect on its own.

**Probe B — Enterprise RBAC misconfiguration.** `GET /rbac/users` with no token.
- HTTP 200 with an RBAC user list ⇒ FAIL. RBAC is not enforcing.
- HTTP 401 with body containing `Invalid RBAC credentials` ⇒ PASS.
- HTTP 404 ⇒ OSS Kong; endpoint absent ⇒ NOT_APPLICABLE for this probe.

### Severity gating (mandatory — this is what keeps the rule shippable)

Emit **high** on an unauthenticated 200. Escalate to **critical** only when *either*:
- the probe originated off-host (the scanner is not on the Kong node / not in the pod), **or**
- `.configuration.admin_listen` is bound non-loopback (see KONG.ADMIN.LISTEN_WILDCARD).

Without this gate the rule fires critical on every default OSS install, and the whole rulepack gets muted.

> **Low-confidence sub-claim:** no Kong doc confirms that `GET /` returns 401 under `enforce_rbac=on` — the docs only say "all requests" require the token. Do not assert that PASS branch for `GET /` without a live Enterprise test. Probe B is the reliable RBAC discriminator.

### Evidence claim

> Unauthenticated `GET /` to the Admin API returned HTTP 200 with `.tagline='Welcome to Kong'`, `.edition='<community|enterprise>'` and a **sanitized** `.configuration` object; no `Kong-Admin-Token` was required. Probe originated from `<on-host | off-host>`; `admin_listen = <value>`.

Do **not** claim a "full `.configuration` object" or secret exposure. `remove_sensitive()` already redacts `pg_password` et al. Claiming otherwise is false and will not survive customer pushback.

### Remediation — must branch on edition/licensing

**`enforce_rbac` does not exist in OSS**, and RBAC is license-gated; per Kong/kong#14660 "free mode" was removed in 3.10, so unlicensed or expired-license Enterprise also cannot enable it. Leading with `enforce_rbac` is wrong advice for most targets.

- **OSS / unlicensed Enterprise:** bind `admin_listen` to loopback, apply L3/L4 network controls, and front the Admin API with an authenticating proxy. There is no in-gateway auth to enable.
- **Licensed Enterprise:** additionally set `enforce_rbac=on` and issue per-user `Kong-Admin-Token` values.

### False positives and how to avoid them

- **Kong OSS on the default loopback bind:** fires 100% of the time and no fix exists. The severity gate is what turns this from noise into a correctly-ranked informational.
- **Scanner running on-host / in-pod / as a sidecar** against `127.0.0.1:8001`: a 200 is expected and safe.
- **Admin API behind an authenticating proxy or mTLS ingress, scanner pointed at the backend:** bypasses the control ⇒ 200 ⇒ FP. Record the probe origin so a triager can see this.
- **`enforce_rbac=entity`:** endpoint-level enforcement semantics are ambiguous in the docs; PASS/FAIL branches may mislabel a hardened gateway.
- **Kong Konnect:** entirely different auth model. Scope this rule to self-managed nodes.

The true positive is real and severe — an unauthenticated, network-reachable Admin API is full gateway takeover (route/plugin injection, certificate access, traffic redirect). Ship it only with the reachability gate, the edition-split remediation, and the corrected evidence string.

### Source

<https://developer.konghq.com/how-to/enable-rbac-with-admin-api/> — cite for the `/rbac/users` probe and remediation only; that page never demonstrates `GET /` under RBAC and states "This tutorial requires Kong Gateway Enterprise." Cite `kong/api/routes/kong.lua` for the `GET /` response shape.

---

## KONG.RBAC.DISABLED

**Severity:** high when `admin_listen` is non-loopback; medium otherwise · **Kinds:** broker · **FP risk:** medium · **Confidence:** high

### Check

`GET /` → `.configuration.enforce_rbac` (string).

**Gates — evaluate only when all hold:**

| Gate | Condition | Else |
|---|---|---|
| Enterprise | `.configuration.enforce_rbac` is present (OSS `kong/templates/kong_defaults.lua` contains no `enforce_rbac` or `rbac_auth_header` key) | 200 with the field absent ⇒ **NOT_APPLICABLE** (OSS), never FAIL |
| Has DB | `.configuration.database != "off"` | **NOT_APPLICABLE**. "RBAC is not available in DB-less." An Enterprise DB-less node reports `enforce_rbac=off` but *cannot* enable it — the remediation is impossible to follow. DB-less is common on Kubernetes. |
| Control plane | `.configuration.role != "data_plane"` | **SKIP**. Hybrid data planes do not own Admin API config; RBAC is a control-plane concern. Also consider skipping Konnect-managed nodes, where authz lives in Konnect. |

**Verdict:**
- `enforce_rbac == "off"` ⇒ **FAIL**. (Enum is `on` \| `off` \| `entity` \| `both`; default `off`.)
- Anything other than `"off"` ⇒ PASS.
- HTTP 401 with a body containing `Invalid RBAC credentials` (no token sent) ⇒ **PASS** — RBAC is on and enforcing, so the field is not returned. Match on **substring**, not equality: some versions report the longer `Invalid RBAC credentials. Token or User credentials required`.

`'admin'` is **not** a valid enum value — do not accept it. The config reference states: "Specifies whether Admin API RBAC is enforced. Accepts one of `entity`, `both`, `on`, or `off`."

### Evidence claim

> Admin API `GET /` reports `.configuration.enforce_rbac = 'off'` on Kong Enterprise version 3.14.0.3 (`database = 'postgres'`, `role = 'traditional'`), so Kong enforces no RBAC authn/authz on Admin API requests. `admin_listen = <value>` — the Admin API may still be protected by loopback-only binding, mTLS, or a fronting auth proxy.

Do not claim "no `Kong-Admin-Token` is required for Admin API requests" as an unqualified fact; that is true only at the RBAC layer.

### Remediation

Set `enforce_rbac=on` in `kong.conf` (or `KONG_ENFORCE_RBAC=on`) and reload. Create a super admin via `POST /rbac/users` with a `user_token`, then send the token on Admin API requests using the header named by `.configuration.rbac_auth_header` — **read this from the same `GET /` response rather than hardcoding**; `Kong-Admin-Token` is its default, not a constant. Verify by confirming an unauthenticated request returns a body containing `Invalid RBAC credentials`.

### False positives and how to avoid them

The three gates above are the FP controls — DB-less especially, where the finding is unactionable. `admin_gui_auth` cannot mask this (Kong errors with "enforce_rbac must be enabled when admin_gui_auth is enabled"), so that is not an FP source. Cross-reference `admin_listen` to set severity: a loopback-bound RBAC-off node is a hardening gap, not an exposure.

### Source

<https://developer.konghq.com/gateway/entities/rbac/> — supports `enforce_rbac=on` in `kong.conf`, `KONG_ENFORCE_RBAC=on`, `POST /rbac/users`, and the `Kong-Admin-Token` header. It does **not** document the enum, the default, `GET /`, or the error string. Add the Kong Gateway configuration reference for the enum/default and <https://developer.konghq.com/how-to/configure-rbac-user-in-kong-gateway/> for the "Invalid RBAC credentials" string.

> The enum and `off` default were verified from the Kong 2.8 configuration reference; the current `developer.konghq.com/gateway/configuration/` fetch did not surface an `enforce_rbac` entry (truncation or OSS page scope). The enum is longstanding with no evidence of change, but confidence that `'admin'` is invalid *in 3.14 specifically* is medium-high, not certain. Note a doc inconsistency: the enable-RBAC how-to's prose says `enable_rbac` while its own example uses `KONG_ENFORCE_RBAC` — **`enforce_rbac` is the real parameter.**

---

## KONG.ADMIN.PLAINTEXT_LISTENER

**Severity:** high · **Kinds:** broker · **FP risk:** low · **Confidence:** high

### Check

`GET /` → `.configuration.admin_listen`. For each entry whose host is **not** loopback, **FAIL** if the entry's whitespace-tokenized flag list does not contain `ssl`.

- Failing: `0.0.0.0:8001 reuseport backlog=16384`
- Passing: `10.0.0.5:8444 http2 ssl`

**Parsing requirements (each is a real FP source):**

- **Loopback set:** the whole of `127.0.0.0/8` (not just `127.0.0.1`); `::1` **and** bracketed `[::1]` — `kong/conf_loader/listeners.lua` normalizes IPv6 with brackets, so a bare `::1` comparison misses it; and the hostname literal `localhost`, which is not an IP literal and will otherwise be read as non-loopback. Without these, `localhost:8001`, `[::1]:8444`, and `127.0.0.2:8001` all false-positive.
- **Skip the literal entry `off`.** Valid, and disables the Admin API. A naive tokenizer FAILs it — `off` has no loopback host and no `ssl` flag. Mostly self-limiting (you cannot query `GET /` when admin is off, and a `control_plane` node errors with "admin_listen must be specified when role = control_plane"), but the parser must not crash or misfire if reached another way.
- **Tokenize on whitespace.** Never substring-match `ssl` against the whole entry, or a path or flag containing that substring causes a false PASS.

Do **not** use `admin_ssl_enabled` as a substitute: it is true if *any* listener has `ssl`, so it cannot detect a mixed plaintext+TLS config.

> **Optional hardening, low confidence — verify on a live node first.** `kong/conf_loader/init.lua` calls `listeners.parse(conf, {{name="admin_listen", subsystem="http", ssl_flag="admin_ssl_enabled"}})`, producing a derived `admin_listeners` array whose entries carry `ip` / `port` / `listener` plus boolean per-flag fields including `ssl`. If `.configuration.admin_listeners` is actually emitted in `GET /`, it is strictly more robust than string-tokenizing (handles `off` as an empty array, normalizes IPv6, resolves flags). Its presence in a real response body is **unconfirmed** — `spec/02-integration/04-admin_api/02-kong_routes_spec.lua` asserts only that `configuration` is a table and that `pg_password` is obfuscated. Keep `.configuration.admin_listen` as the primary path; it *is* confirmed present.

### Evidence claim — branch on `.edition`

> Admin API listener `'0.0.0.0:8001 reuseport backlog=16384'` binds a non-loopback address without the `ssl` flag, exposing full gateway control over plaintext HTTP (Enterprise: `Kong-Admin-Token` RBAC credentials are sent in cleartext; OSS: the Admin API is unauthenticated by default).

The original wording — "Kong-Admin-Token credentials traverse the network in plaintext" — is Enterprise-only and factually wrong on a community node, where no token exists and the actual risk is worse. `GET /` returns `.edition` (`"enterprise"` or `"community"`); branch on it.

If the scanner itself reached `GET /` over plaintext HTTP on a non-loopback address, that connection is direct corroboration — cite it in the evidence.

### Remediation — network restriction first, TLS second

Restrict the Admin API to `127.0.0.1`, firewall it, or drop the plaintext `8001` listener entirely. Only where off-host admin access is genuinely required, add the `ssl` flag (the default TLS listener is `127.0.0.1:8444 http2 ssl`).

This ordering matters: Kong's Secure-the-Admin-API page leads with network-layer restriction — loopback binding, iptables, proxying the Admin API through Kong itself, custom nginx auth, RBAC — and **does not recommend enabling `ssl` on the admin listener anywhere**.

### False positives and how to avoid them

- **Service-mesh mTLS (Istio/Linkerd sidecar) in front of a plaintext admin listener:** the wire is encrypted and the rule fires wrongly. Real but a minority; the defense-in-depth merit survives. Add a suppression note to the finding.
- **`0.0.0.0:8001` behind a host firewall or an unpublished container port:** unobservable from the Admin API.
- The **"Kubernetes containers must bind 0.0.0.0, so this is noise" objection largely fails.** Kong's own Helm chart (`Kong/charts` `values.yaml`) defaults to `admin.enabled: false` and, when enabled, `http.enabled: false` + `tls.enabled: true` on 8444 — plaintext admin is the vendor's *non*-default. And absent a NetworkPolicy, pod IPs are routable cluster-wide, so `0.0.0.0:8001` in a pod is genuinely reachable. A high firing rate on stock Docker deployments (image default `KONG_ADMIN_LISTEN=0.0.0.0:8001`) is **correct firing**, not FP.

### Scope gap (companion rule recommended)

This rule **passes** `0.0.0.0:8444 http2 ssl` — an Admin API exposed to the entire network, merely encrypted. Per Kong's own guidance that is the higher-value finding. Add `KONG.ADMIN.OFF_HOST_LISTENER`, firing on any non-loopback `admin_listen` entry regardless of `ssl`.

### Sources

- <https://developer.konghq.com/gateway/configuration/> — `admin_listen` key, default, flag semantics, the "avoid ... 0.0.0.0:8001" warning
- <https://developer.konghq.com/gateway/secure-the-admin-api/> — primary guidance, network restriction first
- <https://developer.konghq.com/gateway/network/> — 8001 = HTTP, 8444 = HTTPS; "prevent unauthorized access to these ports in production"
- <https://raw.githubusercontent.com/Kong/kong/master/kong.conf.default> — authoritative default and flag docs

---

## KONG.ROUTE.NO_AUTH_PLUGIN

**Severity:** high (escalate to critical only with corroboration) · **Kinds:** route, service · **FP risk:** high · **Confidence:** high

### Check — resolve inheritance yourself

**Do not use `GET /routes/{id}/plugins`.** It returns only plugins whose `route` field points at that route, and omits inherited service-scoped and global plugins that also execute on it. A detector built on it false-positives on every route protected at service or global scope. (This is structurally implied by `kong/api/endpoints.lua` foreign-collection handling rather than stated in one doc sentence — confidence medium-high, but the failure mode is easy to confirm on a live node.)

Correct method:

1. `GET /plugins?size=1000`, following `.next` / `.offset` until exhausted. (`kong/api/endpoints.lua`: `page_size = 100, max_page_size = 1000` — `size=1000` is valid, at the cap. On Enterprise, `/plugins` is **workspace-scoped**; iterate workspaces or the check misses plugins outside the default workspace.)
2. `GET /routes?size=1000`, paginated. Each route `R` has `.id`, `.service` (object with `.id`, or `null` for serviceless routes — `routes.lua` declares `service` as `{ type = "foreign", reference = "services" }` with no `required=true`), and `.protocols`.

**Route filter — skip stream routes.** `routes.lua` defines protocols with `mutually_exclusive_subsets {http,https}, {tcp,tls,udp}, {tls_passthrough}, {grpc,grpcs}`. HTTP auth plugins do not support `tcp`/`tls`/`udp` (key-auth supports "grpc, grpcs, http, https, ws, and wss"). So for any route whose protocols lie wholly within `{tcp, tls, udp, tls_passthrough}`, the protocol-intersection clause can **never** be satisfied by any auth plugin, and the rule fires on 100% of stream routes. Evaluate only routes whose protocols intersect `{http, https, grpc, grpcs, ws, wss}`. TLS-layer controls (mtls-auth, SNI/cert config) govern stream routes, not HTTP auth plugins.

**AUTH set** (all 14 slugs verified in the Plugin Hub; `header-cert-auth` is Gateway 3.8+ Enterprise-only):

```
key-auth, key-auth-enc, basic-auth, hmac-auth, jwt, oauth2,
oauth2-introspection, openid-connect, ldap-auth, ldap-auth-advanced,
mtls-auth, header-cert-auth, vault-auth, saml
```

Make this set **configurable and extensible**. Custom Lua plugins are a first-class Kong feature and are widely used for auth in enterprises, as are third-party plugins (`nokia/kong-oidc`, `opa`, `jwt-signer`, `external-oauth2`, `pre-function` doing auth). Treat an unknown non-core plugin name attached to the route or its service as **"unknown — possible auth"** and downgrade to informational rather than asserting a finding.

**Route `R` is PROTECTED** if there exists a plugin `P` where all hold:

- `P.name` ∈ AUTH
- `P.enabled == true`
- `P.consumer == null` **and** `P.consumer_group == null` (identity is not known until auth completes, so auth plugins cannot meaningfully be consumer-scoped; near-inert but included for symmetry)
- `(P.protocols ∩ R.protocols) != ∅`
- `P.config.anonymous` is null or empty — **see below**
- and one of:
  - **(a) global:** `P.route == null AND P.service == null`
  - **(b) route-scoped:** `P.route != null AND P.route.id == R.id` (a plugin with *both* `route` and `service` set applies only to that route, so matching on `P.route.id` is sufficient — do **not** additionally require `P.service == null` here)
  - **(c) service-scoped:** `P.route == null AND P.service != null AND R.service != null AND P.service.id == R.service.id`. The `P.route == null` requirement is load-bearing: without it, a route+service-scoped plugin on route A is wrongly credited to route B of the same service.

**FAIL** if no such `P` exists.

**Soundness gap — `config.anonymous`.** Per the key-auth reference, `anonymous` is "An optional string (consumer UUID or username) value to use as an 'anonymous' consumer if authentication fails. If empty (default null), the request will fail with an authentication failure 4xx." A route with an enabled auth plugin whose `config.anonymous` is set is **effectively open**, but a naive check marks it PROTECTED. A plugin counts as PROTECTED only if `config.anonymous` is null/empty; otherwise report under KONG.AUTH.ANONYMOUS_FALLBACK.

Kong's documented precedence (most-specific wins: consumer+route+service > … > route > service > global) governs *which* matching instance runs. For a boolean "is any auth in effect" check, the existence of any one matching instance is enough — precedence matters only if you also want to report *which* config applies.

### Evidence claim

> Route 'public-api' (id 7c9e...) on service 'billing' (id 1a2b...), protocols=['http','https'], has no enabled authentication plugin at route, service, or global scope: `/plugins` (fully paginated) contains no entry from {key-auth, jwt, oauth2, openid-connect, …} with `route.id=7c9e...`, `service.id=1a2b...`, or (`route=null AND service=null`) whose `protocols` intersect ['http','https'] and whose `config.anonymous` is null.

Stating the protocols compared and the `config.anonymous` check makes the finding reproducible and makes the stream-route and anonymous exclusions visible.

### Remediation

Attach an authentication plugin at route or service scope, e.g. `POST /routes/{route}/plugins` with `name=key-auth` (or `jwt` / `oauth2` / `openid-connect`). Prefer service scope for uniform coverage. Ensure the plugin's `protocols` overlap the route's, that `enabled=true`, and that `config.anonymous` is null.

### False positives and how to avoid them

Severity is **high, not critical**, and requires triage. The rule cannot establish upstream sensitivity or exploitability, and cannot distinguish:

- **Intentionally public endpoints** — `/health`, `/login`, `/token`, OIDC callbacks, webhooks, public docs, static assets. Consider suppression for routes matching known-public path patterns.
- **Auth enforced at the upstream service** — Kong used as a pure router.
- **Custom or third-party auth plugins** — hence the extensible AUTH set.

Escalate to critical only with a corroborating signal: the route fronts a service flagged sensitive, or no `ip-restriction` / rate-limiting / `request-termination` is present either.

### Source

<https://developer.konghq.com/gateway/entities/plugin/> · <https://developer.konghq.com/gateway/entities/route/> · <https://developer.konghq.com/plugins/key-auth/reference/> · `kong/db/schema/entities/routes.lua` · `kong/api/endpoints.lua` (Kong master, 2026-07-17)

---

## KONG.AUTH.ANONYMOUS_FALLBACK

**Severity:** high (medium when the anonymous consumer carries restrictive plugins) · **Kinds:** plugin, route, service · **FP risk:** medium (after corrections; high as naively written) · **Confidence:** high

### Check

**AUTH set — enumerate explicitly, do not leave it loose.** Verified to carry `config.anonymous`: `key-auth`, `basic-auth`, `jwt`, `oauth2`, `ldap-auth`, `hmac-auth`. Enterprise plugins (`key-auth-enc`, `ldap-auth-advanced`, `openid-connect`, `mtls-auth`) are *likely* but **not individually verified — low confidence**; check each reference page before including.

1. `GET /plugins?size=1000`, following the `next`/`offset` cursor to exhaustion. On Enterprise, `/plugins` is workspace-scoped — iterate workspaces or document the limitation.
2. `GET /consumers?size=1000`, paginated. **Required:** `config.anonymous` accepts a consumer UUID *or* username ("must refer to the Consumer ID or username attribute, and not its `custom_id`"), so resolve it against both `.id` and `.username` before evaluating any consumer-scoped exception. A check that skips this can never match consumer-scoped mitigations at all.
3. For each plugin `P` where `P.name` ∈ AUTH and `P.enabled == true`: **FAIL** if `P.config.anonymous` is non-null, **unless** a mitigation below applies.

**Mitigation 1 — consumer-scoped `request-termination` (primary).** Kong's canonical deny-anonymous pattern scopes `request-termination` to the **anonymous consumer**, not the route or service:

```yaml
- username: anonymous
  plugins:
  - name: request-termination
    config: {status_code: 401, message: '"Error - Authentication required"'}
```

That plugin object has `consumer=<anon-id>`, `service=null`, `route=null`. An exception phrased as "in effect at the same or narrower scope for the same route/service" **does not match it**, and the rule then FAILs the exact config Kong documents as correct. The exception must be: `name == 'request-termination' AND enabled == true AND consumer.id == <resolved anonymous consumer id>`. Kong's authentication overview recommends `request-termination` and never mentions ACL — this is the primary exception, not an afterthought.

**Mitigation 2 — ACL, allow *or* deny.** Per the ACL reference, `allow` and `deny` are arrays of group names and are mutually exclusive ("One of `config.allow` or `config.deny` must be specified").
- Accept `config.deny` containing the anonymous consumer's groups — the documented deny pattern. An allow-only exception misses it and false-positives.
- Do **not** accept a non-empty `config.allow` blindly. If the anonymous consumer belongs to an allowed group, the ACL mitigates nothing. Verify via `GET /consumers/{id}/acls` that the anonymous consumer's groups are **disjoint** from `config.allow`.

**Edge case — `config.anonymous == ""`.** Legacy rows may hold an empty string. Since Kong 2.0 that raises "failed to load anonymous consumer" at runtime rather than falling through, so the stated impact is wrong for that value. Treat `""` as a separate **broken-config** finding, not an anonymous-fallthrough finding.

### Evidence claim

> Plugin key-auth (id 4f1d...) scoped to service 'billing' has `config.anonymous='guest'`; consumer 'guest' (id 8b2e...) has no `request-termination` plugin and no ACL groups excluded by an acl plugin on service 'billing', so requests failing key validation are proxied upstream as 'guest'.

The original "with no companion acl plugin" is insufficient and unfalsifiable — the claim must also assert no consumer-scoped `request-termination` on the anonymous consumer.

### Remediation

Set `config.anonymous` to null so failed authentication returns 401. If an anonymous consumer is intentional, attach `request-termination` to that consumer (Kong's documented multi-auth pattern), or pair it with an acl plugin whose `config.allow` excludes the anonymous consumer's groups (or whose `config.deny` includes them).

### False positives and how to avoid them

`high` is correct for the true positive: an auth plugin present means intent to protect, and unmitigated anonymous fallthrough means unauthenticated upstream access. But `config.anonymous` is a **supported design** for intentionally public or mixed-auth services (identify the caller if credentialed, else anonymous), and the scanner cannot know upstream intent. Downgrade to **medium** when the anonymous consumer carries restrictive plugins (e.g. rate-limiting), and phrase the finding to ask the operator to confirm intent.

> **Low confidence:** Kong/kong#2547 ("Anonymous auth breaks ACL plugin") reports ACL rejecting anonymous-authenticated consumers with "Cannot identify the consumer…"; it was left as needs-investigation with no visible resolution. Current ACL-vs-anonymous behavior is version-dependent and unverified for a current release — another reason to make `request-termination` the primary exception.

### Sources

<https://developer.konghq.com/plugins/key-auth/reference/> (quote matches verbatim) · <https://developer.konghq.com/gateway/authentication/> · <https://developer.konghq.com/how-to/allow-multiple-authentication/> · <https://developer.konghq.com/plugins/acl/reference/> · <https://developer.konghq.com/plugins/acl/examples/deny-consumers/> · `kong/plugins/key-auth/handler.lua` · `kong/db/schema/entities/plugins.lua` · Kong/kong discussion #8143

> The 1000 `size` cap is from secondary sources only (low-medium confidence) — the admin-ee OpenAPI spec URL 404'd. Follow the cursor regardless.

---

## KONG.ROUTE.HTTP_PROTOCOL_ALLOWED

**Severity:** low · **Kinds:** route · **FP risk:** high · **Confidence:** medium

### Check

**Precondition (required — otherwise the finding is inert).** `GET /` → `.configuration.proxy_listen`. If Kong has **no plaintext (non-`ssl`) proxy listener**, `protocols` containing `http` cannot be exercised. Suppress, or drop to info.

Then `GET /routes?size=1000` (paginate via `.offset`/`.next` — `size=1000` is exactly `max_page_size`, **not** "all routes"). For each route `R`, inspect `.protocols`. **FAIL** if it contains a plaintext variant: `http`, `grpc`, or `ws`/`wss` on Enterprise.

**Protocol enum — get this right per edition.** `kong/constants.lua` `PROTOCOLS` = `grpc, grpcs, http, https, tcp, tls, tls_passthrough, udp`. Note:
- `tcp` and `udp` are real and are plaintext L4 — commonly omitted from hand-written enums.
- `ws`/`wss` are **Kong Gateway Enterprise-only**; on OSS they are not valid protocol values and can never appear.
- `routes.lua` enforces `mutually_exclusive_subsets: {http,https} | {tcp,tls,udp} | {tls_passthrough} | {grpc,grpcs}`.

When `.protocols` is exactly `["https"]`, Kong redirects matching plaintext requests using `.https_redirect_status_code` — `one_of {426, 301, 302, 307, 308}`, **default 426** (Upgrade Required). 301/302 are acceptable browser-friendly alternatives.

Schema verified in `kong/db/schema/entities/routes.lua`: `protocols = { type="set", default={"http","https"}, elements=typedefs.protocol }`; `https_redirect_status_code = { type="integer", one_of={426,301,302,307,308}, default=426, required=true }`.

### Evidence claim

> Route 'public-api' (id 7c9e...) has `protocols=['http','https']`, so Kong serves this route over plaintext HTTP rather than redirecting or rejecting cleartext requests. Plaintext proxy listener present: `<yes/no — proxy_listen value>`. `trusted_ips = <value>`.

Recording the plaintext-listener and `trusted_ips` facts lets a triager distinguish real cleartext exposure from TLS offload.

### Remediation — read the `trusted_ips` warning first

`PATCH /routes/{id}` with `protocols=["https"]` (and `grpcs`/`wss` as applicable). Set `https_redirect_status_code=301` if a browser-friendly redirect is wanted instead of the 426 default.

**⚠ If TLS is terminated upstream of Kong, set `trusted_ips` to the LB/proxy CIDRs *before* changing `protocols`.** `kong.conf.default` ships `trusted_ips` unset, and Kong honors `X-Forwarded-*` only from trusted IPs. In a TLS-offload topology, `protocols=["https"]` makes Kong treat LB-forwarded HTTPS as plaintext and redirect/426 **all** traffic, including already-HTTPS requests — an infinite redirect loop (Kong/kong#6797).

**Do not apply the redirect framing to gRPC.** gRPC clients do not follow HTTP redirects; `grpc` → `grpcs` is a client-breaking change, not a redirect.

Kong 3.14+ defaults *new* routes to `["https"]` only; existing routes are unaffected.

### False positives and how to avoid them

`[http, https]` was the shipped default for every Kong release prior to 3.14, so on any pre-3.14 install this fires on ~100% of routes — a global posture observation, not a per-route finding. Hence **low**, downgraded from medium. It is also not exploitable standalone; the plaintext-listener precondition is what gives it any signal. Justify medium only when a plaintext listener is confirmed **and** Kong is the TLS-terminating edge.

Mandatory suppressions:

1. **TLS terminated upstream** by ALB/NLB/CloudFront/nginx/ingress/mesh sidecar — the dominant Kong topology, especially on Kubernetes. Plaintext between LB and Kong is inside the trust boundary and `http` in `protocols` is **required**.
2. **ACME/Let's Encrypt HTTP-01 challenge routes**, which must serve `/.well-known/acme-challenge` over plaintext (Kong/kong#8288).
3. **Health-check/liveness routes** on internal plaintext listeners.
4. **Purely internal east-west Kong instances** with no external plaintext exposure.

### Sources

<https://developer.konghq.com/gateway/entities/route/> supports `.protocols` and the 3.14 default ("v3.14+ By default, Routes only accept requests over HTTPS. To allow requests over HTTP, set `protocols: [http, https]`") but does **not** mention `https_redirect_status_code`, the 426 default, or the protocol enum. Add:

- <https://developer.konghq.com/gateway/breaking-changes/> — 3.14 default change, verbatim
- <https://developer.konghq.com/deck/gateway/defaults/> — shows `https_redirect_status_code: 426`, `protocols: [http, https]`
- <https://developer.konghq.com/kubernetes-ingress-controller/routing/http-to-https/> — "the default if unset is 426"
- `kong/db/schema/entities/routes.lua`, `kong/constants.lua`

---

## KONG.ROUTE.NO_RATE_LIMITING

**Severity:** medium · **Kinds:** route, service · **FP risk:** medium · **Confidence:** high

### Check

Use the inheritance resolution from KONG.ROUTE.NO_AUTH_PLUGIN, **extended with consumer and consumer-group scope**.

**RL set:** `rate-limiting`, `rate-limiting-advanced`, `response-ratelimiting`, `graphql-rate-limiting-advanced`. Consider adding `ai-rate-limiting-advanced` (exists per Kong docs, for LLM traffic).

**FAIL** for any route `R` where no enabled plugin `P` with `P.name` ∈ RL resolves to `R`.

**Required corrections to the resolver:**

1. **Resolve consumer and consumer_group scopes** — the primary FP source. The plugin entity page documents precedence including Consumer+Route+Service, ConsumerGroup+Service+Route, Consumer+Route, Consumer+Service, ConsumerGroup+Route, ConsumerGroup+Service, Consumer, ConsumerGroup. Per-consumer and consumer-group tiered rate limiting is a pattern Kong's own docs promote — `rate-limiting`'s `config.limit_by` accepts `consumer` | `consumer-group` | `credential` | `header` | `ip` | `path` | `service` (**default: `consumer`**). Such plugin rows have `service=null` and `route=null` with `consumer`/`consumer_group` set, so a global/service/route-only resolver emits a FAIL on routes that are in fact fully limited.
2. **Intersect `P.protocols` with `R.protocols`.** Plugin objects carry their own `protocols` (rate-limiting default `["grpc","grpcs","http","https"]`). A global RL plugin scoped to `["grpc","grpcs"]` does not apply to an http route — without the intersection this causes a false **PASS**.
3. **Paginate properly.** Follow the `offset`/`next` cursor until exhausted; do not rely on a single `GET /plugins?size=1000`. Any plugin missed by truncation becomes a false FAIL. (The documented `size` maximum could not be verified against primary docs — the admin-ee reference 404'd — so treat the 1000 cap as unverified and follow the cursor regardless.)

"Prioritise internet-facing routes" is a **ranking hint, not a filter**. Consider excluding routes whose protocols lack `http`/`https`, or demoting them to informational.

### Evidence claim

> Route 'public-api' (id 7c9e...) resolves to no enabled plugin in {rate-limiting, rate-limiting-advanced, response-ratelimiting, graphql-rate-limiting-advanced} at route, service, global, consumer, or consumer-group scope with a protocol matching the route.

(The original listed only three plugins while defining four — keep this consistent with the RL set, and state the scopes actually searched.)

### Remediation — the two plugins have different config keys

Attach `rate-limiting` at service or route scope with at least one of `config.second` / `minute` / `hour` set, **or** `rate-limiting-advanced` with matching `config.limit` and `config.window_size` arrays. For multi-node deployments, set `rate-limiting`'s `config.policy` (or `rate-limiting-advanced`'s `config.strategy`) to `redis` or `cluster` rather than the `local` default, so counters are shared across nodes.

**`rate-limiting-advanced` has no `second`/`minute`/`hour` fields and no `config.policy`** — it uses `config.strategy` (default `local`) and `config.limit[]` / `config.window_size[]` arrays. `config.policy` (default `local`; values `cluster` | `local` | `redis`) is confirmed for `rate-limiting` and is reused by `response-ratelimiting`.

### False positives and how to avoid them

Residual and accepted — document rather than fix:

- **Rate limiting enforced upstream of Kong** (CDN/WAF/nginx) is invisible to the Admin API.
- **Custom or third-party RL plugins** with non-matching names.
- **Internal-only routes** still FAIL under a ranking-only prioritisation; filter or demote them.

### Sources

<https://developer.konghq.com/plugins/rate-limiting/reference/> (supports `second`/`minute`/`hour` and `policy`, but is a bare parameter table and does not support the multi-node rationale) · <https://developer.konghq.com/plugins/rate-limiting/> (overview, for the narrative) · <https://developer.konghq.com/plugins/rate-limiting-advanced/reference/> (the `strategy` key) · <https://developer.konghq.com/gateway/entities/plugin/> (precedence)

---

## KONG.RATELIMIT.FAIL_OPEN

**Severity:** low · **Kinds:** plugin · **FP risk:** high · **Confidence:** high

### Check

`GET /plugins`, following the `offset`/`next` cursor (`max_page_size = 1000` confirmed in `kong/api/endpoints.lua`; a fleet above 1000 plugins silently under-reports otherwise).

For each `P` where **`P.name == 'rate-limiting'`** and `P.enabled == true`: **FAIL** if `P.config.policy` ∈ `{redis, cluster}` **and** `P.config.fault_tolerant == true` (the default).

**`rate-limiting-advanced` is out of scope — remove it.** The rule is factually wrong for it on three counts: (a) RLA has **no `fault_tolerant` parameter** (its full top-level set is `compound_identifier, consumer_groups, counter_key, dictionary_name, disable_penalty, enforce_consumer_groups, error_code, error_message, header_name, hide_client_headers, identifier, limit, lock_dictionary_name, namespace, path, redis, retry_after_jitter_max, strategy, sync_rate, throttling, window_size, window_type`); (b) its datastore selector is `config.strategy`, not `config.policy`; (c) **RLA does not fail open** — "When the `redis` strategy is used and a Kong Gateway node is disconnected from Redis, the plugin will fall back to `local` rate limiting," i.e. it still rate limits, it just cannot sync counters. As written the RLA clause is a dead branch (`config.policy` is nil ⇒ never matches); worse, an implementation treating an absent `fault_tolerant` as "default true" would misfire.

Verified in `kong/plugins/rate-limiting/schema.lua`: `fault_tolerant = { type = "boolean", required = true, default = true }`; `policy = { type = "string", default = "local", one_of = { "local", "cluster", "redis" } }`. **`cluster` is not in `one_of` under DB-less/declarative mode** (dbless `one_of` is `{ "local", "redis" }`), so in DB-less and hybrid deployments only `policy='redis'` can match.

Behavior confirmed in `kong/plugins/rate-limiting/handler.lua`: `if err then if not fault_tolerant then return error(err) end` followed by `kong.log.err("failed to get usage: ", tostring(err))` and continued execution — the limit check is skipped and the request proxies uncounted.

### Evidence claim

> Plugin rate-limiting (id 9b2c...) has `config.policy='redis'` and `config.fault_tolerant=true`, so a Redis outage causes rate limits to be bypassed rather than enforced. `GET /plugins` returns schema defaults materialised, so this rule cannot distinguish a deliberate operator choice from an untouched default.

State that limitation rather than asserting intent — a plugin created without touching the field still returns `"fault_tolerant": true`.

### Remediation — the blanket advice is unsafe

`fault_tolerant=false` does **not** produce a 429. `return error(err)` surfaces as **HTTP 500 for all traffic** on the affected route/service for the duration of the datastore outage (docs: "If `false`, then the clients will see `500` errors").

> If this limiter is a security control (abuse / brute-force / DoS defence), consider `config.fault_tolerant=false`, accepting that a datastore outage will 500 all traffic on this route. If it is a quota, cost-control, or fairness limiter, the default `fault_tolerant=true` is correct and this finding should be dismissed.

### False positives and how to avoid them

**Severity is low — arguably info/posture, not a finding.** This is the vendor default, it is not a standing bypass (it requires a concurrent datastore outage to manifest), and rate-limit bypass is not auth bypass. Kong's own default treats fail-open as intended behavior.

Noise gate required before shipping — this fires on essentially every redis/cluster-policy rate-limiting plugin in any fleet:

- Suppress when a compensating control is visible: a second `rate-limiting` plugin with `policy='local'` on the same route/service, or upstream/CDN limiting recorded out-of-band.
- Treat `policy='cluster'` as lower signal still — there the counter store is Kong's own Postgres, so if it is down the control plane is already degraded and the bypass is largely moot.

### Source

<https://developer.konghq.com/plugins/rate-limiting/reference/> · <https://developer.konghq.com/plugins/rate-limiting-advanced/reference/> · <https://developer.konghq.com/plugins/rate-limiting-advanced/> · `kong/plugins/rate-limiting/{schema,handler}.lua`

---

## KONG.CORS.WILDCARD_WITH_CREDENTIALS

**Severity:** high · **Kinds:** plugin, route, service · **FP risk:** low · **Confidence:** medium (citation is the field reference only)

### Check

`GET /plugins`, following the `next`/`offset` cursor to exhaustion. `size=1000` is exactly `max_page_size` (`kong/api/endpoints.lua`: `page_size = 100, max_page_size = 1000`); values above 1000 are rejected with `INVALID_SIZE` / 400. Deployments with >1000 plugins silently truncate on a single page.

For each `P` where `P.name == 'cors'` and `P.enabled == true`: **FAIL** if `P.config.credentials == true` (default `false`) **AND** any of:

1. `P.config.origins` is **null/absent**, **or**
2. `P.config.origins` is an **empty array `[]`** — this is identical to unset and must fire. `handler.lua:70-73` computes `n_origins = conf.origins ~= nil and #conf.origins or 0` then allow-alls on `n_origins == 0`. (Raised as undocumented in Kong/docs.konghq.com#7875.)
3. `P.config.origins` contains the **literal `'*'`** — correct as written, including in multi-element lists: `handler.lua:102-106` shows `'*'` *anywhere* in a multi-entry origins array returns `allow_all`, not only as a single value.
4. `P.config.origins` contains a **match-anything regex**, restricted to a conservative literal set: `.*`, `.+`, `^.*$`, `.*$`, `^.+$`, `(.*)`.

**Do not implement clause 4 as a substring search for `.*`** — the biggest noise trap. Kong anchors regexes at both ends (`handler.lua:118-124` appends `$` if absent and strips a leading `^`; line 153 matches with the `ajo` flags, `a` = anchored start), so `.*\.example\.com` is a correctly-scoped, legitimate config that a substring check would fire on wrongly. Flag anything outside the literal set as informational only.

**Second code path, same outcome.** An origins entry of `.*` does not set `allow_all` (it fails the `'*'` literal test at line 73 and the non-regex test at line 86), but line 163 sets ACAO to the reflected request origin, then `configure_credentials` (lines 181-183) sets ACAC true. Same exploitability, different branch — a true positive either way.

### Evidence claim — the second sentence is what makes it defensible

> Plugin cors (id 3e8a...) scoped to service 'billing' has `config.origins=['*']` together with `config.credentials=true`, permitting any site to issue credentialed cross-origin requests and read the responses. Kong does not actually emit the literal `'*'` here — `configure_credentials()` (`kong/plugins/cors/handler.lua:186-192`) detects that ACAC cannot be true alongside `ACAO: '*'` and substitutes the caller's request Origin verbatim, setting `Access-Control-Allow-Origin: <attacker-origin>` with `Access-Control-Allow-Credentials: true`. The wildcard is reflected, not blocked.

Without that second sentence a reviewer will dismiss the finding with "browsers reject `ACAO: *` with credentials, so this is theoretical." That rebuttal is wrong, and the evidence should preempt it.

### Remediation

Enumerate exact trusted origins in `config.origins` (e.g. `['https://app.example.com']`) whenever `config.credentials=true`. If a wildcard origin is genuinely required, set `config.credentials=false`. **Never leave `config.origins` unset or empty on a credentialed CORS config — both mean "allow all origins."**

### False positives and how to avoid them

FP risk is low once the regex clause is narrowed. Triage hint, not a suppression: CORS is browser-enforced, so impact is nil where the listener is not browser-reachable (east-west / service-mesh traffic) or where auth is Bearer-token-only in an `Authorization` header (not auto-attached by `credentials: include`). These are latent misconfigurations rather than live vulns, but they are cheap to fix — keep them reportable.

### Source

<https://developer.konghq.com/plugins/cors/reference/> · `kong/plugins/cors/handler.lua`

> Confidence is medium on **citation**, not on mechanics. Kong's CORS reference documents `config.origins` and `config.credentials` and their defaults but carries **no explicit warning** about combining `origins='*'` with `credentials=true`. The rule rests on the general CORS security model plus the handler source, not on a Kong doc statement.

---

## KONG.ROUTE.WILDCARD_HOST_OR_PRESERVE_HOST

**Severity:** low · **Kinds:** route · **FP risk:** low once narrowed (high as naively written) · **Confidence:** medium

### Check — fire only on the conjunction

`GET /routes?size=1000`, paginating via `.offset` until null (`size=1000` is exactly `max_page_size`, not "all routes").

**FAIL** only when **both** hold:

- `.preserve_host == true` (type boolean, `required=true`, `default=false` — `routes.lua:174`), **and**
- `.hosts` is null/`[]` **or** any `.hosts` entry contains a wildcard.

**Both standalone limbs must be dropped:**

- **"`hosts` is null ⇒ FAIL" alone is noise.** `hosts` is not required (`routes.lua`: `{ hosts = typedefs.hosts }` — no default, no `required`). Path-only routes are *the* canonical Kong pattern and are what Kong Ingress Controller and decK generate. This limb fires on a large fraction of routes in every real deployment.
- **"`preserve_host == true` alone" is noise and wrong.** When `.hosts` is an explicit non-wildcard allowlist, Kong only matched because the client Host equalled one of those entries, so the Host forwarded upstream is constrained to the allowlist — not attacker-arbitrary. No finding. `preserve_host=true` is also legitimately required by upstreams that build absolute URLs, OAuth redirects, or multi-tenant vhosts.

**Wildcard forms.** `typedefs.lua` enforces "wildcard must be leftmost or rightmost character" and "only one wildcard must be specified" / "at most one wildcard label". Match both `*.example.com` and `example.*`.

**Expressions-router flavor — a hard false positive if unhandled.** `routes.lua` `validate_route` rejects setting `expression` together with `methods`, `hosts`, `paths`, `headers`, `snis`, `sources`, `destinations`. So **every** expressions-flavor route returns `.hosts == null` over the Admin API while potentially pinning the Host inside the expression (e.g. `http.host == "example.com"`). Read the `.expression` field and treat a route as host-constrained if the expression references `http.host` before concluding "matches any Host header." Without this, every expressions-flavor route is a false positive.

### Evidence claim

> Route 'catch-all' (id 5d7f...) has `hosts=null` (matches any Host header, and carries no `http.host` constraint in `.expression`) and `preserve_host=true`, so arbitrary client-supplied Host values are forwarded to the upstream service.

### The docs read *against* this claim — cite the router source

The schema description and <https://developer.konghq.com/gateway/entities/route/> both say `preserve_host` applies "When matching a Route via one of the hosts domain names," which implies it is a no-op when `hosts` is null and would falsify the evidence claim. **The implementation contradicts the docs** — it is unconditional in both routers:

```
kong/router/atc.lua:413          upstream_host = matched_route.preserve_host and req_host or nil
kong/router/atc.lua:493          if match_t.route.preserve_host then match_t.upstream_host = req_host end
kong/router/traditional.lua:1310 if matched_route.preserve_host then upstream_host = ctx.raw_req_host end
```

No check on *how* the route matched. So `hosts=null` + `preserve_host=true` **does** forward the raw client Host upstream, and the evidence claim is correct. Cite the router source alongside the doc page — the doc alone does not support the load-bearing corollary.

### Remediation

Leave `preserve_host` at its default `false` unless the upstream genuinely requires the original Host. If `preserve_host` must be true, constrain the route with an explicit non-wildcard `.hosts` allowlist (or an `http.host` expression) so the forwarded Host cannot be attacker-controlled.

Do **not** advise "set `.hosts` to explicit FQDNs rather than leaving it null" as blanket guidance — path-only routes are legitimate and do not need `hosts`.

### False positives and how to avoid them

The conjunction plus expression-awareness is the FP control; with both, risk drops from high to low. Severity **low** is defensible and not inflated: Kong itself is not compromised, and impact is entirely upstream-dependent — Host-header injection, cache poisoning, and reset-link poisoning only bite if the upstream trusts the Host header.

### Source

<https://developer.konghq.com/gateway/entities/route/> · `kong/db/schema/entities/routes.lua` · `kong/db/schema/typedefs.lua` · `kong/router/atc.lua` · `kong/router/traditional.lua`

---

## KONG.ROUTE.NO_REQUEST_SIZE_LIMIT

**Severity:** low · **Kinds:** route, service · **FP risk:** medium · **Confidence:** high

### Check

Resolve inheritance as in KONG.ROUTE.NO_AUTH_PLUGIN, **extended to consumer and consumer_group scope** — the plugin entity page documents 12 precedence levels including Consumer+Route+Service, ConsumerGroup+Service+Route, Consumer, and ConsumerGroup. A plugin scoped to a consumer or consumer group is otherwise missed and the route flagged wrongly.

**FAIL** for any route `R` where no enabled plugin with `name == 'request-size-limiting'` resolves via global, service, route, consumer, or consumer-group scope.

**Sub-checks removed from the original — do not implement them as findings:**

- ~~"`config.allowed_payload_size` left at the 128 default is weak"~~ — **info only, or drop.** No source characterizes 128 MB as insecure; the reference simply documents it as the default. This is an opinion, and it is the single most common configuration.
- ~~"`config.require_content_length == false` is weak"~~ — **technically wrong; demote to remediation advice.** `handler.lua` shows that when `require_content_length` is false the plugin **still enforces** `allowed_payload_size` by retrieving the raw body (or inspecting the buffered temp file) and checking its size, returning 413 (or 417 with `Expect: 100-continue`). `require_content_length=true` is defense-in-depth that rejects with 411 before the body is read. Since `false` is the **default**, this sub-check fires on ~100% of correctly-configured plugin instances — pure noise.
- ~~"on an internet-facing route"~~ — **not checkable; drop the qualifier.** A read-only Admin API client cannot determine network exposure. Route entities expose `hosts`/`paths`/`protocols`/`snis` only; none indicate internet reachability. Make it an operator-supplied input (a tag or allowlist) or omit it — never infer it.

Defaults confirmed: `allowed_payload_size = 128` (integer); `size_unit` default resolves to `"megabytes"` (`schema.lua` uses `default = size_units[1]`, and `handler.lua` defines `size_units = {"megabytes","kilobytes","bytes"}` — index 1 *is* megabytes, so the claim holds, though the schema line alone is misleading); `require_content_length = false`.

### Evidence claim

> Route 'reports-api' (id 8a3b...) resolves to no enabled request-size-limiting plugin at route, service, global, consumer, or consumer-group scope, so request bodies are effectively **unbounded** unless `nginx_http_client_max_body_size` has been explicitly set (its default, `0`, disables body-size checking entirely).

Two fixes here. "Bounded only by nginx-level defaults" implies a bound exists — `kong.conf.default` documents `nginx_http_client_max_body_size` default `= 0` and "Setting this value to 0 disables checking the request body size." And the original exemplar route was `'upload-api'` — the worst possible choice, since an upload endpoint is exactly where a high or absent limit is most likely intentional. Use a neutral route name.

### Remediation

Attach `request-size-limiting` at service or route scope with `config.allowed_payload_size` and `config.size_unit` set to the smallest workable value (default is 128 megabytes). Optionally set `config.require_content_length=true` to reject bodies lacking a valid `Content-Length` header before the body is read.

### False positives and how to avoid them

- **Suppression: nginx-layer control.** If `GET /` returns `.configuration.nginx_http_client_max_body_size != 0`, body size is already capped at the nginx layer and the plugin is largely redundant. Suppress or downgrade to info. This is checkable and is a real FP source.
- **Upload/media/backup APIs** that legitimately accept large or unbounded bodies.
- **Upstream CDN/ingress/LB** (Cloudflare, ALB, nginx-ingress) already capping body size before traffic reaches Kong — invisible to Kong's Admin API.
- **Custom/third-party or enterprise WAF plugins** enforcing an equivalent control; the rule matches `name == 'request-size-limiting'` exactly. Provide an operator-configurable equivalent-plugin allowlist.
- **gRPC/streaming routes** where body-size limiting is inapplicable or harmful (the plugin's default protocols include `grpc`/`grpcs`).

### Severity

**Low is correct and arguably generous — do not raise it.** This is DoS-resilience hardening, not a vulnerability, and it fires on the majority of routes in a typical deployment. It stays above `info` only because Kong's own docs state: "For security reasons, we suggest enabling this plugin for any Gateway Service you add to Kong Gateway to prevent a DOS (Denial of Service) attack," and because the nginx default genuinely leaves bodies unbounded.

### Source

<https://developer.konghq.com/plugins/request-size-limiting/reference/> · <https://developer.konghq.com/plugins/request-size-limiting/> (DoS rationale, min gateway version 1.0) · `kong/plugins/request-size-limiting/{schema,handler}.lua` · `kong.conf.default` · `kong/db/schema/entities/plugins.lua` · <https://developer.konghq.com/gateway/entities/plugin/>

> The Admin EE OpenAPI spec page 404'd, so `GET /plugins` pagination and response-envelope details were confirmed from the entity schema and secondary docs. Confidence: high on field names, medium on the exact envelope. Source fetches are Kong master as of 2026-07-17 — pin this rule to a tested gateway version range.

---

## KONG.PLUGIN.SECURITY_PLUGIN_DISABLED

**Severity:** medium (auth/acl tier) / low (availability tier) · **Kinds:** plugin · **FP risk:** medium · **Confidence:** medium

### Check

`GET /plugins`, following the `next`/`offset` cursor until exhausted. (`size=1000` is exactly `max_page_size`; it will not error, but a deployment with >1000 plugin instances silently truncates and the rule under-reports.)

**FAIL** for any `P` where `P.enabled == false` and `P.name` is in:

| Tier | Plugins | Severity |
|---|---|---|
| Access control | the AUTH set (see KONG.ROUTE.NO_AUTH_PLUGIN) + `acl` | medium |
| Availability | `rate-limiting`, `rate-limiting-advanced`, `request-size-limiting` | low |
| Network | `ip-restriction`, `bot-detection` | medium |

**`cors` must not be in this set — including it is fatal.** The Kong CORS plugin **relaxes** the browser same-origin policy to permit cross-origin requests; it does not restrict access. Per Kong's CORS overview, without CORS headers "a browser will stop requests from accessing URLs on different domains." Disabling `cors` makes the browser *more* restrictive. `cors` with `enabled=false` is a functionality break at worst, never a weakened security posture — flagging it inverts the security model and is a guaranteed false positive.

`enabled` is defined in `kong/db/schema/entities/plugins.lua` as `{ type = "boolean", required = true, default = true }`, described as "Whether the plugin is applied." A disabled plugin remains in the config and visible in Kong Manager but is never executed.

### Evidence claim — narrowed

> Plugin key-auth (id 6c4e...) scoped to service 'billing' has `enabled=false`, so this plugin instance is present in the config and visible in Kong Manager but is not executed by Kong.

The original — "the service is configured with an authentication plugin that Kong does not execute" — over-claims. Before asserting the *service* is unauthenticated, confirm no **other enabled instance of the same plugin name** covers the same traffic at another scope (global / service / route / consumer). Suppress the finding when one exists.

> **Low confidence:** forum reports disagree on whether a disabled narrow-scope instance suppresses a broader enabled instance or falls through to it. This could not be verified from Kong source, so the rule **must not depend on either behavior**. The presence-of-another-enabled-instance check is the safe formulation.

### Remediation

Either `PATCH` the plugin with `enabled=true` to restore enforcement, or `DELETE` it so the configuration does not misrepresent the security posture.

### False positives and how to avoid them

Pre-provisioning plugins with `enabled=false` via decK/GitOps and toggling them on later is a **legitimate, common pattern**. Consider demoting to low — or suppressing — when the disabled plugin is scoped to a service/route that has no other traffic-serving config. The tier split above matters too: the availability tier is a DoS concern, not an access-control gap.

### Source

Primary: <https://raw.githubusercontent.com/Kong/kong/master/kong/db/schema/entities/plugins.lua> — the authoritative definition of `enabled`, its default, and its meaning.

Secondary: <https://developer.konghq.com/gateway/entities/plugin/> — cite **only** for scope precedence. That page exists but does **not** document the `enabled` field, its default, or disabling behavior anywhere.

---

## KONG.CONSUMER.NO_CREDENTIALS

**Severity:** info · **Kinds:** consumer · **FP risk:** high · **Confidence:** medium

### Check

**Global gate — run this rule only when it can mean anything.** `GET /plugins`: if **any** `openid-connect`, `ldap-auth-advanced`, or other external-identity-mapping plugin exists anywhere in the config, **skip the rule entirely.**

Kong's documented external-identity-mapping pattern attaches **zero local credentials** to consumers. `openid-connect` maps IdP claims to consumers via `config.consumer_claims` (renamed from `config.consumer_claim` in Kong 3.14 — support both key names) resolved by `config.consumer_by` (default `["custom_id","username"]`), matching on username or custom_id alone. `ldap-auth-advanced` does the same ("Authentication of Consumers based on username or custom ID"). In any OIDC- or LDAP-backed deployment, **every** consumer legitimately has empty `.data` on all credential collections and the rule fires on 100% of them. This is **not exemptible per-consumer**: OIDC matches by IdP claim string, which the Admin API cannot enumerate, so a scanner cannot distinguish an intentionally credential-less OIDC-mapped consumer from a stale one.

Otherwise:

1. `GET /consumers?size=1000`, paginated. Each consumer has `.id`, `.username`, `.custom_id`, `.tags`.
2. For each consumer `C`, query each credential collection: `GET /consumers/{C.id}/key-auth`, `/basic-auth`, `/jwt`, `/hmac-auth`, `/oauth2`, `/acls`, `/mtls-auth`. (Endpoint naming verified: the first five are singular; `/acls` is plural and returns `{data, next, offset}`.)
3. **Predicate — 404 is not a value.** `mtls-auth` is Enterprise-only; on OSS the endpoint does not exist and returns **404, not empty `.data`**. Treat HTTP 404 (plugin not loaded / not in the `plugins` directive) as "no credentials of this type." **FAIL** only if every endpoint that returns 200 returns empty `.data` **and at least one returned 200.**

**Exemptions — all of these are legitimately credential-less:**

- Referenced as any plugin's `config.anonymous`. Match against **both `C.id` and `C.username`** — `config.anonymous` accepts either. An id-only match misses username-form references and false-positives on the anonymous consumer itself. Report under KONG.AUTH.ANONYMOUS_FALLBACK instead.
- Belongs to a consumer group (`GET /consumers/{id}/consumer_groups`), used for `rate-limiting-advanced` scoping.
- Targeted by any consumer-scoped plugin (`GET /plugins`, check `.consumer.id`) — e.g. per-consumer rate limiting.
- Relies on `credential_claim` pseudo-consumer mapping.

### Evidence claim

> Consumer 'legacy-partner' (id 2f6d...) returns 200-with-empty `.data` from `/key-auth`, `/basic-auth`, `/jwt`, `/hmac-auth`, `/oauth2`, `/acls` (`/mtls-auth` returned 404 — plugin not loaded), and is not referenced by any plugin's `config.anonymous` (by id or username), by any consumer-scoped plugin, or by any consumer group. No external-identity-mapping plugin (openid-connect, ldap-auth-advanced) is present in this config.

### Remediation

`DELETE` unused consumers, or attach the intended credential. **Rationale:** unreferenced, credential-less consumers are dead configuration that obscures access review. **No direct exposure.**

The original rationale was self-contradictory and must not be used: it claimed stale consumers "accumulate ACL group memberships and widen the identity surface," but the check requires `/acls` to be empty for the rule to fire, so a firing consumer has zero ACL groups by construction. It also called the consumer simultaneously unusable *and* an expanded identity surface — a consumer with no credentials cannot be authenticated against and is therefore unreachable, not an exposure.

### False positives and how to avoid them

The external-identity-mapping gate is the whole rule's viability. **Severity is `info`** precisely because even with the gate this is hygiene, not risk.

**Cost warning.** This is the most expensive rule in the pack: O(consumers × credential-types) requests. Rate-limit it or skip it on large installs.

### Source

<https://developer.konghq.com/gateway/entities/consumer/> — cite for **endpoint mechanics only** ("Credentials are necessary to authenticate Consumers via various authentication mechanisms"; "If you're using an authentication plugin, you'll need a Consumer with credentials"). It says **nothing** about unused or credential-less consumers, stale-consumer deletion, ACL accumulation, or any security risk, and does not mention ACLs in relation to consumers at all. **Do not cite it as supporting the finding — the hygiene claim has no vendor source.**

Also: <https://developer.konghq.com/plugins/mtls-auth/> (Enterprise tier) · <https://developer.konghq.com/plugins/acl/api/> · <https://developer.konghq.com/plugins/openid-connect/reference/> · <https://developer.konghq.com/how-to/configure-oidc-with-consumers/> · <https://developer.konghq.com/plugins/ldap-auth-advanced/>

> Medium confidence on the exact `ldap-auth-advanced` config key names (`consumer_by` / `consumer_optional` were not confirmed on the fetched page — the mapping *behavior* is confirmed, the key names are not). Verify against the plugin schema before encoding them.

---

## KONG.VERSION.CVE_2026_6338_SMUGGLING

**Severity:** medium · **Kinds:** broker · **FP risk:** medium · **Confidence:** high

### Check

`GET /` → require **`.edition == "enterprise"`** AND `.version` has exactly 4 numeric components. Otherwise **SKIP** — do not zero-pad, do not fire.

**The edition gate is mandatory, not a parenthetical.** The CVE is scoped to Kong Gateway **Enterprise** (per the NVD description; all CPE ranges are 4-part Enterprise versions). Kong OSS 3.4.x is a real, still-deployed LTS line reporting a 3-part version (`"3.4.3"`). A version parser that zero-pads 3-part to 4-part turns `3.4.3` into `3.4.3.0`, which falls inside the `3.4.0.0–3.4.3.26` range and fires wrongly on unaffected community nodes.

`kong/api/routes/kong.lua` confirms the root handler returns `tagline, version, edition, hostname, node_id, timers, plugins, lua_version, configuration, pids`, with `version = meta.version` and `edition = meta._VERSION:match("enterprise") and "enterprise" or "community"`. Note `.version` is the **clean numeric string** (`meta.version`), *not* the suffixed `meta._VERSION` — so the rule **cannot** detect Enterprise by string-matching "enterprise" inside `.version`. It must read `.edition`.

The gate is safe for 3.10–3.14: Kong OSS ends at 3.9.x (latest 3.9.3). From 3.10 onward there is no OSS distribution and no "free mode" — an unlicensed `kong/kong-gateway:3.10+` behaves as an expired-license Enterprise and still reports `edition="enterprise"`, which is correct here (it *is* affected Enterprise code). The only OSS/Enterprise overlap window is the 3.4 series, which the edition gate cleanly resolves.

**FAIL** if `.version` is below the fixed floor for its minor series. Express bounds **exclusive**, mirroring NVD's `versionEndExcluding`:

| Series | Vulnerable | Fixed floor |
|---|---|---|
| 3.4 | `< 3.4.3.27` | 3.4.3.27 |
| 3.10 | `< 3.10.0.12` | 3.10.0.12 |
| 3.11 | `< 3.11.0.12` | 3.11.0.12 |
| 3.12 | `< 3.12.0.7` | 3.12.0.7 |
| 3.13 | `< 3.13.0.5` | 3.13.0.5 |
| 3.14 | `< 3.14.0.4` | 3.14.0.4 |

(Semantically identical to inclusive `<= 3.4.3.26` etc., since the Enterprise patch component increments by whole integers — but the exclusive form removes off-by-one drift on future re-derivation.)

**Compare numerically per component, never lexicographically** — otherwise `"3.4.3.9" > "3.4.3.26"` and affected nodes are missed.

CVSS v4.0 base 4.9 (Medium), vector `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:N/E:P`; published 2026-06-11T14:16:32.553.

### Evidence claim

> Admin API `GET /` reports `.version='3.14.0.2'`, `.edition='enterprise'`, which falls below the CVE-2026-6338 fixed floor 3.14.0.4 for the 3.14 series (HTTP request smuggling / desynchronization when handling untrusted HTTP/1.1 traffic).

Recording `.edition` makes the finding self-justifying.

### Remediation

Upgrade to the fixed floor for your minor series: **3.4.3.27, 3.10.0.12, 3.11.0.12, 3.12.0.7, 3.13.0.5, 3.14.0.4** (or 3.15.0.0). Kong's changelog: "Fixed CVE-2026-6338 in core proxy request handling by preserving inbound Content-Length headers during hop-by-hop Connection header cleanup, preventing CL.0 request smuggling with crafted `Connection: Content-Length` headers on requests with a body."

Until patched, avoid terminating untrusted HTTP/1.1 traffic directly on the affected nodes.

### False positives and how to avoid them

Residual and unavoidable for version-only checks; acceptable at medium:

- **Vendor/backported rebuilds** carrying the fix while still reporting an affected version string.
- **Nodes that never terminate untrusted HTTP/1.1** (fronted by a header-normalizing LB) — technically true, not exploitable.

**Scope caveat (a false negative, not a false positive):** in hybrid mode, data planes do not expose the Admin API by default, so the scanner reads the *control plane's* version while the smuggling exposure is on the *data plane* proxy path. CP/DP versions are normally aligned by Kong's compatibility requirements, so this is acceptable — but the rule simply will not fire on Konnect-managed or admin-disabled data planes.

### Source

<https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-6338> — verified (`totalResults=1`).

> The NVD record lists <https://support.konghq.com/support/s/article/CVE-2026-6338> as a reference. That URL is legitimate and NVD-listed, but its content could **not** be read — it is a JS-rendered Salesforce page returning a loading error to fetchers and may be behind a support login. Keep the link; do not paraphrase content from it.

---

## KONG.VERSION.CVE_2021_27306_JWT_BYPASS

**Severity:** high · **Kinds:** broker, plugin · **FP risk:** medium · **Confidence:** high

### Check

`GET /` → read **both** `.version` and `.edition`. Branch the threshold — **do not cross-compare version schemes:**

| `.edition` | Fixed in | Compare as |
|---|---|---|
| `community` | **2.3.2** | 3-part |
| `enterprise` | **2.3.2.0** | 4-part |

**FAIL** if the version is below the edition-appropriate floor **AND** `GET /plugins` (paginated) contains at least one plugin with `name == 'jwt'` and `enabled == true`.

**Explicitly assert that OSS `2.3.2` does not fire.** Naive comparators treat `2.3.2 < 2.3.2.0` as true and fire on the exact version that carries the fix — a false positive on a freshly patched node.

**Why the branch.** NVD's only CPE for CVE-2021-27306 is `cpe:2.3:a:konghq:kong_gateway:*:*:*:*:enterprise:*:*:*` with `versionEndExcluding` `"2.3.2.0"` — enterprise-scoped, and `2.3.2.0` is a 4-part Kong Enterprise version (`{MAJOR}.{MINOR}.{PATCH}.{ENTERPRISE_PATCH}`). Comparing OSS 3-part versions against a 4-part Enterprise threshold is a category error. **But OSS is genuinely affected:** Kong/kong PR #6821 ("always normalizing the incoming request's URI before matching against the Router") landed in OSS 2.3.2 (2021/02/09) per `CHANGELOG-OLD.md` — same defect, and Enterprise 2.3.2.0 is built on OSS 2.3.2. The rule is right, but must branch on edition to be right for the right reason.

`edition` is derived in `kong/api/routes/kong.lua` as `meta._VERSION:match("enterprise") and "enterprise" or "community"`.

**Pagination and workspaces.** `GET /plugins?size=1000` is exactly the API cap (`kong/api/endpoints.lua`: default 100, `max_page_size` 1000); requests above 1000 are rejected. Follow the `next`/`offset` cursor for fleets above 1000 plugin instances, else false negative. On Enterprise, `/plugins` is **workspace-scoped** — enumerate workspaces or the check misses jwt plugins outside the default workspace.

CVSS v3.1 7.5 HIGH, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — `high` is the CVE's own rating and is defensible.

### Evidence claim — "potentially vulnerable"

> Admin API `GET /` reports `.version='2.2.1'`, `.edition='community'`, and `/plugins` contains an enabled jwt plugin (id b71a...). This is **potentially vulnerable** to CVE-2021-27306 (JWT plugin improper access control allowing access to authenticated routes without a valid token), fixed in OSS 2.3.2 / Enterprise 2.3.2.0. **Unverified preconditions:** exploitation additionally requires (a) at least one *unauthenticated* route and (b) a path-normalizing intermediary (nginx / LB) between Kong and the upstream that collapses `/public/../api/v1/...`. This rule checks neither.

State those as unverified preconditions rather than asserting a live bypass.

### Remediation

Upgrade Kong Gateway to 2.3.2 (OSS) / 2.3.2.0 (Enterprise) or later. Kong 2.x is long past its maintenance window as of 2026 — Kong 2.8 LTS ended 2025-03-01, and supported lines as of 2026-07 are 3.9 (latest 3.9.3, 2026-06-17) and 3.4 LTS (ends 2026-08-09). Plan an upgrade to a supported 3.x release rather than a point patch.

### False positives and how to avoid them

- The **unverified preconditions** above are the main triage lever.
- **CPE-attribution dispute:** NVD's CPE covers enterprise only, so a strict CPE-matching auditor will dispute an OSS attribution. For community-edition findings, cite the OSS changelog / PR #6821 as primary and note the CPE gap in the finding.

### Source

Cite the deterministic record: <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-27306>.

Do **not** cite `?keywordSearch=kong+gateway` — it resolves (valid JSON, `totalResults=4`, includes CVE-2021-27306) but is non-deterministic. For OSS attribution, cite Kong/kong PR #6821 and `CHANGELOG-OLD.md`.

---

## Implementation notes

### Collection the connector must perform

| Step | Request | Notes |
|---|---|---|
| 1 | `GET /` | Once per node. Yields `.version`, `.edition`, `.configuration.{admin_listen, proxy_listen, enforce_rbac, rbac_auth_header, database, role, trusted_ips, nginx_http_client_max_body_size}`. Feeds every config and version rule, plus the severity gates and suppressions of half the entity rules. |
| 2 | `GET /` **unauthenticated** | Separate probe for KONG.ADMIN.UNAUTHENTICATED. Record the probe origin (on-host vs off-host). |
| 3 | `GET /rbac/users` **unauthenticated** | Enterprise RBAC probe. 404 ⇒ OSS ⇒ N/A. Do not OR with step 2. |
| 4 | `GET /plugins` | **Fully paginated.** The single most important collection — five rules depend on complete plugin inventory. Enterprise: repeat **per workspace**. |
| 5 | `GET /routes` | Fully paginated. Need `.id`, `.service`, `.protocols`, `.hosts`, `.preserve_host`, `.expression`, `.https_redirect_status_code`. |
| 6 | `GET /services` | Fully paginated. For naming in evidence strings and service-scope resolution. |
| 7 | `GET /consumers` | Fully paginated. Required to resolve `config.anonymous` by id **or** username. |
| 8 | `GET /consumers/{id}/{key-auth,basic-auth,jwt,hmac-auth,oauth2,acls,mtls-auth}` + `/consumer_groups` | **Only for KONG.CONSUMER.NO_CREDENTIALS.** O(consumers × types). Skip on large installs. Skip entirely when an external-identity-mapping plugin exists. |

### Pagination — the silent under-report

Every collection endpoint returns `{data: [...], next: ..., offset: ...}`. Defaults: `page_size = 100`, `max_page_size = 1000` (`kong/api/endpoints.lua`). `size=1000` is **the cap, not "all"**; values above 1000 are rejected with `INVALID_SIZE` / 400. **Always follow `next`/`offset` to exhaustion.** A detector reading only the first page silently under-reports on any real deployment — and for the "absence of a protective plugin" rules, a truncated plugin list produces **false FAILs**, not false PASSes.

### The plugin scope resolver (shared by 5 rules)

Build this once. `GET /routes/{id}/plugins` is a trap — it returns only route-scoped plugins and omits inherited service and global scopes.

Scope is encoded as nullable object references on each plugin. Given plugin `P` and route `R`:

```
global      : P.route == null AND P.service == null
route-scoped: P.route != null AND P.route.id == R.id
              (a route+service-scoped plugin applies only to that route;
               matching on P.route.id is sufficient — do NOT also require P.service == null)
svc-scoped  : P.route == null AND P.service != null
              AND R.service != null AND P.service.id == R.service.id
              (the P.route == null term is load-bearing: without it, a route+service
               scoped plugin on route A is wrongly credited to route B of the same service)
```

Plus, for the rate-limiting and request-size rules, consumer and consumer_group scopes (`P.consumer != null` / `P.consumer_group != null` with `service`/`route` null).

Two gotchas fold into every rule using this resolver:

1. **`P.enabled == false`** means the plugin is in the config and visible in Kong Manager but **never executes**.
2. **Every plugin has its own `protocols` array.** A plugin whose protocols do not intersect the route's will not run — an auth plugin with `protocols=["grpc","grpcs"]` leaves an http route wide open. Omitting the intersection causes false **PASSes**.

Kong's documented precedence (most-specific wins: consumer+route+service > … > route > service > global) governs *which* of several matching instances runs. For a boolean "is any X in effect" check, existence of any one matching instance is enough — precedence matters only if you also want to report *which* config applies.

### Edition and mode gating

Several rules produce pure noise if run against the wrong node. Read these from `GET /` once and gate on them:

| Signal | Field | Gates |
|---|---|---|
| Enterprise | `.edition == "enterprise"` | RBAC.DISABLED, both CVE rules, and any rule touching `/rbac/users`, `rate-limiting-advanced`, `ldap-auth-advanced`, `ws`/`wss` protocols |
| DB-less | `.configuration.database == "off"` | Skip RBAC.DISABLED (RBAC needs a DB); note `policy='cluster'` is unavailable |
| Hybrid data plane | `.configuration.role == "data_plane"` | Skip RBAC.DISABLED; DPs usually have no Admin API at all |
| Konnect-managed | (out-of-band) | Skip RBAC.DISABLED and ADMIN.UNAUTHENTICATED — different auth model |

### Version comparison

Kong uses **3-part versions for community** and **4-part for Enterprise** (`{MAJOR}.{MINOR}.{PATCH}.{ENTERPRISE_PATCH}`). `.version` is the clean numeric string; the "enterprise" marker lives only in `meta._VERSION` and is exposed as `.edition`. Two hard rules:

- **Never zero-pad a 3-part version to compare against a 4-part threshold.** It silently converts OSS nodes into Enterprise CVE hits.
- **Compare numerically per component.** Lexicographic compare makes `"3.4.3.9" > "3.4.3.26"` and misses affected nodes.

### CVE enrichment

Pin to the **NVD API by CVE ID** (`?cveId=...`), never `?keywordSearch=`, and never web search. See the fabricated-CVE note in the intro — a search-driven pipeline will ingest CVE-2026-29413/29414, which do not exist. Kong's CVE coverage in NVD is thin because most fixes ship through the changelog and support portal without CVE assignment: **version rules are a floor, not a complete picture.**

### Not included (deliberately)

- **Kong Manager auth (`admin_gui_auth`, `admin_gui_session_conf`).** Requested, but these parameters could not be located in the current configuration reference (docs migrated `docs.konghq.com` → `developer.konghq.com` and the config page truncates). **Do not synthesize this rule without verifying the parameter names against a live node.**
- **CVE-2020-11710** (docker-kong Admin API reachable on non-127.0.0.1 interfaces, CVSS 9.8) — not issued as its own rule. The vendor disputes the classification, and it is a docker-kong packaging default rather than a Kong Gateway code defect. It is corroborating context for KONG.ADMIN.LISTEN_WILDCARD only.
- **CVE-2021-32753** (EdgeX Foundry OAuth2) — an EdgeX integration flaw, not Kong Gateway.
- **`KONG.ADMIN.OFF_HOST_LISTENER`** — recommended but not yet written. It would fire on any non-loopback `admin_listen` entry regardless of `ssl`, closing the gap where KONG.ADMIN.PLAINTEXT_LISTENER passes `0.0.0.0:8444 http2 ssl` (an Admin API exposed to the whole network, merely encrypted — the higher-value finding per Kong's own guidance).

### Doc-source caveat

As of 2026-07, `docs.konghq.com/gateway/latest/*` 301-redirects to `developer.konghq.com`; many legacy URLs in circulation are stale. The Admin API OpenAPI spec at `developer.konghq.com/api/gateway/admin-ee/` **404s**. The fullest field-level Admin API reference retrievable is the archived 2.0.x page (`legacy-gateway--kongdocs.netlify.app`), authoritative for response **shape** (`GET /` returning `hostname`/`node_id`/`lua_version`/`version`/`tagline`/`configuration`/`plugins.available_on_server`/`plugins.enabled_in_cluster`; `GET /status` returning `database.reachable`/`memory`/`server`) but five major versions old. **Verify field-level details against a live 3.x node before shipping detectors.** All Kong source references above are the master branch as of 2026-07-17.
