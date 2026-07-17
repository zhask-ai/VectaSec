# RABBITMQ Rulepack

Status: verified. Every rule below survived adversarial verification; verifier corrections are already applied to the checks, evidence strings, severities and remediation text. Where a correction changed a rule materially, the change is called out inline under **Verifier corrections applied** so the reasoning is not lost.

As of 2026-07-17. Source-of-truth reads were done against `rabbitmq-server` branch `main` (4.3-era) unless a tag is named.

## What this system exposes read-only

The scanner's boundary is the **Management HTTP API** (`rabbitmq_management` plugin, default `15672` plaintext / `15671` TLS), accessed with HTTP Basic auth over `GET` only. Everything in this pack is evaluable from that surface, plus one unauthenticated probe (`GET /api/auth`) and one remote-origin credential probe (`GET /api/whoami`).

Four schema facts drive almost every rule and are the most common source of silently-dead detectors:

1. **`listeners` vs `contexts`.** `GET /api/overview` → `listeners` carries **only non-HTTP** listeners (`amqp`, `amqp/ssl`, `clustering`, `clustering/ssl`, `mqtt`, `stomp`, `stream`…). The management UI/HTTP API is **not** in `listeners` — it is in `GET /api/overview` → `contexts`. A rule keyed on the wrong array never fires.
2. **Listener object shape** (`rabbit_mgmt_format:listener/1`): `{node, protocol, ip_address, port, socket_opts, tls}`. `tls` is computed by `has_tls_enabled/2`, which hardcodes `'clustering/ssl' -> true` and `clustering -> false`, and otherwise returns true iff `socket_opts` contains any of `ssl_opts`/`cacertfile`/`certfile`/`keyfile`. The `tls` boolean is confirmed on `main`; the release that introduced it is unconfirmed, so detectors must fall back to "protocol ends in `/ssl`" on older brokers.
3. **Context object shape** (`rabbit_mgmt_format:web_context/1`): always prepends `{ssl_opts, ...}` defaulting to `[]`, so `ssl_opts` is **always present** on a returned context. `{ssl, true}` is emitted only by `get_tls_listener/0`. Companion keys (`description`, `path`, `port`, `node`) are inferred from `rabbit_mgmt_wm_overview:fmt_context/2` and its sort keys — field shape confidence is medium, posture confidence is high.
4. **Authorization gates the payload, not just the request.** `rabbit_mgmt_wm_overview.erl` emits `listeners` and `contexts` **only** when `rabbit_mgmt_util:is_monitor(Tags)` is true (`administrator` or `monitoring`). `management`-tagged credentials get an overview with those keys **absent**, and `management.disable_stats = true` removes them entirely. `/api/users` and `/api/permissions` are `administrator`-only (`is_authorized_admin`). **A missing key or a 401/403 must map to NOT-ASSESSABLE, never to PASS.** Fail-open here is the single largest correctness risk in this pack.

### Not reachable from this surface

- `loopback_users` — no HTTP projection. Detected only behaviourally via the remote `guest:guest` probe, which requires the scanner to originate from a **non-loopback** address.
- `anonymous_login_user` / `anonymous_login_pass` — no HTTP projection. (`auth_mechanisms` **is** projected — see `RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED`.)
- Erlang cookie value and file mode — never exposed by any endpoint.
- epmd (4369) — a separate OS daemon, not a RabbitMQ listener; it never appears in `listeners`. Folded into `RABBITMQ.CLUSTER.DIST_PORT_EXPOSED` remediation rather than given a rule, because a real check needs a port scan.

### Required scanner privilege

| Endpoint | Minimum tag |
|---|---|
| `GET /api/auth` | none (that is the bug) |
| `GET /api/whoami` | any authenticated user |
| `GET /api/overview` (scalar fields) | `management` |
| `GET /api/overview` → `listeners`, `contexts` | `monitoring` or `administrator` |
| `GET /api/nodes` | `monitoring` or `administrator` |
| `GET /api/users`, `GET /api/permissions` | `administrator` only |
| `GET /api/vhosts` | `monitoring` or `administrator` |

RabbitMQ has **no read-only-administrator tag**. Rules touching `/api/users` or `/api/permissions` require an `administrator`-tagged credential that is inherently write-capable and self-restricted to GETs. State this in the connector's onboarding.

---

## RABBITMQ.CVE.OAUTH_SECRET_DISCLOSURE

Obsolete `GET /api/auth` endpoint discloses OAuth 2 client secret to unauthenticated callers (CVE-2026-57219)

- **Severity:** high
- **Kinds:** `broker`, `mcp_server`, `service`
- **Confidence:** high
- **False-positive risk:** low

### Check

1. Issue `GET /api/auth` with **no** `Authorization` header.
2. **Fail** if `status == 200` AND the JSON body contains top-level key `oauth_client_secret` with a non-empty string value.
3. `status == 404` → patched or endpoint not present → **pass**.

`filter_empty_properties/1` omits the key entirely when unset, so *"key present with a non-empty string"* is exactly the right predicate. Firing solely on `200` + non-empty top-level `oauth_client_secret` is the rule's strongest property — do not add conditions to it.

**Corroborating fields (informational only — never require them):** top-level keys are `oauth_enabled`, `oauth_resource_servers`, `oauth_disable_basic_auth`, `oauth_client_id`, `oauth_client_secret`, `oauth_scopes`, `oauth_initiated_logon_type` (plus `oauth_authorization_endpoint_params` / `oauth_token_endpoint_params` on 4.1.x). Verified in `rabbit_mgmt_wm_auth.erl` on both v3.13.x and v4.1.x.

**`oauth_provider_url` is NOT a top-level key.** It is nested inside `oauth_resource_servers[*]` entries. The shipped API reference (`priv/www/api/index.html`) still documents the old flat shape `{"oauth_enabled","oauth_client_id","oauth_provider_url"}` and is stale. Requiring top-level `oauth_provider_url` will false-negative on all 4.x.

**Version correlation is advisory, not a gate.** Optionally read `GET /api/overview` → `rabbitmq_version`. The endpoint exists in `>= 3.13.0` and is removed in 4.3.0 / 4.2.6 / 4.1.11 / 4.0.20 / 3.13.15. Affected ranges per GHSA-pj24-8j6m-vq9q: `>=4.2.0 <4.2.6`, `>=4.1.0 <4.1.11`, `>=4.0.0 <4.0.20`, `>=3.13.0 <3.13.15` (no 4.3.x row; PR #16083 merged 2026-04-14, 4.3.0 released 2026-04-23 with release-note text "The deprecated, unused GET /api/auth endpoint was removed"). **Do not suppress the finding** if `/api/overview` is unreachable, needs creds the scanner lacks, or reports a vendor-mangled version (Broadcom/Tanzu, Bitnami, distro backports) — a direct 200 + non-empty secret is dispositive on its own. A distro-backported fix returns 404 and correctly does not fire.

### Evidence claim

> Unauthenticated `GET /api/auth` returned HTTP 200 with a non-empty `oauth_client_secret` field; broker reports `rabbitmq_version=<version>`, which is below the patched release for its series (4.3.0 / 4.2.6 / 4.1.11 / 4.0.20 / 3.13.15) — CVE-2026-57219 (CVSS 8.7).

Omit the version clause when `/api/overview` was not readable; the 200 stands alone.

### Remediation

Upgrade to 4.3.0, 4.2.6, 4.1.11, 4.0.20 or 3.13.15+, which remove the `/api/auth` endpoint. If immediate patching is impossible: rotate the leaked `management.oauth_client_secret` at the identity provider, switch to an OAuth 2 grant type that does not require a client secret, restrict network access to port 15672, or disable the management/OAuth 2 plugins.

**Ordering trap — patching does not undo disclosure.** If the endpoint was ever reachable while a client secret was configured, assume the secret is compromised and rotate it at the IdP **regardless of current patch status**.

### False-positive risk and how to avoid it

Low. Two low-frequency scenarios fire legitimately: a placeholder/dummy `management.oauth_client_secret` in a dev/test environment, and a secret configured but unused by the active grant type. Both are still worth reporting — the value is genuinely served to unauthenticated callers. Prevalence is low because RabbitMQ's recommended management-UI config is a PKCE public client with no secret.

### Verifier corrections applied

- **Severity critical → high.** Vendor/GHSA CVSS 4.0 base is 8.7 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`). In CVSS 4.0, Critical is 9.0–10.0 and High is 7.0–8.9. `AT:P` and `UI:A` reflect that the secret → admin-token → takeover chain is conditional on the deployment actually using a confidential client.
- Removed `oauth_provider_url` from the top-level corroborating-field list.
- Version gating demoted from gate to advisory.

### Source

- https://thehackernews.com/2026/07/rabbitmq-flaws-could-leak-oauth-secrets.html (secondary; confirm against GHSA-pj24-8j6m-vq9q before shipping)
- `deps/rabbitmq_management/src/rabbit_mgmt_wm_auth.erl`

### Scope note

Per PR #16083, `bootstrap.js` still carries credential information and "cannot be protected". That is a separate surface, outside this rule — not a reason to widen the check.

---

## RABBITMQ.USER.GUEST_REMOTE_LOGIN

Default `guest`/`guest` account authenticates from a remote host

- **Severity:** critical
- **Kinds:** `broker`, `user`
- **Confidence:** high
- **False-positive risk:** medium

### Check

From a **non-loopback source address**, issue `GET /api/whoami` with HTTP Basic credentials `guest:guest`.

- **Fail** if `status == 200` AND body `name == "guest"`.
- `401` with body reason `"User can only log in via localhost"` → loopback restriction intact → report `RABBITMQ.USER.DEFAULT_GUEST_PRESENT` instead, not this rule.
- Plain `401` with reason `"Not_Authorized"` → guest password is not the default → pass.

**Match on the `reason` string, not the `error` atom.** Both 401 bodies are verified verbatim in source and the atoms differ only by s/z, which is trivially transposed:

| Condition | Body |
|---|---|
| Loopback-blocked | `{"error":"not_authorised","reason":"User can only log in via localhost"}` (British `not_authorised`, from `not_authorised/3` → `halt_response(401, not_authorised, ...)`) |
| Bad password | `{"error":"not_authorized","reason":"Not_Authorized"}` (American `not_authorized`, from `not_authenticated/4` → `halt_response(401, not_authorized, ...)`) |

**Known false negative — handle it.** A 401 with reason `"Not management user"` means guest exists **with the default password AND the loopback restriction already bypassed**, but guest lacks a management tag. This rule misses it, because `is_mgmt_user` is checked *after* `check_user_loopback` in `rabbit_web_dispatch_access_control.erl:155-177`. Emit a distinct finding for this response rather than a pass.

**Origin requirement:** running this probe from the broker host itself produces a false negative. The scanner must originate from a non-loopback address.

### Evidence claim

> `GET /api/whoami` from remote source `<scanner_ip>` with Basic auth `guest:guest` returned HTTP 200 and `{"name":"guest","tags":<observed_tags>}` — the default account with default credentials is reachable and management-authorized from this source address. Root cause is either `loopback_users` relaxation or a loopback-appearing proxy hop in front of the management listener; confirm which before applying remediation.

Echo the observed `tags` array verbatim — do **not** hardcode `["administrator"]`. `rabbit_mgmt_format:user/1` returns `[{name,...},{tags, tags_as_binaries(...)},{is_internal_user,...}]`; guest may legitimately carry a non-administrator management tag. Capture `is_internal_user` in evidence too. Raise/lower confidence on whether `administrator` is present.

### Remediation

Restore the default by setting **`loopback_users.guest = true`** in `rabbitmq.conf` (this is the shipped default; see `deps/rabbit/docs/rabbitmq.conf.example`). Preferably delete the `guest` user entirely and create per-application users with generated credentials. Never set `loopback_users = none` on an internet- or LAN-reachable node.

> **Do not write `loopback_users = guest`.** It is invalid `rabbitmq.conf` syntax and fails cuttlefish validation — the node refuses to boot. Per `deps/rabbit/priv/schema/rabbit.schema`, the bare key is `{mapping, "loopback_users", "rabbit.loopback_users", [{datatype, {enum, [none]}}]}` — it accepts **only** the literal `none`. The per-user form is `{mapping, "loopback_users.$user", ..., [{datatype, atom}]}`, and the translation keeps only users whose value is `true`.

### False-positive risk and how to avoid it

Medium, and the cause is architectural, not a matching defect. The management listener has **no `proxy_protocol` support** (zero `proxy` matches in `deps/rabbitmq_management/priv/schema/rabbitmq_management.schema`), so `rabbit_web_dispatch_access_control.erl:142` `{IP, _} = cowboy_req:peer(ReqData)` always yields the real TCP peer. A reverse proxy (nginx/HAProxy/Traefik) **co-located on the RabbitMQ host** therefore presents `127.0.0.1` as the peer, and guest authenticates for remote clients with `loopback_users` fully intact. The observation (remote client got a 200) is real and still worth a critical finding, but the remediation branches on which root cause applies — hence the evidence wording above states only what was observed.

### Verifier corrections applied

- Fixed the fatal `loopback_users = guest` config-key error in remediation (would have broken any broker that followed it).
- Evidence no longer asserts `loopback_users` was relaxed — that is not established by the observation.
- Evidence no longer hardcodes `tags:["administrator"]`.
- Added the reason-string discrimination table and the `"Not management user"` false-negative case.

### Source

- https://www.rabbitmq.com/docs/access-control
- `deps/rabbitmq_web_dispatch/src/rabbit_web_dispatch_access_control.erl`
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl` (`user/1`)

Verified against `rabbitmq-server` main (2026 copyright headers) on 2026-07-17. **Related but not applicable:** CVE-2026-57216 (published 2026-06-24, CVSS 6.8; affects 3.13.0–<3.13.15 / 4.0.0–<4.0.20 / 4.1.0–<4.1.11 / 4.2.0–<4.2.6) is a sockname-vs-peer loopback bypass via PROXY protocol affecting AMQP 0-9-1, AMQP 1.0 and Stream. The advisory states the management HTTP API is **not** affected, so it does not undermine this HTTP-based check.

---

## RABBITMQ.USER.DEFAULT_GUEST_PRESENT

Default `guest` user still exists in the internal user store

- **Severity:** medium (escalates to critical only on a discriminating signal — see below)
- **Kinds:** `user`, `broker`
- **Confidence:** high
- **False-positive risk:** medium

### Check

**Requires an `administrator`-tagged credential.** `/api/users` is administrator-only. Map 401/403 to **NOT-ASSESSABLE**, never to PASS.

1. `GET /api/users`.
2. **Fail (medium)** if any array element has `name == "guest"`.
3. **Escalate to critical** only on a discriminating signal:
   - (a) guest still has the well-known password (verify offline — see below), **or**
   - (b) the loopback restriction is known to be lifted (i.e. `RABBITMQ.USER.GUEST_REMOTE_LOGIN` fired).

**Do not escalate on the `administrator` tag.** `administrator` *is* guest's default tag, so that conditional fires on essentially every hit — it is "critical whenever guest exists" wearing a conditional. Keep the tag as evidence only.

**Offline default-password verification (the real critical discriminator).** `/api/users` returns `password_hash` and `hashing_algorithm`. The construction is documented: random 32-bit salt, `salt + UTF-8 password`, hash (SHA-256 default), prepend salt to the digest, base64. The salt is recoverable from the stored hash, so a read-only client can verify the candidate password `"guest"` offline and **prove** default credentials rather than asserting them. **Honour the reported `hashing_algorithm`** (sha512 and plugin modules are configurable) — do not assume sha256.

**`tags` normalisation (verified, keep):** JSON array in RabbitMQ 3.9+, comma-separated string in older releases. Normalise before matching. Per the 3.9.0 release notes, Compatibility Notes: user tags are now exported as a list rather than a comma-separated list, and HTTP API clients need to support both types.

### Evidence claim

Presence only (medium):

> `GET /api/users` returned an element with `name="guest"`, `tags=["administrator"]`, `hashing_algorithm="rabbit_password_hashing_sha256"` — the well-known default account has not been deleted from the internal user store.

Default credentials proven (critical):

> …and offline verification of `password_hash` against `hashing_algorithm` confirms the password is still the default `guest`.

Claim default credentials **only** when the hash check verifies. Name/tags alone establish presence, not well-known credentials.

### Remediation

Per the production checklist: *"For production environments, delete the default user (guest)."* Create a separate user per application with generated credentials and scoped vhost permissions before deleting guest. Note that `anonymous_login_user` also defaults to `guest`, so deleting guest additionally neutralises the ANONYMOUS mechanism's default identity (verified: `anonymous_login_user` and `anonymous_login_pass` "are set to guest by default").

### False-positive risk and how to avoid it

The literal `name == "guest"` match is deterministic and low-FP; **the FP risk lives entirely in the severity mapping.**

- A legitimately repurposed `guest` with a generated password and scoped permissions fires at critical wrongly → resolved by the offline hash check.
- Dev/CI/Docker environments always ship guest (the official image creates it). If scanner scope is not production-only this is high-volume noise → gate on environment scope.

### Scope caveat

`/api/users` lists **only the internal data store**. Brokers fronted by LDAP/OAuth backends may legitimately return no guest while still having one internally, and vice versa. Keep "internal user store" precision in the output text, not just the title.

### Verifier corrections applied

- Removed the non-discriminating `administrator`-tag → critical escalation; base severity is medium (default config restricts guest to loopback, so mere presence is not remotely reachable on a default broker).
- Added the offline hash verification as the real critical discriminator.
- Softened the evidence claim to presence-only unless the hash verifies.
- Documented the administrator-tag requirement and 401/403 → NOT-ASSESSABLE (fail-open defect).

### Source

- https://www.rabbitmq.com/docs/production-checklist
- https://www.rabbitmq.com/docs/passwords (hash construction)
- https://www.rabbitmq.com/docs/access-control (`loopback_users` includes `guest` by default; `anonymous_login_user` default)
- https://www.rabbitmq.com/docs/management (administrator-tag requirement)
- https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.9.0 (tags array change)

---

## RABBITMQ.MGMT.HTTP_API_NO_TLS

Management UI / HTTP API served over plaintext HTTP

- **Severity:** high (only after FP suppression — see below)
- **Kinds:** `broker`, `route`, `service`
- **Confidence:** medium on field shape, high on the underlying posture issue
- **False-positive risk:** medium

### Check

`GET /api/overview` → **`contexts`** array. The management listener appears here, **not** in `listeners`.

1. If `contexts` is **missing or empty** → emit NOT-APPLICABLE / INSUFFICIENT-PERMISSION. **Never a finding.** `rabbit_mgmt_wm_overview.erl:65-73` only emits `{contexts, web_contexts(ReqData)}` when `rabbit_mgmt_util:is_monitor(Tags)` is true (`is_monitor(T) -> intersects(T, [administrator, monitoring])`, `rabbit_web_dispatch_access_control.erl:255`). A `management`-only scanner user, or `management.disable_stats = true`, yields no contexts at all.
2. Iterate **all** elements whose `description == "RabbitMQ Management"`. `rabbit_mgmt_app.erl:157-172` registers **both** `?TCP_CONTEXT` and `?TLS_CONTEXT` with that identical literal description, and `get_listeners_config/0` explicitly supports running TCP+TLS simultaneously. Singular lookup is wrong.
3. For each matching context, TLS is present iff `ssl == true` (**primary signal** — `get_tls_listener/0` emits `{ssl, true}`; `get_tcp_listener/0` emits neither) with non-empty `ssl_opts` as **corroboration**.
4. **Fail** if a matching context has `ssl_opts == []` or `{}` (no certfile/keyfile/cacertfile) and no `ssl: true` — i.e. a plain `management.tcp.port` listener (default 15672) rather than `management.ssl.port` (default 15671).
5. **Downgrade to medium/low** ("plaintext listener alongside HTTPS") if *any* matching context has `ssl: true` / non-empty `ssl_opts`.
6. **Downgrade to low/info** if the context's `ip` field is `127.0.0.1` or `::1` — the listener is loopback-only and unreachable off-host. (`ip` is present only when `management.tcp.ip` is explicitly set.)

**Never fail on `ssl_opts` being absent.** `rabbit_mgmt_format:web_context/1` (`deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl:289-298`) does `SslOpts0 = pget(ssl_opts, Props0, [])` then prepends `{ssl_opts, format_socket_opts(SslOpts1)}`, so `ssl_opts` is **always present** on any returned context. If it is absent, the cause is that the whole `contexts` key is missing — case 1, not a finding.

### Evidence claim

> `GET /api/overview` `contexts[]` contains `{"node":"rabbit@<host>","description":"RabbitMQ Management","path":"/","port":15672,"ssl_opts":[]}` — the management UI and HTTP API, including HTTP Basic credentials, are served without TLS.

### Remediation

Configure an HTTPS listener: `management.ssl.port = 15671` plus `management.ssl.cacertfile` / `management.ssl.certfile` / `management.ssl.keyfile` in `rabbitmq.conf`, and remove the plaintext `management.tcp.port` listener (or bind it to loopback only). The HTTP API authenticates with HTTP Basic, so plaintext transport exposes base64 credentials on the wire.

### False-positive risk and how to avoid it

Medium — this is the reason for corrections 2, 3 and the mandatory suppression. **The dominant legitimate config is TLS terminated at a reverse proxy / K8s ingress / service mesh with a plaintext `localhost:15672` upstream.** The RabbitMQ docs themselves endorse this ("It is possible to make the web UI available via any proxy that conforms with RFC 1738") and ship Nginx/Apache examples; it is the standard Kubernetes pattern. In that deployment `ssl_opts` is legitimately `[]` and the rule fires wrongly.

**Mandatory suppression:** if the scanner's **own** connection to `/api/overview` was made over `https://` with a valid certificate, TLS is being terminated upstream — suppress or downgrade to info, since the rule cannot see the proxy. Also expose "proxy terminates TLS" as an explicit per-target config toggle.

Firing flat-high on `ssl_opts == []` with no reachability test is noisy. `high` is defensible for the true positive only after the above suppression.

### Verifier corrections applied

- Removed "absent" as a fail condition (correctness defect — absent means no permission, not no TLS).
- Iterate all matching contexts; both TCP and TLS contexts share the literal description.
- `ssl` boolean promoted to primary signal; `ip` field added as a loopback downgrade.
- Fixed the source citation — the cited docs page supports the remediation only, not the evidence.

### Source

Remediation (documented): https://www.rabbitmq.com/docs/management — supports `management.ssl.port` default 15671, `management.ssl.cacertfile/certfile/keyfile`, `management.tcp.port` default 15672, HTTP Basic auth, `management.disable_basic_auth`. It does **not** document `/api/overview`, `contexts` or `ssl_opts` anywhere.

Check (source-verified):
- `deps/rabbitmq_management/src/rabbit_mgmt_wm_overview.erl` — `contexts` key and its `is_monitor` gate
- `deps/rabbitmq_management/src/rabbit_mgmt_app.erl` — description literal, default ports 15672/15671
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_external_stats.erl:337-340` — `path = "/" ++ Path`
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl:289-298` — `ssl_opts` always emitted

Confidence in ports/keys/field names: high (read from source). Confidence that field shapes are identical on 3.13 / 4.0–4.3 tags: **medium — verified on `main` only.**

---

## RABBITMQ.LISTENER.AMQP_PLAINTEXT

AMQP listener accepts plaintext connections on a non-loopback interface

- **Severity:** medium
- **Kinds:** `broker`, `route`
- **Confidence:** high
- **False-positive risk:** medium

### Check

`GET /api/overview` → `listeners` array.

1. If the `listeners` key is **missing** → emit UNABLE-TO-EVALUATE, **not pass**. Two silent false-pass paths are confirmed in source: (a) `rabbit_mgmt_wm_overview.erl:65-77` only appends `{listeners, listeners()}` when `rabbit_mgmt_util:is_monitor(Tags)` is true (`[administrator, monitoring]`, `rabbit_web_dispatch_access_control.erl:255`) — a `management`-tagged credential silently gets no `listeners` key; (b) when `disable_stats` is true, the response is built without `listeners` entirely. Required scanner tag: `monitoring` (read-only) or `administrator`.
2. **Fail** on any element where `protocol == "amqp"` (as opposed to `"amqp/ssl"`) AND `tls == false` AND `ip_address ∈ {"0.0.0.0", "::"}`.
3. **Fallback for older releases** where the `tls` boolean is absent: `protocol` does not end in `/ssl` AND `socket_opts` contains none of `ssl_opts` / `certfile` / `keyfile` / `cacertfile`. This exactly mirrors `has_tls_enabled/2` (`rabbit_networking.erl:300-309`).
4. **Dedup:** group by `(protocol, port)` and report once, listing affected nodes. `rabbit_networking:active_listeners/0` (lines 440-442) appends `node_listeners(Node)` for **every** running node, so a 3-node cluster yields 3 identical findings. Dual-stack also produces two entries per node (`:::5672` is equivalent to `0.0.0.0:5672` and `:::5672`).

**Use the broad form `{0.0.0.0, ::}` as the default match set — not "not loopback".** The not-loopback variant fires on any specific private bind (e.g. `listeners.tcp.1 = 10.0.1.5:5672`), which is a normal private-VPC config and materially noisier.

The `protocol == "amqp"` predicate is largely subsumed by `tls == false` (`has_tls_enabled` only returns true for a plain `amqp` listener if `ssl_opts`/`certfile`/`keyfile`/`cacertfile` are set). Harmless to keep both.

### Evidence claim

> `GET /api/overview` `listeners[]` contains `{"node":"rabbit@<host>","protocol":"amqp","ip_address":"0.0.0.0","port":5672,"tls":false}` — AMQP 0-9-1/1.0 traffic and PLAIN SASL credentials are carried unencrypted on a listener bound to all interfaces on the host (0.0.0.0/::); actual reachability not verified by this check.

Do **not** say "publicly bindable interface" — that is not observable from `/api/overview`. `ip_address=0.0.0.0` is an interface-binding fact, not a reachability fact: the API has no visibility into firewalls, cloud security groups, K8s NetworkPolicy or VPC boundaries, and every containerized broker binds `0.0.0.0` inside its own netns.

### Remediation

Enable a TLS listener (`listeners.ssl.default = 5671` with `ssl_options.certfile` / `ssl_options.keyfile` / `ssl_options.cacertfile`) and remove or loopback-bind the plaintext `listeners.tcp.*` entry. The production checklist recommends *"using TLS connections when possible, at least to encrypt traffic. Peer verification (authentication) is also recommended."*

### False-positive risk and how to avoid it

Medium. The rule fires on stock RabbitMQ (per the networking guide, RabbitMQ listens on port 5672 on all available interfaces by default), and exploitation requires an on-path network position.

**Escalate to high only when exposure is independently corroborated** (a reachability probe, or a correlated internet-exposure signal). The management API alone cannot establish it.

**Suppression required for transparent-TLS topologies:** service-mesh sidecar mTLS (Istio/Linkerd) and TLS-terminating proxy/stunnel/LB both leave the broker binding plaintext with `tls=false` while traffic is encrypted on the wire. Neither is detectable via `/api/overview` — provide a documented exception/waiver path rather than letting these accumulate as noise.

### Verifier corrections applied

- **Severity high → medium** (fires on stock config; needs on-path position).
- **Source misattribution fixed.** The quoted sentence is **not** on `https://www.rabbitmq.com/docs/ssl` (grepped the full `docs/ssl/index.md`, 107KB, 0 hits) — it is on the production checklist under Security Considerations → TLS.
- Evidence no longer claims "publicly bindable interface".
- Missing `listeners` key → unable-to-evaluate; dedup requirement added; broad match set made the default.

### Source

- Remediation config keys (`listeners.ssl`, `ssl_options.certfile/keyfile/cacertfile`, port 5671): https://www.rabbitmq.com/docs/ssl
- The TLS-recommendation quote: https://www.rabbitmq.com/docs/production-checklist
- Default all-interfaces bind: https://www.rabbitmq.com/docs/networking

**Verified correct, no change needed** (checked against RabbitMQ v4.3.2, released 2026-06-15): `/api/overview` `listeners` array and all six field names (`rabbit_mgmt_format.erl:279-287`); the `tls` boolean; protocol atoms `amqp` and `'amqp/ssl'` (`rabbit_networking.erl:290,304,338`); the `socket_opts` fallback mirroring `has_tls_enabled/2` (lines 300-309); `ip` formatting via `rabbit_misc:ntoa` is unbracketed so `'127.0.0.1'`/`'::1'` literals match; PLAIN/AMQPLAIN cleartext default (`rabbit.schema:428`); `listeners.ssl.$name` and `listeners.tcp.$name` mappings (`rabbit.schema:25,48`).

---

## RABBITMQ.CLUSTER.DIST_PORT_EXPOSED

Verify Erlang distribution (clustering) port is firewalled to peer nodes and CLI hosts only

- **Severity:** low (informational / hardening)
- **Kinds:** `broker`, `node`
- **Confidence:** high on mechanics, nil on exposure
- **False-positive risk:** high

### Check

`GET /api/overview` → `listeners` array.

1. If the `listeners` key is **missing** → report **not assessable**, never a silent pass. `rabbit_mgmt_wm_overview.erl` emits `listeners` only when `rabbit_mgmt_util:is_monitor(Tags)` is true (`monitoring` or `administrator`).
2. **Fire (low)** on any element where `protocol ∈ {"clustering", "clustering/ssl"}` AND `ip_address ∈ {"0.0.0.0", "::"}` (default port 25672 = AMQP port + 20000).

**There is no critical escalation.** The previously specified "escalate to critical when `protocol == 'clustering'` and `tls == false`" is **tautological dead logic**: `rabbit_networking.erl` hardcodes `has_tls_enabled(clustering, _Opts) -> false` and `has_tls_enabled('clustering/ssl', _Opts) -> true`, so `protocol == "clustering"` **always** implies `tls == false`. The condition carries zero information — 100% of non-TLS clustering listeners would escalate and the base severity would be unreachable. If you want the distinction, express it honestly as `protocol == "clustering"` (i.e. non-TLS).

### Evidence claim

> `GET /api/overview` `listeners[]` contains `{"node":"rabbit@<host>","protocol":"clustering","ip_address":"::","port":25672,"tls":false}` — the Erlang distribution port is bound to all interfaces per the node's `inet_dist_use_interface` setting. This is the shipped default and does **not** establish that the port is reachable; verify it is firewalled to peer nodes and CLI hosts only.

**`"::"` is the default, not `"0.0.0.0"`.** `maybe_get_epmd_port/2` hardcodes `IPAddress = case application:get_env(kernel, inet_dist_use_interface) of {ok, IP} -> IP; _ -> {0,0,0,0,0,0,0,0} end`, which `rabbit_mgmt_format:ip/1` renders as `"::"`. `"0.0.0.0"` only appears if an operator explicitly sets `distribution.listener.interface = 0.0.0.0`. The match set `{"0.0.0.0","::"}` is correct and stays; the **evidence sample** must show `"::"`.

### Remediation

Bind the distribution listener to a private interface and firewall port 25672 (plus epmd on 4369 and the CLI range 35672-35682) so they are reachable only from peer nodes and CLI hosts. The networking guide states: *"Unless external connections on these ports are really necessary (e.g. the cluster uses federation or CLI tools are used on machines outside the subnet), these ports should not be publicly exposed."* Optionally pin the range with `distribution.listener.port_range.min`/`.max` and enable inter-node TLS.

Pair with `RABBITMQ.ERLANG.DEFAULT_COOKIE`: a weak or default cookie is what makes a reachable 25672 dangerous.

### False-positive risk and how to avoid it

**High — this is why the rule is low severity.** Because `{0,0,0,0,0,0,0,0}` is the hardcoded default when `distribution.listener.interface` is unset, the base fire rate approaches 100% while the true-positive rate (genuinely internet-reachable 25672) is very low. Legitimate configurations that trip it: any node behind a cloud security group / host firewall / K8s NetworkPolicy (the RabbitMQ-endorsed posture); nodes on a private VPC subnet, Docker bridge or pod network with no public route; single-node brokers whose distribution listener is bound but unroutable.

Without an external reachability signal to correlate against, this rule is near-pure noise at high/critical and is defensible **only** as a low-severity hardening reminder. If you have a reachability probe, gate the rule on it and raise severity accordingly.

### Verifier corrections applied

- **Severity high → low**, reframed as hardening. `ip_address` is a config echo of `inet_dist_use_interface`, not an observation of the bound socket or of reachability; the API cannot see firewalls/security groups/NetworkPolicies, which are the primary control the RabbitMQ docs themselves recommend; and the `::` bind is the hardcoded default, so the rule fires on essentially every stock node including correctly-hardened ones. CVE-2021-43799's 8.6 rating presumes an actually-reachable port — a precondition this check cannot establish.
- Deleted the tautological critical escalation.
- Fixed the evidence sample to `"::"`.
- Fixed the misquote (docs say "these ports should not be publicly exposed", not "not be exposed to the public Internet").
- Re-cited the RCE claim — the networking guide does not support it.
- Added the authz gate.

### Source

- https://www.rabbitmq.com/docs/networking (port math AMQP+20000=25672, epmd 4369, CLI range 35672-35682, the "not publicly exposed" sentence)
- RCE claim: CVE-2021-43799 / https://github.com/zulip/zulip/security/advisories/GHSA-p663-wxvv-2fjp (CVSS 8.6) — states a remote attacker can "brute-force the 20 bits of entropy in the 'cookie' and leverage it for arbitrary execution of code as the rabbitmq user" when firewalls do not protect port 25672. The clustering guide only says nodes use a cookie "to determine whether they are allowed to communicate with each other" — do not cite it for RCE.
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl` (`listener/1` field list)
- `deps/rabbit/src/rabbit_networking.erl` (protocol atoms, `maybe_get_epmd_port/2`)
- `deps/rabbit/priv/schema/rabbit.schema` (`distribution.listener.interface` → `kernel.inet_dist_use_interface`; `distribution.listener.port_range.min/max` → `kernel.inet_dist_listen_min/max`)

---

## RABBITMQ.USER.WEAK_PASSWORD_HASHING

User password stored with the legacy MD5 hashing module

- **Severity:** medium
- **Kinds:** `user`, `broker`
- **Confidence:** high
- **False-positive risk:** low

### Check

**Requires an `administrator`-tagged credential** (`rabbit_mgmt_wm_users.erl` gates `GET /api/users` behind `is_authorized_admin`). 401/403 → NOT-ASSESSABLE.

1. `GET /api/users`.
2. **Fail** on any element where `hashing_algorithm == "rabbit_password_hashing_md5"`.
3. **Skip** elements where `password_hash == ""` — no internal password (external auth backend). Verified: `internal_user/1` emits `base64:encode` of the hash, and `change_password_hash(Username, <<"">>)` is how a password is cleared, so base64 of `<<"">>` is `""`.
4. **Flag as info** if `hashing_algorithm` is outside `{rabbit_password_hashing_sha256 (default), rabbit_password_hashing_sha512, rabbit_password_hashing_md5}`. Keep this branch: `hashing_mod(CustomMod) when is_atom(CustomMod) -> CustomMod` explicitly permits plugin-supplied modules, which may be **stronger** than sha256 (e.g. a bcrypt/argon2 plugin) — info, not fail.

**Critical interpretation note — put this in the finding text.** A reported value of `rabbit_password_hashing_md5` does **not** imply md5 is configured. `rabbit_auth_backend_internal:hashing_module_for_user/1` delegates to `rabbit_password:hashing_mod/1`, which has the clause `hashing_mod(undefined) -> rabbit_password_hashing_md5`, commented *"fall back to the hashing function that's been used prior to 3.6.0"*. So legacy user records created before 3.6.0 that store **no** algorithm are reported as md5. This is still a **true positive** — `user_login_authentication` verifies via `hashing_module_for_user(User)`, so the credential really is checked with MD5 — but without this note an operator whose `rabbitmq.conf` already sets sha256 will find no md5 setting and dismiss the finding as a scanner bug.

State explicitly: *the user record predates 3.6.0 or has no recorded algorithm; the server falls back to MD5 for it regardless of `password_hashing_module`. Resetting the user's password is required and sufficient.*

(Minor: `sha512` has no explicit clause in `hashing_mod/1` — it resolves via the `is_atom(CustomMod)` catch-all. Behaviour is as described; the accepted-values list above is correct and should not be "corrected" against the clause list.)

### Evidence claim

> `GET /api/users` returned `{"name":"<user>","hashing_algorithm":"rabbit_password_hashing_md5","password_hash":"<hash>"}` — the credential is hashed with MD5, retained only for backwards compatibility. Either `password_hashing_module` is set to MD5, or the user record predates 3.6.0 and has no recorded algorithm, in which case the server falls back to MD5 for that user regardless of configuration.

### Remediation

Set `password_hashing_module = rabbit_password_hashing_sha256` (or `rabbit_password_hashing_sha512`) in `rabbitmq.conf`. Changing the module does **not** rehash existing credentials — each affected user's password must be reset after the change for the new algorithm to take effect (*"Updated hashing algorithm will be applied to newly created users or when password is changed"*). For pre-3.6.0 records with no recorded algorithm, resetting the password is required and sufficient.

### False-positive risk and how to avoid it

Low. The match is a literal string equality on a server-reported field. The main misread is the pre-3.6.0 fallback case above, which is a true positive but reads as a scanner bug unless the finding text explains it.

### Verifier corrections applied

- **Severity high → medium.** (a) Observing the hash already requires the `administrator` tag, so an attacker who can read it already controls the broker; the residual risk is offline cracking → password reuse elsewhere. (b) The remediation's cryptographic uplift is marginal: `rabbit_password.erl` uses `generate_salt() -> crypto:strong_rand_bytes(4)` (a 4-byte salt) and `salted_hash/3` is a single-iteration digest, so sha256/sha512 are also fast, non-KDF hashes — MD5→SHA-256 is a small constant-factor improvement, not an order of magnitude. Retained at medium (not low) because MD5 is a hard compliance failure (FIPS/PCI) and reliably indicates credentials never rotated since 3.5.x.
- Added the pre-3.6.0 fallback explanation to check and evidence.
- Added the observability citation.

### Source

- https://www.rabbitmq.com/docs/passwords — supports module names, sha256 default, MD5 back-compat status, no-rehash remediation. It does **not** document that `GET /api/users` returns `hashing_algorithm`/`password_hash`.
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl` (`internal_user/1` emits `[name, password_hash (base64), hashing_algorithm, tags, limits]`)
- https://www.rabbitmq.com/docs/http-api-reference
- `deps/rabbit/src/rabbit_password.erl`, `deps/rabbit/src/rabbit_auth_backend_internal.erl`

---

## RABBITMQ.PERMISSION.WILDCARD_ALL

User granted unrestricted `.*` permissions on configure, write and read for a vhost

- **Severity:** medium
- **Kinds:** `acl`, `user`, `vhost`
- **Confidence:** high
- **False-positive risk:** medium

### Check

**Requires an `administrator`-tagged credential.** Only `administrator` can "View, create and delete users" and "View, create and delete permissions"; `monitoring` and `policymaker` **cannot** read `/api/permissions` or `/api/users`. RabbitMQ has no read-only-administrator tag. Without this note the rule silently no-ops (401/403) on correctly-least-privileged scanner creds and reports a clean vhost. 401/403 → NOT-ASSESSABLE.

1. `GET /api/permissions`. Candidate = any element where `configure`, `write` and `read` **all** match a full wildcard — literal `.*` or `^.*$`.
2. `GET /api/users`. **Suppress on the `administrator` tag only.**
3. **Tenancy gate (required, primary FP fix).** Group `/api/permissions` by vhost. **Fire only when >= 2 non-administrator principals hold permissions in the SAME vhost** — i.e. the wildcard actually crosses a trust boundary. For single-tenant vhosts, drop the finding or emit at `info` as *"wildcard grant, single-tenant vhost — blast radius is the vhost"*.
4. **Escalate to high** only when the wildcard triple is combined with a real aggravator: the vhost is provably multi-tenant AND the identity is remotely reachable.

**Do not suppress on `policymaker`.** `policymaker` is orthogonal to resource permissions — it grants "View, create and delete policies and parameters", **not** resource wildcards. Apps are legitimately tagged policymaker to manage their own policies; treating that as an intended admin grant suppresses genuine findings.

**`tags` shape:** JSON array in GET responses on 3.9+/4.x (`{"tags":["administrator"]}`); the comma-separated string form is accepted on **PUT only**. Parse defensively (accept both) if pre-3.9 is in scope.

**Known false negative (acceptable — document, do not fix).** Matching only literal `.*` and `^.*$` misses other total-match regexes (`^.*`, `.*$`, `(.*)`, `.+` for non-empty names). RabbitMQ matches unanchored, so these are equivalent. Keeping to literals is a defensible low-FP choice; note the gap rather than widening into regex-equivalence analysis.

### Evidence claim

> `GET /api/permissions` returned `{"user":"<user>","vhost":"<vhost>","configure":".*","write":".*","read":".*"}` and `GET /api/users` shows that user with `tags=[]` — a non-admin identity can create, destroy and reconfigure every resource in the vhost and read every queue. `<N>` non-administrator principals hold permissions in this vhost, so the grant crosses a trust boundary.

### Remediation

Replace the wildcard triple with regexes scoped to the resource names the application actually uses — **but include the server-generated and default-exchange names, or you will cause an outage**:

```
configure = ^(app-name-.*|amq\.gen.*)$
write     = ^(app-name-.*|amq\.default|amq\.gen.*)$
read      = ^(app-name-.*|amq\.gen.*)$
```

A bare `configure = '^app-name-.*'` breaks any client that declares server-generated or exclusive queues, or publishes via the default exchange: `queue.declare`/`exchange.declare` require `configure`, and server-generated names are prefixed `amq.gen`. Celery, Spring AMQP, MassTransit, NServiceBus and any RPC/reply-to client will fail to start. The docs state: *"'^(amq\.gen.*|amq\.default)$' gives a user access to server-generated names and the default exchange."*

The safe floor is `^$` (synonym: the empty string), which the docs describe as: it *"covers all resources and effectively stops the user from performing any operation"* — **this DENIES everything**; the sentence is notoriously easy to misread as granting access. Start there and widen deliberately.

Use a separate user per application. (The access-control page does not state this in those words — it says *"Production environments should not use the default user. Create new user accounts with generated credentials instead."* Attribute accordingly rather than implying the docs mandate per-app users.)

### False-positive risk and how to avoid it

Medium, driven almost entirely by tenancy. **Dedicated-vhost-per-application is RabbitMQ's dominant pattern, and the vhost IS the isolation boundary** — "A user doesn't have global permissions, only permissions in one or more virtual hosts"; "Connections to a vhost can only operate on exchanges, queues, bindings, and so on in that vhost". A sole app owning its own vhost with `.*` has nothing to be least-privileged from; that is intended design, not a defect. The tenancy gate in check step 3 is what makes this rule shippable.

Confidence on the tenancy-gate argument is medium-high: the vhost-per-app convention is well established and the docs frame vhosts as the permission boundary, but the docs stop short of naming it a best practice, so the gate is an engineering judgement rather than a documented rule.

### Verifier corrections applied

- **Severity high → medium.** Impact is confined to a single vhost, requires already-valid credentials, and confers no cross-vhost, node-level or management-plane reach (that needs tags, not permissions). This is least-privilege hygiene, not an exploitable vulnerability. Reserve `high` for genuinely exploitable findings (remote-enabled `guest`, administrator tag on an application identity, no TLS on 5672).
- Added the tenancy gate.
- Dropped `policymaker` from the suppression list.
- **Fixed the remediation, which was outage-causing as written** (missing `amq.gen`/`amq.default`).
- Documented the administrator-tag prerequisite and pinned the `tags` array shape.

### Source

- https://www.rabbitmq.com/docs/access-control — "Permissions are expressed as a triple of regular expressions - one each for configure, write and read - on a per-vhost basis"; the `^$` and `^(amq\.gen.*|amq\.default)$` guidance
- https://www.rabbitmq.com/docs/http-api-reference — `GET /api/permissions` = "A list of all user permissions in the cluster"; PUT payload is literally `{"configure":".*","write":".*","read":".*"}` with "All three permissions must be explicitly provided."
- https://www.rabbitmq.com/docs/management — tag capability table
- https://www.rabbitmq.com/docs/vhosts — vhost as isolation boundary
- rabbitmq-server#4050 — docs corrected to `"tags": ["administrator"]`

Verified against RabbitMQ 4.3.2 (released 2026-06-15) docs.

---

## RABBITMQ.PERMISSION.CONFIGURE_WILDCARD

Application user holds wildcard `configure` permission on a vhost

- **Severity:** medium
- **Kinds:** `acl`, `user`, `vhost`
- **Confidence:** high
- **False-positive risk:** low

### Check

**Requires an `administrator`-tagged credential** (see WILDCARD_ALL). Degrade gracefully on 401/403 rather than reporting zero findings.

1. `GET /api/permissions`. **Fail** on any element where `configure == ".*"` (or `"^.*$"`) **even if `write` and `read` are narrower**, for a user whose `GET /api/users` `tags` contains no `administrator`/`policymaker` tag.
2. **Suppress** when `RABBITMQ.PERMISSION.WILDCARD_ALL` already fired on the same `(user, vhost)` pair, to avoid double reporting. (This suppression is sound — keep it.)
3. **User absent from `/api/users` → emit unknown/skip, do NOT fire.** Per the HTTP API reference, `GET /api/users` "only includes the users in the internal data store. For example, if the LDAP backend is used, this command will not include any LDAP users." With external authn (LDAP/OAuth2) + internal authz, a principal present in `/api/permissions` may be missing from `/api/users`, so the tag lookup silently fails. Never treat "user not found" as "has no administrator/policymaker tag".

**Coverage gap (low confidence — suggestion only, not verified against server source):** RabbitMQ permission regexes appear to be matched unanchored, so effectively-wildcard patterns such as `.`, `.+` or `a|.*` would evade a literal equality test. Consider a "matches-everything" predicate instead of string equality.

### Evidence claim

> `GET /api/permissions` returned `{"user":"<user>","vhost":"<vhost>","configure":".*","write":"^orders-.*","read":"^orders-.*"}` — the user's publish/consume scope is constrained, but it can still declare or delete any queue or exchange in the vhost, destroying other applications' queues and the messages in them.

**Do not claim bindings.** The original wording ("can create or destroy any queue, exchange or **binding**") is factually wrong and contradicted by the cited page's own operations table. Verified table (`docs/access-control.md`):

| Operation | Permission required |
|---|---|
| `exchange.declare` / `exchange.delete` | `configure` (exchange) |
| `queue.declare` / `queue.delete` | `configure` (queue) |
| `queue.bind` / `queue.unbind` | `write` (queue/destination) + `read` (exchange/source) |
| `exchange.bind` / `exchange.unbind` | `write` (destination exchange) + `read` (source exchange) |
| `basic.publish` | `write` (exchange) |
| `basic.get` / `basic.consume` | `read` (queue) |
| `queue.purge` | `read` (queue) |

`configure` is **not** involved in any binding operation. With `write`/`read` = `^orders-.*`, the user **cannot** create or destroy arbitrary bindings. Configure alone = declare/delete queues and exchanges. The rule's core is sound; only the impact wording was wrong.

### Remediation

Scope `configure` to the resources the application owns, or set it to `^$` entirely for applications that only publish and consume against topology declared by a deployment process. Configure permission governs the ability to *"create or destroy resources, or alter their behaviour"*. (The `^$` deny-all and the empty-string synonym are both documented.)

Note: the assessment that configure is the most destructive of the three permissions is the **scanner's own judgement** — the docs never rank them.

### False-positive risk and how to avoid it

Low. The one legitimate fire is a **topology-provisioning / deployment / migration service account** that genuinely needs `configure='.*'` and may carry no management tags — ironically the exact actor the remediation text invokes. Add an allowlist/exception mechanism for such accounts.

This is not common enough to make the rule noisy: the common sloppy grant is `.* .* .*`, which WILDCARD_ALL catches and the suppression de-dupes; `configure='.*'` with narrower `write`/`read` is a deliberate partial-hardening state where configure was overlooked, so a fire is usually genuine.

### Verifier corrections applied

- Fixed the factually wrong bindings claim in the evidence.
- Removed "and is the most destructive of the three" as a doc-derived claim (marked as scanner assessment).
- Added the "user absent from `/api/users`" unknown branch.
- Documented the administrator-tag requirement.
- **Severity medium kept as-is:** requires already-valid credentials for the vhost, no privilege escalation, blast radius capped at a single vhost — so not high. But enables deletion of any queue/exchange in the vhost with attendant message loss — so not low.

### Source

- https://www.rabbitmq.com/docs/access-control (operations table; `configure` definition; `^$` deny-all)
- https://raw.githubusercontent.com/rabbitmq/rabbitmq-website/main/docs/access-control.md
- https://www.rabbitmq.com/docs/http-api-reference (internal-store-only caveat)
- https://www.rabbitmq.com/docs/management (tag capability table)

---

## RABBITMQ.USER.ADMIN_TAG_SPRAWL

Excessive number of users carrying the `administrator` tag

- **Severity:** low
- **Kinds:** `user`, `broker`
- **Confidence:** high
- **False-positive risk:** medium

### Check

**Requires an `administrator`-tagged credential** (`GET /api/users` is gated on `rabbit_mgmt_util:is_authorized_admin`, verified in `deps/rabbitmq_management/src/rabbit_mgmt_wm_users.erl`). 401/403 → NOT-ASSESSABLE.

1. `GET /api/users`. Normalise `tags` (JSON array in 3.9+, comma-separated string in older releases) and count elements whose tags contain `administrator`.
2. **Exclude the authenticated scanning identity from the count** — identify it via `GET /api/whoami`. Because `/api/users` is administrator-gated, the scanning credential **must** carry `administrator` and therefore inflates its own count by 1. If exclusion is not possible, disclose it explicitly in the evidence string.
3. **Fail** if `count > 2` **AND** `count / total_users > 0.25`, on a broker with more than 4 users. Report each administrator-tagged user by name.

**The threshold is AND, not OR.** The `count > 2` OR-clause fires on legitimate 5-user brokers with 3 operators and is the dominant noise source; the `>4 users` gate does not save it. If you prefer a single criterion, drop the absolute clause and keep the ratio.

These thresholds (>2 absolute, >25% ratio, min 4 users) are **engineering judgement, not from RabbitMQ docs.** The docs establish the tag hierarchy (`management` < `policymaker`/`monitoring` < `administrator`) but publish no numeric guidance. Expect to tune per environment.

### Evidence claim

> `GET /api/users` returned 11 users, of which 7 carry tags containing `"administrator"` (`<names>`) — 64% of identities can manage users, vhosts and permissions cluster-wide. (Count excludes the scanning identity `<scanner_user>`.)

Optionally note the documented caveat: *"Normal RabbitMQ permissions to resources still apply to monitors and administrators; just because a user is a monitor or administrator does not grant them full access to exchanges, queues and bindings."* An admin can grant themselves those permissions, so blast radius is real, but the evidence should not imply automatic data-plane access.

### Remediation

The `administrator` tag grants everything `policymaker` and `monitoring` can do plus "Create and delete virtual hosts. View, create and delete users. View, create and delete permissions. Close other users's connections". Downgrade dashboard-only identities to `management`, metrics scrapers to `monitoring`, and policy automation to `policymaker`. Reserve `administrator` for a small, named set of break-glass operators.

### False-positive risk and how to avoid it

Medium.

- **External identity backends.** The HTTP API reference states `GET /api/users` "only includes the users in the internal data store... if the LDAP backend is used, this command will not include any LDAP users." On LDAP/OAuth2 brokers the internal store holds only a few break-glass accounts that are **legitimately all admin-tagged**. Suppress or reframe when an external auth backend is detected; do not score residual internal accounts as sprawl.
- **Managed providers.** Amazon MQ for RabbitMQ creates the initial user with the `administrator` tag and its own docs instruct creating additional users via `{"password":"...","tags":"administrator"}`. Emit a lower score or an advisory note on detected Amazon MQ brokers rather than a standing finding.
- **Self-counting scanner** — see check step 2.

### Verifier corrections applied

- Threshold OR → AND (primary defect).
- Scanner self-count exclusion added.
- Added the HTTP API reference as the source for the endpoint and field (the management page documents neither).
- External-backend and Amazon MQ suppressions added.
- **`tags` dual normalisation verified correct — keep it.** rabbitmq-server issue #2667 ("It is currently exported as a comma-separated list. It would be significantly more convenient to export it as a JSON array"), opened 2020-12-02, milestoned to 3.9.0. Note `PUT /api/users/{name}` still documents "The tags key takes a comma-separated list of tags" — write-side and read-side formats differ; this rule only reads.

### Source

- https://www.rabbitmq.com/docs/management (tag capability text — supports remediation only)
- https://www.rabbitmq.com/docs/http-api-reference (`GET /api/users`, the `tags` field, internal-store-only caveat)
- `deps/rabbitmq_management/src/rabbit_mgmt_wm_users.erl`

---

## RABBITMQ.VHOST.DEFAULT_VHOST_IN_USE

Multiple unscoped principals share the default `/` virtual host

- **Severity:** low
- **Kinds:** `vhost`, `acl`
- **Confidence:** high on mechanics
- **False-positive risk:** high (as originally written; the corrected check below is what makes it shippable)

### Check

**Requires an `administrator`-tagged credential.** `GET /api/permissions` requires the `administrator` tag; the `monitoring` tag lists vhosts but cannot view permissions ("view, create and delete permissions" is administrator-only). A monitoring-only scanner returns nothing and the rule silently passes — emit **not-assessable** instead.

1. `GET /api/vhosts` → confirm an element with `name == "/"` exists.
2. `GET /api/users` → exclude users whose `tags` include `administrator` or `monitoring`.
3. `GET /api/permissions` → over the remaining non-guest users, count those holding **broad regexes** on vhost `"/"`: `configure`, `write` and `read` each `== ".*"` (or equivalently permissive).
4. **Fire (low)** only when **>= 2 such users** exist. That is the observable condition: "no isolation between principals sharing one namespace".

**Removed conditions — do not reimplement them:**

- **The `>= 1 non-guest user` trigger is contradicted by its own source and must not be used.** The production checklist states verbatim: *"In a single-tenant environment, for example, when your RabbitMQ cluster is dedicated to power a single system in production, using default virtual host (/) is perfectly fine."* Firing at `>=1` flags the doc-blessed majority configuration. The scanner cannot observe tenancy intent and must not assume multi-tenancy.
- **The `>= 2 distinct non-guest users → high` escalation is unsound.** Distinct users != distinct tenants/applications. A legitimate single-tenant cluster routinely has admin + Prometheus scraper + CI/deploy + app user = 4 non-guest users on `/`. The discriminator is the **breadth of the ACLs**, not the count of principals — which is why step 2 excludes operator tags and step 3 requires broad regexes.

### Evidence claim

> `GET /api/permissions` shows `<N>` non-admin, non-guest users (`<names>`) each holding `configure`/`write`/`read` = `".*"` on vhost `"/"` — these principals can access one another's queues and exchanges.

Two assertions were removed as unprovable:

- **"auto-created"** — presence of `/` does not establish it was auto-created. A blank node importing `definitions.local.path` skips creating the default vhost/user, `/` may be deliberately provisioned, and `default_vhost` may have been overridden.
- **"no tenant separation"** — a conclusion the queried data cannot support.

### Remediation

If these principals represent separate applications/tenants, create a dedicated vhost per application/tenant/environment and migrate onto them. The production checklist recommends: *"In multi-tenant environments, use a separate vhost for each tenant/environment, e.g. project1_development, project1_production, project2_development, project2_production."* Then narrow or remove the broad permissions on `/`.

Do **not** advise deleting the default vhost — unnecessary, and gratuitously risky advice for a scanner to hand an operator.

### False-positive risk and how to avoid it

High **unmodified** — the original `>=1` form fires on nearly every single-tenant RabbitMQ deployment, which the vendor documents as perfectly fine. The corrected check (operator-tag exclusion + broad-regex requirement + `>=2` threshold) is the minimum that produces signal. If those corrections are not adopted, **drop this rule** rather than ship it.

Even corrected, this is a blast-radius / namespace-hygiene concern, not a vulnerability — per-user ACLs remain enforced. Hence low.

### Verifier corrections applied

- **Severity medium → low** (high is indefensible).
- Removed the `>=1` trigger and the `>=2 users → high` escalation.
- Rewrote the check to inspect `configure`/`write`/`read` — the only fields that carry signal, which the original check never read.
- Removed "auto-created" and "no tenant separation" from evidence.
- Added the administrator-tag precondition.
- Dropped "consider deleting the default vhost".

### Source

- https://www.rabbitmq.com/docs/production-checklist (both the multi-tenant recommendation and the single-tenant "perfectly fine" statement)
- https://www.rabbitmq.com/docs/configure (`default_vhost` = "Virtual host to create when RabbitMQ creates a new database from scratch", default `/`; alongside `default_user`/`default_pass`/`default_permissions`)
- https://www.rabbitmq.com/docs/access-control (blank-node boot creates vhost `/` and user `guest`)
- https://www.rabbitmq.com/docs/definitions (permissions object fields: exactly `user`, `vhost`, `configure`, `write`, `read`)
- https://www.rabbitmq.com/docs/management (administrator-only permission viewing)

---

## RABBITMQ.TLS.PEER_VERIFICATION_DISABLED

TLS listener does not verify peer certificates (informational hardening)

- **Severity:** low
- **Kinds:** `broker`, `route`
- **Confidence:** medium
- **False-positive risk:** high (this is why the rule is scoped and split — see below)

### Check

**Gate on x509 auth NOT being in use.** `GET /api/nodes` → `auth_mechanisms` array (read-only; `enabled` flag per mechanism, `rabbit_mgmt_external_stats.erl:254-259`). This rule applies **only** when `EXTERNAL` is **not** in the enabled mechanisms. If `EXTERNAL` is enabled, report `RABBITMQ.TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION` (below) instead.

1. `GET /api/overview`. For each `listeners` element with `tls == true` (or `protocol` ending `/ssl`), inspect `socket_opts`. For each `contexts` element with `description == "RabbitMQ Management"`, inspect top-level `ssl_opts`.
2. **Check both `socket_opts.verify` AND `socket_opts.ssl_opts.verify`.** `rabbit_networking:start_ssl_listener/4` registers opts as `tcp_opts() ++ SslOpts` — a **flat** proplist — so for `amqp/ssl` the shape is `socket_opts.verify`. But ranch/web-based listeners **nest** under `socket_opts.ssl_opts` (`has_tls_enabled` does `proplists:get_value(socket_opts, Opts, Opts)` then probes for `ssl_opts`, and `format_socket_opts` recurses into it). Checking only one shape misses half the listeners. (For contexts, `web_context/1` puts `ssl_opts` at the **top level** of the context, not under `socket_opts`.)
3. **Fire (low, informational)** if `verify == "verify_none"` or `verify` is absent (the effective default is no verification).

**`verify` absent is STRONG evidence it is unset, not weak.** `verify` and `fail_if_no_peer_cert` are **not** in `format_socket_opts`' drop list — they fall through to the catch-all clause and are preserved verbatim. Redaction only hits `cacerts`/`certs_keys` (truncated to counts) and drops `customize_hostname_check`/`crl_cache`/`partial_chain`/`user_lookup_fun`/`sni_fun`/`sni_hosts`/`reuse_session`/`ciphers`/`verify_fun`/`match_fun` and function values.

**Do NOT flag `verify_peer` + `fail_if_no_peer_cert == false` in this rule.** That belongs only to the x509 rule below.

**Why "absent" means no verification (verified):** `deps/rabbit/priv/schema/ssl_options.partial` defines `{mapping, "verify", "verify", [{datatype, {enum, [verify_peer, verify_none]}}]}` and `{mapping, "fail_if_no_peer_cert", "fail_if_no_peer_cert", [{datatype, boolean}]}` — **neither carries a `{default, ...}` clause.** Unset → never passed to `ssl:listen` → the Erlang/OTP server default applies, and per the OTP ssl docs "By default the server is in verify_none mode". (OTP 26 changed only the **client** default to verify_peer.) So "verify absent ⇒ no verification" is correct for a listener (server role).

### Evidence claim

> `GET /api/overview` `listeners[]` contains `{"protocol":"amqp/ssl","port":5671,"tls":true,"socket_opts":{"verify":"verify_none"}}` — the TLS listener does not request or validate client certificates. Traffic is still encrypted and the node still presents its own certificate; this matters only if x509 client authentication is intended. `EXTERNAL` is not in this node's enabled `auth_mechanisms`, so no authentication decision depends on peer verification here.

**The MITM framing was removed and must not be reinstated.** Server-side `verify` governs whether the node validates **client** certificates. The server still presents its own cert; traffic is still encrypted; MITM defence is the **client verifying the server**, which this setting does not affect. The docs say outright: *"Thus it is possible to create an encrypted TLS connection without having to verify certificates"*, and mTLS is *"a joint responsibility of RabbitMQ nodes and client connections. Enabling peer verification on just one end is not enough."* The quoted "certificate exchange won't be performed" refers to the **client cert request**, not the server's cert.

### Remediation

If x509 client authentication is intended, set `ssl_options.verify = verify_peer` and `ssl_options.fail_if_no_peer_cert = true`, and point `ssl_options.cacertfile` at the trusted CA bundle. The TLS guide notes that with `verify_none` *"peer verification will be disabled and certificate exchange won't be performed"*.

Note that clients must **independently** verify the server certificate — that is what prevents MITM; this server-side setting does not.

### False-positive risk and how to avoid it

High if unscoped — all three original fail conditions fire on documented/default configs:

- `verify` absent is the out-of-the-box state for anyone enabling TLS with just `cacertfile`/`certfile`/`keyfile` — i.e. the **majority** of deployments doing one-way TLS with username/password auth.
- `verify_none` likewise.
- `verify_peer` + `fail_if_no_peer_cert=false` is RabbitMQ's **own example config** in `rabbit.schema` (comment block ~lines 307-312: `{verify, verify_peer}, {fail_if_no_peer_cert, false}`) and the docs describe it as intentional: it *"tells the node to accept clients which don't present a certificate (for example, were not configured to use one)"*.

The `auth_mechanisms` gate is what makes this rule tolerable. If FP tolerance is low, report only on an explicit `verify_none` and not on absence.

### Verifier corrections applied

- **Severity high → low**, reframed as informational hardening, gated on `EXTERNAL` not being enabled.
- Added the `socket_opts.ssl_opts.verify` nested shape.
- **Deleted the redaction caveat** — it was backwards; absence of `verify` is strong evidence.
- Rewrote the evidence claim; the MITM impact claim was materially false and contradicted by the rule's own cited source.
- Moved `fail_if_no_peer_cert` to the split rule below.

### Source

- https://www.rabbitmq.com/docs/ssl
- https://www.erlang.org/doc/apps/ssl/ssl.html
- `deps/rabbit/priv/schema/ssl_options.partial`, `deps/rabbit/priv/schema/rabbit.schema`
- `deps/rabbit/src/rabbit_networking.erl`, `deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl`, `deps/rabbitmq_management_agent/src/rabbit_mgmt_external_stats.erl`, `deps/rabbitmq_management/src/rabbit_mgmt_app.erl` (description literal at `:172`)

Source paths verified on branch `main` as of 2026-07-17; no version tag pinned.

---

## RABBITMQ.TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION

x509 client authentication enabled without peer certificate verification

- **Severity:** high
- **Kinds:** `broker`, `route`
- **Confidence:** medium
- **False-positive risk:** low

> Derived rule. The verifier required splitting `RABBITMQ.TLS.PEER_VERIFICATION_DISABLED` into a default-posture informational rule (above) and this genuine-bypass rule. It is the half that carries real severity.

### Check

1. `GET /api/nodes` → `auth_mechanisms`. Proceed only if an element has `name == "EXTERNAL"` and `enabled == true`.
2. `GET /api/overview` → for each TLS listener (`tls == true` or protocol ending `/ssl`), read `socket_opts.verify` **and** `socket_opts.ssl_opts.verify`; for the `RabbitMQ Management` contexts, read top-level `ssl_opts.verify`.
3. **Fail** if `verify != "verify_peer"` (including absent).
4. **Also fail** if `verify == "verify_peer"` AND `fail_if_no_peer_cert == false` — clients may simply omit a certificate. Only in this rule is that condition a finding.

### Evidence claim

> `GET /api/nodes` reports `{"name":"EXTERNAL","enabled":true}` in `auth_mechanisms`, and the TLS listener on port 5671 reports `verify` = `<observed_or_absent>` — x509 client authentication is in use while the node does not verify client certificates. An unverified self-signed certificate with an arbitrary CN would authenticate.

### Remediation

Set `ssl_options.verify = verify_peer` and `ssl_options.fail_if_no_peer_cert = true`, and point `ssl_options.cacertfile` at the trusted CA bundle. Per the `rabbitmq-auth-mechanism-ssl` README: *"For safety the server must be configured with the SSL option 'verify' set to 'verify_peer', to ensure that if an SSL client presents a certificate, it gets verified."*

### False-positive risk and how to avoid it

Low. The `EXTERNAL`-enabled gate removes the entire default-posture population that makes the unscoped rule noisy. Residual FP: `auth_mechanisms.enabled` is computed purely from list membership in the `auth_mechanisms` env, so `EXTERNAL` may be listed but unused by every client — still worth reporting, since any client that does use it is unauthenticated in practice.

### Source

- https://github.com/rabbitmq/rabbitmq-auth-mechanism-ssl
- https://www.rabbitmq.com/docs/ssl
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_external_stats.erl:254-259`

---

## RABBITMQ.VERSION.UNPATCHED_CVE

Broker version predates the July 2026 security patch set

- **Severity:** medium (escalates to high only on an observed OAuth secret — see below)
- **Kinds:** `broker`, `node`
- **Confidence:** high
- **False-positive risk:** medium

### Check

1. `GET /api/overview` → `rabbitmq_version` (e.g. `"4.2.3"`). Parse major.minor.patch.
2. **Scope: `>= 3.13.0` only.** Fail if the version is `>= 3.13.0` AND below the patched release for its series:

| Series | Patched at |
|---|---|
| 3.13.x | 3.13.15 |
| 4.0.x | 4.0.20 |
| 4.1.x | 4.1.11 |
| 4.2.x | 4.2.6 |
| 4.3.x | 4.3.0+ — already patched |

3. **Anything `< 3.13.0` → do NOT fire this rule.** Both CVE-2026-57219 and CVE-2026-57221 were **introduced in 3.13.0** ("present since early 2024, impacting release lines from 3.13.0 onward"). A 3.12.x broker is not exposed to either, so firing with this evidence is a guaranteed false positive. That case is covered by `RABBITMQ.VERSION.EOL_SERIES`.
4. **Unrecognized future series** (e.g. 4.4.x) above all known patched releases → **PASS**, not fail-through.
5. **Severity gating.** Default `medium` on version match alone (CVE-2026-57221 only, CVSS 5.3). **Escalate to high only when `GET /api/auth` actually returns a non-empty `oauth_client_secret`** (one unauthenticated request; see `RABBITMQ.CVE.OAUTH_SECRET_DISCLOSURE`). CVE-2026-57219 (8.7) only discloses a secret where OAuth 2 is configured with `management.oauth_client_secret`; the majority of deployments use the internal auth backend and have no secret to leak.
6. **Per-node drift:** `GET /api/nodes` → for each node object, read the `applications` array and take the entry where `name == "rabbit"` → its `version`. **`GET /api/nodes` → `name` returns node identifiers (`rabbit@host`), NOT versions**, and `/api/nodes` exposes no dedicated version field — a drift check keyed on `name` detects nothing.

### Evidence claim

> `GET /api/overview` reports `rabbitmq_version="4.2.3"`, below the 4.2.6 patched release for its series — exposed to CVE-2026-57221 (CVSS 5.3, missing permission check on passive `queue.declare`/`exchange.declare`). CVE-2026-57219 (CVSS 8.7, unauthenticated OAuth client secret disclosure via `GET /api/auth`) additionally applies if OAuth 2 is configured with a client secret.

When `/api/auth` is confirmed to return a non-empty secret, replace the conditional clause with the confirmed statement and escalate to high. Do not assert CVE-2026-57219 exposure from the version string alone.

### Remediation

Upgrade to at least 4.3.0, 4.2.6, 4.1.11, 4.0.20 or 3.13.15 depending on series. CVE-2026-57219 and CVE-2026-57221 were both introduced in 3.13.0 (early 2024). If OAuth 2 with a client secret was configured, rotate `management.oauth_client_secret` as part of the upgrade — patching removes the endpoint but does not invalidate an already-leaked credential.

**CVE-2026-57211** (management static file handler path traversal via URL-encoded backslashes in `rabbit_mgmt_wm_static`): CVSS 6.5, CWE-36/CWE-918, **Windows-only**, affects **4.1.0–4.1.10 and 4.2.0–4.2.5 only** (not 3.13.x, not 4.0.x), requires multiple management extension plugins enabled, fixed in 4.1.11 / 4.2.6. Do not cite it as an upgrade driver on non-Windows nodes. Treat as **unverified** — it came from a search snippet with no page fetched.

### False-positive risk and how to avoid it

Medium. **Distro/vendor backports** (Debian/RHEL `rabbitmq-server`, Tanzu RabbitMQ) patch without bumping the upstream string, so `rabbitmq_version` reports an apparently-vulnerable value on a fixed build. Corroborate with the **observable** `GET /api/auth` behaviour rather than the version string alone where possible, and allow a per-target suppression for backported builds.

### Verifier corrections applied

- Fixed the broken `/api/nodes` cross-check (`name` → `applications[name=="rabbit"].version`).
- Removed the `< 3.13.0 fails outright` clause (guaranteed FP — the CVEs were introduced in 3.13.0).
- Severity gated on an actual `/api/auth` observation rather than asserted from version.
- Dropped the vacuous `4.3.x < 4.3.0` rule; defined unknown-future-series behaviour as PASS.
- Qualified CVE-2026-57211 scope and re-cited it.

### Source

- https://thehackernews.com/2026/07/rabbitmq-flaws-could-leak-oauth-secrets.html (**secondary**; cve.org returned an empty shell for CVE-2026-57219, and the GitHub security-advisories page renders GHSA titles without CVE ids or version ranges in fetched HTML. **Confirm against the vendor advisory before shipping this rule.**)
- CVE-2026-57211: cve.threatint.com/CVE/CVE-2026-57211 (unverified)
- https://www.rabbitmq.com/docs/http-api-reference (`rabbitmq_version` = "Version of RabbitMQ on the node which processed this request")

**Verified as correct, do not change:** field name `rabbitmq_version`; patched releases 4.3.0 / 4.2.6 / 4.1.11 / 4.0.20 / 3.13.15; CVSS 8.7 for CVE-2026-57219 and 5.3 for CVE-2026-57221; vulnerable endpoint `GET /api/auth`; config key `management.oauth_client_secret`; the secret-rotation advice.

---

## RABBITMQ.VERSION.EOL_SERIES

Broker runs a release series past end of community support

- **Severity:** medium (graded — see below)
- **Kinds:** `broker`, `node`
- **Confidence:** medium
- **False-positive risk:** medium

### Check

`GET /api/overview` → `rabbitmq_version`. Evaluate against the support matrix **as of 2026-07-17**, and surface the as-of date in the finding.

| Series | Community support ends | Commercial | Verdict |
|---|---|---|---|
| 4.3 | 30 Nov 2026 | — | pass |
| 4.2 (LTS) | 31 Jul 2026 | to 30 Jun 2030 | **warn** (flips to fail in 14 days) |
| 4.1 | 31 Jan 2026 | to 30 Apr 2027 | fail — **low** |
| 4.0 | 30 Apr 2025 | — | fail — **medium** |
| 3.13 (LTS) | 30 Sep 2024 | to 31 Dec 2029 | fail — **medium** |
| 3.12 | — | expired 30 Jun 2025 | fail — **high** (no support from anyone) |
| < 3.12 | — | — | fail — **high** |

**Grade the severity; do not flatten it.** One flat medium across 4.1 (EOL 6 months, live commercial track) and 3.11-and-earlier (no support from any party, years stale) is not useful. Low for a series EOL <6 months with a live commercial track; medium for 3.13/4.0; high for series with no support from anyone.

**Commercial suppression must be observable — use patch level as the proxy.** No `/api/overview` field reports licence/edition status: `product_name`/`product_version` exist but are branding-overridable, and `rabbitmq_version` deliberately returns `rabbit:base_product_version()` (base version, not edition). "Suppress if the operator holds a commercial licence" as written depends on operator-supplied annotation the scanner cannot see, so every licensed 3.13/4.2 shop gets a medium by default — and the 3.13 population is disproportionately licensed. Instead:

- **3.13.8 (13 Jan 2025) and later are commercial-only builds** → `3.13.12`–`3.13.17` ⇒ **info**.
- `3.13.<=7` ⇒ **medium**.
- Generalise: for any series past community EOL, **a patch newer than the last community build implies a licence** ⇒ downgrade to info.

**Externalize the date matrix.** These constants are a snapshot with a 14-day fuse — 4.2 flips warn→fail on 31 Jul 2026. Move to a dated, refreshable table keyed to the release-information page, with an explicit as-of date surfaced in findings.

**Cluster flapping.** `rabbitmq_version` is defined as the version of the node that **processed** the request. Behind a load balancer or mid-rolling-upgrade, consecutive scans can return different series and flap the finding. Pin the scan to a single node or reconcile across `GET /api/nodes`.

### Evidence claim

> `GET /api/overview` reports `rabbitmq_version="3.13.7"` (`erlang_version="26.2.5"`); the 3.13 series reached end of community support on 30 Sep 2024. 3.13.7 (Sept 2024) is the final freely-distributed 3.13 binary, so this broker is receiving no security fixes. Support matrix as of 2026-07-17.

**Do not use 3.13.14 as the example.** v3.13.14 was released 17 Mar 2026 — 18 months **after** the 30 Sep 2024 community EOL — and its release notes state "Binary artifacts of this release are only available to customers with a valid commercial support license." The public GitHub tag `v3.13.14` returns 404, corroborating. A broker reporting 3.13.14 is near-certainly a licensed Tanzu customer receiving fixes through 31 Dec 2029 — precisely the case the rule says to suppress to info. It is an argument for suppression, not a medium finding.

### Remediation

Plan an upgrade to a series still under community support (4.3 as of mid-2026, or 4.2 LTS if a commercial licence covers it through 30 Jun 2030). Series past community EOL receive security fixes only for commercial customers, so posture rules that depend on patch availability will keep failing.

### False-positive risk and how to avoid it

Medium.

- **Commercial licence holders** — resolved by the patch-level proxy above.
- **Vendor/distro backports** (hedged — not independently verified). Managed and repackaged brokers can pin an upstream series while backporting security fixes; the broker still reports the upstream series, so the rule fires though patches are reaching it. Worth an allowlist/annotation path; treat as an open FP vector rather than an established one.
- **Cluster flapping** — see check.

### Verifier corrections applied

- Replaced the 3.13.14 evidence example with 3.13.7.
- Made the commercial suppression observable via patch level.
- Graded severity by series instead of a flat medium.
- Required the date matrix to be externalized and dated.
- Added the cluster-flapping note.

### Source

- https://www.rabbitmq.com/release-information — states only "Long term support is available to the users who hold a valid commercial support license"; it does not define how community end dates are derived.
- Broadcom 3.13 release notes (commercial-only artifact statement)
- https://www.rabbitmq.com/docs/http-api-reference (`rabbitmq_version` = version of the node that processed the request)

**Low confidence, unverified on the official page:** secondary sources describe a rolling model where a series' community support ends when the next minor GAs. If true, 4.3's 30 Nov 2026 date could move in early when 4.4 ships — another reason to externalize the matrix.

---

## RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED

ANONYMOUS SASL mechanism enabled

- **Severity:** low
- **Kinds:** `broker`, `user`
- **Confidence:** low (on the identity it maps to)
- **False-positive risk:** medium

### Check

**`auth_mechanisms` IS projected into the HTTP API** — the earlier claim that it is not was wrong.

1. `GET /api/nodes` → `auth_mechanisms` array (`name` / `description` / `enabled` per mechanism). Requires the `monitoring` tag; read-only GET.
2. **If `ANONYMOUS.enabled == false` → do NOT fire at all.** That definitively rules the finding out and eliminates the largest false-positive class.
3. **Fire (low, needs-manual-verification)** if `auth_mechanisms` contains `{name: "ANONYMOUS", enabled: true}`.
4. **Escalate** only when the loopback mitigation is known absent: `loopback_users = none` (or guest removed from it — i.e. `RABBITMQ.USER.GUEST_REMOTE_LOGIN` fired), or `anonymous_login_user` points at a user with no loopback restriction.

Source for the projection: `deps/rabbitmq_management_agent/src/rabbit_mgmt_external_stats.erl` —

```erlang
i(auth_mechanisms, State) ->
    {ok, Mechanisms} = application:get_env(rabbit, auth_mechanisms),
    F = fun (N) -> lists:member(list_to_atom(binary_to_list(N)), Mechanisms) end,
    {State, list_registry_plugins(auth_mechanism, F)};
```

Confirmed in the 4.3 HTTP API reference, which documents `auth_mechanisms` under `/api/nodes` ("List of all SASL authentication mechanisms installed on the node").

**Residual unobservable part (this is why the rule stays needs-manual-verification).** `enabled` is computed purely from list membership in the `auth_mechanisms` env, **not** from `should_offer/1`. So `enabled == true` does not prove ANONYMOUS is actually offered: `rabbit_auth_mechanism_anonymous:credentials/0` requires both `anonymous_login_user` and `anonymous_login_pass` to be **binaries**, so `anonymous_login_user = none` (an atom) makes `should_offer/1` false and the mechanism is never offered. `anonymous_login_user` genuinely has no HTTP projection. So `/api/nodes` confirms ANONYMOUS is **configured**; the identity it maps to still needs `rabbitmq-diagnostics environment` or `rabbitmq.conf` inspection.

**Do NOT use the guest-user proxy.** Checking for `guest` in `/api/users` + version `>= 4.0.0` has a fatal noise property: **the signal does not move when the problem is fixed.** An operator who applies this rule's own remediation (`anonymous_login_user = none`, or removing ANONYMOUS from `auth_mechanisms`) but keeps the guest user for localhost admin would fire the rule forever. Presence of guest in `/api/users` is independent of anonymous config and belongs to `RABBITMQ.USER.DEFAULT_GUEST_PRESENT`, which that proxy duplicates.

### Evidence claim

> `GET /api/nodes` reports `auth_mechanisms` containing `{"name":"ANONYMOUS","enabled":true}` — the ANONYMOUS SASL mechanism is configured on this node. On a default broker it authenticates clients as `anonymous_login_user`, which defaults to `guest`. Whether the mechanism is actually offered depends on `anonymous_login_user`/`anonymous_login_pass`, which have no HTTP API projection — confirm via `rabbitmq-diagnostics environment` or `rabbitmq.conf`.

Do **not** cite `rabbitmq_version="4.2.6"` as the example — that is exactly the **fixed** version for CVE-2026-57216, so it undermines rather than supports the finding.

### Remediation

Set `anonymous_login_user = none` in `rabbitmq.conf` (a real special value meaning no user is configured for anonymous logins) and/or remove ANONYMOUS from the `auth_mechanisms` list. The access-control guide advises: *"For production environments, remove this mechanism."*

**Prefer `anonymous_login_user = none`.** "Deleting the guest user also removes the default anonymous identity" is only half-true: with `anonymous_login_user` still `<<"guest">>`, ANONYMOUS is still **offered** (`should_offer` only checks the values are binaries) and connections then fail at login rather than being cleanly disabled.

### False-positive risk and how to avoid it

Medium, mostly resolved by the `enabled == false` short-circuit. The residual is that `enabled == true` with `anonymous_login_user = none` is a correctly-hardened broker that still fires — hence needs-manual-verification framing and low severity.

### Verifier corrections applied

- **Rewrote the check** — the central premise ("no HTTP API projection" for `auth_mechanisms`) was false.
- **Dropped the guest-user proxy** entirely (duplicate + signal doesn't move on fix).
- **Severity medium → low.** The rule omitted the mitigating default: guest is in `loopback_users` by default, and the loopback check is applied at connection level (`rabbit_auth_mechanism_anonymous.erl` contains no loopback check itself; it calls `rabbit_access_control:check_user_pass_login/2`, with the loopback check applied by the reader afterwards). Advisory GHSA-36m6-588r-vqcw / CVE-2026-57216 (CVSS 6.8) confirms loopback enforcement normally prevents remote guest sessions — it was a vulnerability precisely *because* that enforcement could be bypassed. So on a default broker, ANONYMOUS→guest is exploitable only from localhost. Medium/high is defensible only as an escalation (check step 4), not as the baseline.
- Rewrote the self-undermining evidence claim.

### Source

- https://www.rabbitmq.com/docs/access-control — *"This mechanism is enabled by default allowing anonymous clients to connect without providing any credentials. RabbitMQ will internally authenticate and authorize the client using the credentials configured in anonymous_login_user and anonymous_login_pass (both are set to guest by default)"* and *"For production environments, remove this mechanism."*
- https://www.rabbitmq.com/docs/http-api-reference (`/api/nodes` → `auth_mechanisms`)
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_external_stats.erl`
- `deps/rabbit/Makefile` PROJECT_ENV (`{anonymous_login_user, <<"guest">>}`, `{anonymous_login_pass, <<"guest">>}`)
- `deps/rabbit/priv/schema/rabbit.schema` — `{mapping, "anonymous_login_user", "rabbit.anonymous_login_user", [{datatype, [{enum, [none]}, binary]}]}`. Default `auth_mechanisms` list is PLAIN, AMQPLAIN, ANONYMOUS.

---

## RABBITMQ.ERLANG.DEFAULT_COOKIE

Erlang cookie strength and file permissions cannot be verified from the HTTP API

- **Severity:** info
- **Kinds:** `broker`, `node`
- **Confidence:** low (the scanner has verified nothing)
- **False-positive risk:** high

> **Verdict dependency.** This rule assumes the rulepack has an **unknown/manual disposition that renders separately from actionable findings.** If every emitted finding lands in the same actionable queue, **DROP this rule** and fold the cookie guidance into the remediation of `RABBITMQ.CLUSTER.DIST_PORT_EXPOSED`, which has a genuinely observable trigger.

### Check

The Erlang cookie is **not observable** via the Management HTTP API — the shared secret lives in `.erlang.cookie` and is never projected into any endpoint. Emit as an **unknown / manual-verification** finding.

1. `GET /api/overview` → `listeners`. **Missing key → not-assessable, not a pass** (`rabbit_mgmt_wm_overview.erl` gates the field behind `rabbit_mgmt_util:is_monitor(Tags)`; a `management`-tag-only scan silently never fires). Required tag: `monitoring` or `administrator`.
2. Emit when an element has `protocol` **prefix-matching** `clustering` — i.e. `protocol ∈ {"clustering", "clustering/ssl"}` — AND `ip_address` is non-loopback, matching `"::"` **first** and `"0.0.0.0"` secondarily.
3. Confirm out of band: the cookie is not a default/short/predictable value, and the file is readable only by the OS users running RabbitMQ and CLI tools.

**`"::"` is the default — a matcher comparing literally to `"0.0.0.0"` NEVER fires on a default install.** `maybe_get_epmd_port/2` does not observe the real bind address; it reads `IPAddress = case application:get_env(kernel, inet_dist_use_interface) of {ok, IP} -> IP; _ -> {0,0,0,0,0,0,0,0} end`, which serializes via `rabbit_mgmt_format:ip/1` → `rabbit_misc:ntoa/1` → `inet_parse:ntoa({0,0,0,0,0,0,0,0})` = `"::"`. The IPv4-mapped shortcut at `rabbit_misc.erl:802` requires `16#ffff` in the 6th position and does not apply.

**Match protocol as a set/prefix, not exact `"clustering"`.** With `proto_dist` `inet_tls`/`inet6_tls` the atom is `'clustering/ssl'` (`clustering_tls_enabled/0`, `rabbit_networking.erl:783`). Exact-match misses every TLS-distribution cluster. Optionally lower confidence when `tls == true`.

### Evidence claim

> `GET /api/overview` `listeners[]` shows `{"node":"rabbit@<host>","protocol":"clustering","ip_address":"::","port":25672,"socket_opts":[],"tls":false}`, so a weak or default Erlang cookie would be remotely exploitable if the port is reachable. The cookie value itself is not exposed by any Management HTTP API endpoint and was not verified by this read-only check.

### Remediation

Generate a long random cookie (do not use a default, a hostname-derived value, or a container image's baked-in value), distribute it out of band, and restrict the cookie file to the OS users running RabbitMQ and CLI tools — the production checklist states it is *"necessary to restrict cookie file access only to the OS users that will run RabbitMQ and CLI tools"*, that the cookie must be *"generated in a reasonably secure way (e.g. not computed from an easy to guess value)"*, and warns that deployment automation *"can use default or placeholder values: don't rely on them"*.

Pair with firewalling the distribution port — see `RABBITMQ.CLUSTER.DIST_PORT_EXPOSED`.

**Attribution:** "mode 0600" is **not** stated on the production checklist — it only says access must be restricted to those OS users. Either drop the specific octal or cite https://www.rabbitmq.com/docs/cli, which discusses cookie file permissions. Port 25672 is likewise not named on the checklist page; it is documented on https://www.rabbitmq.com/docs/networking.

### False-positive risk and how to avoid it

**High — the trigger is a near-constant, not a signal.** `ip_address` derives **only** from `kernel inet_dist_use_interface`, which is almost never set (the operator-facing key is `distribution.listener.interface` in `rabbitmq.conf`; the docs say "In order to configure the RabbitMQ inter-node communication listener to listen only on a specific address, use distribution.listener.interface"). So the field reports `"::"` regardless of actual reachability — firewalled hosts, private container networks, NAT and single-node installs all report `"::"`. The clustering listener also registers on standalone non-clustered nodes because the epmd port always exists.

"non-loopback ip_address" is therefore true on ~100% of deployments; the rule narrows nothing and is effectively an unconditional emit. It retains marginal value only because `distribution.listener.interface = 127.0.0.1` correctly suppresses it. **This is why severity is info** — the scanner has verified nothing, and severity must track confidence.

### Verifier corrections applied

- **Severity high → info** (unconditional-fire + nothing verified).
- Fixed the fatal `"0.0.0.0"` evidence/matcher error → `"::"`.
- Protocol match widened to `{clustering, clustering/ssl}`.
- Added the `monitoring`-tag requirement and not-assessable degradation.
- Removed the unsupported "mode 0600" attribution.

### Source

- https://www.rabbitmq.com/docs/production-checklist (cookie access restriction; cookie generation; automation placeholder warning)
- https://www.rabbitmq.com/docs/networking (port 25672)
- https://www.rabbitmq.com/docs/cli (cookie file permissions)
- https://www.rabbitmq.com/docs/http-api-reference (`listeners` = "All (non-HTTP) network listeners for all nodes in the cluster.")
- `deps/rabbit/src/rabbit_networking.erl` (`maybe_get_epmd_port/2`, `clustering_tls_enabled/0`)
- `deps/rabbitmq_management_agent/src/rabbit_mgmt_format.erl` (`listener/1`)
- `deps/rabbitmq_management/src/rabbit_mgmt_wm_overview.erl`
- `deps/rabbit_common/src/rabbit_misc.erl` (`ntoa/1`)

All source paths on branch `main`, 2026-07-17. The `ntoa("::")` result was derived by reading `rabbit_misc:ntoa/1` clauses; no Erlang runtime was available for a live confirmation, but the code path is unambiguous.

---

## Implementation notes

### What the connector must collect

| Request | Auth | Feeds |
|---|---|---|
| `GET /api/auth` | **none** (deliberately unauthenticated) | `CVE.OAUTH_SECRET_DISCLOSURE`; severity gate for `VERSION.UNPATCHED_CVE` |
| `GET /api/whoami` with Basic `guest:guest`, **from a non-loopback source** | probe | `USER.GUEST_REMOTE_LOGIN` |
| `GET /api/whoami` with scanner creds | scanner | scanner self-identification for `USER.ADMIN_TAG_SPRAWL` |
| `GET /api/overview` | `monitoring`+ for `listeners`/`contexts` | `MGMT.HTTP_API_NO_TLS`, `LISTENER.AMQP_PLAINTEXT`, `CLUSTER.DIST_PORT_EXPOSED`, `TLS.*`, `VERSION.*`, `ERLANG.DEFAULT_COOKIE` |
| `GET /api/nodes` | `monitoring`+ | `AUTH.ANONYMOUS_LOGIN_ENABLED` (`auth_mechanisms`), `TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION`, per-node version drift (`applications[name=="rabbit"].version`) |
| `GET /api/users` | **`administrator`** | `USER.DEFAULT_GUEST_PRESENT`, `USER.WEAK_PASSWORD_HASHING`, `USER.ADMIN_TAG_SPRAWL`, tag lookups for `PERMISSION.*`, `VHOST.DEFAULT_VHOST_IN_USE` |
| `GET /api/permissions` | **`administrator`** | `PERMISSION.WILDCARD_ALL`, `PERMISSION.CONFIGURE_WILDCARD`, `VHOST.DEFAULT_VHOST_IN_USE` |
| `GET /api/vhosts` | `monitoring`+ | `VHOST.DEFAULT_VHOST_IN_USE` |

Also record, as connector-level metadata, three things no endpoint reports:

1. **The scheme the scanner used to reach `/api/overview`** (`http://` vs `https://` + cert validity). This is the mandatory suppression signal for `MGMT.HTTP_API_NO_TLS`.
2. **The scanner's own source address** (loopback vs not). `USER.GUEST_REMOTE_LOGIN` is invalid from loopback.
3. **The as-of date of the EOL matrix** — surfaced in `VERSION.EOL_SERIES` findings.

### Three-state result model (non-negotiable)

Every rule must emit one of **PASS / FAIL / NOT-ASSESSABLE**. Two-state is a fail-open defect here, because RabbitMQ gates payload *fields* on tags rather than rejecting the request:

- `listeners` / `contexts` absent from `/api/overview` → the credential lacks `monitoring`/`administrator`, or `management.disable_stats = true`. **Not-assessable.**
- 401/403 on `/api/users` or `/api/permissions` → the credential lacks `administrator`. **Not-assessable.**
- A principal in `/api/permissions` missing from `/api/users` → external auth backend. **Unknown**, not "untagged".

Surface the required tag per rule in the not-assessable message so operators can fix the scanner credential rather than trusting a clean report.

### Normalisation helpers to implement once

- **`tags`** — JSON array (3.9+) or comma-separated string (older). Normalise on read. Note `PUT` still takes comma-separated; irrelevant here (read-only) but do not "fix" it either way.
- **Wildcard regex predicate** — literal `.*` and `^.*$`. Documented false negatives: `^.*`, `.*$`, `(.*)`, `.+`, `.`, `a|.*` (RabbitMQ matches unanchored, so these are equivalent). Deliberate low-FP choice; consider a matches-everything predicate if FN tolerance is lower than FP tolerance.
- **Wildcard-bind address set** — `{"0.0.0.0", "::"}`. Prefer `"::"` in evidence samples for `clustering` (it is the hardcoded default); prefer `"0.0.0.0"` for AMQP. Never use "not loopback" as the match — it fires on normal private binds.
- **TLS detection on a listener** — primary `tls == true`; fallback (older brokers) `protocol` ends `/ssl` OR `socket_opts` contains any of `ssl_opts`/`certfile`/`keyfile`/`cacertfile`.
- **TLS detection on a context** — primary `ssl == true`; corroborate with non-empty `ssl_opts`. `ssl_opts` is always present; absence means `contexts` itself is absent.
- **`verify` lookup** — check both `socket_opts.verify` (flat, amqp/ssl) and `socket_opts.ssl_opts.verify` (nested, ranch/web). For contexts, top-level `ssl_opts.verify`.
- **Version compare** — semver on `rabbitmq_version`; per-series patched floor table; unknown-future-series ⇒ PASS.
- **Offline password verification** — salt-prefixed digest, base64; honour the per-user `hashing_algorithm`. Used only by `USER.DEFAULT_GUEST_PRESENT`.

### Dedup and rule interaction

- **Cluster fan-out:** `rabbit_networking:active_listeners/0` appends `node_listeners(Node)` for **every** running node, so an N-node cluster yields N identical listener findings; dual-stack adds a second entry per node. **Group by `(protocol, port)`, report once, list affected nodes.** Applies to `LISTENER.AMQP_PLAINTEXT`, `CLUSTER.DIST_PORT_EXPOSED`, `ERLANG.DEFAULT_COOKIE`, `TLS.*`.
- **`PERMISSION.CONFIGURE_WILDCARD` suppresses when `PERMISSION.WILDCARD_ALL` fired** on the same `(user, vhost)` pair.
- **`USER.GUEST_REMOTE_LOGIN` and `USER.DEFAULT_GUEST_PRESENT` are mutually exclusive** on the loopback-blocked 401 path; GUEST_REMOTE_LOGIN firing is also the escalation signal for DEFAULT_GUEST_PRESENT → critical and for `AUTH.ANONYMOUS_LOGIN_ENABLED` escalation.
- **`CVE.OAUTH_SECRET_DISCLOSURE` firing is the escalation signal** for `VERSION.UNPATCHED_CVE` (medium → high).
- **`TLS.PEER_VERIFICATION_DISABLED` and `TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION` are mutually exclusive**, split on `EXTERNAL ∈ enabled auth_mechanisms`.
- **`ERLANG.DEFAULT_COOKIE` requires an unknown/manual disposition** or it should be dropped and folded into `CLUSTER.DIST_PORT_EXPOSED` remediation.

### Suppression/waiver toggles the connector must expose per target

1. **`proxy_terminates_tls`** — suppresses `MGMT.HTTP_API_NO_TLS`. The K8s/nginx pattern is doc-endorsed and undetectable from the API.
2. **`transparent_tls_mesh`** — suppresses `LISTENER.AMQP_PLAINTEXT`. Istio/Linkerd sidecar mTLS and TLS-terminating LBs leave `tls=false` while the wire is encrypted.
3. **`backported_build`** — suppresses `VERSION.UNPATCHED_CVE` / `VERSION.EOL_SERIES` version-string matching. Distro and Tanzu builds patch without bumping the upstream string.
4. **`external_auth_backend`** — suppresses/reframes `USER.ADMIN_TAG_SPRAWL` and `USER.DEFAULT_GUEST_PRESENT` scope claims. `/api/users` only sees the internal store.
5. **`environment_scope`** (production vs dev/CI) — gates `USER.DEFAULT_GUEST_PRESENT`. Every Docker/CI broker ships guest.
6. **`provisioning_accounts` allowlist** — exempts topology/migration service accounts from `PERMISSION.CONFIGURE_WILDCARD`.
7. **`managed_provider`** (e.g. Amazon MQ) — downgrades `USER.ADMIN_TAG_SPRAWL`.
8. **`reachability_signal`** — an external corroboration input. Its **presence** escalates (`LISTENER.AMQP_PLAINTEXT` medium → high, `CLUSTER.DIST_PORT_EXPOSED` low → higher); its absence is why those rules are capped where they are. The management API can never establish reachability on its own.

### Coverage gaps to revisit against a live broker

- **TLS deprecated versions** (`ssl_options.versions` containing `tlsv1`/`tlsv1.1`) — a rule was planned and **dropped**, because it could not be confirmed that `versions` survives `format_socket_opts` serialisation into the API response. There is a known history of cipher/TLS values failing to serialise on this endpoint. Worth revisiting with a real broker.
- **epmd (4369)** — needs a port scan; outside this pack's read-only-admin-API boundary.
- **`loopback_users`, `anonymous_login_user`, Erlang cookie** — need `rabbitmq-diagnostics environment`, config-file access, or filesystem access. If the product later ships an agent or an SSH collector, these three become directly checkable and `AUTH.ANONYMOUS_LOGIN_ENABLED` / `ERLANG.DEFAULT_COOKIE` graduate from manual-verification to real rules.
- **Field-shape verification on release tags.** Everything here was read from `main` (4.3-era). Shapes on 3.13 / 4.0–4.2 tags are assumed identical but unverified — medium confidence. Validate against a 3.13 broker before claiming support for that series.

### Before shipping

`VERSION.UNPATCHED_CVE` and `CVE.OAUTH_SECRET_DISCLOSURE` rest on **thehackernews.com**, a secondary source, for version ranges. cve.org returned an empty shell for CVE-2026-57219, and the GitHub security-advisories page renders GHSA titles without CVE ids or version ranges in fetched HTML (the 9 Jul 2026 batch is visible but unmapped). Several independent outlets agree, and GHSA-pj24-8j6m-vq9q's ranges were obtained separately — **confirm against the vendor advisory before shipping.** CVE-2026-57211 came from an unfetched search snippet; it appears only in remediation prose, never as a check, and should be treated as unverified.
