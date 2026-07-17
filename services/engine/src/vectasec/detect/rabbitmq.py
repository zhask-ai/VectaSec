"""RabbitMQ rulepack — everything here is read from the Management HTTP API.

Two structural facts about that API drive most of the code below:

  • Authorization gates the *payload*, not the request. `/api/overview` returns `listeners`
    and `contexts` only to a `monitoring`/`administrator` credential, and omits them entirely
    when `management.disable_stats = true`. A missing key therefore means "not assessable",
    never "no listeners" — every rule here returns [] on absence and the gap is reported once
    by RABBITMQ.SCAN.NOT_ASSESSABLE. Mapping absence to PASS is the fail-open defect this
    rulepack exists to avoid.
  • `listeners`/`contexts` are cluster-wide (active_listeners/0 appends every running node's
    listeners, and dual-stack adds a second entry per node). Listener rules therefore hang off
    the single `cluster` resource and group by (protocol, port), or one real issue would arrive
    N times. Per-node facts (`auth_mechanisms`) hang off the per-node resources instead.

A finding is fingerprinted on (tenant, rule_id, ext_id), so a detector must return at most ONE
Hit per resource — several Hits would collapse into one finding row. Rules that can match many
listeners aggregate into a single Hit that lists every match.
"""
import json
from datetime import date

from ..registry import detector
from ..contracts import Hit

# Never "not loopback": that fires on `listeners.tcp.1 = 10.0.1.5:5672`, a normal private-VPC
# bind, and is materially noisier than matching the all-interfaces binds themselves.
_WILDCARD_BINDS = ("0.0.0.0", "::")
_LOOPBACK_IPS = ("127.0.0.1", "::1")
# Deliberate low-FP choice. RabbitMQ matches unanchored, so `^.*`, `.*$`, `(.*)`, `.+`, `.`
# and `a|.*` are equivalent and are known, accepted false negatives.
_WILDCARD_PERMS = (".*", "^.*$")
_MGMT_CONTEXT = "RabbitMQ Management"
_TLS_OPT_KEYS = ("ssl_opts", "cacertfile", "certfile", "keyfile")
_KNOWN_HASH_MODS = ("rabbit_password_hashing_sha256", "rabbit_password_hashing_sha512",
                    "rabbit_password_hashing_md5")

# ── Version tables ────────────────────────────────────────────────────────
# Both CVEs were introduced in 3.13.0; a 3.12.x broker is not exposed, so UNPATCHED_CVE must
# not fire below that floor. Series above the table (4.3+) ship the fix.
_CVE_FLOOR = {(3, 13): 15, (4, 0): 20, (4, 1): 11, (4, 2): 6}

# Dated snapshot with a fuse: 4.2 reaches community EOL on 2026-07-31. Refresh against
# https://www.rabbitmq.com/release-information — the as-of date is surfaced in every finding.
_EOL_AS_OF = date(2026, 7, 17)
# series -> (community_eol, commercial_eol, last_community_patch, severity_once_eol)
_EOL_MATRIX = {
    (4, 3): (date(2026, 11, 30), None, None, None),
    (4, 2): (date(2026, 7, 31), date(2030, 6, 30), None, "low"),
    (4, 1): (date(2026, 1, 31), date(2027, 4, 30), None, "low"),
    (4, 0): (date(2025, 4, 30), None, None, "medium"),
    (3, 13): (date(2024, 9, 30), date(2029, 12, 31), 7, "medium"),
}


# ── Shared helpers ────────────────────────────────────────────────────────
def _cluster(ctx):
    for r in ctx.resources:
        if r.kind == "node" and r.raw.get("role") == "cluster":
            return r
    return None


def _overview(resource):
    """Cluster-wide rules run only on the cluster resource; per-node resources carry no overview."""
    if resource.raw.get("role") != "cluster":
        return None
    return resource.raw.get("overview") or None


def _toggle(resource, name):
    if resource is None:
        return None
    return (resource.raw.get("toggles") or {}).get(name)


def _listener_has_tls(listener: dict) -> bool:
    """Primary signal is the `tls` boolean. Older brokers omit it, so fall back to
    rabbit_networking:has_tls_enabled/2's own logic instead of assuming plaintext."""
    tls = listener.get("tls")
    if isinstance(tls, bool):
        return tls
    if (listener.get("protocol") or "").endswith("/ssl"):
        return True
    opts = listener.get("socket_opts")
    return isinstance(opts, dict) and any(k in opts for k in _TLS_OPT_KEYS)


def _verify_of(listener: dict):
    """(value, path). start_ssl_listener/4 registers a FLAT proplist for amqp/ssl while
    ranch/web listeners nest under socket_opts.ssl_opts — reading one shape misses half of
    them. Absent is strong evidence of unset: `verify` is not in format_socket_opts' drop
    list, and with no schema default the OTP server default (verify_none) applies."""
    opts = listener.get("socket_opts")
    if not isinstance(opts, dict):
        return None, "socket_opts.verify"
    if "verify" in opts:
        return opts.get("verify"), "socket_opts.verify"
    nested = opts.get("ssl_opts")
    if isinstance(nested, dict) and "verify" in nested:
        return nested.get("verify"), "socket_opts.ssl_opts.verify"
    return None, "socket_opts.verify"


def _fail_if_no_peer_cert(listener: dict):
    opts = listener.get("socket_opts")
    if not isinstance(opts, dict):
        return None
    if "fail_if_no_peer_cert" in opts:
        return opts.get("fail_if_no_peer_cert")
    nested = opts.get("ssl_opts")
    return nested.get("fail_if_no_peer_cert") if isinstance(nested, dict) else None


def _brief(listener: dict) -> str:
    """The listener fields the evidence quotes — server values verbatim, nothing derived."""
    keys = ("node", "protocol", "ip_address", "port", "tls")
    return json.dumps({k: listener.get(k) for k in keys if k in listener})


def _group(listeners, keep) -> dict:
    """Group by (protocol, port): active_listeners/0 appends node_listeners(Node) for every
    running node, so an N-node cluster reports one issue N times."""
    out = {}
    for listener in listeners:
        if keep(listener):
            out.setdefault((listener.get("protocol"), listener.get("port")), []).append(listener)
    return out


def _nodes_of(group) -> str:
    return ", ".join(sorted({str(x.get("node")) for x in group}))


def _mgmt_contexts(ov) -> list:
    """rabbit_mgmt_app.erl registers BOTH the TCP and TLS contexts under this identical
    description literal, and TCP+TLS may run simultaneously — a singular lookup is wrong."""
    return [c for c in (ov.get("contexts") or []) if c.get("description") == _MGMT_CONTEXT]


def _context_has_tls(context: dict) -> bool:
    """`ssl: true` is emitted only by get_tls_listener/0 — primary. Non-empty ssl_opts
    corroborates. ssl_opts is always present on a returned context, so emptiness is a real
    observation; its absence would mean `contexts` itself is missing."""
    return context.get("ssl") is True or bool(context.get("ssl_opts"))


def _context_verify(context: dict):
    """web_context/1 puts ssl_opts at the TOP level of a context, not under socket_opts. An
    empty proplist serialises as [], not {}, so the shape must be checked before reading."""
    opts = context.get("ssl_opts")
    return opts.get("verify") if isinstance(opts, dict) else None


def _tags_of(ctx, username):
    """(tags, known). "Absent from /api/users" is NOT "has no tags": that endpoint lists only
    the internal data store, so an LDAP/OAuth principal legitimately holds permissions with no
    user record. Callers must treat unknown as unknown."""
    for r in ctx.resources:
        if r.kind == "user" and r.raw.get("name") == username:
            return r.raw.get("tags") or [], True
    return [], False


def _is_wildcard(pattern) -> bool:
    return pattern in _WILDCARD_PERMS


def _external_enabled(ctx):
    """(enabled, known) for the EXTERNAL SASL mechanism. auth_mechanisms is projected on
    /api/nodes, not /api/overview."""
    known = False
    for r in ctx.of_kind("node"):
        mechs = r.raw.get("auth_mechanisms")
        if mechs is None:
            continue
        known = True
        for m in mechs:
            if m.get("name") == "EXTERNAL" and m.get("enabled"):
                return True, True
    return False, known


def _parse_version(raw):
    if not isinstance(raw, str):
        return None
    try:
        nums = [int(p) for p in raw.split("-")[0].split(".")[:3]]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums)


def _version_of(resource):
    """rabbitmq_version is base_product_version(); product_version is branding-overridable."""
    ov = resource.raw.get("overview") or {}
    raw = ov.get("rabbitmq_version") or ov.get("product_version")
    return _parse_version(raw), raw


def _drift_note(resource, raw_version) -> str:
    """rabbitmq_version is the version of the node that PROCESSED the request; behind a load
    balancer or mid-rolling-upgrade consecutive scans can disagree."""
    versions = resource.raw.get("node_versions") or {}
    distinct = set(versions.values())
    if len(distinct) > 1:
        return (f" Per-node versions from GET /api/nodes applications[name==\"rabbit\"] "
                f"disagree ({json.dumps(versions, sort_keys=True)}), so this cluster is "
                f"mid-upgrade or load-balanced; the reported {raw_version!r} is only the node "
                f"that served this request.")
    return ""


# ── CVE / credential probes ───────────────────────────────────────────────
@detector(kinds=["node"], rule_id="RABBITMQ.CVE.OAUTH_SECRET_DISCLOSURE", severity="high",
          title="Obsolete GET /api/auth endpoint discloses OAuth 2 client secret to "
                "unauthenticated callers (CVE-2026-57219)")
def oauth_secret_disclosure(resource, ctx) -> list:
    if resource.raw.get("role") != "cluster":
        return []
    probe = (resource.raw.get("probes") or {}).get("auth") or {}
    # filter_empty_properties/1 omits the key when unset, so 200 + present + non-empty is the
    # server's own predicate. 404 = patched or endpoint absent. Nothing else is a disclosure.
    if probe.get("status") != 200 or not probe.get("oauth_client_secret_present"):
        return []

    raw_version = (resource.raw.get("overview") or {}).get("rabbitmq_version")
    # A 200 with a non-empty secret is dispositive on its own. Version is advisory only: an
    # unreadable or vendor-mangled version must never suppress the finding.
    version_clause = (
        f"; broker reports rabbitmq_version={raw_version!r}" if raw_version
        else "; /api/overview was not readable, so the version is not corroborated"
    )
    return [Hit(
        observation=(
            f"Unauthenticated GET /api/auth (no Authorization header) returned HTTP 200 with a "
            f"non-empty top-level oauth_client_secret field. Response keys were "
            f"{json.dumps(probe.get('keys'))}, oauth_enabled={probe.get('oauth_enabled')!r}, "
            f"oauth_client_id={probe.get('oauth_client_id')!r}{version_clause}. The secret's "
            f"value is deliberately not recorded — its presence in an unauthenticated response "
            f"is the observation. CVE-2026-57219 (CVSS 8.7)."
        ),
        remediation=(
            "Upgrade to 4.3.0, 4.2.6, 4.1.11, 4.0.20 or 3.13.15+, which remove the /api/auth "
            "endpoint. Patching does not undo the disclosure: if the endpoint was ever reachable "
            "while a client secret was configured, treat the secret as compromised and rotate "
            "management.oauth_client_secret at the identity provider regardless of current patch "
            "status. If immediate patching is impossible, switch to an OAuth 2 grant type that "
            "needs no client secret (RabbitMQ's recommended management-UI config is a PKCE public "
            "client), restrict network access to port 15672, or disable the management/OAuth 2 "
            "plugins."
        ),
        detail=("Fires on a placeholder secret in dev/test, and on a secret configured but unused "
                "by the active grant type. Both are reported: the value is genuinely served to "
                "unauthenticated callers either way."),
        source_ref={"api": "/api/auth", "config_key": "management.oauth_client_secret",
                    "cve": "CVE-2026-57219"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.USER.GUEST_REMOTE_LOGIN", severity="critical",
          title="Default guest/guest account authenticates from a remote host")
def guest_remote_login(resource, ctx) -> list:
    if resource.raw.get("role") != "cluster":
        return []
    probe = (resource.raw.get("probes") or {}).get("guest_whoami") or {}
    if probe.get("status") != 200 or probe.get("name") != "guest":
        return []

    return [Hit(
        # Tags are echoed verbatim: guest may legitimately carry a non-administrator
        # management tag, so hardcoding ["administrator"] would be a fabricated observation.
        observation=(
            f"GET /api/whoami with HTTP Basic guest:guest, issued from a non-loopback source "
            f"address, returned HTTP 200 and "
            f"{json.dumps({'name': probe.get('name'), 'tags': probe.get('tags'), 'is_internal_user': probe.get('is_internal_user')})}"
            f" — the default account with default credentials is reachable and "
            f"management-authorized from this source address. The root cause is either a "
            f"loopback_users relaxation or a loopback-appearing proxy hop in front of the "
            f"management listener; this check observes the 200, not which one."
        ),
        remediation=(
            "Confirm the root cause first. If loopback_users was relaxed, restore the shipped "
            "default with `loopback_users.guest = true` in rabbitmq.conf. Do NOT write "
            "`loopback_users = guest` — the bare key accepts only the literal `none` per "
            "rabbit.schema, so that line fails cuttlefish validation and the node refuses to "
            "boot. Preferably delete the guest user entirely and create per-application users "
            "with generated credentials. Never set `loopback_users = none` on an internet- or "
            "LAN-reachable node. If instead a reverse proxy co-located on the RabbitMQ host is "
            "presenting 127.0.0.1 as the peer, fix it there: the management listener has no "
            "proxy_protocol support, so the broker cannot see the real client address."
        ),
        detail=("The management listener always sees the real TCP peer (no proxy_protocol "
                "support), so a co-located nginx/HAProxy/Traefik makes guest authenticate for "
                "remote clients with loopback_users fully intact. The 200 from a remote client "
                "is real either way; only the remediation branches."),
        source_ref={"api": "/api/whoami", "config_key": "loopback_users.guest"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.USER.GUEST_DEFAULT_PASSWORD_REMOTE", severity="high",
          title="Default guest/guest credentials accepted from a remote host "
                "(guest carries no management tag)")
def guest_default_password_remote(resource, ctx) -> list:
    """The false negative GUEST_REMOTE_LOGIN structurally cannot catch. is_mgmt_user is checked
    AFTER check_user_loopback, so this reason proves the password AND the loopback bypass — it
    is only invisible to the rule above because guest lacks a management tag."""
    if resource.raw.get("role") != "cluster":
        return []
    probe = (resource.raw.get("probes") or {}).get("guest_whoami") or {}
    if probe.get("status") != 401 or probe.get("reason") != "Not management user":
        return []

    return [Hit(
        observation=(
            "GET /api/whoami with HTTP Basic guest:guest, issued from a non-loopback source "
            "address, returned HTTP 401 with reason \"Not management user\". That reason is "
            "reached only after the password check and the loopback check both pass, so the "
            "guest account still has its default password and the loopback restriction is not "
            "in effect for this source address; the request was refused only because guest "
            "carries no management tag. AMQP and other protocol listeners apply no such tag "
            "check."
        ),
        remediation=(
            "Restore `loopback_users.guest = true` in rabbitmq.conf (the shipped default), or "
            "preferably delete the guest user entirely and create per-application users with "
            "generated credentials. Do NOT write `loopback_users = guest` — the bare key accepts "
            "only the literal `none` and the node will refuse to boot. As with "
            "RABBITMQ.USER.GUEST_REMOTE_LOGIN, confirm whether a co-located reverse proxy is "
            "presenting 127.0.0.1 as the peer before changing loopback_users."
        ),
        detail=("Severity is this rulepack's own assignment: the spec mandates a distinct "
                "finding for this response but assigns no severity. Rated high rather than "
                "critical because management-plane access was refused; data-plane listeners "
                "remain reachable with the default credentials."),
        source_ref={"api": "/api/whoami", "config_key": "loopback_users.guest"},
    )]


# ── Users ─────────────────────────────────────────────────────────────────
@detector(kinds=["user"], rule_id="RABBITMQ.USER.DEFAULT_GUEST_PRESENT", severity="medium",
          title="Default guest user still exists in the internal user store")
def default_guest_present(resource, ctx) -> list:
    if resource.raw.get("name") != "guest":
        return []
    cluster = _cluster(ctx)
    scope = _toggle(cluster, "environment_scope")
    # Every Docker/CI broker ships guest; outside production scope this is volume, not signal.
    if scope and str(scope).lower() not in ("production", "prod"):
        return []

    confirmed = resource.raw.get("default_password_confirmed")
    probe = ((cluster.raw.get("probes") if cluster else None) or {}).get("guest_whoami") or {}
    remote = probe.get("status") == 200 and probe.get("name") == "guest"

    observation = (
        f"GET /api/users returned an element with name=\"guest\", "
        f"tags={json.dumps(resource.raw.get('tags'))}, "
        f"hashing_algorithm={resource.raw.get('hashing_algorithm')!r} — the well-known default "
        f"account has not been deleted from the internal user store. This endpoint lists only "
        f"the internal data store; identities from an LDAP or OAuth backend are not included."
    )
    # The administrator tag is guest's DEFAULT tag, so escalating on it would be "critical
    # whenever guest exists" wearing a conditional. Only a discriminating signal escalates.
    if confirmed:
        observation += (" Offline verification of the stored password_hash against the reported "
                        "hashing_algorithm confirms the password is still the default \"guest\".")
    elif confirmed is False:
        observation += (" Offline verification of the stored password_hash shows the password is "
                        "no longer the default \"guest\".")
    if remote:
        observation += (" A guest:guest GET /api/whoami probe from a non-loopback source returned "
                        "HTTP 200, so the loopback restriction is not in effect.")

    return [Hit(
        observation=observation,
        remediation=(
            "Per the production checklist, delete the default guest user. Create a separate user "
            "per application with generated credentials and scoped vhost permissions first, then "
            "delete guest. Deleting guest also neutralises the ANONYMOUS mechanism's default "
            "identity, since anonymous_login_user defaults to guest — but prefer setting "
            "`anonymous_login_user = none` explicitly (see "
            "RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED), because leaving it pointed at a deleted "
            "guest still offers the mechanism and merely fails the login."
        ),
        severity="critical" if (confirmed or remote) else None,
        detail=("Escalates to critical only on a discriminating signal: an offline hash check "
                "proving the default password, or a confirmed remote guest login. Presence alone "
                "is medium because guest is loopback-restricted on a default broker."),
        source_ref={"api": "/api/users", "config_key": "default_user"},
    )]


@detector(kinds=["user"], rule_id="RABBITMQ.USER.WEAK_PASSWORD_HASHING", severity="medium",
          title="User password stored with the legacy MD5 hashing module")
def weak_password_hashing(resource, ctx) -> list:
    algo = resource.raw.get("hashing_algorithm")
    # An empty password_hash is how a password is cleared — the user authenticates via an
    # external backend and nothing is hashed here.
    if not algo or not resource.raw.get("has_internal_password"):
        return []

    if algo == "rabbit_password_hashing_md5":
        return [Hit(
            observation=(
                f"GET /api/users returned {json.dumps({'name': resource.raw.get('name'), 'hashing_algorithm': algo})} "
                f"with a non-empty password_hash (value deliberately not recorded) — the "
                f"credential is hashed with MD5, retained only for backwards compatibility. "
                f"Either password_hashing_module is set to MD5, or the user record predates "
                f"3.6.0 and has no recorded algorithm, in which case rabbit_password:hashing_mod/1 "
                f"falls back to MD5 for that user regardless of configuration."
            ),
            remediation=(
                "Set `password_hashing_module = rabbit_password_hashing_sha256` (or "
                "rabbit_password_hashing_sha512) in rabbitmq.conf. Changing the module does not "
                "rehash existing credentials — this user's password must be reset after the "
                "change for the new algorithm to take effect. If the record predates 3.6.0 and "
                "has no recorded algorithm, you will find no MD5 setting in your config: "
                "resetting the user's password is then both required and sufficient."
            ),
            detail=("Rated medium, not high: reading this field already requires the administrator "
                    "tag, so the residual risk is offline cracking and password reuse elsewhere. "
                    "The uplift is also modest — rabbit_password uses a 4-byte salt and a "
                    "single-iteration digest, so sha256/sha512 are fast non-KDF hashes too. It "
                    "stays above low because MD5 is a hard FIPS/PCI failure and reliably indicates "
                    "credentials never rotated since 3.5.x."),
            source_ref={"api": "/api/users", "config_key": "password_hashing_module"},
        )]

    if algo not in _KNOWN_HASH_MODS:
        # hashing_mod(CustomMod) when is_atom(CustomMod) -> CustomMod explicitly permits plugin
        # modules, which may be STRONGER than sha256 (bcrypt/argon2). Info, never a fail.
        return [Hit(
            observation=(
                f"GET /api/users returned {json.dumps({'name': resource.raw.get('name'), 'hashing_algorithm': algo})} "
                f"— a hashing module outside RabbitMQ's built-in set "
                f"({', '.join(_KNOWN_HASH_MODS)}). RabbitMQ permits plugin-supplied hashing "
                f"modules, so this may be stronger than the sha256 default; the scanner cannot "
                f"tell from the module name alone."
            ),
            remediation=("Confirm the plugin supplying this module is intentional and at least as "
                         "strong as rabbit_password_hashing_sha256. No action if so."),
            severity="info",
            source_ref={"api": "/api/users", "config_key": "password_hashing_module"},
        )]
    return []


@detector(kinds=["node"], rule_id="RABBITMQ.USER.ADMIN_TAG_SPRAWL", severity="low",
          title="Excessive number of users carrying the administrator tag")
def admin_tag_sprawl(resource, ctx) -> list:
    if resource.raw.get("role") != "cluster":
        return []
    if resource.raw.get("users_error"):
        return []
    # /api/users sees only the internal store; on an LDAP/OAuth broker it holds a handful of
    # break-glass accounts that are legitimately all admin-tagged.
    if _toggle(resource, "external_auth_backend"):
        return []

    users = ctx.of_kind("user")
    total = len(users)
    if total <= 4:
        return []

    # /api/users is administrator-gated, so the scanning credential MUST carry administrator
    # and would otherwise inflate its own count by one.
    scanner = ((resource.raw.get("scanner") or {}).get("whoami") or {}).get("name")
    admins = sorted(u.raw.get("name") for u in users
                    if "administrator" in (u.raw.get("tags") or [])
                    and u.raw.get("name") != scanner)
    n = len(admins)
    # AND, not OR: the absolute clause alone fires on legitimate 5-user brokers with 3
    # operators, and the >4-user gate does not save it.
    if not (n > 2 and n / total > 0.25):
        return []

    excluded = (f" (count excludes the scanning identity {scanner!r})" if scanner
                else " (the scanning identity could not be identified via GET /api/whoami and is "
                     "NOT excluded from this count)")
    return [Hit(
        observation=(
            f"GET /api/users returned {total} users, of which {n} carry tags containing "
            f"\"administrator\" ({', '.join(admins)}) — {n / total:.0%} of identities in the "
            f"internal user store can create and delete virtual hosts, users and permissions "
            f"cluster-wide, and close other users' connections{excluded}."
        ),
        remediation=(
            "Downgrade dashboard-only identities to `management`, metrics scrapers to "
            "`monitoring`, and policy automation to `policymaker`. Reserve `administrator` for a "
            "small, named set of break-glass operators. Note that normal resource permissions "
            "still apply to administrators — the tag does not by itself grant access to "
            "exchanges, queues and bindings, though an administrator can grant it to themselves."
        ),
        severity="info" if _toggle(resource, "managed_provider") else None,
        detail=("Thresholds (>2 admins AND >25% of users, on a broker with >4 users) are "
                f"engineering judgement — RabbitMQ publishes no numeric guidance. As of "
                f"{_EOL_AS_OF.isoformat()}, expect to tune per environment."),
        source_ref={"api": "/api/users"},
    )]


# ── Permissions ───────────────────────────────────────────────────────────
@detector(kinds=["permission"], rule_id="RABBITMQ.PERMISSION.WILDCARD_ALL", severity="medium",
          title="User granted unrestricted .* permissions on configure, write and read for a vhost")
def permission_wildcard_all(resource, ctx) -> list:
    triple = (resource.raw.get("configure"), resource.raw.get("write"), resource.raw.get("read"))
    if not all(_is_wildcard(p) for p in triple):
        return []

    user, vhost = resource.raw.get("user"), resource.raw.get("vhost")
    tags, known = _tags_of(ctx, user)
    # Same rule as PERMISSION.CONFIGURE_WILDCARD: "user not found" is not "has no administrator
    # tag". Without this the observation below states tags=[] as a fact read from /api/users for
    # a principal that endpoint never returned — an LDAP/OAuth identity, or every identity when
    # /api/users 401s. SCAN.NOT_ASSESSABLE already reports that gap.
    if not known:
        return []
    # Suppress on administrator only. policymaker is orthogonal to resource permissions — it
    # grants policy/parameter management, not resource wildcards, and apps are legitimately
    # tagged policymaker to manage their own policies.
    if "administrator" in tags:
        return []

    # Tenancy gate. The vhost IS RabbitMQ's isolation boundary and vhost-per-application is
    # the dominant pattern, so a wildcard only crosses a trust boundary when someone else
    # holds permissions in the same vhost.
    principals = {r.raw.get("user") for r in ctx.of_kind("permission")
                  if r.raw.get("vhost") == vhost}
    non_admin = sorted(u for u in principals if "administrator" not in _tags_of(ctx, u)[0])
    multi_tenant = len(non_admin) >= 2

    tenancy = (
        f"{len(non_admin)} non-administrator principals hold permissions in this vhost "
        f"({', '.join(non_admin)}), so the grant crosses a trust boundary."
        if multi_tenant else
        f"This vhost has only {len(non_admin)} non-administrator principal "
        f"({', '.join(non_admin) or 'none'}), so the blast radius is the vhost itself."
    )
    return [Hit(
        observation=(
            f"GET /api/permissions returned "
            f"{json.dumps({'user': user, 'vhost': vhost, 'configure': triple[0], 'write': triple[1], 'read': triple[2]})}"
            f" and GET /api/users shows that user with tags={json.dumps(tags)} — a non-admin "
            f"identity can create, destroy and reconfigure every resource in the vhost and read "
            f"every queue. {tenancy}"
        ),
        remediation=(
            "Replace the wildcard triple with regexes scoped to the resource names the "
            "application actually uses, and include the server-generated and default-exchange "
            "names or you will cause an outage:\n"
            "  configure = ^(app-name-.*|amq\\.gen.*)$\n"
            "  write     = ^(app-name-.*|amq\\.default|amq\\.gen.*)$\n"
            "  read      = ^(app-name-.*|amq\\.gen.*)$\n"
            "A bare `^app-name-.*` breaks any client declaring server-generated or exclusive "
            "queues or publishing via the default exchange (Celery, Spring AMQP, MassTransit, "
            "NServiceBus, any RPC/reply-to client). The safe floor is `^$` — despite reading "
            "like a wildcard, it DENIES everything; start there and widen deliberately. Use a "
            "separate user per application."
        ),
        severity=None if multi_tenant else "info",
        detail=("Confined to one vhost, requires already-valid credentials, and confers no "
                "cross-vhost or management-plane reach (that needs tags, not permissions) — "
                "least-privilege hygiene rather than an exploitable vulnerability. Escalation to "
                "high additionally requires the identity to be provably remotely reachable, "
                "which the Management API cannot establish."),
        source_ref={"api": "/api/permissions"},
    )]


@detector(kinds=["permission"], rule_id="RABBITMQ.PERMISSION.CONFIGURE_WILDCARD", severity="medium",
          title="Application user holds wildcard configure permission on a vhost")
def permission_configure_wildcard(resource, ctx) -> list:
    configure = resource.raw.get("configure")
    write, read = resource.raw.get("write"), resource.raw.get("read")
    if not _is_wildcard(configure):
        return []
    # RABBITMQ.PERMISSION.WILDCARD_ALL owns the all-three case on this (user, vhost) pair.
    if _is_wildcard(write) and _is_wildcard(read):
        return []

    user, vhost = resource.raw.get("user"), resource.raw.get("vhost")
    tags, known = _tags_of(ctx, user)
    # Never read "user not found" as "has no administrator/policymaker tag": with external
    # authn and internal authz the principal simply is not in the internal store.
    if not known:
        return []
    if "administrator" in tags or "policymaker" in tags:
        return []

    allowlist = _toggle(_cluster(ctx), "provisioning_accounts") or []
    if user in allowlist:
        return []

    return [Hit(
        # Deliberately does NOT claim bindings: queue.bind/exchange.bind need write+read, not
        # configure, so with narrower write/read this user cannot touch arbitrary bindings.
        observation=(
            f"GET /api/permissions returned "
            f"{json.dumps({'user': user, 'vhost': vhost, 'configure': configure, 'write': write, 'read': read})}"
            f" and GET /api/users shows that user with tags={json.dumps(tags)} — the user's "
            f"publish/consume scope is constrained, but it can still declare or delete any queue "
            f"or exchange in the vhost, destroying other applications' queues and the messages "
            f"in them."
        ),
        remediation=(
            "Scope `configure` to the resources the application owns, or set it to `^$` entirely "
            "for applications that only publish and consume against topology declared by a "
            "deployment process. `^$` denies everything despite reading like a wildcard. "
            "Configure permission governs the ability to create or destroy resources, or alter "
            "their behaviour."
        ),
        detail=("The one legitimate fire is a topology-provisioning/migration service account "
                "that genuinely needs configure='.*' and carries no management tags — add it to "
                "the connector's `provisioning_accounts` allowlist. The judgement that configure "
                "is the most destructive of the three permissions is this rulepack's own; the "
                "RabbitMQ docs do not rank them."),
        source_ref={"api": "/api/permissions"},
    )]


# ── Vhosts ────────────────────────────────────────────────────────────────
@detector(kinds=["vhost"], rule_id="RABBITMQ.VHOST.DEFAULT_VHOST_IN_USE", severity="low",
          title="Multiple unscoped principals share the default / virtual host")
def default_vhost_in_use(resource, ctx) -> list:
    if resource.raw.get("name") != "/":
        return []
    cluster = _cluster(ctx)
    if cluster is not None and cluster.raw.get("permissions_error"):
        return []

    broad = []
    for p in ctx.of_kind("permission"):
        if p.raw.get("vhost") != "/":
            continue
        user = p.raw.get("user")
        if user == "guest":
            continue
        tags, _known = _tags_of(ctx, user)
        if "administrator" in tags or "monitoring" in tags:
            continue
        if all(_is_wildcard(p.raw.get(k)) for k in ("configure", "write", "read")):
            broad.append(user)

    # The discriminator is the BREADTH of the ACLs, not the count of principals: a legitimate
    # single-tenant cluster routinely has admin + scraper + CI + app on "/". Firing at >=1
    # would flag the configuration the production checklist calls "perfectly fine".
    if len(broad) < 2:
        return []

    return [Hit(
        observation=(
            f"GET /api/permissions shows {len(broad)} non-admin, non-guest users "
            f"({', '.join(sorted(broad))}) each holding configure/write/read = \".*\" on vhost "
            f"\"/\" — these principals can access one another's queues and exchanges."
        ),
        remediation=(
            "If these principals represent separate applications, tenants or environments, create "
            "a dedicated vhost for each and migrate onto them (e.g. project1_development, "
            "project1_production), then narrow or remove the broad permissions on \"/\". Do not "
            "delete the default vhost — that is unnecessary and risky."
        ),
        detail=("Blast-radius/namespace hygiene, not a vulnerability — per-user ACLs remain "
                "enforced. Using \"/\" in a single-tenant cluster is explicitly documented as "
                "perfectly fine, which is why breadth of ACLs and a >=2 threshold gate this."),
        source_ref={"api": "/api/permissions", "config_key": "default_vhost"},
    )]


# ── Listeners and contexts ────────────────────────────────────────────────
@detector(kinds=["node"], rule_id="RABBITMQ.MGMT.HTTP_API_NO_TLS", severity="high",
          title="Management UI / HTTP API served over plaintext HTTP")
def mgmt_http_api_no_tls(resource, ctx) -> list:
    ov = _overview(resource)
    if not ov:
        return []
    if _toggle(resource, "proxy_terminates_tls"):
        return []
    # The management listener is in `contexts`, NOT `listeners`. Missing/empty means the
    # credential lacks monitoring/administrator or disable_stats is on — never a finding.
    if not ov.get("contexts"):
        return []
    mgmt = _mgmt_contexts(ov)
    if not mgmt:
        return []
    plain = [c for c in mgmt if not _context_has_tls(c)]
    if not plain:
        return []

    severity, notes = None, []
    if any(_context_has_tls(c) for c in mgmt):
        severity = "medium"
        notes.append("an HTTPS management context is also present on this broker")
    # `ip` is present only when management.tcp.ip is explicitly set.
    if all(c.get("ip") in _LOOPBACK_IPS for c in plain):
        severity = "info"
        notes.append("every plaintext management context is bound to loopback and is "
                     "unreachable off-host")
    # Mandatory suppression: the dominant legitimate config is TLS terminated at a reverse
    # proxy / ingress / mesh with a plaintext localhost:15672 upstream, which the API cannot
    # see. If OUR OWN hop was verified TLS, that is exactly what is happening.
    if (resource.raw.get("scanner") or {}).get("tls_verified"):
        severity = "info"
        notes.append("the scanner reached this API over https:// with a verified certificate, "
                     "so TLS is terminated upstream of the broker and this rule cannot see the "
                     "terminating proxy")

    quoted = "; ".join(json.dumps(
        {k: c.get(k) for k in ("node", "description", "path", "port", "ip", "ssl", "ssl_opts")
         if k in c}) for c in plain)
    return [Hit(
        observation=(
            f"GET /api/overview contexts[] contains {quoted} — the management UI and HTTP API, "
            f"including HTTP Basic credentials, are served without TLS by the broker itself."
            + (" Note: " + "; ".join(notes) + "." if notes else "")
        ),
        remediation=(
            "Configure an HTTPS listener: `management.ssl.port = 15671` plus "
            "`management.ssl.cacertfile` / `management.ssl.certfile` / `management.ssl.keyfile` "
            "in rabbitmq.conf, and remove the plaintext `management.tcp.port` listener or bind it "
            "to loopback only. The HTTP API authenticates with HTTP Basic, so plaintext transport "
            "exposes base64-encoded credentials on the wire. If TLS is intentionally terminated "
            "at a proxy or ingress, set the connector's `proxy_terminates_tls` toggle."
        ),
        severity=severity,
        detail=("Both the TCP and TLS management contexts share the identical description "
                "literal \"RabbitMQ Management\", so every matching context is inspected."),
        source_ref={"api": "/api/overview", "config_key": "management.ssl.port"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.LISTENER.AMQP_PLAINTEXT", severity="medium",
          title="AMQP listener accepts plaintext connections on a non-loopback interface")
def amqp_plaintext(resource, ctx) -> list:
    ov = _overview(resource)
    if not ov:
        return []
    # Istio/Linkerd sidecar mTLS and TLS-terminating LBs leave the broker binding plaintext
    # with tls=false while the wire is encrypted. Neither is detectable from this API.
    if _toggle(resource, "transparent_tls_mesh"):
        return []
    listeners = ov.get("listeners")
    if listeners is None:
        return []

    groups = _group(listeners, lambda l: (
        l.get("protocol") == "amqp"
        and not _listener_has_tls(l)
        and l.get("ip_address") in _WILDCARD_BINDS
    ))
    if not groups:
        return []

    quoted = "; ".join(
        f"{_brief(group[0])} on node(s) {_nodes_of(group)}"
        for _key, group in sorted(groups.items(), key=lambda kv: str(kv[0]))
    )
    reachable = _toggle(resource, "reachability_signal")
    return [Hit(
        # "publicly bindable interface" is NOT observable here: ip_address is an
        # interface-binding fact, and this API sees no firewall, security group, NetworkPolicy
        # or VPC boundary. Every containerized broker binds 0.0.0.0 inside its own netns.
        observation=(
            f"GET /api/overview listeners[] contains {quoted} — AMQP 0-9-1/1.0 traffic and PLAIN "
            f"SASL credentials are carried unencrypted on a listener bound to all interfaces on "
            f"the host (0.0.0.0/::); actual reachability is not verified by this check."
            + (f" An external reachability signal ({reachable!r}) was supplied for this target, "
               f"corroborating exposure." if reachable else "")
        ),
        remediation=(
            "Enable a TLS listener (`listeners.ssl.default = 5671` with `ssl_options.certfile` / "
            "`ssl_options.keyfile` / `ssl_options.cacertfile`) and remove or loopback-bind the "
            "plaintext `listeners.tcp.*` entry. If TLS is provided transparently by a service "
            "mesh sidecar or a TLS-terminating proxy, set the connector's `transparent_tls_mesh` "
            "toggle rather than leaving this finding to accumulate."
        ),
        severity="high" if reachable else None,
        detail=("Fires on stock RabbitMQ, which binds 5672 on all interfaces by default, and "
                "exploitation requires an on-path network position — hence medium. Escalates to "
                "high only when exposure is independently corroborated by a reachability signal."),
        source_ref={"api": "/api/overview", "config_key": "listeners.tcp"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.CLUSTER.DIST_PORT_EXPOSED", severity="low",
          title="Verify the Erlang distribution (clustering) port is firewalled to peer nodes "
                "and CLI hosts only")
def dist_port_exposed(resource, ctx) -> list:
    ov = _overview(resource)
    if not ov:
        return []
    listeners = ov.get("listeners")
    if listeners is None:
        return []

    # No critical escalation exists: has_tls_enabled hardcodes clustering -> false and
    # clustering/ssl -> true, so "protocol == clustering AND tls == false" is tautological.
    groups = _group(listeners, lambda l: (
        (l.get("protocol") in ("clustering", "clustering/ssl"))
        and l.get("ip_address") in _WILDCARD_BINDS
    ))
    if not groups:
        return []

    quoted = "; ".join(
        f"{_brief(group[0])} on node(s) {_nodes_of(group)}"
        for _key, group in sorted(groups.items(), key=lambda kv: str(kv[0]))
    )
    reachable = _toggle(resource, "reachability_signal")
    return [Hit(
        observation=(
            f"GET /api/overview listeners[] contains {quoted} — the Erlang distribution port is "
            f"bound to all interfaces per the node's inet_dist_use_interface setting. This is the "
            f"shipped default and does not establish that the port is reachable; verify it is "
            f"firewalled to peer nodes and CLI hosts only."
            + (f" An external reachability signal ({reachable!r}) was supplied for this target, "
               f"corroborating exposure." if reachable else "")
        ),
        remediation=(
            "Bind the distribution listener to a private interface "
            "(`distribution.listener.interface`) and firewall port 25672, plus epmd on 4369 and "
            "the CLI range 35672-35682, so they are reachable only from peer nodes and CLI hosts. "
            "Unless external connections on these ports are really necessary (e.g. federation, or "
            "CLI tools on machines outside the subnet), they should not be publicly exposed. "
            "Optionally pin the range with `distribution.listener.port_range.min`/`.max` and "
            "enable inter-node TLS.\n\n"
            "A weak or default Erlang cookie is what makes a reachable 25672 dangerous, and the "
            "cookie is not observable from any HTTP API endpoint — verify out of band that it is "
            "long, random (not computed from an easy-to-guess value, and not a deployment "
            "tool's default or placeholder), distributed out of band, and that the cookie file is "
            "readable only by the OS users running RabbitMQ and CLI tools."
        ),
        severity="medium" if reachable else None,
        detail=("High false-positive rate by construction: ip_address is a config echo of "
                "kernel inet_dist_use_interface, which is almost never set, so \"::\" is reported "
                "on ~100% of stock nodes including correctly-firewalled ones. Defensible only as "
                "a low-severity hardening reminder unless a reachability signal corroborates it."),
        source_ref={"api": "/api/overview", "config_key": "distribution.listener.interface"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.TLS.PEER_VERIFICATION_DISABLED", severity="low",
          title="TLS listener does not verify peer certificates (informational hardening)")
def tls_peer_verification_disabled(resource, ctx) -> list:
    ov = _overview(resource)
    if not ov:
        return []
    external, known = _external_enabled(ctx)
    if not known:
        return []   # cannot read auth_mechanisms -> cannot gate -> not assessable
    if external:
        return []   # RABBITMQ.TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION owns this broker
    listeners = ov.get("listeners")
    if listeners is None:
        return []

    groups = _group(listeners, lambda l: (
        _listener_has_tls(l) and _verify_of(l)[0] in (None, "verify_none")
    ))
    contexts = [c for c in _mgmt_contexts(ov)
                if _context_has_tls(c) and _context_verify(c) in (None, "verify_none")]
    if not groups and not contexts:
        return []

    parts = []
    for _key, group in sorted(groups.items(), key=lambda kv: str(kv[0])):
        value, path = _verify_of(group[0])
        parts.append(f"{_brief(group[0])} with {path}={value!r} on node(s) {_nodes_of(group)}")
    for c in contexts:
        quoted = json.dumps({k: c.get(k) for k in ("node", "description", "port", "ssl") if k in c})
        parts.append(f"{quoted} with ssl_opts.verify={_context_verify(c)!r}")

    return [Hit(
        # No MITM framing. Server-side `verify` governs whether the node validates CLIENT
        # certificates; the node still presents its own cert and traffic is still encrypted.
        # MITM defence is the client verifying the server, which this setting does not affect.
        observation=(
            f"GET /api/overview reports {'; '.join(parts)} — the TLS listener does not request or "
            f"validate client certificates (absent `verify` means unset: it carries no schema "
            f"default, so Erlang/OTP's server default verify_none applies). Traffic is still "
            f"encrypted and the node still presents its own certificate; this matters only if "
            f"x509 client authentication is intended. EXTERNAL is not in this node's enabled "
            f"auth_mechanisms, so no authentication decision depends on peer verification here."
        ),
        remediation=(
            "No action is required if x509 client authentication is not intended — one-way TLS "
            "with username/password auth is a supported configuration. If x509 client "
            "authentication IS intended, set `ssl_options.verify = verify_peer` and "
            "`ssl_options.fail_if_no_peer_cert = true`, and point `ssl_options.cacertfile` at the "
            "trusted CA bundle. Note that clients must independently verify the server "
            "certificate — that is what prevents MITM; this server-side setting does not."
        ),
        detail=("Informational: `verify` absent is the out-of-the-box state for anyone enabling "
                "TLS with just cacertfile/certfile/keyfile, i.e. the majority of one-way-TLS "
                "deployments. Gated on EXTERNAL not being enabled, which is what keeps it "
                "tolerable."),
        source_ref={"api": "/api/overview", "config_key": "ssl_options.verify"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION",
          severity="high",
          title="x509 client authentication enabled without peer certificate verification")
def x509_auth_without_peer_verification(resource, ctx) -> list:
    ov = _overview(resource)
    if not ov:
        return []
    external, _known = _external_enabled(ctx)
    if not external:
        return []
    listeners = ov.get("listeners")
    if listeners is None:
        return []

    def bad(listener):
        if not _listener_has_tls(listener):
            return False
        if _verify_of(listener)[0] != "verify_peer":
            return True
        # verify_peer still lets clients simply omit a certificate unless this is true.
        return _fail_if_no_peer_cert(listener) is False

    groups = _group(listeners, bad)
    if not groups:
        return []

    parts = []
    for _key, group in sorted(groups.items(), key=lambda kv: str(kv[0])):
        value, path = _verify_of(group[0])
        parts.append(f"{_brief(group[0])} with {path}={value!r}, "
                     f"fail_if_no_peer_cert={_fail_if_no_peer_cert(group[0])!r} "
                     f"on node(s) {_nodes_of(group)}")

    return [Hit(
        observation=(
            f"GET /api/nodes reports {{\"name\":\"EXTERNAL\",\"enabled\":true}} in "
            f"auth_mechanisms, and GET /api/overview reports {'; '.join(parts)} — x509 client "
            f"authentication is in use while the node does not verify client certificates. An "
            f"unverified self-signed certificate with an arbitrary CN would authenticate."
        ),
        remediation=(
            "Set `ssl_options.verify = verify_peer` and `ssl_options.fail_if_no_peer_cert = true`, "
            "and point `ssl_options.cacertfile` at the trusted CA bundle. Per the "
            "rabbitmq-auth-mechanism-ssl README, the server must be configured with verify set to "
            "verify_peer to ensure that if a client presents a certificate, it gets verified."
        ),
        detail=("auth_mechanisms.enabled is computed purely from list membership in the "
                "auth_mechanisms env, so EXTERNAL may be listed but unused by every client. Still "
                "reported: any client that does use it is unauthenticated in practice."),
        source_ref={"api": "/api/overview", "config_key": "ssl_options.verify"},
    )]


# ── Versions ──────────────────────────────────────────────────────────────
@detector(kinds=["node"], rule_id="RABBITMQ.VERSION.UNPATCHED_CVE", severity="medium",
          title="Broker version predates the July 2026 security patch set")
def version_unpatched_cve(resource, ctx) -> list:
    if resource.raw.get("role") != "cluster":
        return []
    if _toggle(resource, "backported_build"):
        return []
    version, raw_version = _version_of(resource)
    if version is None:
        return []
    series = version[:2]
    # Both CVEs were introduced in 3.13.0, so a 3.12.x broker is not exposed — firing with
    # this evidence would be a guaranteed false positive. EOL_SERIES covers that case.
    if series < (3, 13):
        return []
    floor = _CVE_FLOOR.get(series)
    # 4.3+ ships the fix; an unrecognized future series PASSES rather than falling through.
    if floor is None or version[2] >= floor:
        return []

    probe = (resource.raw.get("probes") or {}).get("auth") or {}
    disclosed = probe.get("status") == 200 and probe.get("oauth_client_secret_present")
    patched = f"{series[0]}.{series[1]}.{floor}"

    oauth_clause = (
        "GET /api/auth on this broker returns a non-empty oauth_client_secret to unauthenticated "
        "callers, confirming exposure to CVE-2026-57219 (CVSS 8.7, unauthenticated OAuth client "
        "secret disclosure)." if disclosed else
        "CVE-2026-57219 (CVSS 8.7, unauthenticated OAuth client secret disclosure via GET "
        "/api/auth) additionally applies if OAuth 2 is configured with a client secret; this "
        "broker's /api/auth did not return one, so that exposure is not asserted here."
    )
    return [Hit(
        observation=(
            f"GET /api/overview reports rabbitmq_version={raw_version!r}, below the {patched} "
            f"patched release for its series — exposed to CVE-2026-57221 (CVSS 5.3, missing "
            f"permission check on passive queue.declare/exchange.declare). {oauth_clause}"
            + _drift_note(resource, raw_version)
        ),
        remediation=(
            "Upgrade to at least 4.3.0, 4.2.6, 4.1.11, 4.0.20 or 3.13.15 depending on series. "
            "Both CVEs were introduced in 3.13.0 (early 2024). If OAuth 2 with a client secret "
            "was configured, rotate management.oauth_client_secret as part of the upgrade — "
            "patching removes the endpoint but does not invalidate an already-leaked credential."
        ),
        severity="high" if disclosed else None,
        detail=("Distro and vendor backports (Debian/RHEL, Tanzu) patch without bumping the "
                "upstream string, so this can fire on a fixed build — set the connector's "
                "`backported_build` toggle for those targets. CVE-2026-57211 (management static "
                "file path traversal) is Windows-only, affects 4.1.0-4.1.10 and 4.2.0-4.2.5 only, "
                "and is not checked here."),
        source_ref={"api": "/api/overview", "config_key": "rabbitmq_version",
                    "cve": "CVE-2026-57221"},
    )]


@detector(kinds=["node"], rule_id="RABBITMQ.VERSION.EOL_SERIES", severity="medium",
          title="Broker runs a release series past end of community support")
def version_eol_series(resource, ctx) -> list:
    if resource.raw.get("role") != "cluster":
        return []
    if _toggle(resource, "backported_build"):
        return []
    version, raw_version = _version_of(resource)
    if version is None:
        return []
    series, patch = version[:2], version[2]
    today = date.today()
    ov = resource.raw.get("overview") or {}
    erlang = ov.get("erlang_version")
    drift = _drift_note(resource, raw_version)

    entry = _EOL_MATRIX.get(series)
    if entry is None:
        # Above the table = an unrecognized future series -> PASS, not fail-through.
        if series > max(_EOL_MATRIX):
            return []
        # Below the table: 3.12's commercial support expired 30 Jun 2025 and older series have
        # no support from any party.
        return [Hit(
            observation=(
                f"GET /api/overview reports rabbitmq_version={raw_version!r} "
                f"(erlang_version={erlang!r}); the {series[0]}.{series[1]} series is past both "
                f"community and commercial end of support, so this broker receives no security "
                f"fixes from any party. Support matrix as of {_EOL_AS_OF.isoformat()}.{drift}"
            ),
            remediation=("Plan an upgrade to a series still under community support (4.3 as of "
                         "mid-2026, or 4.2 LTS if a commercial licence covers it through "
                         "30 Jun 2030)."),
            severity="high",
            source_ref={"api": "/api/overview", "config_key": "rabbitmq_version"},
        )]

    community_eol, commercial_eol, last_community_patch, severity = entry

    if today < community_eol:
        days = (community_eol - today).days
        if days > 90 or severity is None:
            return []
        return [Hit(
            observation=(
                f"GET /api/overview reports rabbitmq_version={raw_version!r} "
                f"(erlang_version={erlang!r}); the {series[0]}.{series[1]} series reaches end of "
                f"community support on {community_eol.isoformat()}, in {days} days. Support "
                f"matrix as of {_EOL_AS_OF.isoformat()}.{drift}"
            ),
            remediation=("Plan the upgrade before the community end-of-support date, or confirm a "
                         "commercial support licence covers this series"
                         + (f" (commercial support runs to {commercial_eol.isoformat()})."
                            if commercial_eol else ".")),
            severity="info",
            source_ref={"api": "/api/overview", "config_key": "rabbitmq_version"},
        )]

    licensed = commercial_eol is not None and today <= commercial_eol
    # No /api/overview field reports licence or edition status, so patch level is the only
    # observable proxy: a patch newer than the last community build implies a licensed build.
    commercial_build = (last_community_patch is not None and patch > last_community_patch
                        and licensed)

    if commercial_build:
        severity, tail = "info", (
            f" Patch level {patch} is above {series[0]}.{series[1]}.{last_community_patch}, the "
            f"final freely-distributed build in this series, so this is a commercial-only build "
            f"and is receiving fixes"
            + (f" through {commercial_eol.isoformat()}." if commercial_eol else ".")
        )
    elif commercial_eol is not None and today > commercial_eol:
        # Had a commercial track and outlived it — no support from any party, as with 3.12.
        severity, tail = "high", (
            f" The commercial support track for this series expired on "
            f"{commercial_eol.isoformat()}, so this broker is receiving no security fixes from "
            f"any party."
        )
    elif commercial_eol is None:
        # Never had a commercial track. Keeps the series' tabled severity rather than
        # escalating: the matrix grades this case deliberately (4.0 is medium, not high).
        tail = (" No commercial support track is offered for this series, so it receives no "
                "further security fixes.")
    elif (today - community_eol).days < 183:
        severity, tail = "low", (
            f" Community support ended recently and a commercial track runs to "
            f"{commercial_eol.isoformat()}."
        )
    else:
        tail = (f" Security fixes for this series are available only to commercial customers"
                + (f" (through {commercial_eol.isoformat()})." if commercial_eol else "."))

    return [Hit(
        observation=(
            f"GET /api/overview reports rabbitmq_version={raw_version!r} "
            f"(erlang_version={erlang!r}); the {series[0]}.{series[1]} series reached end of "
            f"community support on {community_eol.isoformat()}.{tail} Support matrix as of "
            f"{_EOL_AS_OF.isoformat()}.{drift}"
        ),
        remediation=(
            "Plan an upgrade to a series still under community support (4.3 as of mid-2026, or "
            "4.2 LTS if a commercial licence covers it through 30 Jun 2030). Series past community "
            "EOL receive security fixes only for commercial customers, so posture rules that "
            "depend on patch availability will keep failing."
        ),
        severity=severity,
        detail=(f"The EOL matrix is a dated snapshot (as of {_EOL_AS_OF.isoformat()}) and must be "
                f"refreshed against https://www.rabbitmq.com/release-information. Managed and "
                f"repackaged brokers can backport fixes while still reporting the upstream "
                f"series — set the connector's `backported_build` toggle for those targets."),
        source_ref={"api": "/api/overview", "config_key": "rabbitmq_version"},
    )]


# ── Auth mechanisms (per node) ────────────────────────────────────────────
@detector(kinds=["node"], rule_id="RABBITMQ.AUTH.ANONYMOUS_LOGIN_ENABLED", severity="low",
          title="ANONYMOUS SASL mechanism enabled")
def anonymous_login_enabled(resource, ctx) -> list:
    if resource.raw.get("role") != "node":
        return []
    mechs = resource.raw.get("auth_mechanisms")
    if mechs is None:
        return []
    anon = next((m for m in mechs if m.get("name") == "ANONYMOUS"), None)
    # enabled == false definitively rules the finding out and removes the largest FP class.
    if anon is None or not anon.get("enabled"):
        return []

    cluster = _cluster(ctx)
    probe = ((cluster.raw.get("probes") if cluster else None) or {}).get("guest_whoami") or {}
    loopback_lifted = probe.get("status") == 200 and probe.get("name") == "guest"

    escalation = ""
    if loopback_lifted:
        escalation = (" A guest:guest GET /api/whoami probe from a non-loopback source returned "
                      "HTTP 200, so the loopback restriction that would otherwise confine an "
                      "ANONYMOUS-to-guest login to localhost is not in effect.")
    return [Hit(
        observation=(
            f"GET /api/nodes reports auth_mechanisms containing {json.dumps(anon)} on node "
            f"{resource.raw.get('name')!r} — the ANONYMOUS SASL mechanism is configured on this "
            f"node. On a default broker it authenticates clients as anonymous_login_user, which "
            f"defaults to guest. Whether the mechanism is actually offered depends on "
            f"anonymous_login_user/anonymous_login_pass, which have no HTTP API projection — "
            f"confirm via `rabbitmq-diagnostics environment` or rabbitmq.conf.{escalation}"
        ),
        remediation=(
            "Set `anonymous_login_user = none` in rabbitmq.conf — a real special value meaning no "
            "user is configured for anonymous logins — and/or remove ANONYMOUS from the "
            "`auth_mechanisms` list. For production environments the access-control guide advises "
            "removing this mechanism. Prefer `anonymous_login_user = none` over merely deleting "
            "the guest user: should_offer/1 only checks that the values are binaries, so with "
            "anonymous_login_user still <<\"guest\">> the mechanism is still offered and "
            "connections fail at login rather than being cleanly disabled."
        ),
        severity="medium" if loopback_lifted else None,
        detail=("Needs manual verification: `enabled` is computed purely from list membership in "
                "the auth_mechanisms env, not from should_offer/1, so a correctly-hardened broker "
                "with anonymous_login_user = none still reports enabled=true. Low because guest "
                "is in loopback_users by default, making ANONYMOUS-to-guest exploitable only from "
                "localhost on a default broker."),
        source_ref={"api": "/api/nodes", "config_key": "anonymous_login_user"},
    )]


# ── Coverage reporting ────────────────────────────────────────────────────
@detector(kinds=["node"], rule_id="RABBITMQ.SCAN.NOT_ASSESSABLE", severity="info",
          title="Part of the RabbitMQ rulepack could not be evaluated with this scanner credential")
def scan_not_assessable(resource, ctx) -> list:
    """RabbitMQ gates payload FIELDS on tags rather than rejecting the request, so a rule that
    reads a missing key sees an empty result and silently passes. Every rule above declines to
    assess in that case; this rule is what stops that from becoming a clean bill of health."""
    if resource.raw.get("role") != "cluster":
        return []

    gaps = []
    ov = resource.raw.get("overview")
    if ov is None:
        gaps.append(
            f"GET /api/overview -> {resource.raw.get('overview_error')!r}; requires the "
            f"`management` tag (and `monitoring`/`administrator` for listeners and contexts). "
            f"Not evaluated: MGMT.HTTP_API_NO_TLS, LISTENER.AMQP_PLAINTEXT, "
            f"CLUSTER.DIST_PORT_EXPOSED, TLS.PEER_VERIFICATION_DISABLED, "
            f"TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION, VERSION.UNPATCHED_CVE, VERSION.EOL_SERIES."
        )
    else:
        if ov.get("listeners") is None:
            gaps.append(
                f"GET /api/overview returned no `listeners` key (emitted only to a `monitoring` "
                f"or `administrator` credential, and omitted entirely when "
                f"management.disable_stats = true; this broker reports "
                f"disable_stats={ov.get('disable_stats')!r}). Not evaluated: "
                f"LISTENER.AMQP_PLAINTEXT, CLUSTER.DIST_PORT_EXPOSED, "
                f"TLS.PEER_VERIFICATION_DISABLED, TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION."
            )
        if ov.get("contexts") is None:
            gaps.append(
                "GET /api/overview returned no `contexts` key (same `monitoring`/`administrator` "
                "gate as listeners). Not evaluated: MGMT.HTTP_API_NO_TLS."
            )

    for key, endpoint, tag, rules in (
        ("nodes_error", "/api/nodes", "monitoring",
         "AUTH.ANONYMOUS_LOGIN_ENABLED, TLS.X509_AUTH_WITHOUT_PEER_VERIFICATION (and the "
         "auth_mechanisms gate on TLS.PEER_VERIFICATION_DISABLED), per-node version drift"),
        ("users_error", "/api/users", "administrator",
         "USER.DEFAULT_GUEST_PRESENT, USER.WEAK_PASSWORD_HASHING, USER.ADMIN_TAG_SPRAWL, and the "
         "tag lookups that gate PERMISSION.WILDCARD_ALL, PERMISSION.CONFIGURE_WILDCARD and "
         "VHOST.DEFAULT_VHOST_IN_USE"),
        ("permissions_error", "/api/permissions", "administrator",
         "PERMISSION.WILDCARD_ALL, PERMISSION.CONFIGURE_WILDCARD, VHOST.DEFAULT_VHOST_IN_USE"),
        ("vhosts_error", "/api/vhosts", "monitoring",
         "VHOST.DEFAULT_VHOST_IN_USE"),
    ):
        err = resource.raw.get(key)
        if err:
            gaps.append(f"GET {endpoint} -> {err!r}; requires the `{tag}` tag. "
                        f"Not evaluated: {rules}.")

    probe = (resource.raw.get("probes") or {}).get("guest_whoami") or {}
    if probe.get("skipped"):
        gaps.append(
            f"The guest:guest GET /api/whoami probe was skipped: {probe['skipped']}. "
            f"Not evaluated: USER.GUEST_REMOTE_LOGIN, USER.GUEST_DEFAULT_PASSWORD_REMOTE, and the "
            f"loopback-bypass escalations on USER.DEFAULT_GUEST_PRESENT and "
            f"AUTH.ANONYMOUS_LOGIN_ENABLED."
        )
    if not gaps:
        return []

    return [Hit(
        observation=(
            f"The scanner's credential could not read {len(gaps)} part(s) of this broker's "
            f"management surface, so the rules below returned no result rather than a pass: "
            + " | ".join(gaps)
        ),
        remediation=(
            "Grant the scanning credential the `monitoring` tag for listener, context, node and "
            "vhost rules. The user, permission and vhost-tenancy rules need the `administrator` "
            "tag: RabbitMQ has no read-only-administrator tag, so that credential is inherently "
            "write-capable — this connector issues GETs only. If management.disable_stats = true, "
            "the listener and context rules cannot be evaluated over HTTP at all, regardless of "
            "tag. To enable the guest probe, scan from a non-loopback source address."
        ),
        detail=("Not a defect in the broker: this finding records the scan's own coverage so a "
                "clean report is not mistaken for a clean broker."),
        source_ref={"api": "/api/overview"},
    )]
