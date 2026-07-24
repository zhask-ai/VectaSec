"""HashiCorp Vault rulepack — config-time posture over what connect/vault.py collected.

Every rule reads REAL configuration evidence (the enabled audit-device list, the seal
threshold `t`, a policy's parsed path/capabilities, a federation role's binding fields) and
cites it; none guesses from names. Rules run on the DISTINCT vault_* kinds the connector
emits, so they never collide with the other packs.

Two disciplines carried throughout:
  • The third outcome. A sys endpoint the token could not read (403) is recorded by the
    connector as outcome 'forbidden'; the rule that needed it returns assessable=False (a
    coverage gap) instead of reading the absence as a clean pass.
  • Honest semantics. A mount's `default_lease_ttl=0` means 'inherit the system default',
    not 'infinite' — the lease rule says exactly that and stays low-severity hygiene.

Severity conventions (house): critical = no tamper record / effectively-root grant; high =
live root token / single-key unseal / plaintext transport / write-anywhere / unbound
federation; low = TTL hygiene; info = coverage notes.
"""
from ..contracts import Hit
from ..registry import detector

# A policy path glob that reaches across the whole Vault or its control plane. `sudo` on one
# of these is root-equivalent; write on "*" is write-everywhere.
_BROAD_GLOBS = ("*", "sys/*", "sys/", "auth/*", "auth/", "secret/*")
_WRITE_CAPS = {"create", "update", "delete", "sudo"}


def _is_broad(glob: str) -> bool:
    g = str(glob or "")
    return g == "*" or g.startswith("*") or g in _BROAD_GLOBS or g.startswith("sys/") \
        or g.startswith("auth/")


# ══ vault_server ══════════════════════════════════════════════════════════════
@detector(kinds=["vault_server"], rule_id="VAULT.AUDIT.NO_DEVICE", severity="critical",
          title="Vault has no audit device enabled")
def audit_no_device(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("audit_readable"):
        return [Hit(
            observation=("reading sys/audit was denied for this token, so whether any audit "
                         "device is enabled could not be determined"),
            remediation=("Grant the scan token read on sys/audit (a sudo-capable read policy), "
                         "or confirm an audit device out of band. Until then Vault's audit "
                         "posture is unknown, not clean."),
            detail="audit_readable=False",
            assessable=False,
            assessment_reason="sys/audit returned 403 (forbidden)",
            source_ref={"api": "GET sys/audit"},
        )]
    if raw.get("audit_count"):
        return []
    return [Hit(
        observation=("Vault has zero audit devices enabled (sys/audit is empty) — every token "
                     "creation, secret read, and policy change happens with NO tamper-evident "
                     "record, so a compromise leaves no forensic trail"),
        remediation=("Enable at least one audit device, e.g. `vault audit enable file "
                     "file_path=/var/log/vault/audit.log` (or syslog/socket), and ship it to "
                     "write-once storage. Audit is Vault's only tamper record; a secrets store "
                     "with none cannot prove what was read after a breach."),
        detail=f"audit_count={raw.get('audit_count')}",
        source_ref={"api": "GET sys/audit"},
    )]


@detector(kinds=["vault_server"], rule_id="VAULT.TLS.PLAINTEXT", severity="high",
          title="Vault API address is plaintext HTTP")
def tls_plaintext(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("tls"):
        return []
    return [Hit(
        observation=(f"Vault base_url scheme is '{raw.get('scheme')}' (not https) — the Vault "
                     f"token, every unseal operation, and every secret read/write cross the "
                     f"network in plaintext, readable by anyone on the path"),
        remediation=("Terminate TLS on the Vault listener (`tcp` stanza `tls_disable = false` "
                     "with a certificate) and serve the API over https only. For a secrets "
                     "store, plaintext transport exposes the credentials it exists to protect."),
        detail=f"scheme={raw.get('scheme')} tls=False",
        source_ref={"config": "listener tls_disable", "field": "base_url.scheme"},
    )]


@detector(kinds=["vault_server"], rule_id="VAULT.TOKEN.ROOT_IN_USE", severity="high",
          title="A Vault root token is live and in use")
def token_root_in_use(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("token_readable"):
        return [Hit(
            observation=("auth/token/lookup-self was not readable, so whether this scan uses a "
                         "root (unrestricted) token could not be determined"),
            remediation="Ensure the token can look itself up (the default policy allows it) so "
                        "its privilege can be assessed.",
            detail="token_readable=False",
            assessable=False,
            assessment_reason="auth/token/lookup-self did not return token data",
            source_ref={"api": "GET auth/token/lookup-self"},
        )]
    if not raw.get("token_is_root"):
        return []
    return [Hit(
        observation=(f"the token in use carries the 'root' policy (policies="
                     f"{raw.get('token_policies')}, ttl={raw.get('token_ttl')}) — a root token "
                     f"bypasses every ACL and, with ttl 0, never expires; root tokens are meant "
                     f"to be revoked immediately after initial setup"),
        remediation=("Revoke it (`vault token revoke <accessor>`), operate day-to-day with "
                     "least-privilege policies, and generate a new root token only when needed "
                     "via `vault operator generate-root` (then revoke it again). A standing "
                     "root token is an un-auditable master key over the whole secrets fabric."),
        detail=f"token_is_root=True ttl={raw.get('token_ttl')}",
        source_ref={"api": "GET auth/token/lookup-self", "field": "policies"},
    )]


@detector(kinds=["vault_server"], rule_id="VAULT.SEAL.LOW_THRESHOLD", severity="high",
          title="Vault unseal threshold is a single key share")
def seal_low_threshold(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("seal_status_readable"):
        return [Hit(
            observation="sys/seal-status was not readable, so the unseal key threshold could "
                        "not be determined",
            remediation="Allow the scan to read sys/seal-status (an unauthenticated endpoint by "
                        "default) so the unseal quorum can be assessed.",
            detail="seal_status_readable=False",
            assessable=False,
            assessment_reason="sys/seal-status did not return seal data",
            source_ref={"api": "GET sys/seal-status"},
        )]
    t = raw.get("seal_threshold")
    if not isinstance(t, int) or t > 1:
        return []
    kind = "recovery-key" if raw.get("seal_recovery") else "unseal-key"
    return [Hit(
        observation=(f"Vault {kind} threshold t={t} with n={raw.get('seal_shares')} shares "
                     f"(seal type {raw.get('seal_type')}) — a single key holder can unseal "
                     f"Vault alone, so the quorum that is supposed to protect the master key "
                     f"provides no split of trust"),
        remediation=("Re-key with a real quorum, e.g. `vault operator rekey -init "
                     "-key-shares=5 -key-threshold=3` (or rekey the recovery keys under "
                     "auto-unseal). Distribute the shares to separate custodians. A threshold "
                     "of 1 defeats the purpose of Shamir splitting."),
        detail=f"seal_threshold={t} seal_shares={raw.get('seal_shares')} "
               f"recovery={raw.get('seal_recovery')}",
        source_ref={"api": "GET sys/seal-status", "field": "t"},
    )]


@detector(kinds=["vault_server"], rule_id="VAULT.SERVER.NOT_ASSESSED", severity="info",
          title="A Vault metadata endpoint could not be read with the scan token")
def server_not_assessed(r, ctx) -> list:
    """The third honest outcome at server scope: a sys endpoint that answered 403/forbidden (or
    errored) is a COVERAGE GAP — surfaced as not-assessable rather than letting a token's
    missing read permission read as 'nothing wrong'. The dedicated per-check rules already file
    their own gaps for audit/token/seal; this covers the remaining endpoints (auth/mounts/
    policies) so the whole collection is honestly accounted for."""
    raw = r.raw or {}
    covered = {"sys/audit", "auth/token/lookup-self", "sys/seal-status", "sys/health"}
    hits = []
    for endpoint, rec in sorted((raw.get("collection") or {}).items()):
        if endpoint in covered:
            continue
        outcome = (rec or {}).get("outcome")
        if outcome == "ok":
            continue
        hits.append(Hit(
            observation=(f"reading {endpoint} returned {rec.get('error')} ({outcome}), so the "
                         f"resources it enumerates were not assessed"),
            remediation=(f"Grant the scan token read+list on {endpoint} so its posture can be "
                         f"assessed. Until then this surface is unknown, not clean."),
            detail=f"endpoint={endpoint} outcome={outcome} error={rec.get('error')}",
            assessable=False,
            assessment_reason=f"{endpoint} returned {outcome}",
            source_ref={"api": f"GET {endpoint}"},
        ))
    return hits


# ══ vault_mount ═══════════════════════════════════════════════════════════════
@detector(kinds=["vault_mount"], rule_id="VAULT.MOUNT.DYNAMIC_NO_TTL_OVERRIDE", severity="low",
          title="Dynamic secret engine does not set its own lease TTL")
def mount_dynamic_no_ttl(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("dynamic_engine"):
        return []
    dttl = raw.get("default_lease_ttl")
    mttl = raw.get("max_lease_ttl")
    if dttl not in (0, None) or mttl not in (0, None):
        return []
    return [Hit(
        observation=(f"secret engine '{raw.get('path')}' (type {raw.get('type')}) sets "
                     f"default_lease_ttl=0 and max_lease_ttl=0, so its dynamically-issued "
                     f"credentials inherit the system default lease rather than a TTL scoped "
                     f"to this engine's blast radius"),
        remediation=(f"Set an engine-appropriate lease on the mount, e.g. `vault secrets tune "
                     f"-default-lease-ttl=1h -max-lease-ttl=24h {raw.get('path')}`. Shorter "
                     f"leases shrink the window a leaked dynamic credential stays valid. (TTL 0 "
                     f"means 'use the system default', not 'never expires'.)"),
        detail=f"type={raw.get('type')} default_lease_ttl=0 max_lease_ttl=0",
        source_ref={"api": "GET sys/mounts", "field": "config.default_lease_ttl"},
    )]


# ══ vault_policy ══════════════════════════════════════════════════════════════
@detector(kinds=["vault_policy"], rule_id="VAULT.POLICY.SUDO_GRANT", severity="critical",
          title="Vault ACL policy grants the sudo capability")
def policy_sudo_grant(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for block in raw.get("paths") or []:
        caps = block.get("capabilities") or []
        if "sudo" not in caps:
            continue
        glob = block.get("path")
        broad = _is_broad(glob)
        hits.append(Hit(
            observation=(f"ACL policy '{raw.get('name')}' grants `sudo` on path \"{glob}\" "
                         f"(capabilities {caps}) — sudo unlocks root-protected endpoints "
                         f"(seal, remount, raw storage), so this grant is "
                         f"{'root-equivalent across the control plane' if broad else 'privileged'}"),
            severity="critical" if broad else "high",
            remediation=(f"Remove `sudo` from this path unless a specific root-protected "
                         f"endpoint truly requires it, and scope the path to that exact "
                         f"endpoint instead of \"{glob}\". Grant sudo to no standing app policy."),
            detail=f"policy={raw.get('name')} path={glob} capabilities={caps}",
            source_ref={"api": "GET sys/policies/acl", "path": glob},
        ))
    return hits


@detector(kinds=["vault_policy"], rule_id="VAULT.POLICY.WILDCARD_WRITE", severity="high",
          title="Vault ACL policy allows write access to every path")
def policy_wildcard_write(r, ctx) -> list:
    raw = r.raw or {}
    hits = []
    for block in raw.get("paths") or []:
        if str(block.get("path")) != "*":
            continue
        caps = block.get("capabilities") or []
        writes = sorted(set(caps) & _WRITE_CAPS - {"sudo"})
        if not writes:
            continue   # read/list on "*" is broad-read, a lesser concern than write-everywhere
        hits.append(Hit(
            observation=(f"ACL policy '{raw.get('name')}' grants \"*\" (every path) the "
                         f"capabilities {caps} — write access to every secret, mount, and auth "
                         f"path in Vault, i.e. effective control of the entire secrets fabric"),
            remediation=("Never grant write on the \"*\" glob. Enumerate the exact path "
                         "prefixes this policy needs (e.g. `secret/data/team-a/*`) with only the "
                         "capabilities required. A write-everywhere policy is one leaked token "
                         "away from total compromise."),
            detail=f"policy={raw.get('name')} path=* capabilities={caps} writes={writes}",
            source_ref={"api": "GET sys/policies/acl", "path": "*"},
        ))
    return hits


# ══ vault_auth_role ═══════════════════════════════════════════════════════════
@detector(kinds=["vault_auth_role"], rule_id="VAULT.AUTH.APPROLE_UNBOUNDED", severity="high",
          title="AppRole role authenticates with no secret-id and no network binding")
def approle_unbounded(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("mount_type") != "approle":
        return []
    # bind_secret_id defaults to true; the weak posture is bind_secret_id=false (role_id alone
    # logs in) with no CIDR fence to compensate.
    if raw.get("bind_secret_id") is not False:
        return []
    if raw.get("secret_id_bound_cidrs") or raw.get("token_bound_cidrs"):
        return []
    return [Hit(
        observation=(f"AppRole role '{raw.get('role_name')}' (mount {raw.get('mount_path')}) has "
                     f"bind_secret_id=false with no secret_id_bound_cidrs and no "
                     f"token_bound_cidrs — possession of the role_id alone yields a token with "
                     f"policies {raw.get('token_policies')}, from anywhere"),
        remediation=("Set `bind_secret_id=true` so a secret-id is required, and/or fence the "
                     "role with `token_bound_cidrs` / `secret_id_bound_cidrs`: `vault write "
                     f"auth/{raw.get('mount_path')}role/{raw.get('role_name')} "
                     "bind_secret_id=true token_bound_cidrs=10.0.0.0/8`. A role_id is not a "
                     "secret — treat it as a username, not a password."),
        detail=f"bind_secret_id=False cidrs=none token_policies={raw.get('token_policies')}",
        source_ref={"api": f"GET auth/{raw.get('mount_path')}role/{raw.get('role_name')}",
                    "field": "bind_secret_id"},
    )]


@detector(kinds=["vault_auth_role"], rule_id="VAULT.AUTH.JWT_NO_BOUND_CLAIMS", severity="high",
          title="JWT/OIDC role accepts any token from the identity provider")
def jwt_no_bound_claims(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("mount_type") not in ("jwt", "oidc"):
        return []
    if raw.get("bound_claims") or raw.get("bound_audiences") or raw.get("bound_subject"):
        return []
    return [Hit(
        observation=(f"{raw.get('mount_type')} role '{raw.get('role_name')}' (mount "
                     f"{raw.get('mount_path')}) has no bound_claims, no bound_audiences, and no "
                     f"bound_subject — ANY token the configured provider issues (for any user "
                     f"or workload) can assume this role and its policies "
                     f"{raw.get('token_policies')}"),
        remediation=("Constrain the role to the intended workloads: set `bound_audiences` to "
                     "this role's audience and `bound_claims` to the identifying claim(s) "
                     "(e.g. repository, subject, group): `vault write "
                     f"auth/{raw.get('mount_path')}role/{raw.get('role_name')} "
                     "bound_audiences=... bound_claims=...`. An unbound federation role trusts "
                     "the entire IdP, not a specific principal."),
        detail=f"bound_claims=none bound_audiences=none bound_subject=none "
               f"token_policies={raw.get('token_policies')}",
        source_ref={"api": f"GET auth/{raw.get('mount_path')}role/{raw.get('role_name')}",
                    "field": "bound_claims"},
    )]


@detector(kinds=["vault_auth_role"], rule_id="VAULT.AUTH.KUBERNETES_WILDCARD_BINDING",
          severity="high", title="Kubernetes auth role binds a wildcard service account")
def kubernetes_wildcard_binding(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("mount_type") != "kubernetes":
        return []
    names = raw.get("bound_service_account_names") or []
    namespaces = raw.get("bound_service_account_namespaces") or []
    if "*" not in names and "*" not in namespaces:
        return []
    scope = []
    if "*" in names:
        scope.append("service account names \"*\"")
    if "*" in namespaces:
        scope.append("namespaces \"*\"")
    return [Hit(
        observation=(f"Kubernetes auth role '{raw.get('role_name')}' (mount "
                     f"{raw.get('mount_path')}) binds {', '.join(scope)} — any pod whose "
                     f"service-account token is presented can assume this role and its policies "
                     f"{raw.get('token_policies')}, well beyond the intended workload"),
        remediation=("Pin the role to the exact service account(s) and namespace(s) that need "
                     "it: `vault write "
                     f"auth/{raw.get('mount_path')}role/{raw.get('role_name')} "
                     "bound_service_account_names=my-app "
                     "bound_service_account_namespaces=prod`. A `*` binding trusts the whole "
                     "cluster to Vault."),
        detail=(f"bound_service_account_names={names} "
                f"bound_service_account_namespaces={namespaces}"),
        source_ref={"api": f"GET auth/{raw.get('mount_path')}role/{raw.get('role_name')}",
                    "field": "bound_service_account_names"},
    )]
