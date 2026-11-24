"""MFT / EDI rulepack — detectors over what connect/mft.py read from an MFT appliance.

Two standing constraints shape the pack:

  • These are the systems ransomware crews mass-exploited (Cl0p: MOVEit ~90M records,
    GoAnywhere, Cleo), so the version→CVE rules are the highest-signal checks — but each CVE ID
    and affected-version line here was VERIFIED against the vendor/CISA advisory (anchors in each
    rule's source_ref). A product whose version we cannot parse, or a series we have no verified
    patch floor for, returns a not-assessable coverage gap — NEVER an unverified "you are
    vulnerable" and never a silent pass.
  • Collection is shallow by necessity (closed appliances). Where the admin API was not readable,
    endpoint/account rules simply have nothing to run on and the server-level rules record the
    gap. Silence (`[]`) means "checked, nothing wrong"; not-assessable means "could not check".

Rules run on the DISTINCT `mft_server`/`mft_endpoint`/`mft_transfer_account` kinds this connector
emits, so they never collide with any other pack. Every observation states a value read off the
appliance; nothing here concludes.
"""
import re

from ..contracts import Hit
from ..registry import detector

_VER_RE = re.compile(r"\d+")
_WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


def _ver_tuple(v, width: int):
    """Parse a version string to a fixed-width int tuple (padded with zeros), or None when no
    digits are present. Width fixes the comparison shape per product (GoAnywhere 3, Cleo 4)."""
    if v is None:
        return None
    parts = _VER_RE.findall(str(v))
    if not parts:
        return None
    nums = [int(x) for x in parts[:width]]
    while len(nums) < width:
        nums.append(0)
    return tuple(nums)


# ── verified version→CVE floors ───────────────────────────────────────────────
# MOVEit Transfer CVE-2023-34362 — unauthenticated SQL injection → RCE, exploited by Cl0p (CISA
# AA23-158A). Fixed builds per Progress advisory (2023-05-31): 2021.0.6 (13.0.6), 2021.1.4
# (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), 2023.0.1 (15.0.1). Keyed on BOTH the year-based
# and internal (13/14/15) version representations MOVEit reports; patch below the floor is vulnerable.
_MOVEIT_FIXED = {
    (2021, 0): 6, (2021, 1): 4, (2022, 0): 4, (2022, 1): 5, (2023, 0): 1,
    (13, 0): 6, (13, 1): 4, (14, 0): 4, (14, 1): 5, (15, 0): 1,
}


def _moveit_sqli_vulnerable(version):
    t = _ver_tuple(version, 3)
    if t is None:
        return None
    floor = _MOVEIT_FIXED.get((t[0], t[1]))
    if floor is None:
        return None    # a series with no verified patch floor → unknown, not a pass
    return t[2] < floor


def _ga_0669_vulnerable(version):
    """GoAnywhere MFT CVE-2023-0669 — pre-auth deserialization command injection RCE (Cl0p).
    Affects 7.1.1 and earlier; fixed in 7.1.2 (Fortra advisory, 2023-02-01/07)."""
    t = _ver_tuple(version, 3)
    return None if t is None else t < (7, 1, 2)


def _ga_0204_vulnerable(version):
    """GoAnywhere MFT CVE-2024-0204 — authentication bypass allowing admin-user creation via the
    admin portal. Affects 6.x from 6.0.1 and 7.x before 7.4.1; fixed in 7.4.1 (Fortra advisory,
    disclosed 2024-01-22). Versions below 6.0.1 fall outside the stated range for THIS CVE."""
    t = _ver_tuple(version, 3)
    return None if t is None else (6, 0, 1) <= t < (7, 4, 1)


def _cleo_50623_vulnerable(version):
    """Cleo CVE-2024-50623 — unrestricted file upload/download → RCE in Harmony/VLTrader/LexiCom
    before 5.8.0.21 (Cleo advisory; CISA KEV). The 5.8.0.21 fix was later found incomplete."""
    t = _ver_tuple(version, 4)
    return None if t is None else t < (5, 8, 0, 21)


def _cleo_55956_vulnerable(version):
    """Cleo CVE-2024-55956 — unauthenticated command execution via the Autorun directory,
    fixed in 5.8.0.24 (Cleo advisory; CISA KEV). The earlier 5.8.0.21 remained exploitable."""
    t = _ver_tuple(version, 4)
    return None if t is None else t < (5, 8, 0, 24)


def _na_version(product: str, version, cve: str, floor_text: str) -> list:
    return [Hit(
        observation=(f"{product} reports version {version!r}; this scanner has no verified "
                     f"patch floor to place it against {cve}, so exposure was not determined"),
        remediation=(f"Confirm the running build against the vendor advisory for {cve} and patch "
                     f"to a fixed release ({floor_text})."),
        detail=f"product={product} version={version}",
        assessable=False,
        assessment_reason="version string not parseable to a known-patched series",
        source_ref={"banner": "version", "cve": cve},
    )]


# ── exposed admin console (the mode-(b) headline) ─────────────────────────────
@detector(kinds=["mft_server"], rule_id="MFT.ADMIN.CONSOLE_EXPOSED", severity="critical",
          title="MFT management console reachable without authentication")
def admin_console_exposed(r, ctx) -> list:
    raw = r.raw or {}
    console = raw.get("admin_console") or {}
    if raw.get("admin_console_exposed"):
        paths = ", ".join(p.get("path") or "?" for p in console.get("exposed") or [])
        return [Hit(
            observation=(f"{raw.get('product')} management path(s) {paths} answered HTTP 200 with "
                         f"no authentication gate, so the admin console is served to any client "
                         f"that can reach {raw.get('host')}"),
            remediation=("Put the management console behind authentication and restrict it to an "
                         "admin network/VPN. An unauthenticated MFT console is direct access to "
                         "partner data and, historically, to pre-auth RCE."),
            detail=f"exposed={paths} host={raw.get('host')}",
            source_ref={"admin_console": "exposed", "product": raw.get("product")},
        )]
    if raw.get("probe_outcome") == "ok" and not console.get("probed"):
        return [Hit(
            observation=(f"{raw.get('product')} at {raw.get('host')} was reached but no management "
                         f"path was probed, so console exposure was not determined"),
            remediation="Confirm the admin console path is authenticated and network-restricted.",
            detail=f"host={raw.get('host')}",
            assessable=False,
            assessment_reason="no admin path was probed on a reachable server",
            source_ref={"admin_console": "unprobed"},
        )]
    return []


@detector(kinds=["mft_server"], rule_id="MFT.ADMIN.DEFAULT_ACCOUNT", severity="critical",
          title="MFT appliance has a default or anonymous administrator account")
def default_admin_account(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("default_admin_present"):
        return [Hit(
            observation=(f"{raw.get('product')} admin API reports a default/anonymous "
                         f"administrator account is present and usable"),
            remediation=("Remove or disable the default administrator account and require named "
                         "admin accounts with strong, unique credentials and MFA."),
            detail=f"product={raw.get('product')} host={raw.get('host')}",
            source_ref={"admin_api": "default_admin_present"},
        )]
    # Only a coverage gap when we tried (had a token) but could not read the account list.
    if raw.get("authenticated_scan") and not raw.get("admin_api_readable"):
        return [Hit(
            observation=(f"the {raw.get('product')} admin API was not readable "
                         f"({raw.get('admin_api_reason')}), so default/anonymous admin accounts "
                         f"were not assessed"),
            remediation=("Grant the scan a read-only admin-API token, or export appliance "
                         "config, so administrator accounts can be reviewed."),
            detail=f"reason={raw.get('admin_api_reason')}",
            assessable=False,
            assessment_reason="admin API not readable on an authenticated scan",
            source_ref={"admin_api": "unreadable"},
        )]
    return []


# ── version → known-CVE (each ID + range verified against the vendor/CISA advisory) ──
@detector(kinds=["mft_server"], rule_id="MFT.MOVEIT.SQLI_CVE_2023_34362", severity="critical",
          title="MOVEit Transfer version is affected by the Cl0p SQLi RCE (CVE-2023-34362)")
def moveit_sqli(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("product") != "moveit":
        return []
    version = raw.get("version")
    vuln = _moveit_sqli_vulnerable(version)
    if vuln is False:
        return []
    if vuln is None:
        return _na_version("MOVEit Transfer", version, "CVE-2023-34362",
                           "≥2021.0.6 / 2021.1.4 / 2022.0.4 / 2022.1.5 / 2023.0.1")
    return [Hit(
        observation=(f"MOVEit Transfer version {version} predates the fixed build for its series "
                     f"(CVE-2023-34362, unauthenticated SQL injection → RCE, mass-exploited by "
                     f"Cl0p per CISA AA23-158A)"),
        remediation=("Upgrade to a fixed build (2021.0.6 / 2021.1.4 / 2022.0.4 / 2022.1.5 / "
                     "2023.0.1 or later) and check for LEMURLOOT web shells (human2.aspx). Until "
                     "patched, block inbound HTTP/S to the MOVEit interface."),
        detail=f"version={version}",
        source_ref={"cve": "CVE-2023-34362",
                    "advisory": "cisa.gov/news-events/cybersecurity-advisories AA23-158A"},
    )]


@detector(kinds=["mft_server"], rule_id="MFT.GOANYWHERE.RCE_CVE_2023_0669", severity="critical",
          title="GoAnywhere MFT version is affected by the pre-auth deserialization RCE (CVE-2023-0669)")
def goanywhere_rce_0669(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("product") != "goanywhere":
        return []
    version = raw.get("version")
    vuln = _ga_0669_vulnerable(version)
    if vuln is False:
        return []
    if vuln is None:
        return _na_version("GoAnywhere MFT", version, "CVE-2023-0669", "≥7.1.2")
    return [Hit(
        observation=(f"GoAnywhere MFT version {version} is 7.1.1 or earlier, the range affected by "
                     f"CVE-2023-0669 (pre-authentication deserialization command injection → RCE, "
                     f"exploited by Cl0p)"),
        remediation=("Upgrade to 7.1.2 or later. As interim mitigation Fortra advised removing the "
                     "License Response Servlet mapping and restricting admin-console exposure."),
        detail=f"version={version}",
        source_ref={"cve": "CVE-2023-0669", "advisory": "Fortra GoAnywhere MFT advisory 2023-02"},
    )]


@detector(kinds=["mft_server"], rule_id="MFT.GOANYWHERE.AUTH_BYPASS_CVE_2024_0204",
          severity="critical",
          title="GoAnywhere MFT version is affected by the admin-creation auth bypass (CVE-2024-0204)")
def goanywhere_auth_bypass_0204(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("product") != "goanywhere":
        return []
    version = raw.get("version")
    vuln = _ga_0204_vulnerable(version)
    if vuln is False:
        return []
    if vuln is None:
        return _na_version("GoAnywhere MFT", version, "CVE-2024-0204", "≥7.4.1")
    return [Hit(
        observation=(f"GoAnywhere MFT version {version} is in the CVE-2024-0204 affected range "
                     f"(6.x from 6.0.1, or 7.x before 7.4.1): an authentication bypass lets an "
                     f"unauthenticated attacker create an administrator account via the admin portal"),
        remediation=("Upgrade to 7.4.1 or later, then audit the admin-user list for accounts you "
                     "did not create. Restrict the /goanywhere admin portal to trusted networks."),
        detail=f"version={version}",
        source_ref={"cve": "CVE-2024-0204", "advisory": "Fortra GoAnywhere MFT advisory 2024-01"},
    )]


@detector(kinds=["mft_server"], rule_id="MFT.CLEO.FILE_RCE_CVE_2024_50623", severity="critical",
          title="Cleo MFT version is affected by the unrestricted file upload RCE (CVE-2024-50623)")
def cleo_file_rce_50623(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("product") != "cleo":
        return []
    version = raw.get("version")
    vuln = _cleo_50623_vulnerable(version)
    if vuln is False:
        return []
    if vuln is None:
        return _na_version("Cleo Harmony/VLTrader/LexiCom", version, "CVE-2024-50623", "≥5.8.0.24")
    return [Hit(
        observation=(f"Cleo Harmony/VLTrader/LexiCom version {version} is below 5.8.0.21, the "
                     f"range affected by CVE-2024-50623 (unrestricted file upload/download → RCE, "
                     f"on CISA KEV)"),
        remediation=("Upgrade to 5.8.0.24 or later — the 5.8.0.21 patch was found incomplete "
                     "(see CVE-2024-55956). Disable the Autorun directory and restrict the "
                     "listener to trusted partners until patched."),
        detail=f"version={version}",
        source_ref={"cve": "CVE-2024-50623", "advisory": "Cleo Product Security Advisory"},
    )]


@detector(kinds=["mft_server"], rule_id="MFT.CLEO.AUTORUN_RCE_CVE_2024_55956", severity="critical",
          title="Cleo MFT version is affected by the unauthenticated Autorun RCE (CVE-2024-55956)")
def cleo_autorun_rce_55956(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("product") != "cleo":
        return []
    version = raw.get("version")
    vuln = _cleo_55956_vulnerable(version)
    if vuln is False:
        return []
    if vuln is None:
        return _na_version("Cleo Harmony/VLTrader/LexiCom", version, "CVE-2024-55956", "≥5.8.0.24")
    return [Hit(
        observation=(f"Cleo Harmony/VLTrader/LexiCom version {version} is below 5.8.0.24, the fix "
                     f"for CVE-2024-55956 (unauthenticated command execution via the Autorun "
                     f"directory, on CISA KEV; the earlier 5.8.0.21 remained exploitable)"),
        remediation=("Upgrade to 5.8.0.24 or later and clear/disable the Autorun directory. "
                     "Restrict the listener to known partner IPs until patched."),
        detail=f"version={version}",
        source_ref={"cve": "CVE-2024-55956", "advisory": "Cleo Product Security Advisory"},
    )]


@detector(kinds=["mft_server"], rule_id="MFT.PATCH.VENDOR_ADVISORY_REVIEW", severity="medium",
          title="MFT product has no verified patch floor in this scanner")
def patch_state_unverified(r, ctx) -> list:
    """Honest patch-state for products this scanner recognizes but has no VERIFIED version→CVE
    floor for (Sterling File Gateway, Axway SecureTransport). Rather than assert an unverified CVE,
    it emits a not-assessable pointer to the vendor advisory — a coverage gap, never a pass."""
    raw = r.raw or {}
    if raw.get("product") not in ("sterling", "axway"):
        return []
    version = raw.get("version")
    label = {"sterling": "IBM Sterling File Gateway / B2B Integrator",
             "axway": "Axway SecureTransport"}[raw.get("product")]
    return [Hit(
        observation=(f"{label} reports version {version!r}; this scanner has no verified "
                     f"version→CVE floor for it (its advisories are frequent and version-specific), "
                     f"so patch state was not determined"),
        remediation=(f"Review the running build against the current {label} security bulletins "
                     "(directory-traversal, deserialization and RCE advisories) and apply the "
                     "latest fix pack."),
        detail=f"product={raw.get('product')} version={version}",
        assessable=False,
        assessment_reason="no verified patch floor for this product in the rulepack",
        source_ref={"product": raw.get("product"), "advisory": "vendor security bulletins"},
    )]


# ── AS2 message security ──────────────────────────────────────────────────────
@detector(kinds=["mft_endpoint"], rule_id="MFT.AS2.NO_MESSAGE_SIGNING", severity="high",
          title="AS2 endpoint does not require message signing")
def as2_no_signing(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("endpoint_type") != "as2":
        return []
    signing = raw.get("message_signing")
    if signing is None:
        return [Hit(
            observation=(f"AS2 endpoint {raw.get('name')} did not report its message-signing "
                         f"setting, so non-repudiation could not be assessed"),
            remediation="Confirm the AS2 partner agreement requires signed messages (and MDNs).",
            detail=f"endpoint={raw.get('name')}",
            assessable=False,
            assessment_reason="message_signing not reported by the admin API",
            source_ref={"as2": "message_signing"},
        )]
    if signing:
        return []
    return [Hit(
        observation=(f"AS2 endpoint {raw.get('name')} accepts unsigned messages, so message "
                     f"integrity and non-repudiation of partner submissions are not enforced"),
        remediation=("Require message signing (and signed MDNs) on the AS2 agreement. Unsigned AS2 "
                     "lets a party forge or repudiate a transmission."),
        detail=f"endpoint={raw.get('name')} message_signing=False",
        source_ref={"as2": "message_signing"},
    )]


@detector(kinds=["mft_endpoint"], rule_id="MFT.AS2.NO_ENCRYPTION", severity="high",
          title="AS2 endpoint does not require message encryption")
def as2_no_encryption(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("endpoint_type") != "as2":
        return []
    enc = raw.get("message_encryption")
    if enc is None:
        return [Hit(
            observation=(f"AS2 endpoint {raw.get('name')} did not report its message-encryption "
                         f"setting, so payload confidentiality could not be assessed"),
            remediation="Confirm the AS2 agreement requires encrypted message bodies.",
            detail=f"endpoint={raw.get('name')}",
            assessable=False,
            assessment_reason="message_encryption not reported by the admin API",
            source_ref={"as2": "message_encryption"},
        )]
    if enc:
        return []
    return [Hit(
        observation=(f"AS2 endpoint {raw.get('name')} accepts unencrypted message bodies, so "
                     f"partner payloads are protected only by the transport (if any), not end-to-end"),
        remediation=("Require message-level encryption on the AS2 agreement in addition to TLS. "
                     "AS2 payloads routinely carry EDI/PII and must be encrypted at the message layer."),
        detail=f"endpoint={raw.get('name')} message_encryption=False",
        source_ref={"as2": "message_encryption"},
    )]


# ── SFTP auth hygiene ─────────────────────────────────────────────────────────
@detector(kinds=["mft_endpoint"], rule_id="MFT.SFTP.PASSWORD_AUTH_ENABLED", severity="medium",
          title="SFTP endpoint allows password authentication")
def sftp_password_auth(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("endpoint_type") != "sftp":
        return []
    pw = raw.get("password_auth_allowed")
    if pw is None:
        return [Hit(
            observation=(f"SFTP endpoint {raw.get('name')} did not report whether password "
                         f"authentication is allowed, so its auth mode was not assessed"),
            remediation="Confirm the SFTP endpoint requires public-key (or key + password) auth.",
            detail=f"endpoint={raw.get('name')}",
            assessable=False,
            assessment_reason="password_auth_allowed not reported by the admin API",
            source_ref={"sftp": "password_auth_allowed"},
        )]
    if not pw:
        return []
    return [Hit(
        observation=(f"SFTP endpoint {raw.get('name')} allows password authentication for partner "
                     f"transfer accounts"),
        remediation=("Require public-key authentication for partner SFTP accounts (optionally key "
                     "plus password). Password-only SFTP exposes partner transfers to credential "
                     "stuffing and brute force."),
        detail=f"endpoint={raw.get('name')} password_auth_allowed=True",
        source_ref={"sftp": "password_auth_allowed"},
    )]


@detector(kinds=["mft_endpoint"], rule_id="MFT.SFTP.WEAK_HOST_KEY", severity="high",
          title="SFTP endpoint uses a weak host key")
def sftp_weak_host_key(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("endpoint_type") != "sftp":
        return []
    weak = raw.get("weak_host_key")
    if weak is None:
        return [Hit(
            observation=(f"SFTP endpoint {raw.get('name')} did not report a host-key algorithm or "
                         f"length, so host-key strength was not assessed"),
            remediation="Confirm the SFTP host key is Ed25519 or RSA (rsa-sha2-256/512, ≥2048-bit).",
            detail=f"endpoint={raw.get('name')}",
            assessable=False,
            assessment_reason="host key algorithm/length not reported by the admin API",
            source_ref={"sftp": "host_key_algorithm"},
        )]
    if not weak:
        return []
    return [Hit(
        observation=(f"SFTP endpoint {raw.get('name')} presents a weak host key "
                     f"(algorithm={raw.get('host_key_algorithm')} bits={raw.get('host_key_bits')}): "
                     f"a DSA or SHA-1/undersized RSA key"),
        remediation=("Replace the host key with Ed25519 or RSA ≥2048-bit using rsa-sha2-256/512, "
                     "and disable ssh-dss/ssh-rsa(SHA-1). A weak host key enables MITM against "
                     "partner clients that cannot pin a strong key."),
        detail=(f"endpoint={raw.get('name')} algorithm={raw.get('host_key_algorithm')} "
                f"bits={raw.get('host_key_bits')}"),
        source_ref={"sftp": "host_key_algorithm"},
    )]


# ── TLS hygiene on the server surface ─────────────────────────────────────────
@detector(kinds=["mft_server"], rule_id="MFT.TLS.WEAK_OR_EXPIRED", severity="high",
          title="MFT admin/API surface has weak, expired, or absent TLS")
def tls_weak_or_expired(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("probe_outcome") == "error":
        return []   # unreachable is the SERVER not-assessable rule's job, not this one's
    scheme = raw.get("scheme")
    tls = raw.get("tls") or {}
    if scheme != "https":
        return [Hit(
            observation=(f"the {raw.get('product')} admin/API surface at {raw.get('host')} is "
                         f"served over plaintext HTTP, so admin credentials and partner data cross "
                         f"the network unencrypted"),
            remediation="Serve the MFT admin/API surface over HTTPS only and redirect HTTP to HTTPS.",
            detail=f"scheme={scheme} host={raw.get('host')}",
            source_ref={"tls": "scheme"},
        )]
    status = tls.get("cert_status")
    negotiated = tls.get("negotiated")
    weak_version = negotiated in _WEAK_TLS_VERSIONS
    if tls.get("expired") or status in ("expired", "invalid", "self_signed") or weak_version:
        why = ("certificate expired" if tls.get("expired")
               else f"certificate {status}" if status in ("invalid", "self_signed")
               else f"weak TLS version {negotiated}")
        return [Hit(
            observation=(f"the {raw.get('product')} HTTPS surface at {raw.get('host')} has {why} "
                         f"(negotiated={negotiated}, cert_status={status})"),
            remediation=("Install a valid, unexpired certificate from a trusted CA and disable TLS "
                         "versions below 1.2. Partners validate this endpoint; a bad certificate "
                         "trains them to click through warnings."),
            detail=f"cert_status={status} negotiated={negotiated} expired={tls.get('expired')}",
            source_ref={"tls": "certificate"},
        )]
    if status in (None, "unknown"):
        return [Hit(
            observation=(f"the {raw.get('product')} HTTPS surface at {raw.get('host')} did not "
                         f"complete a TLS probe (cert_status={status}), so TLS hygiene was not assessed"),
            remediation="Confirm the endpoint presents a valid certificate and TLS 1.2+ only.",
            detail=f"cert_status={status} error={tls.get('cert_error')}",
            assessable=False,
            assessment_reason="TLS probe did not return a certificate status",
            source_ref={"tls": "probe"},
        )]
    return []


# ── partner / transfer accounts (NHI surface) ─────────────────────────────────
@detector(kinds=["mft_transfer_account"], rule_id="MFT.TRANSFER.ANONYMOUS_ACCOUNT", severity="high",
          title="MFT transfer account is anonymous or an enabled default")
def transfer_anonymous_account(r, ctx) -> list:
    raw = r.raw or {}
    anonymous = bool(raw.get("anonymous"))
    default_enabled = bool(raw.get("is_default")) and raw.get("enabled") is not False
    if not (anonymous or default_enabled):
        return []
    why = "anonymous" if anonymous else "a default account left enabled"
    return [Hit(
        observation=(f"MFT transfer account {raw.get('username')!r} is {why}, so partner-data "
                     f"transfer is possible without an individually-authenticated identity"),
        remediation=("Disable anonymous and default transfer accounts; require a named account "
                     "with its own credential per partner. Anonymous MFT accounts erase the audit "
                     "trail on who moved which file."),
        detail=(f"username={raw.get('username')} anonymous={anonymous} "
                f"is_default={raw.get('is_default')} enabled={raw.get('enabled')}"),
        source_ref={"account": raw.get("username")},
    )]


@detector(kinds=["mft_transfer_account"], rule_id="MFT.TRANSFER.STORED_CREDENTIAL", severity="low",
          title="MFT transfer account stores a partner credential")
def transfer_stored_credential(r, ctx) -> list:
    """NHI awareness: a stored partner/transfer credential is standing secret material on the
    appliance. Reported at low (inventory), raised when the store is plaintext-capable — the
    connector records presence/type only, never the value."""
    raw = r.raw or {}
    if not raw.get("stored_credential_present"):
        return []
    plaintext = raw.get("credential_plaintext_capable")
    sev = "medium" if plaintext is True else "low"
    pt = ("stored in a reversible/plaintext-capable form" if plaintext is True
          else "stored (storage strength not reported)" if plaintext is None
          else "stored hashed/encrypted")
    return [Hit(
        observation=(f"MFT transfer account {raw.get('username')!r} has a "
                     f"{raw.get('credential_type') or 'password'} credential {pt} on the appliance"),
        remediation=("Prefer key/certificate authentication over stored partner passwords, and "
                     "ensure any stored secret is encrypted at rest with a protected key. Inventory "
                     "these as non-human credentials and rotate on partner offboarding."),
        detail=(f"username={raw.get('username')} type={raw.get('credential_type')} "
                f"plaintext_capable={plaintext}"),
        severity=sev,
        source_ref={"account": raw.get("username"), "credential": "stored"},
    )]


def _age_days(v, now=None):
    from datetime import datetime, timezone
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return ((now or datetime.now(timezone.utc)) - d).days


@detector(kinds=["mft_transfer_account"], rule_id="MFT.TRANSFER.CREDENTIAL_NOT_ROTATED", severity="medium",
          title="MFT partner key or password has not been changed in over a year")
def transfer_credential_not_rotated(r, ctx) -> list:
    """Operators' words: partner SSH keys are swapped by email once and then never rotated.
    Fires only when the export gives the date the credential was set."""
    raw = r.raw or {}
    if raw.get("enabled") is False or raw.get("anonymous"):
        return []
    limit = int((ctx.config or {}).get("mft_credential_max_age_days") or 365)
    age = _age_days(raw.get("credential_created_at"))
    if age is None or age <= limit:
        return []
    kind = raw.get("credential_type") or raw.get("auth_type") or "credential"
    return [Hit(
        observation=(f"MFT transfer account {raw.get('username')!r}"
                     + (f" (partner {raw.get('partner_id')})" if raw.get("partner_id") else "")
                     + f" uses a {kind} set {age} days ago, longer than the {limit}-day limit"),
        remediation=("Agree a new key with the partner and swap it in: add the new public key, confirm a "
                     "transfer works, then remove the old one. Exchange keys through a channel you "
                     "control, not plain email, and put a yearly renewal date on the account."),
        detail=f"credential_age_days={age} limit_days={limit}",
        source_ref={"account": raw.get("username"), "field": "credential_created_at"},
    )]


@detector(kinds=["mft_transfer_account"], rule_id="MFT.TRANSFER.ACCOUNT_UNUSED", severity="low",
          title="MFT partner account has not logged in for six months")
def transfer_account_unused(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("enabled") is False:
        return []
    limit = int((ctx.config or {}).get("mft_unused_days") or 180)
    age = _age_days(raw.get("last_login_at"))
    if age is None or age <= limit:
        return []
    return [Hit(
        observation=(f"MFT transfer account {raw.get('username')!r} is enabled but last logged in "
                     f"{age} days ago"),
        remediation=("Ask the business owner whether this partner still sends files. If not, disable "
                     "the account and remove its key; an unused account with a live key is a quiet "
                     "way in."),
        detail=f"days_since_login={age} limit_days={limit}",
        source_ref={"account": raw.get("username"), "field": "last_login_at"},
    )]


# ── the coverage-gap anchor ───────────────────────────────────────────────────
@detector(kinds=["mft_server"], rule_id="MFT.SERVER.NOT_ASSESSABLE", severity="info",
          title="An MFT target could not be assessed")
def server_not_assessable(r, ctx) -> list:
    """The honest third outcome at appliance scope: a target that was unreachable, or reached but
    not fingerprintable to a known product, is a COVERAGE GAP the connector recorded instead of
    failing the scan — surfaced here as not-assessable rather than an empty (clean) result."""
    raw = r.raw or {}
    outcome = raw.get("probe_outcome")
    if outcome == "error":
        return [Hit(
            observation=(f"MFT target {raw.get('base_url')} was not reachable "
                         f"({raw.get('error')}), so its posture was not assessed"),
            remediation=("Confirm the base URL and that the engine/worker can reach the appliance "
                         "admin surface, then re-scan."),
            detail=f"base_url={raw.get('base_url')} error={raw.get('error')}",
            assessable=False,
            assessment_reason=f"target unreachable: {raw.get('error')}",
            source_ref={"target": raw.get("base_url")},
        )]
    if outcome == "unfingerprinted":
        return [Hit(
            observation=(f"MFT target {raw.get('base_url')} responded (HTTP "
                         f"{raw.get('http_status')}) but did not match a known MFT product "
                         f"fingerprint, so no product rulepack was applied"),
            remediation=("Set the connector's `product` hint if you know the appliance, or confirm "
                         "the base URL points at the MFT admin/API surface (not a load balancer "
                         "splash page)."),
            detail=f"base_url={raw.get('base_url')} banner={raw.get('banner')!r}",
            assessable=False,
            assessment_reason="server reachable but no product fingerprint matched",
            source_ref={"target": raw.get("base_url")},
        )]
    return []
