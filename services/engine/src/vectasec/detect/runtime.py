"""Runtime evidence rulepack — what the estate is ACTUALLY doing, not what it may do.

Every other rulepack in this product reads configuration: what a broker permits. These rules
read `runtime_client` resources, which record who was connected when the scanner looked. That
difference is the whole point. "The guest account exists" is a posture finding; "the guest
account is in use right now, from this address, over an unencrypted socket" is an incident.

A word on the name. Gartner's Adversarial Exposure Validation defines *validation* as safely
executing an attack to prove it works. We do not do that, so nothing here is called validation:
this is EVIDENCE — an observation with a timestamp and a known coverage boundary.

Coverage honesty is doubly important here, because runtime evidence is the one place where
ABSENCE is tempting to over-read. Seeing no clients does not mean a broker is unused; it means
nothing was connected during the instants we looked. The windowed "never observed" reasoning
therefore lives in `runtime_evidence.py`, where the observation window is a real number with a
real start date — not in this file, where a single scan is all anyone can see.
"""
from ..contracts import Hit
from ..registry import detector

# Account names that ship with the product and are meant to be removed, not used. A live
# connection authenticated as one of these is materially worse than its mere existence.
#
# The database superusers below were added when the PgBouncer runtime source landed: a pooler
# reports the role every client authenticated as, and `postgres` — the account PostgreSQL
# creates at initdb and every tutorial connects as — was sailing past this rule while
# connect/pgbouncer.py's own _SHARED_ADMIN already knew it was the broad-admin pattern. Two
# lists disagreeing about what "shared default" means is how a rule quietly stops covering
# half the estate, so the vendor-shipped superusers are named here explicitly.
_SHARED_DEFAULTS = {
    # generic
    "guest", "default", "admin", "administrator", "root",
    # database / pooler superusers shipped by the vendor
    "postgres", "sa", "sys", "system", "mysql", "elastic",
}

# SASL mechanisms that put the credential itself on the wire. Harmless inside TLS, fatal
# outside it.
_CLEARTEXT_MECHANISMS = {"PLAIN", "AMQPLAIN", "LOGIN", "CRAM-MD5"}


def _raw(r) -> dict:
    return r.raw or {}


def _ref(r, **extra) -> dict:
    raw = _raw(r)
    return {"principal": raw.get("principal"), "peer_host": raw.get("peer_host"),
            "observed_via": raw.get("observed_via"), "evidence_type": "runtime", **extra}


@detector(kinds=["runtime_client"], rule_id="RUNTIME.CREDENTIAL.CLEARTEXT_ON_WIRE",
          severity="critical", title="Credentials authenticated over an unencrypted connection")
def cleartext_credentials(r, ctx) -> list:
    """A cleartext SASL mechanism outside TLS means the password crossed the network in the
    clear — and it did so for real, on a connection we observed, not hypothetically."""
    raw = _raw(r)
    mechanisms = {str(m).upper() for m in (raw.get("auth_mechanisms") or [])}
    cleartext = mechanisms & _CLEARTEXT_MECHANISMS
    if not cleartext:
        return []
    if raw.get("tls_all") is True:
        return []                     # inside TLS this is the normal, correct configuration
    if raw.get("tls_all") is None and "tls_mixed" not in raw:
        # The MECHANISM is confirmed cleartext; only the transport is unknown. Staying silent
        # means a PLAIN authentication we definitely observed goes unreported because we could
        # not tell whether TLS wrapped it — the finding is halved, not absent.
        return [Hit(
            observation=(f"{raw.get('connections')} live connection(s) authenticated as "
                         f"{raw.get('principal') or 'an unnamed principal'} used the "
                         f"{', '.join(sorted(cleartext))} SASL mechanism; this source does not "
                         f"report whether the connection was TLS "
                         f"(observed via {raw.get('observed_via')})"),
            detail="A cleartext mechanism sends the password itself. Inside TLS that is normal; "
                   "outside it the credential is on the wire. Which of those happened here "
                   "could not be determined from this source.",
            remediation="Confirm these clients connect over the TLS listener, and disable the "
                        "plaintext one so the question cannot arise.",
            assessable=False,
            assessment_reason="the transport could not be read, so cleartext exposure is unknown",
            source_ref=_ref(r, mechanisms=sorted(cleartext)),
        )]

    principal = raw.get("principal") or "an unnamed principal"
    mixed = raw.get("tls_mixed")
    transport = ("some of these connections are TLS and some are not"
                 if mixed else "the connection is not TLS")
    return [Hit(
        observation=(f"{raw.get('connections')} live connection(s) authenticated as "
                     f"{principal!r} from {raw.get('peer_host')} used the "
                     f"{', '.join(sorted(cleartext))} SASL mechanism, and {transport} "
                     f"(observed via {raw.get('observed_via')})"),
        detail="A cleartext mechanism sends the password itself. Outside TLS, anyone able to "
               "observe this path has the credential — not a hash, the credential. This is an "
               "observation of live traffic, not a configuration possibility.",
        remediation="Move these clients to the TLS listener and disable the plaintext one. "
                    "Then rotate the credential: assume it is known.",
        source_ref=_ref(r, mechanisms=sorted(cleartext)),
    )]


@detector(kinds=["runtime_client"], rule_id="RUNTIME.IDENTITY.SHARED_DEFAULT_IN_USE",
          severity="high", title="A default or shared account is actively in use")
def shared_default_in_use(r, ctx) -> list:
    """The existence of `guest` is a finding elsewhere. This is the escalation: it is being
    used, so removing it will break something — which is exactly why it never gets removed."""
    raw = _raw(r)
    principal = str(raw.get("principal") or "").lower()
    if principal not in _SHARED_DEFAULTS:
        return []
    return [Hit(
        observation=(f"the shared/default account {raw.get('principal')!r} has "
                     f"{raw.get('connections')} live connection(s) from "
                     f"{raw.get('peer_host')} (observed via {raw.get('observed_via')})"),
        detail="Work done under a shared account cannot be attributed to a service or a "
               "person, so its blast radius cannot be reasoned about and its credential "
               "cannot be rotated without breaking an unknown set of clients.",
        remediation="Issue a distinct principal per client with only the permissions that "
                    "client needs, migrate the clients named above, then disable this account. "
                    "The peer address here tells you who to migrate first.",
        source_ref=_ref(r),
    )]


@detector(kinds=["runtime_client"], rule_id="RUNTIME.IDENTITY.UNATTRIBUTED_CLIENT",
          severity="medium", title="Live client cannot be attributed to a principal")
def unattributed_client(r, ctx) -> list:
    """A connection the broker cannot name is a connection nobody can revoke."""
    raw = _raw(r)
    if raw.get("principal_known") is not False:
        return []
    return [Hit(
        observation=(f"{raw.get('connections')} live connection(s) from "
                     f"{raw.get('peer_host')} carry no authenticated principal that the "
                     f"server could report (observed via {raw.get('observed_via')})"),
        detail="Without a principal there is no way to say what this client is entitled to, "
               "no way to revoke it individually, and no audit trail that names it. On Redis "
               "this usually means the server predates ACLs or the client never authenticated.",
        remediation="Enable ACLs and require authentication, then give this client its own "
                    "user. Until then its access is neither limited nor attributable.",
        source_ref=_ref(r),
    )]


@detector(kinds=["runtime_client"], rule_id="RUNTIME.TRANSPORT.PLAINTEXT_IN_USE",
          severity="high", title="Live connection is not encrypted")
def plaintext_transport_in_use(r, ctx) -> list:
    """The transport itself, independent of how the client authenticated.

    RUNTIME.CREDENTIAL.CLEARTEXT_ON_WIRE is about the CREDENTIAL crossing the network in the
    clear, and only fires when the mechanism is one of the cleartext SASL family. This rule is
    about the SESSION: a client using a strong mechanism (SCRAM, mTLS-less certs, an nkey) over
    a plaintext socket protects its password but not one byte of the data it then moves. On a
    pooler that data is every row the application reads; on a broker it is every message.

    The two rules can both fire on one client, and should — they are different exposures with
    different remediations, and collapsing them would let "we fixed the auth mechanism" read as
    "we fixed the exposure".
    """
    raw = _raw(r)
    tls_all = raw.get("tls_all")
    if tls_all is True:
        return []
    if tls_all is None:
        # The source did not report transport at all (an older PgBouncer, a monitoring endpoint
        # that omits the field). Silence here would be indistinguishable from "checked, it is
        # encrypted", so this is a coverage gap, stated as one.
        return [Hit(
            observation=(f"{raw.get('connections')} live connection(s) as "
                         f"{raw.get('principal') or 'an unnamed principal'} from "
                         f"{raw.get('peer_host')} were observed, but this source does not report "
                         f"whether the transport was encrypted "
                         f"(observed via {raw.get('observed_via')})"),
            detail="Whether these sessions are encrypted could not be determined from the data "
                   "this source exposes. That is a gap in coverage, not evidence of safety.",
            remediation="Upgrade the component to a version whose live-connection view reports "
                        "TLS, or confirm at the listener that a plaintext port is not open.",
            assessable=False,
            assessment_reason="the source does not report per-connection transport encryption",
            source_ref=_ref(r),
        )]

    mixed = raw.get("tls_mixed")
    return [Hit(
        observation=(f"{raw.get('connections')} live connection(s) as "
                     f"{raw.get('principal') or 'an unnamed principal'} from "
                     f"{raw.get('peer_host')} "
                     + ("include sessions that are not TLS" if mixed else "are not TLS")
                     + f" (observed via {raw.get('observed_via')})"),
        detail="Everything these sessions carry — queries, messages, results — crosses the "
               "network readable by anyone on the path. This is an observation of live traffic, "
               "not a configuration possibility: the sessions existed when we looked.",
        remediation="Require TLS on the listener these clients reach and migrate them to it, "
                    "then disable the plaintext listener so the state cannot recur. Where the "
                    "credential also crossed in the clear, rotate it.",
        source_ref=_ref(r, tls_mixed=bool(mixed)),
    )]


@detector(kinds=["runtime_client"], rule_id="RUNTIME.ACCESS.UNEXPECTED_PEER",
          severity="medium", title="Client connecting from outside the expected network")
def unexpected_peer(r, ctx) -> list:
    """A public source address on an internal broker. Deliberately narrow: this fires only on
    a peer that is unambiguously non-private, because "unexpected" is otherwise a judgement
    about a network topology we cannot see from here."""
    import ipaddress

    raw = _raw(r)
    peer = str(raw.get("peer_host") or "")
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return []                      # a hostname tells us nothing about locality
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return []
    return [Hit(
        observation=(f"{raw.get('connections')} live connection(s) authenticated as "
                     f"{raw.get('principal') or 'an unnamed principal'} originate from "
                     f"{peer}, which is a public address "
                     f"(observed via {raw.get('observed_via')})"),
        detail="A client reaching this broker from public address space means the broker is "
               "reachable from public address space. Whether that is intended is a question "
               "for the operator; that it is happening is not in question.",
        remediation="Confirm this client is meant to reach the broker from outside your "
                    "network. If it is not, restrict the listener and the security group; if "
                    "it is, require TLS and a dedicated, least-privileged principal for it.",
        source_ref=_ref(r, peer=peer),
    )]
