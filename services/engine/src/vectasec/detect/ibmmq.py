"""IBM MQ detectors — the config-time controls that decide whether a queue manager is reachable
by an unauthenticated or over-privileged remote client.

The order matters in the field: CONNAUTH decides whether a client must authenticate at all,
CHLAUTH decides whether channel-mapping rules run, and each SVRCONN channel's MCAUSER/SSLCIPH
decide what an inbound connection becomes and whether it is encrypted. These rules read those
attributes straight from MQSC DISPLAY output (via the connector's parse layer) and state the
attribute value as evidence, never a conclusion. They run on the distinct `ibmmq_*` kinds, so the
Kafka/RabbitMQ/Redis packs never touch MQ resources.
"""
from ..contracts import Hit
from ..registry import detector
from ..connect.ibmmq import PRIVILEGED_MCAUSER

_CHCKCLNT_NONE = "NONE"
_CHCKCLNT_OPTIONAL = "OPTIONAL"


@detector(kinds=["ibmmq_qmgr"], rule_id="IBMMQ.CONNAUTH.NO_OBJECT", severity="critical",
          title="Queue manager has no connection authentication (CONNAUTH is blank)")
def connauth_missing(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("connauth") or "").strip():
        return []
    return [Hit(
        observation=(f"queue manager {raw.get('qmgr_name')} has CONNAUTH blank — no authentication "
                     f"information object is attached, so client connections are not required to "
                     f"present a user id and password"),
        remediation=("Define an AUTHINFO(TYPE(IDPWOS)) object with CHCKCLNT(REQUIRED), set it as "
                     "the queue manager's CONNAUTH, and REFRESH SECURITY TYPE(CONNAUTH). CONNAUTH "
                     "is the single control that forces a remote MQ client to prove who it is."),
        detail="connauth=(blank)",
        source_ref={"mqsc": "DISPLAY QMGR CONNAUTH"},
    )]


@detector(kinds=["ibmmq_qmgr"], rule_id="IBMMQ.CONNAUTH.CLIENT_CHECK_DISABLED", severity="critical",
          title="Connection authentication does not check client credentials (CHCKCLNT NONE/OPTIONAL)")
def connauth_chckclnt_open(r, ctx) -> list:
    raw = r.raw or {}
    connauth = str(raw.get("connauth") or "").strip()
    if not connauth:
        return []   # NO_OBJECT owns the blank-CONNAUTH case
    if not raw.get("authinfo_readable"):
        return [Hit(
            observation=(f"queue manager {raw.get('qmgr_name')} names CONNAUTH '{connauth}' but its "
                         f"AUTHINFO object could not be read, so CHCKCLNT (whether remote clients "
                         f"are password-checked) was not determined"),
            remediation=(f"Grant the scanning user DISPLAY authority on AUTHINFO('{connauth}') and "
                         f"re-run, or DISPLAY AUTHINFO('{connauth}') CHCKCLNT manually and confirm "
                         f"it is REQUIRED."),
            detail=f"connauth={connauth} authinfo_readable=False",
            assessable=False,
            assessment_reason="CONNAUTH AUTHINFO object not readable with the supplied credentials",
            source_ref={"mqsc": f"DISPLAY AUTHINFO({connauth}) CHCKCLNT"},
        )]
    chckclnt = str(raw.get("chckclnt") or "").strip().upper()
    if chckclnt not in (_CHCKCLNT_NONE, _CHCKCLNT_OPTIONAL):
        return []
    optional = chckclnt == _CHCKCLNT_OPTIONAL
    return [Hit(
        observation=(f"queue manager {raw.get('qmgr_name')} CONNAUTH object '{connauth}' has "
                     f"CHCKCLNT({chckclnt}) — " + ("clients that do not send a user id and password "
                     "are admitted unchecked" if optional else "no client is password-checked")),
        remediation=("Set CHCKCLNT(REQUIRED) on the CONNAUTH AUTHINFO object (REQDADM at minimum) "
                     "and REFRESH SECURITY TYPE(CONNAUTH). CHCKCLNT(NONE/OPTIONAL) leaves the queue "
                     "manager open to unauthenticated remote clients."),
        detail=f"connauth={connauth} chckclnt={chckclnt}",
        severity="high" if optional else "critical",
        source_ref={"mqsc": f"DISPLAY AUTHINFO({connauth}) CHCKCLNT"},
    )]


@detector(kinds=["ibmmq_qmgr"], rule_id="IBMMQ.CHLAUTH.DISABLED", severity="high",
          title="Channel authentication records are disabled (CHLAUTH DISABLED)")
def chlauth_disabled(r, ctx) -> list:
    raw = r.raw or {}
    if str(raw.get("chlauth_records") or "").strip().upper() != "DISABLED":
        return []
    return [Hit(
        observation=(f"queue manager {raw.get('qmgr_name')} has CHLAUTH(DISABLED) — channel "
                     f"authentication records are switched off, so the rules that block privileged "
                     f"ids and restrict channels by address do not run"),
        remediation=("ALTER QMGR CHLAUTH(ENABLED) and REFRESH SECURITY TYPE(CONNAUTH). With CHLAUTH "
                     "disabled, the default rules that block administrative access over SVRCONN "
                     "channels are inactive."),
        detail="chlauth=DISABLED",
        source_ref={"mqsc": "DISPLAY QMGR CHLAUTH"},
    )]


@detector(kinds=["ibmmq_qmgr"], rule_id="IBMMQ.CONNAUTH.LOCAL_CHECK_DISABLED", severity="low",
          title="Locally-bound applications are not authenticated (CHCKLOCL NONE)")
def connauth_chcklocl_none(r, ctx) -> list:
    raw = r.raw or {}
    if not raw.get("authinfo_readable"):
        return []
    if str(raw.get("chcklocl") or "").strip().upper() != _CHCKCLNT_NONE:
        return []
    return [Hit(
        observation=(f"queue manager {raw.get('qmgr_name')} CONNAUTH object has CHCKLOCL(NONE) — "
                     f"applications binding locally are not required to authenticate"),
        remediation=("Set CHCKLOCL(OPTIONAL) or higher so locally-bound applications are "
                     "authenticated. Requires host access to exploit, so it is lower risk than "
                     "CHCKCLNT, but it removes a defence-in-depth layer."),
        detail=f"chcklocl=NONE connauth={raw.get('connauth')}",
        source_ref={"mqsc": "DISPLAY AUTHINFO CHCKLOCL"},
    )]


@detector(kinds=["ibmmq_channel"], rule_id="IBMMQ.CHANNEL.MCAUSER_PRIVILEGED", severity="critical",
          title="SVRCONN channel runs inbound clients as a privileged user (MCAUSER)")
def channel_mcauser_privileged(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("channel_type") != "SVRCONN":
        return []
    mcauser = str(raw.get("mcauser") or "").strip()
    if mcauser.lower() not in PRIVILEGED_MCAUSER:
        return []
    return [Hit(
        observation=(f"SVRCONN channel {raw.get('channel_name')} has MCAUSER('{mcauser}'), so every "
                     f"client that connects on it runs with administrative authority"),
        remediation=(f"Set MCAUSER to a low-privilege, non-mqm user id on '{raw.get('channel_name')}' "
                     f"and add a CHLAUTH rule that blocks privileged ids (TYPE(BLOCKUSER) "
                     f"USERLIST(*MQADMIN)). A privileged MCAUSER hands remote clients full control."),
        detail=f"channel={raw.get('channel_name')} mcauser={mcauser}",
        source_ref={"mqsc": f"DISPLAY CHANNEL({raw.get('channel_name')}) MCAUSER"},
    )]


@detector(kinds=["ibmmq_channel"], rule_id="IBMMQ.CHANNEL.MCAUSER_BLANK", severity="high",
          title="SVRCONN channel has a blank MCAUSER (runs as the flowed identity)")
def channel_mcauser_blank(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("channel_type") != "SVRCONN":
        return []
    if str(raw.get("mcauser") or "").strip() != "":
        return []
    return [Hit(
        observation=(f"SVRCONN channel {raw.get('channel_name')} has a blank MCAUSER — inbound "
                     f"connections run under the user id the client asserts rather than a fixed, "
                     f"low-privilege identity"),
        remediation=("Set an explicit low-privilege MCAUSER on the channel and enforce identity with "
                     "CHLAUTH/CONNAUTH. A blank MCAUSER lets a client present a privileged id (e.g. "
                     "mqm) unless CHLAUTH rules block it."),
        detail=f"channel={raw.get('channel_name')} mcauser=(blank)",
        source_ref={"mqsc": f"DISPLAY CHANNEL({raw.get('channel_name')}) MCAUSER"},
    )]


@detector(kinds=["ibmmq_channel"], rule_id="IBMMQ.CHANNEL.NO_TLS", severity="high",
          title="SVRCONN channel has no TLS cipher (SSLCIPH blank)")
def channel_no_tls(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("channel_type") != "SVRCONN":
        return []
    if str(raw.get("sslciph") or "").strip():
        return []
    return [Hit(
        observation=(f"SVRCONN channel {raw.get('channel_name')} has SSLCIPH blank — client "
                     f"connections, including any credentials flowed on them, cross the network "
                     f"unencrypted"),
        remediation=("Set an SSLCIPH (e.g. ANY_TLS12_OR_HIGHER) on the channel, configure the queue "
                     "manager key repository, and require TLS from clients. Without SSLCIPH the "
                     "channel is plaintext and sniffable."),
        detail=f"channel={raw.get('channel_name')} sslciph=(blank)",
        source_ref={"mqsc": f"DISPLAY CHANNEL({raw.get('channel_name')}) SSLCIPH"},
    )]


@detector(kinds=["ibmmq_channel"], rule_id="IBMMQ.CHANNEL.SSLCAUTH_OPTIONAL", severity="medium",
          title="TLS SVRCONN channel does not require a client certificate (SSLCAUTH OPTIONAL)")
def channel_sslcauth_optional(r, ctx) -> list:
    raw = r.raw or {}
    if raw.get("channel_type") != "SVRCONN":
        return []
    if not str(raw.get("sslciph") or "").strip():
        return []   # no TLS at all is NO_TLS's finding, not this one
    if str(raw.get("sslcauth") or "").strip().upper() != _CHCKCLNT_OPTIONAL:
        return []
    return [Hit(
        observation=(f"SVRCONN channel {raw.get('channel_name')} uses TLS (SSLCIPH set) but has "
                     f"SSLCAUTH(OPTIONAL), so a client may connect without presenting a certificate"),
        remediation=("Set SSLCAUTH(REQUIRED) so the channel enforces mutual TLS. OPTIONAL lets a "
                     "client negotiate TLS without proving its identity via a certificate."),
        detail=f"channel={raw.get('channel_name')} sslcauth=OPTIONAL",
        source_ref={"mqsc": f"DISPLAY CHANNEL({raw.get('channel_name')}) SSLCAUTH"},
    )]


@detector(kinds=["ibmmq_channel"], rule_id="IBMMQ.CHANNEL.SYSTEM_SVRCONN_UNPROTECTED",
          severity="critical",
          title="A SYSTEM SVRCONN channel is usable while CHLAUTH is disabled")
def system_svrconn_unprotected(r, ctx) -> list:
    """Cross-resource: the built-in SYSTEM.DEF.SVRCONN / SYSTEM.ADMIN.SVRCONN channels are the
    classic admin door. They are normally neutralised by the default CHLAUTH rules; with CHLAUTH
    disabled at the queue manager, a blank/privileged MCAUSER on one is directly exploitable."""
    raw = r.raw or {}
    if raw.get("channel_type") != "SVRCONN":
        return []
    name = str(raw.get("channel_name") or "")
    if not name.upper().startswith("SYSTEM."):
        return []
    mcauser = str(raw.get("mcauser") or "").strip()
    if mcauser and mcauser.lower() not in PRIVILEGED_MCAUSER:
        return []   # a locked-down SYSTEM channel (non-privileged MCAUSER) is not the risk here
    qmgr = next((q for q in ctx.of_kind("ibmmq_qmgr")
                 if q.ext_id == raw.get("qmgr_ext_id")
                 or (q.raw or {}).get("qmgr_name") == raw.get("qmgr_name")), None)
    if qmgr is None or str((qmgr.raw or {}).get("chlauth_records") or "").upper() != "DISABLED":
        return []
    return [Hit(
        observation=(f"built-in channel {name} is a SVRCONN with MCAUSER('{mcauser or '(blank)'}') "
                     f"and the queue manager has CHLAUTH(DISABLED), so the default rules that block "
                     f"this administrative channel are not in effect"),
        remediation=(f"Re-enable CHLAUTH (ALTER QMGR CHLAUTH(ENABLED)), or DELETE/disable "
                     f"'{name}' and restrict administrative access to a dedicated, TLS-secured "
                     f"channel with a non-privileged MCAUSER."),
        detail=f"channel={name} mcauser={mcauser or '(blank)'} qmgr_chlauth=DISABLED",
        source_ref={"mqsc": "DISPLAY CHANNEL / DISPLAY QMGR CHLAUTH"},
    )]


@detector(kinds=["ibmmq_queue"], rule_id="IBMMQ.QUEUE.WIDE_AUTHORITY", severity="high",
          title="Queue grants broad authority to a privileged or wildcard entity")
def queue_wide_authority(r, ctx) -> list:
    """An authority record on this queue that grants MQI/admin authority to the mqm group, a
    wildcard entity, or an *all* authority set — a real over-grant read from DISPLAY AUTHREC."""
    raw = r.raw or {}
    hits: list = []
    for rec in raw.get("authority_records") or []:
        entity = str(rec.get("entity") or "").strip()
        authorities = rec.get("authorities") or []
        wide_entity = entity.lower() in PRIVILEGED_MCAUSER or entity in ("*", "nobody")
        wide_auth = any(a in ("all", "alladm", "allmqi") for a in authorities)
        if not (wide_entity or wide_auth):
            continue
        hits.append(Hit(
            observation=(f"queue {raw.get('queue_name')} has an authority record granting "
                         f"{'/'.join(authorities) or '(none)'} to {rec.get('entity_type') or 'entity'} "
                         f"'{entity}'"),
            remediation=("Remove the wide authority record (SET AUTHREC ... AUTHRMV) and grant only "
                         "the specific authorities (+put/+get/+browse) each application group needs. "
                         "Broad or *all* authority on a queue defeats per-object access control."),
            detail=f"queue={raw.get('queue_name')} entity={entity} authorities={','.join(authorities)}",
            source_ref={"mqsc": f"DISPLAY AUTHREC PROFILE({raw.get('queue_name')})"},
        ))
    return hits
