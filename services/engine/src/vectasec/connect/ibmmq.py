"""IBM MQ connector — read-only mqweb administrative REST + MQSC command surface.

WHY THIS EXISTS. IBM MQ is the message backbone of most banks and insurers, and its posture is
decided almost entirely by four objects a console never shows side by side: the queue manager's
CONNAUTH (does a remote client have to prove who it is at all), CHLAUTH (are channel-mapping
rules even switched on), each SVRCONN channel's MCAUSER (what identity an inbound client runs as)
and SSLCIPH (is that channel encrypted). This connector reads exactly those, writes nothing, and
turns them into resources the rulepack can reason over.

HOW IT READS. IBM MQ's mqweb server exposes an administrative REST API at
`/ibmmq/rest/v2/admin`. Object attributes are fetched by POSTing MQSC DISPLAY commands to
`/admin/action/qmgr/{qmgr}/mqsc` with `type:"runCommandJSON"`, which returns each response as a
parsed `parameters` dict rather than raw text lines. Every command issued here is a DISPLAY — no
DEFINE/ALTER/SET, no state change. The POST needs an `ibm-mq-rest-csrf-token` header (the mqweb
CSRF guard); its value is irrelevant, only its presence.

CREDENTIALS NEVER LEAVE THIS MODULE. The scanner authenticates with HTTP Basic; that password is
used to talk to mqweb and is never copied into any `raw` dict. MQSC DISPLAY of authentication
objects returns policy (CHCKCLNT, AUTHTYPE), never stored user passwords — MQ does not expose
those over REST — so there is no secret material to drop, only absence to record honestly.

DISTINCT KINDS. Emits `ibmmq_qmgr`, `ibmmq_channel`, `ibmmq_queue` so the Kafka/RabbitMQ/Redis
packs never run against MQ resources by accident. IBM's runCommandJSON attribute names drift
across MQ versions (long camelCase names vs. the raw MQSC keyword), so the parse layer looks each
attribute up through a small alias set and is case-insensitive — a name it cannot find becomes
"unreadable" (→ not-assessable), never a silent default.

DENIED READS ARE RECORDED, NOT SMOOTHED OVER. An MQWebAdminRO user is routinely granted DISPLAY
on some objects and not others, so a 403 on one command is the normal case, not a scan failure.
Each administrative read therefore carries its own three-valued flag on the queue manager
resource — `qmgr_readable`, `authinfo_readable`, `channels_readable`, `queues_readable`,
`authrecs_readable` — where None means the read was never attempted, False means it was attempted
and denied, and True means the attributes in this `raw` came off the wire. The rulepack gates on
those flags and IBMMQ.SCAN.NOT_ASSESSABLE reports the gap; without them an absent attribute
coerces to "" and a hardened broker reads as CONNAUTH-blank (fabricated) or as clean (silent).
"""
from urllib.parse import urlparse

import httpx

from ..registry import ConnectorField, connector
from ..contracts import Resource, Edge, Collected
from ..identity import _mk_grant, _mk_identity, identity_extractor

# A blank or these MCAUSER values on an inbound SVRCONN channel mean a remote client runs with
# administrative authority — `mqm` is MQ's superuser group/id; the others are common OS admins.
PRIVILEGED_MCAUSER = {"mqm", "root", "administrator", "admin"}

# CONNAUTH CHCKCLNT values, normalized upper-case. NONE = no client is password-checked;
# OPTIONAL = only clients that bother to send a userid+password are checked.
_CHCKCLNT_OPEN = {"NONE", "OPTIONAL"}


def _attr(params: dict, *aliases, default=None):
    """Case-insensitive lookup of an MQSC attribute across the names MQ's REST layer might use.

    runCommandJSON renames MQSC keywords to long camelCase forms and the exact spelling shifts
    between MQ releases, so a rule that hard-codes one name silently reads None on another build.
    Returns the first alias present (case-insensitively); None means genuinely absent."""
    if not isinstance(params, dict):
        return default
    lower = {str(k).lower(): v for k, v in params.items()}
    for a in aliases:
        v = lower.get(a.lower())
        if v is not None:
            return v
    return default


def _norm(v) -> str:
    return str(v).strip().upper() if v is not None else ""


def _run_mqsc(client: httpx.Client, qmgr: str, command: str, qualifier: str,
              name: str | None = None, parameters: dict | None = None,
              response_parameters=("all",)) -> dict:
    """POST one MQSC DISPLAY as runCommandJSON. Returns an envelope, never a bare list, so a
    permission/HTTP failure stays distinguishable from a legitimately empty result set."""
    body: dict = {"type": "runCommandJSON", "command": command, "qualifier": qualifier}
    if name is not None:
        body["name"] = name
    if response_parameters:
        body["responseParameters"] = list(response_parameters)
    if parameters is not None:
        body["parameters"] = parameters
    try:
        r = client.post(f"/ibmmq/rest/v2/admin/action/qmgr/{qmgr}/mqsc", json=body,
                        headers={"ibm-mq-rest-csrf-token": "vectasec"})
    except httpx.HTTPError as e:
        return {"ok": False, "status": None, "error": f"{type(e).__name__}: {e}"}
    if r.status_code not in (200, 201):
        return {"ok": False, "status": r.status_code, "error": f"http_{r.status_code}"}
    try:
        data = r.json()
    except ValueError:
        return {"ok": False, "status": r.status_code, "error": "non_json_body"}
    responses = [cr.get("parameters") or {} for cr in (data.get("commandResponse") or [])
                 if isinstance(cr, dict)]
    return {"ok": True, "status": r.status_code, "responses": responses,
            "overall_completion": data.get("overallCompletionCode")}


# ── pure parse layer (httpx stays out of tests) ────────────────────────────────
def parse_qmgr(qmgr_name: str, base_url: str, qmgr_params: dict,
               authinfo: dict | None, authinfo_readable: bool, *,
               tls: bool = False, errors: dict | None = None,
               qmgr_readable: bool | None = None,
               channels_readable: bool | None = None, channel_count: int | None = None,
               queues_readable: bool | None = None,
               authrecs_readable: bool | None = None) -> Resource:
    """The queue manager resource. `authinfo` is the DISPLAY AUTHINFO parameters for the object
    CONNAUTH names (None when CONNAUTH is blank or the object could not be read).

    The `*_readable` flags are three-valued — None = the read was never attempted, False =
    attempted and denied, True = the attributes here were actually read. `qmgr_readable` is
    inferred when not supplied: a DISPLAY QMGR that recorded an error, or that returned no
    parameters at all, did not read anything, and the CONNAUTH/CHLAUTH keys below are then None
    (absent) rather than "" (read as blank) — the difference between the two is the difference
    between a fabricated CRITICAL and an honest coverage gap.
    """
    if qmgr_readable is None:
        qmgr_readable = bool(qmgr_params) and not (errors or {}).get("qmgr")
    connauth = str(_attr(qmgr_params, "connectionAuthentication", "connauth", default="") or "").strip()
    chlauth = _norm(_attr(qmgr_params, "channelAuthenticationRecords", "chlauth"))
    sslkeyr = str(_attr(qmgr_params, "sslKeyRepository", "sslkeyr", default="") or "").strip()

    ai = authinfo or {}
    return Resource(
        kind="ibmmq_qmgr",
        name=qmgr_name,
        ext_id=f"ibmmq-qmgr-{qmgr_name}",
        labels={"connauth": (connauth or "(none)") if qmgr_readable else "(unread)",
                "chlauth": (chlauth or "?") if qmgr_readable else "(unread)"},
        raw={
            "qmgr_name": qmgr_name,
            "base_url": base_url,
            "connected_via_tls": bool(tls),
            # An unreadable DISPLAY QMGR yields None for every attribute below it: absent, not
            # blank. Every rule that reads one gates on qmgr_readable first.
            "qmgr_readable": bool(qmgr_readable),
            "connauth": connauth if qmgr_readable else None,
            "chlauth_records": chlauth if qmgr_readable else None,   # ENABLED|DISABLED|""|None
            "sslkeyr": sslkeyr if qmgr_readable else None,
            "authinfo_name": connauth if qmgr_readable else None,
            "authinfo_readable": bool(authinfo_readable),
            "authinfo_authtype": _norm(_attr(ai, "authenticationMethod", "authenticationInformationType",
                                              "authtype", "type")) or None,
            "chckclnt": _norm(_attr(ai, "checkClient", "clientChecking", "chckclnt")) or None,
            "chcklocl": _norm(_attr(ai, "checkLocal", "localChecking", "chcklocl")) or None,
            "adoptctx": _norm(_attr(ai, "adoptContext", "adoptctx")) or None,
            # Sibling collections. channels_readable=False (denied) is a different fact from
            # channels_readable=True with channel_count=0 (this qmgr genuinely has no channels).
            "channels_readable": channels_readable,
            "channel_count": channel_count,
            "queues_readable": queues_readable,
            "authrecs_readable": authrecs_readable,
            "errors": errors or {},
        },
    )


def parse_channel(qmgr_name: str, chan_params: dict) -> Resource:
    """A channel. SVRCONN is the inbound client-connection channel — the surface that MCAUSER,
    SSLCIPH and CHLAUTH actually gate. Other channel types are collected for inventory."""
    name = str(_attr(chan_params, "channelName", "channel", "name", default="") or "").strip()
    chltype = _norm(_attr(chan_params, "channelType", "chltype", "type"))
    sslciph = str(_attr(chan_params, "sslCipherSpecification", "sslCipherSpec", "sslciph",
                        default="") or "").strip()
    mcauser = str(_attr(chan_params, "messageChannelAgentUserIdentifier", "mcaUser",
                        "mcauser", default="") or "").strip()
    sslcauth = _norm(_attr(chan_params, "sslClientAuthentication", "sslcauth"))
    return Resource(
        kind="ibmmq_channel",
        name=name,
        ext_id=f"ibmmq-chl-{qmgr_name}-{name}",
        namespace=qmgr_name,
        labels={"type": chltype or "?", "tls": "true" if sslciph else "false"},
        raw={
            "qmgr_name": qmgr_name,
            "channel_name": name,
            "channel_type": chltype,             # SVRCONN | CLNTCONN | SDR | RCVR | ...
            "sslciph": sslciph,                  # "" == no TLS on this channel
            "mcauser": mcauser,                  # "" == flowed/asserted identity is used
            "sslcauth": sslcauth or None,
            "qmgr_ext_id": f"ibmmq-qmgr-{qmgr_name}",
        },
    )


def parse_queue(qmgr_name: str, q_params: dict, authrecs: list | None = None) -> Resource:
    """A local queue plus any authority records (DISPLAY AUTHREC) whose profile is this queue.
    Authority records are the NHI grant material and the evidence for the wide-authority rule."""
    name = str(_attr(q_params, "queueName", "queue", "name", default="") or "").strip()
    qtype = _norm(_attr(q_params, "queueType", "type")) or "LOCAL"
    return Resource(
        kind="ibmmq_queue",
        name=name,
        ext_id=f"ibmmq-queue-{qmgr_name}-{name}",
        namespace=qmgr_name,
        labels={"type": qtype},
        raw={
            "qmgr_name": qmgr_name,
            "queue_name": name,
            "queue_type": qtype,
            "put_enabled": _norm(_attr(q_params, "putEnabled", "put")) not in ("DISABLED", "NO"),
            "get_enabled": _norm(_attr(q_params, "getEnabled", "get")) not in ("DISABLED", "NO"),
            "max_depth": _attr(q_params, "maxQueueDepth", "maxdepth"),
            "authority_records": list(authrecs or []),
            "qmgr_ext_id": f"ibmmq-qmgr-{qmgr_name}",
        },
    )


def parse_authrec(rec_params: dict) -> dict:
    """One DISPLAY AUTHREC row → a small normalized dict. Kept as plain data (not a Resource):
    it is consumed by the queue rule and the NHI extractor, keyed to its profile object."""
    entity = str(_attr(rec_params, "entityName", "principal", "group", "profile_entity",
                       default="") or "").strip()
    etype = _norm(_attr(rec_params, "entityType", "authadd_entitytype")) or None
    # authorities may arrive as a list or a space/comma-joined string
    auth = _attr(rec_params, "authorityAdd", "authority", "authadd", default=[])
    if isinstance(auth, str):
        authorities = [a.strip().lower() for a in auth.replace(",", " ").split() if a.strip()]
    elif isinstance(auth, list):
        authorities = [str(a).strip().lower() for a in auth if str(a).strip()]
    else:
        authorities = []
    return {
        "profile": str(_attr(rec_params, "profileName", "profile", default="") or "").strip(),
        "object_type": _norm(_attr(rec_params, "objectType", "objtype")) or None,
        "entity": entity,
        "entity_type": etype,                # PRINCIPAL | GROUP
        "authorities": authorities,
    }


@connector("ibmmq", fields=[
    ConnectorField("base_url", "mqweb URL", required=True,
                   placeholder="https://mq.example:9443",
                   help="Base URL of the IBM MQ mqweb server. Read-only: only MQSC DISPLAY "
                        "commands are issued."),
    ConnectorField("username", "Admin user", required=True,
                   help="An mqweb user in the MQWebAdmin/MQWebAdminRO role. DISPLAY-only here."),
    ConnectorField("password", "Password", required=True, secret=True),
    ConnectorField("qmgr", "Queue manager", required=True, placeholder="QM1"),
    ConnectorField("tls", "Use TLS", placeholder="true",
                   help="'true' if the mqweb URL is https (recommended)."),
])
def collect(config: dict) -> Collected:
    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        raise SystemExit("ibmmq connector requires config['base_url'] "
                         "(e.g. https://mq.example:9443)")
    qmgr = (config.get("qmgr") or "").strip()
    if not qmgr:
        raise SystemExit("ibmmq connector requires config['qmgr'] (the queue manager name)")
    auth = (config.get("username") or "", config.get("password") or "")
    verify = config.get("verify_tls", True)
    timeout = float(config.get("timeout") or 15)
    scheme = urlparse(base).scheme or "https"
    tls = scheme == "https"

    errors: dict = {}
    with httpx.Client(base_url=base, timeout=timeout, verify=bool(verify),
                      follow_redirects=False, auth=auth) as client:
        qmgr_res = _run_mqsc(client, qmgr, "display", "qmgr")
        # "ok but no response rows" is not a read either: DISPLAY QMGR always answers with one
        # row, so an empty set means nothing came back and every attribute below is unknown.
        qmgr_ok = bool(qmgr_res.get("ok") and qmgr_res.get("responses"))
        qmgr_params = qmgr_res["responses"][0] if qmgr_ok else {}
        if not qmgr_ok:
            errors["qmgr"] = qmgr_res.get("error") or "empty"

        # Resolve CONNAUTH → the AUTHINFO object that actually holds CHCKCLNT.
        connauth = str(_attr(qmgr_params, "connectionAuthentication", "connauth", default="") or "").strip()
        authinfo, authinfo_readable = None, False
        if connauth:
            ai_res = _run_mqsc(client, qmgr, "display", "authinfo", name=connauth)
            if ai_res.get("ok") and ai_res.get("responses"):
                authinfo, authinfo_readable = ai_res["responses"][0], True
            else:
                errors["authinfo"] = ai_res.get("error") or "empty"

        chan_res = _run_mqsc(client, qmgr, "display", "channel", name="*")
        if not chan_res.get("ok"):
            errors["channel"] = chan_res.get("error")
        queue_res = _run_mqsc(client, qmgr, "display", "queue", name="*",
                              parameters={"queueType": "local"})
        if not queue_res.get("ok"):
            errors["queue"] = queue_res.get("error")
        authrec_res = _run_mqsc(client, qmgr, "display", "authrec")   # optional; may be denied
        if not authrec_res.get("ok"):
            # Recorded, not swallowed: with no authority records the queue rule has nothing to
            # read, and "no wide grant found" would otherwise be indistinguishable from "denied".
            errors["authrec"] = authrec_res.get("error")

    resources: list = []
    edges: list = []

    # Channels are parsed before the queue manager so its resource can carry an honest count.
    channels = [c for c in (parse_channel(qmgr, cp) for cp in (chan_res.get("responses") or []))
                if c.name]
    channels_readable = bool(chan_res.get("ok"))

    qmgr_resource = parse_qmgr(qmgr, base, qmgr_params, authinfo, authinfo_readable,
                               tls=tls, errors=errors, qmgr_readable=qmgr_ok,
                               channels_readable=channels_readable,
                               channel_count=len(channels) if channels_readable else None,
                               queues_readable=bool(queue_res.get("ok")),
                               authrecs_readable=bool(authrec_res.get("ok")))
    resources.append(qmgr_resource)

    for chan in channels:
        resources.append(chan)
        edges.append(Edge(src_ext_id=qmgr_resource.ext_id, dst_ext_id=chan.ext_id, kind="hosts"))

    authrecs = [parse_authrec(a) for a in (authrec_res.get("responses") or [])]
    for qp in (queue_res.get("responses") or []):
        qname = str(_attr(qp, "queueName", "queue", "name", default="") or "").strip()
        matching = [a for a in authrecs if a.get("profile") == qname
                    and (a.get("object_type") in (None, "QUEUE"))]
        q = parse_queue(qmgr, qp, matching)
        if not q.name:
            continue
        resources.append(q)
        edges.append(Edge(src_ext_id=qmgr_resource.ext_id, dst_ext_id=q.ext_id, kind="hosts"))

    return Collected(resources=resources, edges=edges)


# ── NHI: channels' effective users + authority-record principals ───────────────
@identity_extractor("ibmmq")
def _from_ibmmq(resources: list) -> tuple:
    """MQ non-human identities come from two places: the MCAUSER an inbound SVRCONN channel runs
    every remote client as (a service account, or `«flowed»` when blank — the client asserts its
    own id), and the principals/groups named in authority records. Grants are the per-object
    authorities from AUTHREC, plus one 'svrconn-access' grant per channel to its MCAUSER identity
    (wildcard when the id is blank or privileged). MQ exposes no stored passwords over REST, so no
    credential resources are emitted — absence, not silence."""
    out: list[Resource] = []
    edges: list[Edge] = []
    seen: dict[str, Resource] = {}

    def _ident(name: str, itype: str, source_ext: str, **extra) -> Resource:
        idr = seen.get(name)
        if idr is None:
            idr = _mk_identity("ibmmq", itype, name, source_ext=source_ext, extra=extra or None)
            seen[name] = idr
            out.append(idr)
        return idr

    for r in resources:
        if r.kind == "ibmmq_channel":
            raw = r.raw or {}
            if raw.get("channel_type") != "SVRCONN":
                continue
            mcauser = (raw.get("mcauser") or "").strip()
            flowed = mcauser == ""
            privileged = mcauser.lower() in PRIVILEGED_MCAUSER
            principal = mcauser or "«flowed»"
            idr = _ident(principal, "admin" if privileged else "service_account", r.ext_id,
                         flowed=flowed, privileged=privileged)
            g = _mk_grant("ibmmq", idr.ext_id, "svrconn-access",
                          f"channel:{raw.get('channel_name')}",
                          wildcard=(flowed or privileged),
                          extra={"channel": raw.get("channel_name"), "tls": bool(raw.get("sslciph"))})
            out.append(g)
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
            edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id, kind="grants_access"))

        elif r.kind == "ibmmq_queue":
            raw = r.raw or {}
            for rec in raw.get("authority_records") or []:
                entity = (rec.get("entity") or "").strip()
                if not entity:
                    continue
                itype = "group" if rec.get("entity_type") == "GROUP" else "service_account"
                idr = _ident(entity, itype, r.ext_id, entity_type=rec.get("entity_type"))
                authorities = rec.get("authorities") or []
                wildcard = any(a in ("all", "alladm", "allmqi") for a in authorities)
                g = _mk_grant("ibmmq", idr.ext_id, "+".join(authorities) or "none",
                              f"queue:{raw.get('queue_name')}", wildcard=wildcard,
                              extra={"authorities": authorities, "queue": raw.get("queue_name")})
                out.append(g)
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=idr.ext_id, kind="granted_to"))
                edges.append(Edge(src_ext_id=g.ext_id, dst_ext_id=r.ext_id, kind="grants_access"))

    return out, edges
