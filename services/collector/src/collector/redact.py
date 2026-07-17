"""The last thing that touches a payload before it leaves the customer's network.

INVARIANT: a credential this collector holds for a customer system never leaves the customer's
network. Not in a finding, not in an observation, not in a resource label, not in an error
string, not in a log line. The control plane cannot leak what it was never sent, and this
module is where that claim is enforced.

redact() is the backstop, not the mechanism. The mechanism is structural: main.py builds
payloads out of credential-free parts and never serialises Target.config. This exists because
"we were careful" is not an argument that survives a security review, and because whoever adds
the seventh connector two years from now will not have read that file.

Three layers, each catching what the others cannot:
  1. value — every credential we hold, byte for byte, wherever it turns up. Shape-independent.
  2. key   — every credential-shaped key, whatever its value. Catches secrets we do NOT hold,
             i.e. ones a connector read off the target itself.
  3. shape — URL userinfo and PEM blocks, which carry secrets in a value position under an
             innocent key ("url") that layer 2 cannot see.
"""
import re

REDACTED = "[redacted]"

# Deliberately precise rather than greedy. A bare `key` alternative would match `config_key`,
# and `source_ref` is `{"config_key": "authorizer.class.name"}` — the provenance of the evidence
# ledger. Over-redaction that destroys why a finding exists is a real failure, not a safe default.
_CRED_KEY_RE = re.compile(
    r"(?:^|[._\-])"
    r"(?:password|passwd|passphrase|secret|secrets|token|tokens|credential|credentials"
    r"|apikey|api_key|private_key|privatekey|keyfile|keystore|truststore|keytab"
    r"|authorization|auth_token|bearer|client_secret|access_key|secret_key|signature"
    r"|cookie|session_id|sessionid)"
    r"(?:$|[._\-])",
    re.I,
)

# Below this length a credential cannot be value-scrubbed without destroying evidence: RabbitMQ's
# default login is `guest`/`guest`, and blanking every occurrence of "guest" would gut the
# observation of the very rule that exists to report it ("user `guest` has tag administrator").
# Short credentials stay covered by the key and shape layers — and a credential this guessable is
# already a finding rather than a secret worth protecting.
_MIN_SCRUBBABLE = 8

_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----", re.S)

# scheme://user:pw@host — the most common way a secret reaches us under a key named "url".
_USERINFO_RE = re.compile(r"\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+(?::[^/\s@]*)?@", re.I)


def is_cred_key(key) -> bool:
    return bool(_CRED_KEY_RE.search(str(key)))


def _scrubbable(secrets) -> list:
    """Known secrets worth a value scrub, longest first.

    Longest first because a short secret that is a substring of a longer one would otherwise
    chop the longer one into a fragment that no longer matches.
    """
    return sorted({s for s in secrets if isinstance(s, str) and len(s) >= _MIN_SCRUBBABLE},
                  key=len, reverse=True)


def _scrub_str(s: str, secrets: list) -> str:
    for sec in secrets:
        if sec in s:
            s = s.replace(sec, REDACTED)
    s = _PEM_RE.sub(REDACTED, s)
    return _USERINFO_RE.sub(r"\1" + REDACTED + "@", s)


def _walk(node, secrets: list):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if is_cred_key(k):
                # Presence is posture; only the value is the secret. "ssl.keystore.password is
                # configured" is a fact a rule may legitimately need to state, so the key
                # survives. Falsey values stay themselves — replacing None with a marker would
                # turn "not set" into "set to something", inverting the finding.
                out[k] = v if (v is None or v is False or v == "") else REDACTED
                continue
            out[k] = _walk(v, secrets)
        return out
    if isinstance(node, (list, tuple)):
        return [_walk(v, secrets) for v in node]
    if isinstance(node, str):
        return _scrub_str(node, secrets)
    return node


def redact(node, secrets):
    """Strip credentials from anything about to go outbound. Pure — returns a copy.

    `secrets` is the set of literal credential strings this process holds (Config.secret_values).
    Passing them in rather than importing config keeps this module dependency-free, so it can be
    read and unit-tested on its own — which is the point of a file whose whole job is to be
    audited.
    """
    return _walk(node, _scrubbable(secrets))
