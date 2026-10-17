"""AWS last-used + owner telemetry: the IAM / Access Advisor / CloudTrail step of the AWS
connector, its pure parse layer, the credential resources the NHI extractor derives from it,
and the CREDENTIAL.LIFECYCLE.* verdicts those credentials now make ASSESSED.

Offline, golden-fixture style like test_connect_aws.py: boto3 never appears. The collectors
take a session, so a stub session whose stub clients dispatch on call arguments drives the
real code paths — including the denied branches, which must land as child gaps and ABSENT raw
keys (not-assessed), never as "never used".
"""
import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

import vectasec.detect  # noqa: F401  — registers every rulepack, incl. CREDENTIAL.LIFECYCLE.*
import vectasec.detect.aws  # noqa: F401
from vectasec.contracts import Collected, Resource, ScanContext
from vectasec.identity import derive_identities
from vectasec.registry import CONNECTOR_FIELDS, DETECTORS
from vectasec.connect.aws import (
    _collect_cloudtrail, _collect_iam, _collect_sns, last_used_summary, mask_key_id,
    owner_from_tags, parse_access_key, parse_cloudtrail_events, parse_iam_role,
    parse_iam_user, parse_last_accessed, parse_queue,
)

FIX = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "aws_responses.json").read_text()
)
IAM, CT = FIX["iam"], FIX["cloudtrail"]
REGION = "us-east-1"
RULES = {d.rule_id: d for d in DETECTORS}

USED_KEY, NEVER_KEY, OLD_KEY = "AKIAIOSFODNN7EXAMPLE", "AKIAI44QH8DHBNEVRUSED", "AKIAJLEGACYBATCH0OLD"


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ctx(resources) -> ScanContext:
    return ScanContext(connection_id="c", tenant_id="t", resources=list(resources))


def account_resource(collection=None) -> Resource:
    ident = FIX["caller_identity"]
    return Resource(
        kind="aws_account", name=ident["Account"], ext_id=f"aws-account-{ident['Account']}",
        labels={"service": "sts", "auth_method": "assume_role"},
        raw={"account_id": ident["Account"], "caller_arn": ident["Arn"],
             "auth_method": "assume_role", "regions": [REGION],
             "collection": collection or {}},
    )


def user(name: str) -> dict:
    return next(u for u in IAM["list_users"]["Users"] if u["UserName"] == name)


def keys_for(name: str, *, deny_last_used=()) -> list:
    """parse_access_key over the fixture: a key id in `deny_last_used` gets last_used=None
    (the GetAccessKeyLastUsed-denied shape)."""
    out = []
    for m in IAM["list_access_keys"][name]["AccessKeyMetadata"]:
        kid = m["AccessKeyId"]
        lu = None if kid in deny_last_used else IAM["get_access_key_last_used"][kid]
        out.append(parse_access_key(m, lu))
    return out


def advisor(**overrides) -> dict:
    return parse_last_accessed({**IAM["get_service_last_accessed_details"], **overrides})


def no_auth_advisor() -> dict:
    """Access Advisor response where no service was ever authenticated."""
    svcs = [{k: v for k, v in s.items() if k != "LastAuthenticated"}
            for s in IAM["get_service_last_accessed_details"]["ServicesLastAccessed"]]
    return advisor(ServicesLastAccessed=svcs)


# ── stub session: clients dispatch on the arguments the collector passes ──────
class _Denied(Exception):
    response = {"Error": {"Code": "AccessDeniedException"}}


class _FakeIam:
    """Fixture-backed IAM client. `deny` is a set of (api, arg) pairs that raise AccessDenied;
    `advisor_statuses` is a per-call queue of JobStatus values to return before COMPLETED."""

    def __init__(self, *, deny=(), advisor_statuses=(), advisor_by_arn=None):
        self.deny = set(deny)
        self.advisor_statuses = list(advisor_statuses)
        self.advisor_by_arn = advisor_by_arn or {}
        self.calls = []
        self._current_arn = None

    def _check(self, api, arg=None):
        self.calls.append((api, arg))
        if (api, arg) in self.deny or (api, None) in self.deny:
            raise _Denied()

    def list_users(self, **_kw):
        self._check("list_users")
        return IAM["list_users"]

    def list_roles(self, **_kw):
        self._check("list_roles")
        return IAM["list_roles"]

    def get_user(self, UserName):
        self._check("get_user", UserName)
        return {"User": user(UserName)}

    def get_role(self, RoleName):
        self._check("get_role", RoleName)
        return IAM["get_role"][RoleName]

    def list_access_keys(self, UserName, **_kw):
        self._check("list_access_keys", UserName)
        return IAM["list_access_keys"][UserName]

    def get_access_key_last_used(self, AccessKeyId):
        self._check("get_access_key_last_used", AccessKeyId)
        return IAM["get_access_key_last_used"][AccessKeyId]

    def list_user_tags(self, UserName):
        self._check("list_user_tags", UserName)
        return IAM["list_user_tags"][UserName]

    def list_role_tags(self, RoleName):
        self._check("list_role_tags", RoleName)
        return IAM["list_role_tags"][RoleName]

    def generate_service_last_accessed_details(self, Arn):
        self._check("generate_service_last_accessed_details", Arn)
        self._current_arn = Arn
        return IAM["generate_service_last_accessed_details"]

    def get_service_last_accessed_details(self, JobId, **_kw):
        self._check("get_service_last_accessed_details", JobId)
        if self.advisor_statuses:
            status = self.advisor_statuses.pop(0)
            return {"JobStatus": status, "ServicesLastAccessed": []}
        return self.advisor_by_arn.get(self._current_arn, IAM["get_service_last_accessed_details"])


class _FakeCloudTrail:
    def __init__(self, *, deny=False, by_user=None):
        self.deny, self.by_user, self.calls = deny, by_user or {}, []

    def lookup_events(self, LookupAttributes, StartTime, EndTime, MaxResults):
        self.calls.append((LookupAttributes[0]["AttributeValue"], MaxResults))
        if self.deny:
            raise _Denied()
        assert LookupAttributes[0]["AttributeKey"] == "Username"
        assert MaxResults <= 5 and (EndTime - StartTime).days == 90
        return self.by_user.get(LookupAttributes[0]["AttributeValue"], CT["lookup_events_empty"])


class _Session:
    def __init__(self, **clients):
        self._clients = clients

    def client(self, service, **_kw):
        return self._clients[service]


def _noop_sleep(_s):
    pass


def never_used_advisor_map():
    return {"arn:aws:iam::111111111111:role/unused-partner-role": {
        **IAM["get_service_last_accessed_details"],
        "ServicesLastAccessed": [{k: v for k, v in s.items() if k != "LastAuthenticated"}
                                 for s in IAM["get_service_last_accessed_details"]["ServicesLastAccessed"]]}}


def collect_iam(iam=None, **kw):
    iam = iam or _FakeIam(advisor_by_arn=never_used_advisor_map())
    session = _Session(iam=iam)
    return _collect_iam(session, REGION, "111111111111", sleeper=_noop_sleep, **kw)


def derived(resources=None):
    """Account + IAM resources (fixture, nothing denied) → derived NHI model."""
    if resources is None:
        resources, _e, _g, _m = collect_iam()
    return derive_identities("aws", Collected(resources=[account_resource()] + list(resources)))


def fire(rule_id: str, resource: Resource, ctx=None) -> list:
    d = RULES[rule_id]
    assert resource.kind in d.kinds
    return d.fn(resource, ctx or _ctx([resource])) or []


# ── pure parse layer ──────────────────────────────────────────────────────────
def test_mask_key_id_keeps_only_ends():
    assert mask_key_id(USED_KEY) == "AKIA…MPLE"
    assert USED_KEY not in mask_key_id(USED_KEY)


def test_parse_access_key_used_never_and_denied_are_three_distinct_shapes():
    used, never = keys_for("ci-deployer")
    assert used["key_id_masked"] == "AKIA…MPLE" and used["status"] == "Active"
    assert used["created_at"] == "2025-09-01T10:05:00Z"
    assert used["last_used_at"] == "2026-10-07T09:12:00Z" and used["last_used_service"] == "sqs"
    # readable but no LastUsedDate: the key EXISTS and has never authenticated
    assert never["last_used_readable"] is True and never["last_used_at"] is None
    assert never["last_used_service"] is None
    # denied: the key is simply absent — not None, which would read as "never used"
    (denied,) = keys_for("legacy-batch", deny_last_used={OLD_KEY})
    assert denied["last_used_readable"] is False and "last_used_at" not in denied
    # two keys on one user are told apart by a stable non-reversible ref
    assert used["key_ref"] != never["key_ref"] and USED_KEY not in json.dumps(used)


def test_parse_last_accessed_takes_newest_across_all_services_but_lists_tracked_only():
    a = advisor()
    assert a["last_authenticated"] == "2026-10-10T07:00:00Z"   # iam is newest overall…
    assert [s["service"] for s in a["services"]] == ["sqs", "sns"]   # …but not tracked
    by = {s["service"]: s["last_authenticated"] for s in a["services"]}
    assert by["sqs"] == "2026-10-07T09:12:00Z" and by["sns"] is None
    assert no_auth_advisor()["last_authenticated"] is None
    assert parse_last_accessed(None) is None


def test_parse_cloudtrail_events_newest_and_empty():
    assert parse_cloudtrail_events(CT["lookup_events"]) == {
        "last_event_at": "2026-10-11T08:30:00Z", "events": 2}
    assert parse_cloudtrail_events(CT["lookup_events_empty"])["last_event_at"] is None
    assert parse_cloudtrail_events(None) is None


def test_owner_from_tags_preference_and_shapes():
    assert owner_from_tags(IAM["list_user_tags"]["ci-deployer"]["Tags"]) == {
        "label": "platform-team", "source": "tag:Owner"}
    assert owner_from_tags(IAM["list_user_tags"]["legacy-batch"]["Tags"]) is None
    assert owner_from_tags([]) is None and owner_from_tags(None) is None
    # dict shape (SQS / MSK / API Gateway), case-insensitive, 'owner' beats 'team'
    assert owner_from_tags({"TEAM": "x", "owner": "y"}) == {"label": "y", "source": "tag:owner"}
    assert owner_from_tags({"created-by": "terraform"})["source"] == "tag:created-by"
    assert owner_from_tags({"Owner": "  "}) is None     # blank value is no owner


def test_parse_iam_user_summarises_last_used_and_owner():
    r = parse_iam_user(user("ci-deployer"), access_keys=keys_for("ci-deployer"),
                       tags=IAM["list_user_tags"]["ci-deployer"]["Tags"], last_accessed=advisor())
    assert r.kind == "aws_iam_user" and r.ext_id == "arn:aws:iam::111111111111:user/ci-deployer"
    assert r.raw["owner"] == {"label": "platform-team", "source": "tag:Owner"}
    assert r.labels["owner_label"] == "platform-team" and r.labels["identity_type"] == "iam_user"
    assert r.raw["last_used_services"][0] == {"service": "sqs", "last_authenticated": "2026-10-07T09:12:00Z"}
    # newest of access-advisor (10-10 iam) vs key (10-07) → access advisor wins
    assert r.raw["last_used_at"] == "2026-10-10T07:00:00Z"
    assert r.raw["last_used_source"] == "iam_access_advisor"
    assert r.raw["cloudtrail_readable"] is None            # the CloudTrail pass has not run


def test_parse_iam_user_with_nothing_readable_has_no_last_used_key():
    r = parse_iam_user(user("legacy-batch"), access_keys=None, tags=None, last_accessed=None)
    assert "last_used_at" not in r.raw and "last_used_source" not in r.raw
    assert r.raw["access_keys_readable"] is False and r.raw["tags_readable"] is False
    assert "owner" not in r.raw and "owner_label" not in r.labels


def test_parse_iam_role_never_used_vs_unreadable():
    used = parse_iam_role(IAM["get_role"]["eb-cross-account"]["Role"],
                          tags=IAM["list_role_tags"]["eb-cross-account"]["Tags"],
                          last_accessed=None)
    assert used.kind == "aws_iam_role" and used.raw["role_last_used_at"] == "2026-10-01T18:00:00Z"
    assert used.raw["last_used_source"] == "role_last_used"
    assert used.labels["owner_label"] == "integrations"     # 'team' tag
    never = parse_iam_role(IAM["get_role"]["unused-partner-role"]["Role"], tags=[],
                           last_accessed=no_auth_advisor())
    assert never.raw["role_last_used_at"] is None
    assert never.raw["last_used_at"] is None and never.raw["last_used_source"] == "none"
    unreadable = parse_iam_role(IAM["list_roles"]["Roles"][1], tags=[], last_accessed=None,
                                last_used_readable=False)
    assert "role_last_used_at" not in unreadable.raw and "last_used_at" not in unreadable.raw


def test_last_used_summary_ignores_unreadable_signals():
    assert last_used_summary({}) == {}
    assert last_used_summary({"access_keys": [{"last_used_readable": False}]}) == {}
    assert last_used_summary({"cloudtrail_readable": True, "last_event_at": None}) == {
        "last_used_at": None, "last_used_source": "none"}


def test_parse_queue_tags_carry_owner_and_absence_is_distinguishable():
    attrs = {"QueueArn": "arn:aws:sqs:us-east-1:111111111111:orders"}
    url = "https://sqs.us-east-1.amazonaws.com/111111111111/orders"
    tagged = parse_queue(REGION, url, attrs, tags={"Owner": "payments"})
    assert tagged.raw["owner"] == {"label": "payments", "source": "tag:Owner"}
    untagged = parse_queue(REGION, url, attrs, tags={})
    denied = parse_queue(REGION, url, attrs, tags=None)
    assert "owner" not in untagged.raw and "owner" not in denied.raw
    assert untagged.raw["tags_readable"] is True and denied.raw["tags_readable"] is False


# ── collection: isolation + gaps ──────────────────────────────────────────────
def test_collect_iam_happy_path_records_no_gaps_and_skips_service_linked_roles():
    iam = _FakeIam(advisor_by_arn=never_used_advisor_map())
    resources, edges, gaps, meta = collect_iam(iam)
    assert gaps == [] and edges == []
    assert meta == {"truncated": False, "service_linked_skipped": 1}
    kinds = sorted((r.kind, r.name) for r in resources)
    assert kinds == [("aws_iam_role", "eb-cross-account"), ("aws_iam_role", "unused-partner-role"),
                     ("aws_iam_user", "ci-deployer"), ("aws_iam_user", "legacy-batch")]
    # ListRoles omits RoleLastUsed, so GetRole was consulted for each kept role
    assert ("get_role", "eb-cross-account") in iam.calls
    assert ("get_role", "AWSServiceRoleForSupport") not in iam.calls
    # no secret or full key id anywhere in what was collected
    blob = json.dumps([r.raw for r in resources])
    assert USED_KEY not in blob and NEVER_KEY not in blob and OLD_KEY not in blob


def test_collect_iam_denied_access_key_last_used_is_a_child_gap_not_never_used():
    iam = _FakeIam(deny={("get_access_key_last_used", OLD_KEY)},
                   advisor_by_arn=never_used_advisor_map())
    resources, _e, gaps, _m = collect_iam(iam)
    assert gaps == [{"parent": "user legacy-batch", "child": "access_key_last_used",
                     "error": "AccessDeniedException"}]
    legacy = next(r for r in resources if r.name == "legacy-batch")
    (k,) = legacy.raw["access_keys"]
    assert k["last_used_readable"] is False and "last_used_at" not in k
    # the user itself still resolves last-used from Access Advisor — isolation, not voiding
    assert legacy.raw["last_used_source"] == "iam_access_advisor"
    # the other user is untouched
    ci = next(r for r in resources if r.name == "ci-deployer")
    assert all(x["last_used_readable"] for x in ci.raw["access_keys"])


def test_collect_iam_denied_everything_per_principal_leaves_keys_absent():
    iam = _FakeIam(deny={("list_access_keys", None), ("list_user_tags", None),
                         ("list_role_tags", None), ("generate_service_last_accessed_details", None),
                         ("get_role", None)})
    resources, _e, gaps, _m = collect_iam(iam)
    assert {g["child"] for g in gaps} == {"access_keys", "tags", "access_advisor", "get_role"}
    for r in resources:
        assert "last_used_at" not in r.raw, r.name
        assert r.raw["access_advisor_readable"] is False and r.raw["tags_readable"] is False


def test_collect_iam_polls_access_advisor_with_injected_sleeper():
    slept = []
    iam = _FakeIam(advisor_statuses=["IN_PROGRESS", "IN_PROGRESS"])
    session = _Session(iam=iam)
    resources, _e, gaps, _m = _collect_iam(session, REGION, "111111111111",
                                           sleeper=lambda s: slept.append(s))
    assert gaps == [] and len(slept) == 2          # two IN_PROGRESS polls → two sleeps
    assert resources[0].raw["access_advisor_readable"] is True


def test_collect_iam_access_advisor_timeout_is_a_gap_not_a_crash():
    iam = _FakeIam(advisor_statuses=["IN_PROGRESS"] * 10)   # first principal never completes
    resources, _e, gaps, _m = collect_iam(iam)
    assert gaps[0]["parent"] == "user ci-deployer" and gaps[0]["child"] == "access_advisor"
    assert "did not complete" in gaps[0]["error"]
    assert resources[0].raw["access_advisor_readable"] is False
    assert len(resources) == 4                                 # the rest still landed


def test_collect_iam_covers_policy_named_principals_past_the_listing():
    """A user ARN a queue policy names must be enumerated even if ListUsers did not return it
    (truncation): the collector falls back to GetUser."""
    q = parse_queue(REGION, "https://sqs.us-east-1.amazonaws.com/111111111111/x",
                    {"QueueArn": "arn:aws:sqs:us-east-1:111111111111:x",
                     "Policy": json.dumps({"Statement": [{"Effect": "Allow", "Action": "sqs:*",
                                                          "Principal": {"AWS": "arn:aws:iam::111111111111:user/ci-deployer"}}]})})
    iam = _FakeIam(advisor_by_arn=never_used_advisor_map())
    listed = IAM["list_users"]
    iam.list_users = lambda **_kw: {"Users": listed["Users"][1:], "IsTruncated": False}
    resources, _e, _g, _m = collect_iam(iam, policy_resources=[q])
    assert ("get_user", "ci-deployer") in iam.calls
    assert any(r.name == "ci-deployer" for r in resources)


def test_collect_cloudtrail_lands_last_event_and_updates_last_used():
    resources, _e, _g, _m = collect_iam()
    ct = _FakeCloudTrail(by_user={"ci-deployer": CT["lookup_events"]})
    gaps, meta = _collect_cloudtrail(_Session(cloudtrail=ct), REGION, resources)
    assert gaps == [] and meta == {"lookups": 4, "truncated": False}
    ci = next(r for r in resources if r.name == "ci-deployer")
    assert ci.raw["cloudtrail_readable"] is True and ci.raw["last_event_at"] == "2026-10-11T08:30:00Z"
    assert ci.raw["last_used_at"] == "2026-10-11T08:30:00Z" and ci.raw["last_used_source"] == "cloudtrail"
    # a principal with no events keeps its IAM-derived answer; the empty lookup is recorded
    legacy = next(r for r in resources if r.name == "legacy-batch")
    assert legacy.raw["cloudtrail_readable"] is True and legacy.raw["last_event_at"] is None
    assert legacy.raw["last_used_source"] == "iam_access_advisor"
    # dormant principals (no last-used yet) are looked up first
    assert ct.calls[0][0] == "unused-partner-role"


def test_collect_cloudtrail_denied_raises_so_the_region_is_recorded_denied_and_iam_data_stays():
    resources, _e, _g, _m = collect_iam()
    before = {r.name: dict(r.raw) for r in resources}
    with pytest.raises(_Denied):
        _collect_cloudtrail(_Session(cloudtrail=_FakeCloudTrail(deny=True)), REGION, resources)
    # nothing about the IAM pass is voided by the CloudTrail denial
    assert {r.name: dict(r.raw) for r in resources} == before
    assert all("last_used_at" in before[n] for n in ("ci-deployer", "legacy-batch"))


def test_account_rule_renders_iam_gaps_and_denied_cloudtrail_as_coverage_gaps():
    acct = account_resource(collection={
        "sqs:us-east-1": {"outcome": "ok", "error": None, "resources": 2},
        "iam:global": {"outcome": "ok", "error": None, "resources": 4, "truncated": False,
                       "child_gaps": [{"parent": "user legacy-batch",
                                       "child": "access_key_last_used",
                                       "error": "AccessDeniedException"}]},
        "cloudtrail:us-east-1": {"outcome": "access_denied", "error": "AccessDeniedException"},
    })
    hits = fire("AWS.ACCOUNT.SERVICE_NOT_ASSESSED", acct)
    assert len(hits) == 2 and all(h.assessable is False for h in hits)
    text = " ".join(h.observation for h in hits)
    assert "cloudtrail in us-east-1 was denied" in text
    assert "iam in global" in text and "access_key_last_used of user legacy-batch" in text


# ── NHI extraction: identities, credentials, labels ───────────────────────────
def test_extractor_emits_one_credential_per_access_key_and_one_per_role():
    col = derived()
    creds = [r for r in col.resources if r.kind == "credential"]
    by_name = {c.name: c for c in creds}
    assert sorted(c.raw["credential_type"] for c in creds) == [
        "access_key", "access_key", "access_key", "role_session", "role_session"]
    assert len({c.ext_id for c in creds}) == 5                 # two keys on one user: distinct ids
    used, never = by_name["AKIA…MPLE"], by_name["AKIA…USED"]
    assert used.raw["last_used_at"] == "2026-10-07T09:12:00Z" and used.labels["last_used_at"] == used.raw["last_used_at"]
    assert used.labels["last_used_source"] == "access_key" and used.labels["credential_type"] == "access_key"
    assert never.raw["last_used_at"] is None and never.labels["last_used_at"] == "never"
    assert used.raw["created_at"] == "2025-09-01T10:05:00Z" and used.raw["plaintext"] is False
    # role credentials carry RoleLastUsed; the never-used role reads "never"
    role_creds = {c.name: c for c in creds if c.raw["credential_type"] == "role_session"}
    assert role_creds["eb-cross-account:role-session"].labels["last_used_at"] == "2026-10-01T18:00:00Z"
    assert role_creds["unused-partner-role:role-session"].raw["last_used_at"] is None
    assert role_creds["unused-partner-role:role-session"].labels["last_used_at"] == "never"
    # every credential is edged to its identity
    edge = {(e.src_ext_id, e.kind, e.dst_ext_id) for e in col.edges}
    for c in creds:
        assert (c.ext_id, "credential_of", c.raw["owner_ext_id"]) in edge


def test_extractor_identities_carry_owner_and_last_used_in_labels():
    col = derived()
    ids = {r.raw["principal"]: r for r in col.resources if r.kind == "identity"}
    ci = ids["arn:aws:iam::111111111111:user/ci-deployer"]
    assert ci.labels["identity_type"] == "iam_user" and ci.labels["external"] == "false"
    assert ci.labels["owner_label"] == "platform-team"
    assert ci.raw["owner"] == {"label": "platform-team", "source": "tag:Owner"}
    assert ci.labels["last_used_at"] == "2026-10-10T07:00:00Z"
    assert ci.labels["last_used_source"] == "iam_access_advisor"
    assert ci.raw["source_ext_id"] == "aws-account-111111111111"   # listed even without a policy
    legacy = ids["arn:aws:iam::111111111111:user/legacy-batch"]
    assert "owner_label" not in legacy.labels and "owner" not in legacy.raw
    # the owner label also rides on the user's credentials
    creds = [c for c in col.resources if c.kind == "credential" and c.raw["owner_ext_id"] == ci.ext_id]
    assert creds and all(c.labels["owner_label"] == "platform-team" for c in creds)
    role = ids["arn:aws:iam::111111111111:role/eb-cross-account"]
    assert role.labels["identity_type"] == "iam_role" and role.labels["owner_label"] == "integrations"


def test_policy_principal_merges_into_the_iam_identity():
    """A role named in a bus policy AND enumerated by IAM is ONE identity: the IAM-typed one,
    which also holds the policy-derived grant."""
    resources, _e, _g, _m = collect_iam()
    bus = Resource(kind="aws_event_bus", name="partner",
                   ext_id="arn:aws:events:us-east-1:111111111111:event-bus/partner",
                   raw={"policy": {"Statement": [{"Effect": "Allow", "Action": "events:PutEvents",
                                                  "Principal": {"AWS": "arn:aws:iam::111111111111:role/eb-cross-account"}}]}})
    col = derived(resources + [bus])
    matches = [r for r in col.resources if r.kind == "identity"
               and r.raw["principal"] == "arn:aws:iam::111111111111:role/eb-cross-account"]
    assert len(matches) == 1 and matches[0].labels["identity_type"] == "iam_role"
    grants = [g for g in col.resources if g.kind == "grant" and g.raw["identity_ext_id"] == matches[0].ext_id]
    assert len(grants) == 1 and grants[0].raw["action"] == "events:putevents"


def test_denied_signals_leave_identity_and_credential_labels_without_last_used():
    iam = _FakeIam(deny={("get_access_key_last_used", None),
                         ("generate_service_last_accessed_details", None), ("get_role", None)})
    resources, _e, _g, _m = collect_iam(iam)
    col = derived(resources)
    for r in col.resources:
        if r.kind in ("identity", "credential"):
            assert "last_used_at" not in r.labels and "last_used_at" not in r.raw, r.name


# ── end to end: CREDENTIAL.LIFECYCLE.* now assess AWS credentials ─────────────
def _lifecycle(col, name: str, rule: str) -> list:
    c = next(r for r in col.resources if r.kind == "credential" and r.name == name)
    return fire(rule, c, _ctx(col.resources))


def test_never_used_fires_assessed_for_the_never_used_key_and_role():
    col = derived()
    h = _lifecycle(col, "AKIA…USED", "CREDENTIAL.LIFECYCLE.NEVER_USED")
    assert len(h) == 1 and h[0].assessable is True and "never authenticated" in h[0].observation
    h = _lifecycle(col, "unused-partner-role:role-session", "CREDENTIAL.LIFECYCLE.NEVER_USED")
    assert len(h) == 1 and h[0].assessable is True


def test_never_used_silent_for_a_key_used_ten_days_ago():
    fresh = {**IAM["get_access_key_last_used"][USED_KEY],
             "AccessKeyLastUsed": {"LastUsedDate": _iso(10), "ServiceName": "sqs", "Region": REGION}}
    iam = _FakeIam(advisor_by_arn=never_used_advisor_map())
    iam.get_access_key_last_used = lambda AccessKeyId: (
        fresh if AccessKeyId == USED_KEY else IAM["get_access_key_last_used"][AccessKeyId])
    resources, _e, _g, _m = collect_iam(iam)
    col = derived(resources)
    assert _lifecycle(col, "AKIA…MPLE", "CREDENTIAL.LIFECYCLE.NEVER_USED") == []


def test_never_used_fires_dormant_for_the_key_last_used_in_2024():
    col = derived()
    h = _lifecycle(col, "AKIA…0OLD", "CREDENTIAL.LIFECYCLE.NEVER_USED")
    assert len(h) == 1 and h[0].assessable is True and "idle threshold" in h[0].observation


def test_rotation_stale_fires_assessed_for_a_key_created_over_a_year_ago():
    col = derived()
    h = _lifecycle(col, "AKIA…0OLD", "CREDENTIAL.LIFECYCLE.ROTATION_STALE")
    assert len(h) == 1 and h[0].assessable is True and "rotation threshold" in h[0].observation
    # a key created 100 days ago (rot-proof: relative to now) is silent
    c = next(r for r in col.resources if r.kind == "credential" and r.name == "AKIA…MPLE")
    c.raw["created_at"] = _iso(100)
    assert fire("CREDENTIAL.LIFECYCLE.ROTATION_STALE", c, _ctx(col.resources)) == []


def test_static_no_rotation_still_matches_access_key_type():
    col = derived()
    h = _lifecycle(col, "AKIA…MPLE", "CREDENTIAL.LIFECYCLE.STATIC_NO_ROTATION")
    assert len(h) == 1 and "access_key" in h[0].observation
    # role sessions are not static bearer secrets
    assert _lifecycle(col, "eb-cross-account:role-session", "CREDENTIAL.LIFECYCLE.STATIC_NO_ROTATION") == []


def test_denied_principal_is_not_assessable_never_a_verdict():
    iam = _FakeIam(deny={("get_access_key_last_used", OLD_KEY), ("list_access_keys", "ci-deployer")})
    resources, _e, _g, _m = collect_iam(iam)
    col = derived(resources)
    # ci-deployer's keys were never listed: no credential at all, nothing to assess
    ci = next(r for r in col.resources if r.kind == "identity" and r.name.endswith("user/ci-deployer"))
    assert [c for c in col.resources if c.kind == "credential" and c.raw["owner_ext_id"] == ci.ext_id] == []
    # legacy-batch's key exists but its last-used was denied → NEVER_USED not_assessable
    h = _lifecycle(col, "AKIA…0OLD", "CREDENTIAL.LIFECYCLE.NEVER_USED")
    assert len(h) == 1 and h[0].assessable is False
    # a credential whose GetRole (CreateDate) was unreadable has no created_at → ROTATION_STALE not_assessable
    iam = _FakeIam(deny={("get_role", None)})
    resources, _e, _g, _m = collect_iam(iam)
    col = derived(resources)
    c = next(r for r in col.resources if r.name == "unused-partner-role:role-session")
    # ListRoles still carries CreateDate, so rotation age is known; last-used is not
    assert fire("CREDENTIAL.LIFECYCLE.NEVER_USED", c, _ctx(col.resources))[0].assessable is False


# ── form field + SNS tag denial isolation ─────────────────────────────────────
def test_regions_help_names_the_extra_actions_and_owner_tags():
    help_ = {f.key: f for f in CONNECTOR_FIELDS["aws"]}["regions"].help
    for needle in ("iam:ListUsers", "GetServiceLastAccessedDetails", "cloudtrail:LookupEvents",
                   "sqs:ListQueueTags", "sns:ListTagsForResource", "owner"):
        assert needle in help_, needle


def test_collect_sns_denied_tags_do_not_void_the_topic():
    arn = FIX["sns"]["attributes"]["alerts"]["TopicArn"]

    class _Paginator:
        def __init__(self, page):
            self.page = page

        def paginate(self, **_kw):
            yield self.page

    class _Sns:
        def get_paginator(self, name):
            return _Paginator({"Topics": [{"TopicArn": arn}]} if name == "list_topics"
                              else {"Subscriptions": []})

        def get_topic_attributes(self, **_kw):
            return {"Attributes": {"TopicArn": arn}}

        def list_tags_for_resource(self, **_kw):
            raise _Denied()

    resources, _e, gaps = _collect_sns(_Session(sns=_Sns()), REGION)
    t = next(r for r in resources if r.kind == "aws_sns_topic")
    assert t.raw["tags_readable"] is False and "owner" not in t.raw and gaps == []


def test_rotation_stale_is_silent_for_role_sessions():
    """A role session is minted per AssumeRole and expires in hours; the role's CreateDate is the
    identity's age, not a secret's. ROTATION_STALE must not file on it — a 2019 role is not an
    unrotated credential — while NEVER_USED still reasons about the role's last use."""
    col = derived(collect_iam(_FakeIam())[0])
    for c in col.resources:
        if c.kind == "credential" and c.raw["credential_type"] == "role_session":
            assert fire("CREDENTIAL.LIFECYCLE.ROTATION_STALE", c, _ctx(col.resources)) == []
