# VectaSec AWS read-only role

`vectasec-readonly-role.yaml` is a CloudFormation template that creates the cross-account
role the VectaSec AWS connector assumes. It is the agentless path: nothing is installed in
your account, and the role can only **read**. Every action in the inline policy is a
`List*` / `Get*` / `Describe*` call (API Gateway's control plane is a single `GET` action
scoped to the REST/HTTP API paths). There is no `Put*`, `Create*`, `Delete*`, `Update*` or
`PassRole` anywhere in it.

## Deploy

```sh
aws cloudformation deploy \
  --stack-name vectasec-readonly \
  --template-file deploy/aws/vectasec-readonly-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides VectaSecAccountId=<vectasec account id> ExternalId=<external id shown in the console>
```

Then paste the stack's `RoleArn` output into the connection's **Role ARN** field and the same
ExternalId into **External ID**. The trust policy only admits the VectaSec account *and* only
with that ExternalId (confused-deputy protection); `MaxSessionDuration` is one hour.

If you prefer a managed policy, `SecurityAudit` covers everything below except
`cloudtrail:LookupEvents` and `sqs:ListQueueTags` — attach those two separately or accept
that CloudTrail last-event and SQS owner tags are reported as a coverage gap.

## What each action is for

| Action | Why the scanner needs it |
|---|---|
| `sts:GetCallerIdentity` | Proves the credential works and records the account id before fan-out. |
| `sqs:ListQueues`, `sqs:GetQueueAttributes` | Queue inventory; resource policy, encryption, DLQ settings. |
| `sqs:ListQueueTags` | Owner attribution (owner/team/service/contact/email/vectasec:owner/created-by tag). |
| `sns:ListTopics`, `sns:GetTopicAttributes`, `sns:ListSubscriptionsByTopic` | Topic inventory, policy, encryption, delivery endpoints (plaintext HTTP subscriptions). |
| `sns:ListTagsForResource` | Owner attribution for topics. |
| `events:ListEventBuses`, `events:DescribeEventBus`, `events:ListRules`, `events:ListTargetsByRule` | Bus policies, rules and cross-account targets. Target input templates are never stored. |
| `kafka:ListClustersV2`, `kafka:DescribeClusterV2` (+ v1 aliases) | MSK client auth, encryption in transit, public access, monitoring level; cluster tags for owner. |
| `apigateway:GET` on `/restapis*` and `/apis*` | REST + HTTP/WebSocket APIs: routes, authorizers, stages, logging, WAF; API tags for owner. |
| `iam:ListUsers`, `iam:GetUser`, `iam:ListRoles`, `iam:GetRole` | Enumerate the IAM principals your integration layer accepts (bounded to 500, truncation recorded). `GetRole` carries `RoleLastUsed`, which `ListRoles` omits. |
| `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` | Per access key: created date, status, last-used date. Key ids are stored masked (`AKIA…MPLE`); the secret is never readable through any API. A key with no last-used date is a **never-used credential** finding. |
| `iam:ListUserTags`, `iam:ListRoleTags` | Owner attribution for principals. |
| `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails` | IAM Access Advisor: when each principal last authenticated to SQS/SNS/EventBridge/MSK/API Gateway. Polled with a short bounded wait. |
| `cloudtrail:LookupEvents` | Newest management event per principal in the last 90 days (5 events per lookup, at most 50 principals per region, dormant principals first). Fills the gap when Access Advisor is coarse. |

## Honesty guarantees

* A denied action is **recorded, not swallowed**: it surfaces as an
  `AWS.ACCOUNT.SERVICE_NOT_ASSESSED` coverage-gap finding (`iam:global`, `cloudtrail:<region>`
  or the per-principal child gap). A principal whose last-used could not be read is reported
  as *not assessed*, never as "never used".
* No secret material is read or stored: access-key secrets, role credentials, message bodies
  and EventBridge input templates are out of reach of this policy by construction.
* Service-linked roles (`/aws-service-role/`) are skipped: AWS manages them and you cannot
  decommission them.
