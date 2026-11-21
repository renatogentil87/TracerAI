# Cross-account discovery setup

TracerAI can read network config in other accounts (VPC route tables, security
groups, NACLs) by assuming a read-only role in each one. This folder has the
CloudFormation template that creates that role.

## How it works

- TracerAI runs in one account (the "trusted account") with its own credentials.
- Each account you want to discover has a `TracerAI-ReadOnly` role that trusts
  the trusted account to assume it.
- The role is read only. It cannot change anything.
- When you ask about a VPC in another account, TracerAI assumes that account's
  role, reads the config, and answers.

Nothing deploys automatically when you clone the repo. You install TracerAI on
your laptop, then an administrator deploys the role into the target accounts
with the template here.

## What you need

- `cross-account-role.yaml` creates the role in a target account.
- The role needs three inputs:
  - `TrustedAccountId`  the account TracerAI runs in
  - `TracerAIRoleName`  the role TracerAI runs as in that account
  - `ExternalId`        a shared secret the caller must present

## Deploy to one account (quick test)

From the target account, with permission to create IAM roles:

```bash
aws cloudformation deploy \
  --template-file deploy/cross-account-role.yaml \
  --stack-name tracerai-readonly \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      TrustedAccountId=<the account TracerAI runs in> \
      TracerAIRoleName=<the role TracerAI runs as> \
      ExternalId=<a secret string>
```

## Deploy across an Organization (the real rollout)

Use a CloudFormation StackSet so the role lands in every account, including new
ones. StackSets that target an Organization are created from the management
account or a delegated administrator, because only those can create IAM roles in
member accounts.

1. Enable trusted access for CloudFormation StackSets in the Organization.
2. Create a service-managed StackSet from `cross-account-role.yaml`.
3. Target the Organization or specific OUs, and turn on automatic deployment so
   new accounts get the role.

## Run TracerAI with cross-account discovery

On the machine running TracerAI, in the trusted account's credentials:

```bash
export TRACERAI_ROLE_NAME=TracerAI-ReadOnly       # must match RoleName in the template
export TRACERAI_EXTERNAL_ID=<the same secret>     # must match ExternalId in the template
export AWS_REGION=<your region>
python -m tracerai.agent
```

The trusted account's own identity also needs permission to assume the role, for
example `sts:AssumeRole` on `arn:aws:iam::*:role/TracerAI-ReadOnly`.

## Security notes

- The role is read only (describe actions only).
- The trust is scoped to one role in the trusted account, not the whole account,
  and requires the external id.
- Keep the external id out of source control. Pass it as an environment variable
  or a parameter at deploy time.
