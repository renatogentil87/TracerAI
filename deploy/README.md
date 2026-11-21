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

## Runbook: make full cross-account discovery work

Full discovery needs three things in place: the read-only role in each target
account, permission for TracerAI's identity to assume it, and the matching
external id at run time. Start with one account to prove it, then go org-wide.

### The role-name parameter (get this right first)

`TracerAIRoleName` must be the role TracerAI actually runs as in the trusted
account. If you run TracerAI under a federated/SSO identity, that role name can
rotate, which makes a brittle trust. For a stable setup, create a dedicated IAM
role (for example `TracerAI-Agent`) in the trusted account, run TracerAI as it,
and use that as `TracerAIRoleName`. For a quick test you can trust the SSO role
name you currently run as.

### Path 1: one account (prove it first)

1. In the target account, with permission to create IAM roles, deploy the role:

   ```bash
   aws cloudformation deploy \
     --template-file deploy/cross-account-role.yaml \
     --stack-name tracerai-readonly \
     --capabilities CAPABILITY_NAMED_IAM \
     --parameter-overrides \
       TrustedAccountId=<trusted account id> \
       TracerAIRoleName=<role TracerAI runs as> \
       ExternalId=<a secret string>
   ```

2. In the trusted account, allow TracerAI's identity to assume it:

   ```
   Action:   sts:AssumeRole
   Resource: arn:aws:iam::<target account id>:role/TracerAI-ReadOnly
   ```

3. Run TracerAI with the trusted account's credentials and the same external id:

   ```bash
   export TRACERAI_ROLE_NAME=TracerAI-ReadOnly
   export TRACERAI_EXTERNAL_ID=<the same secret>
   export AWS_REGION=<region of the model>
   python -m tracerai.agent
   ```

   Ask it to discover the network. That account's VPCs now read fully; accounts
   without the role still come back with a "needs role" note.

### Path 2: org-wide (all accounts, the real rollout)

Service-managed StackSets create the role in every account, including new ones.
They are launched from the management account or a delegated administrator,
because only those can create IAM roles across an Organization.

1. In the management account, enable trusted access for CloudFormation StackSets
   with AWS Organizations.
2. Create a service-managed StackSet from `cross-account-role.yaml` with the same
   parameters as Path 1, targeting the OU(s) that hold your accounts, with
   automatic deployment turned on.
3. In the trusted account, allow TracerAI's identity to assume the role in any
   account:

   ```
   Action:   sts:AssumeRole
   Resource: arn:aws:iam::*:role/TracerAI-ReadOnly
   ```

4. Run TracerAI as in Path 1, step 3.

### Checklist

- [ ] Model (Bedrock) works in the account TracerAI runs as.
- [ ] Guardrail (if used) is in that same account and region.
- [ ] TracerAI-ReadOnly role deployed in each target account (Path 1 or 2).
- [ ] TracerAI's identity has sts:AssumeRole for that role.
- [ ] TRACERAI_EXTERNAL_ID at run time matches the template's ExternalId.
