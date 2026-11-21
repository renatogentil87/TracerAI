# Cross-account discovery setup

TracerAI reads network config in other accounts (VPC route tables, security
groups, NACLs, Transit Gateway and Cloud WAN attachments) by assuming a
read-only role in each one. This folder has the CloudFormation template that
creates that role, plus the runbook to roll it out.

## The model

- TracerAI runs in one account, the **trusted account**, with its own
  credentials (an SSO role, an IAM role, or keys).
- Every account you want to discover has a **`TracerAI-ReadOnly`** role that
  trusts the trusted account to assume it. The role is read only.
- Two controls gate the trust:
  1. an **external id** (a shared secret) the caller must present, and
  2. the caller's own identity must be granted **`sts:AssumeRole`** on the role.
- When you ask about a VPC in another account, TracerAI assumes that account's
  role, reads the config, and answers. For the trusted account's own VPCs it
  uses local credentials (no assume).

Nothing deploys automatically when you clone the repo. An administrator deploys
the role into the target accounts with the template here, and you run TracerAI
on your machine.

## Template parameters (`cross-account-role.yaml`)

| Parameter | Required | Default | Purpose |
|-----------|----------|---------|---------|
| `TrustedAccountId` | yes | n/a | The 12-digit account TracerAI runs in. |
| `ExternalId` | yes | n/a | Shared secret the caller must present (`NoEcho`). |
| `TrustedPrincipalArn` | no | `''` (account root) | Tighten the trust to one principal ARN in the trusted account. Leave blank to trust the trusted account root (external id + the caller's `sts:AssumeRole` permission are then the control). |
| `RoleName` | no | `TracerAI-ReadOnly` | Name of the role created in the target account. |

> **Do not** put a raw AWS SSO role name (`AWSReservedSSO_*`) in
> `TrustedPrincipalArn`. SSO role ARNs live under
> `/aws-reserved/sso.amazonaws.com/` and the suffix rotates, so naming one makes
> the trust invalid or brittle. Trust the account root (default) and rely on the
> external id, or create a dedicated stable IAM role in the trusted account and
> use its ARN.

## Step 0: pick an external id (once)

Generate a secret and keep it out of source control. Reuse the same value for
every deployment and at run time.

```bash
mkdir -p ~/.tracerai && chmod 700 ~/.tracerai
openssl rand -hex 16 > ~/.tracerai/external_id
chmod 600 ~/.tracerai/external_id
```

## Path 1: one account (prove it first)

In the **target** account, with permission to create IAM roles (PowerUser is not
enough, because it excludes IAM write):

```bash
aws cloudformation deploy \
  --template-file deploy/cross-account-role.yaml \
  --stack-name tracerai-readonly \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      TrustedAccountId=<TRUSTED_ACCOUNT_ID> \
      ExternalId="$(tr -d '\n' < ~/.tracerai/external_id)"
```

Then, in the **trusted** account, allow TracerAI's identity to assume it:

```
Action:   sts:AssumeRole
Resource: arn:aws:iam::<TARGET_ACCOUNT_ID>:role/TracerAI-ReadOnly
```

How you attach that depends on how TracerAI runs:
- **IAM user/role:** add the statement to that principal's policy.
- **IAM Identity Center (SSO):** add it to the permission set's inline policy and
  re-provision. Scope the resource to `arn:aws:iam::*:role/TracerAI-ReadOnly` so
  it covers every target account at once.

Verify from the trusted account:

```bash
aws sts assume-role \
  --role-arn "arn:aws:iam::<TARGET_ACCOUNT_ID>:role/TracerAI-ReadOnly" \
  --role-session-name tracerai-test \
  --external-id "$(tr -d '\n' < ~/.tracerai/external_id)"
```

## Path 2: org-wide (all accounts, the real rollout)

A **service-managed StackSet** creates the role in every account in the target
OUs, including new ones. It is launched from the **management account** or a
delegated administrator. Service-managed StackSets deploy to a target OU **and
its child OUs**, but **not** the management account itself. Deploy that one
directly with Path 1 if the management account owns VPCs you want to discover.

The role is a global IAM resource, so deploy the StackSet to a **single region**.

1. Enable trusted access for StackSets with Organizations (management account):

   ```bash
   aws cloudformation activate-organizations-access
   ```

2. Create the StackSet from the template:

   ```bash
   aws cloudformation create-stack-set \
     --stack-set-name TracerAI-ReadOnly \
     --description "TracerAI cross-account read-only network discovery role" \
     --template-body file://deploy/cross-account-role.yaml \
     --capabilities CAPABILITY_NAMED_IAM \
     --permission-model SERVICE_MANAGED \
     --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
     --parameters \
        ParameterKey=TrustedAccountId,ParameterValue=<TRUSTED_ACCOUNT_ID> \
        ParameterKey=ExternalId,ParameterValue="$(tr -d '\n' < ~/.tracerai/external_id)"
   ```

3. Deploy instances to the OU(s) that hold your accounts (one region):

   ```bash
   aws cloudformation create-stack-instances \
     --stack-set-name TracerAI-ReadOnly \
     --deployment-targets OrganizationalUnitIds=<OU_ID> \
     --regions us-east-1
   ```

4. In the trusted account, grant `sts:AssumeRole` on
   `arn:aws:iam::*:role/TracerAI-ReadOnly` (see Path 1, step 2). With auto
   deployment on, new accounts added to the OUs get the role automatically.

## Run TracerAI with cross-account discovery

On the machine running TracerAI, with the trusted account's credentials. Export
these in your terminal for the current session before launching the tool. Only
`TRACERAI_EXTERNAL_ID` is required; `TRACERAI_ROLE_NAME` is optional and defaults
to `TracerAI-ReadOnly`.

```bash
export AWS_PROFILE=<trusted-account-profile>   # or AWS_* env vars
export AWS_REGION=<region of your Bedrock model>
export TRACERAI_EXTERNAL_ID="$(tr -d '\n' < ~/.tracerai/external_id)"   # required
# export TRACERAI_ROLE_NAME=TracerAI-ReadOnly  # optional; only if you renamed the role
python -m tracerai.agent
# then: "discover my network in eu-west-1"
```

## Security notes

- The role is read only (describe / list / get actions only; no mutating calls).
- The default trust is the trusted account root **plus** a required external id.
  Because the caller must also be explicitly granted `sts:AssumeRole`, root is
  gated by two independent controls. Tighten to `TrustedPrincipalArn` if you want
  the trust pinned to a single principal.
- Keep the external id out of source control. Pass it as an environment variable
  or a deploy-time parameter; the template marks it `NoEcho`.

## Checklist

- [ ] External id generated and stored outside the repo.
- [ ] Bedrock (model) works in the account/region TracerAI runs in.
- [ ] `TracerAI-ReadOnly` deployed in each target account (Path 1 or 2).
- [ ] Management account deployed directly if it owns VPCs (StackSets skip it).
- [ ] Trusted identity has `sts:AssumeRole` on `arn:aws:iam::*:role/TracerAI-ReadOnly`.
- [ ] `TRACERAI_EXTERNAL_ID` at run time matches the template's `ExternalId`.
