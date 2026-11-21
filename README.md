# TracerAI

TracerAI is a networking troubleshooting agent for AWS. It is built with the Strands Agents SDK on Amazon Bedrock and uses read-only `boto3` tools to inspect live network infrastructure (EC2 Reachability Analyzer, security groups, instance lookup), then explains in plain language why connectivity works or fails.

## What it does

Ask a question like "Can the web server reach the database on 3306?" The agent resolves instance names to ids, runs Reachability Analyzer, inspects the security group when something is blocked, and returns a diagnosis with the likely fix. It can also list instances in a region.

It also does **cross-account network discovery**. Ask "discover my network in
eu-west-1" and it maps both backbones — **Transit Gateway** and **AWS Cloud WAN**
— and, for every attached VPC, reads the CIDRs, subnets, route tables, security
groups and NACLs in that VPC's owner account. It reads other accounts by assuming
a read-only role there (see [`deploy/`](deploy/README.md)); accounts without the
role are reported with a note instead of failing.

## How it works

The agent loop runs in your Python process.

1. You ask a question (`python -m tracerai.agent`).
2. The Strands agent picks a tool, using a Bedrock model (Claude).
3. Tools in `tracerai/tools/` are plain `boto3` functions, each runnable on its own.
4. The tools call read-only AWS APIs in the account your credentials point at.

The model (Bedrock) and the tools (AWS APIs) use the same AWS credentials.

## Prerequisites

1. **Python 3.10+**
2. **An AWS account** with:
   - Credentials configured (a profile or environment variables).
   - **Amazon Bedrock access to a Claude model**, which means BOTH:
     - the model enabled under Bedrock console > Model access, and
     - the **Anthropic use case details form** submitted (Bedrock requires this
       once per account for Anthropic models; it can take a few minutes to apply).
   - The resources you want to troubleshoot (EC2 instances) in that account.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configure and run

```bash
export AWS_PROFILE=<your-profile>     # creds for the account with Bedrock + your instances
export AWS_REGION=<region>            # default region for the tools

python -m tracerai.agent
```

On start it prints which account and region it is operating against, so you can
confirm you are pointed at the right place.

The Bedrock model id and its region are set in `tracerai/agent.py` (`build_agent`).
Change them there if you use a different model or region.

## Cross-account discovery (prerequisites)

Single-account use needs nothing beyond the prerequisites above. To discover
VPCs that live in **other** accounts, deploy a read-only role into each target
account first. This is a one-time setup, done by an administrator.

What has to be in place:

1. **A `TracerAI-ReadOnly` role in each target account** that trusts the account
   TracerAI runs in. Deploy it from [`deploy/`](deploy/README.md) — one account
   with `aws cloudformation deploy`, or org-wide with a service-managed StackSet.
   The management account is deployed directly (StackSets skip it).
2. **`sts:AssumeRole` permission** for the identity TracerAI runs as, on
   `arn:aws:iam::*:role/TracerAI-ReadOnly`.
3. **A shared external id**, the same value in the role's trust policy and at run
   time.

Then run with the two cross-account environment variables set:

```bash
export AWS_PROFILE=<trusted-account-profile>
export AWS_REGION=<region of your Bedrock model>
export TRACERAI_ROLE_NAME=TracerAI-ReadOnly              # the role to assume
export TRACERAI_EXTERNAL_ID=<the shared secret>          # matches the template
python -m tracerai.agent
# then: "discover my network in eu-west-1"
```

See [`deploy/README.md`](deploy/README.md) for the full runbook and the IAM
template.

## Try a tool on its own

Each tool runs standalone, which is the quickest way to test credentials and output:

```bash
python tracerai/tools/reachability.py
python tracerai/tools/instances.py
python tracerai/tools/security_groups.py
```

## Repository layout

| Path | Purpose |
|------|---------|
| `tracerai/agent.py` | Strands agent, tool wiring, system prompt |
| `tracerai/aws_session.py` | boto3 session helper; assumes the read-only role for cross-account reads |
| `tracerai/tools/reachability.py` | EC2 Reachability Analyzer wrapper |
| `tracerai/tools/instances.py` | Resolve a Name tag to an id, and list instances |
| `tracerai/tools/security_groups.py` | Inspect security group rules |
| `tracerai/tools/cross_account.py` | Cross-account network discovery (TGW + Cloud WAN, per-VPC detail) |
| `tracerai/banner.py` | Startup banner |
| `deploy/` | CloudFormation template + runbook for the cross-account read-only role |
| `requirements.txt` | Dependencies |
| `ROADMAP.md` | Planned features |

## IAM permissions

All tool calls are read-only or analysis only. The identity running TracerAI needs:

- **Bedrock (model):** `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`
  (or the Converse equivalents). The model access + use case form above are also required.
- **EC2 read:** `ec2:Describe*` (covers instances, security groups, and the region
  opt-in check the Bedrock call depends on).
- **Reachability Analyzer:** `ec2:CreateNetworkInsightsPath`,
  `ec2:StartNetworkInsightsAnalysis`, `ec2:DescribeNetworkInsightsAnalyses`,
  `ec2:DeleteNetworkInsightsPath`, plus `tiros:CreateQuery`, `tiros:GetQueryAnswer`,
  `tiros:GetQueryExplanation`, and a service-linked role for Reachability Analyzer.

A broad policy like PowerUserAccess covers all of this. There are no mutating
network permissions; TracerAI diagnoses, it does not change infrastructure.

For **cross-account discovery**, two more things apply:

- **In the trusted account** (where TracerAI runs): the identity needs
  `sts:AssumeRole` on `arn:aws:iam::*:role/TracerAI-ReadOnly`, plus
  `networkmanager:List*/Get*/Describe*` if you own a Cloud WAN core network.
- **In each target account**: the `TracerAI-ReadOnly` role from
  [`deploy/cross-account-role.yaml`](deploy/cross-account-role.yaml) grants only
  read-only EC2 describe and networkmanager read actions. Deploying the role
  needs IAM-write permission (PowerUserAccess is not enough), which is why the
  org-wide rollout uses a StackSet from the management account.

## Troubleshooting

- **"Model use case details have not been submitted" / ResourceNotFound on the model:**
  submit the Anthropic use case form in the Bedrock console, then wait a few minutes.
- **Instance not found:** TracerAI only sees the account your credentials point at.
  Check the "Operating against account ... region ..." line at startup. Name
  matching is partial and case insensitive and a few regions are searched by default.
- **AccessDenied with "explicit deny in a service control policy":** an org SCP is
  blocking the call (common for Bedrock). That is an org-level control, not the tool.

## License

TBD
