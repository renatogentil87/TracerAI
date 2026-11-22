# TracerAI

TracerAI is a networking troubleshooting agent for AWS. It is built with the Strands Agents SDK on Amazon Bedrock and uses read-only `boto3` tools to inspect live network infrastructure across accounts and regions (Transit Gateway, Cloud WAN, VPC routing, security groups, NACLs, NAT, Direct Connect, flow logs), then explains in plain language why connectivity works or fails.

## What it does

Ask a question like "Can the web server reach the database on 3306?" The agent resolves instance names to ids, runs Reachability Analyzer, inspects the security group when something is blocked, and returns a diagnosis with the likely fix. It can also list instances in a region.

It also does **cross-account network discovery**. Ask "discover my network in
eu-west-1" and it maps both backbones (Transit Gateway and AWS Cloud WAN). For
every attached VPC it reads the CIDRs, subnets, route tables, security groups and
NACLs in that VPC's owner account. Other accounts are read by assuming a
read-only role there (see [`deploy/`](deploy/README.md)); accounts without the
role are reported with a note instead of failing.

Beyond discovery it can **trace reachability across accounts and regions** (and
it is 1:1 NAT aware), **check Direct Connect** health and resilience against the
AWS SLA targets, and **read VPC flow logs** for evidence of accepted or rejected
traffic. See [Tools](#tools) for the full set and when each is used.

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

## Model configuration

TracerAI calls a Bedrock Claude model. `build_agent()` in `tracerai/agent.py`
reads its configuration from the environment, with working defaults, so you do
not edit code to point at your account:

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRACERAI_MODEL_ID` | `global.anthropic.claude-sonnet-4-6` | Bedrock model id |
| `TRACERAI_BEDROCK_REGION` | `AWS_REGION`, else `ca-central-1` | region the model is called in |
| `TRACERAI_GUARDRAIL_ID` | _unset_ | optional Bedrock guardrail; applied only when set (guardrails are account-specific, so there is no default) |
| `TRACERAI_GUARDRAIL_VERSION` | `1` | guardrail version, used only with the id |
| `TRACERAI_MASK_ACCOUNT_IDS` | `true` | show only the last 4 digits of account ids in replies (set `false` to show full ids) |

A fresh clone runs with no guardrail. Set `TRACERAI_GUARDRAIL_ID` only if you
have a guardrail in your own account.

By default TracerAI prints account ids as their last 4 digits only (for example
`account ...9670`) so the output is safe to paste into tickets or share. Set
`TRACERAI_MASK_ACCOUNT_IDS=false` if you want full 12-digit account ids. Either
way, full ids are always used internally for cross-account calls.

## Cross-account discovery (prerequisites)

Single-account use needs nothing beyond the prerequisites above. To discover
VPCs that live in **other** accounts, deploy a read-only role into each target
account first. This is a one-time setup, done by an administrator.

What has to be in place:

1. **A `TracerAI-ReadOnly` role in each target account** that trusts the account
   TracerAI runs in. Deploy it from [`deploy/`](deploy/README.md): a single
   account with `aws cloudformation deploy`, or org-wide with a service-managed
   StackSet. The management account is deployed directly (StackSets skip it).
2. **`sts:AssumeRole` permission** for the identity TracerAI runs as, on
   `arn:aws:iam::*:role/TracerAI-ReadOnly`.
3. **A shared external id**, the same value in the role's trust policy and at run
   time.

Then run with the cross-account environment variables set. "Set" means export
them in your terminal for the current session, right before you launch the tool;
they are not permanent. Of the two, only `TRACERAI_EXTERNAL_ID` is required.
`TRACERAI_ROLE_NAME` is optional and defaults to `TracerAI-ReadOnly`.

```bash
export AWS_PROFILE=<trusted-account-profile>
export AWS_REGION=<region of your Bedrock model>
# Required: the shared secret; cross-account reads fail without it.
export TRACERAI_EXTERNAL_ID=<the shared secret>
# Optional: only if your role is named something other than TracerAI-ReadOnly.
# export TRACERAI_ROLE_NAME=TracerAI-ReadOnly
python -m tracerai.agent
# then: "discover my network in eu-west-1"
```

If your trusted-account credentials are an expired SSO session, run
`aws sso login --profile <trusted-account-profile>` first.

See [`deploy/README.md`](deploy/README.md) for the full runbook and the IAM
template.

## Try a tool on its own

Each tool runs standalone, which is the quickest way to test credentials and output:

```bash
python tracerai/tools/reachability.py
python tracerai/tools/instances.py
python tracerai/tools/security_groups.py
python tracerai/tools/cross_account.py
python tracerai/tools/directconnect.py
python tracerai/tools/flow_logs.py
```

## Tools

The agent has these tools and decides which to call from your question.

**Discovery and mapping**
- `discover_network` maps Transit Gateway and Cloud WAN across accounts: per VPC it
  reads CIDRs, subnets, route tables, security groups, NACLs, NAT gateways and flow
  logs, plus each attachment's 1:1 NAT state. Pass one region, or several comma
  separated (for example `eu-west-1,us-east-1`) for a cross-region map.
- `get_vpc_route_tables` reads one VPC's route tables, in this or another account.
- `list_instances` lists the instances in a region.
- `resolve_instance` resolves a Name tag to an instance id in this account.

**Reachability**
- `check_reachability` runs EC2 Reachability Analyzer between two instances in the
  same account.
- `trace_cross_account` walks the path between two instances in different accounts
  and regions: security groups, NACLs, route tables, the Transit Gateway route table
  in the hub account, and the return path. It is 1:1 NAT aware and names the first
  layer that blocks the flow.
- `resolve_endpoint` turns a Name tag, instance id, private IP or ARN into an
  instance (in any account) so you can confirm the ends before a cross-account trace.

**Security groups and ports**
- `check_security_group` inspects the inbound and outbound rules of an instance or a
  security group, with a verdict for a given port.
- `scan_open_port` scans every security group in a region for an open inbound port.
- `get_instance_security_groups` reads an instance's security group rules, in this or
  another account.

**Direct Connect**
- `check_direct_connect` reports connections (dedicated or hosted), virtual
  interfaces, and each BGP peer up or down, plus the DX gateway's advertised prefixes.
- `recommend_dx_resilience` assesses the resilience posture and recommends how to
  reach the 99.9% or 99.99% SLA, following the AWS Direct Connect Resiliency Toolkit.

**Evidence**
- `check_vpc_flow_logs` reads VPC flow log records for an interface from CloudWatch
  Logs and shows the ACCEPT or REJECT traffic, so you can confirm with evidence what
  the config trace predicts. CloudWatch Logs destinations only.

## Repository layout

| Path | Purpose |
|------|---------|
| `tracerai/agent.py` | Strands agent, tool wiring, system prompt |
| `tracerai/aws_session.py` | boto3 session helper; assumes the read-only role for cross-account reads |
| `tracerai/tools/reachability.py` | EC2 Reachability Analyzer wrapper |
| `tracerai/tools/instances.py` | Resolve a Name tag to an id, and list instances |
| `tracerai/tools/security_groups.py` | Inspect security group rules |
| `tracerai/tools/cross_account.py` | Cross-account network discovery (TGW + Cloud WAN, per-VPC detail) |
| `tracerai/tools/reachability_trace.py` | Cross-account reachability tracing (endpoint resolution + path walk) |
| `tracerai/tools/directconnect.py` | Direct Connect health and resilience recommendations |
| `tracerai/tools/flow_logs.py` | VPC flow log reader (CloudWatch Logs): ACCEPT/REJECT for an interface |
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
  To label accounts with their names (for example "SpokeDev1 (...9670)") the
  identity also needs `organizations:ListAccounts`, which works from the
  management account or a delegated administrator. Without it, discovery still
  works and just shows the account id.
- **In each target account**: the `TracerAI-ReadOnly` role from
  [`deploy/cross-account-role.yaml`](deploy/cross-account-role.yaml) grants
  read-only actions only. It covers EC2 describe (VPCs, subnets, route tables,
  security groups, NACLs, NAT gateways, flow logs, and Transit Gateway including
  `SearchTransitGatewayRoutes` and `GetTransitGatewayAttachmentNatConfiguration`),
  `networkmanager` read for Cloud WAN, `directconnect:Describe*`, and CloudWatch
  Logs Insights (`logs:StartQuery` / `GetQueryResults`) for VPC flow logs.
  Deploying the role needs IAM-write permission (PowerUserAccess is not enough),
  which is why the org-wide rollout uses a StackSet from the management account.

## Troubleshooting

- **"Model use case details have not been submitted" / ResourceNotFound on the model:**
  submit the Anthropic use case form in the Bedrock console, then wait a few minutes.
- **Instance not found:** TracerAI only sees the account your credentials point at
  (unless you give it another account to assume into). Check the "Operating in ...
  in region ..." line at startup. Name matching is partial and case insensitive.
- **AccessDenied with "explicit deny in a service control policy":** an org SCP is
  blocking the call (common for Bedrock). That is an org-level control, not the tool.

## License

TBD
