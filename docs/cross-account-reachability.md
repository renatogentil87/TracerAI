# Cross-account reachability

A planned TracerAI capability: answer "can source A reach destination B" when the two
ends live in different AWS accounts, by reading network config from both accounts and
modeling the path. Read only. No Reachability Analyzer, no resource changes.

## Why model instead of using Reachability Analyzer

EC2 Reachability Analyzer works within a single account and cannot trace a path whose
hops live in another account. When traffic leaves one account over a Transit Gateway or
a peering, RA on the source side reports the route as unknown because it cannot see the
other account's route tables. A workload spread across several accounts (a spoke VPC, a
Transit Gateway account, an inspection VPC, an egress VPC) is exactly the case RA cannot
cover on its own.

TracerAI reads the config from each account on the path and works out reachability
directly. This is passive, describe calls only, and it naturally spans accounts.

## Inputs

- Source: account id plus an instance id or a private IP.
- Destination: account id plus an instance id or a private IP.
- Port and protocol.

From those, TracerAI resolves each endpoint to its ENI, subnet, VPC, and account, then
collects the config needed to walk the path between them.

## How it reaches each account

TracerAI assumes a read-only role in each account with STS, using a role name you pass
in (the same role name must exist in every account, trusting the identity TracerAI runs
as). It then makes describe calls with those temporary credentials. Nothing is created
or changed in any account.

A single boto3 session per account is built from the assumed credentials, so the tool
code is the same whether the account is the one TracerAI runs in or a remote one.

## What it reads

Per account on the path, normalized into one internal model:

- VPC route tables
- Security groups
- Network ACLs
- Transit Gateway route tables and attachment associations
- Transit Gateway peering
- Cloud WAN segment routes, if present
- Network Firewall policy, if the path goes through an inspection VPC

## The walk

Forward, source to destination:

1. Source security group egress allows the destination and port.
2. Source subnet NACL egress allows it.
3. Source VPC route table: which target owns the destination prefix (local, NAT, TGW,
   peering, gateway).
4. If it leaves via a Transit Gateway, follow the TGW route table the attachment is
   associated with, including peering to another region's TGW.
5. If the path goes through an inspection or egress VPC, check the firewall policy
   allows the flow instead of reporting a missing route. Central inspection looks like a
   missing route if only the source side is read.
6. Destination side: the route back toward the source, destination NACL ingress, and
   destination security group ingress.

Then the same walk in reverse, destination back to source. Asymmetric routing is a
common real failure, so a clean forward path is not a pass on its own.

TracerAI reports the first layer that denies the flow or has no route, names the exact
rule or the missing prefix, and says which account and route table it is in.

## Example of the kind of gap it catches

A common cross-region, cross-account failure: the forward path is correct all the way to
the internet or to the far VPC, but the return route is missing at the far Transit
Gateway. Transit Gateway peering does not propagate routes, so return routes are static
and easy to forget for one VPC while a sibling VPC has its route. Traffic goes out and
never comes back. A forward-and-return walk catches this where a forward-only check would
call the path healthy.

## Honest limits

- Config based. It proves what the config says, not what a live packet does. It can miss
  a host firewall, an appliance dropping traffic, or anything not visible in AWS config.
- It needs a read-only role it can assume in every account on the path. An account it
  cannot reach is reported as a gap in coverage, not a false "blocked".

## Status

Implemented for the same-region case in `tracerai/tools/reachability_trace.py`
(`resolve_endpoint` and `trace_cross_account`). The forward and return walk reads
security groups, NACLs, VPC route tables and the Transit Gateway route table in
the hub account, and reports the first blocking layer. An inspection VPC on the
path is detected and flagged for manual firewall review.

Not yet implemented: cross-region paths (TGW peering between regions), reading
firewall policy to verify the inspection step, and expanding prefix lists.
