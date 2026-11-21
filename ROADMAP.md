# TracerAI Roadmap

This is a running list of what I want TracerAI to do next. Today it can resolve an
instance by its Name tag and run a Reachability Analyzer check between two instances.
That is a solid base, but the goal is a real network assistant: something you can ask
a plain question and get a useful answer about your AWS network.

I am keeping everything read only. TracerAI should diagnose and recommend, never
change infrastructure. If I ever add write actions, that gets its own design pass with
confirmation prompts and tight permissions.

## Near term

These answer the questions I hit most often, and they build straight on what is already here.

**Security group inspection.** Ask things like "is security group B allowing port 1010?"
or "what can reach this instance on 443?" The tool reads the ingress and egress rules and
the agent tells me in plain words whether a port and source are allowed.

**Route table inspection.** Ask "does this subnet have a route to the internet?" or
"where does 10.0.0.0/8 go from here?" The agent explains the routes and their targets,
whether that is an internet gateway, a NAT gateway, a transit gateway, or a peering
connection.

**Public or private subnet check.** A quick one that looks at whether a subnet has a
default route to an internet gateway, so I can confirm what is actually public.

**NACL inspection.** The thing everyone forgets after they check security groups. Ask
"is a network ACL blocking this?" and get the subnet level rules explained.

## The real goal: let it investigate

Once the inspection tools exist, the interesting part is letting the agent chain them on
its own. I ask "why can't A reach B?", it runs the reachability check, sees the blocking
reason, and then goes and pulls the right security group or route table to tell me the
specific rule to fix. I do not want to tell it which tool to use. I want it to work the
problem the way I would.

## Discovery and inventory

Handy for the "what do I even have" moments.

**List instances, VPCs, and subnets** with their CIDRs, so I can get my bearings in an
account I do not know well.

**Find a resource by IP.** I get an IP out of a log and have no idea what owns it. Give
the agent the address and have it tell me the instance, ENI, or service behind it.

**List transit gateway attachments** so I can see what is actually connected to a hub.

## Hybrid and transit, the parts I care about most

This is where TracerAI stops being a VPC helper and becomes a networking tool that
matches the work I actually do.

**VPN tunnel status.** Ask "are my tunnels up, and which one is down?" and get a straight
answer instead of clicking through the console.

**Direct Connect VIF status.** Check whether a virtual interface is up and its BGP session
is established.

**Transit gateway route lookups.** Ask "which attachment does 172.24.0.0/16 resolve to?"
or "is there a blackhole route in this table?" The blackhole question alone would save me
real time.

**Cloud WAN segment routes.** Ask whether a segment is learning a given prefix, which is
exactly the kind of silent failure that is painful to chase by hand.

## Evidence, not just config

**Flow log queries.** Ask "show me rejected traffic to this ENI in the last hour." This is
the step that proves whether traffic is even arriving and whether it is being dropped,
rather than only reading what the config says should happen.

**CloudWatch metrics.** Pull a trend for things like NAT gateway or transit gateway bytes
processed, so I can spot a problem that is about volume rather than reachability.

## Quality of life

Small things that make it feel like an assistant rather than a command wrapper.

Infer ports from service names, so "over HTTPS" becomes 443 without me spelling it out.
Suggest the actual fix, not just the blocking reason. Handle follow up questions like
"now check the reverse direction." And fail gracefully when an instance or name cannot be
found, with a message that tells me what to try instead.

## Interpret results in the context of centralized inspection

This one came out of a real run. I asked whether prod-instance-vpc-a could reach
nonprod-instance-vpc-b, and Reachability Analyzer returned TGW_RTB_ROUTES_ARE_UNKNOWN,
which TracerAI reported as a missing Transit Gateway route. That is misleading in my
network. The Transit Gateway is deliberately sending the traffic to a central inspection
firewall, which inspects it and returns it, so the source route table points at the
inspection VPC on purpose. What looks like a missing route is actually the send-via
firewall path. Reachability Analyzer also cannot always see a Transit Gateway route table
that lives in another account, which produces the same code.

So TracerAI should not flatly call this a missing route. Planned improvements:

- Teach the agent that TGW_RTB_ROUTES_ARE_UNKNOWN (and similar "no route" findings) can
  mean traffic is being inspected and returned, not dropped. Caveat it instead of
  asserting a gap, and never recommend a route that would bypass the firewall.
- Add tools to read the Transit Gateway route tables and the firewall policy, so the
  agent can confirm whether traffic is being sent to an inspection VPC and returned, and
  explain that path.
- When inspection is in play, describe the expected flow (source to Transit Gateway to
  inspection firewall to destination and back) rather than treating it as broken.

## Cross-account discovery (shipped, with follow-ups)

Discovery is now cross-account. From the Transit Gateway owner account it maps the TGW
attachments, then reads each connected VPC's CIDRs, subnets, route tables, security
groups and NACLs in the VPC's owner account, assuming a read-only role (deploy/) for
other accounts. Targeted lookups exist too: a VPC's route tables, and an instance's
security groups, by account.

Follow-ups:

- The TracerAI-ReadOnly role has to be deployed into each account (CloudFormation
  StackSet, from the management or a delegated-admin account) before cross-account reads
  work. Until then those accounts come back with a "needs role" note.
- Cloud WAN is still a placeholder in the discovery result (cloud_wan is empty). Fill it
  in with the networkmanager client (global, us-east-1): core network, segments, segment
  route tables / RIB, attachments.
- Discovery makes many assume-role and describe calls on a large estate. Add concurrency
  if it gets slow.

## Full path review for a TGW, Cloud WAN, and firewall network

The north star. For a network like mine (Transit Gateway peered with Cloud WAN, with a
central inspection firewall), I want to ask one question like "why can't A reach B?" and
have TracerAI walk the entire path and tell me where it breaks, without me pointing it at
each layer by hand.

To do that it has to read every layer on the path and reason across them:

- Security groups and NACLs on both ends (security groups done, NACLs listed above).
- Subnet and VPC route tables.
- Transit Gateway route tables, including which attachment a prefix resolves to and any
  blackhole.
- Cloud WAN segment route tables, and whether a segment is actually learning the prefix.
- Network Firewall rule groups and policy, to see whether the inspected traffic is allowed
  by a rule, not just routed to the firewall.

Then it chains them into one diagnosis: resolve both ends, run reachability, and for each
layer on the path confirm the config allows the flow, calling out the first thing that
blocks it (a missing or blackhole route, a security group or NACL rule, or a firewall rule
that drops the traffic). It has to understand the send-via firewall path, so when traffic
is routed to the inspection VPC it checks the firewall policy instead of reporting a
missing route.

New tools this needs:

- **Network Firewall inspection.** Read the firewall policy and rule groups and say whether
  a given flow (source, destination, port, protocol) is allowed or dropped.
- **Cloud WAN route tables.** Read a segment route table and say how a prefix resolves and
  which edge or attachment it was learned from.
- **Transit Gateway route tables.** Listed above under hybrid and transit.

This is the capability that makes TracerAI match the work I actually do, troubleshooting a
TGW, Cloud WAN, and firewall estate end to end instead of answering one layer at a time.

## How I build each one

Same approach every time. Write a plain boto3 function in `tracerai/tools/`, prove it on
its own from the command line, then wrap it as a tool and describe it well so the agent
knows when to reach for it. Update the system prompt so it fits into how the agent
investigates.
