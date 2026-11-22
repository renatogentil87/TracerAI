# TracerAI Roadmap

A running list of what I want TracerAI to do next. Everything stays read only:
it diagnoses and recommends, never changes infrastructure. If I ever add a write
action it gets its own design pass with confirmation prompts and tight
permissions.

## Shipped today

- Discovery across accounts and both backbones (Transit Gateway and Cloud WAN),
  with per-VPC CIDRs, subnets, route tables, security groups, NACLs, NAT gateways
  and flow logs, and the 1:1 NAT state on each attachment. Multi-region in one
  call.
- Same-account reachability through EC2 Reachability Analyzer, and a cross-account,
  cross-region, NAT-aware path trace that names the first blocking layer.
- Security group inspection, open-port scans, route-table and instance lookups by
  account.
- Direct Connect health (connections, VIFs, BGP peers) and a resilience
  recommendation against the AWS Direct Connect Resiliency Toolkit.

## Next up

**Network Firewall rule verification.** The trace already detects when traffic is
routed through an inspection VPC and tells me to check the firewall by hand. The
next step is to read the AWS Network Firewall policy and rule groups (stateless and
stateful, including Suricata rules) and say whether a specific flow (source,
destination, port, protocol) is allowed or dropped. That closes the one layer the
end-to-end trace still hands off to me.

**Route 53 and DNS.** Resolve a name the way the workload would, then trace the IP
it returns. Read private hosted zones and their records, split-horizon overlaps,
and Route 53 Resolver inbound and outbound endpoints and forwarding rules. A lot of
"it can reach it but the name does not resolve" problems live here, and the trace
tools already handle everything once we have the address.

**Cloud WAN 1:1 NAT rule detail.** Today the NAT enabled state reads fine, but the
API in the installed SDK does not return the Cloud WAN NAT rule CIDRs, so the trace
falls back to the segment route tables. Derive the NAT CIDR from those routes
automatically (or pick it up from a newer SDK) so a Cloud WAN destination
translates without me supplying the outside CIDR.

**Follow the inter-region and cross-backbone leg.** The cross-region trace checks
each side in its own region but does not yet walk the Transit Gateway peering or the
TGW-to-Cloud-WAN hop between them. Follow the peering and segment routes end to end
so a cross-region path gets a single verdict instead of a "confirm this leg" note.

**VPN (Site-to-Site) status.** Tunnel up or down, and the BGP session per tunnel,
the same way the Direct Connect tool reports VIFs and BGP. Hybrid connectivity is
rarely only Direct Connect.

**Received routes, not just advertised.** Neither the Direct Connect nor the VPN API
returns the routes learned from on-premises. Correlate the advertised prefixes and
BGP state with the propagated routes in the attached VGW or Transit Gateway route
table, so I can see both directions of what BGP actually exchanged.

**Expand managed prefix lists.** Security group and route-table references to a
prefix list currently come back as "unknown" in the trace because the list contents
are not resolved. Expand them so a rule that allows a prefix list can be matched to
an address.

**IPv6 paths.** The matching logic is IPv4 only today. Add IPv6 so dual-stack VPCs
get the same security group, NACL and route evaluation.

## Evidence, not just config

**Flow log queries.** "Show me rejected traffic to this ENI in the last hour."
Config says what should happen; flow logs prove whether traffic arrived and whether
it was dropped.

**CloudWatch metrics.** A trend for NAT gateway or Transit Gateway bytes processed,
to catch a volume problem rather than a reachability one.

## Quality of life

Concurrency for discovery on a large estate, since it makes many assume-role and
describe calls. A way to export a run as JSON or a diagram. Follow-up handling like
"now check the reverse direction" without restating the whole question.

## How I build each one

Same approach every time. Write a plain boto3 function in `tracerai/tools/`, prove
it on its own from the command line, then wrap it as a tool with a docstring that
tells the agent when to reach for it, and update the system prompt so it fits into
how the agent investigates. Verify it live before trusting it.
